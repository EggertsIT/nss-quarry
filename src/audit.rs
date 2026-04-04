use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::AuditConfig;
use crate::models::AuditEvent;

#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<AuditEvent>,
}

impl AuditLogger {
    pub async fn new(cfg: &AuditConfig) -> Result<Self> {
        let path = cfg.path.clone();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed creating audit dir {}", parent.display()))?;
        }
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(10_000);
        let retention_days = cfg.retention_days;
        let rotate_max_bytes = cfg.rotate_max_bytes;
        let rotate_max_files = cfg.rotate_max_files;
        tokio::spawn(async move {
            if retention_days > 0
                && let Err(err) = cleanup_retention(&path, retention_days).await
            {
                warn!(error = %err, "failed initial cleanup of old audit logs");
            }
            let mut events_since_cleanup: u64 = 0;
            while let Some(event) = rx.recv().await {
                if let Err(err) =
                    append_event(&path, &event, rotate_max_bytes, rotate_max_files).await
                {
                    warn!(error = %err, "failed writing audit event");
                }
                events_since_cleanup = events_since_cleanup.saturating_add(1);
                if retention_days > 0
                    && events_since_cleanup >= 200
                    && let Err(err) = cleanup_retention(&path, retention_days).await
                {
                    warn!(error = %err, "failed cleanup of old audit logs");
                }
                if events_since_cleanup >= 200 {
                    events_since_cleanup = 0;
                }
            }
        });
        Ok(Self { tx })
    }

    pub async fn log(&self, event: AuditEvent) {
        let _ = self.tx.send(event).await;
    }
}

async fn append_event(
    path: &Path,
    event: &AuditEvent,
    rotate_max_bytes: u64,
    rotate_max_files: u32,
) -> Result<()> {
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    if rotate_max_bytes > 0 {
        rotate_if_needed(path, rotate_max_bytes, rotate_max_files, line.len() as u64).await?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("failed opening audit file {}", path.display()))?;
    file.write_all(&line).await?;
    Ok(())
}

async fn rotate_if_needed(
    path: &Path,
    rotate_max_bytes: u64,
    rotate_max_files: u32,
    incoming_len: u64,
) -> Result<()> {
    if rotate_max_bytes == 0 {
        return Ok(());
    }
    let metadata = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if metadata.len().saturating_add(incoming_len) <= rotate_max_bytes {
        return Ok(());
    }
    if rotate_max_files == 0 {
        return Ok(());
    }

    let oldest = rotated_path(path, rotate_max_files);
    let _ = tokio::fs::remove_file(&oldest).await;
    for idx in (1..rotate_max_files).rev() {
        let src = rotated_path(path, idx);
        let dst = rotated_path(path, idx + 1);
        if tokio::fs::metadata(&src).await.is_ok() {
            let _ = tokio::fs::rename(&src, &dst).await;
        }
    }
    if tokio::fs::metadata(path).await.is_ok() {
        let _ = tokio::fs::rename(path, rotated_path(path, 1)).await;
    }
    Ok(())
}

fn rotated_path(path: &Path, idx: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.{}", path.display(), idx))
}

async fn cleanup_retention(path: &Path, retention_days: u64) -> Result<()> {
    if retention_days == 0 {
        return Ok(());
    }
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let Some(base_name) = path.file_name().and_then(|s| s.to_str()) else {
        return Ok(());
    };
    let cutoff = Duration::from_secs(retention_days.saturating_mul(86_400));

    let mut entries = tokio::fs::read_dir(parent)
        .await
        .with_context(|| format!("failed reading audit dir {}", parent.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(suffix) = file_name
            .strip_prefix(base_name)
            .and_then(|s| s.strip_prefix('.'))
        else {
            continue;
        };
        if suffix.parse::<u32>().is_err() {
            continue;
        }
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match meta.modified() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let age = match modified.elapsed() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if age > cutoff {
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
    }
    Ok(())
}
