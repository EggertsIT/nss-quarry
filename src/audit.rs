use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

use crate::models::AuditEvent;

#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<AuditEvent>,
}

impl AuditLogger {
    pub async fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed creating audit dir {}", parent.display()))?;
        }
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(10_000);
        let path = path.to_path_buf();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(err) = append_event(&path, &event).await {
                    warn!(error = %err, "failed writing audit event");
                }
            }
        });
        Ok(Self { tx })
    }

    pub async fn log(&self, event: AuditEvent) {
        let _ = self.tx.send(event).await;
    }
}

async fn append_event(path: &Path, event: &AuditEvent) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("failed opening audit file {}", path.display()))?;

    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    file.write_all(&line).await?;
    Ok(())
}
