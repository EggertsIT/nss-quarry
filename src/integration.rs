use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::warn;
use uuid::Uuid;

use crate::config::RoleName;
use crate::models::{
    ServiceNowInvestigationJobStatus, ServiceNowInvestigationResult,
    ServiceNowInvestigationSubmitRequest, ServiceNowJobState,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const JOB_SCHEMA_VERSION: &str = "servicenow_integration_v1";
const CLEANUP_MIN_INTERVAL_SECS: u64 = 60;
const EXPIRED_JOB_GRACE_SECS: i64 = 3600;

#[derive(Clone)]
pub struct ServiceNowIntegrationService {
    inner: Arc<IntegrationInner>,
}

struct IntegrationInner {
    jobs_dir: PathBuf,
    job_ttl_hours: u64,
    cleanup_interval_secs: u64,
    jobs: RwLock<HashMap<String, StoredJob>>,
}

#[derive(Debug, Clone)]
pub struct ServiceNowJobInput {
    pub submitted_by: String,
    pub submitted_role: RoleName,
    pub source_ip: Option<String>,
    pub case_id: String,
    pub request_id: Option<String>,
    pub request: ServiceNowInvestigationSubmitRequest,
}

#[derive(Debug, Clone)]
pub struct SubmitJobResult {
    pub deduplicated: bool,
    pub status: ServiceNowInvestigationJobStatus,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredJob {
    schema_version: String,
    job_id: String,
    case_id: String,
    request_id: Option<String>,
    status: ServiceNowJobState,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    submitted_by: String,
    submitted_role: RoleName,
    source_ip: Option<String>,
    include_csv: bool,
    request: ServiceNowInvestigationSubmitRequest,
    result: Option<ServiceNowInvestigationResult>,
    csv_data: Option<String>,
    csv_token: Option<String>,
    error: Option<String>,
}

impl ServiceNowIntegrationService {
    pub async fn new(
        jobs_dir: PathBuf,
        job_ttl_hours: u64,
        cleanup_interval_secs: u64,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(&jobs_dir)
            .await
            .with_context(|| format!("failed creating jobs dir {}", jobs_dir.display()))?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&jobs_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| format!("failed setting perms on {}", jobs_dir.display()))?;

        let svc = Self {
            inner: Arc::new(IntegrationInner {
                jobs_dir,
                job_ttl_hours: job_ttl_hours.max(1),
                cleanup_interval_secs: cleanup_interval_secs.max(CLEANUP_MIN_INTERVAL_SECS),
                jobs: RwLock::new(HashMap::new()),
            }),
        };
        svc.load_existing_jobs().await?;
        Ok(svc)
    }

    pub fn start_cleanup_task(&self) {
        let svc = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(svc.inner.cleanup_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(err) = svc.cleanup_expired().await {
                    warn!(error = %err, "servicenow job cleanup failed");
                }
            }
        });
    }

    pub async fn submit_job(&self, input: ServiceNowJobInput) -> Result<SubmitJobResult> {
        validate_submit_input(&input.request)?;
        let now = Utc::now();
        let mut jobs = self.inner.jobs.write().await;

        if let Some(request_id) = input.request_id.as_deref()
            && let Some(existing) = jobs.values().find(|job| {
                job.case_id == input.case_id
                    && job.request_id.as_deref() == Some(request_id)
                    && job.expires_at > now
            })
        {
            return Ok(SubmitJobResult {
                deduplicated: true,
                status: to_job_status(existing),
            });
        }

        let job_id = Uuid::new_v4().to_string();
        let expires_at = now + chrono::Duration::hours(self.inner.job_ttl_hours as i64);
        let record = StoredJob {
            schema_version: JOB_SCHEMA_VERSION.to_string(),
            job_id: job_id.clone(),
            case_id: input.case_id,
            request_id: input.request_id,
            status: ServiceNowJobState::Queued,
            created_at: now,
            updated_at: now,
            expires_at,
            started_at: None,
            finished_at: None,
            submitted_by: input.submitted_by,
            submitted_role: input.submitted_role,
            source_ip: input.source_ip,
            include_csv: input.request.include_csv,
            request: input.request,
            result: None,
            csv_data: None,
            csv_token: None,
            error: None,
        };
        save_job(&self.inner.jobs_dir, &record).await?;
        let status = to_job_status(&record);
        jobs.insert(job_id, record);
        Ok(SubmitJobResult {
            deduplicated: false,
            status,
        })
    }

    pub async fn mark_running(
        &self,
        job_id: &str,
    ) -> Result<Option<ServiceNowInvestigationJobStatus>> {
        let mut jobs = self.inner.jobs.write().await;
        let Some(job) = jobs.get_mut(job_id) else {
            return Ok(None);
        };
        let now = Utc::now();
        job.status = ServiceNowJobState::Running;
        job.started_at = Some(now);
        job.updated_at = now;
        job.error = None;
        save_job(&self.inner.jobs_dir, job).await?;
        Ok(Some(to_job_status(job)))
    }

    pub async fn mark_completed(
        &self,
        job_id: &str,
        mut result: ServiceNowInvestigationResult,
        csv_data: Option<String>,
        csv_token: Option<String>,
    ) -> Result<Option<ServiceNowInvestigationJobStatus>> {
        let mut jobs = self.inner.jobs.write().await;
        let Some(job) = jobs.get_mut(job_id) else {
            return Ok(None);
        };
        let now = Utc::now();
        job.status = ServiceNowJobState::Completed;
        job.updated_at = now;
        job.finished_at = Some(now);
        job.error = None;
        job.csv_data = csv_data;
        job.csv_token = csv_token;
        result.job_id = job.job_id.clone();
        result.case_id = job.case_id.clone();
        result.request_id = job.request_id.clone();
        result.expires_at = job.expires_at;
        job.result = Some(result);
        save_job(&self.inner.jobs_dir, job).await?;
        Ok(Some(to_job_status(job)))
    }

    pub async fn mark_failed(
        &self,
        job_id: &str,
        message: String,
    ) -> Result<Option<ServiceNowInvestigationJobStatus>> {
        let mut jobs = self.inner.jobs.write().await;
        let Some(job) = jobs.get_mut(job_id) else {
            return Ok(None);
        };
        let now = Utc::now();
        job.status = ServiceNowJobState::Failed;
        job.updated_at = now;
        job.finished_at = Some(now);
        job.error = Some(trim_error(&message));
        job.result = None;
        job.csv_data = None;
        job.csv_token = None;
        save_job(&self.inner.jobs_dir, job).await?;
        Ok(Some(to_job_status(job)))
    }

    pub async fn job_status(
        &self,
        job_id: &str,
    ) -> Result<Option<ServiceNowInvestigationJobStatus>> {
        self.expire_jobs_if_needed().await?;
        let jobs = self.inner.jobs.read().await;
        Ok(jobs.get(job_id).map(to_job_status))
    }

    pub async fn job_input(&self, job_id: &str) -> Result<Option<ServiceNowJobInput>> {
        self.expire_jobs_if_needed().await?;
        let jobs = self.inner.jobs.read().await;
        let Some(job) = jobs.get(job_id) else {
            return Ok(None);
        };
        Ok(Some(ServiceNowJobInput {
            submitted_by: job.submitted_by.clone(),
            submitted_role: job.submitted_role,
            source_ip: job.source_ip.clone(),
            case_id: job.case_id.clone(),
            request_id: job.request_id.clone(),
            request: job.request.clone(),
        }))
    }

    pub async fn job_result(&self, job_id: &str) -> Result<Option<ServiceNowInvestigationResult>> {
        self.expire_jobs_if_needed().await?;
        let jobs = self.inner.jobs.read().await;
        Ok(jobs.get(job_id).and_then(|job| job.result.clone()))
    }

    pub async fn csv_for_job(&self, job_id: &str, token: &str) -> Result<Option<String>> {
        self.expire_jobs_if_needed().await?;
        let jobs = self.inner.jobs.read().await;
        let Some(job) = jobs.get(job_id) else {
            return Ok(None);
        };
        if job.status != ServiceNowJobState::Completed {
            return Ok(None);
        }
        match (job.csv_token.as_deref(), job.csv_data.as_ref()) {
            (Some(stored), Some(data)) if stored == token => Ok(Some(data.clone())),
            _ => Ok(None),
        }
    }

    pub async fn cleanup_expired(&self) -> Result<()> {
        self.expire_jobs_if_needed().await?;
        let now = Utc::now();
        let mut jobs = self.inner.jobs.write().await;
        let removable = jobs
            .iter()
            .filter_map(|(id, job)| {
                if job.status == ServiceNowJobState::Expired
                    && now - job.updated_at > chrono::Duration::seconds(EXPIRED_JOB_GRACE_SECS)
                {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for id in removable {
            jobs.remove(&id);
            let path = job_path_for(&self.inner.jobs_dir, &id);
            if let Err(err) = tokio::fs::remove_file(&path).await
                && err.kind() != std::io::ErrorKind::NotFound
            {
                warn!(error = %err, path = %path.display(), "failed removing expired servicenow job");
            }
        }
        Ok(())
    }

    async fn expire_jobs_if_needed(&self) -> Result<()> {
        let mut jobs = self.inner.jobs.write().await;
        let now = Utc::now();
        for job in jobs.values_mut() {
            if job.expires_at <= now && job.status != ServiceNowJobState::Expired {
                job.status = ServiceNowJobState::Expired;
                job.updated_at = now;
                job.result = None;
                job.csv_data = None;
                job.csv_token = None;
                job.error = Some("job expired".to_string());
                save_job(&self.inner.jobs_dir, job).await?;
            }
        }
        Ok(())
    }

    async fn load_existing_jobs(&self) -> Result<()> {
        let mut entries = tokio::fs::read_dir(&self.inner.jobs_dir)
            .await
            .with_context(|| {
                format!("failed reading jobs dir {}", self.inner.jobs_dir.display())
            })?;
        let mut jobs = HashMap::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_type = entry.file_type().await?;
            if !file_type.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if !name.ends_with(".json") {
                continue;
            }
            let payload = tokio::fs::read(&path)
                .await
                .with_context(|| format!("failed reading {}", path.display()))?;
            let mut job: StoredJob = serde_json::from_slice(&payload)
                .with_context(|| format!("failed parsing {}", path.display()))?;
            if job.schema_version != JOB_SCHEMA_VERSION {
                continue;
            }
            if job.job_id.trim().is_empty() {
                continue;
            }
            if job.expires_at <= Utc::now() {
                job.status = ServiceNowJobState::Expired;
                job.result = None;
                job.csv_data = None;
                job.csv_token = None;
                job.error = Some("job expired".to_string());
                job.updated_at = Utc::now();
            }
            jobs.insert(job.job_id.clone(), job);
        }
        let mut guard = self.inner.jobs.write().await;
        *guard = jobs;
        Ok(())
    }
}

fn validate_submit_input(req: &ServiceNowInvestigationSubmitRequest) -> Result<()> {
    let case_id = req.case_id.trim();
    if case_id.is_empty() {
        anyhow::bail!("case_id is required");
    }
    if case_id.chars().count() > 128 {
        anyhow::bail!("case_id exceeds 128 characters");
    }
    if let Some(request_id) = req.request_id.as_deref() {
        let value = request_id.trim();
        if value.is_empty() {
            anyhow::bail!("request_id cannot be empty when provided");
        }
        if value.chars().count() > 128 {
            anyhow::bail!("request_id exceeds 128 characters");
        }
    }
    Ok(())
}

fn trim_error(message: &str) -> String {
    let compact = message.trim();
    if compact.chars().count() <= 240 {
        compact.to_string()
    } else {
        let mut out = compact.chars().take(237).collect::<String>();
        out.push_str("...");
        out
    }
}

fn to_job_status(job: &StoredJob) -> ServiceNowInvestigationJobStatus {
    ServiceNowInvestigationJobStatus {
        schema_version: job.schema_version.clone(),
        job_id: job.job_id.clone(),
        case_id: job.case_id.clone(),
        request_id: job.request_id.clone(),
        status: job.status,
        created_at: job.created_at,
        updated_at: job.updated_at,
        expires_at: job.expires_at,
        started_at: job.started_at,
        finished_at: job.finished_at,
        result_available: job.result.is_some(),
        error: job.error.clone(),
    }
}

fn job_path_for(root: &Path, job_id: &str) -> PathBuf {
    root.join(format!("{job_id}.json"))
}

async fn save_job(root: &Path, job: &StoredJob) -> Result<()> {
    let path = job_path_for(root, &job.job_id);
    let tmp_path = root.join(format!("{}.tmp", job.job_id));
    let payload = serde_json::to_vec_pretty(job).context("failed encoding servicenow job")?;
    tokio::fs::write(&tmp_path, &payload)
        .await
        .with_context(|| format!("failed writing {}", tmp_path.display()))?;
    #[cfg(unix)]
    tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("failed setting perms on {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, &path)
        .await
        .with_context(|| format!("failed moving {} to {}", tmp_path.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoleName;
    use crate::models::{SearchFilters, SearchRequest, ServiceNowJobState};
    use chrono::{TimeZone, Utc};

    fn sample_request(
        case_id: &str,
        request_id: Option<&str>,
    ) -> ServiceNowInvestigationSubmitRequest {
        ServiceNowInvestigationSubmitRequest {
            case_id: case_id.to_string(),
            request_id: request_id.map(ToString::to_string),
            search: SearchRequest {
                time_from: Utc.with_ymd_and_hms(2026, 4, 5, 10, 0, 0).unwrap(),
                time_to: Utc.with_ymd_and_hms(2026, 4, 5, 11, 0, 0).unwrap(),
                filters: SearchFilters::default(),
                limit: Some(100),
                columns: None,
            },
            pcap_context: None,
            include_csv: false,
        }
    }

    #[tokio::test]
    async fn submit_is_idempotent_for_case_and_request_id() {
        let root = std::env::temp_dir().join(format!("nss-quarry-snow-jobs-{}", Uuid::new_v4()));
        let svc = ServiceNowIntegrationService::new(root, 24, 60)
            .await
            .expect("service");

        let first = svc
            .submit_job(ServiceNowJobInput {
                submitted_by: "svc".to_string(),
                submitted_role: RoleName::Analyst,
                source_ip: Some("127.0.0.1".to_string()),
                case_id: "INC001".to_string(),
                request_id: Some("REQ001".to_string()),
                request: sample_request("INC001", Some("REQ001")),
            })
            .await
            .expect("first");
        assert!(!first.deduplicated);

        let second = svc
            .submit_job(ServiceNowJobInput {
                submitted_by: "svc".to_string(),
                submitted_role: RoleName::Analyst,
                source_ip: Some("127.0.0.1".to_string()),
                case_id: "INC001".to_string(),
                request_id: Some("REQ001".to_string()),
                request: sample_request("INC001", Some("REQ001")),
            })
            .await
            .expect("second");
        assert!(second.deduplicated);
        assert_eq!(first.status.job_id, second.status.job_id);
    }

    #[tokio::test]
    async fn completed_job_exposes_status() {
        let root = std::env::temp_dir().join(format!("nss-quarry-snow-jobs-{}", Uuid::new_v4()));
        let svc = ServiceNowIntegrationService::new(root, 24, 60)
            .await
            .expect("service");
        let created = svc
            .submit_job(ServiceNowJobInput {
                submitted_by: "svc".to_string(),
                submitted_role: RoleName::Analyst,
                source_ip: Some("127.0.0.1".to_string()),
                case_id: "INC002".to_string(),
                request_id: Some("REQ002".to_string()),
                request: sample_request("INC002", Some("REQ002")),
            })
            .await
            .expect("create");
        let job_id = created.status.job_id.clone();

        svc.mark_running(&job_id).await.expect("running");
        let running = svc.job_status(&job_id).await.expect("status").expect("job");
        assert_eq!(running.status, ServiceNowJobState::Running);
    }
}
