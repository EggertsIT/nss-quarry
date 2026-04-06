use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use tokio::sync::RwLock;
use tracing::warn;
use uuid::Uuid;

use crate::models::{
    InvestigationPinnedItem, InvestigationPivot, InvestigationPivotInput, InvestigationSession,
    InvestigationUpdateRequest, SearchFilters, SearchRequest,
};

const STORE_VERSION: u32 = 1;
const DEFAULT_TTL_HOURS: i64 = 24;
const CLEANUP_INTERVAL_SECS: u64 = 3600;
const MAX_SESSIONS: usize = 2_000;
const MAX_PINNED_ITEMS_PER_SESSION: usize = 500;
const MAX_ROW_FIELDS: usize = 512;
const MAX_NOTE_TEXT_LEN: usize = 512;
const MAX_FILTER_TEXT_LEN: usize = 8_192;
const MAX_CSV_FILTER_TEXT_LEN: usize = 200_000;
const MAX_CSV_FILTER_VALUES: usize = 6_000;
const MAX_ROW_TEXT_LEN: usize = 2_048;
const MAX_PIVOTS_PER_SESSION: usize = 100;

#[derive(Clone)]
pub struct InvestigationService {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    ttl: Duration,
    input_value_re: Regex,
    sessions: RwLock<HashMap<String, InvestigationSession>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InvestigationStore {
    version: u32,
    sessions: Vec<InvestigationSession>,
}

impl Default for InvestigationStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            sessions: Vec::new(),
        }
    }
}

impl InvestigationService {
    pub async fn new(path: PathBuf, ttl_hours: i64, input_value_regex: &str) -> Result<Self> {
        let ttl = Duration::hours(ttl_hours.max(DEFAULT_TTL_HOURS));
        let input_value_re = Regex::new(input_value_regex)
            .with_context(|| "invalid security.input_value_regex".to_string())?;
        let sessions = load_sessions(&path, ttl).await?;
        Ok(Self {
            inner: Arc::new(Inner {
                path,
                ttl,
                input_value_re,
                sessions: RwLock::new(sessions),
            }),
        })
    }

    pub fn start_maintenance(&self) {
        let svc = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(err) = svc.cleanup_expired().await {
                    warn!(error = %err, "investigation session cleanup failed");
                }
            }
        });
    }

    pub async fn create(&self, owner: &str, search: SearchRequest) -> Result<InvestigationSession> {
        validate_search_request(&search, &self.inner.input_value_re)?;
        let now = Utc::now();
        let session = InvestigationSession {
            id: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            expires_at: now + self.inner.ttl,
            owner: owner.to_string(),
            search,
            pivots: Vec::new(),
            pinned_items: Vec::new(),
        };
        let snapshot = {
            let mut guard = self.inner.sessions.write().await;
            purge_expired_locked(&mut guard, now);
            enforce_max_sessions_locked(&mut guard);
            guard.insert(session.id.clone(), session.clone());
            collect_snapshot_locked(&guard)
        };
        self.persist_snapshot(snapshot).await?;
        Ok(session)
    }

    pub async fn get(&self, id: &str) -> Result<Option<InvestigationSession>> {
        let now = Utc::now();
        let (session, changed, snapshot) = {
            let mut guard = self.inner.sessions.write().await;
            let changed = purge_expired_locked(&mut guard, now);
            let session = guard.get(id).cloned();
            let snapshot = if changed {
                Some(collect_snapshot_locked(&guard))
            } else {
                None
            };
            (session, changed, snapshot)
        };
        if changed && let Some(snapshot) = snapshot {
            self.persist_snapshot(snapshot).await?;
        }
        Ok(session)
    }

    pub async fn apply_update(
        &self,
        id: &str,
        update: InvestigationUpdateRequest,
    ) -> Result<Option<InvestigationSession>> {
        self.mutate_session(id, move |session, input_value_re| {
            if let Some(time_from) = update.time_from {
                session.search.time_from = time_from;
            }
            if let Some(time_to) = update.time_to {
                session.search.time_to = time_to;
            }
            if let Some(filters) = update.filters {
                validate_filters(&filters, input_value_re)?;
                session.search.filters = filters;
            }
            if let Some(columns) = update.columns {
                validate_columns(&columns)?;
                session.search.columns = if columns.is_empty() {
                    None
                } else {
                    Some(columns)
                };
            }
            if let Some(limit) = update.limit {
                session.search.limit = Some(limit.max(1));
            }
            if let Some(page) = update.page {
                session.search.page = Some(page.max(1));
            }
            if let Some(page_size) = update.page_size {
                session.search.page_size = Some(page_size.max(1));
            }
            if let Some(pivots) = update.pivots {
                session.pivots = build_pivots(pivots, input_value_re)?;
            }
            validate_search_request(&session.search, input_value_re)?;
            Ok(())
        })
        .await
    }

    pub async fn add_pin(
        &self,
        id: &str,
        row: serde_json::Map<String, serde_json::Value>,
        note: Option<String>,
    ) -> Result<Option<InvestigationSession>> {
        self.mutate_session(id, move |session, _input_value_re| {
            if session.pinned_items.len() >= MAX_PINNED_ITEMS_PER_SESSION {
                anyhow::bail!(
                    "max pinned items reached (max {})",
                    MAX_PINNED_ITEMS_PER_SESSION
                );
            }
            validate_pin_row(&row)?;
            let normalized_note = note
                .as_deref()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(|text| text.chars().take(MAX_NOTE_TEXT_LEN).collect::<String>());
            session.pinned_items.push(InvestigationPinnedItem {
                id: Uuid::new_v4().to_string(),
                pinned_at: Utc::now(),
                note: normalized_note,
                row,
            });
            Ok(())
        })
        .await
    }

    pub async fn remove_pin(&self, id: &str, pin_id: &str) -> Result<Option<InvestigationSession>> {
        self.mutate_session(id, move |session, _| {
            session.pinned_items.retain(|pin| pin.id != pin_id);
            Ok(())
        })
        .await
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let now = Utc::now();
        let snapshot = {
            let mut guard = self.inner.sessions.write().await;
            if !purge_expired_locked(&mut guard, now) {
                return Ok(());
            }
            collect_snapshot_locked(&guard)
        };
        self.persist_snapshot(snapshot).await
    }

    async fn mutate_session<F>(&self, id: &str, mutate: F) -> Result<Option<InvestigationSession>>
    where
        F: FnOnce(&mut InvestigationSession, &Regex) -> Result<()>,
    {
        let now = Utc::now();
        let (out, snapshot) = {
            let mut guard = self.inner.sessions.write().await;
            purge_expired_locked(&mut guard, now);
            let Some(session) = guard.get_mut(id) else {
                return Ok(None);
            };
            mutate(session, &self.inner.input_value_re)?;
            session.updated_at = now;
            session.expires_at = now + self.inner.ttl;
            let out = session.clone();
            (out, collect_snapshot_locked(&guard))
        };
        self.persist_snapshot(snapshot).await?;
        Ok(Some(out))
    }

    async fn persist_snapshot(&self, sessions: Vec<InvestigationSession>) -> Result<()> {
        let store = InvestigationStore {
            version: STORE_VERSION,
            sessions,
        };
        if let Some(parent) = self.inner.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        let tmp = self
            .inner
            .path
            .with_extension(format!("tmp.{}", Uuid::new_v4()));
        let payload = serde_json::to_vec_pretty(&store)?;
        tokio::fs::write(&tmp, payload)
            .await
            .with_context(|| format!("failed writing {}", tmp.display()))?;
        tokio::fs::rename(&tmp, &self.inner.path)
            .await
            .with_context(|| format!("failed replacing {}", self.inner.path.display()))?;
        Ok(())
    }
}

fn collect_snapshot_locked(
    sessions: &HashMap<String, InvestigationSession>,
) -> Vec<InvestigationSession> {
    let mut out = sessions.values().cloned().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn enforce_max_sessions_locked(sessions: &mut HashMap<String, InvestigationSession>) {
    if sessions.len() < MAX_SESSIONS {
        return;
    }
    let mut ordered = sessions
        .values()
        .map(|session| (session.id.clone(), session.updated_at))
        .collect::<Vec<_>>();
    ordered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let remove_count = sessions.len().saturating_sub(MAX_SESSIONS) + 1;
    for (id, _) in ordered.into_iter().take(remove_count) {
        sessions.remove(&id);
    }
}

fn purge_expired_locked(
    sessions: &mut HashMap<String, InvestigationSession>,
    now: DateTime<Utc>,
) -> bool {
    let before = sessions.len();
    sessions.retain(|_, session| session.expires_at > now);
    sessions.len() != before
}

async fn load_sessions(
    path: &Path,
    ttl: Duration,
) -> Result<HashMap<String, InvestigationSession>> {
    let raw = match tokio::fs::read_to_string(path).await {
        Ok(v) => v,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed reading {}", path.display()));
        }
    };
    if raw.trim().is_empty() {
        return Ok(HashMap::new());
    }
    let mut store: InvestigationStore = serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing investigations {}", path.display()))?;
    if store.version != STORE_VERSION {
        return Ok(HashMap::new());
    }
    let now = Utc::now();
    let mut out = HashMap::new();
    for mut session in store.sessions.drain(..) {
        if session.expires_at <= now {
            continue;
        }
        if session.expires_at - session.updated_at > ttl + Duration::hours(1) {
            session.expires_at = session.updated_at + ttl;
        }
        out.insert(session.id.clone(), session);
    }
    Ok(out)
}

fn build_pivots(
    pivots: Vec<InvestigationPivotInput>,
    input_value_re: &Regex,
) -> Result<Vec<InvestigationPivot>> {
    if pivots.len() > MAX_PIVOTS_PER_SESSION {
        anyhow::bail!("max pivots reached (max {})", MAX_PIVOTS_PER_SESSION);
    }
    let now = Utc::now();
    let mut out = Vec::with_capacity(pivots.len());
    for pivot in pivots {
        validate_identifier(&pivot.field)?;
        validate_filter_text(&pivot.value, input_value_re, false)?;
        out.push(InvestigationPivot {
            id: Uuid::new_v4().to_string(),
            field: pivot.field.trim().to_string(),
            value: pivot.value.trim().to_string(),
            created_at: now,
        });
    }
    Ok(out)
}

fn validate_search_request(req: &SearchRequest, input_value_re: &Regex) -> Result<()> {
    if req.time_to <= req.time_from {
        anyhow::bail!("time_to must be later than time_from");
    }
    validate_filters(&req.filters, input_value_re)?;
    if let Some(columns) = req.columns.as_ref() {
        validate_columns(columns)?;
    }
    Ok(())
}

fn validate_columns(columns: &[String]) -> Result<()> {
    for col in columns {
        validate_identifier(col)?;
    }
    Ok(())
}

fn validate_filters(filters: &SearchFilters, input_value_re: &Regex) -> Result<()> {
    validate_filter_value(filters.user.as_deref(), input_value_re, false)?;
    validate_filter_value(filters.url.as_deref(), input_value_re, false)?;
    validate_filter_value(filters.action.as_deref(), input_value_re, false)?;
    validate_filter_value(filters.response_code.as_deref(), input_value_re, true)?;
    validate_filter_value(filters.reason.as_deref(), input_value_re, false)?;
    validate_filter_value(filters.threat.as_deref(), input_value_re, false)?;
    validate_filter_value(filters.category.as_deref(), input_value_re, false)?;
    validate_filter_value(filters.source_ip.as_deref(), input_value_re, true)?;
    validate_filter_value(filters.server_ip.as_deref(), input_value_re, true)?;
    validate_filter_value(filters.source_country.as_deref(), input_value_re, true)?;
    validate_filter_value(filters.destination_country.as_deref(), input_value_re, true)?;
    validate_filter_value(filters.device.as_deref(), input_value_re, false)?;
    validate_filter_value(filters.department.as_deref(), input_value_re, false)?;
    Ok(())
}

fn validate_filter_text(value: &str, input_value_re: &Regex, allow_csv: bool) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if !allow_csv && trimmed.len() > MAX_FILTER_TEXT_LEN {
        anyhow::bail!("filter value exceeds {MAX_FILTER_TEXT_LEN} characters");
    }
    if allow_csv && trimmed.len() > MAX_CSV_FILTER_TEXT_LEN {
        anyhow::bail!("filter CSV value exceeds {MAX_CSV_FILTER_TEXT_LEN} characters");
    }
    if !input_value_re.is_match(trimmed) {
        anyhow::bail!("filter value contains disallowed characters");
    }
    Ok(())
}

fn validate_filter_value(
    value: Option<&str>,
    input_value_re: &Regex,
    allow_csv: bool,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if allow_csv {
        let parts = split_csv_values(value);
        if parts.len() > MAX_CSV_FILTER_VALUES {
            anyhow::bail!("too many CSV filter values (max {})", MAX_CSV_FILTER_VALUES);
        }
        for part in parts {
            validate_filter_text(&part, input_value_re, false)?;
        }
        return Ok(());
    }
    validate_filter_text(value, input_value_re, false)
}

fn split_csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn validate_pin_row(row: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    if row.is_empty() {
        anyhow::bail!("pin row cannot be empty");
    }
    if row.len() > MAX_ROW_FIELDS {
        anyhow::bail!("pin row has too many fields (max {MAX_ROW_FIELDS})");
    }
    for (key, value) in row {
        validate_identifier(key)?;
        validate_pin_value(value)?;
    }
    Ok(())
}

fn validate_pin_value(value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Null => Ok(()),
        serde_json::Value::Bool(_) => Ok(()),
        serde_json::Value::Number(_) => Ok(()),
        serde_json::Value::String(text) => validate_pin_text(text),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            anyhow::bail!("pin row value must be a scalar (string/number/bool/null)")
        }
    }
}

fn validate_pin_text(value: &str) -> Result<()> {
    if value.chars().count() > MAX_ROW_TEXT_LEN {
        anyhow::bail!("pin row value exceeds {MAX_ROW_TEXT_LEN} characters");
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        anyhow::bail!("pin row value contains invalid control characters");
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("identifier cannot be empty");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        anyhow::bail!("identifier contains disallowed characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn test_search_request() -> SearchRequest {
        SearchRequest {
            time_from: Utc.with_ymd_and_hms(2026, 4, 6, 10, 0, 0).unwrap(),
            time_to: Utc.with_ymd_and_hms(2026, 4, 6, 11, 0, 0).unwrap(),
            filters: SearchFilters::default(),
            limit: Some(500),
            page: Some(1),
            page_size: Some(200),
            columns: Some(vec![
                "time".to_string(),
                "action".to_string(),
                "sip".to_string(),
            ]),
        }
    }

    #[tokio::test]
    async fn session_create_update_pin_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "nss-quarry-investigation-test-{}.json",
            Uuid::new_v4()
        ));
        let svc = InvestigationService::new(
            path.clone(),
            24,
            r#"^[A-Za-z0-9@\._:/,\-\s\(\)\[\]\{\}\|%=&\?"+#!;]{0,1024}$"#,
        )
        .await
        .expect("service");

        let created = svc
            .create("analyst@example.com", test_search_request())
            .await
            .expect("create");
        assert!(!created.id.is_empty());

        let fetched = svc.get(&created.id).await.expect("get").expect("exists");
        assert_eq!(fetched.owner, "analyst@example.com");

        let updated = svc
            .apply_update(
                &created.id,
                InvestigationUpdateRequest {
                    time_from: None,
                    time_to: None,
                    filters: Some(SearchFilters {
                        server_ip: Some("1.1.1.1, 8.8.8.8".to_string()),
                        reason: Some("Not allowed to browse this category".to_string()),
                        ..SearchFilters::default()
                    }),
                    columns: None,
                    limit: Some(1000),
                    page: Some(2),
                    page_size: Some(250),
                    pivots: Some(vec![
                        InvestigationPivotInput {
                            field: "reason".to_string(),
                            value: "Not allowed to browse this category".to_string(),
                        },
                        InvestigationPivotInput {
                            field: "respcode".to_string(),
                            value: "403".to_string(),
                        },
                    ]),
                },
            )
            .await
            .expect("update")
            .expect("updated session");
        assert_eq!(updated.search.page, Some(2));
        assert_eq!(updated.pivots.len(), 2);

        let pinned = svc
            .add_pin(
                &created.id,
                serde_json::json!({
                    "time": "2026-04-06 10:15:00",
                    "action": "Blocked",
                    "reason": "Not allowed to browse this category",
                    "sip": "8.8.8.8"
                })
                .as_object()
                .expect("object")
                .clone(),
                Some("ticket correlation".to_string()),
            )
            .await
            .expect("pin")
            .expect("session after pin");
        assert_eq!(pinned.pinned_items.len(), 1);

        let pin_id = pinned.pinned_items[0].id.clone();
        let unpinned = svc
            .remove_pin(&created.id, &pin_id)
            .await
            .expect("remove pin")
            .expect("session after remove");
        assert!(unpinned.pinned_items.is_empty());

        let _ = tokio::fs::remove_file(path).await;
    }

    #[test]
    fn pin_row_allows_realistic_log_values() {
        let row = serde_json::json!({
            "url": "caching.graphql.imdb.com/?operationName=WinnersWidget&variables={\"enableOverride\":false,\"locale\":\"en-GB\"}",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "respcode": "403",
            "reason": "Not allowed to browse this category"
        })
        .as_object()
        .expect("object")
        .clone();
        validate_pin_row(&row).expect("pin row should validate");
    }

    #[test]
    fn pin_row_rejects_nested_json_values() {
        let row = serde_json::json!({
            "time": "2026-04-06 10:15:00",
            "payload": { "nested": "value" }
        })
        .as_object()
        .expect("object")
        .clone();
        let err = validate_pin_row(&row).expect_err("nested values should fail");
        assert!(err.to_string().contains("scalar"));
    }
}
