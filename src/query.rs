use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, NaiveDateTime, Timelike, Utc};
use duckdb::Connection;
use regex::Regex;
use tracing::{error, warn};

use crate::config::{AppConfig, FieldMap, RoleName};
use crate::models::{
    DashboardResponse, DashboardStatus, MetricCard, SearchFilters, SearchGroupedResponse,
    SearchRequest, SearchResponse, SearchTimelineMarker, SearchTimelinePoint,
    SearchTimelineResponse, SearchTriageBucket, SearchTriageResponse, SearchViewMode,
    SupportSummaryItem, TableBlock,
};

const MIN_SEARCH_TIMEOUT_MS: u64 = 60_000;
const DUCKDB_MEMORY_LIMIT: &str = "512MB";
const DUCKDB_THREADS: u32 = 2;
const DASHBOARD_SNAPSHOT_VERSION: u32 = 3;
const DASHBOARD_TOP_LIMIT: usize = 10;
const DASHBOARD_FLOW_LIMIT: usize = 240;
const MAX_DASHBOARD_DELTA_RANGE_HOURS: i64 = 2;

#[derive(Clone)]
pub struct QueryService {
    inner: Arc<QueryInner>,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct VisibilityFilters {
    #[serde(default)]
    pub url_regex: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct CompiledVisibilityFilters {
    raw: VisibilityFilters,
    compiled_url_regex: Vec<Regex>,
    blocked_ip_set: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardRefreshMode {
    Normal,
    Delta,
}

#[derive(Debug, Clone)]
pub struct GroupedSearchOptions {
    pub view_mode: SearchViewMode,
    pub sort_by: Option<String>,
    pub sort_desc: Option<bool>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DashboardSnapshot {
    version: u32,
    name: String,
    generated_at: DateTime<Utc>,
    data_window_from: DateTime<Utc>,
    data_window_to: DateTime<Utc>,
    aggregate: DashboardAggregate,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct DashboardAggregate {
    events: i64,
    blocked: i64,
    threats: i64,
    top_users: BTreeMap<String, i64>,
    top_categories: BTreeMap<String, i64>,
    top_devices: BTreeMap<String, i64>,
    top_source_ips: BTreeMap<String, i64>,
    top_departments: BTreeMap<String, i64>,
    #[serde(default)]
    top_response_codes: BTreeMap<String, i64>,
    #[serde(default)]
    top_policy_reasons: BTreeMap<String, i64>,
    country_flows: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Default)]
struct DashboardRefreshState {
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_error_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

struct QueryInner {
    parquet_root: PathBuf,
    fields: FieldMap,
    default_columns: Vec<String>,
    helpdesk_mask_fields: Vec<String>,
    visibility_filters: RwLock<CompiledVisibilityFilters>,
    dashboard_snapshot_dir: PathBuf,
    dashboard_snapshot_cache: RwLock<HashMap<String, DashboardSnapshot>>,
    dashboard_snapshot_refresh_secs: u64,
    dashboard_refresh_in_progress: AtomicBool,
    dashboard_refresh_state: RwLock<DashboardRefreshState>,
    input_value_re: Regex,
    max_days_per_query: i64,
    default_limit: u32,
    max_rows: u32,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct TimelineBucketAggregate {
    total: usize,
    blocked: usize,
    policy: usize,
    ssl_tls: usize,
    zero_response: usize,
    geo: usize,
    threat: usize,
    reason_counts: HashMap<String, usize>,
    destination_counts: HashMap<String, usize>,
    threat_counts: HashMap<String, usize>,
}

impl QueryService {
    pub fn new(cfg: &AppConfig) -> Result<Self> {
        let input_value_re = Regex::new(&cfg.security.input_value_regex)
            .with_context(|| "invalid security.input_value_regex".to_string())?;
        Ok(Self {
            inner: Arc::new(QueryInner {
                parquet_root: cfg.data.parquet_root.clone(),
                fields: cfg.data.fields.clone(),
                default_columns: cfg.query.default_columns.clone(),
                helpdesk_mask_fields: cfg.security.helpdesk_mask_fields.clone(),
                visibility_filters: RwLock::new(CompiledVisibilityFilters::default()),
                dashboard_snapshot_dir: dashboard_snapshot_dir(cfg),
                dashboard_snapshot_cache: RwLock::new(HashMap::new()),
                dashboard_snapshot_refresh_secs: cfg.query.dashboard_snapshot_refresh_secs,
                dashboard_refresh_in_progress: AtomicBool::new(false),
                dashboard_refresh_state: RwLock::new(DashboardRefreshState::default()),
                input_value_re,
                max_days_per_query: cfg.query.max_days_per_query,
                default_limit: cfg.query.default_limit,
                max_rows: cfg.query.max_rows,
                timeout_ms: cfg.query.timeout_ms,
            }),
        })
    }

    pub async fn ready_check(&self) -> Result<()> {
        let root = self.inner.parquet_root.clone();
        let has_data = tokio::task::spawn_blocking(move || find_any_parquet(&root))
            .await
            .context("ready check join error")??;
        if !has_data {
            anyhow::bail!("no parquet files found under configured parquet_root");
        }
        Ok(())
    }

    pub async fn search(&self, req: SearchRequest, role: RoleName) -> Result<SearchResponse> {
        let svc = self.clone();
        let work = tokio::task::spawn_blocking(move || svc.search_sync(req, role));
        let result = tokio::time::timeout(
            Duration::from_millis(self.inner.timeout_ms.max(MIN_SEARCH_TIMEOUT_MS)),
            work,
        )
        .await
        .map_err(|_| anyhow::anyhow!("query timed out"))?
        .context("search worker failed")??;
        Ok(result)
    }

    pub async fn search_timeline(
        &self,
        req: SearchRequest,
        role: RoleName,
        bucket_minutes: Option<u32>,
    ) -> Result<SearchTimelineResponse> {
        let svc = self.clone();
        let work = tokio::task::spawn_blocking(move || {
            svc.search_timeline_sync(req, role, bucket_minutes)
        });
        let result = tokio::time::timeout(
            Duration::from_millis(self.inner.timeout_ms.max(MIN_SEARCH_TIMEOUT_MS)),
            work,
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeline query timed out"))?
        .context("timeline worker failed")??;
        Ok(result)
    }

    pub async fn search_triage(
        &self,
        req: SearchRequest,
        role: RoleName,
    ) -> Result<SearchTriageResponse> {
        let svc = self.clone();
        let work = tokio::task::spawn_blocking(move || svc.search_triage_sync(req, role));
        let result = tokio::time::timeout(
            Duration::from_millis(self.inner.timeout_ms.max(MIN_SEARCH_TIMEOUT_MS)),
            work,
        )
        .await
        .map_err(|_| anyhow::anyhow!("triage query timed out"))?
        .context("triage worker failed")??;
        Ok(result)
    }

    pub async fn search_grouped(
        &self,
        req: SearchRequest,
        role: RoleName,
        opts: GroupedSearchOptions,
    ) -> Result<SearchGroupedResponse> {
        let svc = self.clone();
        let work = tokio::task::spawn_blocking(move || svc.search_grouped_sync(req, role, opts));
        let result = tokio::time::timeout(
            Duration::from_millis(self.inner.timeout_ms.max(MIN_SEARCH_TIMEOUT_MS)),
            work,
        )
        .await
        .map_err(|_| anyhow::anyhow!("grouped query timed out"))?
        .context("grouped worker failed")??;
        Ok(result)
    }

    pub async fn export_csv(&self, req: SearchRequest, role: RoleName) -> Result<String> {
        let result = self.search(req, role).await?;
        Ok(rows_to_csv(&result.rows))
    }

    pub fn start_dashboard_maintenance(&self) {
        let svc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = svc.refresh_dashboard_snapshot("overview").await {
                warn!(error = %err, "initial dashboard snapshot refresh failed");
            }
            let mut interval = tokio::time::interval(Duration::from_secs(
                svc.inner.dashboard_snapshot_refresh_secs.max(60),
            ));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(err) = svc.refresh_dashboard_snapshot("overview").await {
                    warn!(error = %err, "scheduled dashboard snapshot refresh failed");
                }
            }
        });
    }

    pub async fn dashboard(
        &self,
        name: &str,
        role: RoleName,
        refresh_mode: DashboardRefreshMode,
    ) -> Result<DashboardResponse> {
        let now = Utc::now();
        let Some(snapshot) = self.dashboard_snapshot_get(name)? else {
            self.spawn_dashboard_snapshot_refresh(name.to_string());
            let refresh_state = self.dashboard_refresh_state_value();
            let mut notes =
                vec!["Dashboard snapshot is building. Refresh again shortly.".to_string()];
            let (status, source) = if let Some(err) = refresh_state.last_error.clone() {
                notes = vec![
                    "Dashboard snapshot is currently unavailable. A background rebuild has been scheduled.".to_string(),
                    format!("Last refresh error: {err}"),
                ];
                (DashboardStatus::Degraded, "snapshot_unavailable")
            } else {
                (DashboardStatus::Warming, "warming")
            };
            return Ok(empty_dashboard_response(
                name,
                now,
                status,
                source,
                notes,
                self.inner
                    .dashboard_refresh_in_progress
                    .load(Ordering::Relaxed),
                refresh_state,
            ));
        };

        if snapshot_needs_refresh(&snapshot, now, self.inner.dashboard_snapshot_refresh_secs) {
            self.spawn_dashboard_snapshot_refresh(name.to_string());
        }

        match refresh_mode {
            DashboardRefreshMode::Normal => Ok(self.render_dashboard_snapshot(
                &snapshot,
                role,
                now,
                "hourly_snapshot",
                default_dashboard_notes(&snapshot, now, self.inner.dashboard_snapshot_refresh_secs),
                None,
            )),
            DashboardRefreshMode::Delta => {
                if snapshot_needs_full_rebuild_before_delta(
                    &snapshot,
                    now,
                    self.inner.dashboard_snapshot_refresh_secs,
                ) {
                    self.spawn_dashboard_snapshot_refresh(name.to_string());
                    return Ok(self.render_dashboard_snapshot(
                        &snapshot,
                        role,
                        now,
                        "hourly_snapshot",
                        vec![
                            "Current snapshot is too old for a safe delta refresh. A background hourly rebuild was started."
                                .to_string(),
                        ],
                        None,
                    ));
                }
                match self.refresh_dashboard_delta(name, &snapshot).await {
                    Ok(Some(delta_snapshot)) => Ok(self.render_dashboard_snapshot(
                        &delta_snapshot,
                        role,
                        now,
                        "hourly_snapshot_plus_delta",
                        vec![
                            "Manual refresh merged finalized data newer than the hourly snapshot."
                                .to_string(),
                        ],
                        None,
                    )),
                    Ok(None) => Ok(self.render_dashboard_snapshot(
                        &snapshot,
                        role,
                        now,
                        "hourly_snapshot",
                        vec![
                            "No newer finalized parquet data was available for delta refresh."
                                .to_string(),
                        ],
                        None,
                    )),
                    Err(err) => {
                        warn!(error = %err, "dashboard delta refresh failed");
                        Ok(self.render_dashboard_snapshot(
                            &snapshot,
                            role,
                            now,
                            "hourly_snapshot",
                            vec![
                                "Delta refresh failed. Showing the latest hourly snapshot."
                                    .to_string(),
                            ],
                            Some(trim_dashboard_error_message(&err.to_string())),
                        ))
                    }
                }
            }
        }
    }

    pub async fn refresh_dashboard_snapshot(&self, name: &str) -> Result<()> {
        if self
            .inner
            .dashboard_refresh_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }

        self.record_dashboard_refresh_attempt(Utc::now());
        let result = self
            .refresh_dashboard_snapshot_inner(name)
            .await
            .and_then(|snapshot| {
                let generated_at = snapshot.generated_at;
                self.dashboard_snapshot_put(snapshot)?;
                self.record_dashboard_refresh_success(generated_at);
                Ok(())
            });
        if let Err(err) = &result {
            self.record_dashboard_refresh_failure(Utc::now(), err);
        }
        self.inner
            .dashboard_refresh_in_progress
            .store(false, Ordering::SeqCst);
        result
    }

    fn spawn_dashboard_snapshot_refresh(&self, name: String) {
        if self
            .inner
            .dashboard_refresh_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        self.record_dashboard_refresh_attempt(Utc::now());
        let svc = self.clone();
        tokio::spawn(async move {
            let result = svc
                .refresh_dashboard_snapshot_inner(&name)
                .await
                .and_then(|snapshot| {
                    let generated_at = snapshot.generated_at;
                    svc.dashboard_snapshot_put(snapshot)?;
                    svc.record_dashboard_refresh_success(generated_at);
                    Ok(())
                });
            if let Err(err) = result {
                svc.record_dashboard_refresh_failure(Utc::now(), &err);
                error!(error = %err, dashboard = %name, "dashboard snapshot refresh failed");
            }
            svc.inner
                .dashboard_refresh_in_progress
                .store(false, Ordering::SeqCst);
        });
    }

    pub fn visibility_filters(&self) -> Result<VisibilityFilters> {
        let guard = self
            .inner
            .visibility_filters
            .read()
            .map_err(|_| anyhow::anyhow!("visibility filters lock poisoned"))?;
        Ok(guard.raw.clone())
    }

    pub fn set_visibility_filters(&self, filters: VisibilityFilters) -> Result<()> {
        let compiled = compile_visibility_filters(filters)?;
        let mut guard = self
            .inner
            .visibility_filters
            .write()
            .map_err(|_| anyhow::anyhow!("visibility filters lock poisoned"))?;
        *guard = compiled;
        Ok(())
    }

    fn dashboard_refresh_state_value(&self) -> DashboardRefreshState {
        match self
            .inner
            .dashboard_refresh_state
            .read()
            .map_err(|_| anyhow::anyhow!("dashboard refresh state lock poisoned"))
        {
            Ok(guard) => guard.clone(),
            Err(err) => {
                warn!(error = %err, "failed reading dashboard refresh state");
                DashboardRefreshState::default()
            }
        }
    }

    fn mutate_dashboard_refresh_state<F>(&self, mutate: F) -> Result<()>
    where
        F: FnOnce(&mut DashboardRefreshState),
    {
        let mut guard = self
            .inner
            .dashboard_refresh_state
            .write()
            .map_err(|_| anyhow::anyhow!("dashboard refresh state lock poisoned"))?;
        mutate(&mut guard);
        Ok(())
    }

    fn record_dashboard_refresh_attempt(&self, at: DateTime<Utc>) {
        if let Err(err) = self.mutate_dashboard_refresh_state(|state| {
            state.last_attempt_at = Some(at);
        }) {
            warn!(error = %err, "failed recording dashboard refresh attempt");
        }
    }

    fn record_dashboard_refresh_success(&self, at: DateTime<Utc>) {
        if let Err(err) = self.mutate_dashboard_refresh_state(|state| {
            state.last_success_at = Some(at);
            state.last_error_at = None;
            state.last_error = None;
        }) {
            warn!(error = %err, "failed recording dashboard refresh success");
        }
    }

    fn record_dashboard_refresh_failure(&self, at: DateTime<Utc>, err: &anyhow::Error) {
        let message = trim_dashboard_error_message(&err.to_string());
        if let Err(lock_err) = self.mutate_dashboard_refresh_state(|state| {
            state.last_error_at = Some(at);
            state.last_error = Some(message.clone());
        }) {
            warn!(error = %lock_err, "failed recording dashboard refresh failure");
        }
    }

    async fn refresh_dashboard_snapshot_inner(&self, name: &str) -> Result<DashboardSnapshot> {
        let svc = self.clone();
        let worker_name = name.to_string();
        let snapshot =
            tokio::task::spawn_blocking(move || svc.dashboard_full_snapshot_sync(&worker_name))
                .await
                .context("dashboard snapshot worker failed")??;
        Ok(snapshot)
    }

    async fn refresh_dashboard_delta(
        &self,
        name: &str,
        snapshot: &DashboardSnapshot,
    ) -> Result<Option<DashboardSnapshot>> {
        let now = Utc::now();
        if now <= snapshot.data_window_to {
            return Ok(None);
        }
        let svc = self.clone();
        let name = name.to_string();
        let snapshot = snapshot.clone();
        let work = tokio::task::spawn_blocking(move || {
            svc.dashboard_delta_snapshot_sync(&name, snapshot, now)
        });
        let result = tokio::time::timeout(
            Duration::from_millis(self.inner.timeout_ms.max(MIN_SEARCH_TIMEOUT_MS)),
            work,
        )
        .await
        .map_err(|_| anyhow::anyhow!("dashboard delta refresh timed out"))?
        .context("dashboard delta refresh worker failed")??;
        Ok(result)
    }

    fn dashboard_full_snapshot_sync(&self, name: &str) -> Result<DashboardSnapshot> {
        let now = Utc::now();
        let window_to = floor_to_hour(now);
        let window_from = window_to - chrono::Duration::hours(24);
        let aggregate = self.dashboard_aggregate_for_range(window_from, window_to)?;
        Ok(DashboardSnapshot {
            version: DASHBOARD_SNAPSHOT_VERSION,
            name: name.to_string(),
            generated_at: Utc::now(),
            data_window_from: window_from,
            data_window_to: window_to,
            aggregate,
        })
    }

    fn dashboard_delta_snapshot_sync(
        &self,
        name: &str,
        snapshot: DashboardSnapshot,
        now: DateTime<Utc>,
    ) -> Result<Option<DashboardSnapshot>> {
        if now <= snapshot.data_window_to {
            return Ok(None);
        }
        let delta_from = snapshot.data_window_to;
        let delta_to = now;
        let delta = self.dashboard_aggregate_for_range(delta_from, delta_to)?;
        if delta.is_empty() {
            return Ok(None);
        }
        Ok(Some(DashboardSnapshot {
            version: DASHBOARD_SNAPSHOT_VERSION,
            name: name.to_string(),
            generated_at: Utc::now(),
            data_window_from: snapshot.data_window_from,
            data_window_to: delta_to,
            aggregate: snapshot.aggregate.merge(&delta),
        }))
    }

    fn dashboard_aggregate_for_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<DashboardAggregate> {
        let time_col = ident(&self.inner.fields.time_field);
        let action_col = ident(&self.inner.fields.action_field);
        let threat_col = ident(&self.inner.fields.threat_field);
        let user_col = ident(&self.inner.fields.user_field);
        let category_col = ident(&self.inner.fields.category_field);
        let device_col = ident(&self.inner.fields.device_field);
        let ip_col = ident(&self.inner.fields.source_ip_field);
        let dept_col = ident(&self.inner.fields.department_field);
        let resp_code_col = ident(&self.inner.fields.response_code_field);
        let reason_col = ident(&self.inner.fields.reason_field);
        let src_country_col = self.inner.fields.source_country_field.as_deref().map(ident);
        let dst_country_col = self
            .inner
            .fields
            .destination_country_field
            .as_deref()
            .map(ident);

        let Some(parquet_src) = parquet_source_sql_for_range(&self.inner.parquet_root, from, to)?
        else {
            return Ok(DashboardAggregate::default());
        };

        let conn = open_query_connection()?;
        let from_ts = from.format("%Y-%m-%d %H:%M:%S").to_string();
        let to_ts = to.format("%Y-%m-%d %H:%M:%S").to_string();

        let events = scalar_i64(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM {parquet_src} WHERE CAST({time_col} AS TIMESTAMP) >= TIMESTAMP '{from_ts}' AND CAST({time_col} AS TIMESTAMP) < TIMESTAMP '{to_ts}'"
            ),
        )?;
        let blocked = scalar_i64(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM {parquet_src} WHERE CAST({time_col} AS TIMESTAMP) >= TIMESTAMP '{from_ts}' AND CAST({time_col} AS TIMESTAMP) < TIMESTAMP '{to_ts}' AND CAST({action_col} AS VARCHAR) = 'Blocked'"
            ),
        )?;
        let threats = scalar_i64(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM {parquet_src} WHERE CAST({time_col} AS TIMESTAMP) >= TIMESTAMP '{from_ts}' AND CAST({time_col} AS TIMESTAMP) < TIMESTAMP '{to_ts}' AND COALESCE(CAST({threat_col} AS VARCHAR),'') NOT IN ('', 'None', 'N/A')"
            ),
        )?;

        let top_users = group_counts(
            &conn,
            GroupCountArgs {
                field_col: &user_col,
                time_col: &time_col,
                from_ts: &from_ts,
                to_ts: &to_ts,
                parquet_src: parquet_src.as_str(),
            },
        )?;
        let top_categories = group_counts(
            &conn,
            GroupCountArgs {
                field_col: &category_col,
                time_col: &time_col,
                from_ts: &from_ts,
                to_ts: &to_ts,
                parquet_src: parquet_src.as_str(),
            },
        )?;
        let top_devices = group_counts(
            &conn,
            GroupCountArgs {
                field_col: &device_col,
                time_col: &time_col,
                from_ts: &from_ts,
                to_ts: &to_ts,
                parquet_src: parquet_src.as_str(),
            },
        )?;
        let top_source_ips = group_counts(
            &conn,
            GroupCountArgs {
                field_col: &ip_col,
                time_col: &time_col,
                from_ts: &from_ts,
                to_ts: &to_ts,
                parquet_src: parquet_src.as_str(),
            },
        )?;
        let top_departments = group_counts(
            &conn,
            GroupCountArgs {
                field_col: &dept_col,
                time_col: &time_col,
                from_ts: &from_ts,
                to_ts: &to_ts,
                parquet_src: parquet_src.as_str(),
            },
        )?;
        let top_response_codes = group_counts(
            &conn,
            GroupCountArgs {
                field_col: &resp_code_col,
                time_col: &time_col,
                from_ts: &from_ts,
                to_ts: &to_ts,
                parquet_src: parquet_src.as_str(),
            },
        )?;
        let top_policy_reasons = group_counts(
            &conn,
            GroupCountArgs {
                field_col: &reason_col,
                time_col: &time_col,
                from_ts: &from_ts,
                to_ts: &to_ts,
                parquet_src: parquet_src.as_str(),
            },
        )?;

        let country_flows = match (src_country_col.as_deref(), dst_country_col.as_deref()) {
            (Some(src_col), Some(dst_col)) => country_flow_counts(
                &conn,
                CountryFlowCountArgs {
                    src_country_col: src_col,
                    dst_country_col: dst_col,
                    time_col: &time_col,
                    from_ts: &from_ts,
                    to_ts: &to_ts,
                    parquet_src: parquet_src.as_str(),
                },
            )?,
            _ => BTreeMap::new(),
        };

        Ok(DashboardAggregate {
            events,
            blocked,
            threats,
            top_users,
            top_categories,
            top_devices,
            top_source_ips,
            top_departments,
            top_response_codes,
            top_policy_reasons,
            country_flows,
        })
    }

    fn render_dashboard_snapshot(
        &self,
        snapshot: &DashboardSnapshot,
        role: RoleName,
        now: DateTime<Utc>,
        source: &str,
        notes: Vec<String>,
        transient_error: Option<String>,
    ) -> DashboardResponse {
        let mut tables = vec![
            table_block_from_counts(
                "top_users",
                &snapshot.aggregate.top_users,
                DASHBOARD_TOP_LIMIT,
            ),
            table_block_from_counts(
                "top_categories",
                &snapshot.aggregate.top_categories,
                DASHBOARD_TOP_LIMIT,
            ),
            table_block_from_counts(
                "top_devices",
                &snapshot.aggregate.top_devices,
                DASHBOARD_TOP_LIMIT,
            ),
            table_block_from_counts(
                "top_source_ips",
                &snapshot.aggregate.top_source_ips,
                DASHBOARD_TOP_LIMIT,
            ),
            table_block_from_counts(
                "top_departments",
                &snapshot.aggregate.top_departments,
                DASHBOARD_TOP_LIMIT,
            ),
            table_block_from_counts(
                "top_response_codes",
                &snapshot.aggregate.top_response_codes,
                DASHBOARD_TOP_LIMIT,
            ),
            table_block_from_counts(
                "top_policy_reasons",
                &snapshot.aggregate.top_policy_reasons,
                DASHBOARD_TOP_LIMIT,
            ),
            table_block_from_country_flows(
                "country_flows_24h",
                &snapshot.aggregate.country_flows,
                DASHBOARD_FLOW_LIMIT,
            ),
        ];

        if role == RoleName::Helpdesk {
            for block in &mut tables {
                if matches!(
                    block.name.as_str(),
                    "top_users" | "top_devices" | "top_source_ips"
                ) {
                    for row in &mut block.rows {
                        if let Some(first) = row.first_mut() {
                            *first = "[REDACTED]".to_string();
                        }
                    }
                }
            }
        }

        let refresh_state = self.dashboard_refresh_state_value();
        let last_refresh_error = transient_error.or(refresh_state.last_error.clone());
        let status = if last_refresh_error.is_some() {
            DashboardStatus::Degraded
        } else if snapshot_needs_refresh(snapshot, now, self.inner.dashboard_snapshot_refresh_secs)
        {
            DashboardStatus::Stale
        } else {
            DashboardStatus::Ready
        };

        DashboardResponse {
            name: snapshot.name.clone(),
            generated_at: now,
            status,
            source: source.to_string(),
            snapshot_generated_at: Some(snapshot.generated_at),
            snapshot_age_seconds: Some(snapshot_age_seconds(snapshot, now)),
            data_window_from: Some(snapshot.data_window_from),
            data_window_to: Some(snapshot.data_window_to),
            refresh_in_progress: self
                .inner
                .dashboard_refresh_in_progress
                .load(Ordering::Relaxed),
            last_refresh_attempt_at: refresh_state.last_attempt_at,
            last_refresh_success_at: refresh_state
                .last_success_at
                .or(Some(snapshot.generated_at)),
            last_refresh_error,
            notes,
            cards: vec![
                MetricCard {
                    name: "events_24h".to_string(),
                    value: snapshot.aggregate.events,
                },
                MetricCard {
                    name: "blocked_24h".to_string(),
                    value: snapshot.aggregate.blocked,
                },
                MetricCard {
                    name: "threat_hits_24h".to_string(),
                    value: snapshot.aggregate.threats,
                },
            ],
            tables,
        }
    }

    fn search_sync(&self, req: SearchRequest, role: RoleName) -> Result<SearchResponse> {
        validate_time_window(req.time_from, req.time_to, self.inner.max_days_per_query)?;
        validate_filters(&req.filters, &self.inner.input_value_re)?;

        let columns = req
            .columns
            .clone()
            .unwrap_or_else(|| self.inner.default_columns.clone());
        if columns.is_empty() {
            anyhow::bail!("at least one selected column is required");
        }
        for col in &columns {
            validate_identifier(col)?;
        }

        let limit = req
            .limit
            .unwrap_or(self.inner.max_rows)
            .clamp(1, self.inner.max_rows);
        let page_size = req
            .page_size
            .unwrap_or(self.inner.default_limit)
            .clamp(1, self.inner.max_rows);
        let max_pages = limit.div_ceil(page_size).max(1);
        let page = req.page.unwrap_or(1).clamp(1, max_pages);
        let start_index = (page - 1).saturating_mul(page_size);
        let collect_target = start_index
            .saturating_add(page_size)
            .saturating_add(1)
            .min(limit.saturating_add(1));

        let groups =
            parquet_file_groups_for_range(&self.inner.parquet_root, req.time_from, req.time_to)?;
        if groups.is_empty() {
            return Ok(SearchResponse {
                rows: Vec::new(),
                row_count: 0,
                truncated: false,
                page,
                page_size,
                has_more: false,
            });
        }

        let visibility_filters = self
            .inner
            .visibility_filters
            .read()
            .map_err(|_| anyhow::anyhow!("visibility filters lock poisoned"))?
            .clone();
        let batch_limit = search_batch_limit(page_size);
        let conn = open_query_connection()?;
        let mut out = Vec::new();

        'hours: for files in groups.into_iter().rev() {
            let parquet_src = parquet_source_sql_from_files(&files);
            let mut offset = 0u32;
            loop {
                let sql = build_search_sql(
                    &columns,
                    &req,
                    &self.inner.fields,
                    &parquet_src,
                    batch_limit,
                    offset,
                );
                let mut batch = execute_search_sql(&conn, &sql, &columns)?;
                let raw_count = batch.len() as u32;
                if raw_count == 0 {
                    break;
                }
                apply_visibility_filters(&mut batch, &self.inner.fields, &visibility_filters);
                if role == RoleName::Helpdesk {
                    apply_helpdesk_masking(&mut batch, &self.inner.helpdesk_mask_fields);
                }
                out.extend(batch);
                if out.len() as u32 >= collect_target {
                    out.truncate(collect_target as usize);
                    break 'hours;
                }
                if raw_count < batch_limit {
                    break;
                }
                offset = offset.saturating_add(raw_count);
            }
        }

        let start = start_index as usize;
        let end = start.saturating_add(page_size as usize).min(out.len());
        let rows = if start < out.len() {
            out[start..end].to_vec()
        } else {
            Vec::new()
        };
        let has_more = out.len() > end;
        let row_count = rows.len();
        Ok(SearchResponse {
            rows,
            row_count,
            truncated: has_more,
            page,
            page_size,
            has_more,
        })
    }

    fn search_rows_for_analysis(
        &self,
        req: SearchRequest,
        role: RoleName,
        required_columns: &[String],
        optional_columns: &[String],
    ) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
        let mut all_columns = required_columns.to_vec();
        for col in optional_columns {
            if !all_columns.iter().any(|c| c == col) {
                all_columns.push(col.clone());
            }
        }
        let limit = req
            .limit
            .unwrap_or(self.inner.max_rows)
            .clamp(1, self.inner.max_rows);
        let mut full_req = req.clone();
        full_req.columns = Some(all_columns);
        full_req.page = Some(1);
        full_req.page_size = Some(limit);
        full_req.limit = Some(limit);
        match self.search_sync(full_req, role) {
            Ok(res) => Ok(res.rows),
            Err(err) => {
                if optional_columns.is_empty() || !is_missing_column_error(&err) {
                    return Err(err);
                }
                let mut fallback_req = req;
                fallback_req.columns = Some(required_columns.to_vec());
                fallback_req.page = Some(1);
                fallback_req.page_size = Some(limit);
                fallback_req.limit = Some(limit);
                let res = self.search_sync(fallback_req, role)?;
                Ok(res.rows)
            }
        }
    }

    fn search_timeline_sync(
        &self,
        req: SearchRequest,
        role: RoleName,
        bucket_minutes: Option<u32>,
    ) -> Result<SearchTimelineResponse> {
        let required = vec![
            self.inner.fields.time_field.clone(),
            self.inner.fields.action_field.clone(),
        ];
        let optional = vec![
            self.inner.fields.reason_field.clone(),
            self.inner.fields.response_code_field.clone(),
            self.inner.fields.server_ip_field.clone(),
            self.inner.fields.threat_field.clone(),
            self.inner.fields.user_field.clone(),
            "respsize".to_string(),
            "externalspr".to_string(),
            "cltsslfailreason".to_string(),
            "is_ssluntrustedca".to_string(),
            "is_sslselfsigned".to_string(),
            "is_sslexpiredca".to_string(),
            "clienttlsversion".to_string(),
            "srvtlsversion".to_string(),
        ];
        let rows = self.search_rows_for_analysis(req.clone(), role, &required, &optional)?;
        let bucket_minutes = normalize_bucket_minutes(req.time_from, req.time_to, bucket_minutes);
        let step_secs = i64::from(bucket_minutes) * 60;
        let mut buckets: BTreeMap<i64, TimelineBucketAggregate> = BTreeMap::new();

        for row in &rows {
            let Some(event_time) =
                row_get_str(row, &self.inner.fields.time_field).and_then(parse_row_timestamp)
            else {
                continue;
            };
            if event_time < req.time_from || event_time >= req.time_to {
                continue;
            }
            let bucket = align_to_bucket_start(event_time, step_secs);
            let entry = buckets.entry(bucket.timestamp()).or_default();
            entry.total += 1;
            let action = row_get_str(row, &self.inner.fields.action_field).unwrap_or_default();
            if action.eq_ignore_ascii_case("blocked") {
                entry.blocked += 1;
                entry.policy += 1;
            }
            let reason = normalized_row_value(row, &self.inner.fields.reason_field);
            if reason != "None" {
                increment_count(&mut entry.reason_counts, &reason);
            }
            let destination = normalized_row_value(row, &self.inner.fields.server_ip_field);
            if destination != "None" {
                increment_count(&mut entry.destination_counts, &destination);
            }
            let threat = normalized_row_value(row, &self.inner.fields.threat_field);
            if threat != "None" {
                entry.threat += 1;
                increment_count(&mut entry.threat_counts, &threat);
            }
            if row_respsize_zero(row) {
                entry.zero_response += 1;
            }
            if row_is_tls_issue(row, &self.inner.fields) {
                entry.ssl_tls += 1;
            }
            if row_is_geo_issue(row, &self.inner.fields) {
                entry.geo += 1;
            }
        }

        let mut points = Vec::new();
        let mut markers = Vec::new();
        let mut cursor = align_to_bucket_start(req.time_from, step_secs);
        while cursor < req.time_to {
            let key = cursor.timestamp();
            let bucket_state = buckets.get(&key).cloned().unwrap_or_default();
            let bucket_end = cursor + ChronoDuration::seconds(step_secs);
            points.push(SearchTimelinePoint {
                bucket_start: cursor,
                bucket_end,
                count: bucket_state.total,
                blocked: bucket_state.blocked,
            });
            if let Some(marker) =
                timeline_marker_from_bucket(&bucket_state, cursor, bucket_end, &self.inner.fields)
            {
                markers.push(marker);
            }
            cursor = bucket_end;
        }

        Ok(SearchTimelineResponse {
            generated_at: Utc::now(),
            bucket_minutes,
            points,
            markers,
        })
    }

    fn search_triage_sync(
        &self,
        req: SearchRequest,
        role: RoleName,
    ) -> Result<SearchTriageResponse> {
        let required = vec![
            self.inner.fields.reason_field.clone(),
            self.inner.fields.response_code_field.clone(),
            self.inner.fields.server_ip_field.clone(),
        ];
        let optional = vec![
            "respsize".to_string(),
            "externalspr".to_string(),
            "cltsslfailreason".to_string(),
            "is_ssluntrustedca".to_string(),
            "is_sslselfsigned".to_string(),
            "is_sslexpiredca".to_string(),
            "clienttlsversion".to_string(),
            "srvtlsversion".to_string(),
            "ssl_rulename".to_string(),
            self.inner.fields.user_field.clone(),
            self.inner.fields.threat_field.clone(),
            self.inner
                .fields
                .destination_country_field
                .clone()
                .unwrap_or_else(|| "dstip_country".to_string()),
        ];
        let rows = self.search_rows_for_analysis(req, role, &required, &optional)?;

        let mut reason_counts: HashMap<String, usize> = HashMap::new();
        let mut code_counts: HashMap<String, usize> = HashMap::new();
        let mut destination_counts: HashMap<String, usize> = HashMap::new();
        let mut user_counts: HashMap<String, usize> = HashMap::new();
        let mut zero_destination_counts: HashMap<String, usize> = HashMap::new();
        let mut tls_counts: HashMap<String, usize> = HashMap::new();
        let mut policy_reason_counts: HashMap<String, usize> = HashMap::new();
        let mut ssl_reason_counts: HashMap<String, usize> = HashMap::new();
        let mut geo_reason_counts: HashMap<String, usize> = HashMap::new();
        let mut geo_destination_counts: HashMap<String, usize> = HashMap::new();
        let mut threat_reason_counts: HashMap<String, usize> = HashMap::new();
        let mut threat_name_counts: HashMap<String, usize> = HashMap::new();
        let mut zero_reason_counts: HashMap<String, usize> = HashMap::new();
        let mut policy_bucket_count = 0usize;
        let mut ssl_bucket_count = 0usize;
        let mut geo_bucket_count = 0usize;
        let mut threat_bucket_count = 0usize;
        let mut zero_bucket_count = 0usize;

        for row in &rows {
            let reason = normalized_row_value(row, &self.inner.fields.reason_field);
            *reason_counts.entry(reason.clone()).or_insert(0) += 1;

            let code = normalized_row_value(row, &self.inner.fields.response_code_field);
            *code_counts.entry(code).or_insert(0) += 1;

            let destination = normalized_row_value(row, &self.inner.fields.server_ip_field);
            *destination_counts.entry(destination.clone()).or_insert(0) += 1;
            let user = normalized_row_value(row, &self.inner.fields.user_field);
            if user != "None" {
                *user_counts.entry(user).or_insert(0) += 1;
            }

            if row_respsize_zero(row) {
                zero_bucket_count += 1;
                *zero_destination_counts.entry(destination).or_insert(0) += 1;
                if reason != "None" {
                    *zero_reason_counts.entry(reason.clone()).or_insert(0) += 1;
                }
            }

            for indicator in row_tls_indicators(row, &self.inner.fields) {
                let key = indicator;
                *tls_counts.entry(key).or_insert(0) += 1;
            }
            if row_is_policy_issue(row, &self.inner.fields) {
                policy_bucket_count += 1;
                if reason != "None" {
                    *policy_reason_counts.entry(reason.clone()).or_insert(0) += 1;
                }
            }
            if row_is_tls_issue(row, &self.inner.fields) {
                ssl_bucket_count += 1;
                if reason != "None" {
                    *ssl_reason_counts.entry(reason.clone()).or_insert(0) += 1;
                }
            }
            if row_is_geo_issue(row, &self.inner.fields) {
                geo_bucket_count += 1;
                if reason != "None" {
                    *geo_reason_counts.entry(reason.clone()).or_insert(0) += 1;
                }
                if let Some(dst_country_col) =
                    self.inner.fields.destination_country_field.as_deref()
                {
                    let destination_country = normalized_row_value(row, dst_country_col);
                    if destination_country != "None" {
                        *geo_destination_counts
                            .entry(destination_country)
                            .or_insert(0) += 1;
                    }
                }
            }
            if row_is_threat_issue(row, &self.inner.fields) {
                threat_bucket_count += 1;
                if reason != "None" {
                    *threat_reason_counts.entry(reason.clone()).or_insert(0) += 1;
                }
                let threat_name = normalized_row_value(row, &self.inner.fields.threat_field);
                if threat_name != "None" {
                    *threat_name_counts.entry(threat_name).or_insert(0) += 1;
                }
            }
        }

        let root_cause_buckets = build_root_cause_buckets(
            &policy_reason_counts,
            &ssl_reason_counts,
            &zero_destination_counts,
            &zero_reason_counts,
            &geo_reason_counts,
            &geo_destination_counts,
            &threat_reason_counts,
            &threat_name_counts,
            policy_bucket_count,
            ssl_bucket_count,
            zero_bucket_count,
            geo_bucket_count,
            threat_bucket_count,
            &self.inner.fields,
        );

        Ok(SearchTriageResponse {
            generated_at: Utc::now(),
            root_cause_buckets,
            top_reasons: top_support_items(&reason_counts, 12),
            top_response_codes: top_support_items(&code_counts, 12),
            top_destinations: top_support_items(&destination_counts, 12),
            top_users: top_support_items(&user_counts, 12),
            zero_response_destinations: top_support_items(&zero_destination_counts, 12),
            tls_or_ssl_indicators: top_support_items(&tls_counts, 12),
        })
    }

    fn search_grouped_sync(
        &self,
        req: SearchRequest,
        role: RoleName,
        opts: GroupedSearchOptions,
    ) -> Result<SearchGroupedResponse> {
        let view_mode = opts.view_mode;
        let sort_by = opts.sort_by;
        let sort_desc = opts.sort_desc;
        let page = opts.page;
        let page_size = opts.page_size;
        let group_columns = grouped_columns_for_mode(&self.inner.fields, view_mode);
        let rows = self.search_rows_for_analysis(req.clone(), role, &group_columns, &[])?;
        let mut counts: HashMap<Vec<String>, usize> = HashMap::new();
        for row in rows {
            let key = group_columns
                .iter()
                .map(|col| normalized_row_value(&row, col))
                .collect::<Vec<_>>();
            *counts.entry(key).or_insert(0) += 1;
        }

        let mut grouped_rows = counts
            .into_iter()
            .map(|(key, count)| {
                let mut row = serde_json::Map::new();
                for (idx, col) in group_columns.iter().enumerate() {
                    row.insert(
                        col.clone(),
                        serde_json::Value::String(key.get(idx).cloned().unwrap_or_default()),
                    );
                }
                row.insert(
                    "count".to_string(),
                    serde_json::Value::String(count.to_string()),
                );
                row
            })
            .collect::<Vec<_>>();

        let sort_key = sort_by.unwrap_or_else(|| "count".to_string());
        let desc = sort_desc.unwrap_or(true);
        grouped_rows.sort_by(|a, b| compare_grouped_rows(a, b, &sort_key, desc));

        let page_size = page_size
            .or(req.page_size)
            .unwrap_or(self.inner.default_limit)
            .clamp(1, self.inner.max_rows);
        let total_groups = grouped_rows.len();
        let max_pages = (total_groups as u32).div_ceil(page_size).max(1);
        let page = page.unwrap_or(1).clamp(1, max_pages);
        let start = ((page - 1) * page_size) as usize;
        let end = start.saturating_add(page_size as usize).min(total_groups);
        let rows = if start < total_groups {
            grouped_rows[start..end].to_vec()
        } else {
            Vec::new()
        };
        let has_more = end < total_groups;

        Ok(SearchGroupedResponse {
            view_mode,
            row_count: rows.len(),
            total_groups,
            truncated: has_more,
            page,
            page_size,
            has_more,
            rows,
        })
    }

    fn dashboard_snapshot_get(&self, name: &str) -> Result<Option<DashboardSnapshot>> {
        {
            let guard = self
                .inner
                .dashboard_snapshot_cache
                .read()
                .map_err(|_| anyhow::anyhow!("dashboard snapshot cache lock poisoned"))?;
            if let Some(snapshot) = guard.get(name) {
                return Ok(Some(snapshot.clone()));
            }
        }

        let path = dashboard_snapshot_path(&self.inner.dashboard_snapshot_dir, name);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed reading dashboard snapshot {}", path.display()))?;
        let snapshot: DashboardSnapshot = serde_json::from_str(&raw)
            .with_context(|| format!("failed parsing dashboard snapshot {}", path.display()))?;
        if snapshot.version != DASHBOARD_SNAPSHOT_VERSION {
            return Ok(None);
        }
        let mut guard = self
            .inner
            .dashboard_snapshot_cache
            .write()
            .map_err(|_| anyhow::anyhow!("dashboard snapshot cache lock poisoned"))?;
        guard.insert(name.to_string(), snapshot.clone());
        Ok(Some(snapshot))
    }

    fn dashboard_snapshot_put(&self, snapshot: DashboardSnapshot) -> Result<()> {
        std::fs::create_dir_all(&self.inner.dashboard_snapshot_dir).with_context(|| {
            format!(
                "failed creating dashboard snapshot dir {}",
                self.inner.dashboard_snapshot_dir.display()
            )
        })?;
        let path = dashboard_snapshot_path(&self.inner.dashboard_snapshot_dir, &snapshot.name);
        let tmp_path = path.with_extension("json.tmp");
        let raw = serde_json::to_vec_pretty(&snapshot)?;
        std::fs::write(&tmp_path, raw)
            .with_context(|| format!("failed writing dashboard snapshot {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &path).with_context(|| {
            format!(
                "failed finalizing dashboard snapshot {} -> {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        let mut guard = self
            .inner
            .dashboard_snapshot_cache
            .write()
            .map_err(|_| anyhow::anyhow!("dashboard snapshot cache lock poisoned"))?;
        guard.insert(snapshot.name.clone(), snapshot);
        Ok(())
    }
}

struct GroupCountArgs<'a> {
    field_col: &'a str,
    time_col: &'a str,
    from_ts: &'a str,
    to_ts: &'a str,
    parquet_src: &'a str,
}

struct CountryFlowCountArgs<'a> {
    src_country_col: &'a str,
    dst_country_col: &'a str,
    time_col: &'a str,
    from_ts: &'a str,
    to_ts: &'a str,
    parquet_src: &'a str,
}

fn group_counts(conn: &Connection, args: GroupCountArgs<'_>) -> Result<BTreeMap<String, i64>> {
    let sql = format!(
        "SELECT COALESCE(CAST({field_col} AS VARCHAR), 'None') AS value, COUNT(*) AS cnt \
         FROM {parquet_src} \
         WHERE CAST({time_col} AS TIMESTAMP) >= TIMESTAMP '{from_ts}' \
           AND CAST({time_col} AS TIMESTAMP) < TIMESTAMP '{to_ts}' \
         GROUP BY 1",
        field_col = args.field_col,
        parquet_src = args.parquet_src,
        time_col = args.time_col,
        from_ts = args.from_ts,
        to_ts = args.to_ts,
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let value: Option<String> = row.get(0)?;
        let count: i64 = row.get(1)?;
        out.insert(value.unwrap_or_else(|| "None".to_string()), count);
    }
    Ok(out)
}

fn country_flow_counts(
    conn: &Connection,
    args: CountryFlowCountArgs<'_>,
) -> Result<BTreeMap<String, i64>> {
    let sql = format!(
        "SELECT \
            CAST({src_country_col} AS VARCHAR) AS source_country, \
            CAST({dst_country_col} AS VARCHAR) AS destination_country, \
            COUNT(*) AS cnt \
         FROM {parquet_src} \
         WHERE CAST({time_col} AS TIMESTAMP) >= TIMESTAMP '{from_ts}' \
           AND CAST({time_col} AS TIMESTAMP) < TIMESTAMP '{to_ts}' \
           AND COALESCE(CAST({src_country_col} AS VARCHAR), '') NOT IN ('', 'None', 'N/A') \
           AND COALESCE(CAST({dst_country_col} AS VARCHAR), '') NOT IN ('', 'None', 'N/A') \
         GROUP BY 1, 2",
        src_country_col = args.src_country_col,
        dst_country_col = args.dst_country_col,
        parquet_src = args.parquet_src,
        time_col = args.time_col,
        from_ts = args.from_ts,
        to_ts = args.to_ts,
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let src: Option<String> = row.get(0)?;
        let dst: Option<String> = row.get(1)?;
        let count: i64 = row.get(2)?;
        out.insert(
            format!(
                "{}\u{001f}{}",
                src.unwrap_or_else(|| "None".to_string()),
                dst.unwrap_or_else(|| "None".to_string())
            ),
            count,
        );
    }
    Ok(out)
}

fn empty_top_table(name: &str) -> TableBlock {
    TableBlock {
        name: name.to_string(),
        columns: vec!["value".to_string(), "count".to_string()],
        rows: Vec::new(),
    }
}

fn empty_country_flow_table(name: &str) -> TableBlock {
    TableBlock {
        name: name.to_string(),
        columns: vec![
            "source_country".to_string(),
            "destination_country".to_string(),
            "count".to_string(),
        ],
        rows: Vec::new(),
    }
}

impl DashboardAggregate {
    fn is_empty(&self) -> bool {
        self.events == 0
            && self.blocked == 0
            && self.threats == 0
            && self.top_users.is_empty()
            && self.top_categories.is_empty()
            && self.top_devices.is_empty()
            && self.top_source_ips.is_empty()
            && self.top_departments.is_empty()
            && self.top_response_codes.is_empty()
            && self.top_policy_reasons.is_empty()
            && self.country_flows.is_empty()
    }

    fn merge(&self, delta: &DashboardAggregate) -> DashboardAggregate {
        DashboardAggregate {
            events: self.events + delta.events,
            blocked: self.blocked + delta.blocked,
            threats: self.threats + delta.threats,
            top_users: merged_counts(&self.top_users, &delta.top_users),
            top_categories: merged_counts(&self.top_categories, &delta.top_categories),
            top_devices: merged_counts(&self.top_devices, &delta.top_devices),
            top_source_ips: merged_counts(&self.top_source_ips, &delta.top_source_ips),
            top_departments: merged_counts(&self.top_departments, &delta.top_departments),
            top_response_codes: merged_counts(&self.top_response_codes, &delta.top_response_codes),
            top_policy_reasons: merged_counts(&self.top_policy_reasons, &delta.top_policy_reasons),
            country_flows: merged_counts(&self.country_flows, &delta.country_flows),
        }
    }
}

fn merged_counts(
    base: &BTreeMap<String, i64>,
    delta: &BTreeMap<String, i64>,
) -> BTreeMap<String, i64> {
    let mut merged = base.clone();
    for (key, value) in delta {
        *merged.entry(key.clone()).or_insert(0) += *value;
    }
    merged
}

fn empty_dashboard_response(
    name: &str,
    generated_at: DateTime<Utc>,
    status: DashboardStatus,
    source: &str,
    notes: Vec<String>,
    refresh_in_progress: bool,
    refresh_state: DashboardRefreshState,
) -> DashboardResponse {
    DashboardResponse {
        name: name.to_string(),
        generated_at,
        status,
        source: source.to_string(),
        snapshot_generated_at: None,
        snapshot_age_seconds: None,
        data_window_from: None,
        data_window_to: None,
        refresh_in_progress,
        last_refresh_attempt_at: refresh_state.last_attempt_at,
        last_refresh_success_at: refresh_state.last_success_at,
        last_refresh_error: refresh_state.last_error,
        notes,
        cards: vec![
            MetricCard {
                name: "events_24h".to_string(),
                value: 0,
            },
            MetricCard {
                name: "blocked_24h".to_string(),
                value: 0,
            },
            MetricCard {
                name: "threat_hits_24h".to_string(),
                value: 0,
            },
        ],
        tables: vec![
            empty_top_table("top_users"),
            empty_top_table("top_categories"),
            empty_top_table("top_devices"),
            empty_top_table("top_source_ips"),
            empty_top_table("top_departments"),
            empty_top_table("top_response_codes"),
            empty_top_table("top_policy_reasons"),
            empty_country_flow_table("country_flows_24h"),
        ],
    }
}

fn default_dashboard_notes(
    snapshot: &DashboardSnapshot,
    now: DateTime<Utc>,
    refresh_secs: u64,
) -> Vec<String> {
    let mut notes = vec![format!(
        "Hourly snapshot covers {} to {} UTC.",
        snapshot.data_window_from.format("%Y-%m-%d %H:%M"),
        snapshot.data_window_to.format("%Y-%m-%d %H:%M")
    )];
    if snapshot.aggregate.is_empty() {
        notes.push(
            "No finalized parquet rows were available in the current 24-hour dashboard window."
                .to_string(),
        );
    }
    if snapshot_needs_refresh(snapshot, now, refresh_secs) {
        notes.push("Snapshot is older than the normal hourly cadence. A background rebuild has been scheduled.".to_string());
    } else {
        notes.push(
            "Use Refresh to merge newer finalized parquet data without waiting for the next hourly snapshot."
                .to_string(),
        );
    }
    notes
}

fn snapshot_needs_refresh(
    snapshot: &DashboardSnapshot,
    now: DateTime<Utc>,
    refresh_secs: u64,
) -> bool {
    let current_hour = floor_to_hour(now);
    snapshot.data_window_to < current_hour
        || (now - snapshot.generated_at).num_seconds() >= refresh_secs as i64
}

fn snapshot_needs_full_rebuild_before_delta(
    snapshot: &DashboardSnapshot,
    now: DateTime<Utc>,
    refresh_secs: u64,
) -> bool {
    let lag_hours = (floor_to_hour(now) - snapshot.data_window_to).num_hours();
    lag_hours > MAX_DASHBOARD_DELTA_RANGE_HOURS
        || (now - snapshot.generated_at).num_seconds() >= (refresh_secs as i64 * 2)
}

fn snapshot_age_seconds(snapshot: &DashboardSnapshot, now: DateTime<Utc>) -> i64 {
    (now - snapshot.generated_at).num_seconds().max(0)
}

fn trim_dashboard_error_message(message: &str) -> String {
    const MAX_LEN: usize = 240;
    let mut out = String::new();
    for ch in message.chars().take(MAX_LEN) {
        out.push(ch);
    }
    if message.chars().count() > MAX_LEN {
        out.push_str("...");
    }
    out
}

fn dashboard_snapshot_dir(cfg: &AppConfig) -> PathBuf {
    cfg.audit
        .path
        .parent()
        .unwrap_or_else(|| Path::new("/var/lib/nss-quarry"))
        .join("dashboard-cache")
}

fn dashboard_snapshot_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!("{name}.json"))
}

fn table_block_from_counts(name: &str, counts: &BTreeMap<String, i64>, limit: usize) -> TableBlock {
    let rows = top_rows_from_counts(counts, limit)
        .into_iter()
        .map(|(value, count)| vec![value, count.to_string()])
        .collect::<Vec<_>>();
    TableBlock {
        name: name.to_string(),
        columns: vec!["value".to_string(), "count".to_string()],
        rows,
    }
}

fn table_block_from_country_flows(
    name: &str,
    counts: &BTreeMap<String, i64>,
    limit: usize,
) -> TableBlock {
    let rows = top_rows_from_counts(counts, limit)
        .into_iter()
        .map(|(value, count)| {
            let mut parts = value.split('\u{001f}');
            vec![
                parts.next().unwrap_or("None").to_string(),
                parts.next().unwrap_or("None").to_string(),
                count.to_string(),
            ]
        })
        .collect::<Vec<_>>();
    TableBlock {
        name: name.to_string(),
        columns: vec![
            "source_country".to_string(),
            "destination_country".to_string(),
            "count".to_string(),
        ],
        rows,
    }
}

fn top_rows_from_counts(counts: &BTreeMap<String, i64>, limit: usize) -> Vec<(String, i64)> {
    let mut rows = counts
        .iter()
        .map(|(value, count)| (value.clone(), *count))
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(limit);
    rows
}

fn scalar_i64(conn: &Connection, sql: &str) -> Result<i64> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        let v: i64 = row.get(0)?;
        Ok(v)
    } else {
        Ok(0)
    }
}

fn apply_filter(where_clauses: &mut Vec<String>, column: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    where_clauses.push(format!(
        "STRPOS(LOWER(CAST({} AS VARCHAR)), LOWER('{}')) > 0",
        ident(column),
        escape_sql_literal(value)
    ));
}

fn apply_multi_exact_filter(where_clauses: &mut Vec<String>, column: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    let values = split_csv_values(value);
    if values.is_empty() {
        return;
    }

    let lowered_values = values
        .iter()
        .map(|v| format!("'{}'", escape_sql_literal(&v.to_lowercase())))
        .collect::<Vec<_>>();

    where_clauses.push(format!(
        "LOWER(CAST({} AS VARCHAR)) IN ({})",
        ident(column),
        lowered_values.join(", ")
    ));
}

fn apply_contains_or_multi_exact_filter(
    where_clauses: &mut Vec<String>,
    column: &str,
    value: Option<&str>,
) {
    let Some(value) = value else {
        return;
    };
    if value.contains(',') {
        apply_multi_exact_filter(where_clauses, column, Some(value));
    } else {
        apply_filter(where_clauses, column, Some(value));
    }
}

fn apply_tls_issue_filter(
    where_clauses: &mut Vec<String>,
    fields: &FieldMap,
    enabled: Option<bool>,
) {
    if enabled != Some(true) {
        return;
    }
    where_clauses.push(format!(
        "(\
        STRPOS(LOWER(CAST({reason_col} AS VARCHAR)), 'ssl') > 0 OR \
        STRPOS(LOWER(CAST({reason_col} AS VARCHAR)), 'tls') > 0 OR \
        STRPOS(LOWER(CAST({reason_col} AS VARCHAR)), 'certificate') > 0 OR \
        STRPOS(LOWER(CAST({reason_col} AS VARCHAR)), 'ocsp') > 0 OR \
        STRPOS(LOWER(CAST({reason_col} AS VARCHAR)), 'handshake') > 0\
        )",
        reason_col = ident(&fields.reason_field)
    ));
}

fn build_search_sql(
    columns: &[String],
    req: &SearchRequest,
    fields: &FieldMap,
    parquet_src: &str,
    limit: u32,
    offset: u32,
) -> String {
    let time_col = ident(&fields.time_field);
    let from = req
        .time_from
        .with_timezone(&Utc)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let to = req
        .time_to
        .with_timezone(&Utc)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let select_list = columns
        .iter()
        .map(|col| format!("CAST({} AS VARCHAR) AS {}", ident(col), ident(col)))
        .collect::<Vec<_>>()
        .join(", ");

    let mut where_clauses = vec![format!(
        "CAST({time_col} AS TIMESTAMP) >= TIMESTAMP '{from}' AND CAST({time_col} AS TIMESTAMP) < TIMESTAMP '{to}'"
    )];
    apply_filter(
        &mut where_clauses,
        &fields.user_field,
        req.filters.user.as_deref(),
    );
    apply_filter(
        &mut where_clauses,
        &fields.url_field,
        req.filters.url.as_deref(),
    );
    apply_filter(
        &mut where_clauses,
        &fields.action_field,
        req.filters.action.as_deref(),
    );
    apply_contains_or_multi_exact_filter(
        &mut where_clauses,
        &fields.response_code_field,
        req.filters.response_code.as_deref(),
    );
    apply_contains_or_multi_exact_filter(
        &mut where_clauses,
        "respsize",
        req.filters.response_size.as_deref(),
    );
    apply_filter(
        &mut where_clauses,
        &fields.reason_field,
        req.filters.reason.as_deref(),
    );
    apply_filter(
        &mut where_clauses,
        &fields.threat_field,
        req.filters.threat.as_deref(),
    );
    apply_filter(
        &mut where_clauses,
        &fields.category_field,
        req.filters.category.as_deref(),
    );
    apply_contains_or_multi_exact_filter(
        &mut where_clauses,
        &fields.source_ip_field,
        req.filters.source_ip.as_deref(),
    );
    apply_multi_exact_filter(
        &mut where_clauses,
        &fields.server_ip_field,
        req.filters.server_ip.as_deref(),
    );
    if let Some(source_country_col) = fields.source_country_field.as_deref() {
        apply_contains_or_multi_exact_filter(
            &mut where_clauses,
            source_country_col,
            req.filters.source_country.as_deref(),
        );
    }
    if let Some(destination_country_col) = fields.destination_country_field.as_deref() {
        apply_contains_or_multi_exact_filter(
            &mut where_clauses,
            destination_country_col,
            req.filters.destination_country.as_deref(),
        );
    }
    apply_filter(
        &mut where_clauses,
        &fields.device_field,
        req.filters.device.as_deref(),
    );
    apply_filter(
        &mut where_clauses,
        &fields.department_field,
        req.filters.department.as_deref(),
    );
    apply_tls_issue_filter(&mut where_clauses, fields, req.filters.tls_issue_only);

    let mut sql = format!(
        "SELECT {select_list} FROM {parquet_src} WHERE {} ORDER BY {time_col} DESC LIMIT {limit}",
        where_clauses.join(" AND "),
        parquet_src = parquet_src
    );
    if offset > 0 {
        sql.push_str(&format!(" OFFSET {offset}"));
    }
    sql
}

fn execute_search_sql(
    conn: &Connection,
    sql: &str,
    columns: &[String],
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut map = serde_json::Map::new();
        for (i, col) in columns.iter().enumerate() {
            let value: Option<String> = row.get(i)?;
            match value {
                Some(v) => {
                    map.insert(col.clone(), serde_json::Value::String(v));
                }
                None => {
                    map.insert(col.clone(), serde_json::Value::Null);
                }
            }
        }
        out.push(map);
    }
    Ok(out)
}

fn search_batch_limit(page_size: u32) -> u32 {
    page_size.clamp(200, 1_000)
}

fn is_missing_column_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("binder error")
        || msg.contains("referenced column")
        || msg.contains("column with name")
}

fn normalize_bucket_minutes(from: DateTime<Utc>, to: DateTime<Utc>, requested: Option<u32>) -> u32 {
    if let Some(value) = requested {
        return value.clamp(1, 1_440);
    }
    let minutes = (to - from).num_minutes().max(1);
    if minutes <= 24 * 60 {
        5
    } else if minutes <= 72 * 60 {
        15
    } else {
        60
    }
}

fn align_to_bucket_start(ts: DateTime<Utc>, bucket_secs: i64) -> DateTime<Utc> {
    let epoch = ts.timestamp();
    let aligned = epoch - epoch.rem_euclid(bucket_secs.max(1));
    DateTime::from_timestamp(aligned, 0).unwrap_or(ts)
}

fn row_get_str<'a>(
    row: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    row.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn parse_row_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(ts) = DateTime::parse_from_rfc3339(text) {
        return Some(ts.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f%:z",
        "%Y-%m-%d %H:%M:%S%:z",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%a %b %e %H:%M:%S %Y",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(text, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(naive) = NaiveDateTime::parse_from_str(text, fmt) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
        }
    }
    None
}

fn normalized_row_value(row: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    row.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| "None".to_string())
}

fn top_support_items(counts: &HashMap<String, usize>, limit: usize) -> Vec<SupportSummaryItem> {
    let mut rows = counts
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.into_iter()
        .take(limit)
        .map(|(value, count)| SupportSummaryItem {
            value,
            count,
            hint: None,
            severity: None,
        })
        .collect()
}

fn increment_count(counts: &mut HashMap<String, usize>, value: &str) {
    *counts.entry(value.to_string()).or_insert(0) += 1;
}

fn row_respsize_zero(row: &serde_json::Map<String, serde_json::Value>) -> bool {
    row.get("respsize")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<i64>().ok())
        == Some(0)
}

fn row_reason<'a>(
    row: &'a serde_json::Map<String, serde_json::Value>,
    fields: &FieldMap,
) -> Option<&'a str> {
    row_get_str(row, &fields.reason_field)
}

fn row_action<'a>(
    row: &'a serde_json::Map<String, serde_json::Value>,
    fields: &FieldMap,
) -> Option<&'a str> {
    row_get_str(row, &fields.action_field)
}

fn row_is_policy_issue(
    row: &serde_json::Map<String, serde_json::Value>,
    fields: &FieldMap,
) -> bool {
    let action = row_action(row, fields).unwrap_or_default();
    if action.eq_ignore_ascii_case("blocked") {
        return true;
    }
    let reason = row_reason(row, fields)
        .unwrap_or_default()
        .to_ascii_lowercase();
    reason.contains("not allowed")
        || reason.contains("blocked")
        || reason.contains("denylist")
        || reason.contains("url filtering")
}

fn row_is_tls_issue(row: &serde_json::Map<String, serde_json::Value>, fields: &FieldMap) -> bool {
    !row_tls_indicators(row, fields).is_empty()
}

fn row_tls_indicators(
    row: &serde_json::Map<String, serde_json::Value>,
    fields: &FieldMap,
) -> Vec<String> {
    let mut indicators = Vec::new();
    let reason = row_reason(row, fields)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if reason.contains("ssl")
        || reason.contains("tls")
        || reason.contains("certificate")
        || reason.contains("ocsp")
        || reason.contains("handshake")
    {
        indicators.push("reason=tls_or_certificate".to_string());
    }

    if let Some(value) = row_get_str(row, "externalspr") {
        let lower = value.to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "n/a" | "inspected" | "inspect all" | "none" | ""
        ) {
            indicators.push(format!("externalspr={value}"));
        }
    }
    if let Some(value) = row_get_str(row, "cltsslfailreason") {
        let lower = value.to_ascii_lowercase();
        if !matches!(lower.as_str(), "n/a" | "none" | "") {
            indicators.push(format!("cltsslfailreason={value}"));
        }
    }
    if let Some(value) = row_get_str(row, "is_ssluntrustedca") {
        let lower = value.to_ascii_lowercase();
        if matches!(lower.as_str(), "fail" | "yes") {
            indicators.push(format!("is_ssluntrustedca={value}"));
        }
    }
    if let Some(value) = row_get_str(row, "is_sslselfsigned")
        && value.eq_ignore_ascii_case("yes")
    {
        indicators.push(format!("is_sslselfsigned={value}"));
    }
    if let Some(value) = row_get_str(row, "is_sslexpiredca")
        && value.eq_ignore_ascii_case("yes")
    {
        indicators.push(format!("is_sslexpiredca={value}"));
    }
    for col in ["clienttlsversion", "srvtlsversion"] {
        if let Some(value) = row_get_str(row, col) {
            let lower = value.to_ascii_lowercase();
            if matches!(lower.as_str(), "ssl2" | "ssl3" | "tls1_1") {
                indicators.push(format!("{col}={value}"));
            }
        }
    }

    indicators
}

fn row_is_geo_issue(row: &serde_json::Map<String, serde_json::Value>, fields: &FieldMap) -> bool {
    let reason = row_reason(row, fields)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if reason.contains("country") || reason.contains("geo") {
        return true;
    }
    false
}

fn row_is_threat_issue(
    row: &serde_json::Map<String, serde_json::Value>,
    fields: &FieldMap,
) -> bool {
    let reason = row_reason(row, fields)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if reason.contains("phishing")
        || reason.contains("malware")
        || reason.contains("botnet")
        || reason.contains("spyware")
        || reason.contains("reputation")
        || reason.contains("ips block")
    {
        return true;
    }
    let threat = row_get_str(row, &fields.threat_field)
        .unwrap_or_default()
        .trim();
    !threat.is_empty() && !threat.eq_ignore_ascii_case("none") && threat != "N/A"
}

fn top_count_entry(counts: &HashMap<String, usize>) -> Option<(String, usize)> {
    counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(key, count)| (key.clone(), *count))
}

#[allow(clippy::too_many_arguments)]
fn build_root_cause_buckets(
    policy_reason_counts: &HashMap<String, usize>,
    ssl_reason_counts: &HashMap<String, usize>,
    zero_destination_counts: &HashMap<String, usize>,
    zero_reason_counts: &HashMap<String, usize>,
    geo_reason_counts: &HashMap<String, usize>,
    geo_destination_counts: &HashMap<String, usize>,
    threat_reason_counts: &HashMap<String, usize>,
    threat_name_counts: &HashMap<String, usize>,
    policy_count: usize,
    ssl_count: usize,
    zero_count: usize,
    geo_count: usize,
    threat_count: usize,
    fields: &FieldMap,
) -> Vec<SearchTriageBucket> {
    let mut buckets = Vec::new();
    if policy_count > 0 {
        let top_reason = top_count_entry(policy_reason_counts);
        buckets.push(SearchTriageBucket {
            id: "policy_block".to_string(),
            title: "Policy Blocks".to_string(),
            severity: "high".to_string(),
            summary: match top_reason.as_ref() {
                Some((reason, count)) => format!("Dominant block reason: {reason} ({count})"),
                None => "Blocked activity is present in the current window.".to_string(),
            },
            count: policy_count,
            filters: SearchFilters {
                action: Some("Blocked".to_string()),
                reason: top_reason.as_ref().map(|(reason, _)| reason.clone()),
                ..SearchFilters::default()
            },
            example_values: top_support_items(policy_reason_counts, 3)
                .into_iter()
                .map(|item| item.value)
                .collect(),
        });
    }
    if ssl_count > 0 {
        let top_reason = top_count_entry(ssl_reason_counts);
        buckets.push(SearchTriageBucket {
            id: "ssl_tls".to_string(),
            title: "SSL/TLS Issues".to_string(),
            severity: "high".to_string(),
            summary: match top_reason.as_ref() {
                Some((reason, count)) => format!("Dominant TLS signal: {reason} ({count})"),
                None => "TLS, certificate, or handshake issues are present.".to_string(),
            },
            count: ssl_count,
            filters: SearchFilters {
                reason: top_reason.as_ref().map(|(reason, _)| reason.clone()),
                ..SearchFilters::default()
            },
            example_values: top_support_items(ssl_reason_counts, 3)
                .into_iter()
                .map(|item| item.value)
                .collect(),
        });
    }
    if zero_count > 0 {
        let top_destination = top_count_entry(zero_destination_counts);
        buckets.push(SearchTriageBucket {
            id: "zero_response".to_string(),
            title: "Zero-Response Destinations".to_string(),
            severity: "medium".to_string(),
            summary: match top_destination.as_ref() {
                Some((destination, count)) => {
                    format!("Destination with respsize=0 leading signal: {destination} ({count})")
                }
                None => "Transactions with respsize=0 are present.".to_string(),
            },
            count: zero_count,
            filters: SearchFilters {
                server_ip: top_destination
                    .as_ref()
                    .map(|(destination, _)| destination.clone()),
                reason: top_count_entry(zero_reason_counts).map(|(reason, _)| reason),
                ..SearchFilters::default()
            },
            example_values: top_support_items(zero_destination_counts, 3)
                .into_iter()
                .map(|item| item.value)
                .collect(),
        });
    }
    if geo_count > 0 {
        let top_geo_reason = top_count_entry(geo_reason_counts);
        let top_geo_destination = top_count_entry(geo_destination_counts);
        buckets.push(SearchTriageBucket {
            id: "geo_issue".to_string(),
            title: "Geo Issues".to_string(),
            severity: "high".to_string(),
            summary: match (top_geo_reason.as_ref(), top_geo_destination.as_ref()) {
                (Some((reason, _)), Some((destination_country, _))) => {
                    format!(
                        "Geo signal led by {reason}; top destination country {destination_country}"
                    )
                }
                (Some((reason, _)), None) => format!("Geo signal led by reason: {reason}"),
                _ => "Country or geo-related policy signals are present.".to_string(),
            },
            count: geo_count,
            filters: SearchFilters {
                reason: top_geo_reason.as_ref().map(|(reason, _)| reason.clone()),
                destination_country: top_geo_destination
                    .as_ref()
                    .map(|(destination_country, _)| destination_country.clone()),
                ..SearchFilters::default()
            },
            example_values: top_support_items(geo_reason_counts, 3)
                .into_iter()
                .map(|item| item.value)
                .collect(),
        });
    }
    if threat_count > 0 {
        let top_threat = top_count_entry(threat_name_counts);
        let top_reason = top_count_entry(threat_reason_counts);
        buckets.push(SearchTriageBucket {
            id: "threat_reputation".to_string(),
            title: "Threat / Reputation".to_string(),
            severity: "critical".to_string(),
            summary: match (top_threat.as_ref(), top_reason.as_ref()) {
                (Some((threat, _)), Some((reason, _))) => {
                    format!("Threat signal led by {threat}; dominant reason {reason}")
                }
                (Some((threat, _)), None) => format!("Threat signal led by {threat}"),
                (None, Some((reason, _))) => format!("Threat signal led by {reason}"),
                _ => "Threat or reputation-related traffic is present.".to_string(),
            },
            count: threat_count,
            filters: SearchFilters {
                threat: top_threat.as_ref().map(|(threat, _)| threat.clone()),
                reason: top_reason.as_ref().map(|(reason, _)| reason.clone()),
                ..SearchFilters::default()
            },
            example_values: top_support_items(threat_name_counts, 3)
                .into_iter()
                .map(|item| item.value)
                .chain(
                    top_support_items(threat_reason_counts, 2)
                        .into_iter()
                        .map(|item| item.value),
                )
                .collect(),
        });
    }
    buckets.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.title.cmp(&b.title)));
    let _ = fields;
    buckets
}

fn timeline_marker_from_bucket(
    bucket: &TimelineBucketAggregate,
    bucket_start: DateTime<Utc>,
    bucket_end: DateTime<Utc>,
    fields: &FieldMap,
) -> Option<SearchTimelineMarker> {
    if bucket.total == 0 {
        return None;
    }
    let dominant = [
        (
            "threat_reputation",
            "Threat / Reputation",
            "critical",
            bucket.threat,
        ),
        ("ssl_tls", "SSL/TLS", "high", bucket.ssl_tls),
        ("geo_issue", "Geo Issue", "high", bucket.geo),
        (
            "zero_response",
            "Zero Response",
            "medium",
            bucket.zero_response,
        ),
        ("policy_block", "Policy Block", "medium", bucket.policy),
    ]
    .into_iter()
    .max_by(|a, b| a.3.cmp(&b.3).then_with(|| a.0.cmp(b.0)))?;
    if dominant.3 == 0 {
        return None;
    }

    let (summary, filters) = match dominant.0 {
        "threat_reputation" => {
            let top_threat = top_count_entry(&bucket.threat_counts);
            (
                top_threat
                    .as_ref()
                    .map(|(threat, count)| {
                        format!("{count} threat/reputation events led by {threat}")
                    })
                    .unwrap_or_else(|| {
                        "Threat/reputation signals detected in this bucket.".to_string()
                    }),
                SearchFilters {
                    threat: top_threat.map(|(threat, _)| threat),
                    ..SearchFilters::default()
                },
            )
        }
        "ssl_tls" => {
            let top_reason = top_count_entry(&bucket.reason_counts);
            (
                top_reason
                    .as_ref()
                    .map(|(reason, count)| format!("{count} SSL/TLS events led by {reason}"))
                    .unwrap_or_else(|| "SSL/TLS signals detected in this bucket.".to_string()),
                SearchFilters {
                    reason: top_reason.map(|(reason, _)| reason),
                    ..SearchFilters::default()
                },
            )
        }
        "geo_issue" => {
            let top_reason = top_count_entry(&bucket.reason_counts);
            (
                top_reason
                    .as_ref()
                    .map(|(reason, count)| format!("{count} geo-related events led by {reason}"))
                    .unwrap_or_else(|| "Geo-related signals detected in this bucket.".to_string()),
                SearchFilters {
                    reason: top_reason.map(|(reason, _)| reason),
                    ..SearchFilters::default()
                },
            )
        }
        "zero_response" => {
            let top_destination = top_count_entry(&bucket.destination_counts);
            (
                top_destination
                    .as_ref()
                    .map(|(destination, count)| {
                        format!("{count} zero-response events targeting {destination}")
                    })
                    .unwrap_or_else(|| {
                        "Zero-response destinations detected in this bucket.".to_string()
                    }),
                SearchFilters {
                    server_ip: top_destination.map(|(destination, _)| destination),
                    ..SearchFilters::default()
                },
            )
        }
        _ => {
            let top_reason = top_count_entry(&bucket.reason_counts);
            (
                top_reason
                    .as_ref()
                    .map(|(reason, count)| format!("{count} blocked/policy events led by {reason}"))
                    .unwrap_or_else(|| {
                        "Blocked/policy activity detected in this bucket.".to_string()
                    }),
                SearchFilters {
                    action: Some("Blocked".to_string()),
                    reason: top_reason.map(|(reason, _)| reason),
                    ..SearchFilters::default()
                },
            )
        }
    };

    let _ = fields;
    Some(SearchTimelineMarker {
        at: bucket_start,
        bucket_start,
        bucket_end,
        category: dominant.1.to_string(),
        severity: dominant.2.to_string(),
        label: dominant.1.to_string(),
        summary,
        filters,
    })
}

fn grouped_columns_for_mode(fields: &FieldMap, mode: SearchViewMode) -> Vec<String> {
    match mode {
        SearchViewMode::Raw => vec![
            fields.time_field.clone(),
            fields.action_field.clone(),
            fields.server_ip_field.clone(),
            fields.reason_field.clone(),
            fields.response_code_field.clone(),
            fields.user_field.clone(),
            fields.device_field.clone(),
        ],
        SearchViewMode::ByDestination => vec![
            fields.server_ip_field.clone(),
            fields.action_field.clone(),
            fields.response_code_field.clone(),
        ],
        SearchViewMode::ByReason => vec![
            fields.reason_field.clone(),
            fields.response_code_field.clone(),
            fields.action_field.clone(),
        ],
        SearchViewMode::ByUserDevice => vec![
            fields.user_field.clone(),
            fields.device_field.clone(),
            fields.action_field.clone(),
        ],
    }
}

fn compare_grouped_rows(
    a: &serde_json::Map<String, serde_json::Value>,
    b: &serde_json::Map<String, serde_json::Value>,
    sort_key: &str,
    desc: bool,
) -> std::cmp::Ordering {
    let order = if sort_key.eq_ignore_ascii_case("count") {
        let av = a
            .get("count")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let bv = b
            .get("count")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        av.cmp(&bv)
    } else {
        let av = a.get(sort_key).and_then(|v| v.as_str()).unwrap_or_default();
        let bv = b.get(sort_key).and_then(|v| v.as_str()).unwrap_or_default();
        av.cmp(bv)
    };
    if desc { order.reverse() } else { order }
}

fn open_query_connection() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    let temp_dir = std::env::temp_dir().join("nss-quarry-duckdb");
    std::fs::create_dir_all(&temp_dir)
        .with_context(|| format!("failed creating DuckDB temp dir {}", temp_dir.display()))?;
    conn.execute_batch(&format!(
        "SET memory_limit = '{memory_limit}'; \
         SET threads = {threads}; \
         SET temp_directory = '{temp_dir}';",
        memory_limit = DUCKDB_MEMORY_LIMIT,
        threads = DUCKDB_THREADS,
        temp_dir = escape_sql_literal(&temp_dir.display().to_string()),
    ))?;
    Ok(conn)
}

fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

fn split_csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn rows_to_csv(rows: &[serde_json::Map<String, serde_json::Value>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let headers = rows[0].keys().cloned().collect::<Vec<_>>();
    let mut out = String::new();
    out.push_str(
        &headers
            .iter()
            .map(|h| csv_escape(h))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
    for row in rows {
        let line = headers
            .iter()
            .map(|h| {
                let v = row.get(h).cloned().unwrap_or(serde_json::Value::Null);
                match v {
                    serde_json::Value::Null => String::new(),
                    serde_json::Value::String(s) => csv_escape(&s),
                    other => csv_escape(&other.to_string()),
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn csv_escape(value: &str) -> String {
    let value = neutralize_csv_formula(value);
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

fn neutralize_csv_formula(value: &str) -> String {
    let first_non_ws = value.chars().find(|c| !matches!(c, ' ' | '\t'));
    if matches!(first_non_ws, Some('=' | '+' | '-' | '@')) {
        format!("'{}", value)
    } else {
        value.to_string()
    }
}

fn apply_helpdesk_masking(
    rows: &mut [serde_json::Map<String, serde_json::Value>],
    sensitive_fields: &[String],
) {
    let sensitive = sensitive_fields.iter().cloned().collect::<HashSet<_>>();
    for row in rows {
        for key in &sensitive {
            if let Some(value) = row.get_mut(key)
                && !value.is_null()
            {
                *value = serde_json::Value::String("[REDACTED]".to_string());
            }
        }
    }
}

fn compile_visibility_filters(raw: VisibilityFilters) -> Result<CompiledVisibilityFilters> {
    const MAX_RULES: usize = 500;
    const MAX_RULE_LEN: usize = 256;

    if raw.url_regex.len() > MAX_RULES {
        anyhow::bail!("too many URL regex rules (max {MAX_RULES})");
    }
    if raw.blocked_ips.len() > MAX_RULES {
        anyhow::bail!("too many blocked IP rules (max {MAX_RULES})");
    }

    let mut normalized = VisibilityFilters::default();
    let mut compiled_url_regex = Vec::new();
    for pattern in raw.url_regex {
        let rule = pattern.trim();
        if rule.is_empty() {
            continue;
        }
        if rule.len() > MAX_RULE_LEN {
            anyhow::bail!("URL regex rule exceeds {MAX_RULE_LEN} characters");
        }
        let compiled =
            Regex::new(rule).map_err(|err| anyhow::anyhow!("invalid URL regex '{rule}': {err}"))?;
        normalized.url_regex.push(rule.to_string());
        compiled_url_regex.push(compiled);
    }

    let mut blocked_ip_set = HashSet::new();
    for value in raw.blocked_ips {
        let rule = value.trim();
        if rule.is_empty() {
            continue;
        }
        if rule.len() > MAX_RULE_LEN {
            anyhow::bail!("IP rule exceeds {MAX_RULE_LEN} characters");
        }
        let ip = rule
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid IP rule '{rule}'"))?;
        let canonical = ip.to_string().to_lowercase();
        blocked_ip_set.insert(canonical.clone());
        normalized.blocked_ips.push(canonical);
    }
    normalized.url_regex.sort();
    normalized.url_regex.dedup();
    normalized.blocked_ips.sort();
    normalized.blocked_ips.dedup();

    Ok(CompiledVisibilityFilters {
        raw: normalized,
        compiled_url_regex,
        blocked_ip_set,
    })
}

fn apply_visibility_filters(
    rows: &mut Vec<serde_json::Map<String, serde_json::Value>>,
    fields: &FieldMap,
    filters: &CompiledVisibilityFilters,
) {
    if filters.compiled_url_regex.is_empty() && filters.blocked_ip_set.is_empty() {
        return;
    }
    rows.retain(|row| !row_matches_visibility_filter(row, fields, filters));
}

fn row_matches_visibility_filter(
    row: &serde_json::Map<String, serde_json::Value>,
    fields: &FieldMap,
    filters: &CompiledVisibilityFilters,
) -> bool {
    if !filters.compiled_url_regex.is_empty()
        && let Some(url) = row_string(row, &[&fields.url_field, "url", "eurl"])
    {
        for re in &filters.compiled_url_regex {
            if re.is_match(url) {
                return true;
            }
        }
    }

    if filters.blocked_ip_set.is_empty() {
        return false;
    }
    [
        fields.source_ip_field.as_str(),
        fields.server_ip_field.as_str(),
    ]
    .into_iter()
    .chain([
        "cip",
        "cintip",
        "cpubip",
        "sip",
        "source_ip",
        "destination_ip",
    ])
    .any(|column| {
        row.get(column)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .map(|v| filters.blocked_ip_set.contains(&v.to_lowercase()))
            .unwrap_or(false)
    })
}

fn row_string<'a>(
    row: &'a serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter().find_map(|k| {
        row.get(*k)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    })
}

fn validate_time_window(from: DateTime<Utc>, to: DateTime<Utc>, max_days: i64) -> Result<()> {
    if to < from {
        anyhow::bail!("time_to must be >= time_from");
    }
    let range = to - from;
    if range > chrono::Duration::days(max_days) {
        anyhow::bail!("time window exceeds max_days_per_query={max_days}");
    }
    Ok(())
}

fn validate_filters(filters: &SearchFilters, re: &Regex) -> Result<()> {
    validate_filter_value(filters.user.as_deref(), re, false)?;
    validate_filter_value(filters.url.as_deref(), re, false)?;
    validate_filter_value(filters.action.as_deref(), re, false)?;
    validate_filter_value(filters.response_code.as_deref(), re, true)?;
    validate_filter_value(filters.response_size.as_deref(), re, true)?;
    validate_reason_filter(filters.reason.as_deref())?;
    validate_filter_value(filters.threat.as_deref(), re, false)?;
    validate_filter_value(filters.category.as_deref(), re, false)?;
    validate_filter_value(filters.source_ip.as_deref(), re, true)?;
    validate_filter_value(filters.server_ip.as_deref(), re, true)?;
    validate_filter_value(filters.source_country.as_deref(), re, true)?;
    validate_filter_value(filters.destination_country.as_deref(), re, true)?;
    validate_filter_value(filters.device.as_deref(), re, false)?;
    validate_filter_value(filters.department.as_deref(), re, false)?;
    Ok(())
}

fn validate_reason_filter(value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() {
        return Ok(());
    }
    if value.chars().count() > 256 {
        anyhow::bail!("reason filter exceeds 256 characters");
    }
    for c in value.chars() {
        if c.is_ascii_alphanumeric()
            || matches!(
                c,
                ' ' | '@'
                    | '.'
                    | '_'
                    | ':'
                    | '/'
                    | '-'
                    | ','
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '&'
                    | '+'
                    | '%'
                    | '\''
            )
        {
            continue;
        }
        anyhow::bail!("reason filter contains disallowed characters");
    }
    Ok(())
}

fn validate_filter_value(value: Option<&str>, re: &Regex, allow_csv: bool) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if allow_csv {
        for part in split_csv_values(value) {
            if !re.is_match(&part) {
                anyhow::bail!("filter value contains disallowed characters");
            }
        }
        return Ok(());
    }
    if !re.is_match(value) {
        anyhow::bail!("filter value contains disallowed characters");
    }
    Ok(())
}

fn parquet_source_sql_for_range(
    root: &Path,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Option<String>> {
    let files = parquet_files_for_range(root, from, to)?;
    if files.is_empty() {
        return Ok(None);
    }
    Ok(Some(parquet_source_sql_from_files(&files)))
}

fn parquet_source_sql_from_files(files: &[PathBuf]) -> String {
    let list = files
        .iter()
        .map(|path| format!("'{}'", escape_sql_literal(&path.display().to_string())))
        .collect::<Vec<_>>()
        .join(", ");
    format!("read_parquet([{list}], union_by_name=true)")
}

fn parquet_file_groups_for_range(
    root: &Path,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<Vec<PathBuf>>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut groups = Vec::new();
    let mut cursor = floor_to_hour(from);
    let end_floor = floor_to_hour(to);
    let end = if to == end_floor {
        end_floor - chrono::Duration::hours(1)
    } else {
        end_floor
    };
    if end < cursor {
        return Ok(groups);
    }
    while cursor <= end {
        let part_dir = root.join(format!(
            "dt={}/hour={:02}",
            cursor.format("%Y-%m-%d"),
            cursor.hour()
        ));
        let mut files = Vec::new();
        if part_dir.is_dir() {
            for entry in std::fs::read_dir(&part_dir)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_file()
                    && let Some(ext) = entry.path().extension().and_then(|e| e.to_str())
                    && ext.eq_ignore_ascii_case("parquet")
                {
                    files.push(entry.path());
                }
            }
        }
        files.sort();
        if !files.is_empty() {
            groups.push(files);
        }
        cursor += chrono::Duration::hours(1);
    }
    Ok(groups)
}

fn parquet_files_for_range(
    root: &Path,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let mut cursor = floor_to_hour(from);
    let end_floor = floor_to_hour(to);
    let end = if to == end_floor {
        end_floor - chrono::Duration::hours(1)
    } else {
        end_floor
    };
    if end < cursor {
        return Ok(files);
    }
    while cursor <= end {
        let part_dir = root.join(format!(
            "dt={}/hour={:02}",
            cursor.format("%Y-%m-%d"),
            cursor.hour()
        ));
        if part_dir.is_dir() {
            for entry in std::fs::read_dir(&part_dir)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_file()
                    && let Some(ext) = entry.path().extension().and_then(|e| e.to_str())
                    && ext.eq_ignore_ascii_case("parquet")
                {
                    files.push(entry.path());
                }
            }
        }
        cursor += chrono::Duration::hours(1);
    }
    files.sort();
    Ok(files)
}

fn floor_to_hour(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(ts)
}

fn validate_identifier(name: &str) -> Result<()> {
    let re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid regex");
    if re.is_match(name) {
        Ok(())
    } else {
        anyhow::bail!("invalid identifier '{}'", name);
    }
}

fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn find_any_parquet(root: &Path) -> Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file()
                && let Some(name) = entry.file_name().to_str()
                && name.ends_with(".parquet")
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::TimeZone;

    use super::*;

    #[test]
    fn validate_time_window_rejects_inverted_range() {
        let from = Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 3, 31, 23, 59, 59).unwrap();
        let err = validate_time_window(from, to, 7).expect_err("must reject to < from");
        assert!(err.to_string().contains("time_to must be >= time_from"));
    }

    #[test]
    fn validate_filters_rejects_disallowed_chars() {
        let re = Regex::new(r"^[A-Za-z0-9@\._:/\-\s]{1,256}$").expect("regex");
        let filters = SearchFilters {
            url: Some("evil;drop table".to_string()),
            ..SearchFilters::default()
        };
        let err = validate_filters(&filters, &re).expect_err("must reject semicolon");
        assert!(
            err.to_string()
                .contains("filter value contains disallowed characters")
        );
    }

    #[test]
    fn validate_filters_allows_reason_with_policy_punctuation() {
        let re = Regex::new(r"^[A-Za-z0-9@\._:/\-\s]{1,256}$").expect("regex");
        let filters = SearchFilters {
            reason: Some(
                "Violates Compliance Category, archive to mailbox failed (PII)".to_string(),
            ),
            ..SearchFilters::default()
        };
        validate_filters(&filters, &re).expect("reason punctuation should be allowed");
    }

    #[test]
    fn validate_filters_rejects_reason_with_control_characters() {
        let re = Regex::new(r"^[A-Za-z0-9@\._:/\-\s]{1,256}$").expect("regex");
        let filters = SearchFilters {
            reason: Some("Bad\nReason".to_string()),
            ..SearchFilters::default()
        };
        let err = validate_filters(&filters, &re).expect_err("must reject newline");
        assert!(
            err.to_string()
                .contains("reason filter contains disallowed characters")
        );
    }

    #[test]
    fn build_search_sql_includes_escaped_filters_and_limit() {
        let req = SearchRequest {
            time_from: Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap(),
            time_to: Utc.with_ymd_and_hms(2026, 4, 1, 1, 0, 0).unwrap(),
            filters: SearchFilters {
                user: Some("alice".to_string()),
                url: Some("exa%m_ple'\\path".to_string()),
                ..SearchFilters::default()
            },
            limit: Some(123),
            page: None,
            page_size: None,
            columns: Some(vec!["time".to_string(), "url".to_string()]),
        };
        let columns = req.columns.clone().expect("columns");
        let fields = FieldMap::default();
        let src = "read_parquet(['/tmp/o''hare/dt=2026-04-01/hour=00/part-000001.parquet'], union_by_name=true)";
        let sql = build_search_sql(&columns, &req, &fields, src, 123, 0);

        assert!(sql.contains(
            "SELECT CAST(\"time\" AS VARCHAR) AS \"time\", CAST(\"url\" AS VARCHAR) AS \"url\""
        ));
        assert!(sql.contains("read_parquet(['/tmp/o''hare/dt=2026-04-01/hour=00/part-000001.parquet'], union_by_name=true)"));
        assert!(sql.contains("ORDER BY \"time\" DESC LIMIT 123"));
        assert!(
            sql.contains(
                "CAST(\"time\" AS TIMESTAMP) >= TIMESTAMP '2026-04-01 00:00:00' AND CAST(\"time\" AS TIMESTAMP) < TIMESTAMP '2026-04-01 01:00:00'"
            ),
            "expected exclusive upper-bound timestamp filter"
        );

        let escaped_url = escape_sql_literal("exa%m_ple'\\path");
        assert!(sql.contains("STRPOS(LOWER(CAST(\"login\" AS VARCHAR)), LOWER('alice')) > 0"));
        assert!(sql.contains(&format!(
            "STRPOS(LOWER(CAST(\"url\" AS VARCHAR)), LOWER('{}')) > 0",
            escaped_url
        )));
    }

    #[test]
    fn build_search_sql_supports_multiple_server_ips() {
        let req = SearchRequest {
            time_from: Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap(),
            time_to: Utc.with_ymd_and_hms(2026, 4, 1, 1, 0, 0).unwrap(),
            filters: SearchFilters {
                server_ip: Some("1.1.1.1, 8.8.8.8".to_string()),
                ..SearchFilters::default()
            },
            limit: Some(50),
            page: None,
            page_size: None,
            columns: Some(vec!["time".to_string(), "sip".to_string()]),
        };
        let columns = req.columns.clone().expect("columns");
        let fields = FieldMap::default();
        let src =
            "read_parquet(['/tmp/dt=2026-04-01/hour=00/part-000001.parquet'], union_by_name=true)";
        let sql = build_search_sql(&columns, &req, &fields, src, 50, 0);

        assert!(sql.contains("LOWER(CAST(\"sip\" AS VARCHAR)) IN ('1.1.1.1', '8.8.8.8')"));
    }

    #[test]
    fn build_search_sql_supports_response_size_and_tls_filters() {
        let fields = FieldMap::default();
        let req = SearchRequest {
            time_from: Utc::now() - ChronoDuration::hours(1),
            time_to: Utc::now(),
            filters: SearchFilters {
                response_size: Some("0".to_string()),
                tls_issue_only: Some(true),
                ..SearchFilters::default()
            },
            limit: Some(100),
            page: None,
            page_size: None,
            columns: None,
        };
        let columns = vec![
            "time".to_string(),
            "reason".to_string(),
            "respsize".to_string(),
        ];
        let sql = build_search_sql(&columns, &req, &fields, "read_parquet('x')", 100, 0);
        assert!(sql.contains("LOWER(CAST(\"reason\" AS VARCHAR))"));
        assert!(sql.contains("CAST(\"respsize\" AS VARCHAR)"));
        assert!(sql.contains("'0'"));
    }

    #[test]
    fn parquet_files_for_range_only_includes_overlapping_hours() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nss-quarry-range-test-{unique}"));
        let h00 = root.join("dt=2026-04-01").join("hour=00");
        let h01 = root.join("dt=2026-04-01").join("hour=01");
        let h02 = root.join("dt=2026-04-01").join("hour=02");

        std::fs::create_dir_all(&h00).expect("mkdir h00");
        std::fs::create_dir_all(&h01).expect("mkdir h01");
        std::fs::create_dir_all(&h02).expect("mkdir h02");
        std::fs::write(h00.join("part-000001.parquet"), b"").expect("touch h00 parquet");
        std::fs::write(h01.join("part-000001.parquet"), b"").expect("touch h01 parquet");
        std::fs::write(h02.join("part-000001.parquet"), b"").expect("touch h02 parquet");

        let from = Utc.with_ymd_and_hms(2026, 4, 1, 0, 30, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 4, 1, 1, 5, 0).unwrap();
        let files = parquet_files_for_range(&root, from, to).expect("range files");

        assert_eq!(files.len(), 2);
        let joined = files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("hour=00/part-000001.parquet"));
        assert!(joined.contains("hour=01/part-000001.parquet"));
        assert!(!joined.contains("hour=02/part-000001.parquet"));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn parquet_files_for_range_excludes_upper_hour_on_exact_boundary() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nss-quarry-boundary-test-{unique}"));
        let h00 = root.join("dt=2026-04-01").join("hour=00");
        let h01 = root.join("dt=2026-04-01").join("hour=01");

        std::fs::create_dir_all(&h00).expect("mkdir h00");
        std::fs::create_dir_all(&h01).expect("mkdir h01");
        std::fs::write(h00.join("part-000001.parquet"), b"").expect("touch h00 parquet");
        std::fs::write(h01.join("part-000001.parquet"), b"").expect("touch h01 parquet");

        let from = Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 4, 1, 1, 0, 0).unwrap();
        let files = parquet_files_for_range(&root, from, to).expect("range files");

        assert_eq!(
            files.len(),
            1,
            "upper hour should be excluded when time_to is exact"
        );
        let only = files[0].display().to_string();
        assert!(only.contains("hour=00/part-000001.parquet"));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn build_search_sql_includes_offset_when_requested() {
        let req = SearchRequest {
            time_from: Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap(),
            time_to: Utc.with_ymd_and_hms(2026, 4, 1, 1, 0, 0).unwrap(),
            filters: SearchFilters::default(),
            limit: Some(200),
            page: None,
            page_size: None,
            columns: Some(vec!["time".to_string()]),
        };
        let columns = req.columns.clone().expect("columns");
        let fields = FieldMap::default();
        let src =
            "read_parquet(['/tmp/dt=2026-04-01/hour=00/part-000001.parquet'], union_by_name=true)";
        let sql = build_search_sql(&columns, &req, &fields, src, 200, 400);
        assert!(sql.contains("LIMIT 200 OFFSET 400"));
    }

    #[test]
    fn parquet_file_groups_for_range_groups_files_per_hour() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nss-quarry-group-range-test-{unique}"));
        let h00 = root.join("dt=2026-04-01").join("hour=00");
        let h01 = root.join("dt=2026-04-01").join("hour=01");

        std::fs::create_dir_all(&h00).expect("mkdir h00");
        std::fs::create_dir_all(&h01).expect("mkdir h01");
        std::fs::write(h00.join("part-000001.parquet"), b"").expect("touch h00 parquet 1");
        std::fs::write(h00.join("part-000002.parquet"), b"").expect("touch h00 parquet 2");
        std::fs::write(h01.join("part-000001.parquet"), b"").expect("touch h01 parquet");

        let from = Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 4, 1, 1, 30, 0).unwrap();
        let groups = parquet_file_groups_for_range(&root, from, to).expect("range groups");

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[1].len(), 1);

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn apply_visibility_filters_hides_rows_on_url_or_ip_rule_match() {
        let mut row = serde_json::Map::new();
        row.insert(
            "cip".to_string(),
            serde_json::Value::String("10.0.0.10".to_string()),
        );
        row.insert(
            "sip".to_string(),
            serde_json::Value::String("8.8.8.8".to_string()),
        );
        row.insert(
            "url".to_string(),
            serde_json::Value::String("example.com".to_string()),
        );
        let mut safe_row = serde_json::Map::new();
        safe_row.insert(
            "cip".to_string(),
            serde_json::Value::String("10.0.0.11".to_string()),
        );
        safe_row.insert(
            "sip".to_string(),
            serde_json::Value::String("8.8.4.4".to_string()),
        );
        safe_row.insert(
            "url".to_string(),
            serde_json::Value::String("safe.example.com".to_string()),
        );
        let mut rows = vec![row, safe_row];
        let fields = FieldMap::default();
        let compiled = compile_visibility_filters(VisibilityFilters {
            url_regex: vec!["^example\\.com$".to_string()],
            blocked_ips: vec!["10.0.0.10".to_string()],
        })
        .expect("compile visibility filters");

        apply_visibility_filters(&mut rows, &fields, &compiled);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["url"], "safe.example.com");
    }

    #[test]
    fn compile_visibility_filters_rejects_invalid_ip() {
        let err = compile_visibility_filters(VisibilityFilters {
            url_regex: Vec::new(),
            blocked_ips: vec!["not-an-ip".to_string()],
        })
        .expect_err("must reject invalid ip");
        assert!(err.to_string().contains("invalid IP rule"));
    }

    #[test]
    fn empty_dashboard_response_includes_response_code_table() {
        let generated_at = Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap();
        let response = empty_dashboard_response(
            "overview",
            generated_at,
            DashboardStatus::Warming,
            "warming",
            vec!["building".to_string()],
            true,
            DashboardRefreshState::default(),
        );

        assert!(
            response
                .tables
                .iter()
                .any(|table| table.name == "top_response_codes")
        );
        assert!(
            response
                .tables
                .iter()
                .any(|table| table.name == "top_policy_reasons")
        );
    }

    #[test]
    fn dashboard_status_is_ready_for_fresh_snapshot() {
        let now = Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap();
        let snapshot = DashboardSnapshot {
            version: DASHBOARD_SNAPSHOT_VERSION,
            name: "overview".to_string(),
            generated_at: Utc.with_ymd_and_hms(2026, 4, 5, 11, 45, 0).unwrap(),
            data_window_from: Utc.with_ymd_and_hms(2026, 4, 4, 11, 0, 0).unwrap(),
            data_window_to: Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap(),
            aggregate: DashboardAggregate::default(),
        };
        assert!(!snapshot_needs_refresh(&snapshot, now, 3600));
        assert_eq!(snapshot_age_seconds(&snapshot, now), 900);
    }

    #[test]
    fn dashboard_status_detects_stale_snapshot() {
        let now = Utc.with_ymd_and_hms(2026, 4, 5, 14, 5, 0).unwrap();
        let snapshot = DashboardSnapshot {
            version: DASHBOARD_SNAPSHOT_VERSION,
            name: "overview".to_string(),
            generated_at: Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap(),
            data_window_from: Utc.with_ymd_and_hms(2026, 4, 4, 12, 0, 0).unwrap(),
            data_window_to: Utc.with_ymd_and_hms(2026, 4, 5, 12, 0, 0).unwrap(),
            aggregate: DashboardAggregate::default(),
        };
        assert!(snapshot_needs_refresh(&snapshot, now, 3600));
    }

    #[test]
    fn trim_dashboard_error_message_bounds_output() {
        let msg = "x".repeat(300);
        let trimmed = trim_dashboard_error_message(&msg);
        assert!(trimmed.len() <= 243);
        assert!(trimmed.ends_with("..."));
    }

    #[test]
    fn csv_escape_neutralizes_formula_injection_payloads() {
        assert_eq!(csv_escape("=2+2"), "'=2+2");
        assert_eq!(csv_escape(" \t+SUM(A1:A2)"), "' \t+SUM(A1:A2)");
        assert_eq!(csv_escape("@malicious"), "'@malicious");
        assert_eq!(csv_escape("normal-value"), "normal-value");
    }
}
