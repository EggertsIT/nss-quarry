mod audit;
mod auth;
mod config;
mod models;
mod query;
mod webui;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use clap::{Parser, Subcommand};
use duckdb::Connection;
use tracing::{error, info};

use crate::audit::AuditLogger;
use crate::auth::{AuthManager, has_min_role};
use crate::config::{AppConfig, AuthMode, RoleName};
use crate::models::{
    AuditEvent, AuditListResponse, AuthResponse, HealthResponse, LocalLoginRequest,
    ParquetColumnInfo, ReadyResponse, SchemaFieldInfo, SchemaResponse, SearchRequest,
};
use crate::query::QueryService;
use crate::webui::render_dashboard_html;

#[derive(Parser, Debug)]
#[command(name = "nss-quarry")]
#[command(about = "Secure helpdesk query and dashboard service for NSS Parquet logs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    ValidateConfig {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    HashPassword {
        #[arg(long)]
        password: String,
    },
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<AppConfig>,
    auth: AuthManager,
    audit: AuditLogger,
    query: QueryService,
}

#[derive(Debug, serde::Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Command::Run { config } => run(config).await,
        Command::ValidateConfig { config } => {
            let cfg = AppConfig::load(&config)?;
            info!(
                bind = %cfg.server.bind_addr,
                parquet_root = %cfg.data.parquet_root.display(),
                mode = ?cfg.auth.mode,
                "config is valid"
            );
            Ok(())
        }
        Command::HashPassword { password } => {
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|_| anyhow::anyhow!("failed to hash password"))?
                .to_string();
            println!("{hash}");
            Ok(())
        }
    }
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

async fn run(config_path: std::path::PathBuf) -> Result<()> {
    let cfg = Arc::new(AppConfig::load(&config_path)?);
    let auth = AuthManager::new(&cfg.auth).await?;
    let query = QueryService::new(&cfg)?;
    let audit = AuditLogger::new(&cfg.audit).await?;
    let state = AppState {
        cfg: Arc::clone(&cfg),
        auth,
        audit,
        query,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/dashboard", get(dashboard_page))
        .route("/auth/login", get(auth_login_oidc).post(auth_login_local))
        .route("/auth/callback", get(auth_callback_oidc))
        .route("/auth/logout", post(auth_logout))
        .route("/api/me", get(api_me))
        .route("/api/search", post(api_search))
        .route("/api/export/csv", post(api_export_csv))
        .route("/api/dashboards/{name}", get(api_dashboard))
        .route("/api/schema", get(api_schema))
        .route("/api/audit", get(api_audit))
        .route("/api/audit/export/csv", get(api_audit_export_csv))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cfg.server.bind_addr)
        .await
        .with_context(|| format!("failed binding to {}", cfg.server.bind_addr))?;
    info!(bind = %cfg.server.bind_addr, "nss-quarry listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        generated_at: Utc::now(),
    })
}

async fn readyz(State(state): State<AppState>) -> Response {
    match state.query.ready_check().await {
        Ok(()) => (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ok",
                reason: None,
                generated_at: Utc::now(),
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "degraded",
                reason: Some(err.to_string()),
                generated_at: Utc::now(),
            }),
        )
            .into_response(),
    }
}

async fn dashboard_page(State(state): State<AppState>) -> Html<String> {
    Html(render_dashboard_html(state.cfg.auth.mode))
}

async fn auth_login_local(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LocalLoginRequest>,
) -> Result<(CookieJar, Json<AuthResponse>), AppError> {
    let res = state
        .auth
        .local_login(req)
        .await
        .map_err(AppError::bad_request)?;
    let cookie = state.auth.create_session_cookie(res.user.clone()).await;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(res.user.username.clone()),
            role: Some(res.user.role),
            action: "auth.local_login".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({ "mode": "local_users" }),
        })
        .await;
    Ok((jar.add(cookie), Json(res)))
}

async fn auth_login_oidc(State(state): State<AppState>) -> Result<Redirect, AppError> {
    if state.auth.mode() == AuthMode::LocalUsers {
        return Err(AppError::method_not_allowed(
            "OIDC login is disabled in local_users mode",
        ));
    }
    let url = state
        .auth
        .oidc_login_url()
        .await
        .map_err(AppError::internal)?;
    Ok(Redirect::to(&url))
}

async fn auth_callback_oidc(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<OidcCallbackQuery>,
) -> Result<(CookieJar, Redirect), AppError> {
    let res = state
        .auth
        .oidc_callback(&params.code, &params.state)
        .await
        .map_err(AppError::unauthorized)?;
    let cookie = state.auth.create_session_cookie(res.user.clone()).await;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(res.user.username.clone()),
            role: Some(res.user.role),
            action: "auth.oidc_callback".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({ "mode": res.user.auth_mode }),
        })
        .await;
    Ok((jar.add(cookie), Redirect::to("/dashboard")))
}

async fn auth_logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AppError> {
    let actor = state
        .auth
        .resolve_user_from_cookie(&jar)
        .await
        .map(|u| u.username);
    state.auth.invalidate_cookie_session(&jar).await;
    let cleared = state.auth.clear_session_cookie();
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor,
            role: None,
            action: "auth.logout".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({}),
        })
        .await;
    Ok((jar.add(cleared), StatusCode::NO_CONTENT))
}

async fn api_me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<AuthResponse>, AppError> {
    let user = require_user(&state, &jar, RoleName::Helpdesk).await?;
    Ok(Json(AuthResponse { user }))
}

async fn api_search(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<SearchRequest>,
) -> Result<Json<crate::models::SearchResponse>, AppError> {
    let user = require_user(&state, &jar, RoleName::Helpdesk).await?;
    let result = state
        .query
        .search(req.clone(), user.role)
        .await
        .map_err(AppError::bad_request)?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "query.search".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "query": req,
                "rows": result.row_count
            }),
        })
        .await;
    Ok(Json(result))
}

async fn api_export_csv(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<SearchRequest>,
) -> Result<Response, AppError> {
    let user = require_user(&state, &jar, RoleName::Helpdesk).await?;
    let csv = state
        .query
        .export_csv(req.clone(), user.role)
        .await
        .map_err(AppError::bad_request)?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "query.export_csv".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "query": req,
                "bytes": csv.len()
            }),
        })
        .await;

    let mut res = Response::new(csv.into());
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    res.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"nss-quarry-export.csv\""),
    );
    Ok(res)
}

async fn api_dashboard(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(name): Path<String>,
) -> Result<Json<crate::models::DashboardResponse>, AppError> {
    let user = require_user(&state, &jar, RoleName::Helpdesk).await?;
    let data = state
        .query
        .dashboard(&name, user.role)
        .await
        .map_err(AppError::bad_request)?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "query.dashboard".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({ "name": name }),
        })
        .await;
    Ok(Json(data))
}

async fn api_schema(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<SchemaResponse>, AppError> {
    let _user = require_user(&state, &jar, RoleName::Helpdesk).await?;
    let fields = vec![
        SchemaFieldInfo {
            name: "time_field".to_string(),
            mapped_from: state.cfg.data.fields.time_field.clone(),
        },
        SchemaFieldInfo {
            name: "user_field".to_string(),
            mapped_from: state.cfg.data.fields.user_field.clone(),
        },
        SchemaFieldInfo {
            name: "url_field".to_string(),
            mapped_from: state.cfg.data.fields.url_field.clone(),
        },
        SchemaFieldInfo {
            name: "action_field".to_string(),
            mapped_from: state.cfg.data.fields.action_field.clone(),
        },
        SchemaFieldInfo {
            name: "threat_field".to_string(),
            mapped_from: state.cfg.data.fields.threat_field.clone(),
        },
        SchemaFieldInfo {
            name: "category_field".to_string(),
            mapped_from: state.cfg.data.fields.category_field.clone(),
        },
        SchemaFieldInfo {
            name: "source_ip_field".to_string(),
            mapped_from: state.cfg.data.fields.source_ip_field.clone(),
        },
        SchemaFieldInfo {
            name: "server_ip_field".to_string(),
            mapped_from: state.cfg.data.fields.server_ip_field.clone(),
        },
        SchemaFieldInfo {
            name: "device_field".to_string(),
            mapped_from: state.cfg.data.fields.device_field.clone(),
        },
        SchemaFieldInfo {
            name: "department_field".to_string(),
            mapped_from: state.cfg.data.fields.department_field.clone(),
        },
    ];
    let parquet_root = state.cfg.data.parquet_root.clone();
    let (parquet_columns, parquet_schema_error) =
        tokio::task::spawn_blocking(move || detect_parquet_columns(&parquet_root))
            .await
            .map_err(AppError::internal)?;

    let auth_mode = match state.cfg.auth.mode {
        AuthMode::OidcEntra => "oidc_entra",
        AuthMode::OidcOkta => "oidc_okta",
        AuthMode::LocalUsers => "local_users",
    };
    Ok(Json(SchemaResponse {
        auth_mode: auth_mode.to_string(),
        fields,
        parquet_columns,
        parquet_schema_error,
        default_columns: state.cfg.query.default_columns.clone(),
        helpdesk_mask_fields: state.cfg.security.helpdesk_mask_fields.clone(),
        generated_at: Utc::now(),
    }))
}

fn detect_parquet_columns(root: &std::path::Path) -> (Vec<ParquetColumnInfo>, Option<String>) {
    let Some(sample_file) = find_first_parquet(root) else {
        return (
            Vec::new(),
            Some(format!("No parquet file found under {}", root.display())),
        );
    };

    let conn = match Connection::open_in_memory() {
        Ok(c) => c,
        Err(err) => {
            return (Vec::new(), Some(format!("duckdb open failed: {err}")));
        }
    };

    let sample_file_sql = sample_file.display().to_string().replace('\'', "''");
    let sql =
        format!("DESCRIBE SELECT * FROM read_parquet('{sample_file_sql}', union_by_name=true)");

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(err) => {
            return (
                Vec::new(),
                Some(format!(
                    "failed to inspect parquet schema from {}: {err}",
                    sample_file.display()
                )),
            );
        }
    };

    let mut rows = match stmt.query([]) {
        Ok(r) => r,
        Err(err) => {
            return (
                Vec::new(),
                Some(format!(
                    "failed to query parquet schema from {}: {err}",
                    sample_file.display()
                )),
            );
        }
    };

    let mut cols = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        let name: Option<String> = row.get(0).ok();
        let data_type: Option<String> = row.get(1).ok();
        if let (Some(name), Some(data_type)) = (name, data_type) {
            cols.push(ParquetColumnInfo { name, data_type });
        }
    }

    (cols, None)
}

fn find_first_parquet(root: &std::path::Path) -> Option<PathBuf> {
    if !root.exists() {
        return None;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("parquet"))
            {
                return Some(entry.path());
            }
        }
    }
    None
}

const DEFAULT_AUDIT_PAGE_SIZE: u32 = 50;
const MAX_AUDIT_PAGE_SIZE: u32 = 500;
const MAX_AUDIT_EXPORT_ROWS: usize = 50_000;

#[derive(Debug, Clone, serde::Deserialize)]
struct AuditListQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    from: Option<chrono::DateTime<Utc>>,
    to: Option<chrono::DateTime<Utc>>,
    actor: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    text: Option<String>,
}

impl Default for AuditListQuery {
    fn default() -> Self {
        Self {
            page: Some(1),
            page_size: Some(DEFAULT_AUDIT_PAGE_SIZE),
            from: None,
            to: None,
            actor: None,
            action: None,
            outcome: None,
            text: None,
        }
    }
}

async fn api_audit(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<AuditListQuery>,
) -> Result<Json<AuditListResponse>, AppError> {
    let user = require_user(&state, &jar, RoleName::Admin).await?;
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
        .clamp(1, MAX_AUDIT_PAGE_SIZE);

    let start = ((page - 1) as usize).saturating_mul(page_size as usize);
    let (rows, total) =
        load_paginated_audit_events(&state.cfg.audit.path, &query, start, page_size as usize)
            .await
            .map_err(AppError::internal)?;
    let total_pages = if total == 0 {
        0
    } else {
        ((total as u64).div_ceil(page_size as u64)) as u32
    };

    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.audit.read".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "page": page,
                "page_size": page_size,
                "returned": rows.len(),
                "total": total,
                "filters": audit_filter_metadata(&query),
            }),
        })
        .await;

    Ok(Json(AuditListResponse {
        rows,
        page,
        page_size,
        total,
        total_pages,
    }))
}

async fn api_audit_export_csv(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<AuditListQuery>,
) -> Result<Response, AppError> {
    let user = require_user(&state, &jar, RoleName::Admin).await?;
    let filtered = load_filtered_audit_events(&state.cfg.audit.path, &query)
        .await
        .map_err(AppError::internal)?;
    let rows = filtered
        .into_iter()
        .take(MAX_AUDIT_EXPORT_ROWS)
        .collect::<Vec<_>>();
    let csv = audit_rows_to_csv(&rows);

    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.audit.export_csv".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "rows": rows.len(),
                "bytes": csv.len(),
                "filters": audit_filter_metadata(&query),
            }),
        })
        .await;

    let mut res = Response::new(csv.into());
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    res.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"nss-quarry-audit.csv\""),
    );
    Ok(res)
}

async fn load_filtered_audit_events(
    path: &std::path::Path,
    query: &AuditListQuery,
) -> Result<Vec<AuditEvent>> {
    let files = audit_log_files(path).await?;
    let mut out = Vec::new();
    for file in files {
        let text = match tokio::fs::read_to_string(&file).await {
            Ok(t) => t,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed reading audit log {}", file.display()));
            }
        };
        for line in text.lines().rev() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<AuditEvent>(line) else {
                continue;
            };
            if audit_event_matches(&event, query) {
                out.push(event);
            }
        }
    }
    Ok(out)
}

async fn load_paginated_audit_events(
    path: &std::path::Path,
    query: &AuditListQuery,
    offset: usize,
    limit: usize,
) -> Result<(Vec<AuditEvent>, usize)> {
    let files = audit_log_files(path).await?;
    let mut rows = Vec::new();
    let mut total = 0usize;

    for file in files {
        let text = match tokio::fs::read_to_string(&file).await {
            Ok(t) => t,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed reading audit log {}", file.display()));
            }
        };
        for line in text.lines().rev() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<AuditEvent>(line) else {
                continue;
            };
            if !audit_event_matches(&event, query) {
                continue;
            }
            if total >= offset && rows.len() < limit {
                rows.push(event);
            }
            total = total.saturating_add(1);
        }
    }

    Ok((rows, total))
}

async fn audit_log_files(path: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = vec![path.to_path_buf()];
    let Some(parent) = path.parent() else {
        return Ok(files);
    };
    let Some(base_name) = path.file_name().and_then(|s| s.to_str()) else {
        return Ok(files);
    };

    let mut rotated: Vec<(u32, std::path::PathBuf)> = Vec::new();
    let mut entries = match tokio::fs::read_dir(parent).await {
        Ok(e) => e,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(files),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed reading audit dir {}", parent.display()));
        }
    };

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(suffix) = name
            .strip_prefix(base_name)
            .and_then(|s| s.strip_prefix('.'))
        else {
            continue;
        };
        let Ok(idx) = suffix.parse::<u32>() else {
            continue;
        };
        rotated.push((idx, entry.path()));
    }
    rotated.sort_by_key(|(idx, _)| *idx);
    files.extend(rotated.into_iter().map(|(_, p)| p));
    Ok(files)
}

fn audit_event_matches(event: &AuditEvent, query: &AuditListQuery) -> bool {
    if let Some(from) = query.from
        && event.at < from
    {
        return false;
    }
    if let Some(to) = query.to
        && event.at > to
    {
        return false;
    }
    if let Some(actor) = query.actor.as_deref()
        && !contains_ci(event.actor.as_deref().unwrap_or_default(), actor)
    {
        return false;
    }
    if let Some(action) = query.action.as_deref()
        && !contains_ci(&event.action, action)
    {
        return false;
    }
    if let Some(outcome) = query.outcome.as_deref()
        && !contains_ci(&event.outcome, outcome)
    {
        return false;
    }
    if let Some(text) = query.text.as_deref() {
        let haystack = format!(
            "{} {} {} {} {} {}",
            event.at,
            event.actor.as_deref().unwrap_or_default(),
            event.role.map(|r| format!("{r:?}")).unwrap_or_default(),
            event.action,
            event.outcome,
            event.metadata
        );
        if !contains_ci(&haystack, text) {
            return false;
        }
    }
    true
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn audit_filter_metadata(query: &AuditListQuery) -> serde_json::Value {
    serde_json::json!({
        "page": query.page,
        "page_size": query.page_size,
        "from": query.from,
        "to": query.to,
        "actor": query.actor,
        "action": query.action,
        "outcome": query.outcome,
        "text": query.text,
    })
}

fn audit_rows_to_csv(rows: &[AuditEvent]) -> String {
    let mut out = String::new();
    out.push_str("at,actor,role,action,outcome,metadata\n");
    for row in rows {
        let role = row.role.map(|r| format!("{r:?}")).unwrap_or_default();
        let line = [
            csv_escape_audit(&row.at.to_rfc3339()),
            csv_escape_audit(row.actor.as_deref().unwrap_or_default()),
            csv_escape_audit(&role),
            csv_escape_audit(&row.action),
            csv_escape_audit(&row.outcome),
            csv_escape_audit(&row.metadata.to_string()),
        ]
        .join(",");
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn csv_escape_audit(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

async fn require_user(
    state: &AppState,
    jar: &CookieJar,
    min_role: RoleName,
) -> Result<crate::models::AuthUser, AppError> {
    let user = state
        .auth
        .resolve_user_from_cookie(jar)
        .await
        .ok_or_else(|| AppError::unauthorized(anyhow::anyhow!("authentication required")))?;
    if !has_min_role(&user, min_role) {
        return Err(AppError::forbidden("insufficient role"));
    }
    Ok(user)
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
        }
    }

    fn unauthorized(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: err.to_string(),
        }
    }

    fn forbidden(msg: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: msg.to_string(),
        }
    }

    fn internal(err: impl std::fmt::Display) -> Self {
        error!(error = %err, "internal error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error".to_string(),
        }
    }

    fn method_not_allowed(msg: &str) -> Self {
        Self {
            status: StatusCode::METHOD_NOT_ALLOWED,
            message: msg.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": self.message,
            })),
        )
            .into_response()
    }
}
