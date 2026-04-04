mod audit;
mod auth;
mod config;
mod models;
mod pcap;
mod query;
mod webui;

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use clap::{Parser, Subcommand};
use duckdb::Connection;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

use crate::audit::AuditLogger;
use crate::auth::{AuthManager, has_min_role};
use crate::config::{AppConfig, AuthMode, RoleName};
use crate::models::{
    AuditEvent, AuditListResponse, AuthResponse, HealthResponse,
    IngestorForceFinalizeOpenFilesResponse, LocalLoginRequest, ParquetColumnInfo,
    PcapAnalyzeResponse, ReadyResponse, SchemaFieldInfo, SchemaResponse, SearchRequest,
};
use crate::pcap::analyze_pcap_file;
use crate::query::{QueryService, VisibilityFilters};
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
    ingestor_client: reqwest::Client,
    visibility_filters_path: PathBuf,
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
    let visibility_filters_path = visibility_filters_path_for_config(&cfg);
    let visibility_filters = load_visibility_filters(&visibility_filters_path).await?;
    query.set_visibility_filters(visibility_filters.clone())?;
    let audit = AuditLogger::new(&cfg.audit).await?;
    let ingestor_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.ingestor.request_timeout_ms))
        .build()
        .context("failed building ingestor HTTP client")?;
    let state = AppState {
        cfg: Arc::clone(&cfg),
        auth,
        audit,
        query,
        ingestor_client,
        visibility_filters_path,
    };
    info!(
        rules_url_regex = visibility_filters.url_regex.len(),
        rules_blocked_ips = visibility_filters.blocked_ips.len(),
        "loaded visibility filters"
    );

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.server.bind_addr)
        .await
        .with_context(|| format!("failed binding to {}", cfg.server.bind_addr))?;
    info!(bind = %cfg.server.bind_addr, "nss-quarry listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/dashboard", get(dashboard_page))
        .route("/assets/world.geojson", get(world_geojson))
        .route("/auth/login", get(auth_login_oidc).post(auth_login_local))
        .route("/auth/callback", get(auth_callback_oidc))
        .route("/auth/logout", post(auth_logout))
        .route("/api/me", get(api_me))
        .route("/authz/ingestor", get(authz_ingestor))
        .route(
            "/api/admin/ingestor/force-finalize-open-files",
            post(api_admin_ingestor_force_finalize_open_files),
        )
        .route("/api/search", post(api_search))
        .route("/api/export/csv", post(api_export_csv))
        .route(
            "/api/pcap/analyze",
            post(api_pcap_analyze).layer(DefaultBodyLimit::max(pcap_upload_body_limit())),
        )
        .route("/api/dashboards/{name}", get(api_dashboard))
        .route("/api/schema", get(api_schema))
        .route(
            "/api/admin/visibility-filters",
            get(api_admin_visibility_filters_get).put(api_admin_visibility_filters_put),
        )
        .route("/api/audit", get(api_audit))
        .route("/api/audit/export/csv", get(api_audit_export_csv))
        .with_state(state)
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

async fn world_geojson() -> Response {
    let mut res = Response::new(include_str!("world.geojson").to_string().into());
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/geo+json; charset=utf-8"),
    );
    res
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

async fn authz_ingestor(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<StatusCode, AppError> {
    let _ = require_user(&state, &jar, RoleName::Admin).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_admin_ingestor_force_finalize_open_files(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = require_user(&state, &jar, RoleName::Admin).await?;
    let source_ip = extract_source_ip(&headers);
    let url = format!(
        "{}/api/admin/force-finalize-open-files",
        state.cfg.ingestor.base_url.trim_end_matches('/')
    );

    let upstream = state
        .ingestor_client
        .post(&url)
        .send()
        .await
        .map_err(AppError::bad_gateway)?;
    let upstream_status = upstream.status();
    let upstream_body = upstream.text().await.map_err(AppError::bad_gateway)?;
    let response_payload =
        serde_json::from_str::<IngestorForceFinalizeOpenFilesResponse>(&upstream_body)
            .unwrap_or_else(|_| IngestorForceFinalizeOpenFilesResponse {
                status: "error".to_string(),
                message: format!(
                    "invalid upstream response (status={}): {}",
                    upstream_status.as_u16(),
                    upstream_body
                ),
                triggered_at: Utc::now().to_rfc3339(),
                cooldown_secs: None,
                retry_after_secs: None,
                result: None,
            });

    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.ingestor.force_finalize_open_files".to_string(),
            outcome: if upstream_status.is_success() {
                "success".to_string()
            } else {
                format!("http_{}", upstream_status.as_u16())
            },
            metadata: serde_json::json!({
                "source_ip": source_ip,
                "upstream_status": upstream_status.as_u16(),
                "response": response_payload,
            }),
        })
        .await;

    let mut response = Json(response_payload).into_response();
    *response.status_mut() = upstream_status;
    Ok(response)
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

const MAX_PCAP_UPLOAD_BYTES: u64 = 5_u64 * 1024 * 1024 * 1024;
const DEFAULT_PCAP_MAX_IPS: usize = 500;
const MAX_PCAP_MAX_IPS: usize = 5000;
const PCAP_SEARCH_WINDOW_PAD_SECONDS: i64 = 5 * 60;

fn pcap_upload_body_limit() -> usize {
    let with_slack = MAX_PCAP_UPLOAD_BYTES.saturating_add(1024 * 1024);
    usize::try_from(with_slack).unwrap_or(usize::MAX)
}

async fn api_pcap_analyze(
    State(state): State<AppState>,
    jar: CookieJar,
    mut multipart: Multipart,
) -> Result<Json<PcapAnalyzeResponse>, AppError> {
    let user = require_user(&state, &jar, RoleName::Helpdesk).await?;
    let mut file_name: Option<String> = None;
    let mut pcap_path: Option<PathBuf> = None;
    let mut uploaded_bytes: u64 = 0;
    let mut max_ips = DEFAULT_PCAP_MAX_IPS;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(AppError::bad_request)?
    {
        let field_name = field.name().unwrap_or_default().to_string();
        match field_name.as_str() {
            "pcap" => {
                file_name = field.file_name().map(|v| v.to_string());
                let path = std::env::temp_dir()
                    .join(format!("nss-quarry-upload-{}.pcap", uuid::Uuid::new_v4()));
                let mut file = tokio::fs::File::create(&path)
                    .await
                    .map_err(AppError::internal)?;
                let mut size = 0_u64;
                while let Some(chunk) = field.chunk().await.map_err(AppError::bad_request)? {
                    size = size.saturating_add(chunk.len() as u64);
                    if size > MAX_PCAP_UPLOAD_BYTES {
                        let _ = tokio::fs::remove_file(&path).await;
                        return Err(AppError::bad_request(format!(
                            "pcap is too large (max {} bytes)",
                            MAX_PCAP_UPLOAD_BYTES
                        )));
                    }
                    file.write_all(&chunk).await.map_err(AppError::internal)?;
                }
                pcap_path = Some(path);
                uploaded_bytes = size;
            }
            "max_ips" => {
                let value = field.text().await.map_err(AppError::bad_request)?;
                if let Ok(parsed) = value.trim().parse::<usize>() {
                    max_ips = parsed.clamp(1, MAX_PCAP_MAX_IPS);
                }
            }
            _ => {}
        }
    }

    let pcap_path =
        pcap_path.ok_or_else(|| AppError::bad_request("multipart field 'pcap' is required"))?;
    let analyze_path = pcap_path.clone();
    let summary_result =
        tokio::task::spawn_blocking(move || analyze_pcap_file(&analyze_path, max_ips))
            .await
            .map_err(AppError::internal)?;
    let _ = tokio::fs::remove_file(&pcap_path).await;
    let summary = summary_result.map_err(AppError::bad_request)?;
    let duration_seconds = (summary.time_to - summary.time_from).num_seconds().max(0);
    let search_time_from =
        summary.time_from - chrono::Duration::seconds(PCAP_SEARCH_WINDOW_PAD_SECONDS);
    let search_time_to =
        summary.time_to + chrono::Duration::seconds(PCAP_SEARCH_WINDOW_PAD_SECONDS);

    let response = PcapAnalyzeResponse {
        file_name: file_name.clone(),
        link_type: summary.link_type,
        time_from: summary.time_from,
        time_to: summary.time_to,
        search_time_from,
        search_time_to,
        search_window_pad_seconds: PCAP_SEARCH_WINDOW_PAD_SECONDS,
        duration_seconds,
        packet_count: summary.packet_count,
        ip_packet_count: summary.ip_packet_count,
        unique_source_ip_count: summary.unique_source_ip_count,
        source_ips: summary.source_ips,
        truncated_source_ips: summary.truncated_source_ips,
        unique_destination_ip_count: summary.unique_destination_ip_count,
        destination_ips: summary.destination_ips,
        truncated_ips: summary.truncated_ips,
    };

    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "query.pcap_analyze".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "file_name": file_name,
                "link_type": response.link_type,
                "time_from": response.time_from,
                "time_to": response.time_to,
                "search_time_from": response.search_time_from,
                "search_time_to": response.search_time_to,
                "search_window_pad_seconds": response.search_window_pad_seconds,
                "duration_seconds": response.duration_seconds,
                "uploaded_bytes": uploaded_bytes,
                "packet_count": response.packet_count,
                "ip_packet_count": response.ip_packet_count,
                "unique_source_ip_count": response.unique_source_ip_count,
                "returned_source_ips": response.source_ips.len(),
                "truncated_source_ips": response.truncated_source_ips,
                "unique_destination_ip_count": response.unique_destination_ip_count,
                "returned_destination_ips": response.destination_ips.len(),
                "truncated_ips": response.truncated_ips,
            }),
        })
        .await;

    Ok(Json(response))
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
            name: "response_code_field".to_string(),
            mapped_from: state.cfg.data.fields.response_code_field.clone(),
        },
        SchemaFieldInfo {
            name: "reason_field".to_string(),
            mapped_from: state.cfg.data.fields.reason_field.clone(),
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
    let mut fields = fields;
    if let Some(source_country_field) = state.cfg.data.fields.source_country_field.clone() {
        fields.push(SchemaFieldInfo {
            name: "source_country_field".to_string(),
            mapped_from: source_country_field,
        });
    }
    if let Some(destination_country_field) = state.cfg.data.fields.destination_country_field.clone()
    {
        fields.push(SchemaFieldInfo {
            name: "destination_country_field".to_string(),
            mapped_from: destination_country_field,
        });
    }
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

async fn api_admin_visibility_filters_get(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<VisibilityFilters>, AppError> {
    let user = require_user(&state, &jar, RoleName::Admin).await?;
    let rules = state
        .query
        .visibility_filters()
        .map_err(AppError::internal)?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.visibility_filters.read".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "url_regex_rules": rules.url_regex.len(),
                "blocked_ip_rules": rules.blocked_ips.len(),
            }),
        })
        .await;
    Ok(Json(rules))
}

async fn api_admin_visibility_filters_put(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(rules): Json<VisibilityFilters>,
) -> Result<Json<VisibilityFilters>, AppError> {
    let user = require_user(&state, &jar, RoleName::Admin).await?;
    state
        .query
        .set_visibility_filters(rules.clone())
        .map_err(AppError::bad_request)?;
    let persisted = state
        .query
        .visibility_filters()
        .map_err(AppError::internal)?;
    save_visibility_filters(&state.visibility_filters_path, &persisted)
        .await
        .map_err(AppError::internal)?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.visibility_filters.update".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "url_regex_rules": persisted.url_regex.len(),
                "blocked_ip_rules": persisted.blocked_ips.len(),
                "path": state.visibility_filters_path,
            }),
        })
        .await;
    Ok(Json(persisted))
}

fn visibility_filters_path_for_config(cfg: &AppConfig) -> PathBuf {
    cfg.audit
        .path
        .parent()
        .unwrap_or_else(|| FsPath::new("/var/lib/nss-quarry"))
        .join("visibility_filters.json")
}

async fn load_visibility_filters(path: &FsPath) -> Result<VisibilityFilters> {
    let raw = match tokio::fs::read_to_string(path).await {
        Ok(v) => v,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VisibilityFilters::default());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("failed reading {}", path.display()));
        }
    };
    if raw.trim().is_empty() {
        return Ok(VisibilityFilters::default());
    }
    serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing visibility filters {}", path.display()))
}

async fn save_visibility_filters(path: &FsPath, filters: &VisibilityFilters) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    let payload =
        serde_json::to_vec_pretty(filters).context("failed encoding visibility filters")?;
    tokio::fs::write(&tmp, payload)
        .await
        .with_context(|| format!("failed writing {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed replacing {}", path.display()))?;
    Ok(())
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

fn extract_source_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let first = forwarded
            .split(',')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
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

    fn bad_gateway(err: impl std::fmt::Display) -> Self {
        error!(error = %err, "upstream ingestor call failed");
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: "ingestor upstream call failed".to_string(),
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

#[cfg(test)]
mod security_tests {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::config::LocalUser;

    fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("password hash")
            .to_string()
    }

    fn test_config() -> Arc<AppConfig> {
        let mut cfg = AppConfig::default();
        cfg.auth.local_users.users = vec![
            LocalUser {
                username: "admin".to_string(),
                password_hash: hash_password("admin"),
                role: RoleName::Admin,
                disabled: false,
            },
            LocalUser {
                username: "analyst".to_string(),
                password_hash: hash_password("analyst"),
                role: RoleName::Analyst,
                disabled: false,
            },
            LocalUser {
                username: "helpdesk".to_string(),
                password_hash: hash_password("helpdesk"),
                role: RoleName::Helpdesk,
                disabled: false,
            },
        ];

        let root = std::env::temp_dir().join(format!("nss-quarry-tests-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("parquet")).expect("create parquet dir");
        cfg.data.parquet_root = root.join("parquet");
        cfg.audit.path = root.join("audit/audit.log");

        Arc::new(cfg)
    }

    async fn test_app() -> Router {
        let cfg = test_config();
        let auth = AuthManager::new(&cfg.auth).await.expect("auth manager");
        let query = QueryService::new(&cfg).expect("query service");
        let visibility_filters_path = visibility_filters_path_for_config(&cfg);
        query
            .set_visibility_filters(VisibilityFilters::default())
            .expect("set default visibility filters");
        let audit = AuditLogger::new(&cfg.audit).await.expect("audit logger");
        let ingestor_client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.ingestor.request_timeout_ms))
            .build()
            .expect("ingestor client");
        build_router(AppState {
            cfg,
            auth,
            audit,
            query,
            ingestor_client,
            visibility_filters_path,
        })
    }

    async fn login_cookie(app: &Router, username: &str, password: &str) -> String {
        let body = format!(r#"{{"username":"{username}","password":"{password}"}}"#);
        let req = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.into_bytes()))
            .expect("login request");
        let res = app.clone().oneshot(req).await.expect("login response");
        assert_eq!(res.status(), StatusCode::OK);
        let set_cookie = res
            .headers()
            .get(header::SET_COOKIE)
            .expect("session cookie")
            .to_str()
            .expect("set-cookie header");
        set_cookie
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string()
    }

    #[tokio::test]
    async fn admin_routes_require_authentication() {
        let app = test_app().await;

        let req_ingestor = Request::builder()
            .uri("/authz/ingestor")
            .body(Body::empty())
            .expect("request");
        let res_ingestor = app.clone().oneshot(req_ingestor).await.expect("response");
        assert_eq!(res_ingestor.status(), StatusCode::UNAUTHORIZED);

        let req_audit = Request::builder()
            .uri("/api/audit")
            .body(Body::empty())
            .expect("request");
        let res_audit = app.clone().oneshot(req_audit).await.expect("response");
        assert_eq!(res_audit.status(), StatusCode::UNAUTHORIZED);

        let req_finalize = Request::builder()
            .method("POST")
            .uri("/api/admin/ingestor/force-finalize-open-files")
            .body(Body::empty())
            .expect("request");
        let res_finalize = app.clone().oneshot(req_finalize).await.expect("response");
        assert_eq!(res_finalize.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn helpdesk_cannot_access_ingestor_admin_gate() {
        let app = test_app().await;
        let cookie = login_cookie(&app, "helpdesk", "helpdesk").await;

        let req = Request::builder()
            .uri("/authz/ingestor")
            .header(header::COOKIE, cookie.clone())
            .body(Body::empty())
            .expect("request");
        let res = app.clone().oneshot(req).await.expect("response");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let req_finalize = Request::builder()
            .method("POST")
            .uri("/api/admin/ingestor/force-finalize-open-files")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request");
        let res_finalize = app.clone().oneshot(req_finalize).await.expect("response");
        assert_eq!(res_finalize.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn analyst_cannot_read_admin_audit_endpoint() {
        let app = test_app().await;
        let cookie = login_cookie(&app, "analyst", "analyst").await;

        let req = Request::builder()
            .uri("/api/audit")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request");
        let res = app.clone().oneshot(req).await.expect("response");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_can_access_admin_only_endpoints() {
        let app = test_app().await;
        let cookie = login_cookie(&app, "admin", "admin").await;

        let req_ingestor = Request::builder()
            .uri("/authz/ingestor")
            .header(header::COOKIE, cookie.clone())
            .body(Body::empty())
            .expect("request");
        let res_ingestor = app.clone().oneshot(req_ingestor).await.expect("response");
        assert_eq!(res_ingestor.status(), StatusCode::NO_CONTENT);

        let req_audit = Request::builder()
            .uri("/api/audit?page=1&page_size=10")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request");
        let res_audit = app.clone().oneshot(req_audit).await.expect("response");
        assert_eq!(res_audit.status(), StatusCode::OK);
    }
}
