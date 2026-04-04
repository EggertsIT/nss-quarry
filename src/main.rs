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
use std::{fs::OpenOptions as StdOpenOptions, net::SocketAddr};

use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng, rand_core::RngCore};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use base64::Engine;
use chrono::Utc;
use clap::{Parser, Subcommand};
use duckdb::Connection;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

use crate::audit::AuditLogger;
use crate::auth::{ApiTokenAuthError, AuthManager, has_min_role};
use crate::config::{ApiTokenConfig, AppConfig, AuthMode, RoleName};
use crate::models::{
    ApiTokenCreateRequest, ApiTokenCreateResponse, ApiTokenInfo, ApiTokenListResponse,
    ApiTokenUpdateRequest, AuditEvent, AuditListResponse, AuthResponse, HealthResponse,
    IngestorForceFinalizeOpenFilesResponse, LocalLoginRequest, ParquetColumnInfo,
    PcapAnalyzeResponse, ReadyResponse, SchemaFieldInfo, SchemaResponse, SearchRequest,
};
use crate::pcap::analyze_pcap_file;
use crate::query::{QueryService, VisibilityFilters};
use crate::webui::render_dashboard_html;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
    GenerateApiToken {
        #[arg(long, default_value = "svc_servicenow_analyst")]
        name: String,
    },
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<AppConfig>,
    auth: AuthManager,
    audit: AuditLogger,
    query: QueryService,
    ingestor_client: reqwest::Client,
    api_tokens_path: PathBuf,
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
            let hash = hash_secret(&password)?;
            println!("{hash}");
            Ok(())
        }
        Command::GenerateApiToken { name } => {
            let token = generate_api_token_secret();
            let hash = hash_secret(&token)?;
            println!("token={token}");
            println!("token_hash={hash}");
            println!();
            println!("Add this to config.toml:");
            println!("[[auth.api_tokens.tokens]]");
            println!("name = {:?}", name);
            println!("token_hash = {:?}", hash);
            println!("role = \"analyst\"");
            println!("disabled = false");
            Ok(())
        }
    }
}

fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("failed to hash secret"))?
        .to_string();
    Ok(hash)
}

fn generate_api_token_secret() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
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
    let api_tokens_path = api_tokens_path_for_config(&cfg);
    let api_tokens = load_api_tokens(&api_tokens_path, &cfg.auth.api_tokens.tokens).await?;
    auth.set_api_tokens(api_tokens.clone())?;
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
        api_tokens_path,
        visibility_filters_path,
    };
    info!(
        rules_url_regex = visibility_filters.url_regex.len(),
        rules_blocked_ips = visibility_filters.blocked_ips.len(),
        "loaded visibility filters"
    );
    info!(api_tokens = api_tokens.len(), "loaded api tokens");

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.server.bind_addr)
        .await
        .with_context(|| format!("failed binding to {}", cfg.server.bind_addr))?;
    info!(bind = %cfg.server.bind_addr, "nss-quarry listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
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
            "/api/admin/api-tokens",
            get(api_admin_api_tokens_get).post(api_admin_api_tokens_create),
        )
        .route(
            "/api/admin/api-tokens/{name}",
            axum::routing::put(api_admin_api_tokens_update),
        )
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<AuthResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Helpdesk,
    )
    .await?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username.clone()),
            role: Some(user.role),
            action: "api.me".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
            }),
        })
        .await;
    Ok(Json(AuthResponse { user }))
}

async fn authz_ingestor(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<StatusCode, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "authz.ingestor".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
            }),
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn api_admin_ingestor_force_finalize_open_files(
    State(state): State<AppState>,
    jar: CookieJar,
    auth_headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &auth_headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
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
                "auth_mode": user.auth_mode,
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<SearchRequest>,
) -> Result<Json<crate::models::SearchResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Helpdesk,
    )
    .await?;
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
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<SearchRequest>,
) -> Result<Response, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Helpdesk,
    )
    .await?;
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
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> Result<Json<PcapAnalyzeResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Helpdesk,
    )
    .await?;
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
                let (path, mut file) = create_private_upload_file(&state).await?;
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
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
) -> Result<Json<crate::models::DashboardResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Helpdesk,
    )
    .await?;
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
            metadata: serde_json::json!({
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
                "name": name
            }),
        })
        .await;
    Ok(Json(data))
}

async fn api_schema(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<SchemaResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Helpdesk,
    )
    .await?;
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
    let response = SchemaResponse {
        auth_mode: auth_mode.to_string(),
        fields,
        parquet_columns,
        parquet_schema_error,
        default_columns: state.cfg.query.default_columns.clone(),
        helpdesk_mask_fields: state.cfg.security.helpdesk_mask_fields.clone(),
        generated_at: Utc::now(),
    };
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "query.schema".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
                "parquet_columns": response.parquet_columns.len(),
            }),
        })
        .await;
    Ok(Json(response))
}

async fn api_admin_visibility_filters_get(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<VisibilityFilters>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
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
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(rules): Json<VisibilityFilters>,
) -> Result<Json<VisibilityFilters>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
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
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
                "url_regex_rules": persisted.url_regex.len(),
                "blocked_ip_rules": persisted.blocked_ips.len(),
                "path": state.visibility_filters_path,
            }),
        })
        .await;
    Ok(Json(persisted))
}

async fn api_admin_api_tokens_get(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<ApiTokenListResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
    let rows = state
        .auth
        .api_tokens()
        .map_err(AppError::internal)?
        .into_iter()
        .map(api_token_info_from_config)
        .collect::<Vec<_>>();
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.api_tokens.read".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
                "tokens": rows.len(),
            }),
        })
        .await;
    Ok(Json(ApiTokenListResponse {
        rows,
        generated_at: Utc::now(),
    }))
}

async fn api_admin_api_tokens_create(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<ApiTokenCreateRequest>,
) -> Result<Json<ApiTokenCreateResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
    let name = validate_api_token_name(&req.name).map_err(AppError::bad_request)?;
    let now = Utc::now();
    let mut tokens = state.auth.api_tokens().map_err(AppError::internal)?;
    if tokens.iter().any(|token| token.name == name) {
        return Err(AppError::bad_request(format!(
            "api token '{}' already exists",
            name
        )));
    }
    let plain_token = generate_api_token_secret();
    let token_hash = hash_secret(&plain_token).map_err(AppError::internal)?;
    let token = ApiTokenConfig {
        name: name.clone(),
        token_hash,
        role: req.role,
        allowed_sources: normalize_allowed_sources(&req.allowed_sources)
            .map_err(AppError::bad_request)?,
        disabled: false,
        created_at: Some(now),
        updated_at: Some(now),
    };
    tokens.push(token.clone());
    persist_api_tokens(&state, tokens).await?;
    state
        .audit
        .log(AuditEvent {
            at: now,
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.api_tokens.create".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
                "token_name": token.name,
                "token_role": token.role,
                "allowed_sources": token.allowed_sources,
            }),
        })
        .await;
    Ok(Json(ApiTokenCreateResponse {
        token: plain_token,
        token_info: api_token_info_from_config(token),
    }))
}

async fn api_admin_api_tokens_update(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    Json(req): Json<ApiTokenUpdateRequest>,
) -> Result<Json<ApiTokenInfo>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
    let name = validate_api_token_name(&name).map_err(AppError::bad_request)?;
    let mut tokens = state.auth.api_tokens().map_err(AppError::internal)?;
    let normalized_sources =
        normalize_allowed_sources(&req.allowed_sources).map_err(AppError::bad_request)?;
    let token = tokens
        .iter_mut()
        .find(|token| token.name == name)
        .ok_or_else(|| AppError::bad_request(format!("api token '{}' not found", name)))?;
    token.role = req.role;
    token.allowed_sources = normalized_sources;
    token.disabled = req.disabled;
    token.updated_at = Some(Utc::now());
    let updated = token.clone();
    persist_api_tokens(&state, tokens).await?;
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.api_tokens.update".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
                "token_name": updated.name,
                "token_role": updated.role,
                "disabled": updated.disabled,
                "allowed_sources": updated.allowed_sources,
            }),
        })
        .await;
    Ok(Json(api_token_info_from_config(updated)))
}

fn visibility_filters_path_for_config(cfg: &AppConfig) -> PathBuf {
    cfg.audit
        .path
        .parent()
        .unwrap_or_else(|| FsPath::new("/var/lib/nss-quarry"))
        .join("visibility_filters.json")
}

fn api_tokens_path_for_config(cfg: &AppConfig) -> PathBuf {
    cfg.audit
        .path
        .parent()
        .unwrap_or_else(|| FsPath::new("/var/lib/nss-quarry"))
        .join("api_tokens.json")
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

async fn load_api_tokens(
    path: &FsPath,
    bootstrap: &[ApiTokenConfig],
) -> Result<Vec<ApiTokenConfig>> {
    let raw = match tokio::fs::read_to_string(path).await {
        Ok(v) => Some(v),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("failed reading {}", path.display()));
        }
    };

    if let Some(raw) = raw {
        if raw.trim().is_empty() {
            return Ok(Vec::new());
        }
        return serde_json::from_str(&raw)
            .with_context(|| format!("failed parsing api tokens {}", path.display()));
    }

    let seeded = bootstrap.to_vec();
    if !seeded.is_empty() {
        save_api_tokens(path, &seeded).await?;
    }
    Ok(seeded)
}

async fn save_api_tokens(path: &FsPath, tokens: &[ApiTokenConfig]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    let payload = serde_json::to_vec_pretty(tokens).context("failed encoding api tokens")?;
    tokio::fs::write(&tmp, payload)
        .await
        .with_context(|| format!("failed writing {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed replacing {}", path.display()))?;
    Ok(())
}

async fn persist_api_tokens(state: &AppState, tokens: Vec<ApiTokenConfig>) -> Result<(), AppError> {
    save_api_tokens(&state.api_tokens_path, &tokens)
        .await
        .map_err(AppError::internal)?;
    state
        .auth
        .set_api_tokens(tokens)
        .map_err(AppError::bad_request)?;
    Ok(())
}

fn api_token_info_from_config(token: ApiTokenConfig) -> ApiTokenInfo {
    ApiTokenInfo {
        name: token.name,
        role: token.role,
        allowed_sources: token.allowed_sources,
        disabled: token.disabled,
        created_at: token.created_at,
        updated_at: token.updated_at,
    }
}

fn validate_api_token_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    let re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$").expect("valid regex");
    if !re.is_match(trimmed) {
        anyhow::bail!(
            "invalid api token name '{}': allowed [A-Za-z0-9][A-Za-z0-9._:-]{{0,63}}",
            trimmed
        );
    }
    Ok(trimmed.to_string())
}

fn normalize_allowed_sources(values: &[String]) -> Result<Vec<String>> {
    let mut out = values
        .iter()
        .map(|value| crate::config::parse_allowed_source(value))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|net| net.to_string())
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    Ok(out)
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<AuditListQuery>,
) -> Result<Json<AuditListResponse>, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
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
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
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
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<AuditListQuery>,
) -> Result<Response, AppError> {
    let source_ip = extract_source_ip(&headers, Some(peer));
    let user = require_user(
        &state,
        &jar,
        &headers,
        source_ip.as_deref(),
        RoleName::Admin,
    )
    .await?;
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
                "auth_mode": user.auth_mode,
                "source_ip": source_ip,
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

async fn create_private_upload_file(
    state: &AppState,
) -> Result<(PathBuf, tokio::fs::File), AppError> {
    let parent = state
        .cfg
        .audit
        .path
        .parent()
        .unwrap_or_else(|| FsPath::new("/var/lib/nss-quarry"));
    let dir = parent.join("tmp");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(AppError::internal)?;
    #[cfg(unix)]
    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(AppError::internal)?;

    let path = dir.join(format!("nss-quarry-upload-{}.pcap", uuid::Uuid::new_v4()));
    let mut options = StdOpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(&path).map_err(AppError::internal)?;
    Ok((path, tokio::fs::File::from_std(file)))
}

fn extract_source_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<String> {
    if let Some(peer) = peer
        && !peer.ip().is_loopback()
    {
        return Some(peer.ip().to_string());
    }

    if peer.is_some() {
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
        if let Some(real_ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return Some(real_ip.to_string());
        }
    }

    peer.map(|addr| addr.ip().to_string())
}

async fn require_user(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    source_ip: Option<&str>,
    min_role: RoleName,
) -> Result<crate::models::AuthUser, AppError> {
    let user = if let Some(user) = state.auth.resolve_user_from_cookie(jar).await {
        user
    } else {
        match state
            .auth
            .resolve_user_from_api_token_header(headers, source_ip)
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return Err(AppError::unauthorized(anyhow::anyhow!(
                    "authentication required"
                )));
            }
            Err(ApiTokenAuthError::InvalidToken) => {
                state
                    .audit
                    .log(AuditEvent {
                        at: Utc::now(),
                        actor: None,
                        role: None,
                        action: "auth.api_token".to_string(),
                        outcome: "invalid_token".to_string(),
                        metadata: serde_json::json!({
                            "source_ip": source_ip,
                            "required_role": min_role,
                        }),
                    })
                    .await;
                return Err(AppError::unauthorized(anyhow::anyhow!("invalid api token")));
            }
            Err(ApiTokenAuthError::SourceIpRequired) => {
                state
                    .audit
                    .log(AuditEvent {
                        at: Utc::now(),
                        actor: None,
                        role: None,
                        action: "auth.api_token".to_string(),
                        outcome: "source_ip_required".to_string(),
                        metadata: serde_json::json!({
                            "source_ip": source_ip,
                            "required_role": min_role,
                        }),
                    })
                    .await;
                return Err(AppError::forbidden(
                    "source ip is required for this api token",
                ));
            }
            Err(ApiTokenAuthError::SourceNotAllowed) => {
                state
                    .audit
                    .log(AuditEvent {
                        at: Utc::now(),
                        actor: None,
                        role: None,
                        action: "auth.api_token".to_string(),
                        outcome: "source_not_allowed".to_string(),
                        metadata: serde_json::json!({
                            "source_ip": source_ip,
                            "required_role": min_role,
                        }),
                    })
                    .await;
                return Err(AppError::forbidden("api token source is not allowed"));
            }
        }
    };
    if !has_min_role(&user, min_role) {
        state
            .audit
            .log(AuditEvent {
                at: Utc::now(),
                actor: Some(user.username.clone()),
                role: Some(user.role),
                action: "auth.role_check".to_string(),
                outcome: "insufficient_role".to_string(),
                metadata: serde_json::json!({
                    "auth_mode": user.auth_mode,
                    "source_ip": source_ip,
                    "required_role": min_role,
                }),
            })
            .await;
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::config::{ApiTokenConfig, LocalUser};

    fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("password hash")
            .to_string()
    }

    fn hash_secret(secret: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(secret.as_bytes(), &salt)
            .expect("secret hash")
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
        cfg.auth.api_tokens.tokens = vec![
            ApiTokenConfig {
                name: "svc-analyst".to_string(),
                token_hash: hash_secret("analyst-token"),
                role: RoleName::Analyst,
                allowed_sources: vec!["127.0.0.1/32".to_string()],
                disabled: false,
                created_at: None,
                updated_at: None,
            },
            ApiTokenConfig {
                name: "svc-admin".to_string(),
                token_hash: hash_secret("admin-token"),
                role: RoleName::Admin,
                allowed_sources: vec!["127.0.0.1/32".to_string()],
                disabled: false,
                created_at: None,
                updated_at: None,
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
            api_tokens_path: std::env::temp_dir()
                .join(format!("nss-quarry-api-tokens-{}.json", Uuid::new_v4())),
            visibility_filters_path,
        })
    }

    fn with_local_peer(mut req: Request<Body>) -> Request<Body> {
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
        )));
        req
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
        let res_ingestor = app
            .clone()
            .oneshot(with_local_peer(req_ingestor))
            .await
            .expect("response");
        assert_eq!(res_ingestor.status(), StatusCode::UNAUTHORIZED);

        let req_audit = Request::builder()
            .uri("/api/audit")
            .body(Body::empty())
            .expect("request");
        let res_audit = app
            .clone()
            .oneshot(with_local_peer(req_audit))
            .await
            .expect("response");
        assert_eq!(res_audit.status(), StatusCode::UNAUTHORIZED);

        let mut req_finalize = Request::builder()
            .method("POST")
            .uri("/api/admin/ingestor/force-finalize-open-files")
            .body(Body::empty())
            .expect("request");
        req_finalize
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8080,
            )));
        let res_finalize = app.clone().oneshot(req_finalize).await.expect("response");
        assert_eq!(res_finalize.status(), StatusCode::UNAUTHORIZED);

        let req_visibility = Request::builder()
            .uri("/api/admin/visibility-filters")
            .body(Body::empty())
            .expect("request");
        let res_visibility = app
            .clone()
            .oneshot(with_local_peer(req_visibility))
            .await
            .expect("response");
        assert_eq!(res_visibility.status(), StatusCode::UNAUTHORIZED);
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
        let res = app
            .clone()
            .oneshot(with_local_peer(req))
            .await
            .expect("response");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let mut req_finalize = Request::builder()
            .method("POST")
            .uri("/api/admin/ingestor/force-finalize-open-files")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request");
        req_finalize
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8080,
            )));
        let res_finalize = app.clone().oneshot(req_finalize).await.expect("response");
        assert_eq!(res_finalize.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn helpdesk_cannot_access_visibility_filters_admin_api() {
        let app = test_app().await;
        let cookie = login_cookie(&app, "helpdesk", "helpdesk").await;

        let req_get = Request::builder()
            .uri("/api/admin/visibility-filters")
            .header(header::COOKIE, cookie.clone())
            .body(Body::empty())
            .expect("request");
        let res_get = app
            .clone()
            .oneshot(with_local_peer(req_get))
            .await
            .expect("response");
        assert_eq!(res_get.status(), StatusCode::FORBIDDEN);

        let req_put = Request::builder()
            .method("PUT")
            .uri("/api/admin/visibility-filters")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"url_regex":[],"blocked_ips":["1.1.1.1"]}"#))
            .expect("request");
        let res_put = app
            .clone()
            .oneshot(with_local_peer(req_put))
            .await
            .expect("response");
        assert_eq!(res_put.status(), StatusCode::FORBIDDEN);
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
        let res = app
            .clone()
            .oneshot(with_local_peer(req))
            .await
            .expect("response");
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
        let res_ingestor = app
            .clone()
            .oneshot(with_local_peer(req_ingestor))
            .await
            .expect("response");
        assert_eq!(res_ingestor.status(), StatusCode::NO_CONTENT);

        let req_audit = Request::builder()
            .uri("/api/audit?page=1&page_size=10")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request");
        let res_audit = app
            .clone()
            .oneshot(with_local_peer(req_audit))
            .await
            .expect("response");
        assert_eq!(res_audit.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_can_read_and_update_visibility_filters() {
        let app = test_app().await;
        let cookie = login_cookie(&app, "admin", "admin").await;

        let req_get = Request::builder()
            .uri("/api/admin/visibility-filters")
            .header(header::COOKIE, cookie.clone())
            .body(Body::empty())
            .expect("request");
        let res_get = app
            .clone()
            .oneshot(with_local_peer(req_get))
            .await
            .expect("response");
        assert_eq!(res_get.status(), StatusCode::OK);

        let req_put = Request::builder()
            .method("PUT")
            .uri("/api/admin/visibility-filters")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"url_regex":["^blocked\\.example\\.com$"],"blocked_ips":["1.1.1.1"]}"#,
            ))
            .expect("request");
        let res_put = app
            .clone()
            .oneshot(with_local_peer(req_put))
            .await
            .expect("response");
        assert_eq!(res_put.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_can_manage_api_tokens() {
        let app = test_app().await;
        let cookie = login_cookie(&app, "admin", "admin").await;

        let req_get = Request::builder()
            .uri("/api/admin/api-tokens")
            .header(header::COOKIE, cookie.clone())
            .body(Body::empty())
            .expect("request");
        let res_get = app
            .clone()
            .oneshot(with_local_peer(req_get))
            .await
            .expect("response");
        assert_eq!(res_get.status(), StatusCode::OK);

        let req_create = Request::builder()
            .method("POST")
            .uri("/api/admin/api-tokens")
            .header(header::COOKIE, cookie.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"name":"svc-test","role":"analyst","allowed_sources":["127.0.0.1/32"]}"#,
            ))
            .expect("request");
        let res_create = app
            .clone()
            .oneshot(with_local_peer(req_create))
            .await
            .expect("response");
        assert_eq!(res_create.status(), StatusCode::OK);

        let req_update = Request::builder()
            .method("PUT")
            .uri("/api/admin/api-tokens/svc-test")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"role":"analyst","allowed_sources":["127.0.0.1/32"],"disabled":true}"#,
            ))
            .expect("request");
        let res_update = app
            .clone()
            .oneshot(with_local_peer(req_update))
            .await
            .expect("response");
        assert_eq!(res_update.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn analyst_api_token_can_access_api_me() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/api/me")
            .header(header::AUTHORIZATION, "Bearer analyst-token")
            .body(Body::empty())
            .expect("request");
        let res = app
            .clone()
            .oneshot(with_local_peer(req))
            .await
            .expect("response");
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_token_source_whitelist_is_enforced_at_route_level() {
        let app = test_app().await;
        let mut req = Request::builder()
            .uri("/api/me")
            .header(header::AUTHORIZATION, "Bearer analyst-token")
            .body(Body::empty())
            .expect("request");
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            8080,
        )));
        let res = app.clone().oneshot(req).await.expect("response");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn analyst_api_token_cannot_access_admin_endpoints() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/api/audit")
            .header(header::AUTHORIZATION, "Bearer analyst-token")
            .body(Body::empty())
            .expect("request");
        let res = app
            .clone()
            .oneshot(with_local_peer(req))
            .await
            .expect("response");
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_api_token_can_access_admin_endpoints() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/api/audit?page=1&page_size=10")
            .header(header::AUTHORIZATION, "Bearer admin-token")
            .body(Body::empty())
            .expect("request");
        let res = app
            .clone()
            .oneshot(with_local_peer(req))
            .await
            .expect("response");
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_visibility_filter_update_rejects_invalid_ip() {
        let app = test_app().await;
        let cookie = login_cookie(&app, "admin", "admin").await;

        let req_put = Request::builder()
            .method("PUT")
            .uri("/api/admin/visibility-filters")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"url_regex":[],"blocked_ips":["not-an-ip"]}"#,
            ))
            .expect("request");
        let res_put = app
            .clone()
            .oneshot(with_local_peer(req_put))
            .await
            .expect("response");
        assert_eq!(res_put.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn source_ip_ignores_forwarded_headers_for_non_loopback_peers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.10"));

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 44321);
        let source = extract_source_ip(&headers, Some(peer));
        assert_eq!(source.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn source_ip_trusts_forwarded_headers_for_loopback_proxy_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 127.0.0.1"),
        );

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let source = extract_source_ip(&headers, Some(peer));
        assert_eq!(source.as_deref(), Some("203.0.113.9"));
    }
}
