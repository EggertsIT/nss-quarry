mod audit;
mod auth;
mod config;
mod models;
mod query;

use std::sync::Arc;

use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use clap::{Parser, Subcommand};
use tracing::{error, info};

use crate::audit::AuditLogger;
use crate::auth::{AuthManager, has_min_role};
use crate::config::{AppConfig, AuthMode, RoleName};
use crate::models::{
    AuditEvent, AuthResponse, HealthResponse, LocalLoginRequest, ReadyResponse, SearchRequest,
};
use crate::query::QueryService;

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
    let audit = AuditLogger::new(&cfg.audit.path).await?;
    let state = AppState {
        cfg: Arc::clone(&cfg),
        auth,
        audit,
        query,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/dashboard", get(dashboard_placeholder))
        .route("/auth/login", get(auth_login_oidc).post(auth_login_local))
        .route("/auth/callback", get(auth_callback_oidc))
        .route("/auth/logout", post(auth_logout))
        .route("/api/me", get(api_me))
        .route("/api/search", post(api_search))
        .route("/api/export/csv", post(api_export_csv))
        .route("/api/dashboards/:name", get(api_dashboard))
        .route("/api/audit", get(api_audit))
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

async fn dashboard_placeholder() -> &'static str {
    "nss-quarry is running. Use /api/dashboards/{name} and /api/search."
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
                "time_from": req.time_from,
                "time_to": req.time_to,
                "limit": req.limit,
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
                "time_from": req.time_from,
                "time_to": req.time_to,
                "limit": req.limit,
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

async fn api_audit(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<AuditEvent>>, AppError> {
    let user = require_user(&state, &jar, RoleName::Admin).await?;
    let text = tokio::fs::read_to_string(&state.cfg.audit.path)
        .await
        .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for line in text.lines().rev().take(200) {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<AuditEvent>(line) {
            out.push(event);
        }
    }
    state
        .audit
        .log(AuditEvent {
            at: Utc::now(),
            actor: Some(user.username),
            role: Some(user.role),
            action: "admin.audit.read".to_string(),
            outcome: "success".to_string(),
            metadata: serde_json::json!({ "returned": out.len() }),
        })
        .await;
    Ok(Json(out))
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
