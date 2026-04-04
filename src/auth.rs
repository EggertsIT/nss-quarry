use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::{HeaderMap, header};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, RedirectUrl, Scope, TokenResponse,
};
use tokio::sync::RwLock;
use tracing::warn;
use uuid::Uuid;

use crate::config::{ApiTokenConfig, AuthConfig, AuthMode, LocalUser, OidcRoleMap, RoleName};
use crate::models::{AuthResponse, AuthUser, LocalLoginRequest};

#[derive(Clone)]
pub struct AuthManager {
    cfg: AuthConfig,
    api_tokens: Arc<Vec<ApiTokenConfig>>,
    local_users: Arc<HashMap<String, LocalUser>>,
    sessions: Arc<RwLock<HashMap<String, StoredSession>>>,
    oidc: Option<OidcRuntime>,
}

#[derive(Clone)]
struct OidcRuntime {
    client: OidcClient,
    http_client: reqwest::Client,
    claim_username: String,
    claim_groups: String,
    role_map: OidcRoleMap,
    pending: Arc<RwLock<HashMap<String, PendingOidcState>>>,
}

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Debug, Clone)]
struct PendingOidcState {
    nonce: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct StoredSession {
    user: AuthUser,
    expires_at: DateTime<Utc>,
}

impl AuthManager {
    pub async fn new(cfg: &AuthConfig) -> Result<Self> {
        let api_tokens = cfg.api_tokens.tokens.clone();
        let local_users = cfg
            .local_users
            .users
            .iter()
            .map(|u| (u.username.clone(), u.clone()))
            .collect::<HashMap<_, _>>();

        let oidc = match cfg.mode {
            AuthMode::OidcEntra | AuthMode::OidcOkta => {
                let oidc_cfg = cfg
                    .oidc
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("auth.oidc is required"))?;
                let http_client = reqwest::ClientBuilder::new()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .context("failed building OIDC HTTP client")?;
                let issuer = IssuerUrl::new(oidc_cfg.issuer_url.clone())
                    .context("invalid auth.oidc.issuer_url")?;
                let metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
                    .await
                    .context("failed OIDC discovery")?;
                let client = CoreClient::from_provider_metadata(
                    metadata,
                    ClientId::new(oidc_cfg.client_id.clone()),
                    Some(ClientSecret::new(oidc_cfg.client_secret.clone())),
                )
                .set_redirect_uri(
                    RedirectUrl::new(oidc_cfg.redirect_url.clone())
                        .context("invalid auth.oidc.redirect_url")?,
                );
                Some(OidcRuntime {
                    client,
                    http_client,
                    claim_username: oidc_cfg.claim_username.clone(),
                    claim_groups: oidc_cfg.claim_groups.clone(),
                    role_map: oidc_cfg.role_map.clone(),
                    pending: Arc::new(RwLock::new(HashMap::new())),
                })
            }
            AuthMode::LocalUsers => None,
        };

        Ok(Self {
            cfg: cfg.clone(),
            api_tokens: Arc::new(api_tokens),
            local_users: Arc::new(local_users),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            oidc,
        })
    }

    pub fn mode(&self) -> AuthMode {
        self.cfg.mode
    }

    pub async fn local_login(&self, req: LocalLoginRequest) -> Result<AuthResponse> {
        if self.cfg.mode != AuthMode::LocalUsers {
            anyhow::bail!("local login is not enabled");
        }
        let user = self
            .local_users
            .get(&req.username)
            .ok_or_else(|| anyhow::anyhow!("invalid credentials"))?;
        if user.disabled {
            anyhow::bail!("user is disabled");
        }

        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| anyhow::anyhow!("invalid password hash format in config"))?;
        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| anyhow::anyhow!("invalid credentials"))?;

        Ok(AuthResponse {
            user: AuthUser {
                username: user.username.clone(),
                role: user.role,
                auth_mode: "local_users".to_string(),
            },
        })
    }

    pub async fn oidc_login_url(&self) -> Result<String> {
        let oidc = self
            .oidc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("oidc auth is not enabled"))?;

        let mut req = oidc.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        if let Some(oidc_cfg) = self.cfg.oidc.as_ref() {
            for scope in &oidc_cfg.scopes {
                req = req.add_scope(Scope::new(scope.clone()));
            }
        }
        let (url, state, nonce) = req.url();
        oidc.pending.write().await.insert(
            state.secret().to_string(),
            PendingOidcState {
                nonce: nonce.secret().to_string(),
                created_at: Utc::now(),
            },
        );
        Ok(url.to_string())
    }

    pub async fn oidc_callback(&self, code: &str, state: &str) -> Result<AuthResponse> {
        let oidc = self
            .oidc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("oidc auth is not enabled"))?;
        let pending = oidc
            .pending
            .write()
            .await
            .remove(state)
            .ok_or_else(|| anyhow::anyhow!("invalid or expired OIDC state"))?;
        if Utc::now() - pending.created_at > Duration::minutes(10) {
            anyhow::bail!("expired OIDC state");
        }

        let token_response = oidc
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .context("missing token endpoint in provider metadata")?
            .request_async(&oidc.http_client)
            .await
            .context("failed token exchange")?;
        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow::anyhow!("provider did not return id_token"))?;
        let nonce = Nonce::new(pending.nonce);
        let _claims = id_token
            .claims(&oidc.client.id_token_verifier(), &nonce)
            .context("failed id_token verification")?;

        let claims_value = decode_jwt_claims(&id_token.to_string())?;
        let username = extract_username(&claims_value, &oidc.claim_username)
            .ok_or_else(|| anyhow::anyhow!("unable to resolve username claim"))?;
        let groups = extract_groups(&claims_value, &oidc.claim_groups);
        let role = resolve_role(&oidc.role_map, &groups)
            .ok_or_else(|| anyhow::anyhow!("no role mapping matched for user"))?;
        let auth_mode = match self.cfg.mode {
            AuthMode::OidcEntra => "oidc_entra",
            AuthMode::OidcOkta => "oidc_okta",
            AuthMode::LocalUsers => "local_users",
        };
        Ok(AuthResponse {
            user: AuthUser {
                username,
                role,
                auth_mode: auth_mode.to_string(),
            },
        })
    }

    pub async fn create_session_cookie(&self, user: AuthUser) -> Cookie<'static> {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::minutes(self.cfg.session_ttl_minutes as i64);
        self.sessions
            .write()
            .await
            .insert(token.clone(), StoredSession { user, expires_at });

        Cookie::build((self.cfg.cookie_name.clone(), token))
            .http_only(true)
            .secure(self.cfg.secure_cookie)
            .same_site(SameSite::Lax)
            .path("/")
            .build()
    }

    pub fn clear_session_cookie(&self) -> Cookie<'static> {
        Cookie::build((self.cfg.cookie_name.clone(), ""))
            .max_age(time::Duration::seconds(0))
            .path("/")
            .build()
    }

    pub async fn resolve_user_from_cookie(&self, jar: &CookieJar) -> Option<AuthUser> {
        let token = jar.get(&self.cfg.cookie_name)?.value().to_string();
        let maybe = self.sessions.read().await.get(&token).cloned();
        let session = maybe?;
        if Utc::now() > session.expires_at {
            self.sessions.write().await.remove(&token);
            return None;
        }
        Some(session.user)
    }

    pub fn resolve_user_from_api_token_header(&self, headers: &HeaderMap) -> Option<AuthUser> {
        let token = extract_api_token(headers)?;
        self.resolve_user_from_api_token(token)
    }

    pub async fn invalidate_cookie_session(&self, jar: &CookieJar) {
        if let Some(cookie) = jar.get(&self.cfg.cookie_name) {
            self.sessions.write().await.remove(cookie.value());
        }
    }

    fn resolve_user_from_api_token(&self, token: &str) -> Option<AuthUser> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }

        for api_token in self.api_tokens.iter() {
            if api_token.disabled {
                continue;
            }
            let parsed_hash = match PasswordHash::new(&api_token.token_hash) {
                Ok(hash) => hash,
                Err(_) => continue,
            };
            if Argon2::default()
                .verify_password(token.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return Some(AuthUser {
                    username: api_token.name.clone(),
                    role: api_token.role,
                    auth_mode: "api_token".to_string(),
                });
            }
        }
        None
    }
}

pub fn has_min_role(user: &AuthUser, required: RoleName) -> bool {
    role_rank(user.role) >= role_rank(required)
}

fn role_rank(role: RoleName) -> i32 {
    match role {
        RoleName::Helpdesk => 10,
        RoleName::Analyst => 20,
        RoleName::Admin => 30,
    }
}

fn resolve_role(map: &OidcRoleMap, groups: &[String]) -> Option<RoleName> {
    if intersects(groups, &map.admin_groups) {
        return Some(RoleName::Admin);
    }
    if intersects(groups, &map.analyst_groups) {
        return Some(RoleName::Analyst);
    }
    if intersects(groups, &map.helpdesk_groups) {
        return Some(RoleName::Helpdesk);
    }
    None
}

fn intersects(a: &[String], b: &[String]) -> bool {
    a.iter().any(|item| b.iter().any(|wanted| wanted == item))
}

fn decode_jwt_claims(jwt: &str) -> Result<serde_json::Value> {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        anyhow::bail!("malformed jwt");
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("invalid jwt payload encoding")?;
    serde_json::from_slice(&payload).context("invalid jwt payload json")
}

fn extract_username(claims: &serde_json::Value, claim_name: &str) -> Option<String> {
    let preferred = claims.get(claim_name).and_then(|v| v.as_str());
    let fallback = claims
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("upn").and_then(|v| v.as_str()))
        .or_else(|| claims.get("email").and_then(|v| v.as_str()))
        .or_else(|| claims.get("sub").and_then(|v| v.as_str()));
    preferred.or(fallback).map(ToOwned::to_owned)
}

fn extract_groups(claims: &serde_json::Value, claim_name: &str) -> Vec<String> {
    let Some(value) = claims.get(claim_name) else {
        return Vec::new();
    };
    if let Some(arr) = value.as_array() {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
    }
    if let Some(single) = value.as_str() {
        return single
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
    warn!("unsupported groups claim format");
    Vec::new()
}

fn extract_api_token(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let mut parts = value.split_whitespace();
        if let (Some(scheme), Some(token), None) = (parts.next(), parts.next(), parts.next())
            && scheme.eq_ignore_ascii_case("bearer")
            && !token.trim().is_empty()
        {
            return Some(token.trim());
        }
    }

    headers
        .get("x-api-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    use axum::http::{HeaderValue, header};

    use super::*;

    fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("hash password")
            .to_string()
    }

    fn local_auth_cfg() -> AuthConfig {
        let mut cfg = AuthConfig::default();
        cfg.local_users.users = vec![LocalUser {
            username: "alice".to_string(),
            password_hash: hash_password("correct-horse-battery-staple"),
            role: RoleName::Analyst,
            disabled: false,
        }];
        cfg
    }

    fn hash_secret(secret: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(secret.as_bytes(), &salt)
            .expect("hash secret")
            .to_string()
    }

    #[tokio::test]
    async fn local_login_success_and_session_roundtrip() {
        let cfg = local_auth_cfg();
        let manager = AuthManager::new(&cfg).await.expect("create manager");
        let login = manager
            .local_login(LocalLoginRequest {
                username: "alice".to_string(),
                password: "correct-horse-battery-staple".to_string(),
            })
            .await
            .expect("login should succeed");
        assert_eq!(login.user.username, "alice");
        assert_eq!(login.user.role, RoleName::Analyst);

        let session_cookie = manager.create_session_cookie(login.user).await;
        let jar = CookieJar::new().add(session_cookie);
        let resolved = manager
            .resolve_user_from_cookie(&jar)
            .await
            .expect("session must resolve");
        assert_eq!(resolved.username, "alice");

        manager.invalidate_cookie_session(&jar).await;
        let after_invalidate = manager.resolve_user_from_cookie(&jar).await;
        assert!(after_invalidate.is_none());
    }

    #[tokio::test]
    async fn local_login_rejects_bad_password() {
        let cfg = local_auth_cfg();
        let manager = AuthManager::new(&cfg).await.expect("create manager");
        let err = manager
            .local_login(LocalLoginRequest {
                username: "alice".to_string(),
                password: "wrong-password".to_string(),
            })
            .await
            .expect_err("login must fail");
        assert!(err.to_string().contains("invalid credentials"));
    }

    #[test]
    fn role_order_is_enforced() {
        let helpdesk = AuthUser {
            username: "h".to_string(),
            role: RoleName::Helpdesk,
            auth_mode: "local_users".to_string(),
        };
        let analyst = AuthUser {
            username: "a".to_string(),
            role: RoleName::Analyst,
            auth_mode: "local_users".to_string(),
        };
        assert!(has_min_role(&analyst, RoleName::Helpdesk));
        assert!(!has_min_role(&helpdesk, RoleName::Analyst));
    }

    #[tokio::test]
    async fn api_token_header_resolves_user() {
        let mut cfg = local_auth_cfg();
        cfg.api_tokens.tokens = vec![ApiTokenConfig {
            name: "svc-servicenow".to_string(),
            token_hash: hash_secret("secret-token-value"),
            role: RoleName::Analyst,
            disabled: false,
        }];
        let manager = AuthManager::new(&cfg).await.expect("create manager");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token-value"),
        );

        let user = manager
            .resolve_user_from_api_token_header(&headers)
            .expect("api token user");
        assert_eq!(user.username, "svc-servicenow");
        assert_eq!(user.role, RoleName::Analyst);
        assert_eq!(user.auth_mode, "api_token");
    }

    #[test]
    fn x_api_token_header_is_supported() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-token",
            HeaderValue::from_static("secret-token-value"),
        );
        assert_eq!(extract_api_token(&headers), Some("secret-token-value"));
    }
}
