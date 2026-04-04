use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use argon2::PasswordHash;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub data: DataConfig,
    pub ingestor: IngestorConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
    pub query: QueryConfig,
    pub audit: AuditConfig,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading config {}", path.display()))?;
        let mut cfg: AppConfig =
            toml::from_str(&raw).with_context(|| format!("failed parsing {}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if cfg.data.parquet_root.is_relative() {
            cfg.data.parquet_root = base.join(&cfg.data.parquet_root);
        }
        if cfg.audit.path.is_relative() {
            cfg.audit.path = base.join(&cfg.audit.path);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.query.max_days_per_query == 0 {
            anyhow::bail!("query.max_days_per_query must be > 0");
        }
        if self.query.max_rows == 0 {
            anyhow::bail!("query.max_rows must be > 0");
        }
        if self.query.default_limit == 0 || self.query.default_limit > self.query.max_rows {
            anyhow::bail!("query.default_limit must be in range 1..=query.max_rows");
        }
        if self.query.timeout_ms < 500 {
            anyhow::bail!("query.timeout_ms must be >= 500");
        }
        if self.ingestor.base_url.trim().is_empty() {
            anyhow::bail!("ingestor.base_url cannot be empty");
        }
        if !self.ingestor.base_url.starts_with("http://")
            && !self.ingestor.base_url.starts_with("https://")
        {
            anyhow::bail!("ingestor.base_url must start with http:// or https://");
        }
        if self.ingestor.request_timeout_ms < 500 {
            anyhow::bail!("ingestor.request_timeout_ms must be >= 500");
        }
        if self.auth.session_ttl_minutes == 0 {
            anyhow::bail!("auth.session_ttl_minutes must be > 0");
        }
        if self.auth.cookie_name.trim().is_empty() {
            anyhow::bail!("auth.cookie_name cannot be empty");
        }
        let mut api_token_names = std::collections::HashSet::new();
        for token in &self.auth.api_tokens.tokens {
            if token.name.trim().is_empty() {
                anyhow::bail!("auth.api_tokens.tokens[].name cannot be empty");
            }
            PasswordHash::new(&token.token_hash).map_err(|_| {
                anyhow::anyhow!(
                    "auth.api_tokens.tokens[{}] has invalid token_hash format",
                    token.name
                )
            })?;
            for source in &token.allowed_sources {
                parse_allowed_source(source).map_err(|err| {
                    anyhow::anyhow!(
                        "auth.api_tokens.tokens[{}] has invalid allowed_sources entry '{}': {err}",
                        token.name,
                        source
                    )
                })?;
            }
            if !api_token_names.insert(token.name.clone()) {
                anyhow::bail!("duplicate auth.api_tokens token name '{}'", token.name);
            }
        }
        validate_identifier(&self.data.fields.time_field)?;
        validate_identifier(&self.data.fields.user_field)?;
        validate_identifier(&self.data.fields.url_field)?;
        validate_identifier(&self.data.fields.action_field)?;
        validate_identifier(&self.data.fields.response_code_field)?;
        validate_identifier(&self.data.fields.reason_field)?;
        validate_identifier(&self.data.fields.threat_field)?;
        validate_identifier(&self.data.fields.category_field)?;
        validate_identifier(&self.data.fields.source_ip_field)?;
        validate_identifier(&self.data.fields.server_ip_field)?;
        validate_identifier(&self.data.fields.device_field)?;
        validate_identifier(&self.data.fields.department_field)?;
        if let Some(name) = self.data.fields.source_country_field.as_deref() {
            validate_identifier(name)?;
        }
        if let Some(name) = self.data.fields.destination_country_field.as_deref() {
            validate_identifier(name)?;
        }
        for col in &self.query.default_columns {
            validate_identifier(col)?;
        }
        for col in &self.security.helpdesk_mask_fields {
            validate_identifier(col)?;
        }
        if self.audit.rotate_max_bytes > 0 && self.audit.rotate_max_files == 0 {
            anyhow::bail!("audit.rotate_max_files must be > 0 when audit.rotate_max_bytes is set");
        }

        match self.auth.mode {
            AuthMode::LocalUsers => {
                if self.auth.local_users.users.is_empty() {
                    anyhow::bail!("auth.local_users.users cannot be empty in local_users mode");
                }
            }
            AuthMode::OidcEntra | AuthMode::OidcOkta => {
                if !self.auth.secure_cookie {
                    anyhow::bail!("auth.secure_cookie must be true in oidc modes");
                }
                let oidc = self
                    .auth
                    .oidc
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("auth.oidc is required in oidc mode"))?;
                if oidc.issuer_url.trim().is_empty()
                    || oidc.client_id.trim().is_empty()
                    || oidc.client_secret.trim().is_empty()
                    || oidc.redirect_url.trim().is_empty()
                {
                    anyhow::bail!(
                        "auth.oidc issuer_url/client_id/client_secret/redirect_url are required in oidc mode"
                    );
                }
                if !oidc.redirect_url.starts_with("https://") {
                    anyhow::bail!("auth.oidc.redirect_url must use https in oidc modes");
                }
            }
        }
        Ok(())
    }
}

fn validate_identifier(name: &str) -> Result<()> {
    let re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid regex");
    if re.is_match(name) {
        Ok(())
    } else {
        anyhow::bail!(
            "invalid field identifier '{}': allowed [A-Za-z_][A-Za-z0-9_]*",
            name
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind_addr: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9191".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DataConfig {
    pub parquet_root: PathBuf,
    pub fields: FieldMap,
}

impl Default for DataConfig {
    fn default() -> Self {
        Self {
            parquet_root: PathBuf::from("/var/lib/nss-ingestor/data"),
            fields: FieldMap::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct IngestorConfig {
    pub base_url: String,
    pub request_timeout_ms: u64,
}

impl Default for IngestorConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:9090".to_string(),
            request_timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FieldMap {
    pub time_field: String,
    pub user_field: String,
    pub url_field: String,
    pub action_field: String,
    pub response_code_field: String,
    pub reason_field: String,
    pub threat_field: String,
    pub category_field: String,
    pub source_ip_field: String,
    pub server_ip_field: String,
    pub device_field: String,
    pub department_field: String,
    pub source_country_field: Option<String>,
    pub destination_country_field: Option<String>,
}

impl Default for FieldMap {
    fn default() -> Self {
        Self {
            time_field: "time".to_string(),
            user_field: "login".to_string(),
            url_field: "url".to_string(),
            action_field: "action".to_string(),
            response_code_field: "respcode".to_string(),
            reason_field: "reason".to_string(),
            threat_field: "threatname".to_string(),
            category_field: "urlcat".to_string(),
            source_ip_field: "cip".to_string(),
            server_ip_field: "sip".to_string(),
            device_field: "devicehostname".to_string(),
            department_field: "dept".to_string(),
            source_country_field: Some("srcip_country".to_string()),
            destination_country_field: Some("dstip_country".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    OidcEntra,
    OidcOkta,
    LocalUsers,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub cookie_name: String,
    pub session_ttl_minutes: u64,
    pub secure_cookie: bool,
    pub oidc: Option<OidcConfig>,
    pub api_tokens: ApiTokensConfig,
    pub local_users: LocalUsersConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::LocalUsers,
            cookie_name: "nssq_session".to_string(),
            session_ttl_minutes: 60,
            secure_cookie: true,
            oidc: None,
            api_tokens: ApiTokensConfig::default(),
            local_users: LocalUsersConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub claim_username: String,
    pub claim_groups: String,
    pub role_map: OidcRoleMap,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_url: String::new(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            claim_username: "preferred_username".to_string(),
            claim_groups: "groups".to_string(),
            role_map: OidcRoleMap::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct OidcRoleMap {
    pub helpdesk_groups: Vec<String>,
    pub analyst_groups: Vec<String>,
    pub admin_groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct LocalUsersConfig {
    pub users: Vec<LocalUser>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct ApiTokensConfig {
    pub tokens: Vec<ApiTokenConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiTokenConfig {
    pub name: String,
    pub token_hash: String,
    pub role: RoleName,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

pub fn parse_allowed_source(value: &str) -> Result<IpNet> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("source cannot be empty");
    }
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Ok(net);
    }
    let ip = trimmed
        .parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!("expected IP or CIDR"))?;
    Ok(IpNet::from(ip))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalUser {
    pub username: String,
    pub password_hash: String,
    pub role: RoleName,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoleName {
    Helpdesk,
    Analyst,
    Admin,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub helpdesk_mask_fields: Vec<String>,
    pub input_value_regex: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            helpdesk_mask_fields: vec![
                "login".to_string(),
                "cip".to_string(),
                "devicehostname".to_string(),
            ],
            input_value_regex: r"^[A-Za-z0-9@\._:/\-\s]{1,256}$".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct QueryConfig {
    pub max_days_per_query: i64,
    pub default_limit: u32,
    pub max_rows: u32,
    pub timeout_ms: u64,
    pub default_columns: Vec<String>,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            max_days_per_query: 7,
            default_limit: 200,
            max_rows: 2000,
            timeout_ms: 120_000,
            default_columns: vec![
                "time".to_string(),
                "action".to_string(),
                "url".to_string(),
                "login".to_string(),
                "cip".to_string(),
                "urlcat".to_string(),
                "threatname".to_string(),
                "rulelabel".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditConfig {
    pub path: PathBuf,
    pub retention_days: u64,
    pub rotate_max_bytes: u64,
    pub rotate_max_files: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/nss-quarry/audit.log"),
            retention_days: 0,
            rotate_max_bytes: 0,
            rotate_max_files: 7,
        }
    }
}

#[cfg(test)]
mod tests {
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};

    use super::*;

    fn hash_secret(secret: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(secret.as_bytes(), &salt)
            .expect("secret hash")
            .to_string()
    }

    fn valid_local_config() -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.auth.local_users.users = vec![LocalUser {
            username: "alice".to_string(),
            password_hash: "dummy".to_string(),
            role: RoleName::Helpdesk,
            disabled: false,
        }];
        cfg
    }

    #[test]
    fn validate_accepts_valid_local_config() {
        let cfg = valid_local_config();
        cfg.validate().expect("config should be valid");
    }

    #[test]
    fn validate_rejects_empty_local_users() {
        let mut cfg = AppConfig::default();
        cfg.auth.local_users.users.clear();
        let err = cfg.validate().expect_err("must reject empty users");
        assert!(
            err.to_string()
                .contains("auth.local_users.users cannot be empty")
        );
    }

    #[test]
    fn validate_rejects_invalid_identifier() {
        let mut cfg = valid_local_config();
        cfg.data.fields.user_field = "bad-name".to_string();
        let err = cfg.validate().expect_err("must reject invalid identifier");
        assert!(err.to_string().contains("invalid field identifier"));
    }

    #[test]
    fn validate_rejects_oidc_mode_without_oidc_config() {
        let mut cfg = valid_local_config();
        cfg.auth.mode = AuthMode::OidcEntra;
        cfg.auth.oidc = None;
        let err = cfg.validate().expect_err("must reject missing oidc config");
        assert!(
            err.to_string()
                .contains("auth.oidc is required in oidc mode")
        );
    }

    #[test]
    fn validate_rejects_oidc_with_insecure_cookie() {
        let mut cfg = valid_local_config();
        cfg.auth.mode = AuthMode::OidcOkta;
        cfg.auth.secure_cookie = false;
        cfg.auth.oidc = Some(OidcConfig {
            issuer_url: "https://example.okta.com/oauth2/default".to_string(),
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "https://nss-quarry.example.com/auth/callback".to_string(),
            scopes: vec!["openid".to_string()],
            claim_username: "preferred_username".to_string(),
            claim_groups: "groups".to_string(),
            role_map: OidcRoleMap::default(),
        });
        let err = cfg
            .validate()
            .expect_err("must reject insecure cookie in oidc");
        assert!(
            err.to_string()
                .contains("auth.secure_cookie must be true in oidc modes")
        );
    }

    #[test]
    fn validate_rejects_oidc_non_https_redirect() {
        let mut cfg = valid_local_config();
        cfg.auth.mode = AuthMode::OidcEntra;
        cfg.auth.oidc = Some(OidcConfig {
            issuer_url: "https://login.microsoftonline.com/tenant/v2.0".to_string(),
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "http://nss-quarry.example.com/auth/callback".to_string(),
            scopes: vec!["openid".to_string()],
            claim_username: "preferred_username".to_string(),
            claim_groups: "roles".to_string(),
            role_map: OidcRoleMap::default(),
        });
        let err = cfg
            .validate()
            .expect_err("must reject non-https redirect in oidc");
        assert!(
            err.to_string()
                .contains("auth.oidc.redirect_url must use https in oidc modes")
        );
    }

    #[test]
    fn validate_rejects_rotate_bytes_without_rotate_files() {
        let mut cfg = valid_local_config();
        cfg.audit.rotate_max_bytes = 1024;
        cfg.audit.rotate_max_files = 0;
        let err = cfg
            .validate()
            .expect_err("must reject invalid audit rotation config");
        assert!(
            err.to_string()
                .contains("audit.rotate_max_files must be > 0 when audit.rotate_max_bytes is set")
        );
    }

    #[test]
    fn validate_rejects_invalid_api_token_hash() {
        let mut cfg = valid_local_config();
        cfg.auth.api_tokens.tokens = vec![ApiTokenConfig {
            name: "svc-servicenow".to_string(),
            token_hash: "not-a-hash".to_string(),
            role: RoleName::Analyst,
            allowed_sources: Vec::new(),
            disabled: false,
            created_at: None,
            updated_at: None,
        }];
        let err = cfg
            .validate()
            .expect_err("must reject invalid api token hash");
        assert!(err.to_string().contains("invalid token_hash format"));
    }

    #[test]
    fn validate_rejects_invalid_api_token_allowed_source() {
        let mut cfg = valid_local_config();
        cfg.auth.api_tokens.tokens = vec![ApiTokenConfig {
            name: "svc-servicenow".to_string(),
            token_hash: hash_secret("secret-token"),
            role: RoleName::Analyst,
            allowed_sources: vec!["bad-cidr".to_string()],
            disabled: false,
            created_at: None,
            updated_at: None,
        }];
        let err = cfg
            .validate()
            .expect_err("must reject invalid api token allowed source");
        assert!(err.to_string().contains("invalid allowed_sources entry"));
    }
}
