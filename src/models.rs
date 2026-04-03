use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::RoleName;

#[derive(Debug, Clone, Serialize)]
pub struct AuthUser {
    pub username: String,
    pub role: RoleName,
    pub auth_mode: String,
}

#[derive(Debug, Deserialize)]
pub struct LocalLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: AuthUser,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchRequest {
    pub time_from: DateTime<Utc>,
    pub time_to: DateTime<Utc>,
    #[serde(default)]
    pub filters: SearchFilters,
    pub limit: Option<u32>,
    pub columns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SearchFilters {
    pub user: Option<String>,
    pub url: Option<String>,
    pub action: Option<String>,
    pub threat: Option<String>,
    pub category: Option<String>,
    #[serde(alias = "cip")]
    pub source_ip: Option<String>,
    #[serde(alias = "sip")]
    pub server_ip: Option<String>,
    pub device: Option<String>,
    pub department: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
    pub row_count: usize,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub name: String,
    pub generated_at: DateTime<Utc>,
    pub cards: Vec<MetricCard>,
    pub tables: Vec<TableBlock>,
}

#[derive(Debug, Serialize)]
pub struct SchemaFieldInfo {
    pub name: String,
    pub mapped_from: String,
}

#[derive(Debug, Serialize)]
pub struct ParquetColumnInfo {
    pub name: String,
    pub data_type: String,
}

#[derive(Debug, Serialize)]
pub struct SchemaResponse {
    pub auth_mode: String,
    pub fields: Vec<SchemaFieldInfo>,
    pub parquet_columns: Vec<ParquetColumnInfo>,
    pub parquet_schema_error: Option<String>,
    pub default_columns: Vec<String>,
    pub helpdesk_mask_fields: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct MetricCard {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Serialize)]
pub struct TableBlock {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub reason: Option<String>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: DateTime<Utc>,
    pub actor: Option<String>,
    pub role: Option<RoleName>,
    pub action: String,
    pub outcome: String,
    pub metadata: serde_json::Value,
}
