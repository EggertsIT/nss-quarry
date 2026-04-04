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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchRequest {
    pub time_from: DateTime<Utc>,
    pub time_to: DateTime<Utc>,
    #[serde(default)]
    pub filters: SearchFilters,
    pub limit: Option<u32>,
    pub columns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SearchFilters {
    pub user: Option<String>,
    pub url: Option<String>,
    pub action: Option<String>,
    #[serde(alias = "respcode")]
    pub response_code: Option<String>,
    pub reason: Option<String>,
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
pub struct PcapAnalyzeResponse {
    pub file_name: Option<String>,
    pub link_type: String,
    pub time_from: DateTime<Utc>,
    pub time_to: DateTime<Utc>,
    pub search_time_from: DateTime<Utc>,
    pub search_time_to: DateTime<Utc>,
    pub search_window_pad_seconds: i64,
    pub duration_seconds: i64,
    pub packet_count: u64,
    pub ip_packet_count: u64,
    pub unique_source_ip_count: usize,
    pub source_ips: Vec<String>,
    pub truncated_source_ips: bool,
    pub unique_destination_ip_count: usize,
    pub destination_ips: Vec<String>,
    pub truncated_ips: bool,
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

#[derive(Debug, Serialize)]
pub struct AuditListResponse {
    pub rows: Vec<AuditEvent>,
    pub page: u32,
    pub page_size: u32,
    pub total: usize,
    pub total_pages: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngestorForceFinalizeOpenFilesResult {
    pub finalized_files: u64,
    pub finalized_rows: u64,
    pub skipped_empty_writers: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngestorForceFinalizeOpenFilesResponse {
    pub status: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub triggered_at: String,
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    #[serde(default)]
    pub retry_after_secs: Option<u64>,
    #[serde(default)]
    pub result: Option<IngestorForceFinalizeOpenFilesResult>,
}
