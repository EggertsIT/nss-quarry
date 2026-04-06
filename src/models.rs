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
    pub page: Option<u32>,
    pub page_size: Option<u32>,
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
    pub source_country: Option<String>,
    pub destination_country: Option<String>,
    pub device: Option<String>,
    pub department: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
    pub row_count: usize,
    pub truncated: bool,
    pub page: u32,
    pub page_size: u32,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchViewMode {
    Raw,
    ByDestination,
    ByReason,
    ByUserDevice,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchGroupedRequest {
    pub search: SearchRequest,
    #[serde(default)]
    pub view_mode: Option<SearchViewMode>,
    pub sort_by: Option<String>,
    pub sort_desc: Option<bool>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchGroupedResponse {
    pub view_mode: SearchViewMode,
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
    pub row_count: usize,
    pub total_groups: usize,
    pub truncated: bool,
    pub page: u32,
    pub page_size: u32,
    pub has_more: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchTimelineRequest {
    pub search: SearchRequest,
    pub bucket_minutes: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchTimelinePoint {
    pub bucket_start: DateTime<Utc>,
    pub bucket_end: DateTime<Utc>,
    pub count: usize,
    pub blocked: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchTimelineResponse {
    pub generated_at: DateTime<Utc>,
    pub bucket_minutes: u32,
    pub points: Vec<SearchTimelinePoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SearchTriageRequest {
    pub search: SearchRequest,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchTriageResponse {
    pub generated_at: DateTime<Utc>,
    pub top_reasons: Vec<SupportSummaryItem>,
    pub top_response_codes: Vec<SupportSummaryItem>,
    pub top_destinations: Vec<SupportSummaryItem>,
    pub zero_response_destinations: Vec<SupportSummaryItem>,
    pub tls_or_ssl_indicators: Vec<SupportSummaryItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SupportSummaryRequest {
    pub search: SearchRequest,
    #[serde(default)]
    pub pcap_context: Option<SupportSummaryPcapContext>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SupportSummaryPcapContext {
    pub file_name: Option<String>,
    pub link_type: Option<String>,
    pub time_from: Option<DateTime<Utc>>,
    pub time_to: Option<DateTime<Utc>>,
    pub search_time_from: Option<DateTime<Utc>>,
    pub search_time_to: Option<DateTime<Utc>>,
    pub packet_count: Option<u64>,
    pub unique_source_ip_count: Option<usize>,
    pub unique_destination_ip_count: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SupportClassification {
    PolicyBlock,
    SslTlsIssue,
    GeoIssue,
    ThreatOrReputation,
    ConnectivityOrProbeFailure,
    CloudAppOrFileControl,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportSummaryItem {
    pub value: String,
    pub count: usize,
    pub hint: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportFinding {
    pub title: String,
    pub severity: String,
    pub summary: String,
    pub count: usize,
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportSummaryResponse {
    pub generated_at: DateTime<Utc>,
    pub time_from: DateTime<Utc>,
    pub time_to: DateTime<Utc>,
    pub row_count: usize,
    pub truncated: bool,
    pub pcap_assisted: bool,
    pub overview: String,
    pub issue_classification: Vec<SupportClassification>,
    pub primary_findings: Vec<SupportFinding>,
    pub top_signals: Vec<SupportSummaryItem>,
    pub recommended_next_checks: Vec<String>,
    pub missing_inputs: Vec<String>,
    pub response_code_summary: Vec<SupportSummaryItem>,
    pub policy_reason_summary: Vec<SupportSummaryItem>,
    pub zero_response_destinations: Vec<SupportSummaryItem>,
    pub tls_or_certificate_indicators: Vec<SupportSummaryItem>,
    pub geo_indicators: Vec<SupportSummaryItem>,
    pub threat_indicators: Vec<SupportSummaryItem>,
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DashboardStatus {
    Warming,
    Ready,
    Stale,
    Degraded,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardResponse {
    pub name: String,
    pub generated_at: DateTime<Utc>,
    pub status: DashboardStatus,
    pub source: String,
    pub snapshot_generated_at: Option<DateTime<Utc>>,
    pub snapshot_age_seconds: Option<i64>,
    pub data_window_from: Option<DateTime<Utc>>,
    pub data_window_to: Option<DateTime<Utc>>,
    pub refresh_in_progress: bool,
    pub last_refresh_attempt_at: Option<DateTime<Utc>>,
    pub last_refresh_success_at: Option<DateTime<Utc>>,
    pub last_refresh_error: Option<String>,
    pub notes: Vec<String>,
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

#[derive(Debug, Clone, Serialize)]
pub struct MetricCard {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenInfo {
    pub name: String,
    pub role: RoleName,
    pub allowed_sources: Vec<String>,
    pub disabled: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenListResponse {
    pub rows: Vec<ApiTokenInfo>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiTokenCreateRequest {
    pub name: String,
    pub role: RoleName,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenCreateResponse {
    pub token: String,
    pub token_info: ApiTokenInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiTokenUpdateRequest {
    pub role: RoleName,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvestigationPivot {
    pub id: String,
    pub field: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvestigationPinnedItem {
    pub id: String,
    pub pinned_at: DateTime<Utc>,
    pub note: Option<String>,
    pub row: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvestigationSession {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub owner: String,
    pub search: SearchRequest,
    #[serde(default)]
    pub pivots: Vec<InvestigationPivot>,
    #[serde(default)]
    pub pinned_items: Vec<InvestigationPinnedItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvestigationCreateRequest {
    pub search: SearchRequest,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvestigationPivotInput {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvestigationUpdateRequest {
    pub time_from: Option<DateTime<Utc>>,
    pub time_to: Option<DateTime<Utc>>,
    pub filters: Option<SearchFilters>,
    pub columns: Option<Vec<String>>,
    pub limit: Option<u32>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub pivots: Option<Vec<InvestigationPivotInput>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InvestigationPinRequest {
    pub row: serde_json::Map<String, serde_json::Value>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvestigationExportResponse {
    pub investigation_id: String,
    pub exported_at: DateTime<Utc>,
    pub owner: String,
    pub query: SearchRequest,
    pub pivots: Vec<InvestigationPivot>,
    pub pinned_items: Vec<InvestigationPinnedItem>,
    pub summary: SupportSummaryResponse,
    pub csv: String,
    pub csv_filename: String,
}
