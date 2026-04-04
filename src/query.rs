use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Timelike, Utc};
use duckdb::Connection;
use regex::Regex;

use crate::config::{AppConfig, FieldMap, RoleName};
use crate::models::{
    DashboardResponse, MetricCard, SearchFilters, SearchRequest, SearchResponse, TableBlock,
};

#[derive(Clone)]
pub struct QueryService {
    inner: Arc<QueryInner>,
}

struct QueryInner {
    parquet_root: PathBuf,
    fields: FieldMap,
    default_columns: Vec<String>,
    helpdesk_mask_fields: Vec<String>,
    input_value_re: Regex,
    max_days_per_query: i64,
    default_limit: u32,
    max_rows: u32,
    timeout_ms: u64,
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
        let result = tokio::time::timeout(Duration::from_millis(self.inner.timeout_ms), work)
            .await
            .map_err(|_| anyhow::anyhow!("query timed out"))?
            .context("search worker failed")??;
        Ok(result)
    }

    pub async fn export_csv(&self, req: SearchRequest, role: RoleName) -> Result<String> {
        let result = self.search(req, role).await?;
        Ok(rows_to_csv(&result.rows))
    }

    pub async fn dashboard(&self, name: &str, role: RoleName) -> Result<DashboardResponse> {
        let svc = self.clone();
        let name = name.to_string();
        let work = tokio::task::spawn_blocking(move || svc.dashboard_sync(&name, role));
        tokio::time::timeout(Duration::from_millis(self.inner.timeout_ms), work)
            .await
            .map_err(|_| anyhow::anyhow!("dashboard query timed out"))?
            .context("dashboard worker failed")?
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
            .unwrap_or(self.inner.default_limit)
            .min(self.inner.max_rows);

        let Some(parquet_src) =
            parquet_source_sql_for_range(&self.inner.parquet_root, req.time_from, req.time_to)?
        else {
            return Ok(SearchResponse {
                rows: Vec::new(),
                row_count: 0,
                truncated: false,
            });
        };

        let sql = build_search_sql(&columns, &req, &self.inner.fields, &parquet_src, limit);

        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let col_names = columns;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut map = serde_json::Map::new();
            for (i, col) in col_names.iter().enumerate() {
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

        if role == RoleName::Helpdesk {
            apply_helpdesk_masking(&mut out, &self.inner.helpdesk_mask_fields);
        }
        let row_count = out.len();
        Ok(SearchResponse {
            rows: out,
            row_count,
            truncated: row_count as u32 >= limit,
        })
    }

    fn dashboard_sync(&self, name: &str, role: RoleName) -> Result<DashboardResponse> {
        let now = Utc::now();
        let from_24h = now - chrono::Duration::hours(24);
        let time_col = ident(&self.inner.fields.time_field);
        let action_col = ident(&self.inner.fields.action_field);
        let user_col = ident(&self.inner.fields.user_field);
        let category_col = ident(&self.inner.fields.category_field);
        let threat_col = ident(&self.inner.fields.threat_field);
        let device_col = ident(&self.inner.fields.device_field);
        let ip_col = ident(&self.inner.fields.source_ip_field);
        let dept_col = ident(&self.inner.fields.department_field);
        let src_country_col = self.inner.fields.source_country_field.as_deref().map(ident);
        let dst_country_col = self
            .inner
            .fields
            .destination_country_field
            .as_deref()
            .map(ident);
        let Some(parquet_src) =
            parquet_source_sql_for_range(&self.inner.parquet_root, from_24h, now)?
        else {
            return Ok(DashboardResponse {
                name: name.to_string(),
                generated_at: now,
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
                    empty_country_flow_table("country_flows_24h"),
                ],
            });
        };

        let conn = Connection::open_in_memory()?;
        let from_ts = from_24h.format("%Y-%m-%d %H:%M:%S").to_string();
        let to_ts = now.format("%Y-%m-%d %H:%M:%S").to_string();

        let total = scalar_i64(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM {parquet_src} WHERE CAST({time_col} AS TIMESTAMP) BETWEEN TIMESTAMP '{from_ts}' AND TIMESTAMP '{to_ts}'"
            ),
        )?;
        let blocked = scalar_i64(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM {parquet_src} WHERE CAST({time_col} AS TIMESTAMP) BETWEEN TIMESTAMP '{from_ts}' AND TIMESTAMP '{to_ts}' AND CAST({action_col} AS VARCHAR) = 'Blocked'"
            ),
        )?;
        let threats = scalar_i64(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM {parquet_src} WHERE CAST({time_col} AS TIMESTAMP) BETWEEN TIMESTAMP '{from_ts}' AND TIMESTAMP '{to_ts}' AND COALESCE(CAST({threat_col} AS VARCHAR),'') NOT IN ('', 'None', 'N/A')"
            ),
        )?;

        let mut tables = vec![
            top_n(
                &conn,
                TopNArgs {
                    name: "top_users",
                    field_col: &user_col,
                    time_col: &time_col,
                    from_ts: &from_ts,
                    to_ts: &to_ts,
                    parquet_src: parquet_src.as_str(),
                    limit: 10,
                },
            )?,
            top_n(
                &conn,
                TopNArgs {
                    name: "top_categories",
                    field_col: &category_col,
                    time_col: &time_col,
                    from_ts: &from_ts,
                    to_ts: &to_ts,
                    parquet_src: parquet_src.as_str(),
                    limit: 10,
                },
            )?,
            top_n(
                &conn,
                TopNArgs {
                    name: "top_devices",
                    field_col: &device_col,
                    time_col: &time_col,
                    from_ts: &from_ts,
                    to_ts: &to_ts,
                    parquet_src: parquet_src.as_str(),
                    limit: 10,
                },
            )?,
            top_n(
                &conn,
                TopNArgs {
                    name: "top_source_ips",
                    field_col: &ip_col,
                    time_col: &time_col,
                    from_ts: &from_ts,
                    to_ts: &to_ts,
                    parquet_src: parquet_src.as_str(),
                    limit: 10,
                },
            )?,
            top_n(
                &conn,
                TopNArgs {
                    name: "top_departments",
                    field_col: &dept_col,
                    time_col: &time_col,
                    from_ts: &from_ts,
                    to_ts: &to_ts,
                    parquet_src: parquet_src.as_str(),
                    limit: 10,
                },
            )?,
        ];

        let country_flows = match (src_country_col.as_deref(), dst_country_col.as_deref()) {
            (Some(src_col), Some(dst_col)) => top_country_flows(
                &conn,
                CountryFlowArgs {
                    name: "country_flows_24h",
                    src_country_col: src_col,
                    dst_country_col: dst_col,
                    time_col: &time_col,
                    from_ts: &from_ts,
                    to_ts: &to_ts,
                    parquet_src: parquet_src.as_str(),
                    limit: 240,
                },
            )
            .unwrap_or_else(|_| empty_country_flow_table("country_flows_24h")),
            _ => empty_country_flow_table("country_flows_24h"),
        };
        tables.push(country_flows);

        if role == RoleName::Helpdesk {
            for block in &mut tables {
                if block.name == "top_users"
                    || block.name == "top_devices"
                    || block.name == "top_source_ips"
                {
                    for row in &mut block.rows {
                        if let Some(first) = row.first_mut() {
                            *first = "[REDACTED]".to_string();
                        }
                    }
                }
            }
        }

        Ok(DashboardResponse {
            name: name.to_string(),
            generated_at: now,
            cards: vec![
                MetricCard {
                    name: "events_24h".to_string(),
                    value: total,
                },
                MetricCard {
                    name: "blocked_24h".to_string(),
                    value: blocked,
                },
                MetricCard {
                    name: "threat_hits_24h".to_string(),
                    value: threats,
                },
            ],
            tables,
        })
    }
}

struct TopNArgs<'a> {
    name: &'a str,
    field_col: &'a str,
    time_col: &'a str,
    from_ts: &'a str,
    to_ts: &'a str,
    parquet_src: &'a str,
    limit: u32,
}

struct CountryFlowArgs<'a> {
    name: &'a str,
    src_country_col: &'a str,
    dst_country_col: &'a str,
    time_col: &'a str,
    from_ts: &'a str,
    to_ts: &'a str,
    parquet_src: &'a str,
    limit: u32,
}

fn top_n(conn: &Connection, args: TopNArgs<'_>) -> Result<TableBlock> {
    let sql = format!(
        "SELECT COALESCE(CAST({field_col} AS VARCHAR), 'None') AS value, COUNT(*) AS cnt \
         FROM {parquet_src} \
         WHERE CAST({time_col} AS TIMESTAMP) BETWEEN TIMESTAMP '{from_ts}' AND TIMESTAMP '{to_ts}' \
         GROUP BY 1 ORDER BY 2 DESC LIMIT {limit}",
        field_col = args.field_col,
        parquet_src = args.parquet_src,
        time_col = args.time_col,
        from_ts = args.from_ts,
        to_ts = args.to_ts,
        limit = args.limit
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let value: Option<String> = row.get(0)?;
        let count: i64 = row.get(1)?;
        out.push(vec![
            value.unwrap_or_else(|| "None".to_string()),
            count.to_string(),
        ]);
    }
    Ok(TableBlock {
        name: args.name.to_string(),
        columns: vec!["value".to_string(), "count".to_string()],
        rows: out,
    })
}

fn top_country_flows(conn: &Connection, args: CountryFlowArgs<'_>) -> Result<TableBlock> {
    let sql = format!(
        "SELECT \
            CAST({src_country_col} AS VARCHAR) AS source_country, \
            CAST({dst_country_col} AS VARCHAR) AS destination_country, \
            COUNT(*) AS cnt \
         FROM {parquet_src} \
         WHERE CAST({time_col} AS TIMESTAMP) BETWEEN TIMESTAMP '{from_ts}' AND TIMESTAMP '{to_ts}' \
           AND COALESCE(CAST({src_country_col} AS VARCHAR), '') NOT IN ('', 'None', 'N/A') \
           AND COALESCE(CAST({dst_country_col} AS VARCHAR), '') NOT IN ('', 'None', 'N/A') \
         GROUP BY 1, 2 \
         ORDER BY 3 DESC \
         LIMIT {limit}",
        src_country_col = args.src_country_col,
        dst_country_col = args.dst_country_col,
        parquet_src = args.parquet_src,
        time_col = args.time_col,
        from_ts = args.from_ts,
        to_ts = args.to_ts,
        limit = args.limit
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let src: Option<String> = row.get(0)?;
        let dst: Option<String> = row.get(1)?;
        let count: i64 = row.get(2)?;
        out.push(vec![
            src.unwrap_or_else(|| "None".to_string()),
            dst.unwrap_or_else(|| "None".to_string()),
            count.to_string(),
        ]);
    }
    Ok(TableBlock {
        name: args.name.to_string(),
        columns: vec![
            "source_country".to_string(),
            "destination_country".to_string(),
            "count".to_string(),
        ],
        rows: out,
    })
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

    let predicates = values
        .iter()
        .map(|v| {
            format!(
                "LOWER(CAST({} AS VARCHAR)) = LOWER('{}')",
                ident(column),
                escape_sql_literal(v)
            )
        })
        .collect::<Vec<_>>();

    where_clauses.push(format!("({})", predicates.join(" OR ")));
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

fn build_search_sql(
    columns: &[String],
    req: &SearchRequest,
    fields: &FieldMap,
    parquet_src: &str,
    limit: u32,
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
        "CAST({time_col} AS TIMESTAMP) BETWEEN TIMESTAMP '{from}' AND TIMESTAMP '{to}'"
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

    format!(
        "SELECT {select_list} FROM {parquet_src} WHERE {} ORDER BY {time_col} DESC LIMIT {limit}",
        where_clauses.join(" AND "),
        parquet_src = parquet_src
    )
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
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
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
    validate_filter_value(filters.reason.as_deref(), re, false)?;
    validate_filter_value(filters.threat.as_deref(), re, false)?;
    validate_filter_value(filters.category.as_deref(), re, false)?;
    validate_filter_value(filters.source_ip.as_deref(), re, true)?;
    validate_filter_value(filters.server_ip.as_deref(), re, true)?;
    validate_filter_value(filters.device.as_deref(), re, false)?;
    validate_filter_value(filters.department.as_deref(), re, false)?;
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
    let end = floor_to_hour(to);
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
            columns: Some(vec!["time".to_string(), "url".to_string()]),
        };
        let columns = req.columns.clone().expect("columns");
        let fields = FieldMap::default();
        let src = "read_parquet(['/tmp/o''hare/dt=2026-04-01/hour=00/part-000001.parquet'], union_by_name=true)";
        let sql = build_search_sql(&columns, &req, &fields, src, 123);

        assert!(sql.contains(
            "SELECT CAST(\"time\" AS VARCHAR) AS \"time\", CAST(\"url\" AS VARCHAR) AS \"url\""
        ));
        assert!(sql.contains("read_parquet(['/tmp/o''hare/dt=2026-04-01/hour=00/part-000001.parquet'], union_by_name=true)"));
        assert!(sql.contains("ORDER BY \"time\" DESC LIMIT 123"));

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
            columns: Some(vec!["time".to_string(), "sip".to_string()]),
        };
        let columns = req.columns.clone().expect("columns");
        let fields = FieldMap::default();
        let src =
            "read_parquet(['/tmp/dt=2026-04-01/hour=00/part-000001.parquet'], union_by_name=true)";
        let sql = build_search_sql(&columns, &req, &fields, src, 50);

        assert!(sql.contains("LOWER(CAST(\"sip\" AS VARCHAR)) = LOWER('1.1.1.1')"));
        assert!(sql.contains("LOWER(CAST(\"sip\" AS VARCHAR)) = LOWER('8.8.8.8')"));
        assert!(sql.contains(" OR "));
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
}
