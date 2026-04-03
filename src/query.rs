use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
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
        let sql = build_search_sql(
            &columns,
            &req,
            &self.inner.fields,
            &self.inner.parquet_root,
            limit,
        );

        let conn = Connection::open_in_memory()?;
        let mut stmt = conn.prepare(&sql)?;
        let col_names = stmt
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
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
        let parquet_src = parquet_source_sql(&self.inner.parquet_root);

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
                    parquet_src: &parquet_src,
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
                    parquet_src: &parquet_src,
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
                    parquet_src: &parquet_src,
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
                    parquet_src: &parquet_src,
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
                    parquet_src: &parquet_src,
                    limit: 10,
                },
            )?,
        ];

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
    if value.trim().is_empty() {
        return;
    }
    where_clauses.push(format!(
        "CAST({} AS VARCHAR) ILIKE '%{}%' ESCAPE '\\\\'",
        ident(column),
        escape_like(value)
    ));
}

fn build_search_sql(
    columns: &[String],
    req: &SearchRequest,
    fields: &FieldMap,
    parquet_root: &Path,
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
    apply_filter(
        &mut where_clauses,
        &fields.source_ip_field,
        req.filters.source_ip.as_deref(),
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

    let parquet_src = parquet_source_sql(parquet_root);

    format!(
        "SELECT {select_list} FROM {parquet_src} WHERE {} ORDER BY {time_col} DESC LIMIT {limit}",
        where_clauses.join(" AND "),
        parquet_src = parquet_src
    )
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''")
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
    for value in [
        filters.user.as_deref(),
        filters.url.as_deref(),
        filters.action.as_deref(),
        filters.threat.as_deref(),
        filters.category.as_deref(),
        filters.source_ip.as_deref(),
        filters.device.as_deref(),
        filters.department.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !re.is_match(value) {
            anyhow::bail!("filter value contains disallowed characters");
        }
    }
    Ok(())
}

fn parquet_glob_pattern(root: &Path) -> String {
    let raw = root.join("dt=*/hour=*/*.parquet").display().to_string();
    raw.replace('\'', "''")
}

fn parquet_source_sql(root: &Path) -> String {
    let pattern = parquet_glob_pattern(root);
    format!("read_parquet('{pattern}', union_by_name=true)")
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
            columns: Some(vec!["time".to_string(), "eurl".to_string()]),
        };
        let columns = req.columns.clone().expect("columns");
        let fields = FieldMap::default();
        let sql = build_search_sql(&columns, &req, &fields, Path::new("/tmp/o'hare"), 123);

        assert!(sql.contains(
            "SELECT CAST(\"time\" AS VARCHAR) AS \"time\", CAST(\"eurl\" AS VARCHAR) AS \"eurl\""
        ));
        assert!(sql.contains("read_parquet('/tmp/o''hare/dt=*/hour=*/*.parquet', union_by_name=true)"));
        assert!(sql.contains("ORDER BY \"time\" DESC LIMIT 123"));

        let escaped_url = escape_like("exa%m_ple'\\path");
        assert!(sql.contains("CAST(\"ologin\" AS VARCHAR) ILIKE '%alice%' ESCAPE '\\\\'"));
        assert!(sql.contains(&format!(
            "CAST(\"eurl\" AS VARCHAR) ILIKE '%{}%' ESCAPE '\\\\'",
            escaped_url
        )));
    }
}
