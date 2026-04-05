use anyhow::Result;
use serde_json::{Map, Value};

use crate::config::FieldMap;
use crate::models::{SearchResponse, SupportFinding, SupportSummaryItem, SupportSummaryResponse};

const PAGE_WIDTH: i32 = 595;
const PAGE_HEIGHT: i32 = 842;
const LEFT_MARGIN: i32 = 48;
const TOP_MARGIN: i32 = 804;
const LINE_HEIGHT: i32 = 14;
const MAX_CHARS_PER_LINE: usize = 96;
const LINES_PER_PAGE: usize = 52;

pub fn build_support_summary_pdf(
    summary: &SupportSummaryResponse,
    search_result: &SearchResponse,
    fields: &FieldMap,
    requested_by: &str,
) -> Result<Vec<u8>> {
    let incident_rows = collect_incident_rows(search_result, fields);
    let mut lines = Vec::new();
    lines.push("NSS Quarry - Deep Dive Incident Report".to_string());
    lines.push(format!(
        "Generated: {} UTC | Requested by: {}",
        summary.generated_at.format("%Y-%m-%d %H:%M:%S"),
        sanitize_ascii(requested_by)
    ));
    lines.push(format!(
        "Window: {} UTC -> {} UTC",
        summary.time_from.format("%Y-%m-%d %H:%M:%S"),
        summary.time_to.format("%Y-%m-%d %H:%M:%S")
    ));
    lines.push(format!(
        "Returned Rows: {} | Relevant Incident Rows: {} | Truncated: {} | PCAP-assisted: {}",
        search_result.row_count,
        incident_rows.len(),
        if search_result.truncated { "yes" } else { "no" },
        if summary.pcap_assisted { "yes" } else { "no" }
    ));
    lines.push(
        "Relevant incident traffic includes every returned transaction whose policy reason is not empty and not equal to Allowed/None/N/A."
            .to_string(),
    );
    lines.push(String::new());
    lines.extend(wrap_prefixed("Overview: ", &summary.overview));
    lines.push(String::new());
    lines.extend(wrap_prefixed(
        "Issue Classification: ",
        &summary
            .issue_classification
            .iter()
            .map(|v| format!("{v:?}"))
            .collect::<Vec<_>>()
            .join(", "),
    ));
    lines.push(String::new());
    push_findings(&mut lines, "Primary Findings", &summary.primary_findings);
    push_items(&mut lines, "Top Signals", &summary.top_signals);
    push_items(&mut lines, "Policy Reasons", &summary.policy_reason_summary);
    push_items(&mut lines, "Response Codes", &summary.response_code_summary);
    push_items(
        &mut lines,
        "Zero-Response Destinations",
        &summary.zero_response_destinations,
    );
    push_items(
        &mut lines,
        "TLS/Certificate Indicators",
        &summary.tls_or_certificate_indicators,
    );
    push_items(&mut lines, "Geo Indicators", &summary.geo_indicators);
    push_items(&mut lines, "Threat Indicators", &summary.threat_indicators);
    if !summary.recommended_next_checks.is_empty() {
        lines.push("Recommended Next Checks".to_string());
        for item in &summary.recommended_next_checks {
            lines.extend(wrap_prefixed(" - ", item));
        }
        lines.push(String::new());
    }
    if !summary.missing_inputs.is_empty() {
        lines.extend(wrap_prefixed(
            "Missing Inputs: ",
            &summary.missing_inputs.join(", "),
        ));
        lines.push(String::new());
    }
    push_incident_overview(&mut lines, &incident_rows);
    push_incident_transactions(&mut lines, &incident_rows);

    let pages = paginate_lines(&lines);
    Ok(build_pdf_from_pages(&pages))
}

#[derive(Debug, Clone)]
struct IncidentTransaction {
    time: String,
    user: String,
    action: String,
    response_code: String,
    reason: String,
    destination_ip: String,
    url: String,
    device: String,
    department: String,
    threat: String,
    category: String,
    rule_label: String,
}

fn push_findings(lines: &mut Vec<String>, title: &str, items: &[SupportFinding]) {
    if items.is_empty() {
        return;
    }
    lines.push(title.to_string());
    for item in items.iter().take(8) {
        lines.extend(wrap_prefixed(
            " - ",
            &format!(
                "{} [{}] ({}): {}",
                item.title,
                item.severity.to_uppercase(),
                item.count,
                item.summary
            ),
        ));
        if !item.examples.is_empty() {
            lines.extend(wrap_prefixed("   Examples: ", &item.examples.join(", ")));
        }
    }
    lines.push(String::new());
}

fn push_items(lines: &mut Vec<String>, title: &str, items: &[SupportSummaryItem]) {
    if items.is_empty() {
        return;
    }
    lines.push(title.to_string());
    for item in items.iter().take(10) {
        let mut text = format!(" - {} ({})", item.value, item.count);
        if let Some(severity) = item.severity.as_deref() {
            text.push_str(&format!(" [{}]", severity.to_uppercase()));
        }
        if let Some(hint) = item.hint.as_deref()
            && !hint.trim().is_empty()
        {
            text.push_str(": ");
            text.push_str(hint);
        }
        lines.extend(wrap_prefixed("", &text));
    }
    lines.push(String::new());
}

fn push_incident_overview(lines: &mut Vec<String>, incidents: &[IncidentTransaction]) {
    lines.push("Incident Traffic Coverage".to_string());
    lines.push(format!(
        " - Relevant incident transactions captured in this report: {}",
        incidents.len()
    ));
    if incidents.is_empty() {
        lines.push(
            " - No non-allowed policy reason transactions were present in the returned search rows."
                .to_string(),
        );
        lines.push(String::new());
        return;
    }

    let mut top_reasons = std::collections::BTreeMap::new();
    let mut top_codes = std::collections::BTreeMap::new();
    let mut top_destinations = std::collections::BTreeMap::new();
    for incident in incidents {
        *top_reasons.entry(incident.reason.clone()).or_insert(0usize) += 1;
        *top_codes
            .entry(incident.response_code.clone())
            .or_insert(0usize) += 1;
        *top_destinations
            .entry(incident.destination_ip.clone())
            .or_insert(0usize) += 1;
    }

    lines.extend(wrap_prefixed(
        " - Dominant reasons: ",
        &format_top_counts(&top_reasons, 5),
    ));
    lines.extend(wrap_prefixed(
        " - Response codes: ",
        &format_top_counts(&top_codes, 5),
    ));
    lines.extend(wrap_prefixed(
        " - Top destinations: ",
        &format_top_counts(&top_destinations, 5),
    ));
    lines.push(String::new());
}

fn push_incident_transactions(lines: &mut Vec<String>, incidents: &[IncidentTransaction]) {
    if incidents.is_empty() {
        return;
    }
    lines.push("Relevant Incident Transactions".to_string());
    for (idx, incident) in incidents.iter().enumerate() {
        lines.extend(wrap_prefixed(
            "",
            &format!(
                "{}. {} | user={} | action={} | respcode={} | sip={}",
                idx + 1,
                incident.time,
                incident.user,
                incident.action,
                incident.response_code,
                incident.destination_ip
            ),
        ));
        lines.extend(wrap_prefixed("   Reason: ", &incident.reason));
        if !incident.url.is_empty() && incident.url != "None" {
            lines.extend(wrap_prefixed("   URL: ", &incident.url));
        }
        let mut context = Vec::new();
        if !incident.device.is_empty() && incident.device != "None" {
            context.push(format!("device={}", incident.device));
        }
        if !incident.department.is_empty() && incident.department != "None" {
            context.push(format!("department={}", incident.department));
        }
        if !incident.category.is_empty() && incident.category != "None" {
            context.push(format!("category={}", incident.category));
        }
        if !incident.rule_label.is_empty() && incident.rule_label != "None" {
            context.push(format!("rule={}", incident.rule_label));
        }
        if !incident.threat.is_empty() && incident.threat != "None" && incident.threat != "N/A" {
            context.push(format!("threat={}", incident.threat));
        }
        if !context.is_empty() {
            lines.extend(wrap_prefixed("   Context: ", &context.join(" | ")));
        }
        lines.push(String::new());
    }
}

fn collect_incident_rows(
    search_result: &SearchResponse,
    fields: &FieldMap,
) -> Vec<IncidentTransaction> {
    search_result
        .rows
        .iter()
        .filter_map(|row| incident_transaction_from_row(row, fields))
        .collect()
}

fn incident_transaction_from_row(
    row: &Map<String, Value>,
    fields: &FieldMap,
) -> Option<IncidentTransaction> {
    let reason = row_value(
        row,
        &[fields.reason_field.as_str(), "reason", "policy_reason"],
    );
    if !is_relevant_reason(&reason) {
        return None;
    }

    Some(IncidentTransaction {
        time: row_value(row, &[fields.time_field.as_str(), "time"]),
        user: row_value(row, &[fields.user_field.as_str(), "login", "user"]),
        action: row_value(row, &[fields.action_field.as_str(), "action"]),
        response_code: row_value(
            row,
            &[
                fields.response_code_field.as_str(),
                "respcode",
                "response_code",
            ],
        ),
        reason,
        destination_ip: row_value(row, &[fields.server_ip_field.as_str(), "sip", "server_ip"]),
        url: row_value(row, &[fields.url_field.as_str(), "url", "host"]),
        device: row_value(
            row,
            &[fields.device_field.as_str(), "device", "devicehostname"],
        ),
        department: row_value(
            row,
            &[fields.department_field.as_str(), "department", "dept"],
        ),
        threat: row_value(row, &[fields.threat_field.as_str(), "threat", "threatname"]),
        category: row_value(row, &[fields.category_field.as_str(), "category", "urlcat"]),
        rule_label: row_value(row, &["rulelabel", "urlfilterrulelabel"]),
    })
}

fn row_value(row: &Map<String, Value>, candidates: &[&str]) -> String {
    for candidate in candidates {
        if let Some(value) = row.get(*candidate) {
            return json_value_to_string(value);
        }
        if let Some((_, value)) = row
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(candidate))
        {
            return json_value_to_string(value);
        }
    }
    String::new()
}

fn json_value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        Value::Bool(v) => v.to_string(),
        other => other.to_string(),
    }
}

fn is_relevant_reason(reason: &str) -> bool {
    let normalized = reason.trim();
    if normalized.is_empty() {
        return false;
    }
    !matches!(
        normalized.to_ascii_lowercase().as_str(),
        "allowed" | "none" | "n/a"
    )
}

fn format_top_counts(counts: &std::collections::BTreeMap<String, usize>, limit: usize) -> String {
    let mut rows = counts
        .iter()
        .map(|(value, count)| (value.clone(), *count))
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if rows.is_empty() {
        return "none".to_string();
    }
    rows.into_iter()
        .take(limit)
        .map(|(value, count)| format!("{value} ({count})"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn wrap_prefixed(prefix: &str, text: &str) -> Vec<String> {
    let normalized = sanitize_ascii(text);
    let max_first = MAX_CHARS_PER_LINE
        .saturating_sub(prefix.chars().count())
        .max(16);
    let chunks = wrap_text(&normalized, max_first);
    if chunks.is_empty() {
        return vec![prefix.to_string()];
    }
    let mut out = Vec::with_capacity(chunks.len());
    for (idx, chunk) in chunks.into_iter().enumerate() {
        if idx == 0 {
            out.push(format!("{prefix}{chunk}"));
        } else {
            out.push(format!("{}{}", " ".repeat(prefix.chars().count()), chunk));
        }
    }
    out
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            if word.chars().count() <= max_chars {
                current.push_str(word);
            } else {
                for chunk in split_hard(word, max_chars) {
                    out.push(chunk);
                }
            }
            continue;
        }
        let next_len = current.chars().count() + 1 + word.chars().count();
        if next_len <= max_chars {
            current.push(' ');
            current.push_str(word);
        } else {
            out.push(std::mem::take(&mut current));
            if word.chars().count() <= max_chars {
                current = word.to_string();
            } else {
                let hard = split_hard(word, max_chars);
                if let Some((last, rest)) = hard.split_last() {
                    out.extend(rest.iter().cloned());
                    current = last.clone();
                } else {
                    current.clear();
                }
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn split_hard(text: &str, max_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        current.push(ch);
        if current.chars().count() >= max_chars {
            out.push(current);
            current = String::new();
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn paginate_lines(lines: &[String]) -> Vec<Vec<String>> {
    let mut pages = Vec::new();
    let mut idx = 0;
    while idx < lines.len() {
        let end = (idx + LINES_PER_PAGE).min(lines.len());
        pages.push(lines[idx..end].to_vec());
        idx = end;
    }
    if pages.is_empty() {
        pages.push(vec!["NSS Quarry - Search Summary".to_string()]);
    }
    pages
}

fn build_pdf_from_pages(pages: &[Vec<String>]) -> Vec<u8> {
    let page_count = pages.len().max(1);
    let font_id = 3 + (page_count as u32) * 2;
    let max_id = font_id;

    let mut objects: Vec<Vec<u8>> = vec![Vec::new(); (max_id + 1) as usize];
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>".to_vec();

    let kids = (0..page_count)
        .map(|i| format!("{} 0 R", 3 + (i as u32) * 2))
        .collect::<Vec<_>>()
        .join(" ");
    objects[2] = format!("<< /Type /Pages /Kids [{kids}] /Count {page_count} >>").into_bytes();

    for (idx, page_lines) in pages.iter().enumerate() {
        let page_obj_id = 3 + (idx as u32) * 2;
        let content_obj_id = page_obj_id + 1;
        let stream = build_page_stream(page_lines);
        objects[content_obj_id as usize] = format!(
            "<< /Length {} >>\nstream\n{}endstream",
            stream.len(),
            String::from_utf8_lossy(&stream)
        )
        .into_bytes();
        objects[page_obj_id as usize] = format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_obj_id} 0 R >>"
        )
        .into_bytes();
    }

    objects[font_id as usize] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec();

    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = vec![0usize; (max_id + 1) as usize];
    for obj_id in 1..=max_id {
        offsets[obj_id as usize] = out.len();
        out.extend_from_slice(format!("{obj_id} 0 obj\n").as_bytes());
        out.extend_from_slice(&objects[obj_id as usize]);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref_pos = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", max_id + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for obj_id in 1..=max_id {
        out.extend_from_slice(format!("{:010} 00000 n \n", offsets[obj_id as usize]).as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\n", max_id + 1).as_bytes());
    out.extend_from_slice(format!("startxref\n{xref_pos}\n%%EOF\n").as_bytes());
    out
}

fn build_page_stream(lines: &[String]) -> Vec<u8> {
    let mut content = String::new();
    content.push_str("BT\n/F1 11 Tf\n");
    content.push_str(&format!("{LINE_HEIGHT} TL\n"));
    content.push_str(&format!("{LEFT_MARGIN} {TOP_MARGIN} Td\n"));
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 {
            content.push_str("T*\n");
        }
        content.push('(');
        content.push_str(&escape_pdf_text(line));
        content.push_str(") Tj\n");
    }
    content.push_str("ET\n");
    content.into_bytes()
}

fn escape_pdf_text(input: &str) -> String {
    let mut out = String::new();
    for ch in sanitize_ascii(input).chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            c if c.is_ascii_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn sanitize_ascii(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_ascii() { c } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FieldMap;
    use crate::models::{SearchResponse, SupportClassification};
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn creates_valid_pdf_header_and_eof() {
        let summary = SupportSummaryResponse {
            generated_at: Utc::now(),
            time_from: Utc::now(),
            time_to: Utc::now(),
            row_count: 12,
            truncated: false,
            pcap_assisted: true,
            overview: "Example summary.".to_string(),
            issue_classification: vec![SupportClassification::PolicyBlock],
            primary_findings: vec![],
            top_signals: vec![],
            recommended_next_checks: vec![],
            missing_inputs: vec![],
            response_code_summary: vec![],
            policy_reason_summary: vec![],
            zero_response_destinations: vec![],
            tls_or_certificate_indicators: vec![],
            geo_indicators: vec![],
            threat_indicators: vec![],
        };
        let search_result = SearchResponse {
            rows: vec![],
            row_count: 0,
            truncated: false,
            page: 1,
            page_size: 200,
            has_more: false,
        };
        let bytes =
            build_support_summary_pdf(&summary, &search_result, &FieldMap::default(), "tester")
                .expect("pdf");
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn includes_only_non_allowed_transactions_in_incident_section() {
        let summary = SupportSummaryResponse {
            generated_at: Utc::now(),
            time_from: Utc::now(),
            time_to: Utc::now(),
            row_count: 2,
            truncated: false,
            pcap_assisted: false,
            overview: "Example summary.".to_string(),
            issue_classification: vec![SupportClassification::PolicyBlock],
            primary_findings: vec![],
            top_signals: vec![],
            recommended_next_checks: vec![],
            missing_inputs: vec![],
            response_code_summary: vec![],
            policy_reason_summary: vec![],
            zero_response_destinations: vec![],
            tls_or_certificate_indicators: vec![],
            geo_indicators: vec![],
            threat_indicators: vec![],
        };
        let search_result = SearchResponse {
            rows: vec![
                serde_json::Map::from_iter([
                    ("time".to_string(), json!("2026-04-05T17:00:00Z")),
                    ("login".to_string(), json!("user1@corp.example")),
                    ("action".to_string(), json!("Allowed")),
                    ("respcode".to_string(), json!("200")),
                    ("reason".to_string(), json!("Allowed")),
                    ("sip".to_string(), json!("1.1.1.1")),
                    ("url".to_string(), json!("allowed.example")),
                ]),
                serde_json::Map::from_iter([
                    ("time".to_string(), json!("2026-04-05T17:01:00Z")),
                    ("login".to_string(), json!("user2@corp.example")),
                    ("action".to_string(), json!("Blocked")),
                    ("respcode".to_string(), json!("403")),
                    (
                        "reason".to_string(),
                        json!("Not allowed to browse this category"),
                    ),
                    ("sip".to_string(), json!("8.8.8.8")),
                    ("url".to_string(), json!("blocked.example")),
                ]),
            ],
            row_count: 2,
            truncated: false,
            page: 1,
            page_size: 200,
            has_more: false,
        };
        let bytes =
            build_support_summary_pdf(&summary, &search_result, &FieldMap::default(), "tester")
                .expect("pdf");
        let rendered = String::from_utf8_lossy(&bytes);
        assert!(rendered.contains("Relevant Incident Transactions"));
        assert!(rendered.contains("Not allowed to browse this category"));
        assert!(!rendered.contains("allowed.example"));
    }
}
