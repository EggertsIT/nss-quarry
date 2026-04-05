use anyhow::Result;

use crate::models::{SupportFinding, SupportSummaryItem, SupportSummaryResponse};

const PAGE_WIDTH: i32 = 595;
const PAGE_HEIGHT: i32 = 842;
const LEFT_MARGIN: i32 = 48;
const TOP_MARGIN: i32 = 804;
const LINE_HEIGHT: i32 = 14;
const MAX_CHARS_PER_LINE: usize = 96;
const LINES_PER_PAGE: usize = 52;

pub fn build_support_summary_pdf(
    summary: &SupportSummaryResponse,
    requested_by: &str,
) -> Result<Vec<u8>> {
    let mut lines = Vec::new();
    lines.push("NSS Quarry - Search Summary".to_string());
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
        "Rows: {} | Truncated: {} | PCAP-assisted: {}",
        summary.row_count,
        if summary.truncated { "yes" } else { "no" },
        if summary.pcap_assisted { "yes" } else { "no" }
    ));
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
    }

    let pages = paginate_lines(&lines);
    Ok(build_pdf_from_pages(&pages))
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
    use crate::models::SupportClassification;
    use chrono::Utc;

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
        let bytes = build_support_summary_pdf(&summary, "tester").expect("pdf");
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF\n"));
    }
}
