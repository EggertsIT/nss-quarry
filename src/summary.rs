use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use crate::config::FieldMap;
use crate::models::{
    SearchRequest, SearchResponse, SupportClassification, SupportFinding, SupportSummaryItem,
    SupportSummaryPcapContext, SupportSummaryResponse,
};

pub fn build_support_summary(
    req: &SearchRequest,
    result: &SearchResponse,
    pcap_context: Option<&SupportSummaryPcapContext>,
    fields: &FieldMap,
) -> SupportSummaryResponse {
    let rows = &result.rows;
    let action_col = find_column(rows, &[fields.action_field.as_str(), "action"]);
    let response_code_col = find_column(
        rows,
        &[
            fields.response_code_field.as_str(),
            "respcode",
            "response_code",
            "status_code",
        ],
    );
    let reason_col = find_column(
        rows,
        &[fields.reason_field.as_str(), "reason", "policy_reason"],
    );
    let threat_col = find_column(
        rows,
        &[fields.threat_field.as_str(), "threatname", "threat"],
    );
    let category_col = find_column(
        rows,
        &[fields.category_field.as_str(), "urlcat", "category"],
    );
    let server_ip_col = find_column(
        rows,
        &[fields.server_ip_field.as_str(), "sip", "destination_ip"],
    );
    let source_country_col = find_column_optional(
        rows,
        fields.source_country_field.as_deref(),
        &["srcip_country", "source_country"],
    );
    let destination_country_col = find_column_optional(
        rows,
        fields.destination_country_field.as_deref(),
        &["dstip_country", "destination_country"],
    );
    let respsize_col = find_column(rows, &["respsize", "response_size", "resp_size"]);
    let host_col = find_column(rows, &["host", "hostname"]);
    let rulelabel_col = find_column(rows, &["rulelabel", "urlfilterrulelabel", "apprulelabel"]);
    let ruletype_col = find_column(rows, &["ruletype"]);

    let mut missing_inputs = Vec::new();
    if response_code_col.is_none() {
        missing_inputs.push(fields.response_code_field.clone());
    }
    if reason_col.is_none() {
        missing_inputs.push(fields.reason_field.clone());
    }
    if respsize_col.is_none() {
        missing_inputs.push("respsize".to_string());
    }
    if threat_col.is_none() {
        missing_inputs.push(fields.threat_field.clone());
    }
    if source_country_col.is_none() {
        missing_inputs.push(
            fields
                .source_country_field
                .clone()
                .unwrap_or_else(|| "srcip_country".to_string()),
        );
    }
    if destination_country_col.is_none() {
        missing_inputs.push(
            fields
                .destination_country_field
                .clone()
                .unwrap_or_else(|| "dstip_country".to_string()),
        );
    }

    let response_code_summary = count_column(rows, response_code_col.as_deref(), false, 10)
        .into_iter()
        .map(|(value, count)| SupportSummaryItem {
            severity: Some(response_code_severity(&value).to_string()),
            hint: Some("Response code distribution".to_string()),
            value,
            count,
        })
        .collect::<Vec<_>>();

    let policy_reason_summary = count_column(rows, reason_col.as_deref(), true, 10)
        .into_iter()
        .map(|(value, count)| {
            let reason_hint = reason_hint_from_policy_reason(&value);
            SupportSummaryItem {
                value,
                count,
                hint: Some(reason_hint.hint.to_string()),
                severity: Some(reason_hint.severity.to_string()),
            }
        })
        .collect::<Vec<_>>();

    let zero_response_destinations = build_zero_response_destinations(
        rows,
        respsize_col.as_deref(),
        server_ip_col.as_deref(),
        host_col.as_deref(),
        Some(fields.url_field.as_str()),
        10,
    );

    let tls_or_certificate_indicators = policy_reason_summary
        .iter()
        .filter(|item| is_tls_reason(&item.value))
        .cloned()
        .collect::<Vec<_>>();

    let geo_indicators = build_geo_indicators(
        rows,
        reason_col.as_deref(),
        source_country_col.as_deref(),
        destination_country_col.as_deref(),
        10,
    );

    let threat_indicators =
        build_threat_indicators(rows, threat_col.as_deref(), reason_col.as_deref(), 10);

    let classifications = classify_rows(
        rows,
        action_col.as_deref(),
        response_code_col.as_deref(),
        reason_col.as_deref(),
        threat_col.as_deref(),
        category_col.as_deref(),
    );

    let top_signals = build_top_signals(
        &policy_reason_summary,
        &response_code_summary,
        &zero_response_destinations,
        &tls_or_certificate_indicators,
        &geo_indicators,
        &threat_indicators,
    );

    let primary_findings = build_primary_findings(FindingInputs {
        policy_reason_summary: &policy_reason_summary,
        zero_response_destinations: &zero_response_destinations,
        tls_indicators: &tls_or_certificate_indicators,
        geo_indicators: &geo_indicators,
        threat_indicators: &threat_indicators,
        rulelabel_col: rulelabel_col.as_deref(),
        ruletype_col: ruletype_col.as_deref(),
        rows,
    });

    let recommended_next_checks = build_recommended_checks(
        &classifications,
        result.truncated,
        pcap_context.is_some(),
        &missing_inputs,
    );

    let overview = build_overview(OverviewInputs {
        time_from: req.time_from,
        time_to: req.time_to,
        row_count: result.row_count,
        truncated: result.truncated,
        pcap_assisted: pcap_context.is_some(),
        primary_classification: classifications.first().copied(),
        top_reason: policy_reason_summary.first(),
        top_response: response_code_summary.first(),
        top_threat: threat_indicators.first(),
        missing_inputs: &missing_inputs,
    });

    SupportSummaryResponse {
        generated_at: Utc::now(),
        time_from: req.time_from,
        time_to: req.time_to,
        row_count: result.row_count,
        truncated: result.truncated,
        pcap_assisted: pcap_context.is_some(),
        overview,
        issue_classification: classifications,
        primary_findings,
        top_signals,
        recommended_next_checks,
        missing_inputs,
        response_code_summary,
        policy_reason_summary,
        zero_response_destinations,
        tls_or_certificate_indicators,
        geo_indicators,
        threat_indicators,
    }
}

fn build_overview(inputs: OverviewInputs<'_>) -> String {
    let mut parts = vec![format!(
        "Analyzed {row_count} row(s) from {} to {} UTC.",
        inputs.time_from.format("%Y-%m-%d %H:%M:%S"),
        inputs.time_to.format("%Y-%m-%d %H:%M:%S"),
        row_count = inputs.row_count
    )];
    if inputs.pcap_assisted {
        parts.push("PCAP-assisted search context was applied.".to_string());
    }
    if let Some(classification) = inputs.primary_classification {
        parts.push(format!(
            "Primary classification: {}.",
            display_classification(classification)
        ));
    }
    if let Some(item) = inputs.top_threat {
        parts.push(format!(
            "Top threat indicator: {} ({} row(s)).",
            item.value, item.count
        ));
    } else if let Some(item) = inputs.top_reason {
        parts.push(format!(
            "Top policy reason: {} ({} row(s)).",
            item.value, item.count
        ));
    } else if let Some(item) = inputs.top_response {
        parts.push(format!(
            "Top response code: {} ({} row(s)).",
            item.value, item.count
        ));
    }
    if inputs.truncated {
        parts.push(
            "The current result set hit the active search limit, so the summary reflects a bounded slice."
                .to_string(),
        );
    }
    if !inputs.missing_inputs.is_empty() {
        parts.push(format!(
            "Some summary inputs are unavailable in the current schema: {}.",
            inputs.missing_inputs.join(", ")
        ));
    }
    parts.join(" ")
}

fn build_primary_findings(inputs: FindingInputs<'_>) -> Vec<SupportFinding> {
    let mut findings = Vec::new();

    if let Some(item) = inputs.threat_indicators.first() {
        findings.push(SupportFinding {
            title: "Threat or reputation activity detected".to_string(),
            severity: item
                .severity
                .clone()
                .unwrap_or_else(|| "critical".to_string()),
            summary: format!(
                "Most common threat indicator is '{}' across {} row(s).",
                item.value, item.count
            ),
            count: item.count,
            examples: collect_examples(inputs.threat_indicators, 3),
        });
    }

    if let Some(item) = inputs.tls_indicators.first() {
        findings.push(SupportFinding {
            title: "SSL/TLS issues dominate the current window".to_string(),
            severity: item.severity.clone().unwrap_or_else(|| "high".to_string()),
            summary: format!(
                "The leading TLS/certificate signal is '{}' across {} row(s).",
                item.value, item.count
            ),
            count: item.count,
            examples: collect_examples(inputs.tls_indicators, 3),
        });
    }

    if let Some(item) = inputs.geo_indicators.first() {
        findings.push(SupportFinding {
            title: "Geo-related restriction or country signal observed".to_string(),
            severity: item.severity.clone().unwrap_or_else(|| "high".to_string()),
            summary: format!(
                "The strongest geo indicator is '{}' across {} row(s).",
                item.value, item.count
            ),
            count: item.count,
            examples: collect_examples(inputs.geo_indicators, 3),
        });
    }

    if let Some(item) = inputs.policy_reason_summary.first() {
        let policy_context =
            top_policy_context(inputs.rows, inputs.rulelabel_col, inputs.ruletype_col);
        findings.push(SupportFinding {
            title: "Dominant policy reason".to_string(),
            severity: item.severity.clone().unwrap_or_else(|| "medium".to_string()),
            summary: match policy_context {
                Some(context) => format!(
                    "'{}' is the main policy reason across {} row(s). Most common policy context: {}.",
                    item.value, item.count, context
                ),
                None => format!(
                    "'{}' is the main policy reason across {} row(s).",
                    item.value, item.count
                ),
            },
            count: item.count,
            examples: collect_examples(inputs.policy_reason_summary, 3),
        });
    }

    if let Some(item) = inputs.zero_response_destinations.first() {
        findings.push(SupportFinding {
            title: "Zero-response destinations observed".to_string(),
            severity: "medium".to_string(),
            summary: format!(
                "Destination '{}' appears with respsize=0 in {} row(s).",
                item.value, item.count
            ),
            count: item.count,
            examples: collect_examples(inputs.zero_response_destinations, 3),
        });
    }

    if findings.is_empty() {
        findings.push(SupportFinding {
            title: "No strong issue signature found".to_string(),
            severity: "info".to_string(),
            summary:
                "The current bounded result set does not contain a clear dominant failure pattern."
                    .to_string(),
            count: inputs.rows.len(),
            examples: Vec::new(),
        });
    }

    findings.truncate(4);
    findings
}

fn top_policy_context(
    rows: &[Map<String, Value>],
    rulelabel_col: Option<&str>,
    ruletype_col: Option<&str>,
) -> Option<String> {
    let mut counts = BTreeMap::new();
    for row in rows {
        let rulelabel = rulelabel_col
            .and_then(|col| row_value(row, col))
            .filter(|v| !is_none_like(v))
            .unwrap_or("None");
        let ruletype = ruletype_col
            .and_then(|col| row_value(row, col))
            .filter(|v| !is_none_like(v))
            .unwrap_or("None");
        if rulelabel == "None" && ruletype == "None" {
            continue;
        }
        let key = format!("{ruletype} / {rulelabel}");
        *counts.entry(key).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
        .map(|(key, _)| key)
}

fn build_top_signals(
    policy_reason_summary: &[SupportSummaryItem],
    response_code_summary: &[SupportSummaryItem],
    zero_response_destinations: &[SupportSummaryItem],
    tls_indicators: &[SupportSummaryItem],
    geo_indicators: &[SupportSummaryItem],
    threat_indicators: &[SupportSummaryItem],
) -> Vec<SupportSummaryItem> {
    let mut signals = Vec::new();
    if let Some(item) = threat_indicators.first() {
        signals.push(tag_signal(item, "Threat indicator"));
    }
    if let Some(item) = tls_indicators.first() {
        signals.push(tag_signal(item, "TLS indicator"));
    }
    if let Some(item) = policy_reason_summary.first() {
        signals.push(tag_signal(item, "Policy reason"));
    }
    if let Some(item) = response_code_summary.first() {
        signals.push(tag_signal(item, "Response code"));
    }
    if let Some(item) = zero_response_destinations.first() {
        signals.push(tag_signal(item, "Zero-response destination"));
    }
    if let Some(item) = geo_indicators.first() {
        signals.push(tag_signal(item, "Geo indicator"));
    }
    signals.truncate(5);
    signals
}

fn tag_signal(item: &SupportSummaryItem, label: &str) -> SupportSummaryItem {
    SupportSummaryItem {
        value: item.value.clone(),
        count: item.count,
        hint: Some(label.to_string()),
        severity: item.severity.clone(),
    }
}

fn build_recommended_checks(
    classifications: &[SupportClassification],
    truncated: bool,
    pcap_assisted: bool,
    missing_inputs: &[String],
) -> Vec<String> {
    let mut checks = Vec::new();
    for classification in classifications {
        match classification {
            SupportClassification::ThreatOrReputation => push_unique(
                &mut checks,
                "Treat this as a security event: review IOC context, endpoint ownership, and whether containment is required.",
            ),
            SupportClassification::SslTlsIssue => push_unique(
                &mut checks,
                "Verify certificate chain, OCSP result, TLS minimum version, and SSL inspection rule alignment.",
            ),
            SupportClassification::GeoIssue => push_unique(
                &mut checks,
                "Validate the destination/source country policy decision and confirm whether a business exception is expected.",
            ),
            SupportClassification::ConnectivityOrProbeFailure => push_unique(
                &mut checks,
                "Check service-edge reachability, DNS resolution, server path health, and config download status.",
            ),
            SupportClassification::PolicyBlock => push_unique(
                &mut checks,
                "Review rule type, rule label, URL/category, and whether the block is expected policy behavior.",
            ),
            SupportClassification::CloudAppOrFileControl => push_unique(
                &mut checks,
                "Review cloud app or file-control policy settings, upload/download posture, and exception workflow.",
            ),
            SupportClassification::InsufficientEvidence => push_unique(
                &mut checks,
                "Capture a narrower timeframe or increase signal quality before concluding root cause.",
            ),
        }
    }
    if truncated {
        push_unique(
            &mut checks,
            "Rerun with a higher limit or a narrower time window if you need a more complete sample.",
        );
    }
    if pcap_assisted {
        push_unique(
            &mut checks,
            "Compare the capture timeframe with the padded search window if expected destinations are still missing.",
        );
    }
    if !missing_inputs.is_empty() {
        push_unique(
            &mut checks,
            &format!(
                "The current feed/schema does not expose all summary inputs: {}.",
                missing_inputs.join(", ")
            ),
        );
    }
    if checks.is_empty() {
        checks.push("Review the top signals and raw log rows to determine whether this traffic is expected.".to_string());
    }
    checks
}

fn build_zero_response_destinations(
    rows: &[Map<String, Value>],
    respsize_col: Option<&str>,
    server_ip_col: Option<&str>,
    host_col: Option<&str>,
    url_col: Option<&str>,
    limit: usize,
) -> Vec<SupportSummaryItem> {
    let Some(respsize_col) = respsize_col else {
        return Vec::new();
    };
    let mut counts = BTreeMap::new();
    for row in rows {
        let Some(size_raw) = row_value(row, respsize_col) else {
            continue;
        };
        let Ok(size) = size_raw.trim().parse::<i64>() else {
            continue;
        };
        if size != 0 {
            continue;
        }
        let destination = server_ip_col
            .and_then(|col| row_value(row, col))
            .filter(|v| !is_none_like(v))
            .or_else(|| {
                host_col
                    .and_then(|col| row_value(row, col))
                    .filter(|v| !is_none_like(v))
            })
            .or_else(|| {
                url_col
                    .and_then(|col| row_value(row, col))
                    .filter(|v| !is_none_like(v))
            })
            .unwrap_or("Unknown destination");
        *counts.entry(destination.to_string()).or_insert(0usize) += 1;
    }
    top_items_from_counts(
        counts,
        limit,
        Some("Response payload size was zero".to_string()),
        Some("medium".to_string()),
    )
}

fn build_geo_indicators(
    rows: &[Map<String, Value>],
    reason_col: Option<&str>,
    source_country_col: Option<&str>,
    destination_country_col: Option<&str>,
    limit: usize,
) -> Vec<SupportSummaryItem> {
    let mut counts = BTreeMap::new();
    for row in rows {
        let reason = reason_col
            .and_then(|col| row_value(row, col))
            .unwrap_or_default()
            .to_string();
        if !is_geo_reason(&reason) {
            continue;
        }
        let src = source_country_col
            .and_then(|col| row_value(row, col))
            .filter(|v| !is_none_like(v))
            .unwrap_or("Unknown source");
        let dst = destination_country_col
            .and_then(|col| row_value(row, col))
            .filter(|v| !is_none_like(v))
            .unwrap_or("Unknown destination");
        let key = if src == "Unknown source" && dst == "Unknown destination" {
            reason.clone()
        } else {
            format!("{src} -> {dst}")
        };
        *counts.entry(key).or_insert(0usize) += 1;
    }
    top_items_from_counts(
        counts,
        limit,
        Some("Country-based restriction or geo signal".to_string()),
        Some("high".to_string()),
    )
}

fn build_threat_indicators(
    rows: &[Map<String, Value>],
    threat_col: Option<&str>,
    reason_col: Option<&str>,
    limit: usize,
) -> Vec<SupportSummaryItem> {
    let mut counts = BTreeMap::new();
    if let Some(threat_col) = threat_col {
        for row in rows {
            let Some(threat) = row_value(row, threat_col) else {
                continue;
            };
            if is_none_like(threat) {
                continue;
            }
            *counts.entry(threat.to_string()).or_insert(0usize) += 1;
        }
    }
    if counts.is_empty()
        && let Some(reason_col) = reason_col
    {
        for row in rows {
            let Some(reason) = row_value(row, reason_col) else {
                continue;
            };
            if !is_threat_reason(reason) {
                continue;
            }
            *counts.entry(reason.to_string()).or_insert(0usize) += 1;
        }
    }
    top_items_from_counts(
        counts,
        limit,
        Some("Threat or reputation signal".to_string()),
        Some("critical".to_string()),
    )
}

fn classify_rows(
    rows: &[Map<String, Value>],
    action_col: Option<&str>,
    response_code_col: Option<&str>,
    reason_col: Option<&str>,
    threat_col: Option<&str>,
    category_col: Option<&str>,
) -> Vec<SupportClassification> {
    let mut scores = BTreeMap::new();
    for row in rows {
        let action = action_col
            .and_then(|col| row_value(row, col))
            .unwrap_or_default()
            .to_string();
        let response_code = response_code_col
            .and_then(|col| row_value(row, col))
            .unwrap_or_default()
            .to_string();
        let reason = reason_col
            .and_then(|col| row_value(row, col))
            .unwrap_or_default()
            .to_string();
        let threat = threat_col
            .and_then(|col| row_value(row, col))
            .unwrap_or_default()
            .to_string();
        let category = category_col
            .and_then(|col| row_value(row, col))
            .unwrap_or_default()
            .to_string();

        if !is_none_like(&threat) || is_threat_reason(&reason) {
            bump(&mut scores, SupportClassification::ThreatOrReputation, 3);
        }
        if is_tls_reason(&reason) {
            bump(&mut scores, SupportClassification::SslTlsIssue, 3);
        }
        if is_geo_reason(&reason) {
            bump(&mut scores, SupportClassification::GeoIssue, 3);
        }
        if is_connectivity_reason(&reason)
            || matches!(response_code.as_str(), "502" | "503" | "504")
        {
            bump(
                &mut scores,
                SupportClassification::ConnectivityOrProbeFailure,
                2,
            );
        }
        if is_cloud_or_file_reason(&reason) || is_cloud_or_file_category(&category) {
            bump(&mut scores, SupportClassification::CloudAppOrFileControl, 2);
        }
        if action.eq_ignore_ascii_case("blocked")
            || matches!(response_code.as_str(), "403" | "407")
            || is_policy_block_reason(&reason)
        {
            bump(&mut scores, SupportClassification::PolicyBlock, 1);
        }
    }

    let mut out = scores.into_iter().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| classification_priority(a.0).cmp(&classification_priority(b.0)))
    });
    let mut classifications = out.into_iter().map(|(k, _)| k).collect::<Vec<_>>();
    if classifications.is_empty() {
        classifications.push(SupportClassification::InsufficientEvidence);
    }
    classifications
}

fn classification_priority(classification: SupportClassification) -> usize {
    match classification {
        SupportClassification::ThreatOrReputation => 0,
        SupportClassification::SslTlsIssue => 1,
        SupportClassification::GeoIssue => 2,
        SupportClassification::ConnectivityOrProbeFailure => 3,
        SupportClassification::PolicyBlock => 4,
        SupportClassification::CloudAppOrFileControl => 5,
        SupportClassification::InsufficientEvidence => 6,
    }
}

fn bump(
    scores: &mut BTreeMap<SupportClassification, usize>,
    key: SupportClassification,
    by: usize,
) {
    *scores.entry(key).or_insert(0usize) += by;
}

fn collect_examples(items: &[SupportSummaryItem], limit: usize) -> Vec<String> {
    items
        .iter()
        .take(limit)
        .map(|item| item.value.clone())
        .collect()
}

fn count_column(
    rows: &[Map<String, Value>],
    column: Option<&str>,
    exclude_none_like: bool,
    limit: usize,
) -> Vec<(String, usize)> {
    let Some(column) = column else {
        return Vec::new();
    };
    let mut counts = BTreeMap::new();
    for row in rows {
        let Some(value) = row_value(row, column) else {
            continue;
        };
        if exclude_none_like && is_none_like(value) {
            continue;
        }
        let normalized = value.trim();
        if normalized.is_empty() {
            continue;
        }
        *counts.entry(normalized.to_string()).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .collect::<Vec<_>>()
        .into_iter()
        .sorted_by_count_desc(limit)
}

trait CountVecExt {
    fn sorted_by_count_desc(self, limit: usize) -> Vec<(String, usize)>;
}

impl CountVecExt for std::vec::IntoIter<(String, usize)> {
    fn sorted_by_count_desc(self, limit: usize) -> Vec<(String, usize)> {
        let mut rows = self.collect::<Vec<_>>();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit);
        rows
    }
}

fn top_items_from_counts(
    counts: BTreeMap<String, usize>,
    limit: usize,
    hint: Option<String>,
    severity: Option<String>,
) -> Vec<SupportSummaryItem> {
    counts
        .into_iter()
        .collect::<Vec<_>>()
        .into_iter()
        .sorted_by_count_desc(limit)
        .into_iter()
        .map(|(value, count)| SupportSummaryItem {
            value,
            count,
            hint: hint.clone(),
            severity: severity.clone(),
        })
        .collect()
}

fn row_value<'a>(row: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn find_column(rows: &[Map<String, Value>], candidates: &[&str]) -> Option<String> {
    let first = rows.first()?;
    let available = first
        .keys()
        .map(|key| (key.to_ascii_lowercase(), key.as_str()))
        .collect::<BTreeMap<_, _>>();
    for candidate in candidates {
        let key = candidate.to_ascii_lowercase();
        if let Some(hit) = available.get(&key) {
            return Some((*hit).to_string());
        }
    }
    None
}

fn find_column_optional(
    rows: &[Map<String, Value>],
    mapped: Option<&str>,
    fallbacks: &[&str],
) -> Option<String> {
    let mut candidates = Vec::new();
    if let Some(mapped) = mapped {
        candidates.push(mapped);
    }
    candidates.extend(fallbacks.iter().copied());
    find_column(rows, &candidates)
}

fn reason_hint_from_policy_reason(reason: &str) -> ReasonHint {
    let lower = reason.to_ascii_lowercase();
    let allowed = lower.contains("allowed") || lower.contains("cautioned");
    let base = if allowed { "low" } else { "high" };

    if is_tls_reason(reason) {
        return ReasonHint {
            severity: if allowed { "medium" } else { "high" },
            hint: "Verify certificate chain, OCSP, TLS minimums, and SSL inspection rule alignment.",
        };
    }
    if lower.contains("domain fronting") {
        return ReasonHint {
            severity: "high",
            hint: "Compare URL, host header, and SNI to confirm expected application behavior.",
        };
    }
    if is_connectivity_reason(reason) {
        return ReasonHint {
            severity: "high",
            hint: "Check service-edge connectivity, DNS resolution, server reachability, and config download health.",
        };
    }
    if is_geo_reason(reason) {
        return ReasonHint {
            severity: if allowed { "medium" } else { "high" },
            hint: "Review source/destination country policy and whether the flow needs a business exception.",
        };
    }
    if is_threat_reason(reason) {
        return ReasonHint {
            severity: "critical",
            hint: "Treat as a threat-protection event and confirm endpoint/user containment requirements.",
        };
    }
    if lower.contains("dlp") || lower.contains("compliance") {
        return ReasonHint {
            severity: if allowed { "medium" } else { "high" },
            hint: "Validate the DLP/compliance rule, matched content, and required escalation path.",
        };
    }
    if lower.contains("time quota")
        || lower.contains("volume quota")
        || lower.contains("time of day")
    {
        return ReasonHint {
            severity: "medium",
            hint: "Check time or quota-based controls before treating this as a transport failure.",
        };
    }
    if is_cloud_or_file_reason(reason) {
        return ReasonHint {
            severity: if allowed { "medium" } else { "high" },
            hint: "Review cloud app or file-control policy settings and any approved exception path.",
        };
    }

    ReasonHint {
        severity: base,
        hint: "Review the rule label, rule type, destination, and action to decide whether this is expected policy behavior.",
    }
}

fn response_code_severity(code: &str) -> &'static str {
    match code.trim() {
        "403" => "high",
        "407" => "medium",
        c if c.starts_with('5') => "high",
        c if c.starts_with('4') => "medium",
        _ => "low",
    }
}

fn is_none_like(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "none" | "n/a" | "na" | "null"
    )
}

fn is_tls_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("bad server certificate")
        || lower.contains("low tls version")
        || lower.contains("ssl/tls")
        || lower.contains("ocsp")
        || lower.contains("handshake")
}

fn is_geo_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("country") || lower.contains("geo")
}

fn is_connectivity_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("server probe failure")
        || lower.contains("timed out while waiting for a config")
        || lower.contains("missing config")
        || lower.contains("internal error")
        || lower.contains("dnat")
        || lower.contains("firewall")
        || lower.contains("invalid server ip")
}

fn is_threat_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("sandbox")
        || lower.contains("malware")
        || lower.contains("phishing")
        || lower.contains("botnet")
        || lower.contains("ips block")
        || lower.contains("reputation block")
        || lower.contains("cryptomining")
}

fn is_policy_block_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("not allowed")
        || lower.contains("blocked")
        || lower.contains("denylist")
        || lower.contains("url filtering")
        || lower.contains("request method")
}

fn is_cloud_or_file_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("cloud app")
        || lower.contains("webmail")
        || lower.contains("social network")
        || lower.contains("consumer site")
        || lower.contains("tenant")
        || lower.contains("upload/download")
        || lower.contains("filetype")
        || lower.contains("file attachment")
        || lower.contains("file share")
}

fn is_cloud_or_file_category(category: &str) -> bool {
    let lower = category.to_ascii_lowercase();
    lower.contains("file")
        || lower.contains("streaming")
        || lower.contains("webmail")
        || lower.contains("instant messaging")
        || lower.contains("marketing")
}

fn display_classification(classification: SupportClassification) -> &'static str {
    match classification {
        SupportClassification::PolicyBlock => "policy block",
        SupportClassification::SslTlsIssue => "SSL/TLS issue",
        SupportClassification::GeoIssue => "geo issue",
        SupportClassification::ThreatOrReputation => "threat or reputation",
        SupportClassification::ConnectivityOrProbeFailure => "connectivity or probe failure",
        SupportClassification::CloudAppOrFileControl => "cloud app or file control",
        SupportClassification::InsufficientEvidence => "insufficient evidence",
    }
}

fn push_unique(items: &mut Vec<String>, value: &str) {
    if !items.iter().any(|item| item == value) {
        items.push(value.to_string());
    }
}

struct ReasonHint {
    severity: &'static str,
    hint: &'static str,
}

struct OverviewInputs<'a> {
    time_from: DateTime<Utc>,
    time_to: DateTime<Utc>,
    row_count: usize,
    truncated: bool,
    pcap_assisted: bool,
    primary_classification: Option<SupportClassification>,
    top_reason: Option<&'a SupportSummaryItem>,
    top_response: Option<&'a SupportSummaryItem>,
    top_threat: Option<&'a SupportSummaryItem>,
    missing_inputs: &'a [String],
}

struct FindingInputs<'a> {
    policy_reason_summary: &'a [SupportSummaryItem],
    zero_response_destinations: &'a [SupportSummaryItem],
    tls_indicators: &'a [SupportSummaryItem],
    geo_indicators: &'a [SupportSummaryItem],
    threat_indicators: &'a [SupportSummaryItem],
    rulelabel_col: Option<&'a str>,
    ruletype_col: Option<&'a str>,
    rows: &'a [Map<String, Value>],
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn row(entries: &[(&str, &str)]) -> Map<String, Value> {
        let mut map = Map::new();
        for (key, value) in entries {
            map.insert((*key).to_string(), json!(*value));
        }
        map
    }

    fn base_request() -> SearchRequest {
        SearchRequest {
            time_from: Utc.with_ymd_and_hms(2026, 4, 5, 10, 0, 0).unwrap(),
            time_to: Utc.with_ymd_and_hms(2026, 4, 5, 11, 0, 0).unwrap(),
            filters: Default::default(),
            limit: Some(200),
            columns: None,
        }
    }

    #[test]
    fn summary_classifies_tls_policy_block() {
        let response = SearchResponse {
            rows: vec![row(&[
                ("action", "Blocked"),
                ("respcode", "403"),
                ("reason", "Access denied due to bad server certificate"),
                ("sip", "1.1.1.1"),
            ])],
            row_count: 1,
            truncated: false,
        };
        let summary = build_support_summary(&base_request(), &response, None, &FieldMap::default());

        assert!(
            summary
                .issue_classification
                .contains(&SupportClassification::SslTlsIssue)
        );
        assert!(
            summary
                .issue_classification
                .contains(&SupportClassification::PolicyBlock)
        );
        assert_eq!(summary.tls_or_certificate_indicators.len(), 1);
    }

    #[test]
    fn summary_classifies_geo_issue() {
        let response = SearchResponse {
            rows: vec![row(&[
                (
                    "reason",
                    "Country block outbound request: not allowed to access sites in this country",
                ),
                ("srcip_country", "Germany"),
                ("dstip_country", "Russia"),
            ])],
            row_count: 1,
            truncated: false,
        };
        let summary = build_support_summary(&base_request(), &response, None, &FieldMap::default());

        assert!(
            summary
                .issue_classification
                .contains(&SupportClassification::GeoIssue)
        );
        assert_eq!(
            summary.geo_indicators.first().map(|v| v.value.as_str()),
            Some("Germany -> Russia")
        );
    }

    #[test]
    fn summary_reports_zero_response_destinations() {
        let response = SearchResponse {
            rows: vec![
                row(&[("respsize", "0"), ("sip", "8.8.8.8")]),
                row(&[("respsize", "0"), ("sip", "8.8.8.8")]),
            ],
            row_count: 2,
            truncated: false,
        };
        let summary = build_support_summary(&base_request(), &response, None, &FieldMap::default());

        assert_eq!(
            summary
                .zero_response_destinations
                .first()
                .map(|v| v.value.as_str()),
            Some("8.8.8.8")
        );
        assert_eq!(
            summary.zero_response_destinations.first().map(|v| v.count),
            Some(2)
        );
    }

    #[test]
    fn summary_defaults_to_insufficient_evidence() {
        let response = SearchResponse {
            rows: Vec::new(),
            row_count: 0,
            truncated: false,
        };
        let summary = build_support_summary(&base_request(), &response, None, &FieldMap::default());

        assert_eq!(
            summary.issue_classification,
            vec![SupportClassification::InsufficientEvidence]
        );
        assert!(summary.overview.contains("Analyzed 0 row(s)"));
    }
}
