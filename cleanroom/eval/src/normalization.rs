use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::evaluate::EvaluationReport;

const LATENCY_OPERATIONS: &[&str] = &["tools/list", "memory/recall", "memory/stats"];

const EXACT_RULES: &[(&str, &str, &str)] = &[
    (
        "iso.mock-daemon-raii-cleanup",
        "/pid",
        "positive-process-id",
    ),
    (
        "legacy.transcript-start",
        "/response/result/content/0/text",
        "ulid-in-text",
    ),
    ("legacy.transcript-start", "/text", "ulid-in-text"),
    (
        "legacy.transcript-record-all-roles",
        "/response/result/content/0/text",
        "ulid-in-text",
    ),
    (
        "legacy.transcript-record-all-roles",
        "/text",
        "ulid-in-text",
    ),
    (
        "legacy.feedback-record",
        "/response/result/content/0/text",
        "ulid-in-text",
    ),
    ("legacy.feedback-record", "/text", "ulid-in-text"),
    (
        "modern.structured-transcript-start",
        "/response/result/structuredContent/sessionId",
        "ulid",
    ),
    (
        "modern.structured-transcript-start",
        "/response/result/content/0/text",
        "ulid-in-text",
    ),
    (
        "modern.structured-transcript-record",
        "/response/result/structuredContent/messageId",
        "ulid",
    ),
    (
        "modern.structured-transcript-record",
        "/response/result/content/0/text",
        "ulid-in-text",
    ),
    (
        "modern.structured-feedback-record",
        "/response/result/structuredContent/id",
        "ulid",
    ),
    (
        "modern.structured-feedback-record",
        "/response/result/content/0/text",
        "ulid-in-text",
    ),
    (
        "modern.structured-feedback-record",
        "/response/result/structuredContent/createdAt",
        "rfc3339",
    ),
    (
        "modern.structured-memory-recall",
        "/response/result/structuredContent/memories/0/lastAccessed",
        "rfc3339",
    ),
    (
        "modern.concise-text-no-duplication",
        "/response/result/structuredContent/memories/0/lastAccessed",
        "rfc3339",
    ),
    (
        "modern.2025-06-structured-recall",
        "/response/result/structuredContent/memories/0/lastAccessed",
        "rfc3339",
    ),
    (
        "modern.2025-11-structured-recall",
        "/response/result/structuredContent/memories/0/lastAccessed",
        "rfc3339",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/0/result/structuredContent/memories/0/lastAccessed",
        "rfc3339",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/3/result/structuredContent/sessionId",
        "ulid",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/4/result/structuredContent/messageId",
        "ulid",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/5/result/structuredContent/hits/0/session/updatedAt",
        "rfc3339",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/6/result/structuredContent/session/updatedAt",
        "rfc3339",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/6/result/structuredContent/messages/4/id",
        "ulid",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/6/result/structuredContent/messages/4/timestamp",
        "rfc3339",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/7/result/structuredContent/newest",
        "rfc3339",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/8/result/structuredContent/id",
        "ulid",
    ),
    (
        "modern.schema-valid-real-emissions",
        "/responses/8/result/structuredContent/createdAt",
        "rfc3339",
    ),
];

const PREFIX_RULES: &[(&str, &str, &str)] = &[
    ("provider.", "/scopes/0/serverId", "server-id-or-null"),
    ("provider.", "/scopes/1/serverId", "server-id-or-null"),
    ("provider.", "/scopes/0/manifestSha256", "sha256-or-null"),
    ("provider.", "/scopes/1/manifestSha256", "sha256-or-null"),
    ("proxy.real-daemon-", "/proxyPid", "positive-process-id"),
    ("proxy.real-daemon-", "/daemonPid", "positive-process-id"),
];

pub fn normalize_report(report: &EvaluationReport) -> Result<Vec<u8>> {
    let mut design = report.design.clone();
    // The design binds the baseline receipt, so its own hash cannot bind that receipt's report.
    design.contract_hashes.remove("preregistered-design.json");
    let scenarios: Vec<_> = report
        .scenarios
        .iter()
        .map(|scenario| {
            Ok(json!({
                "id": scenario.id,
                "status": scenario.status,
                "detail": normalize_detail(&scenario.id, scenario.detail.clone())?
            }))
        })
        .collect::<Result<_>>()?;
    serde_json::to_vec(&json!({
        "reportVersion": report.report_version,
        "mode": report.mode,
        "candidateSha256": report.candidate_sha256,
        "design": design,
        "scenarios": scenarios,
        "payloadSizes": report.metrics.payload_sizes,
        "retrieval": report.metrics.retrieval,
        "statusCounts": report.status_counts,
        "portableAcceptance": report.portable_acceptance,
        "legacyObservation": report.legacy_observation
    }))
    .map_err(Into::into)
}

pub fn normalize_detail(scenario: &str, mut detail: Value) -> Result<Value> {
    let mut dynamic_values = BTreeMap::<String, String>::new();
    for (rule_scenario, pointer, kind) in EXACT_RULES {
        if scenario == *rule_scenario {
            normalize_pointer(&mut detail, pointer, kind, &mut dynamic_values)?;
        }
    }
    for (prefix, pointer, kind) in PREFIX_RULES {
        if scenario.starts_with(prefix) {
            normalize_pointer(&mut detail, pointer, kind, &mut dynamic_values)?;
        }
    }
    if scenario == "metrics.latency-five-blocks" {
        for operation in LATENCY_OPERATIONS {
            let escaped = operation.replace('~', "~0").replace('/', "~1");
            for (field, kind) in [
                ("blockMediansMicros", "latency-array"),
                ("medianMicros", "latency"),
                ("p95Micros", "latency"),
            ] {
                normalize_pointer(
                    &mut detail,
                    &format!("/{escaped}/{field}"),
                    kind,
                    &mut dynamic_values,
                )?;
            }
        }
    }
    Ok(detail)
}

pub fn verify_contract(path: &Path) -> Result<()> {
    let contract: Value = serde_json::from_slice(&fs::read(path)?)?;
    let rules = contract
        .get("rules")
        .and_then(Value::as_array)
        .context("normalization rules missing")?;
    for (scenario, pointer, kind) in EXACT_RULES {
        let found = rules.iter().any(|rule| {
            rule.get("scenario").and_then(Value::as_str) == Some(*scenario)
                && rule.get("pointer").and_then(Value::as_str) == Some(*pointer)
                && rule.get("kind").and_then(Value::as_str) == Some(*kind)
        });
        if !found {
            anyhow::bail!("normalization contract lacks exact rule {scenario} {pointer} {kind}");
        }
    }
    for (prefix, pointer, kind) in PREFIX_RULES {
        let found = rules.iter().any(|rule| {
            rule.get("scenarioPrefix").and_then(Value::as_str) == Some(*prefix)
                && rule.get("pointer").and_then(Value::as_str) == Some(*pointer)
                && rule.get("kind").and_then(Value::as_str) == Some(*kind)
        });
        if !found {
            anyhow::bail!("normalization contract lacks prefix rule {prefix} {pointer} {kind}");
        }
    }
    let operations = contract
        .get("latencyOperations")
        .and_then(Value::as_array)
        .context("normalization latency operations missing")?;
    let expected: Vec<Value> = LATENCY_OPERATIONS
        .iter()
        .map(|value| Value::String((*value).to_owned()))
        .collect();
    if operations != &expected
        || contract.get("default").and_then(Value::as_str) != Some("preserve")
        || contract.get("shapeChangesAllowed").and_then(Value::as_bool) != Some(false)
        || contract
            .get("recursiveKeyMatchingAllowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        anyhow::bail!("normalization contract and executable pointer allowlist differ");
    }
    Ok(())
}

fn normalize_pointer(
    detail: &mut Value,
    pointer: &str,
    kind: &str,
    dynamic_values: &mut BTreeMap<String, String>,
) -> Result<()> {
    let Some(value) = detail.pointer_mut(pointer) else {
        return Ok(());
    };
    match kind {
        "positive-process-id" => {
            if value.as_u64().is_none_or(|pid| pid == 0) {
                anyhow::bail!("{pointer}: expected positive process ID before normalization");
            }
            *value = Value::String("<PROCESS_ID>".to_owned());
        }
        "ulid" => {
            let raw = value
                .as_str()
                .with_context(|| format!("{pointer}: expected ULID string"))?;
            validate_ulid(raw).with_context(|| format!("{pointer}: invalid generated ULID"))?;
            let replacement = dynamic_replacement(dynamic_values, raw);
            *value = Value::String(replacement);
        }
        "ulid-in-text" => {
            let raw = value
                .as_str()
                .with_context(|| format!("{pointer}: expected text string"))?;
            *value = Value::String(replace_ulids(raw, dynamic_values)?);
        }
        "rfc3339" => {
            let raw = value
                .as_str()
                .with_context(|| format!("{pointer}: expected RFC3339 string"))?;
            chrono::DateTime::parse_from_rfc3339(raw)
                .with_context(|| format!("{pointer}: invalid RFC3339 value"))?;
            *value = Value::String("<PROVIDER_WRITTEN_AT>".to_owned());
        }
        "sha256" | "sha256-or-null" => {
            if kind == "sha256-or-null" && value.is_null() {
                return Ok(());
            }
            let hash = value
                .as_str()
                .with_context(|| format!("{pointer}: expected SHA-256 string"))?;
            if hash.len() != 64
                || !hash.chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
            {
                anyhow::bail!("{pointer}: malformed SHA-256 before normalization");
            }
            *value = Value::String("<SHA256>".to_owned());
        }
        "server-id" | "server-id-or-null" => {
            if kind == "server-id-or-null" && value.is_null() {
                return Ok(());
            }
            let server_id = value
                .as_str()
                .with_context(|| format!("{pointer}: expected server ID"))?;
            if server_id.is_empty()
                || !server_id
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
            {
                anyhow::bail!("{pointer}: invalid server ID before normalization");
            }
            *value = Value::String("<SERVER_ID>".to_owned());
        }
        "latency" => {
            if !value.is_u64() {
                anyhow::bail!("{pointer}: expected unsigned latency");
            }
            *value = Value::String("<LATENCY_MICROS>".to_owned());
        }
        "latency-array" => {
            let array = value
                .as_array()
                .with_context(|| format!("{pointer}: expected latency array"))?;
            if array.is_empty() || array.iter().any(|sample| !sample.is_u64()) {
                anyhow::bail!("{pointer}: latency array is empty or contains a non-unsigned value");
            }
            *value = Value::Array(
                array
                    .iter()
                    .map(|_| Value::String("<LATENCY_MICROS>".to_owned()))
                    .collect(),
            );
        }
        other => anyhow::bail!("unknown normalization kind {other}"),
    }
    Ok(())
}

fn replace_ulids(text: &str, dynamic_values: &mut BTreeMap<String, String>) -> Result<String> {
    let mut output = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if index + 26 <= bytes.len() {
            let candidate = &text[index..index + 26];
            if validate_ulid(candidate).is_ok() {
                output.push_str(&dynamic_replacement(dynamic_values, candidate));
                index += 26;
                continue;
            }
        }
        let character = text[index..]
            .chars()
            .next()
            .context("invalid UTF-8 character boundary")?;
        output.push(character);
        index += character.len_utf8();
    }
    if output == text {
        anyhow::bail!("expected generated ULID was absent at declared text pointer");
    }
    Ok(output)
}

fn dynamic_replacement(values: &mut BTreeMap<String, String>, raw: &str) -> String {
    if let Some(existing) = values.get(raw) {
        return existing.clone();
    }
    let replacement = format!("<DYNAMIC_ULID_{}>", values.len() + 1);
    values.insert(raw.to_owned(), replacement.clone());
    replacement
}

fn validate_ulid(value: &str) -> Result<()> {
    if value.len() != 26
        || !value.starts_with("01")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
    {
        anyhow::bail!("not a 26-character uppercase Crockford-style identifier");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_pointer_is_normalized() {
        let value = json!({"pid": 44, "nested": {"pid": 55}, "sibling": "keep"});
        let normalized = normalize_detail("iso.mock-daemon-raii-cleanup", value).unwrap();
        assert_eq!(normalized["pid"], "<PROCESS_ID>");
        assert_eq!(normalized.pointer("/nested/pid"), Some(&json!(55)));
        assert_eq!(normalized["sibling"], "keep");
    }

    #[test]
    fn undeclared_dynamic_key_and_shape_drift_survive() {
        let value = json!({"dynamic": 9, "writtenAt": "not-normalized", "items": [1, 2, 3]});
        assert_eq!(
            normalize_detail("other.scenario", value.clone()).unwrap(),
            value
        );
    }

    #[test]
    fn latency_keeps_sample_count_and_unknown_fields() {
        let value = json!({
            "tools/list": {
                "blockMediansMicros": [1, 2, 3, 4, 5],
                "medianMicros": 3,
                "p95Micros": 5,
                "sampleCount": 100,
                "median": 777
            }
        });
        let normalized = normalize_detail("metrics.latency-five-blocks", value).unwrap();
        assert_eq!(
            normalized.pointer("/tools~1list/sampleCount"),
            Some(&json!(100))
        );
        assert_eq!(normalized.pointer("/tools~1list/median"), Some(&json!(777)));
        assert_eq!(
            normalized.pointer("/tools~1list/blockMediansMicros/0"),
            Some(&json!("<LATENCY_MICROS>"))
        );
    }

    #[test]
    fn dynamic_ulid_mapping_is_consistent_across_declared_text_fields() {
        let id = "01JZZZZZZZZZZZZZZZZZZZZZZZ";
        let value = json!({
            "response": {"result": {"content": [{"text": format!("Feedback recorded: {id}")}]}},
            "text": format!("Feedback recorded: {id}")
        });
        let normalized = normalize_detail("legacy.feedback-record", value).unwrap();
        assert_eq!(
            normalized.pointer("/response/result/content/0/text"),
            normalized.pointer("/text")
        );
    }
}
