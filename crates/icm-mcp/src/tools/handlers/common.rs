//! Shared parsing, policy, and rendering helpers for MCP tool handlers.

use serde_json::Value;

use icm_core::{Memoir, MemoirStore, Memory};
use icm_store::Store;

#[allow(unused_imports)]
pub use crate::memory::{
    AutoConsolidate, AUTO_CONSOLIDATE_THRESHOLD, MAX_CONTENT_LEN, MAX_TOPIC_LEN,
};
use crate::protocol::ToolResult;

/// `icm_feedback_record`'s context/predicted/corrected/reason had no length
/// cap at all, unlike icm_memory_store's MAX_CONTENT_LEN (audit finding).
pub const MAX_FEEDBACK_FIELD_LEN: usize = 20_000;

/// Parse a JSON keywords array from tool arguments.
pub fn parse_keywords(args: &Value) -> Vec<String> {
    args.get("keywords")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn get_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

pub fn get_i64(args: &Value, key: &str, default: i64) -> i64 {
    args.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
}

/// Flatten untrusted text before embedding it into line-oriented output.
pub fn flatten_untrusted_text(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

pub fn resolve_memoir(store: &Store, name: &str) -> Result<Memoir, ToolResult> {
    store
        .get_memoir_by_name(name)
        .map_err(|e| ToolResult::error(format!("db error: {e}")))?
        .ok_or_else(|| ToolResult::error(format!("memoir not found: {name}")))
}

pub fn format_memory_output(memories: &[(Memory, f32)], compact: bool) -> String {
    // Audit finding: `summary` has no newline/CR validation at the store
    // layer (only `topic` is checked — see `validate_fields`), and it can
    // be LLM/tool-extracted from untrusted content. Written verbatim, a
    // stored summary could forge a fake `--- <id> [score: ...] ---`
    // delimiter indistinguishable from a real entry, or (compact mode) a
    // fake `[topic] ...` line. `keywords` has no validation at all. Flatten
    // both, same fix already applied to recall_context/render_detail.
    let mut output = String::new();
    if compact {
        for (mem, _) in memories {
            output.push_str(&format!(
                "[{}] {}\n",
                mem.topic,
                flatten_untrusted_text(&mem.summary)
            ));
        }
    } else {
        for (mem, score) in memories {
            let summary = flatten_untrusted_text(&mem.summary);
            if *score >= 0.0 {
                output.push_str(&format!(
                    "--- {} [score: {:.3}] ---\n  topic: {}\n  importance: {}\n  weight: {:.3}\n  summary: {}\n",
                    mem.id, score, mem.topic, mem.importance, mem.weight, summary
                ));
            } else {
                output.push_str(&format!(
                    "--- {} ---\n  topic: {}\n  importance: {}\n  weight: {:.3}\n  summary: {}\n",
                    mem.id, mem.topic, mem.importance, mem.weight, summary
                ));
            }
            if !mem.keywords.is_empty() {
                let flattened_keywords: Vec<String> = mem
                    .keywords
                    .iter()
                    .map(|k| flatten_untrusted_text(k))
                    .collect();
                output.push_str(&format!("  keywords: {}\n", flattened_keywords.join(", ")));
            }
            if let Some(ref raw) = mem.raw_excerpt {
                // raw_excerpt can hold up to 64 KB per memory; dumping it in
                // full for every hit floods the client LLM's context (audit
                // finding). Cap the recall view — the full excerpt stays in
                // the store.
                let (excerpt, truncated) = crate::outputs::truncate_recall_raw(raw);
                if truncated {
                    output.push_str(&format!(
                        "  raw: {}… [truncated, {} bytes total]\n",
                        excerpt,
                        raw.len()
                    ));
                } else {
                    output.push_str(&format!("  raw: {raw}\n"));
                }
            }
            output.push('\n');
        }
    }
    output
}
