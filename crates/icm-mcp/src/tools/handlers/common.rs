//! Shared parsing, policy, and rendering helpers for MCP tool handlers.

use serde_json::Value;

use icm_core::{Embedder, Memoir, MemoirStore, Memory};
use icm_store::Store;

use crate::protocol::ToolResult;

/// Historical default threshold for auto-consolidation. The live value comes
/// from [`AutoConsolidate`] (issue #318); this constant is only the fallback
/// for callers that don't pass a policy.
pub const AUTO_CONSOLIDATE_THRESHOLD: usize = 10;

/// Auto-consolidation policy for the MCP store path (issue #318).
///
/// Previously the MCP `icm_memory_store` handler consolidated a topic past a
/// hardcoded 10 entries **unconditionally**, ignoring `[memory]
/// auto_consolidate_enabled` / `auto_consolidate_threshold` — so an explicit
/// `enabled = false` still destructively rolled up (and deleted) a topic's
/// memories. `icm serve` now threads the loaded config through as one of
/// these, and the handler honors it.
#[derive(Clone, Copy, Debug)]
pub struct AutoConsolidate {
    pub enabled: bool,
    pub threshold: usize,
}

impl Default for AutoConsolidate {
    /// The historical always-on behavior (threshold 10). Used only by callers
    /// that don't supply a policy — e.g. tests via [`call_tool`]. The
    /// `icm serve` path passes the user's real config through
    /// [`call_tool_with_config`] instead.
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: AUTO_CONSOLIDATE_THRESHOLD,
        }
    }
}

/// Maximum allowed UTF-8 byte length for topic names. Must stay <= the
/// store layer's `MAX_TOPIC_BYTES` so the MCP-level rejection happens
/// *before* the store's lower-level validation does.
pub const MAX_TOPIC_LEN: usize = 255;

/// Maximum allowed length for content/summary text. Aligned with the
/// store layer's `MAX_SUMMARY_BYTES` (64 KB). Letting MCP accept
/// larger inputs only to have the store reject them would be
/// confusing — fail fast at the API surface.
pub const MAX_CONTENT_LEN: usize = 64 * 1024;

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

/// Try to auto-consolidate a topic if the policy is enabled and the topic
/// exceeds the configured threshold (issue #318). Returns a human-readable
/// message if consolidation happened, or an empty string (including when the
/// policy is disabled — a no-op).
///
/// Routes through `auto_consolidate_with_embedder` so the consolidated
/// memory is embedded inline (closes audit M2/AC2: previously the
/// rolled-up memory had `embedding = None` and was invisible to hybrid
/// recall until a manual `icm embed` rebuilt it).
pub fn try_auto_consolidate(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    topic: &str,
    auto: AutoConsolidate,
) -> String {
    if !auto.enabled {
        return String::new();
    }
    match store.auto_consolidate_with_embedder(topic, auto.threshold, embedder) {
        Ok(true) => format!(
            "Auto-consolidated topic '{topic}' (exceeded {} entries).",
            auto.threshold
        ),
        Ok(false) => String::new(),
        Err(e) => {
            tracing::warn!("auto-consolidation failed for topic '{topic}': {e}");
            String::new()
        }
    }
}

pub fn get_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

pub fn get_i64(args: &Value, key: &str, default: i64) -> i64 {
    args.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
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
    let flatten = |s: &str| s.replace(['\n', '\r'], " ");
    let mut output = String::new();
    if compact {
        for (mem, _) in memories {
            output.push_str(&format!("[{}] {}\n", mem.topic, flatten(&mem.summary)));
        }
    } else {
        for (mem, score) in memories {
            let summary = flatten(&mem.summary);
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
                let flattened_keywords: Vec<String> =
                    mem.keywords.iter().map(|k| flatten(k)).collect();
                output.push_str(&format!("  keywords: {}\n", flattened_keywords.join(", ")));
            }
            if let Some(ref raw) = mem.raw_excerpt {
                // raw_excerpt can hold up to 64 KB per memory; dumping it in
                // full for every hit floods the client LLM's context (audit
                // finding). Cap the recall view — the full excerpt stays in
                // the store.
                const MAX_RAW_IN_RECALL: usize = 2048;
                if raw.len() > MAX_RAW_IN_RECALL {
                    let mut cut = MAX_RAW_IN_RECALL;
                    while !raw.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    output.push_str(&format!(
                        "  raw: {}… [truncated, {} bytes total]\n",
                        &raw[..cut],
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
