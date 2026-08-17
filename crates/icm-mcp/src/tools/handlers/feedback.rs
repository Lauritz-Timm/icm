//! MCP feedback tool handlers.

use serde_json::Value;

use icm_core::{Embedder, Feedback, FeedbackStore};
use icm_store::Store;

use crate::outputs::{FeedbackOutput, FeedbackSearchOutput, FeedbackStatsOutput};
use crate::protocol::ToolResult;

use super::common::{flatten_untrusted_text, get_i64, get_str, MAX_FEEDBACK_FIELD_LEN};

pub(in crate::tools) fn tool_feedback_record(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    args: &Value,
    compact: bool,
) -> ToolResult {
    let topic = match get_str(args, "topic") {
        Some(t) => t,
        None => return ToolResult::error("missing required field: topic".into()),
    };
    let context = match get_str(args, "context") {
        Some(c) => c,
        None => return ToolResult::error("missing required field: context".into()),
    };
    let predicted = match get_str(args, "predicted") {
        Some(p) => p,
        None => return ToolResult::error("missing required field: predicted".into()),
    };
    let corrected = match get_str(args, "corrected") {
        Some(c) => c,
        None => return ToolResult::error("missing required field: corrected".into()),
    };
    let reason = get_str(args, "reason").map(|s| s.to_string());
    let source = get_str(args, "source").unwrap_or("").to_string();

    for (field_name, field_value) in [
        ("context", context),
        ("predicted", predicted),
        ("corrected", corrected),
        ("reason", reason.as_deref().unwrap_or("")),
    ] {
        if field_value.len() > MAX_FEEDBACK_FIELD_LEN {
            return ToolResult::error(format!(
                "{field_name} exceeds maximum length ({} > {MAX_FEEDBACK_FIELD_LEN} UTF-8 bytes)",
                field_value.len()
            ));
        }
    }

    let mut feedback = Feedback::new(
        topic.into(),
        context.into(),
        predicted.into(),
        corrected.into(),
        reason,
        source,
    );
    // Manual-testing finding: feedback search had no semantic fallback at
    // all — pure FTS5 with implicit AND, so a query missing even one exact
    // token returned nothing. Attach an embedding here so search_feedback
    // can blend semantic similarity in, mirroring icm_memory_store.
    if let Some(emb) = embedder {
        if let Ok(v) = emb.embed(&feedback.embed_text()) {
            feedback.embedding = Some(v);
        }
    }

    let id = feedback.id.clone();
    let structured = FeedbackOutput::from(&feedback);
    match store.store_feedback(feedback) {
        Ok(_) => {
            let legacy = if compact {
                format!("ok {id}")
            } else {
                format!("Feedback recorded: {id}\n  topic: {topic}\n  predicted: {predicted}\n  corrected: {corrected}")
            };
            ToolResult::structured(legacy, "Feedback recorded.".into(), &structured)
        }
        Err(e) => ToolResult::error(format!("failed to store feedback: {e}")),
    }
}

pub(in crate::tools) fn tool_feedback_search(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    args: &Value,
) -> ToolResult {
    let query = match get_str(args, "query") {
        Some(q) => q,
        None => return ToolResult::error("missing required field: query".into()),
    };
    let topic = get_str(args, "topic");
    let limit = get_i64(args, "limit", 5).clamp(1, 100) as usize;
    let query_embedding = embedder.and_then(|emb| emb.embed_query(query).ok());

    match store.search_feedback(query, query_embedding.as_deref(), topic, limit) {
        Ok(results) => {
            let structured = FeedbackSearchOutput::new(&results);
            if results.is_empty() {
                return ToolResult::structured(
                    "No feedback found.".into(),
                    "Found 0 feedback entries.".into(),
                    &structured,
                );
            }
            // context/predicted/corrected/reason/source can originate from
            // untrusted content (a feedback entry recorded from tool output
            // the agent processed). Flatten embedded newlines so a stored
            // value can't forge a fake "--- id [topic] ---" delimiter and
            // inject a spoofed entry into this output (same injection class
            // already fixed in recall_context/build_consolidate_prompt).
            let mut output = String::new();
            for fb in &results {
                output.push_str(&format!(
                    "--- {} [{}] ---\n  context: {}\n  predicted: {}\n  corrected: {}\n",
                    fb.id,
                    flatten_untrusted_text(&fb.topic),
                    flatten_untrusted_text(&fb.context),
                    flatten_untrusted_text(&fb.predicted),
                    flatten_untrusted_text(&fb.corrected)
                ));
                if let Some(ref reason) = fb.reason {
                    output.push_str(&format!("  reason: {}\n", flatten_untrusted_text(reason)));
                }
                if !fb.source.is_empty() {
                    output.push_str(&format!(
                        "  source: {}\n",
                        flatten_untrusted_text(&fb.source)
                    ));
                }
                if fb.applied_count > 0 {
                    output.push_str(&format!("  applied: {} times\n", fb.applied_count));
                }
            }
            ToolResult::structured(
                output,
                format!("Found {} feedback entries.", structured.len()),
                &structured,
            )
        }
        Err(e) => ToolResult::error(format!("failed to search feedback: {e}")),
    }
}

pub(in crate::tools) fn tool_feedback_stats(store: &Store) -> ToolResult {
    match store.feedback_stats() {
        Ok(stats) => {
            let structured = FeedbackStatsOutput::from(stats.clone());
            let mut output = format!("Feedback total: {}\n", stats.total);
            if !stats.by_topic.is_empty() {
                output.push_str("\nBy topic:\n");
                for (topic, count) in &stats.by_topic {
                    output.push_str(&format!("  {topic}: {count}\n"));
                }
            }
            if !stats.most_applied.is_empty() {
                output.push_str("\nMost applied:\n");
                for (id, count) in &stats.most_applied {
                    output.push_str(&format!("  {id}: {count} times\n"));
                }
            }
            ToolResult::structured(output, "Returned feedback statistics.".into(), &structured)
        }
        Err(e) => ToolResult::error(format!("failed to get feedback stats: {e}")),
    }
}
