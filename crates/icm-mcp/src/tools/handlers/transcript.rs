//! MCP transcript tool handlers.

use serde_json::{json, Value};

use icm_core::TranscriptStore;

use icm_store::Store;

use crate::protocol::ToolResult;

pub(in crate::tools) fn tool_transcript_start_session(store: &Store, args: &Value) -> ToolResult {
    let agent = args.get("agent").and_then(|v| v.as_str()).unwrap_or("mcp");
    let project = args.get("project").and_then(|v| v.as_str());
    let metadata = args.get("metadata").and_then(|v| v.as_str());
    match store.create_session(agent, project, metadata) {
        Ok(id) => ToolResult::text(format!("{{\"session_id\":\"{id}\"}}")),
        Err(e) => ToolResult::error(format!("start_session failed: {e}")),
    }
}

pub(in crate::tools) fn tool_transcript_record(store: &Store, args: &Value) -> ToolResult {
    use icm_core::{Role, TranscriptStore};
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return ToolResult::error("session_id is required".into()),
    };
    let role_str = match args.get("role").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return ToolResult::error("role is required".into()),
    };
    let role = match Role::parse(role_str) {
        Some(r) => r,
        None => {
            return ToolResult::error(format!(
                "invalid role '{role_str}'; must be user|assistant|system|tool"
            ))
        }
    };
    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return ToolResult::error("content is required".into()),
    };
    let tool_name = args.get("tool_name").and_then(|v| v.as_str());
    let tokens = args.get("tokens").and_then(|v| v.as_i64());
    let metadata = args.get("metadata").and_then(|v| v.as_str());
    match store.record_message(session_id, role, content, tool_name, tokens, metadata) {
        Ok(id) => ToolResult::text(format!("{{\"message_id\":\"{id}\"}}")),
        Err(e) => ToolResult::error(format!("record failed: {e}")),
    }
}

pub(in crate::tools) fn tool_transcript_search(store: &Store, args: &Value) -> ToolResult {
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return ToolResult::error("query is required".into()),
    };
    let session_id = args.get("session_id").and_then(|v| v.as_str());
    let project = args.get("project").and_then(|v| v.as_str());
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .min(50) as usize;
    match store.search_transcripts(query, session_id, project, limit) {
        Ok(hits) => {
            let json = serde_json::to_string(&hits).unwrap_or_else(|_| "[]".into());
            ToolResult::text(json)
        }
        Err(e) => ToolResult::error(format!("search failed: {e}")),
    }
}

pub(in crate::tools) fn tool_transcript_show(store: &Store, args: &Value) -> ToolResult {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return ToolResult::error("session_id is required".into()),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(200)
        .min(2000) as usize;
    let sess = match store.get_session(session_id) {
        Ok(Some(s)) => s,
        Ok(None) => return ToolResult::error(format!("session {session_id} not found")),
        Err(e) => return ToolResult::error(format!("get_session failed: {e}")),
    };
    let msgs = match store.list_session_messages(session_id, limit, 0) {
        Ok(m) => m,
        Err(e) => return ToolResult::error(format!("list_messages failed: {e}")),
    };
    let body = json!({ "session": sess, "messages": msgs });
    ToolResult::text(body.to_string())
}

pub(in crate::tools) fn tool_transcript_stats(store: &Store) -> ToolResult {
    match store.transcript_stats() {
        Ok(s) => ToolResult::text(serde_json::to_string(&s).unwrap_or_else(|_| "{}".into())),
        Err(e) => ToolResult::error(format!("stats failed: {e}")),
    }
}
