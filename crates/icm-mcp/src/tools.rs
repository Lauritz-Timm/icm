use serde_json::Value;

use icm_core::Embedder;
use icm_store::Store;

use crate::catalog::{DispatchResult, ToolContext};
use crate::protocol::ToolResult;

mod handlers;
mod registry;

pub use handlers::AutoConsolidate;
pub(crate) use registry::build_catalog;

/// Frozen 2024 tool-list projection retained for callers and compatibility
/// tests. Production service instances cache this projection in their catalog.
pub fn tool_definitions(has_embedder: bool) -> Value {
    build_catalog(has_embedder).legacy_list()
}

pub fn call_tool(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    name: &str,
    args: &Value,
    compact: bool,
) -> ToolResult {
    call_tool_with_config(
        store,
        embedder,
        name,
        args,
        compact,
        AutoConsolidate::default(),
    )
}

/// Like [`call_tool`] but with an explicit auto-consolidation policy
/// (issue #318). `icm serve` calls this with the user's loaded config so an
/// `auto_consolidate_enabled = false` is honored on the MCP store path.
pub fn call_tool_with_config(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    name: &str,
    args: &Value,
    compact: bool,
    auto_consolidate: AutoConsolidate,
) -> ToolResult {
    // This public helper is the frozen pre-catalog compatibility dispatcher.
    // Keep unavailable tools dispatchable here so their established handler
    // errors remain stable; production service discovery and dispatch use the
    // capability-filtered catalog stored by `McpService`.
    let catalog = build_catalog(true);
    let working_directory =
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let context = ToolContext {
        store,
        embedder,
        compact,
        auto_consolidate,
        working_directory: &working_directory,
        enforce_directory_boundary: false,
    };
    match catalog.dispatch(
        &context,
        name,
        args,
        crate::catalog::InputValidation::Legacy2024Unchecked,
    ) {
        DispatchResult::ToolResult(result) => result,
        DispatchResult::UnknownTool => ToolResult::error(format!("unknown tool: {name}")),
        DispatchResult::InvalidInput(_) => {
            unreachable!("unchecked legacy compatibility dispatch cannot reject typed inputs")
        }
    }
}

#[cfg(test)]
mod tests;
