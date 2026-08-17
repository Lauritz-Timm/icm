//! Transport-neutral MCP request service.

use std::collections::HashSet;
use std::path::PathBuf;

use icm_core::{project::project_from_path, Embedder, IcmError, IcmResult, Memory};
use icm_store::Store;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::catalog::{DispatchResult, InputValidation, ToolCatalog, ToolContext};
use crate::protocol::{
    valid_metadata_key, JsonRpcMessage, JsonRpcResponse, ProtocolEra, ProtocolRevision,
    ERA_LOCKED_ERROR_CODE, LIFECYCLE_VIOLATION_ERROR_CODE, META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO, META_PROTOCOL_VERSION, META_SERVER_INFO, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::tools::{self, AutoConsolidate};

const SERVER_NAME: &str = "icm";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const STORE_NUDGE_THRESHOLD: u32 = 10;
const MODERN_LOG_LEVEL_KEY: &str = "io.modelcontextprotocol/logLevel";
const MODERN_SUBSCRIPTION_ID_KEY: &str = "io.modelcontextprotocol/subscriptionId";
const MAX_STORED_LIFECYCLE_METHOD_BYTES: usize = 256;
const ACTIVE_PROJECT_CONTEXT_URI: &str = "icm://active-project/context";
const ACTIVE_PROJECT_CONTEXT_MIME_TYPE: &str = "application/json";
const RESOURCE_ROW_LIMIT: usize = 64;
const RESOURCE_FIELD_BYTES: usize = 512;
const RESOURCE_MAX_BYTES: usize = 2048;

pub const ICM_INSTRUCTIONS: &str = "\
Use ICM (Infinite Context Memory) proactively to maintain long-term memory across sessions.\n\
\n\
RECALL (icm_memory_recall): At the start of a task, search for relevant past context — decisions, \
resolved errors, user preferences. Search only what is relevant, do not dump everything.\n\
\n\
STORE (icm_memory_store): You MUST store when ANY of these triggers occur:\n\
1. Error resolved → topic: \"errors-resolved\", importance: high\n\
2. Architecture/design decision made → topic: \"decisions-{project}\", importance: high\n\
3. User preference discovered (correction, feedback) → topic: \"preferences\", importance: critical\n\
4. Significant task completed (feature, fix, config, review) → topic: \"context-{project}\", importance: high\n\
5. Conversation exceeds ~20 tool calls without a store → store a progress summary\n\
\n\
Do this BEFORE responding to the user. Not after. Not later. Immediately.\n\
\n\
Do NOT store: trivial details, information already in CLAUDE.md, ephemeral state.\n\
\n\
Importance levels: critical (never forgotten), high (slow decay), medium (normal), low (fast decay).";

#[derive(Clone, Debug)]
struct LifecycleViolation {
    kind: &'static str,
    state: &'static str,
    method: String,
}

#[derive(Clone, Debug)]
enum ConnectionPhase {
    Uninitialized,
    /// The 2024 compatibility projection is ready immediately after
    /// initialize because the frozen legacy clients do not send the
    /// initialized notification. One optional notification is still accepted.
    LegacyReady {
        revision: ProtocolRevision,
        initialized_seen: bool,
    },
    LegacyAwaitingInitialized(ProtocolRevision),
    Modern,
    Poisoned(LifecycleViolation),
}

#[derive(Clone, Debug)]
pub struct ConnectionState {
    phase: ConnectionPhase,
    calls_since_store: u32,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            phase: ConnectionPhase::Uninitialized,
            calls_since_store: 0,
        }
    }
}

impl ConnectionState {
    /// Start a stateless HTTP request in the frozen 2024 compatibility era.
    /// Stdio still begins uninitialized; only transports that already carry
    /// the protocol revision out-of-band should use this constructor.
    pub fn legacy_2024_ready() -> Self {
        Self {
            phase: ConnectionPhase::LegacyReady {
                revision: ProtocolRevision::V2024_11_05,
                initialized_seen: false,
            },
            calls_since_store: 0,
        }
    }
}

pub struct McpService<'a> {
    store: &'a Store,
    embedder: Option<&'a dyn Embedder>,
    compact: bool,
    auto_consolidate: AutoConsolidate,
    working_directory: PathBuf,
    active_project: Option<String>,
    catalog: ToolCatalog,
}

impl<'a> McpService<'a> {
    pub fn new(
        store: &'a Store,
        embedder: Option<&'a dyn Embedder>,
        compact: bool,
        auto_consolidate: AutoConsolidate,
    ) -> Self {
        let working_directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::with_working_directory(
            store,
            embedder,
            compact,
            auto_consolidate,
            working_directory,
        )
    }

    pub fn with_working_directory(
        store: &'a Store,
        embedder: Option<&'a dyn Embedder>,
        compact: bool,
        auto_consolidate: AutoConsolidate,
        working_directory: PathBuf,
    ) -> Self {
        let active_project = working_directory
            .to_str()
            .and_then(project_from_path)
            .filter(|project| valid_resource_project(project));
        Self {
            store,
            embedder,
            compact,
            auto_consolidate,
            working_directory,
            active_project,
            catalog: tools::build_catalog(embedder.is_some()),
        }
    }

    pub fn handle(
        &self,
        state: &mut ConnectionState,
        message: JsonRpcMessage,
    ) -> Option<JsonRpcResponse> {
        let response_id = message.id.clone().unwrap_or(Value::Null);
        if message.jsonrpc != "2.0" {
            return Some(JsonRpcResponse::err(
                response_id,
                -32600,
                "invalid JSON-RPC version; expected 2.0".into(),
            ));
        }
        let Some(method) = message
            .method
            .as_deref()
            .filter(|method| !method.is_empty())
        else {
            return Some(JsonRpcResponse::err(
                response_id,
                -32600,
                "invalid request: method must be a non-empty string".into(),
            ));
        };

        if message.id.is_none() {
            self.handle_notification(state, method, &message);
            return None;
        }

        if !valid_request_id(message.id.as_ref().expect("checked above"))
            && !matches!(
                state.phase,
                ConnectionPhase::LegacyReady {
                    revision: ProtocolRevision::V2024_11_05,
                    ..
                }
            )
        {
            return Some(JsonRpcResponse::err(
                Value::Null,
                -32600,
                "invalid request id; expected a string or integer".into(),
            ));
        }

        Some(self.handle_request(state, response_id, method, &message))
    }

    fn handle_request(
        &self,
        state: &mut ConnectionState,
        id: Value,
        method: &str,
        message: &JsonRpcMessage,
    ) -> JsonRpcResponse {
        if let ConnectionPhase::Poisoned(violation) = &state.phase {
            return lifecycle_error(id, violation);
        }

        if method == "initialize" {
            return match state.phase.clone() {
                ConnectionPhase::Uninitialized => self.initialize(state, id, message),
                ConnectionPhase::Modern => era_locked_error(
                    id,
                    ProtocolEra::PerRequest,
                    ProtocolEra::InitializationBased,
                ),
                ConnectionPhase::LegacyReady { .. }
                | ConnectionPhase::LegacyAwaitingInitialized(_) => self.lifecycle_violation(
                    state,
                    id,
                    "initialize-already-completed",
                    phase_name(&state.phase),
                    method,
                ),
                ConnectionPhase::Poisoned(_) => unreachable!("handled above"),
            };
        }

        match state.phase.clone() {
            ConnectionPhase::Uninitialized => {
                if method == "server/discover" || requests_modern_era(message) {
                    if let Err(response) = validate_modern_request(id.clone(), message) {
                        return *response;
                    }
                    state.phase = ConnectionPhase::Modern;
                    self.dispatch(state, id, ProtocolRevision::V2026_07_28, method, message)
                } else {
                    self.lifecycle_violation(
                        state,
                        id,
                        "initialize-required",
                        "uninitialized",
                        method,
                    )
                }
            }
            ConnectionPhase::LegacyAwaitingInitialized(revision) => {
                if requests_modern_era(message) {
                    return era_locked_error(
                        id,
                        ProtocolEra::InitializationBased,
                        ProtocolEra::PerRequest,
                    );
                }
                if let Err(response) = validate_legacy_request(
                    id.clone(),
                    message,
                    revision == ProtocolRevision::V2024_11_05,
                ) {
                    return *response;
                }
                if method == "ping" {
                    self.dispatch(state, id, revision, method, message)
                } else {
                    self.lifecycle_violation(
                        state,
                        id,
                        "initialized-notification-required",
                        "initialize-responded",
                        method,
                    )
                }
            }
            ConnectionPhase::LegacyReady { revision, .. } => {
                if requests_modern_era(message) {
                    era_locked_error(
                        id,
                        ProtocolEra::InitializationBased,
                        ProtocolEra::PerRequest,
                    )
                } else {
                    if let Err(response) = validate_legacy_request(
                        id.clone(),
                        message,
                        revision == ProtocolRevision::V2024_11_05,
                    ) {
                        return *response;
                    }
                    self.dispatch(state, id, revision, method, message)
                }
            }
            ConnectionPhase::Modern => {
                if let Err(response) = validate_modern_request(id.clone(), message) {
                    return *response;
                }
                self.dispatch(state, id, ProtocolRevision::V2026_07_28, method, message)
            }
            ConnectionPhase::Poisoned(_) => unreachable!("handled above"),
        }
    }

    fn handle_notification(
        &self,
        state: &mut ConnectionState,
        method: &str,
        message: &JsonRpcMessage,
    ) {
        if method == "notifications/initialized" {
            if let Err(error) = validate_initialized_notification(message) {
                tracing::warn!(error, "ignored malformed MCP initialized notification");
                return;
            }
        }
        if method != "notifications/initialized" {
            if matches!(state.phase, ConnectionPhase::Modern) {
                if let Err(error) = validate_modern_notification(message) {
                    tracing::warn!(method, error, "ignored malformed modern MCP notification");
                }
            }
            return;
        }

        match state.phase.clone() {
            ConnectionPhase::Uninitialized => {
                state.phase = ConnectionPhase::Poisoned(LifecycleViolation {
                    kind: "initialized-before-initialize",
                    state: "protocol-error",
                    method: method.into(),
                });
            }
            ConnectionPhase::LegacyAwaitingInitialized(revision) => {
                state.phase = ConnectionPhase::LegacyReady {
                    revision,
                    initialized_seen: true,
                };
            }
            ConnectionPhase::LegacyReady {
                revision,
                initialized_seen: false,
            } if revision == ProtocolRevision::V2024_11_05 => {
                state.phase = ConnectionPhase::LegacyReady {
                    revision,
                    initialized_seen: true,
                };
            }
            ConnectionPhase::LegacyReady { .. } => {
                state.phase = ConnectionPhase::Poisoned(LifecycleViolation {
                    kind: "initialized-already-received",
                    state: "protocol-error",
                    method: method.into(),
                });
            }
            ConnectionPhase::Modern => {
                if let Err(error) = validate_modern_notification(message) {
                    tracing::warn!(method, error, "ignored malformed modern MCP notification");
                }
            }
            ConnectionPhase::Poisoned(_) => {}
        }
    }

    fn initialize(
        &self,
        state: &mut ConnectionState,
        id: Value,
        message: &JsonRpcMessage,
    ) -> JsonRpcResponse {
        if let Err(response) = validate_legacy_request(id.clone(), message, false) {
            return *response;
        }
        let Some(params) = message.params.as_ref().and_then(Value::as_object) else {
            return JsonRpcResponse::err(id, -32602, "initialize params must be an object".into());
        };
        let Some(requested) = params.get("protocolVersion").and_then(Value::as_str) else {
            return JsonRpcResponse::err(
                id,
                -32602,
                "initialize.protocolVersion must be a string".into(),
            );
        };

        let revision = match ProtocolRevision::parse_exact(requested) {
            Some(ProtocolRevision::V2026_07_28) => {
                return JsonRpcResponse::err(
                    id,
                    -32602,
                    "2026-07-28 does not use initialize; send per-request metadata or call server/discover"
                        .into(),
                )
            }
            Some(revision) => revision,
            None => ProtocolRevision::V2025_11_25,
        };

        if !params.get("capabilities").is_some_and(|capabilities| {
            valid_initialize_client_capabilities(revision, capabilities)
        }) {
            return JsonRpcResponse::err(
                id,
                -32602,
                "initialize.capabilities must be a valid client capabilities object".into(),
            );
        }
        if !params
            .get("clientInfo")
            .is_some_and(|identity| valid_initialize_implementation_identity(revision, identity))
        {
            return JsonRpcResponse::err(
                id,
                -32602,
                "initialize.clientInfo must be valid for the negotiated protocol revision".into(),
            );
        }

        state.phase = if revision == ProtocolRevision::V2024_11_05 {
            ConnectionPhase::LegacyReady {
                revision,
                initialized_seen: false,
            }
        } else {
            ConnectionPhase::LegacyAwaitingInitialized(revision)
        };

        let capabilities = if revision == ProtocolRevision::V2024_11_05 {
            json!({ "tools": {} })
        } else {
            json!({ "tools": {}, "resources": {} })
        };
        JsonRpcResponse::ok(
            id,
            json!({
                "protocolVersion": revision.as_str(),
                "capabilities": capabilities,
                "serverInfo": server_info(),
                "instructions": ICM_INSTRUCTIONS,
            }),
        )
    }

    fn lifecycle_violation(
        &self,
        state: &mut ConnectionState,
        id: Value,
        kind: &'static str,
        state_name: &'static str,
        method: &str,
    ) -> JsonRpcResponse {
        let violation = LifecycleViolation {
            kind,
            state: state_name,
            method: bounded_lifecycle_method(method),
        };
        let response = lifecycle_error(id, &violation);
        state.phase = ConnectionPhase::Poisoned(violation);
        response
    }

    fn dispatch(
        &self,
        state: &mut ConnectionState,
        id: Value,
        revision: ProtocolRevision,
        method: &str,
        message: &JsonRpcMessage,
    ) -> JsonRpcResponse {
        match method {
            "ping" => JsonRpcResponse::ok(id, project_result(revision, json!({}), None)),
            "server/discover" if revision == ProtocolRevision::V2026_07_28 => {
                JsonRpcResponse::ok(id, discovery_result())
            }
            "tools/list" => self.list_tools(id, revision, message),
            "tools/call" => self.call_tool(state, id, revision, message),
            "resources/list" if revision != ProtocolRevision::V2024_11_05 => {
                self.list_resources(id, revision, message)
            }
            "resources/read" if revision != ProtocolRevision::V2024_11_05 => {
                self.read_resource(id, revision, message)
            }
            other => JsonRpcResponse::method_not_found(id, other),
        }
    }

    fn list_resources(
        &self,
        id: Value,
        revision: ProtocolRevision,
        message: &JsonRpcMessage,
    ) -> JsonRpcResponse {
        let cursor = message
            .params
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|params| params.get("cursor"));
        if cursor.is_some_and(|cursor| !cursor.is_null() && cursor.as_str() != Some("")) {
            return JsonRpcResponse::err(
                id,
                -32602,
                "resources/list cursor is not supported".into(),
            );
        }

        let resources = self
            .active_project
            .as_ref()
            .map(|_| {
                json!({
                    "uri": ACTIVE_PROJECT_CONTEXT_URI,
                    "name": "active-project-context",
                    "title": "Active Project Context",
                    "description": "Stored context for the project inferred from the MCP server working directory.",
                    "mimeType": ACTIVE_PROJECT_CONTEXT_MIME_TYPE,
                    "annotations": { "audience": ["assistant"], "priority": 1.0 }
                })
            })
            .into_iter()
            .collect::<Vec<_>>();
        let result = if revision == ProtocolRevision::V2026_07_28 {
            project_result(
                revision,
                json!({ "resources": resources }),
                Some((3_600_000, "private")),
            )
        } else {
            json!({
                "resources": resources,
                "_meta": { "ttlMs": 0, "cacheScope": "private" }
            })
        };
        JsonRpcResponse::ok(id, result)
    }

    fn read_resource(
        &self,
        id: Value,
        revision: ProtocolRevision,
        message: &JsonRpcMessage,
    ) -> JsonRpcResponse {
        let Some(params) = message.params.as_ref().and_then(Value::as_object) else {
            return JsonRpcResponse::err(
                id,
                -32602,
                "resources/read params must be an object".into(),
            );
        };
        if params
            .keys()
            .any(|key| !matches!(key.as_str(), "uri" | "_meta"))
        {
            return JsonRpcResponse::err(
                id,
                -32602,
                "resources/read accepts only uri and _meta".into(),
            );
        }
        let Some(uri) = params.get("uri").and_then(Value::as_str) else {
            return JsonRpcResponse::err(id, -32602, "resources/read.uri must be a string".into());
        };
        let Some(project) = self
            .active_project
            .as_deref()
            .filter(|_| uri == ACTIVE_PROJECT_CONTEXT_URI)
        else {
            let code = if revision == ProtocolRevision::V2026_07_28 {
                -32602
            } else {
                -32002
            };
            return JsonRpcResponse::err_with_data(
                id,
                code,
                "resource not found".into(),
                Some(json!({ "uri": uri })),
            );
        };

        let text = match active_project_context(self.store, project) {
            Ok(text) => text,
            Err(error) => {
                tracing::warn!(%error, "failed to read active-project MCP resource");
                return JsonRpcResponse::err(id, -32603, "failed to read resource".into());
            }
        };
        let value = json!({
            "contents": [{
                "uri": ACTIVE_PROJECT_CONTEXT_URI,
                "mimeType": ACTIVE_PROJECT_CONTEXT_MIME_TYPE,
                "text": text,
            }]
        });
        let result = if revision == ProtocolRevision::V2026_07_28 {
            project_result(revision, value, Some((0, "private")))
        } else {
            let mut value = value;
            value["_meta"] = json!({ "ttlMs": 0, "cacheScope": "private" });
            value
        };
        JsonRpcResponse::ok(id, result)
    }

    fn list_tools(
        &self,
        id: Value,
        revision: ProtocolRevision,
        message: &JsonRpcMessage,
    ) -> JsonRpcResponse {
        if revision != ProtocolRevision::V2024_11_05 {
            let cursor = message
                .params
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|params| params.get("cursor"));
            if cursor.is_some_and(|cursor| !cursor.is_null() && cursor.as_str() != Some("")) {
                return JsonRpcResponse::err(
                    id,
                    -32602,
                    "tools/list cursor is not supported for the immutable catalog".into(),
                );
            }
        }
        let result = match revision {
            ProtocolRevision::V2024_11_05 => self.catalog.legacy_list(),
            ProtocolRevision::V2025_06_18 | ProtocolRevision::V2025_11_25 => {
                self.catalog.modern_list()
            }
            ProtocolRevision::V2026_07_28 => project_result(
                revision,
                self.catalog.modern_list(),
                Some((3_600_000, "private")),
            ),
        };
        JsonRpcResponse::ok(id, result)
    }

    fn call_tool(
        &self,
        state: &mut ConnectionState,
        id: Value,
        revision: ProtocolRevision,
        message: &JsonRpcMessage,
    ) -> JsonRpcResponse {
        let Some(params) = message.params.as_ref() else {
            return JsonRpcResponse::err(id, -32602, "missing params".into());
        };
        if revision != ProtocolRevision::V2024_11_05 && !params.is_object() {
            return JsonRpcResponse::err(id, -32602, "missing params".into());
        }
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return JsonRpcResponse::err(id, -32602, "missing tool name".into());
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if revision != ProtocolRevision::V2024_11_05 && !arguments.is_object() {
            return JsonRpcResponse::err(id, -32602, "tool arguments must be an object".into());
        }

        if name == "icm_memory_store" {
            state.calls_since_store = 0;
        } else {
            state.calls_since_store = state.calls_since_store.saturating_add(1);
        }

        let context = ToolContext {
            store: self.store,
            embedder: self.embedder,
            compact: self.compact,
            auto_consolidate: self.auto_consolidate,
            working_directory: &self.working_directory,
            enforce_directory_boundary: revision != ProtocolRevision::V2024_11_05,
        };
        let validation = if revision == ProtocolRevision::V2024_11_05 {
            InputValidation::Legacy2024Unchecked
        } else {
            InputValidation::Modern
        };
        let mut result = match self
            .catalog
            .dispatch(&context, name, &arguments, validation)
        {
            DispatchResult::ToolResult(mut result) => {
                result.select_projection(revision != ProtocolRevision::V2024_11_05);
                result
            }
            DispatchResult::UnknownTool if revision == ProtocolRevision::V2024_11_05 => {
                crate::protocol::ToolResult::error(format!("unknown tool: {name}"))
            }
            DispatchResult::UnknownTool => {
                return JsonRpcResponse::err(id, -32602, format!("unknown tool: {name}"))
            }
            DispatchResult::InvalidInput(message) => {
                return self.invalid_tool_arguments_result(id, revision, message)
            }
        };

        if revision != ProtocolRevision::V2026_07_28
            && name != "icm_memory_store"
            && state.calls_since_store >= STORE_NUDGE_THRESHOLD
            && state
                .calls_since_store
                .is_multiple_of(STORE_NUDGE_THRESHOLD)
        {
            result.append_hint(&format!(
                "\n[ICM: {} tool calls since last store. Consider saving important context with \
                 icm_memory_store before it is lost.]",
                state.calls_since_store
            ));
        }

        let value = serde_json::to_value(result).unwrap_or(Value::Null);
        JsonRpcResponse::ok(id, project_result(revision, value, None))
    }

    fn invalid_tool_arguments_result(
        &self,
        id: Value,
        revision: ProtocolRevision,
        message: String,
    ) -> JsonRpcResponse {
        if revision != ProtocolRevision::V2024_11_05 {
            return JsonRpcResponse::err(id, -32602, format!("invalid arguments: {message}"));
        }
        let result = crate::protocol::ToolResult::error(format!("invalid arguments: {message}"));
        let value = serde_json::to_value(result).unwrap_or(Value::Null);
        JsonRpcResponse::ok(id, project_result(revision, value, None))
    }
}

fn valid_request_id(id: &Value) -> bool {
    id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()
}

fn phase_name(phase: &ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::Uninitialized => "uninitialized",
        ConnectionPhase::LegacyAwaitingInitialized(_) => "initialize-responded",
        ConnectionPhase::LegacyReady { .. } => "initialized",
        ConnectionPhase::Modern => "modern",
        ConnectionPhase::Poisoned(_) => "protocol-error",
    }
}

fn bounded_lifecycle_method(method: &str) -> String {
    if method.len() <= MAX_STORED_LIFECYCLE_METHOD_BYTES {
        method.into()
    } else {
        format!("<method omitted: {} bytes>", method.len())
    }
}

fn lifecycle_error(id: Value, violation: &LifecycleViolation) -> JsonRpcResponse {
    JsonRpcResponse::err_with_data(
        id,
        LIFECYCLE_VIOLATION_ERROR_CODE,
        "protocol lifecycle violation; open a new connection".into(),
        Some(json!({
            "kind": violation.kind,
            "state": violation.state,
            "method": violation.method,
        })),
    )
}

fn era_locked_error(id: Value, selected: ProtocolEra, requested: ProtocolEra) -> JsonRpcResponse {
    JsonRpcResponse::err_with_data(
        id,
        ERA_LOCKED_ERROR_CODE,
        "protocol era is locked for this connection; open a new connection".into(),
        Some(json!({
            "kind": "protocolEraLocked",
            "selectedEra": selected.as_str(),
            "requestedEra": requested.as_str(),
        })),
    )
}

fn requests_modern_era(message: &JsonRpcMessage) -> bool {
    message
        .params
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
        .is_some_and(|metadata| {
            [
                META_PROTOCOL_VERSION,
                META_CLIENT_CAPABILITIES,
                META_CLIENT_INFO,
            ]
            .into_iter()
            .any(|key| metadata.contains_key(key))
        })
}

fn validate_legacy_request(
    id: Value,
    message: &JsonRpcMessage,
    allow_non_object_params: bool,
) -> Result<(), Box<JsonRpcResponse>> {
    if message.extra.contains_key("_meta") {
        return Err(invalid_params(
            id,
            "request metadata must be nested at params._meta",
        ));
    }
    let Some(params) = message.params.as_ref() else {
        return Ok(());
    };
    let Some(params) = params.as_object() else {
        if allow_non_object_params {
            return Ok(());
        }
        return Err(invalid_params(id, "request params must be an object"));
    };
    let Some(raw_metadata) = params.get("_meta") else {
        return Ok(());
    };
    let Some(metadata) = raw_metadata.as_object() else {
        return Err(invalid_params(id, "params._meta must be an object"));
    };
    validate_legacy_metadata(&id, metadata)
}

fn validate_modern_request(
    id: Value,
    message: &JsonRpcMessage,
) -> Result<(), Box<JsonRpcResponse>> {
    if message.extra.contains_key("_meta") {
        return Err(invalid_params(
            id,
            "request metadata must be nested at params._meta",
        ));
    }
    let Some(params) = message.params.as_ref().and_then(Value::as_object) else {
        return Err(invalid_params(
            id,
            "modern request params must be an object",
        ));
    };
    let Some(metadata) = params.get("_meta").and_then(Value::as_object) else {
        return Err(invalid_params(id, "params._meta must be an object"));
    };
    validate_metadata_shape(&id, metadata)?;

    let Some(requested) = metadata.get(META_PROTOCOL_VERSION).and_then(Value::as_str) else {
        return Err(invalid_params(
            id,
            format!("missing or invalid {META_PROTOCOL_VERSION}"),
        ));
    };
    if requested != ProtocolRevision::V2026_07_28.as_str() {
        return Err(Box::new(unsupported_protocol_version_error(id, requested)));
    }

    let Some(capabilities) = metadata
        .get(META_CLIENT_CAPABILITIES)
        .filter(|capabilities| valid_client_capabilities(capabilities))
    else {
        return Err(invalid_params(
            id,
            format!("missing or invalid {META_CLIENT_CAPABILITIES}"),
        ));
    };
    debug_assert!(capabilities.is_object());

    if metadata
        .get(META_CLIENT_INFO)
        .is_some_and(|identity| !valid_implementation_identity(identity))
    {
        return Err(invalid_params(id, format!("invalid {META_CLIENT_INFO}")));
    }
    validate_optional_metadata_values(&id, metadata)
}

/// Build the protocol-defined error shared by MCP services and transports.
pub fn unsupported_protocol_version_error(id: Value, requested: &str) -> JsonRpcResponse {
    JsonRpcResponse::err_with_data(
        id,
        -32022,
        format!("unsupported protocol version: {requested}"),
        Some(json!({
            "supported": SUPPORTED_PROTOCOL_VERSIONS,
            "requested": requested,
        })),
    )
}

fn validate_modern_notification(message: &JsonRpcMessage) -> Result<(), String> {
    if message.extra.contains_key("_meta") {
        return Err("notification metadata must be nested at params._meta".into());
    }
    let Some(params) = message.params.as_ref() else {
        return Ok(());
    };
    let Some(params) = params.as_object() else {
        return Err("notification params must be an object".into());
    };
    let Some(raw_metadata) = params.get("_meta") else {
        return Ok(());
    };
    let Some(metadata) = raw_metadata.as_object() else {
        return Err("notification params._meta must be an object".into());
    };
    let null_id = Value::Null;
    validate_metadata_shape(&null_id, metadata)
        .map_err(|_| "notification metadata has an invalid key or size".to_owned())?;
    if metadata
        .get(META_PROTOCOL_VERSION)
        .is_some_and(|version| version.as_str() != Some(ProtocolRevision::V2026_07_28.as_str()))
    {
        return Err(format!("invalid {META_PROTOCOL_VERSION}"));
    }
    if metadata
        .get(META_CLIENT_CAPABILITIES)
        .is_some_and(|capabilities| !valid_client_capabilities(capabilities))
    {
        return Err(format!("invalid {META_CLIENT_CAPABILITIES}"));
    }
    if metadata
        .get(META_CLIENT_INFO)
        .is_some_and(|identity| !valid_implementation_identity(identity))
    {
        return Err(format!("invalid {META_CLIENT_INFO}"));
    }
    validate_optional_metadata_values(&null_id, metadata)
        .map_err(|_| "notification metadata has an invalid value".to_owned())
}

fn validate_initialized_notification(message: &JsonRpcMessage) -> Result<(), String> {
    if message.extra.contains_key("_meta") {
        return Err("initialized metadata must be nested at params._meta".into());
    }
    let Some(params) = message.params.as_ref() else {
        return Ok(());
    };
    let Some(params) = params.as_object() else {
        return Err("initialized params must be an object".into());
    };
    let Some(raw_metadata) = params.get("_meta") else {
        return Ok(());
    };
    let Some(metadata) = raw_metadata.as_object() else {
        return Err("initialized params._meta must be an object".into());
    };
    let null_id = Value::Null;
    validate_legacy_metadata(&null_id, metadata)
        .map_err(|_| "initialized metadata has an invalid shape or value".to_owned())
}

fn invalid_params(id: Value, message: impl Into<String>) -> Box<JsonRpcResponse> {
    Box::new(JsonRpcResponse::err(id, -32602, message.into()))
}

fn validate_metadata_shape(
    id: &Value,
    metadata: &Map<String, Value>,
) -> Result<(), Box<JsonRpcResponse>> {
    if metadata.len() > 64
        || serde_json::to_vec(metadata).is_ok_and(|encoded| encoded.len() > 65_536)
        || metadata
            .values()
            .any(|value| !metadata_value_within_depth(value, 32))
    {
        return Err(invalid_params(
            id.clone(),
            "params._meta exceeds the supported size or nesting depth",
        ));
    }
    for key in metadata.keys() {
        if !valid_metadata_key(key) {
            return Err(invalid_params(
                id.clone(),
                format!("invalid metadata key: {key}"),
            ));
        }
    }
    Ok(())
}

fn validate_legacy_metadata(
    id: &Value,
    metadata: &Map<String, Value>,
) -> Result<(), Box<JsonRpcResponse>> {
    if metadata.len() > 64
        || serde_json::to_vec(metadata).is_ok_and(|encoded| encoded.len() > 65_536)
        || metadata
            .values()
            .any(|value| !metadata_value_within_depth(value, 32))
    {
        return Err(invalid_params(
            id.clone(),
            "params._meta exceeds the supported size or nesting depth",
        ));
    }
    if metadata
        .get("progressToken")
        .is_some_and(|token| !(token.is_string() || token.is_number()))
    {
        return Err(invalid_params(
            id.clone(),
            "progressToken must be a string or number",
        ));
    }
    if metadata
        .get(MODERN_SUBSCRIPTION_ID_KEY)
        .is_some_and(|subscription_id| !valid_request_id(subscription_id))
    {
        return Err(invalid_params(
            id.clone(),
            format!("{MODERN_SUBSCRIPTION_ID_KEY} must be a string or integer"),
        ));
    }
    Ok(())
}

fn metadata_value_within_depth(value: &Value, remaining: usize) -> bool {
    match value {
        Value::Array(values) => {
            remaining > 0
                && values
                    .iter()
                    .all(|value| metadata_value_within_depth(value, remaining - 1))
        }
        Value::Object(values) => {
            remaining > 0
                && values
                    .values()
                    .all(|value| metadata_value_within_depth(value, remaining - 1))
        }
        _ => true,
    }
}

fn validate_optional_metadata_values(
    id: &Value,
    metadata: &Map<String, Value>,
) -> Result<(), Box<JsonRpcResponse>> {
    if metadata
        .get("progressToken")
        .is_some_and(|token| !(token.is_string() || token.is_number()))
    {
        return Err(invalid_params(
            id.clone(),
            "progressToken must be a string or number",
        ));
    }
    if metadata
        .get(MODERN_SUBSCRIPTION_ID_KEY)
        .is_some_and(|subscription_id| !valid_request_id(subscription_id))
    {
        return Err(invalid_params(
            id.clone(),
            format!("{MODERN_SUBSCRIPTION_ID_KEY} must be a string or integer"),
        ));
    }
    for (key, validator) in [
        ("traceparent", valid_traceparent as fn(&str) -> bool),
        ("tracestate", valid_tracestate),
        ("baggage", valid_baggage),
    ] {
        if metadata
            .get(key)
            .is_some_and(|value| !value.as_str().is_some_and(validator))
        {
            return Err(invalid_params(id.clone(), format!("invalid {key}")));
        }
    }
    if metadata.get(MODERN_LOG_LEVEL_KEY).is_some_and(|level| {
        !matches!(
            level.as_str(),
            Some(
                "debug"
                    | "info"
                    | "notice"
                    | "warning"
                    | "error"
                    | "critical"
                    | "alert"
                    | "emergency"
            )
        )
    }) {
        return Err(invalid_params(
            id.clone(),
            format!("invalid {MODERN_LOG_LEVEL_KEY}"),
        ));
    }
    Ok(())
}

fn valid_initialize_client_capabilities(revision: ProtocolRevision, value: &Value) -> bool {
    if revision == ProtocolRevision::V2026_07_28 {
        return valid_client_capabilities(value);
    }
    let Some(capabilities) = bounded_capabilities(value) else {
        return false;
    };
    capabilities
        .iter()
        .all(|(name, capability)| match name.as_str() {
            "experimental" => valid_experimental_capability(capability),
            "roots" => valid_roots_capability(capability),
            "sampling"
                if matches!(
                    revision,
                    ProtocolRevision::V2024_11_05 | ProtocolRevision::V2025_06_18
                ) =>
            {
                capability.is_object()
            }
            "sampling" => valid_capability_fields(capability, &["context", "tools"]),
            "elicitation" if revision == ProtocolRevision::V2025_06_18 => capability.is_object(),
            "elicitation" if revision == ProtocolRevision::V2025_11_25 => {
                valid_capability_fields(capability, &["form", "url"])
            }
            "tasks" if revision == ProtocolRevision::V2025_11_25 => {
                valid_tasks_capability(capability)
            }
            _ => true,
        })
}

fn valid_client_capabilities(value: &Value) -> bool {
    let Some(capabilities) = bounded_capabilities(value) else {
        return false;
    };
    capabilities
        .iter()
        .all(|(name, capability)| match name.as_str() {
            "experimental" => valid_experimental_capability(capability),
            "roots" => valid_roots_capability(capability),
            "sampling" => valid_capability_fields(capability, &["context", "tools"]),
            "elicitation" => valid_capability_fields(capability, &["form", "url"]),
            "extensions" => capability.as_object().is_some_and(|extensions| {
                extensions.iter().all(|(identifier, settings)| {
                    valid_prefixed_metadata_key(identifier) && settings.is_object()
                })
            }),
            _ => true,
        })
}

fn bounded_capabilities(value: &Value) -> Option<&Map<String, Value>> {
    let capabilities = value.as_object()?;
    (capabilities.len() <= 64
        && serde_json::to_vec(capabilities).is_ok_and(|encoded| encoded.len() <= 65_536))
    .then_some(capabilities)
}

fn valid_experimental_capability(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|entries| entries.values().all(Value::is_object))
}

fn valid_roots_capability(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|fields| fields.get("listChanged").is_none_or(Value::is_boolean))
}

fn valid_capability_fields(value: &Value, allowed: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields
            .iter()
            .all(|(name, value)| !allowed.contains(&name.as_str()) || value.is_object())
    })
}

fn valid_tasks_capability(value: &Value) -> bool {
    let Some(tasks) = value.as_object() else {
        return false;
    };
    if ["cancel", "list"]
        .into_iter()
        .any(|field| tasks.get(field).is_some_and(|value| !value.is_object()))
    {
        return false;
    }
    tasks.get("requests").is_none_or(|requests| {
        requests.as_object().is_some_and(|requests| {
            requests
                .get("elicitation")
                .is_none_or(|value| valid_capability_fields(value, &["create"]))
                && requests
                    .get("sampling")
                    .is_none_or(|value| valid_capability_fields(value, &["createMessage"]))
        })
    })
}

fn valid_prefixed_metadata_key(key: &str) -> bool {
    key.contains('/') && valid_metadata_key(key)
}

fn valid_implementation_identity(value: &Value) -> bool {
    let Some(identity) = value.as_object() else {
        return false;
    };
    if !valid_base_implementation_identity(identity) {
        return false;
    }
    if ["title", "description", "websiteUrl"]
        .into_iter()
        .any(|field| identity.get(field).is_some_and(|value| !value.is_string()))
    {
        return false;
    }
    identity.get("icons").is_none_or(|icons| {
        icons
            .as_array()
            .is_some_and(|icons| icons.iter().all(valid_icon))
    })
}

fn valid_initialize_implementation_identity(revision: ProtocolRevision, value: &Value) -> bool {
    let Some(identity) = value.as_object() else {
        return false;
    };
    if !valid_base_implementation_identity(identity) {
        return false;
    }
    match revision {
        ProtocolRevision::V2024_11_05 => true,
        ProtocolRevision::V2025_06_18 => identity.get("title").is_none_or(Value::is_string),
        ProtocolRevision::V2025_11_25 | ProtocolRevision::V2026_07_28 => {
            valid_implementation_identity(value)
        }
    }
}

fn valid_base_implementation_identity(identity: &Map<String, Value>) -> bool {
    ["name", "version"]
        .into_iter()
        .all(|field| identity.get(field).is_some_and(Value::is_string))
}

fn valid_icon(value: &Value) -> bool {
    let Some(icon) = value.as_object() else {
        return false;
    };
    if !icon.get("src").is_some_and(Value::is_string) {
        return false;
    }
    if icon.get("mimeType").is_some_and(|value| !value.is_string()) {
        return false;
    }
    if icon.get("sizes").is_some_and(|sizes| {
        !sizes
            .as_array()
            .is_some_and(|sizes| sizes.iter().all(Value::is_string))
    }) {
        return false;
    }
    !icon
        .get("theme")
        .is_some_and(|theme| !matches!(theme.as_str(), Some("light" | "dark")))
}

fn valid_traceparent(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 55
        || bytes.get(2) != Some(&b'-')
        || bytes.get(35) != Some(&b'-')
        || bytes.get(52) != Some(&b'-')
        || !bytes[0..2].iter().copied().all(is_lower_hex)
        || !bytes[3..35].iter().copied().all(is_lower_hex)
        || !bytes[36..52].iter().copied().all(is_lower_hex)
        || !bytes[53..55].iter().copied().all(is_lower_hex)
        || &bytes[0..2] == b"ff"
        || bytes[3..35].iter().all(|byte| *byte == b'0')
        || bytes[36..52].iter().all(|byte| *byte == b'0')
    {
        return false;
    }

    if &bytes[0..2] == b"00" {
        bytes.len() == 55
    } else {
        bytes.len() == 55 || bytes.get(55) == Some(&b'-')
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn valid_tracestate(value: &str) -> bool {
    let members: Vec<&str> = value.split(',').collect();
    if !(1..=32).contains(&members.len()) {
        return false;
    }
    let mut keys = HashSet::new();
    for raw_member in members {
        let member = trim_ows(raw_member);
        if member.is_empty() {
            return false;
        }
        let Some((key, value)) = member.split_once('=') else {
            return false;
        };
        if !valid_tracestate_key(key) || !valid_tracestate_value(value) || !keys.insert(key) {
            return false;
        }
    }
    true
}

fn valid_tracestate_key(key: &str) -> bool {
    if let Some((tenant_id, system_id)) = key.split_once('@') {
        !tenant_id.contains('@')
            && !system_id.contains('@')
            && valid_tracestate_identifier(tenant_id, 241, true)
            && valid_tracestate_identifier(system_id, 14, false)
    } else {
        valid_tracestate_identifier(key, 256, false)
    }
}

fn valid_tracestate_identifier(value: &str, maximum: usize, digit_start: bool) -> bool {
    let bytes = value.as_bytes();
    (1..=maximum).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || (digit_start && bytes[0].is_ascii_digit()))
        && bytes.iter().copied().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'*' | b'/')
        })
}

fn valid_tracestate_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=256).contains(&bytes.len())
        && bytes.last().is_some_and(|byte| *byte != b' ')
        && bytes
            .iter()
            .copied()
            .all(|byte| (0x20..=0x7e).contains(&byte) && !matches!(byte, b',' | b'='))
}

fn valid_baggage(value: &str) -> bool {
    if value.len() > 8_192 {
        return false;
    }
    let members: Vec<&str> = value.split(',').collect();
    (1..=64).contains(&members.len())
        && members
            .into_iter()
            .all(|member| valid_baggage_member(trim_ows(member)))
}

fn valid_baggage_member(member: &str) -> bool {
    let mut parts = member.split(';');
    parts
        .next()
        .is_some_and(|pair| valid_baggage_pair(pair, false))
        && parts.all(|property| valid_baggage_pair(property, true))
}

fn valid_baggage_pair(part: &str, key_only_allowed: bool) -> bool {
    let part = trim_ows(part);
    match part.split_once('=') {
        Some((key, value)) => {
            valid_http_token(trim_ows(key)) && valid_baggage_value(trim_ows(value))
        }
        None => key_only_allowed && valid_http_token(part),
    }
}

fn valid_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_baggage_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !matches!(
            byte,
            0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e
        ) {
            return false;
        }
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActiveProjectContext {
    project: String,
    topics: Vec<String>,
    memories: Vec<ResourceMemory>,
    truncated: bool,
    truncation_reasons: Vec<&'static str>,
    omitted_at_least: usize,
    budget: ResourceBudget,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceMemory {
    id: String,
    topic: String,
    summary: String,
    importance: String,
    weight: f32,
    updated_at: String,
    field_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceBudget {
    max_portable_tokens: usize,
    used_portable_tokens: usize,
    algorithm: &'static str,
}

fn active_project_context(store: &Store, project: &str) -> IcmResult<String> {
    let mut context = empty_resource_context(project);
    let topic_refs = context
        .topics
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let fetched = store.get_by_topics_limited(&topic_refs, RESOURCE_ROW_LIMIT + 1)?;
    let fetched_count = fetched.len();
    let memories = fetched
        .into_iter()
        .take(RESOURCE_ROW_LIMIT)
        .map(resource_memory)
        .collect::<Vec<_>>();
    let field_limited = memories.iter().any(|memory| memory.field_truncated);
    let row_limited = fetched_count > RESOURCE_ROW_LIMIT;
    let mut truncation_reasons = Vec::new();
    if row_limited {
        truncation_reasons.push("rowLimit");
    }
    if field_limited {
        truncation_reasons.push("fieldLimit");
    }
    context.omitted_at_least = fetched_count.saturating_sub(memories.len());
    context.truncated = !truncation_reasons.is_empty();
    context.truncation_reasons = truncation_reasons;
    context.memories = memories;

    loop {
        let text = serialize_resource_context(&mut context)?;
        if text.len() <= RESOURCE_MAX_BYTES {
            return Ok(text);
        }
        if !context.truncation_reasons.contains(&"tokenBudget") {
            context.truncation_reasons.push("tokenBudget");
        }
        context.truncated = true;
        if context.memories.pop().is_none() {
            return Err(IcmError::InvalidInput(
                "active-project resource metadata exceeds its fixed budget".into(),
            ));
        }
        context.omitted_at_least = fetched_count.saturating_sub(context.memories.len());
    }
}

fn empty_resource_context(project: &str) -> ActiveProjectContext {
    ActiveProjectContext {
        project: project.into(),
        topics: vec![
            format!("context-{project}"),
            format!("contexte-{project}"),
            format!("decisions-{project}"),
        ],
        memories: Vec::new(),
        truncated: false,
        truncation_reasons: Vec::new(),
        omitted_at_least: 0,
        budget: ResourceBudget {
            max_portable_tokens: RESOURCE_MAX_BYTES,
            used_portable_tokens: 0,
            algorithm: "utf8-bytes-v1",
        },
    }
}

fn resource_memory(memory: Memory) -> ResourceMemory {
    let (id, id_truncated) = truncate_resource_field(&memory.id);
    let (summary, summary_truncated) = truncate_resource_field(&memory.summary);
    ResourceMemory {
        id,
        topic: memory.topic,
        summary,
        importance: memory.importance.to_string(),
        weight: memory.weight,
        updated_at: memory.updated_at.to_rfc3339(),
        field_truncated: id_truncated || summary_truncated,
    }
}

fn truncate_resource_field(value: &str) -> (String, bool) {
    if value.len() <= RESOURCE_FIELD_BYTES {
        return (value.into(), false);
    }
    let mut end = RESOURCE_FIELD_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].into(), true)
}

fn serialize_resource_context(context: &mut ActiveProjectContext) -> IcmResult<String> {
    loop {
        let text = serde_json::to_string_pretty(context)?;
        let used = text.len();
        if context.budget.used_portable_tokens == used {
            return Ok(text);
        }
        context.budget.used_portable_tokens = used;
    }
}

fn valid_resource_project(project: &str) -> bool {
    if project.is_empty()
        || project.len() > 246
        || project.trim() != project
        || project.chars().any(char::is_control)
    {
        return false;
    }
    serialize_resource_context(&mut empty_resource_context(project))
        .is_ok_and(|text| text.len() <= RESOURCE_MAX_BYTES)
}

fn server_info() -> Value {
    json!({ "name": SERVER_NAME, "version": SERVER_VERSION })
}

fn project_result(
    revision: ProtocolRevision,
    mut value: Value,
    cache: Option<(u64, &'static str)>,
) -> Value {
    if revision != ProtocolRevision::V2026_07_28 {
        return value;
    }
    let object = value
        .as_object_mut()
        .expect("MCP result projections must have object roots");
    object.insert("resultType".into(), Value::String("complete".into()));
    let metadata = object
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    let metadata = metadata
        .as_object_mut()
        .expect("MCP result metadata must have an object root");
    metadata.insert(META_SERVER_INFO.into(), server_info());
    if let Some((ttl_ms, scope)) = cache {
        object.insert("ttlMs".into(), json!(ttl_ms));
        object.insert("cacheScope".into(), Value::String(scope.into()));
    }
    value
}

fn discovery_result() -> Value {
    project_result(
        ProtocolRevision::V2026_07_28,
        json!({
            "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
            "capabilities": { "tools": {}, "resources": {} },
            "instructions": ICM_INSTRUCTIONS,
        }),
        Some((3_600_000, "private")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use icm_core::{Importance, Memory, MemoryStore};

    fn service(store: &Store) -> McpService<'_> {
        McpService::new(store, None, false, AutoConsolidate::default())
    }

    fn request(value: Value) -> JsonRpcMessage {
        serde_json::from_value(value).unwrap()
    }

    fn initialize_response(
        service: &McpService<'_>,
        state: &mut ConnectionState,
        protocol_version: &str,
        capabilities: Value,
        client_info: Value,
    ) -> JsonRpcResponse {
        service
            .handle(
                state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"initialize",
                    "params":{
                        "protocolVersion":protocol_version,
                        "capabilities":capabilities,
                        "clientInfo":client_info
                    }
                })),
            )
            .unwrap()
    }

    fn initialize_2025(service: &McpService<'_>, state: &mut ConnectionState) {
        service.handle(
            state,
            request(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );
        assert!(service
            .handle(
                state,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                })),
            )
            .is_none());
    }

    fn initialized_state_for_revision(
        service: &McpService<'_>,
        revision: ProtocolRevision,
    ) -> ConnectionState {
        assert_ne!(revision, ProtocolRevision::V2026_07_28);
        let mut state = ConnectionState::default();
        let response = initialize_response(
            service,
            &mut state,
            revision.as_str(),
            json!({}),
            json!({"name":"test","version":"1"}),
        );
        assert!(response.error.is_none());
        if revision != ProtocolRevision::V2024_11_05 {
            assert!(service
                .handle(
                    &mut state,
                    request(json!({
                        "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                    })),
                )
                .is_none());
        }
        state
    }

    fn modern_metadata() -> Value {
        json!({
            META_PROTOCOL_VERSION: "2026-07-28",
            META_CLIENT_CAPABILITIES: {}
        })
    }

    #[test]
    fn frozen_2024_is_ready_without_initialized_notification() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        let initialized = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"initialize",
                    "params":{
                        "protocolVersion":"2024-11-05","capabilities":{},
                        "clientInfo":{"name":"test","version":"1"}
                    }
                })),
            )
            .unwrap();
        assert_eq!(initialized.result.unwrap()["protocolVersion"], "2024-11-05");
        let listed = service
            .handle(
                &mut state,
                request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})),
            )
            .unwrap();
        assert!(listed.result.unwrap()["tools"].is_array());
    }

    #[test]
    fn poisoned_lifecycle_state_does_not_retain_or_reemit_oversized_method_names() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        let oversized_method = "m".repeat(MAX_STORED_LIFECYCLE_METHOD_BYTES + 1);

        let first = service
            .handle(
                &mut state,
                JsonRpcMessage {
                    jsonrpc: "2.0".into(),
                    id: Some(json!(1)),
                    method: Some(oversized_method),
                    params: Some(json!({})),
                    extra: Map::new(),
                },
            )
            .unwrap();
        let first_method = first
            .error
            .as_ref()
            .and_then(|error| error.data.as_ref())
            .and_then(|data| data.get("method"))
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(
            first_method,
            format!(
                "<method omitted: {} bytes>",
                MAX_STORED_LIFECYCLE_METHOD_BYTES + 1
            )
        );

        let repeated = service
            .handle(
                &mut state,
                request(json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}})),
            )
            .unwrap();
        let encoded = serde_json::to_vec(&repeated).unwrap();
        assert!(
            encoded.len() < 1_024,
            "poisoned response was {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn initialized_2025_requires_notification() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        service.handle(
            &mut state,
            request(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );
        let response = service
            .handle(
                &mut state,
                request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})),
            )
            .unwrap();
        assert_eq!(response.error.unwrap().code, -31011);
    }

    #[test]
    fn initialize_2025_validates_request_metadata_before_state_transition() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();

        for (id, metadata) in [
            (1, json!([])),
            (2, json!({"progressToken":{"wrong":"type"}})),
        ] {
            let response = service
                .handle(
                    &mut state,
                    request(json!({
                        "jsonrpc":"2.0","id":id,"method":"initialize",
                        "params":{
                            "protocolVersion":"2025-11-25",
                            "capabilities":{},
                            "clientInfo":{"name":"test","version":"1"},
                            "_meta":metadata
                        }
                    })),
                )
                .unwrap();
            assert_eq!(response.error.unwrap().code, -32602);
            assert!(matches!(state.phase, ConnectionPhase::Uninitialized));
        }

        let valid = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"initialize",
                    "params":{
                        "protocolVersion":"2025-11-25",
                        "capabilities":{},
                        "clientInfo":{"name":"test","version":"1"},
                        "_meta":{"progressToken":"initializing"}
                    }
                })),
            )
            .unwrap();
        assert_eq!(valid.result.unwrap()["protocolVersion"], "2025-11-25");
        assert!(matches!(
            state.phase,
            ConnectionPhase::LegacyAwaitingInitialized(ProtocolRevision::V2025_11_25)
        ));
    }

    #[test]
    fn initialize_capabilities_use_the_negotiated_revision_schema() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);

        let mut june_state = ConnectionState::default();
        let june = initialize_response(
            &service,
            &mut june_state,
            "2025-06-18",
            json!({
                "experimental":{"future":{}},
                "roots":{"listChanged":true,"future":5},
                "sampling":{"tools":5},
                "elicitation":{"form":5},
                "futureCapability":5
            }),
            json!({"name":"test","version":"1"}),
        );
        assert_eq!(june.result.unwrap()["protocolVersion"], "2025-06-18");
        assert!(matches!(
            june_state.phase,
            ConnectionPhase::LegacyAwaitingInitialized(ProtocolRevision::V2025_06_18)
        ));

        let mut november_state = ConnectionState::default();
        let november = initialize_response(
            &service,
            &mut november_state,
            "2025-11-25",
            json!({"sampling":{"tools":5}}),
            json!({"name":"test","version":"1"}),
        );
        assert_eq!(november.error.unwrap().code, -32602);
        assert!(matches!(
            november_state.phase,
            ConnectionPhase::Uninitialized
        ));

        let mut legacy_state = ConnectionState::default();
        let legacy = initialize_response(
            &service,
            &mut legacy_state,
            "2024-11-05",
            json!({
                "sampling":{"tools":5},
                "elicitation":5,
                "futureCapability":[1,2,3]
            }),
            json!({"name":"test","version":"1"}),
        );
        assert_eq!(legacy.result.unwrap()["protocolVersion"], "2024-11-05");
        assert!(matches!(
            legacy_state.phase,
            ConnectionPhase::LegacyReady {
                revision: ProtocolRevision::V2024_11_05,
                initialized_seen: false
            }
        ));

        for (revision, capabilities) in [
            ("2024-11-05", json!({"roots":{"listChanged":"yes"}})),
            ("2025-06-18", json!({"elicitation":5})),
            ("2025-11-25", json!({"experimental":{"future":5}})),
        ] {
            let mut state = ConnectionState::default();
            let response = initialize_response(
                &service,
                &mut state,
                revision,
                capabilities,
                json!({"name":"test","version":"1"}),
            );
            assert_eq!(response.error.unwrap().code, -32602);
            assert!(matches!(state.phase, ConnectionPhase::Uninitialized));
        }
    }

    #[test]
    fn initialize_2025_11_validates_tasks_capability_shapes() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);

        let mut valid_state = ConnectionState::default();
        let valid = initialize_response(
            &service,
            &mut valid_state,
            "2025-11-25",
            json!({
                "tasks":{
                    "cancel":{"future":5},
                    "list":{},
                    "requests":{
                        "elicitation":{"create":{},"future":5},
                        "sampling":{"createMessage":{},"future":false},
                        "future":5
                    },
                    "future":true
                }
            }),
            json!({"name":"test","version":"1"}),
        );
        assert!(valid.error.is_none());
        assert!(matches!(
            valid_state.phase,
            ConnectionPhase::LegacyAwaitingInitialized(ProtocolRevision::V2025_11_25)
        ));

        for malformed_tasks in [
            json!(5),
            json!({"cancel":5}),
            json!({"list":"yes"}),
            json!({"requests":5}),
            json!({"requests":{"elicitation":5}}),
            json!({"requests":{"elicitation":{"create":5}}}),
            json!({"requests":{"sampling":5}}),
            json!({"requests":{"sampling":{"createMessage":5}}}),
        ] {
            let mut state = ConnectionState::default();
            let response = initialize_response(
                &service,
                &mut state,
                "2025-11-25",
                json!({"tasks":malformed_tasks}),
                json!({"name":"test","version":"1"}),
            );
            assert_eq!(response.error.unwrap().code, -32602);
            assert!(matches!(state.phase, ConnectionPhase::Uninitialized));
        }

        let mut june_state = ConnectionState::default();
        let june = initialize_response(
            &service,
            &mut june_state,
            "2025-06-18",
            json!({"tasks":5}),
            json!({"name":"test","version":"1"}),
        );
        assert!(june.error.is_none());
        assert!(matches!(
            june_state.phase,
            ConnectionPhase::LegacyAwaitingInitialized(ProtocolRevision::V2025_06_18)
        ));
    }

    #[test]
    fn initialize_identity_fields_are_revision_specific() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);

        let mut legacy_state = ConnectionState::default();
        let legacy = initialize_response(
            &service,
            &mut legacy_state,
            "2024-11-05",
            json!({}),
            json!({
                "name":"test","version":"1","title":5,"description":5,"icons":5
            }),
        );
        assert!(legacy.error.is_none());
        assert!(matches!(
            legacy_state.phase,
            ConnectionPhase::LegacyReady {
                revision: ProtocolRevision::V2024_11_05,
                initialized_seen: false
            }
        ));

        let mut june_state = ConnectionState::default();
        let june = initialize_response(
            &service,
            &mut june_state,
            "2025-06-18",
            json!({}),
            json!({"name":"test","version":"1","title":"Test","description":5}),
        );
        assert!(june.error.is_none());

        let mut malformed_june_state = ConnectionState::default();
        let malformed_june = initialize_response(
            &service,
            &mut malformed_june_state,
            "2025-06-18",
            json!({}),
            json!({"name":"test","version":"1","title":5}),
        );
        assert_eq!(malformed_june.error.unwrap().code, -32602);
        assert!(matches!(
            malformed_june_state.phase,
            ConnectionPhase::Uninitialized
        ));

        let mut november_state = ConnectionState::default();
        let november = initialize_response(
            &service,
            &mut november_state,
            "2025-11-25",
            json!({}),
            json!({"name":"test","version":"1","description":5}),
        );
        assert_eq!(november.error.unwrap().code, -32602);
        assert!(matches!(
            november_state.phase,
            ConnectionPhase::Uninitialized
        ));

        let mut unknown_state = ConnectionState::default();
        let malformed_unknown = initialize_response(
            &service,
            &mut unknown_state,
            "2099-01-01",
            json!({}),
            json!({"name":"test","version":"1","description":5}),
        );
        assert_eq!(malformed_unknown.error.unwrap().code, -32602);
        assert!(matches!(
            unknown_state.phase,
            ConnectionPhase::Uninitialized
        ));

        let negotiated_unknown = initialize_response(
            &service,
            &mut unknown_state,
            "2099-01-01",
            json!({"sampling":{"tools":{}}}),
            json!({"name":"test","version":"1","description":"valid"}),
        );
        assert_eq!(
            negotiated_unknown.result.unwrap()["protocolVersion"],
            "2025-11-25"
        );
        assert!(matches!(
            unknown_state.phase,
            ConnectionPhase::LegacyAwaitingInitialized(ProtocolRevision::V2025_11_25)
        ));

        let mut modern_state = ConnectionState::default();
        let modern = initialize_response(
            &service,
            &mut modern_state,
            "2026-07-28",
            json!(5),
            json!(5),
        );
        let modern_error = modern.error.unwrap();
        assert_eq!(modern_error.code, -32602);
        assert!(modern_error.message.contains("does not use initialize"));
        assert!(matches!(modern_state.phase, ConnectionPhase::Uninitialized));
    }

    #[test]
    fn malformed_initialized_notifications_do_not_advance_or_poison_state() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);

        let mut still_awaiting = ConnectionState::default();
        service.handle(
            &mut still_awaiting,
            request(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );
        assert!(service
            .handle(
                &mut still_awaiting,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/initialized","params":[]
                })),
            )
            .is_none());
        let required = service
            .handle(
                &mut still_awaiting,
                request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})),
            )
            .unwrap();
        assert_eq!(required.error.as_ref().unwrap().code, -31011);
        assert_eq!(
            required.error.unwrap().data.unwrap()["kind"],
            "initialized-notification-required"
        );

        let mut recoverable = ConnectionState::default();
        service.handle(
            &mut recoverable,
            request(json!({
                "jsonrpc":"2.0","id":3,"method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );
        assert!(service
            .handle(
                &mut recoverable,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/initialized",
                    "params":{"_meta":[]}
                })),
            )
            .is_none());
        assert!(service
            .handle(
                &mut recoverable,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                })),
            )
            .is_none());
        let listed = service
            .handle(
                &mut recoverable,
                request(json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}})),
            )
            .unwrap();
        assert!(listed.error.is_none());
    }

    #[test]
    fn initialized_2025_allows_progress_only_request_metadata() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        service.handle(
            &mut state,
            request(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );
        assert!(service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                })),
            )
            .is_none());
        let response = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/list",
                    "params":{"_meta":{"progressToken":1}}
                })),
            )
            .unwrap();
        assert!(response.error.is_none());
        assert!(response.result.unwrap()["tools"].is_array());
    }

    #[test]
    fn initialized_2025_validates_optional_metadata_without_switching_era() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        initialize_2025(&service, &mut state);

        let malformed = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/list",
                    "params":{"_meta":[]}
                })),
            )
            .unwrap();
        assert_eq!(malformed.error.unwrap().code, -32602);

        let valid = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/list",
                    "params":{"_meta":{
                        "progressToken":1.5,
                        "com.example/evaluation":{"opaque":true},
                        "foo":1,
                        "arbitrary":[{"nested":true}]
                    }}
                })),
            )
            .unwrap();
        assert!(valid.error.is_none());
    }

    #[test]
    fn discovery_accepts_optional_client_info() {
        let store = Store::in_memory().unwrap();
        let initialized_service = service(&store);
        let mut state = ConnectionState::default();
        let response = initialized_service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"server/discover",
                    "params":{"_meta":{
                        META_PROTOCOL_VERSION:"2026-07-28",
                        META_CLIENT_CAPABILITIES:{}
                    }}
                })),
            )
            .unwrap();
        let result = response.result.unwrap();
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["_meta"][META_SERVER_INFO]["name"], SERVER_NAME);
    }

    #[test]
    fn malformed_2026_identity_does_not_lock_the_connection() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        let malformed = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"server/discover",
                    "params":{"_meta":{
                        META_PROTOCOL_VERSION:"2026-07-28",
                        META_CLIENT_CAPABILITIES:{},
                        META_CLIENT_INFO:{
                            "name":"test","version":"1","icons":"not-an-array"
                        }
                    }}
                })),
            )
            .unwrap();
        assert_eq!(malformed.error.unwrap().code, -32602);

        let valid = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"server/discover",
                    "params":{"_meta":modern_metadata()}
                })),
            )
            .unwrap();
        assert!(valid.error.is_none());
    }

    #[test]
    fn client_capabilities_are_open_but_validate_known_final_shapes() {
        let store = Store::in_memory().unwrap();
        let initialized_service = service(&store);
        let mut state = ConnectionState::default();
        let response = initialized_service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"initialize",
                    "params":{
                        "protocolVersion":"2025-11-25",
                        "capabilities":{"tools":{},"resources":{}},
                        "clientInfo":{"name":"test","version":"1"}
                    }
                })),
            )
            .unwrap();
        assert_eq!(response.result.unwrap()["protocolVersion"], "2025-11-25");

        let modern_store = Store::in_memory().unwrap();
        let modern_service = service(&modern_store);
        let mut modern_state = ConnectionState::default();
        let modern = modern_service
            .handle(
                &mut modern_state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"server/discover",
                    "params":{"_meta":{
                        META_PROTOCOL_VERSION:"2026-07-28",
                        META_CLIENT_CAPABILITIES:{
                            "sampling":{"context":{},"tools":{},"future":5},
                            "elicitation":{"form":{},"url":{},"future":false},
                            "experimental":{"x":{}},
                            "unknownCapability":5,
                            "extensions":{"com.example/feature":{}}
                        }
                    }}
                })),
            )
            .unwrap();
        assert!(modern.error.is_none());

        for capabilities in [
            json!({"sampling":{"tools":5}}),
            json!({"elicitation":{"form":"yes"}}),
            json!({"experimental":{"x":5}}),
            json!({"extensions":{"unprefixed":{}}}),
            json!({"extensions":{"com.example/feature":5}}),
            json!({"roots":5}),
            json!({"roots":{"listChanged":"yes"}}),
        ] {
            assert!(!valid_client_capabilities(&capabilities));
        }
        assert!(valid_client_capabilities(&json!({
            "sampling":{"unknown":5},
            "elicitation":{"unknown":"opaque"},
            "unknownCapability":[1,2,3]
        })));
    }

    #[test]
    fn modern_metadata_reuses_the_legacy_nesting_bound() {
        let mut nested = Value::Null;
        for _ in 0..32 {
            nested = json!({"next": nested});
        }
        let mut metadata = Map::from_iter([("future".to_owned(), nested)]);
        assert!(validate_metadata_shape(&Value::Null, &metadata).is_ok());

        let nested = metadata.remove("future").unwrap();
        metadata.insert("future".into(), json!({"next": nested}));
        assert!(validate_metadata_shape(&Value::Null, &metadata).is_err());
    }

    #[test]
    fn implementation_identity_validates_final_field_types_without_invented_bounds() {
        assert!(valid_implementation_identity(&json!({
            "name":"",
            "version":"",
            "title":"",
            "description":"",
            "websiteUrl":"not interpreted as a URI by structural validation",
            "icons":[{
                "src":"data:,",
                "mimeType":"",
                "sizes":["", "not-a-size"],
                "theme":"dark",
                "future":{"opaque":true}
            }],
            "futureField":5
        })));
        for identity in [
            json!({"name":"test"}),
            json!({"name":5,"version":"1"}),
            json!({"name":"test","version":"1","description":5}),
            json!({"name":"test","version":"1","icons":[{}]}),
            json!({"name":"test","version":"1","icons":[{"src":"x","sizes":[5]}]}),
            json!({"name":"test","version":"1","icons":[{"src":"x","theme":"auto"}]}),
        ] {
            assert!(!valid_implementation_identity(&identity));
        }
    }

    #[test]
    fn metadata_keys_follow_the_final_optional_prefix_grammar() {
        for key in [
            "",
            "progressToken",
            "traceparent",
            "tracestate",
            "baggage",
            "invalid",
            "vendor_hint",
            "io.modelcontextprotocol/futureField",
            "dev.mcp/future",
            "com.example/key_name.v2",
            "com.example/",
        ] {
            assert!(
                valid_metadata_key(key),
                "expected valid metadata key: {key}"
            );
        }

        for key in [
            "1bad/foo",
            "bad_/foo",
            "bad-/foo",
            ".bad/foo",
            "bad..name/foo",
            "/foo",
            "com.example/_bad",
            "com.example/-bad",
            "com.example/.bad",
            "com.example/bad_",
            "com.example/bad-",
            "com.example/bad.",
            "com.example/bad/extra",
            "com.example/💥",
        ] {
            assert!(
                !valid_metadata_key(key),
                "expected invalid metadata key: {key}"
            );
        }
    }

    #[test]
    fn opaque_metadata_and_subscription_ids_do_not_change_dispatch() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        assert!(service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"server/discover",
                    "params":{"_meta":modern_metadata()}
                })),
            )
            .unwrap()
            .error
            .is_none());

        let baseline = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"ping",
                    "params":{"_meta":modern_metadata()}
                })),
            )
            .unwrap()
            .result
            .unwrap();

        let mut enriched_metadata = modern_metadata();
        let enriched = enriched_metadata.as_object_mut().unwrap();
        enriched.insert("invalid".into(), json!({"opaque":true}));
        enriched.insert("vendor_hint".into(), json!([1, 2, 3]));
        enriched.insert(
            "io.modelcontextprotocol/futureField".into(),
            json!({"mustNotAuthorize":true}),
        );
        enriched.insert("dev.mcp/future".into(), Value::Bool(true));
        enriched.insert("com.example/key_name.v2".into(), Value::Null);
        enriched.insert("com.example/".into(), json!("empty-name"));
        enriched.insert(MODERN_SUBSCRIPTION_ID_KEY.into(), json!("subscription"));
        let enriched_result = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"ping",
                    "params":{"_meta":enriched_metadata}
                })),
            )
            .unwrap()
            .result
            .unwrap();
        assert_eq!(enriched_result, baseline);

        let mut integer_subscription = modern_metadata();
        integer_subscription
            .as_object_mut()
            .unwrap()
            .insert(MODERN_SUBSCRIPTION_ID_KEY.into(), json!(42));
        assert!(service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":4,"method":"ping",
                    "params":{"_meta":integer_subscription}
                })),
            )
            .unwrap()
            .error
            .is_none());

        for (id, invalid_subscription) in [(5, json!(1.5)), (6, json!(true)), (7, json!({}))] {
            let mut metadata = modern_metadata();
            metadata
                .as_object_mut()
                .unwrap()
                .insert(MODERN_SUBSCRIPTION_ID_KEY.into(), invalid_subscription);
            let rejected = service
                .handle(
                    &mut state,
                    request(json!({
                        "jsonrpc":"2.0","id":id,"method":"ping",
                        "params":{"_meta":metadata}
                    })),
                )
                .unwrap();
            assert_eq!(rejected.error.unwrap().code, -32602);
        }

        let mut invalid_key = modern_metadata();
        invalid_key
            .as_object_mut()
            .unwrap()
            .insert("1bad/foo".into(), Value::Null);
        let rejected = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":8,"method":"ping",
                    "params":{"_meta":invalid_key}
                })),
            )
            .unwrap();
        assert_eq!(rejected.error.unwrap().code, -32602);
    }

    #[test]
    fn modern_tracing_metadata_is_w3c_validated_and_typed() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        let accepted = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"server/discover",
                    "params":{"_meta":{
                        META_PROTOCOL_VERSION:"2026-07-28",
                        META_CLIENT_CAPABILITIES:{},
                        "traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                        "tracestate":"vendor=value",
                        "baggage":"project=icm"
                    }}
                })),
            )
            .unwrap();
        assert!(accepted.error.is_none());

        let rejected = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"ping",
                    "params":{"_meta":{
                        META_PROTOCOL_VERSION:"2026-07-28",
                        META_CLIENT_CAPABILITIES:{},
                        "traceparent":{"wrong":"type"}
                    }}
                })),
            )
            .unwrap();
        assert_eq!(rejected.error.unwrap().code, -32602);
    }

    #[test]
    fn w3c_trace_context_and_baggage_boundaries_are_exact() {
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let parent_id = "00f067aa0ba902b7";
        let current = format!("00-{trace_id}-{parent_id}-01");
        assert!(valid_traceparent(&current));
        assert!(valid_traceparent(&format!("01-{trace_id}-{parent_id}-01")));
        assert!(valid_traceparent(&format!(
            "01-{trace_id}-{parent_id}-01-future-fields-are-opaque"
        )));
        for invalid in [
            format!("ff-{trace_id}-{parent_id}-01"),
            format!("00-{}-{parent_id}-01", "0".repeat(32)),
            format!("00-{trace_id}-{}-01", "0".repeat(16)),
            format!("00-{trace_id}-{parent_id}-0A"),
            format!("00-{}-{parent_id}-01", trace_id.to_ascii_uppercase()),
            format!("00-{trace_id}-{parent_id}-01-extra"),
            format!("01-{trace_id}-{parent_id}-01extra"),
        ] {
            assert!(
                !valid_traceparent(&invalid),
                "accepted invalid traceparent: {invalid}"
            );
        }

        assert!(valid_tracestate("vendor=value"));
        assert!(valid_tracestate("1tenant@system=value"));
        assert!(valid_tracestate(&format!(
            "one={},two={},three={}",
            "a".repeat(200),
            "b".repeat(200),
            "c".repeat(200)
        )));
        assert!(valid_tracestate(&format!("{}@s=value", "1".repeat(241))));
        assert!(valid_tracestate(&format!(
            "tenant@{}=value",
            "s".repeat(14)
        )));
        assert!(valid_tracestate(&format!("vendor={}", "v".repeat(256))));
        let thirty_two_members = (0..32)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(valid_tracestate(&thirty_two_members));

        for invalid in [
            "".to_owned(),
            " \t ".to_owned(),
            ",vendor=value".to_owned(),
            "vendor=value,".to_owned(),
            "one=value,,two=value".to_owned(),
            "1simple=value".to_owned(),
            "a@@b=value".to_owned(),
            "a@1bad=value".to_owned(),
            format!("{}@s=value", "1".repeat(242)),
            format!("tenant@{}=value", "s".repeat(15)),
            "duplicate=one,duplicate=two".to_owned(),
            format!("vendor={}", "v".repeat(257)),
            "vendor=bad=value".to_owned(),
            "vendor=bad\nvalue".to_owned(),
            (0..33)
                .map(|index| format!("k{index}=v"))
                .collect::<Vec<_>>()
                .join(","),
        ] {
            assert!(
                !valid_tracestate(&invalid),
                "accepted invalid tracestate: {invalid}"
            );
        }

        assert!(valid_baggage("key="));
        assert!(valid_baggage(
            "key=value;property;second=x%20y, other = value"
        ));
        assert!(valid_baggage(&format!("k={}", "a".repeat(8_190))));
        let sixty_four_members = (0..64)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(valid_baggage(&sixty_four_members));
        for invalid in [
            "".to_owned(),
            "key=unencoded space".to_owned(),
            "key=bad%ZZ".to_owned(),
            "key=value;".to_owned(),
            "key=\"quoted\"".to_owned(),
            format!("k={}", "a".repeat(8_191)),
            (0..65)
                .map(|index| format!("k{index}=v"))
                .collect::<Vec<_>>()
                .join(","),
        ] {
            assert!(
                !valid_baggage(&invalid),
                "accepted invalid baggage: {invalid}"
            );
        }

        for key in ["traceparent", "tracestate", "baggage"] {
            let metadata = Map::from_iter([(key.to_owned(), json!({"wrong":"type"}))]);
            assert!(validate_optional_metadata_values(&Value::Null, &metadata).is_err());
        }
    }

    #[test]
    fn modern_notifications_have_optional_metadata_and_never_poison_requests() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        assert!(service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"server/discover",
                    "params":{"_meta":modern_metadata()}
                })),
            )
            .unwrap()
            .error
            .is_none());
        assert!(service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/progress",
                    "params":{"progressToken":"work","progress":0.5}
                })),
            )
            .is_none());
        assert!(service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/cancelled",
                    "params":{"requestId":1,"reason":"test"}
                })),
            )
            .is_none());
        assert!(service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","method":"notifications/progress",
                    "params":{"_meta":[]}
                })),
            )
            .is_none());

        let response = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"ping",
                    "params":{"_meta":modern_metadata()}
                })),
            )
            .unwrap();
        assert!(response.error.is_none());
        assert_eq!(response.result.unwrap()["resultType"], "complete");
    }

    #[test]
    fn active_project_resource_is_fixed_scoped_and_bounded() {
        let store = Store::in_memory().unwrap();
        for index in 0..66 {
            let mut memory = Memory::new(
                "context-test-project".into(),
                format!(
                    "row {index:02} prompt boundary\n--- RESOURCE-FORGE --- {}",
                    "bounded ".repeat(90)
                ),
                Importance::High,
            );
            memory.id = format!("01R{index:023}");
            memory.weight = 1.0 - index as f32 / 1_000.0;
            memory.access_count = 2;
            store.store(memory).unwrap();
        }

        let mut service = service(&store);
        service.active_project = Some("test-project".into());
        let mut state = ConnectionState::default();
        let listed = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":1,"method":"resources/list",
                    "params":{"_meta":{
                        META_PROTOCOL_VERSION:"2026-07-28",
                        META_CLIENT_CAPABILITIES:{}
                    }}
                })),
            )
            .unwrap();
        let listed = listed.result.unwrap();
        assert_eq!(listed["ttlMs"], 3_600_000);
        assert_eq!(listed["cacheScope"], "private");
        assert_eq!(listed["resources"][0]["uri"], ACTIVE_PROJECT_CONTEXT_URI);
        assert_eq!(listed["resources"][0]["mimeType"], "application/json");

        let mut state_2025 =
            initialized_state_for_revision(&service, ProtocolRevision::V2025_11_25);
        let listed_2025 = service
            .handle(
                &mut state_2025,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"resources/list","params":{}
                })),
            )
            .unwrap()
            .result
            .unwrap();
        assert_eq!(listed_2025["_meta"]["ttlMs"], 0);
        assert_eq!(listed_2025["_meta"]["cacheScope"], "private");

        let read = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"resources/read",
                    "params":{"uri":ACTIVE_PROJECT_CONTEXT_URI,"_meta":modern_metadata()}
                })),
            )
            .unwrap()
            .result
            .unwrap();
        assert_eq!(read["ttlMs"], 0);
        assert_eq!(read["cacheScope"], "private");
        let text = read["contents"][0]["text"].as_str().unwrap();
        assert!(text.len() <= RESOURCE_MAX_BYTES);
        assert!(text.contains("\\n--- RESOURCE-FORGE"));
        let context: Value = serde_json::from_str(text).unwrap();
        assert_eq!(context["project"], "test-project");
        assert_eq!(
            context["topics"],
            json!([
                "context-test-project",
                "contexte-test-project",
                "decisions-test-project"
            ])
        );
        assert_eq!(context["budget"]["usedPortableTokens"], text.len());
        assert_eq!(context["budget"]["algorithm"], "utf8-bytes-v1");
        assert_eq!(context["truncated"], true);
        for reason in ["rowLimit", "fieldLimit", "tokenBudget"] {
            assert!(context["truncationReasons"]
                .as_array()
                .unwrap()
                .contains(&json!(reason)));
        }
        assert!(context["memories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|memory| memory["fieldTruncated"] == true));
        assert_eq!(
            store
                .get("01R00000000000000000000000")
                .unwrap()
                .unwrap()
                .access_count,
            2
        );
    }

    #[test]
    fn active_project_resource_is_empty_and_cross_project_isolated_in_2025() {
        let store = Store::in_memory().unwrap();
        let mut service = service(&store);
        service.active_project = Some("test-project".into());
        let mut state = initialized_state_for_revision(&service, ProtocolRevision::V2025_11_25);

        let read = |service: &McpService<'_>, state: &mut ConnectionState, id| {
            service
                .handle(
                    state,
                    request(json!({
                        "jsonrpc":"2.0","id":id,"method":"resources/read",
                        "params":{"uri":ACTIVE_PROJECT_CONTEXT_URI}
                    })),
                )
                .unwrap()
                .result
                .unwrap()
        };
        let empty = read(&service, &mut state, 2);
        assert_eq!(empty["_meta"], json!({"ttlMs":0,"cacheScope":"private"}));
        let context: Value =
            serde_json::from_str(empty["contents"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(context["memories"], json!([]));
        assert_eq!(context["truncated"], false);

        for (topic, summary) in [
            ("context-test-project", "included"),
            ("context-other-project", "excluded project"),
            ("preferences", "excluded global"),
        ] {
            store
                .store(Memory::new(topic.into(), summary.into(), Importance::High))
                .unwrap();
        }
        let populated = read(&service, &mut state, 3);
        let context: Value =
            serde_json::from_str(populated["contents"][0]["text"].as_str().unwrap()).unwrap();
        let memories = context["memories"].as_array().unwrap();
        assert_eq!(memories.len(), 1);
        assert_eq!(memories[0]["summary"], "included");
    }

    #[test]
    fn active_project_resource_rejects_bad_uris_and_hides_internal_failures() {
        let store = Store::in_memory().unwrap();
        let mut service = service(&store);
        service.active_project = Some("test-project".into());

        let mut legacy = initialized_state_for_revision(&service, ProtocolRevision::V2024_11_05);
        let unavailable = service
            .handle(
                &mut legacy,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"resources/read",
                    "params":{"uri":ACTIVE_PROJECT_CONTEXT_URI}
                })),
            )
            .unwrap();
        assert_eq!(unavailable.error.unwrap().code, -32601);

        for (id, mut params) in [
            (3, json!({})),
            (4, json!({"uri":42})),
            (
                5,
                json!({"uri":"icm://active-project/context?unexpected=1"}),
            ),
        ] {
            params
                .as_object_mut()
                .unwrap()
                .insert("_meta".into(), modern_metadata());
            let mut modern = ConnectionState::default();
            let rejected = service
                .handle(
                    &mut modern,
                    request(json!({
                        "jsonrpc":"2.0","id":id,"method":"resources/read",
                        "params":params
                    })),
                )
                .unwrap();
            assert_eq!(rejected.error.unwrap().code, -32602);
        }

        service.active_project = Some("x".repeat(RESOURCE_MAX_BYTES));
        let mut modern = ConnectionState::default();
        let failed = service
            .handle(
                &mut modern,
                request(json!({
                    "jsonrpc":"2.0","id":6,"method":"resources/read",
                    "params":{"uri":ACTIVE_PROJECT_CONTEXT_URI,"_meta":modern_metadata()}
                })),
            )
            .unwrap();
        let error = failed.error.unwrap();
        assert_eq!(error.code, -32603);
        assert_eq!(error.message, "failed to read resource");
        assert!(error.data.is_none());
    }

    #[test]
    fn explicit_working_directory_scopes_default_recall() {
        let tmp = tempfile::tempdir().unwrap();
        let client_directory = tmp.path().join("client-project");
        std::fs::create_dir(&client_directory).unwrap();
        let store = Store::in_memory().unwrap();
        store
            .store(Memory::new(
                "context-client-project".into(),
                "shared marker from client".into(),
                Importance::High,
            ))
            .unwrap();
        store
            .store(Memory::new(
                "context-other-project".into(),
                "shared marker from other".into(),
                Importance::High,
            ))
            .unwrap();
        let service = McpService::with_working_directory(
            &store,
            None,
            false,
            AutoConsolidate::default(),
            client_directory,
        );

        let mut state = ConnectionState::default();
        initialize_2025(&service, &mut state);
        let result = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_recall",
                        "arguments":{"query":"shared marker"}
                    }
                })),
            )
            .unwrap()
            .result
            .unwrap();
        let memories = result["structuredContent"]["memories"].as_array().unwrap();
        assert_eq!(memories.len(), 1);
        assert_eq!(memories[0]["summary"], "shared marker from client");
    }

    #[test]
    fn typed_tool_input_errors_use_revision_appropriate_envelopes() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);

        for revision in [
            ProtocolRevision::V2024_11_05,
            ProtocolRevision::V2025_06_18,
            ProtocolRevision::V2025_11_25,
        ] {
            let mut state = initialized_state_for_revision(&service, revision);
            let response = service
                .handle(
                    &mut state,
                    request(json!({
                        "jsonrpc":"2.0","id":2,"method":"tools/call",
                        "params":{"name":"icm_memory_recall","arguments":{"query":"  "}}
                    })),
                )
                .unwrap();
            if revision == ProtocolRevision::V2024_11_05 {
                assert!(response.error.is_none());
                let result = response.result.unwrap();
                assert_ne!(result["isError"], true);
            } else {
                assert!(response.result.is_none());
                let error = response.error.unwrap();
                assert_eq!(error.code, -32602);
                assert!(error.message.starts_with("invalid arguments: "));
            }
        }

        let mut modern_state = ConnectionState::default();
        let modern = service
            .handle(
                &mut modern_state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_recall",
                        "arguments":{"query":"  "},
                        "_meta":modern_metadata()
                    }
                })),
            )
            .unwrap();
        assert!(modern.result.is_none());
        let modern_error = modern.error.unwrap();
        assert_eq!(modern_error.code, -32602);
        assert!(modern_error.message.starts_with("invalid arguments: "));
    }

    #[test]
    fn valid_tool_business_errors_remain_tool_results_in_every_revision() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);

        for revision in [
            ProtocolRevision::V2024_11_05,
            ProtocolRevision::V2025_06_18,
            ProtocolRevision::V2025_11_25,
        ] {
            let mut state = initialized_state_for_revision(&service, revision);
            let response = service
                .handle(
                    &mut state,
                    request(json!({
                        "jsonrpc":"2.0","id":2,"method":"tools/call",
                        "params":{
                            "name":"icm_memory_forget",
                            "arguments":{"id":"does-not-exist"}
                        }
                    })),
                )
                .unwrap();
            assert!(response.error.is_none());
            let result = response.result.unwrap();
            assert_eq!(result["isError"], true);
            assert!(result.get("resultType").is_none());
        }

        let mut modern_state = ConnectionState::default();
        let modern = service
            .handle(
                &mut modern_state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_forget",
                        "arguments":{"id":"does-not-exist"},
                        "_meta":modern_metadata()
                    }
                })),
            )
            .unwrap();
        assert!(modern.error.is_none());
        let modern_result = modern.result.unwrap();
        assert_eq!(modern_result["isError"], true);
        assert_eq!(modern_result["resultType"], "complete");
        assert_eq!(
            modern_result["_meta"][META_SERVER_INFO]["name"],
            SERVER_NAME
        );
    }

    #[test]
    fn typed_outputs_follow_the_negotiated_projection() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);

        for revision in [
            ProtocolRevision::V2024_11_05,
            ProtocolRevision::V2025_06_18,
            ProtocolRevision::V2025_11_25,
        ] {
            let mut state = initialized_state_for_revision(&service, revision);
            let result = service
                .handle(
                    &mut state,
                    request(json!({
                        "jsonrpc":"2.0","id":2,"method":"tools/call",
                        "params":{"name":"icm_memory_stats","arguments":{}}
                    })),
                )
                .unwrap()
                .result
                .unwrap();
            if revision == ProtocolRevision::V2024_11_05 {
                assert!(result["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .starts_with("Memories: 0\nTopics: 0\n"));
                assert!(result.get("structuredContent").is_none());
            } else {
                assert_eq!(result["content"][0]["text"], "Returned memory statistics.");
                assert_eq!(result["structuredContent"]["totalMemories"], 0);
            }
        }

        let mut state = ConnectionState::default();
        let result = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_stats","arguments":{},
                        "_meta":modern_metadata()
                    }
                })),
            )
            .unwrap()
            .result
            .unwrap();
        assert_eq!(result["content"][0]["text"], "Returned memory statistics.");
        assert_eq!(result["structuredContent"]["totalMemories"], 0);
        assert_eq!(result["resultType"], "complete");
    }

    #[test]
    fn topic_schema_and_runtime_enforce_the_multibyte_boundary() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        initialize_2025(&service, &mut state);

        let accepted_topic = format!("{}a", "é".repeat(127));
        assert_eq!(accepted_topic.chars().count(), 128);
        assert_eq!(accepted_topic.len(), 255);
        let accepted = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_store",
                        "arguments":{"topic":accepted_topic,"content":"valid"}
                    }
                })),
            )
            .unwrap();
        assert!(accepted.error.is_none());
        assert_ne!(accepted.result.unwrap()["isError"], true);

        let rejected_topic = "é".repeat(128);
        assert_eq!(rejected_topic.chars().count(), 128);
        assert_eq!(rejected_topic.len(), 256);
        let rejected = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_store",
                        "arguments":{"topic":rejected_topic,"content":"invalid"}
                    }
                })),
            )
            .unwrap();
        assert!(rejected.result.is_none());
        let rejected_error = rejected.error.unwrap();
        assert_eq!(rejected_error.code, -32602);
        assert!(rejected_error.message.contains("exceeds 255 UTF-8 bytes"));
    }

    #[test]
    fn recall_limit_preserves_legacy_normalization_and_modern_strictness() {
        let store = Store::in_memory().unwrap();
        let consolidation_off = AutoConsolidate {
            enabled: false,
            threshold: 10,
        };
        for index in 0..30 {
            let stored = crate::tools::call_tool_with_config(
                &store,
                None,
                "icm_memory_store",
                &json!({
                    "topic":"limit-probe",
                    "content":format!("revision limit probe entry {index}")
                }),
                false,
                consolidation_off,
            );
            assert!(!stored.is_error);
        }
        let service = service(&store);

        let mut legacy_state = ConnectionState::default();
        service.handle(
            &mut legacy_state,
            request(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );
        for (id, limit, expected_hits) in [(2, 0, 1), (3, 21, 20), (4, 101, 20)] {
            let response = service
                .handle(
                    &mut legacy_state,
                    request(json!({
                        "jsonrpc":"2.0","id":id,"method":"tools/call",
                        "params":{
                            "name":"icm_memory_recall",
                            "arguments":{
                                "query":"revision limit probe",
                                "project":"",
                                "limit":limit
                            }
                        }
                    })),
                )
                .unwrap();
            assert!(response.error.is_none());
            let result = response.result.unwrap();
            assert_ne!(result["isError"], true);
            assert_eq!(
                result["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .matches("revision limit probe")
                    .count(),
                expected_hits
            );
        }

        let legacy_unknown = service
            .handle(
                &mut legacy_state,
                request(json!({
                    "jsonrpc":"2.0","id":5,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_recall",
                        "arguments":{
                            "query":"revision limit probe","project":"","limit":2,
                            "futureField":{"opaque":[1,2,3]}
                        }
                    }
                })),
            )
            .unwrap();
        let legacy_unknown_result = legacy_unknown.result.unwrap();
        assert_ne!(legacy_unknown_result["isError"], true);
        assert_eq!(
            legacy_unknown_result["content"][0]["text"]
                .as_str()
                .unwrap()
                .matches("revision limit probe")
                .count(),
            2
        );

        let legacy_bad_type = service
            .handle(
                &mut legacy_state,
                request(json!({
                    "jsonrpc":"2.0","id":6,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_recall",
                        "arguments":{
                            "query":"revision limit probe","project":"","limit":"2"
                        }
                    }
                })),
            )
            .unwrap();
        let legacy_bad_type = legacy_bad_type.result.unwrap();
        assert_ne!(legacy_bad_type["isError"], true);
        assert_eq!(
            legacy_bad_type["content"][0]["text"]
                .as_str()
                .unwrap()
                .matches("revision limit probe")
                .count(),
            5
        );

        let mut modern_state = ConnectionState::default();
        let accepted = service
            .handle(
                &mut modern_state,
                request(json!({
                    "jsonrpc":"2.0","id":7,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_recall",
                        "arguments":{
                            "query":"revision limit probe","project":"","limit":100
                        },
                        "_meta":modern_metadata()
                    }
                })),
            )
            .unwrap();
        let accepted_result = accepted.result.unwrap();
        assert_ne!(accepted_result["isError"], true);
        assert_eq!(accepted_result["content"][0]["text"], "Found 30 memories.");
        assert_eq!(
            accepted_result["structuredContent"]["memories"]
                .as_array()
                .map(Vec::len),
            Some(30)
        );
        let first = &accepted_result["structuredContent"]["memories"][0];
        let stored = store.get(first["id"].as_str().unwrap()).unwrap().unwrap();
        assert_eq!(first["accessCount"], stored.access_count);
        assert_eq!(
            first["lastAccessed"],
            serde_json::to_value(stored.last_accessed).unwrap()
        );

        for (id, limit) in [(8, 0), (9, 101)] {
            let rejected = service
                .handle(
                    &mut modern_state,
                    request(json!({
                        "jsonrpc":"2.0","id":id,"method":"tools/call",
                        "params":{
                            "name":"icm_memory_recall",
                            "arguments":{
                                "query":"revision limit probe","project":"","limit":limit
                            },
                            "_meta":modern_metadata()
                        }
                    })),
                )
                .unwrap();
            assert!(rejected.result.is_none());
            assert_eq!(rejected.error.unwrap().code, -32602);
        }

        let modern_unknown = service
            .handle(
                &mut modern_state,
                request(json!({
                    "jsonrpc":"2.0","id":10,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_recall",
                        "arguments":{
                            "query":"revision limit probe","project":"","limit":2,
                            "futureField":{"opaque":[1,2,3]}
                        },
                        "_meta":modern_metadata()
                    }
                })),
            )
            .unwrap();
        assert!(modern_unknown.result.is_none());
        assert_eq!(modern_unknown.error.unwrap().code, -32602);

        let modern_bad_type = service
            .handle(
                &mut modern_state,
                request(json!({
                    "jsonrpc":"2.0","id":11,"method":"tools/call",
                    "params":{
                        "name":"icm_memory_recall",
                        "arguments":{
                            "query":"revision limit probe","project":"","limit":"2"
                        },
                        "_meta":modern_metadata()
                    }
                })),
            )
            .unwrap();
        assert!(modern_bad_type.result.is_none());
        assert_eq!(modern_bad_type.error.unwrap().code, -32602);
    }

    #[test]
    fn malformed_tool_call_and_unknown_name_remain_protocol_errors() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        initialize_2025(&service, &mut state);

        let malformed = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{"name":"icm_memory_recall","arguments":[]}
                })),
            )
            .unwrap();
        assert_eq!(malformed.error.unwrap().code, -32602);

        let unknown = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{"name":"icm_missing","arguments":{}}
                })),
            )
            .unwrap();
        assert_eq!(unknown.error.unwrap().code, -32602);
    }

    #[test]
    fn frozen_2024_unknown_tool_remains_a_legacy_tool_error() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = ConnectionState::default();
        service.handle(
            &mut state,
            request(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );

        let response = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{"name":"icm_missing","arguments":{}}
                })),
            )
            .unwrap();
        assert!(response.error.is_none());
        assert_eq!(
            response.result.unwrap(),
            json!({
                "content":[{"type":"text","text":"unknown tool: icm_missing"}],
                "isError":true
            })
        );

        let non_object_arguments = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{"name":"icm_memory_stats","arguments":[]}
                })),
            )
            .unwrap();
        assert!(non_object_arguments.error.is_none());
        assert_ne!(non_object_arguments.result.unwrap()["isError"], true);

        let non_object_params = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":4,"method":"tools/call","params":[]
                })),
            )
            .unwrap();
        let error = non_object_params.error.unwrap();
        assert_eq!(error.code, -32602);
        assert_eq!(error.message, "missing tool name");
    }

    #[test]
    fn unavailable_embedder_tool_stays_hidden_but_preserves_legacy_dispatch() {
        let store = Store::in_memory().unwrap();
        let service = service(&store);
        let mut state = initialized_state_for_revision(&service, ProtocolRevision::V2024_11_05);
        let listed = service
            .handle(
                &mut state,
                request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})),
            )
            .unwrap()
            .result
            .unwrap();
        assert!(!listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == "icm_memory_embed_all"));

        let called = service
            .handle(
                &mut state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{"name":"icm_memory_embed_all","arguments":{}}
                })),
            )
            .unwrap();
        assert!(called.error.is_none());
        assert_eq!(
            called.result.unwrap(),
            json!({
                "content":[{
                    "type":"text",
                    "text":"embeddings not available"
                }],
                "isError":true
            })
        );

        let mut modern = initialized_state_for_revision(&service, ProtocolRevision::V2025_11_25);
        let modern_called = service
            .handle(
                &mut modern,
                request(json!({
                    "jsonrpc":"2.0","id":4,"method":"tools/call",
                    "params":{"name":"icm_memory_embed_all","arguments":{}}
                })),
            )
            .unwrap();
        assert_eq!(modern_called.error.unwrap().code, -32602);
    }

    #[test]
    fn legacy_learn_keeps_caller_selected_paths_while_modern_stays_bounded() {
        let root = tempfile::tempdir().unwrap();
        let working_directory = root.path().join("server-project");
        let external_directory = root.path().join("external-project");
        std::fs::create_dir(&working_directory).unwrap();
        std::fs::create_dir(&external_directory).unwrap();
        std::fs::write(
            external_directory.join("Cargo.toml"),
            "[package]\nname='external-project'\nversion='0.1.0'\n",
        )
        .unwrap();

        let store = Store::in_memory().unwrap();
        let service = McpService::with_working_directory(
            &store,
            None,
            false,
            AutoConsolidate::default(),
            working_directory,
        );
        let arguments = json!({"directory":external_directory});

        let mut legacy = initialized_state_for_revision(&service, ProtocolRevision::V2024_11_05);
        let accepted = service
            .handle(
                &mut legacy,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{"name":"icm_learn","arguments":arguments}
                })),
            )
            .unwrap()
            .result
            .unwrap();
        assert_ne!(accepted["isError"], true);

        let mut modern = initialized_state_for_revision(&service, ProtocolRevision::V2025_11_25);
        let rejected = service
            .handle(
                &mut modern,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{"name":"icm_learn","arguments":arguments}
                })),
            )
            .unwrap()
            .result
            .unwrap();
        assert_eq!(rejected["isError"], true);
        assert!(rejected["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("within the server working directory"));
    }

    #[test]
    fn transcript_show_offset_is_tolerated_only_by_the_2024_projection() {
        use icm_core::TranscriptStore;

        let store = Store::in_memory().unwrap();
        let session_id = store.create_session("test", None, None).unwrap();
        let service = service(&store);
        let mut legacy_state = ConnectionState::default();
        service.handle(
            &mut legacy_state,
            request(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            })),
        );
        let legacy = service
            .handle(
                &mut legacy_state,
                request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{
                        "name":"icm_transcript_show",
                        "arguments":{"session_id":session_id,"offset":0}
                    }
                })),
            )
            .unwrap();
        assert!(legacy.error.is_none());
        let legacy_result = legacy.result.unwrap();
        assert_ne!(legacy_result["isError"], true);
        assert!(legacy_result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&session_id));

        let mut initialized_state = ConnectionState::default();
        initialize_2025(&service, &mut initialized_state);
        let initialized = service
            .handle(
                &mut initialized_state,
                request(json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{
                        "name":"icm_transcript_show",
                        "arguments":{"session_id":session_id,"offset":0}
                    }
                })),
            )
            .unwrap();
        assert!(initialized.result.is_none());
        assert_eq!(initialized.error.unwrap().code, -32602);

        let mut modern_state = ConnectionState::default();
        let modern = service
            .handle(
                &mut modern_state,
                request(json!({
                    "jsonrpc":"2.0","id":4,"method":"tools/call",
                    "params":{
                        "name":"icm_transcript_show",
                        "arguments":{"session_id":session_id,"offset":0},
                        "_meta":modern_metadata()
                    }
                })),
            )
            .unwrap();
        assert!(modern.result.is_none());
        assert_eq!(modern.error.unwrap().code, -32602);
    }
}
