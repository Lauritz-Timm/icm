//! Persistent local HTTP API for ICM — warm-model fast path (issue #290).
//!
//! The CLI reloads the embedding model on every invocation (~9 s on
//! CPU), which makes semantic recall impractical for high-frequency
//! callers (scripts, agents, loops). `icm serve` already keeps the
//! model warm but only over an MCP/stdio JSON-RPC transport that is
//! awkward to call from non-MCP clients.
//!
//! This module adds an axum HTTP server (`icm serve --http
//! 127.0.0.1:11435`) that shares ONE warm [`Store`] and ONE
//! embedder across all requests via [`Arc`]. The endpoints mirror the
//! existing MCP tools and route through the SAME store methods so
//! behavior stays consistent.
//!
//! Response format defaults to TOON (the project's existing compact
//! representation, identical to `icm recall -f toon`). `?format=json`
//! or `Accept: application/json` returns the JSON variant. TOON keeps
//! token cost low for LLM-facing pipes; JSON suits programmatic
//! parsers.
//!
//! Bound to `127.0.0.1` by default — the user has to type any other
//! bind explicitly. An optional `--token` enables `Authorization:
//! Bearer <token>` checking; a loopback bind may run without one
//! ("open localhost API"), but any other interface without a token
//! is refused at startup — otherwise the full memory store would be
//! reachable, unauthenticated, to anyone on that interface.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use icm_core::{
    is_preference_topic, keyword_matches, project_matches, topic_matches, Embedder, Importance,
    Memory, MemoryStore, MSG_NO_MEMORIES,
};
use icm_mcp::{
    protocol::{JsonRpcMessage, JsonRpcResponse, ProtocolRevision},
    service::{unsupported_protocol_version_error, ConnectionState, McpService},
    AutoConsolidate,
};
use icm_store::Store;

#[cfg(test)]
use crate::mcp_http::encode_working_directory;
use crate::mcp_http::WORKING_DIRECTORY_HEADER;
use crate::recall_format::{self, RecallFormat};

const MAX_MCP_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_MCP_SESSIONS: usize = 1024;
static NEXT_MCP_SESSION_ID: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Arc-shared so every axum handler reads the SAME warm store + embedder.
/// `Store` wraps a `rusqlite::Connection`, which is `Send` but
/// not `Sync`, so the same `Arc<Mutex<…>>` pattern as the web
/// dashboard (see `web.rs`) serializes DB access. Embedders are
/// already `Send + Sync` (see `icm-core::embedder::Embedder`).
/// `None` skips semantic recall — the `--no-embeddings` path.
#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<Store>>,
    embedder: Option<Arc<dyn Embedder + Send + Sync>>,
    // ponytail: one lock caps the session table; shard it only if concurrent
    // MCP sessions become a measured bottleneck.
    mcp_sessions: Arc<Mutex<HashMap<String, McpSession>>>,
    mcp_compact: bool,
    auto_consolidate: AutoConsolidate,
    daemon_working_directory: PathBuf,
    /// When set, every request must carry `Authorization: Bearer <token>`.
    token: Option<String>,
}

struct McpSession {
    connection: ConnectionState,
    protocol_version: ProtocolRevision,
    working_directory: PathBuf,
}

/// Audit finding: every store access here treated a poisoned Mutex as a
/// *permanent* fault ("store poisoned", 500) rather than recovering, unlike
/// `web.rs::lock_store` (fixed in #372) — a single panic anywhere in Store
/// while the lock was held (a future bug, an upstream edge case) would
/// permanently 500 all five endpoints (recall/store/consolidate/stats/
/// topics) for the rest of the process, recoverable only by restarting
/// `icm serve --http`. A stdlib Mutex poison flag carries no corruption
/// guarantee for a plain data store — the guard's data is still valid,
/// just possibly mid-mutation from the panicking call, which the store's
/// own operations are already robust to (each is a self-contained SQL
/// statement/transaction).
fn lock_store(state: &AppState) -> std::sync::MutexGuard<'_, Store> {
    state
        .store
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl AppState {
    fn embedder_ref(&self) -> Option<&dyn Embedder> {
        self.embedder.as_deref().map(|e| e as &dyn Embedder)
    }
}

// ---------------------------------------------------------------------------
// Response format negotiation
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct FormatQuery {
    /// `toon` (default) or `json`. Accepts the same value `icm recall
    /// -f` accepts so muscle memory carries over.
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Toon,
    Json,
}

impl OutputFormat {
    /// Resolve from `?format=` first, then `Accept` header. TOON is
    /// the default because the whole point of #290 is the low token
    /// cost on LLM-side reads.
    fn resolve(query: &FormatQuery, headers: &HeaderMap) -> Self {
        if let Some(q) = query.format.as_deref() {
            match q.to_ascii_lowercase().as_str() {
                "json" => return Self::Json,
                "toon" => return Self::Toon,
                _ => {}
            }
        }
        if let Some(a) = headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase)
        {
            // Honor explicit JSON requests; everything else (text/plain,
            // text/toon, */*, anything ambiguous) stays on TOON.
            if a.contains("application/json") && !a.contains("text/") {
                return Self::Json;
            }
        }
        Self::Toon
    }
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RecallReq {
    query: String,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    keyword: Option<String>,
    /// Empty string disables the project filter (matches the MCP tool
    /// convention). Omitted → no filter is applied; HTTP callers
    /// usually run outside any project so the cwd-based fallback that
    /// MCP uses is intentionally not replicated here.
    #[serde(default)]
    project: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StoreReq {
    topic: String,
    content: String,
    #[serde(default)]
    importance: Option<String>,
    /// Accept either a CSV string (`"a,b,c"`) or a JSON array
    /// (`["a","b","c"]`). The CSV form mirrors `icm store -k a,b,c`.
    #[serde(default)]
    keywords: Option<Value>,
    #[serde(default)]
    raw: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConsolidateReq {
    topic: String,
    #[serde(default)]
    keep_originals: bool,
}

#[derive(Debug, Deserialize, Default)]
struct McpQuery {
    #[serde(default)]
    compact: bool,
}

// ---------------------------------------------------------------------------
// Server entry
// ---------------------------------------------------------------------------

/// Pure guard, factored out for unit testing: reject a non-loopback bind
/// with no token. Returns `Err(message)` when the combination is unsafe.
fn check_bind_requires_token(addr: &SocketAddr, token: &Option<String>) -> Result<(), String> {
    if token.is_none() && !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to bind {addr}: only loopback addresses (127.0.0.1, ::1) may run \
             without --token. Pass --token <TOKEN> to expose on other interfaces."
        ));
    }
    Ok(())
}

/// Run the HTTP server until it's interrupted. Loads NOTHING beyond
/// what the caller has already loaded — the warm store and embedder
/// are pre-built by `cmd_serve` and handed to us as `Arc`s.
#[tokio::main]
pub async fn run_http_server(
    store: Store,
    embedder: Option<Box<dyn Embedder + Send + Sync>>,
    addr: SocketAddr,
    token: Option<String>,
    compact: bool,
    auto_consolidate: AutoConsolidate,
) -> Result<()> {
    // A non-loopback bind with no token exposes the full memory store —
    // recall, store, consolidate — to anyone who can reach the interface,
    // with zero authentication (security audit finding). Loopback-only
    // still works without a token, matching the doc comment's original
    // intent ("absent token = open localhost API").
    if let Err(msg) = check_bind_requires_token(&addr, &token) {
        anyhow::bail!(msg);
    }
    let daemon_working_directory = std::env::current_dir()
        .context("cannot resolve HTTP server working directory")?
        .canonicalize()
        .context("cannot canonicalize HTTP server working directory")?;
    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        embedder: embedder.map(Arc::from),
        mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
        mcp_compact: compact,
        auto_consolidate,
        daemon_working_directory,
        token,
    };

    let app = Router::new()
        .route(
            "/mcp",
            post(handle_mcp)
                .delete(handle_mcp_delete)
                .layer(DefaultBodyLimit::max(MAX_MCP_REQUEST_BYTES)),
        )
        .route("/recall", post(handle_recall))
        .route("/store", post(handle_store))
        .route("/consolidate", post(handle_consolidate))
        .route("/stats", get(handle_stats))
        .route("/topics", get(handle_topics))
        .route("/health", get(handle_health))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {addr}: {e}"))?;
    let local = listener.local_addr().unwrap_or(addr);
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "READY http://{local}/")?;
        stdout.flush()?;
    }
    eprintln!("[icm http] listening on http://{local}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(_) => {
                let _ = ctrl_c.await;
                return;
            }
        };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate.recv() => {},
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

// ---------------------------------------------------------------------------
// Handler: /mcp
// ---------------------------------------------------------------------------

async fn handle_mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<McpQuery>,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        return mcp_http_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Value::Null,
            -32600,
            "content-type must be application/json",
            None,
        );
    }

    let session_id = match mcp_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(message) => {
            return mcp_http_error(StatusCode::BAD_REQUEST, Value::Null, -32600, message, None)
        }
    };
    let protocol_version = match mcp_protocol_version(&headers) {
        Ok(protocol_version) => protocol_version,
        Err(McpProtocolVersionError::Invalid(message)) => {
            return mcp_http_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                message,
                session_id.as_deref(),
            )
        }
        Err(McpProtocolVersionError::Unsupported(requested)) => {
            let message = serde_json::from_slice::<JsonRpcMessage>(&body).ok();
            let response_id = message
                .as_ref()
                .and_then(|message| message.id.clone())
                .unwrap_or(Value::Null);
            if let Some(message) = message.as_ref() {
                if let Err(message) =
                    validate_mcp_request_headers(&headers, message, Some(&requested))
                {
                    return mcp_http_error(
                        StatusCode::BAD_REQUEST,
                        response_id,
                        -32020,
                        &message,
                        session_id.as_deref(),
                    );
                }
            }
            let mut response = mcp_http_response(
                Some(unsupported_protocol_version_error(response_id, &requested)),
                session_id.as_deref(),
            );
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return response;
        }
    };
    let bound_working_directory = if let Some(session_id) = session_id.as_deref() {
        let sessions = state
            .mcp_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(session) = sessions.get(session_id) else {
            return mcp_http_error(
                StatusCode::NOT_FOUND,
                Value::Null,
                -32001,
                "unknown MCP session",
                None,
            );
        };
        if protocol_version != Some(session.protocol_version) {
            return mcp_http_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "mcp-protocol-version is required and must match the negotiated session version",
                Some(session_id),
            );
        }
        Some(session.working_directory.clone())
    } else {
        None
    };
    let requested_working_directory = match mcp_working_directory(&headers) {
        Ok(directory) => directory,
        Err(message) => {
            return mcp_http_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                message,
                session_id.as_deref(),
            )
        }
    };
    let working_directory = match bound_working_directory {
        Some(bound) => {
            if requested_working_directory
                .as_ref()
                .is_some_and(|requested| requested != &bound)
            {
                return mcp_http_error(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32600,
                    "working directory does not match the MCP session",
                    session_id.as_deref(),
                );
            }
            bound
        }
        None => {
            requested_working_directory.unwrap_or_else(|| state.daemon_working_directory.clone())
        }
    };

    let wire_value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return mcp_http_error(
                StatusCode::OK,
                Value::Null,
                -32700,
                &format!("parse error: {error}"),
                session_id.as_deref(),
            )
        }
    };
    let message: JsonRpcMessage = match serde_json::from_value(wire_value) {
        Ok(message) => message,
        Err(error) => {
            return mcp_http_error(
                StatusCode::OK,
                Value::Null,
                -32600,
                &format!("invalid request: {error}"),
                session_id.as_deref(),
            )
        }
    };
    let response_id = message.id.clone().unwrap_or(Value::Null);
    if let Err(message) = validate_mcp_request_headers(
        &headers,
        &message,
        protocol_version.map(ProtocolRevision::as_str),
    ) {
        return mcp_http_error(
            StatusCode::BAD_REQUEST,
            response_id,
            -32020,
            &message,
            session_id.as_deref(),
        );
    }
    let compact = state.mcp_compact || query.compact;

    if let Some(session_id) = session_id.as_deref() {
        let mut sessions = state
            .mcp_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(session) = sessions.get_mut(session_id) else {
            return mcp_http_error(
                StatusCode::NOT_FOUND,
                response_id,
                -32001,
                "unknown MCP session",
                None,
            );
        };
        let store = lock_store(&state);
        let service = McpService::with_working_directory(
            &store,
            state.embedder_ref(),
            compact,
            state.auto_consolidate,
            session.working_directory.clone(),
        );
        return mcp_service_response(
            service.handle(&mut session.connection, message),
            Some(session_id),
            session.protocol_version,
        );
    }

    let is_initialize = message.method.as_deref() == Some("initialize");
    if !is_initialize
        && matches!(
            protocol_version,
            Some(ProtocolRevision::V2025_06_18 | ProtocolRevision::V2025_11_25)
        )
    {
        return mcp_http_error(
            StatusCode::BAD_REQUEST,
            response_id,
            -32600,
            "mcp-session-id is required for this protocol version",
            None,
        );
    }
    let modern = message.method.as_deref() == Some("server/discover")
        || protocol_version == Some(ProtocolRevision::V2026_07_28)
        || message
            .params
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|params| params.get("_meta"))
            .and_then(Value::as_object)
            .is_some_and(|metadata| {
                [
                    "io.modelcontextprotocol/protocolVersion",
                    "io.modelcontextprotocol/clientCapabilities",
                    "io.modelcontextprotocol/clientInfo",
                ]
                .into_iter()
                .any(|key| metadata.contains_key(key))
            });
    let mut connection = if is_initialize || modern {
        ConnectionState::default()
    } else {
        ConnectionState::legacy_2024_ready()
    };
    let response = {
        let store = lock_store(&state);
        let service = McpService::with_working_directory(
            &store,
            state.embedder_ref(),
            compact,
            state.auto_consolidate,
            working_directory.clone(),
        );
        service.handle(&mut connection, message)
    };

    let negotiated_revision = response
        .as_ref()
        .and_then(|response| response.result.as_ref())
        .and_then(|result| result.get("protocolVersion"))
        .and_then(Value::as_str)
        .and_then(ProtocolRevision::parse_exact);
    if is_initialize
        && matches!(
            negotiated_revision,
            Some(ProtocolRevision::V2025_06_18 | ProtocolRevision::V2025_11_25)
        )
    {
        let mut sessions = state
            .mcp_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if sessions.len() >= MAX_MCP_SESSIONS {
            // Generated IDs end in a fixed-width monotonic counter, so the
            // lexical minimum is the oldest live session.
            if let Some(oldest) = sessions.keys().min().cloned() {
                sessions.remove(&oldest);
            }
        }
        let session_id = format!(
            "icm-{:x}-{:016x}",
            std::process::id(),
            NEXT_MCP_SESSION_ID.fetch_add(1, Ordering::Relaxed)
        );
        sessions.insert(
            session_id.clone(),
            McpSession {
                connection,
                protocol_version: negotiated_revision
                    .expect("matched negotiated protocol revision"),
                working_directory,
            },
        );
        return mcp_http_response(response, Some(&session_id));
    }

    mcp_service_response(
        response,
        None,
        protocol_version.unwrap_or(ProtocolRevision::V2024_11_05),
    )
}

async fn handle_mcp_delete(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let session_id = match mcp_session_id(&headers) {
        Ok(Some(session_id)) => session_id,
        Ok(None) | Err(_) => return StatusCode::BAD_REQUEST,
    };
    let protocol_version = match mcp_protocol_version(&headers) {
        Ok(protocol_version) => protocol_version,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let mut sessions = state
        .mcp_sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(session) = sessions.get(&session_id) else {
        return StatusCode::NOT_FOUND;
    };
    if protocol_version != Some(session.protocol_version) {
        return StatusCode::BAD_REQUEST;
    }
    let Ok(working_directory) = mcp_working_directory(&headers) else {
        return StatusCode::BAD_REQUEST;
    };
    if working_directory
        .as_ref()
        .is_some_and(|directory| directory != &session.working_directory)
    {
        return StatusCode::BAD_REQUEST;
    }
    sessions.remove(&session_id);
    StatusCode::NO_CONTENT
}

fn mcp_session_id(headers: &HeaderMap) -> Result<Option<String>, &'static str> {
    let value = single_header(headers, "mcp-session-id")
        .map_err(|_| "mcp-session-id header must appear once")?;
    match value {
        None => Ok(None),
        Some(value) => value
            .to_str()
            .ok()
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 128
                    && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            })
            .map(str::to_owned)
            .map(Some)
            .ok_or("invalid mcp-session-id header"),
    }
}

enum McpProtocolVersionError {
    Invalid(&'static str),
    Unsupported(String),
}

fn mcp_protocol_version(
    headers: &HeaderMap,
) -> Result<Option<ProtocolRevision>, McpProtocolVersionError> {
    let first = single_header(headers, "mcp-protocol-version")
        .map_err(|_| McpProtocolVersionError::Invalid("mcp-protocol-version must appear once"))?;
    match first {
        None => Ok(None),
        Some(value) => {
            let value = value.to_str().map_err(|_| {
                McpProtocolVersionError::Invalid("invalid mcp-protocol-version header")
            })?;
            ProtocolRevision::parse_exact(value)
                .map(Some)
                .ok_or_else(|| McpProtocolVersionError::Unsupported(value.to_owned()))
        }
    }
}

fn validate_mcp_request_headers(
    headers: &HeaderMap,
    message: &JsonRpcMessage,
    header_version: Option<&str>,
) -> Result<(), String> {
    let body_version = message
        .params
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("io.modelcontextprotocol/protocolVersion"))
        .and_then(Value::as_str);
    let current = ProtocolRevision::V2026_07_28.as_str();
    let unsupported_header =
        header_version.is_some_and(|version| ProtocolRevision::parse_exact(version).is_none());
    if !unsupported_header && header_version != Some(current) && body_version != Some(current) {
        return Ok(());
    }
    if header_version != body_version {
        return Err("MCP-Protocol-Version header does not match request metadata".into());
    }
    if header_version != Some(current) {
        return Ok(());
    }

    let method = message
        .method
        .as_deref()
        .filter(|method| !method.is_empty())
        .ok_or_else(|| "Mcp-Method header cannot match a missing request method".to_owned())?;
    let header_method = single_header(headers, "mcp-method")?
        .ok_or_else(|| "required Mcp-Method header is missing".to_owned())?
        .to_str()
        .map_err(|_| "Mcp-Method header is not visible ASCII".to_owned())?;
    if header_method != method {
        return Err("Mcp-Method header does not match request method".into());
    }

    let requires_name = matches!(method, "tools/call" | "prompts/get" | "resources/read");
    let expected_name = match method {
        "tools/call" | "prompts/get" => message
            .params
            .as_ref()
            .and_then(|params| params.get("name")),
        "resources/read" => message.params.as_ref().and_then(|params| params.get("uri")),
        _ => None,
    }
    .and_then(Value::as_str);
    let header_name = single_header(headers, "mcp-name")?;
    match (expected_name, header_name) {
        (Some(expected), Some(actual)) if decode_mcp_name(actual)? == expected => Ok(()),
        (None, None) if !requires_name => Ok(()),
        (Some(_), None) => Err("required Mcp-Name header is missing".into()),
        (None, None) => Err("request body is missing the required MCP name".into()),
        _ => Err("Mcp-Name header does not match request name".into()),
    }
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a HeaderValue>, String> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(format!("{name} header must appear once"));
    }
    Ok(first)
}

fn validate_mcp_header_multiplicity(headers: &HeaderMap) -> Result<(), String> {
    for name in [
        "origin",
        "authorization",
        "mcp-session-id",
        "mcp-protocol-version",
    ] {
        single_header(headers, name)?;
    }
    Ok(())
}

fn decode_mcp_name(value: &HeaderValue) -> Result<String, String> {
    let value = value
        .to_str()
        .map_err(|_| "Mcp-Name header is not visible ASCII".to_owned())?;
    if let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    {
        let decoded = BASE64
            .decode(encoded)
            .map_err(|_| "Mcp-Name header has invalid Base64 encoding".to_owned())?;
        return String::from_utf8(decoded)
            .map_err(|_| "Mcp-Name header Base64 is not UTF-8".to_owned());
    }
    if value.is_empty()
        || value.starts_with([' ', '\t'])
        || value.ends_with([' ', '\t'])
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err("Mcp-Name header must use Base64 sentinel encoding".into());
    }
    Ok(value.to_owned())
}

fn mcp_working_directory(headers: &HeaderMap) -> Result<Option<PathBuf>, &'static str> {
    let mut values = headers.get_all(WORKING_DIRECTORY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("x-icm-working-directory must appear once");
    }
    let value = value
        .to_str()
        .map_err(|_| "x-icm-working-directory must be ASCII hex")?;
    if value.len() % 2 != 0 {
        return Err("x-icm-working-directory must be ASCII hex");
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0]).ok_or("x-icm-working-directory must be ASCII hex")?;
        let low = hex_digit(pair[1]).ok_or("x-icm-working-directory must be ASCII hex")?;
        decoded.push((high << 4) | low);
    }
    let directory = String::from_utf8(decoded)
        .map(PathBuf::from)
        .map_err(|_| "x-icm-working-directory must encode a UTF-8 path")?;
    if !directory.is_absolute() {
        return Err("x-icm-working-directory must be absolute");
    }
    let directory = directory
        .canonicalize()
        .map_err(|_| "x-icm-working-directory must be an existing directory")?;
    if !directory.is_dir() {
        return Err("x-icm-working-directory must be an existing directory");
    }
    Ok(Some(directory))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn mcp_origin_is_loopback(origin: &HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Ok(uri) = origin.parse::<Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    if authority.as_str().contains('@')
        || !uri.scheme_str().is_some_and(|scheme| {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        })
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return false;
    }
    let host = uri.host().unwrap_or_default();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn mcp_http_error(
    status: StatusCode,
    id: Value,
    code: i64,
    message: &str,
    session_id: Option<&str>,
) -> Response {
    let mut response = mcp_http_response(
        Some(JsonRpcResponse::err(id, code, message.to_owned())),
        session_id,
    );
    *response.status_mut() = status;
    response
}

fn mcp_service_response(
    response: Option<JsonRpcResponse>,
    session_id: Option<&str>,
    revision: ProtocolRevision,
) -> Response {
    let method_not_found = revision == ProtocolRevision::V2026_07_28
        && response
            .as_ref()
            .and_then(|response| response.error.as_ref())
            .is_some_and(|error| error.code == -32601);
    let mut response = mcp_http_response(response, session_id);
    if method_not_found {
        *response.status_mut() = StatusCode::NOT_FOUND;
    }
    response
}

fn mcp_http_response(response: Option<JsonRpcResponse>, session_id: Option<&str>) -> Response {
    let mut response = match response {
        Some(response) => Json(response).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    };
    if let Some(session_id) = session_id {
        if let Ok(value) = HeaderValue::from_str(session_id) {
            response.headers_mut().insert("mcp-session-id", value);
        }
    }
    response
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if let Err(message) = validate_mcp_header_multiplicity(&headers) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    if request.uri().path() == "/mcp"
        && headers
            .get(header::ORIGIN)
            .is_some_and(|origin| !mcp_origin_is_loopback(origin))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Health is always reachable so an unauth'd liveness probe works.
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }
    let Some(expected) = state.token.as_deref() else {
        return next.run(request).await;
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    match presented {
        // Constant-time compare: a naive `==` leaks a timing side-channel an
        // attacker can use to brute-force the token byte-by-byte (audit
        // finding).
        Some(tok) if constant_time_eq(tok.as_bytes(), expected.as_bytes()) => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            "missing or invalid Bearer token\n",
        )
            .into_response(),
    }
}

/// Compare two byte strings in time independent of where they first differ.
/// Still short-circuits on length (safe: lengths aren't secret here).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Handler: /recall
// ---------------------------------------------------------------------------

async fn handle_recall(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FormatQuery>,
    Json(req): Json<RecallReq>,
) -> Response {
    let format = OutputFormat::resolve(&q, &headers);
    match run_recall(&state, &req) {
        Ok(results) => render_recall(&results, format),
        Err(e) => err_response(StatusCode::BAD_REQUEST, &e.to_string(), format),
    }
}

/// Recall logic mirrored from `icm-mcp::tools::tool_recall` but
/// returning the raw `Vec<(Memory, Option<f32>)>` so HTTP can format
/// it with the project's `recall_format` renderer (TOON or JSON).
/// Reuses the same store methods so behavior stays consistent across
/// transports.
fn run_recall(state: &AppState, req: &RecallReq) -> Result<Vec<(Memory, Option<f32>)>> {
    if req.query.trim().is_empty() {
        anyhow::bail!("missing required field: query");
    }
    let store = lock_store(state);
    if let Err(e) = store.maybe_auto_decay() {
        tracing::warn!(error = %e, "auto-decay failed during /recall");
    }

    let limit = req.limit.unwrap_or(5).clamp(1, 100);

    let project_filter = |m: &Memory| -> bool {
        match req.project.as_deref() {
            None | Some("") => true,
            Some(p) => is_preference_topic(&m.topic) || project_matches(&m.topic, Some(p)),
        }
    };

    let scored: Vec<(Memory, Option<f32>)> = if let Some(emb) = state.embedder_ref() {
        match emb.embed_query(&req.query) {
            Ok(q_emb) => match store.search_hybrid(&req.query, &q_emb, limit) {
                Ok(rows) => rows
                    .into_iter()
                    .filter(|(m, _)| project_filter(m))
                    .filter(|(m, _)| {
                        req.topic
                            .as_deref()
                            .is_none_or(|t| topic_matches(&m.topic, t))
                    })
                    .filter(|(m, _)| {
                        req.keyword
                            .as_deref()
                            .is_none_or(|k| keyword_matches(&m.keywords, k))
                    })
                    .map(|(m, s)| (m, Some(s)))
                    .collect(),
                Err(_) => fts_fallback(&store, req, &project_filter, limit)?,
            },
            Err(_) => fts_fallback(&store, req, &project_filter, limit)?,
        }
    } else {
        fts_fallback(&store, req, &project_filter, limit)?
    };

    // Best-effort access bookkeeping (matches the MCP path).
    let ids: Vec<&str> = scored.iter().map(|(m, _)| m.id.as_str()).collect();
    let _ = store.batch_update_access(&ids);

    Ok(scored)
}

fn fts_fallback<F>(
    store: &Store,
    req: &RecallReq,
    project_filter: &F,
    limit: usize,
) -> Result<Vec<(Memory, Option<f32>)>>
where
    F: Fn(&Memory) -> bool,
{
    let mut rows = store.search_fts(&req.query, limit)?;
    if rows.is_empty() {
        let keywords: Vec<&str> = req.query.split_whitespace().collect();
        rows = store.search_by_keywords(&keywords, limit)?;
    }
    rows.retain(project_filter);
    if let Some(t) = req.topic.as_deref() {
        rows.retain(|m| topic_matches(&m.topic, t));
    }
    if let Some(k) = req.keyword.as_deref() {
        rows.retain(|m| keyword_matches(&m.keywords, k));
    }
    Ok(rows.into_iter().map(|m| (m, None)).collect())
}

fn render_recall(results: &[(Memory, Option<f32>)], format: OutputFormat) -> Response {
    if results.is_empty() {
        return text_response(MSG_NO_MEMORIES, format);
    }
    match format {
        OutputFormat::Toon => match recall_format::render(results, RecallFormat::Toon) {
            Ok(body) => toon_response(body),
            Err(e) => err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("toon render failed: {e}"),
                format,
            ),
        },
        OutputFormat::Json => match recall_format::render(results, RecallFormat::Json) {
            Ok(body) => json_string_response(body),
            Err(e) => err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("json render failed: {e}"),
                format,
            ),
        },
    }
}

// ---------------------------------------------------------------------------
// Handler: /store
// ---------------------------------------------------------------------------

async fn handle_store(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FormatQuery>,
    Json(req): Json<StoreReq>,
) -> Response {
    let format = OutputFormat::resolve(&q, &headers);
    if req.topic.trim().is_empty() || req.content.trim().is_empty() {
        return err_response(
            StatusCode::BAD_REQUEST,
            "topic and content must be non-empty",
            format,
        );
    }
    let importance = match parse_importance(req.importance.as_deref()) {
        Ok(i) => i,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, &e, format),
    };
    let keywords = parse_keywords_value(req.keywords.as_ref());

    let mut mem = Memory::new(req.topic.clone(), req.content.clone(), importance);
    mem.keywords = keywords;
    if let Some(raw) = req.raw.as_deref().filter(|s| !s.is_empty()) {
        mem.raw_excerpt = Some(raw.to_string());
    }
    if let Some(emb) = state.embedder_ref() {
        if let Ok(v) = emb.embed(&format!("{} {}", mem.topic, mem.summary)) {
            mem.embedding = Some(v);
        }
    }

    let outcome = lock_store(&state).store(mem.clone());
    match outcome {
        Ok(id) => {
            let mut stored = mem;
            stored.id = id;
            render_recall(&[(stored, None)], format)
        }
        Err(e) => err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store failed: {e}"),
            format,
        ),
    }
}

fn parse_importance(s: Option<&str>) -> Result<Importance, String> {
    let raw = s.unwrap_or("medium").to_ascii_lowercase();
    match raw.as_str() {
        "critical" => Ok(Importance::Critical),
        "high" => Ok(Importance::High),
        "medium" => Ok(Importance::Medium),
        "low" => Ok(Importance::Low),
        other => Err(format!(
            "invalid importance {other:?}; expected one of: critical, high, medium, low"
        )),
    }
}

fn parse_keywords_value(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(csv)) => csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Handler: /consolidate
// ---------------------------------------------------------------------------

async fn handle_consolidate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FormatQuery>,
    Json(req): Json<ConsolidateReq>,
) -> Response {
    let format = OutputFormat::resolve(&q, &headers);
    if req.topic.trim().is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "topic required", format);
    }
    let store = lock_store(&state);
    let topic_memories = match store.get_by_topic(&req.topic) {
        Ok(ms) => ms,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("topic lookup failed: {e}"),
                format,
            )
        }
    };
    if topic_memories.is_empty() {
        return err_response(
            StatusCode::NOT_FOUND,
            &format!("no memories under topic {:?}", req.topic),
            format,
        );
    }
    let summary = topic_memories
        .iter()
        .map(|m| m.summary.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    let mut consolidated = Memory::new(req.topic.clone(), summary, Importance::High);
    // Same bug class as #400 (cmd_consolidate/tool_consolidate): this is a
    // third, independent /consolidate implementation that had the same gap
    // — never attached an embedding to the merged memory it creates.
    if let Some(emb) = state.embedder_ref() {
        if let Ok(v) = emb.embed(&consolidated.embed_text()) {
            consolidated.embedding = Some(v);
        }
    }

    let result = if req.keep_originals {
        store.store(consolidated.clone()).map(|_| ())
    } else {
        store.consolidate_topic(&req.topic, consolidated.clone())
    };
    match result {
        Ok(()) => render_recall(&[(consolidated, None)], format),
        Err(e) => err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("consolidate failed: {e}"),
            format,
        ),
    }
}

// ---------------------------------------------------------------------------
// Handler: /stats
// ---------------------------------------------------------------------------

async fn handle_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FormatQuery>,
) -> Response {
    let format = OutputFormat::resolve(&q, &headers);
    let store = lock_store(&state);
    match store.stats() {
        Ok(s) => {
            let payload = json!({
                "total_memories": s.total_memories,
                "total_topics": s.total_topics,
                "avg_weight": s.avg_weight,
                "oldest_memory": s.oldest_memory.map(|d| d.to_rfc3339()),
                "newest_memory": s.newest_memory.map(|d| d.to_rfc3339()),
            });
            match format {
                OutputFormat::Json => json_value_response(payload),
                // TOON for a single key-value object: emit a 1-row table.
                OutputFormat::Toon => {
                    let body = format!(
                        "stats[1]{{total_memories,total_topics,avg_weight,oldest,newest}}:\n  \
                         {},{},{:.3},{},{}\n",
                        s.total_memories,
                        s.total_topics,
                        s.avg_weight,
                        s.oldest_memory
                            .map(|d| d.to_rfc3339())
                            .unwrap_or_else(|| "-".into()),
                        s.newest_memory
                            .map(|d| d.to_rfc3339())
                            .unwrap_or_else(|| "-".into()),
                    );
                    toon_response(body)
                }
            }
        }
        Err(e) => err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("stats failed: {e}"),
            format,
        ),
    }
}

// ---------------------------------------------------------------------------
// Handler: /topics
// ---------------------------------------------------------------------------

async fn handle_topics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FormatQuery>,
) -> Response {
    let format = OutputFormat::resolve(&q, &headers);
    let store = lock_store(&state);
    match store.list_topics() {
        Ok(rows) => match format {
            OutputFormat::Json => json_value_response(json!(rows
                .iter()
                .map(|(t, n)| json!({"topic": t, "count": n}))
                .collect::<Vec<_>>())),
            OutputFormat::Toon => {
                let mut body = format!("topics[{}]{{topic,count}}:\n", rows.len());
                for (t, n) in &rows {
                    let topic = if t.contains(',') || t.contains('"') {
                        format!("\"{}\"", t.replace('"', "\"\""))
                    } else {
                        t.clone()
                    };
                    body.push_str(&format!("  {topic},{n}\n"));
                }
                toon_response(body)
            }
        },
        Err(e) => err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("topics failed: {e}"),
            format,
        ),
    }
}

// ---------------------------------------------------------------------------
// Handler: /health (unauthenticated, used by integration tests + probes)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Health {
    status: &'static str,
    has_embedder: bool,
}

async fn handle_health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        has_embedder: state.embedder.is_some(),
    })
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn toon_response(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

fn json_string_response(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn json_value_response(v: Value) -> Response {
    Json(v).into_response()
}

fn text_response(body: &str, format: OutputFormat) -> Response {
    match format {
        OutputFormat::Json => json_value_response(json!({"message": body, "results": []})),
        OutputFormat::Toon => toon_response(format!("{body}\n")),
    }
}

fn err_response(status: StatusCode, msg: &str, format: OutputFormat) -> Response {
    match format {
        OutputFormat::Json => (status, Json(json!({"error": msg}))).into_response(),
        OutputFormat::Toon => (
            status,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("error: {msg}\n"),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn h(name: &'static str, val: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(val).unwrap());
        h
    }

    #[test]
    fn output_format_defaults_to_toon() {
        let q = FormatQuery::default();
        let hs = HeaderMap::new();
        assert!(matches!(OutputFormat::resolve(&q, &hs), OutputFormat::Toon));
    }

    #[test]
    fn output_format_query_json_wins() {
        let q = FormatQuery {
            format: Some("json".into()),
        };
        let hs = HeaderMap::new();
        assert!(matches!(OutputFormat::resolve(&q, &hs), OutputFormat::Json));
    }

    #[test]
    fn output_format_query_toon_explicit() {
        let q = FormatQuery {
            format: Some("toon".into()),
        };
        // Even if the client sends `Accept: application/json`, explicit
        // `?format=toon` wins so the user has the last word.
        let hs = h("accept", "application/json");
        assert!(matches!(OutputFormat::resolve(&q, &hs), OutputFormat::Toon));
    }

    #[test]
    fn output_format_accept_application_json() {
        let q = FormatQuery::default();
        let hs = h("accept", "application/json");
        assert!(matches!(OutputFormat::resolve(&q, &hs), OutputFormat::Json));
    }

    #[test]
    fn output_format_accept_text_plain_stays_toon() {
        let q = FormatQuery::default();
        let hs = h("accept", "text/plain");
        assert!(matches!(OutputFormat::resolve(&q, &hs), OutputFormat::Toon));
    }

    #[test]
    fn parse_importance_accepts_known_values() {
        assert!(matches!(
            parse_importance(Some("critical")),
            Ok(Importance::Critical)
        ));
        assert!(matches!(
            parse_importance(Some("HIGH")),
            Ok(Importance::High)
        ));
        assert!(matches!(parse_importance(None), Ok(Importance::Medium)));
        assert!(parse_importance(Some("bogus")).is_err());
    }

    #[test]
    fn parse_keywords_value_handles_string_and_array() {
        let s = Value::String("a, b ,c".into());
        let v = parse_keywords_value(Some(&s));
        assert_eq!(v, vec!["a", "b", "c"]);

        let arr = json!(["foo", "", "bar"]);
        let v = parse_keywords_value(Some(&arr));
        assert_eq!(v, vec!["foo", "bar"]);

        assert!(parse_keywords_value(None).is_empty());
        assert!(parse_keywords_value(Some(&json!(42))).is_empty());
    }

    /// Audit regression: a non-loopback bind with no `--token` exposes the
    /// full memory store (recall/store/consolidate) unauthenticated to
    /// anyone who can reach the interface — must be rejected.
    #[test]
    fn non_loopback_bind_without_token_is_rejected() {
        let addr: SocketAddr = "0.0.0.0:8420".parse().unwrap();
        let err = check_bind_requires_token(&addr, &None).unwrap_err();
        assert!(err.contains("--token"));

        let addr: SocketAddr = "203.0.113.5:8420".parse().unwrap();
        assert!(check_bind_requires_token(&addr, &None).is_err());
    }

    #[test]
    fn loopback_bind_without_token_is_still_allowed() {
        // Loopback-only stays usable without a token — same intent as the
        // module doc comment ("absent token = open localhost API"), just
        // now scoped to loopback instead of any address.
        let addr: SocketAddr = "127.0.0.1:8420".parse().unwrap();
        assert!(check_bind_requires_token(&addr, &None).is_ok());
        let addr: SocketAddr = "[::1]:8420".parse().unwrap();
        assert!(check_bind_requires_token(&addr, &None).is_ok());
    }

    #[test]
    fn non_loopback_bind_with_token_is_allowed() {
        let addr: SocketAddr = "0.0.0.0:8420".parse().unwrap();
        assert!(check_bind_requires_token(&addr, &Some("secret".into())).is_ok());
    }

    #[test]
    fn constant_time_eq_matches_naive_equality() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"wrong!"));
        assert!(!constant_time_eq(b"short", b"longer-string"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn mcp_security_headers_must_be_single_valued() {
        for name in [
            "origin",
            "authorization",
            "mcp-session-id",
            "mcp-protocol-version",
        ] {
            let mut headers = HeaderMap::new();
            headers.append(name, HeaderValue::from_static("one"));
            headers.append(name, HeaderValue::from_static("two"));
            assert!(
                validate_mcp_header_multiplicity(&headers).is_err(),
                "accepted duplicate {name} header"
            );
        }
    }

    #[test]
    fn cloned_http_clients_share_one_embedder_instance() {
        struct SharedEmbedder;
        impl Embedder for SharedEmbedder {
            fn embed(&self, _text: &str) -> icm_core::IcmResult<Vec<f32>> {
                Ok(vec![0.0])
            }

            fn embed_batch(&self, texts: &[&str]) -> icm_core::IcmResult<Vec<Vec<f32>>> {
                Ok(texts.iter().map(|_| vec![0.0]).collect())
            }

            fn dimensions(&self) -> usize {
                1
            }
        }

        let embedder: Arc<dyn Embedder + Send + Sync> = Arc::new(SharedEmbedder);
        let state = AppState {
            store: Arc::new(Mutex::new(Store::in_memory().unwrap())),
            embedder: Some(embedder),
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            mcp_compact: false,
            auto_consolidate: AutoConsolidate::default(),
            daemon_working_directory: std::env::current_dir().unwrap().canonicalize().unwrap(),
            token: None,
        };
        let client_a = state.clone();
        let client_b = state;
        assert!(Arc::ptr_eq(
            client_a.embedder.as_ref().unwrap(),
            client_b.embedder.as_ref().unwrap(),
        ));
    }

    #[tokio::test]
    async fn mcp_http_supports_stateless_2024_and_sessioned_2025() {
        let state = AppState {
            store: Arc::new(Mutex::new(Store::in_memory().unwrap())),
            embedder: None,
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            mcp_compact: false,
            auto_consolidate: AutoConsolidate::default(),
            daemon_working_directory: std::env::current_dir().unwrap().canonicalize().unwrap(),
            token: None,
        };
        let headers = h("content-type", "application/json");

        let response = handle_mcp(
            State(state.clone()),
            headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(serde_json::from_slice::<Value>(&body).unwrap()["result"]["tools"].is_array());

        let mut version_headers = headers.clone();
        version_headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-11-25"),
        );
        let response = handle_mcp(
            State(state.clone()),
            version_headers,
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut unsupported_headers = headers.clone();
        unsupported_headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2099-01-01"),
        );
        unsupported_headers.insert("mcp-method", HeaderValue::from_static("tools/list"));
        let response = handle_mcp(
            State(state.clone()),
            unsupported_headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["id"], 9);
        assert_eq!(error["error"]["code"], -32022);
        assert_eq!(
            error["error"]["message"],
            "unsupported protocol version: 2099-01-01"
        );
        assert_eq!(error["error"]["data"]["requested"], "2099-01-01");
        assert_eq!(
            error["error"]["data"]["supported"],
            json!(["2026-07-28", "2025-11-25", "2025-06-18", "2024-11-05"])
        );

        let response = handle_mcp(
            State(state.clone()),
            unsupported_headers,
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["id"], 10);
        assert_eq!(error["error"]["code"], -32020);
        assert_eq!(
            error["error"]["message"],
            "MCP-Protocol-Version header does not match request metadata"
        );

        let response = handle_mcp(
            State(state.clone()),
            headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers().get("mcp-session-id").unwrap().clone();

        let mut unknown_headers = headers.clone();
        unknown_headers.insert("mcp-session-id", HeaderValue::from_static("missing"));
        unknown_headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-11-25"),
        );
        let response = handle_mcp(
            State(state.clone()),
            unknown_headers,
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let mut session_headers = headers;
        session_headers.insert("mcp-session-id", session);
        session_headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-11-25"),
        );
        let mut missing_version_headers = session_headers.clone();
        missing_version_headers.remove("mcp-protocol-version");
        let response = handle_mcp(
            State(state.clone()),
            missing_version_headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            handle_mcp_delete(State(state.clone()), missing_version_headers).await,
            StatusCode::BAD_REQUEST
        );
        let mut mismatch_headers = session_headers.clone();
        mismatch_headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-06-18"),
        );
        let response = handle_mcp(
            State(state.clone()),
            mismatch_headers,
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = handle_mcp(
            State(state.clone()),
            session_headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let response = handle_mcp(
            State(state.clone()),
            session_headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = handle_mcp_delete(State(state.clone()), session_headers.clone()).await;
        assert_eq!(response, StatusCode::NO_CONTENT);
        assert!(state.mcp_sessions.lock().unwrap().is_empty());
        let response = handle_mcp(
            State(state),
            session_headers,
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn mcp_2026_headers_validate_method_and_base64_name() {
        let message: JsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc":"2.0","id":1,"method":"resources/read",
            "params":{
                "uri":"Hello, 世界",
                "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}
            }
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("mcp-method", HeaderValue::from_static("resources/read"));
        headers.insert(
            "mcp-name",
            HeaderValue::from_static("=?base64?SGVsbG8sIOS4lueVjA==?="),
        );
        assert!(validate_mcp_request_headers(
            &headers,
            &message,
            Some(ProtocolRevision::V2026_07_28.as_str())
        )
        .is_ok());

        headers.insert("mcp-method", HeaderValue::from_static("tools/call"));
        assert!(validate_mcp_request_headers(
            &headers,
            &message,
            Some(ProtocolRevision::V2026_07_28.as_str())
        )
        .is_err());
    }

    #[tokio::test]
    async fn mcp_2026_rejects_header_mismatch_and_uses_404_for_unknown_method() {
        let state = AppState {
            store: Arc::new(Mutex::new(Store::in_memory().unwrap())),
            embedder: None,
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            mcp_compact: false,
            auto_consolidate: AutoConsolidate::default(),
            daemon_working_directory: std::env::current_dir().unwrap().canonicalize().unwrap(),
            token: None,
        };
        let mut headers = h("content-type", "application/json");
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2026-07-28"),
        );
        headers.insert("mcp-method", HeaderValue::from_static("ping"));
        headers.insert("mcp-name", HeaderValue::from_static("icm_memory_recall"));
        let response = handle_mcp(
            State(state.clone()),
            headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"icm_memory_recall","arguments":{"query":"x"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"]["code"],
            -32020
        );

        headers.remove("mcp-name");
        headers.insert("mcp-method", HeaderValue::from_static("unknown/method"));
        let response = handle_mcp(
            State(state),
            headers,
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":2,"method":"unknown/method","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"]["code"],
            -32601
        );
    }

    #[tokio::test]
    async fn mcp_session_binds_encoded_client_directory_and_rejects_drift() {
        let temp = tempfile::tempdir().unwrap();
        let client_directory = temp.path().join("client project ü");
        let other_directory = temp.path().join("other project");
        std::fs::create_dir_all(&client_directory).unwrap();
        std::fs::create_dir_all(&other_directory).unwrap();
        let client_directory = client_directory.canonicalize().unwrap();
        let other_directory = other_directory.canonicalize().unwrap();
        let encoded_client = encode_working_directory(client_directory.to_str().unwrap());
        assert!(encoded_client.is_ascii());
        let mut duplicate_headers = HeaderMap::new();
        duplicate_headers.append(
            WORKING_DIRECTORY_HEADER,
            HeaderValue::from_str(&encoded_client).unwrap(),
        );
        duplicate_headers.append(
            WORKING_DIRECTORY_HEADER,
            HeaderValue::from_str(&encoded_client).unwrap(),
        );
        assert!(mcp_working_directory(&duplicate_headers).is_err());

        let store = Store::in_memory().unwrap();
        store
            .store(Memory::new(
                "context-client project ü".into(),
                "shared marker from client".into(),
                Importance::High,
            ))
            .unwrap();
        store
            .store(Memory::new(
                "context-other project".into(),
                "shared marker from other".into(),
                Importance::High,
            ))
            .unwrap();
        let state = AppState {
            store: Arc::new(Mutex::new(store)),
            embedder: None,
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            mcp_compact: false,
            auto_consolidate: AutoConsolidate::default(),
            daemon_working_directory: other_directory.clone(),
            token: None,
        };
        let mut initialize_headers = h("content-type", "application/json");
        initialize_headers.insert(
            WORKING_DIRECTORY_HEADER,
            HeaderValue::from_str(&encoded_client).unwrap(),
        );
        let response = handle_mcp(
            State(state.clone()),
            initialize_headers,
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session_id = response.headers().get("mcp-session-id").unwrap().clone();

        let mut session_headers = h("content-type", "application/json");
        session_headers.insert("mcp-session-id", session_id);
        session_headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-11-25"),
        );
        let response = handle_mcp(
            State(state.clone()),
            session_headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let response = handle_mcp(
            State(state.clone()),
            session_headers.clone(),
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"icm_memory_recall","arguments":{"query":"shared marker"}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        if let Some(memories) = body["result"]["structuredContent"]["memories"].as_array() {
            assert_eq!(memories.len(), 1);
            assert_eq!(memories[0]["summary"], "shared marker from client");
        } else {
            let text = body["result"]["content"][0]["text"].as_str().unwrap();
            assert!(text.contains("from client"));
            assert!(!text.contains("from other"));
        }

        let mut drift_headers = session_headers.clone();
        drift_headers.insert(
            WORKING_DIRECTORY_HEADER,
            HeaderValue::from_str(&encode_working_directory(other_directory.to_str().unwrap()))
                .unwrap(),
        );
        let response = handle_mcp(
            State(state.clone()),
            drift_headers,
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        session_headers.insert(
            WORKING_DIRECTORY_HEADER,
            HeaderValue::from_str(&encoded_client).unwrap(),
        );
        let response = handle_mcp(
            State(state),
            session_headers,
            Query(McpQuery::default()),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mcp_preflights_unknown_sessions_and_evicts_at_capacity() {
        let state = AppState {
            store: Arc::new(Mutex::new(Store::in_memory().unwrap())),
            embedder: None,
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            mcp_compact: false,
            auto_consolidate: AutoConsolidate::default(),
            daemon_working_directory: std::env::current_dir().unwrap().canonicalize().unwrap(),
            token: None,
        };
        let mut session_headers = h("content-type", "application/json");
        session_headers.insert("mcp-session-id", HeaderValue::from_static("missing"));
        session_headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-11-25"),
        );
        let response = handle_mcp(
            State(state.clone()),
            session_headers,
            Query(McpQuery::default()),
            Bytes::from_static(b"{"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        {
            let mut sessions = state.mcp_sessions.lock().unwrap();
            let working_directory = state.daemon_working_directory.clone();
            for index in 0..MAX_MCP_SESSIONS {
                sessions.insert(
                    format!("icm-test-{index:016x}"),
                    McpSession {
                        connection: ConnectionState::default(),
                        protocol_version: ProtocolRevision::V2025_11_25,
                        working_directory: working_directory.clone(),
                    },
                );
            }
        }
        let response = handle_mcp(
            State(state.clone()),
            h("content-type", "application/json"),
            Query(McpQuery::default()),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let sessions = state.mcp_sessions.lock().unwrap();
        assert_eq!(sessions.len(), MAX_MCP_SESSIONS);
        assert!(!sessions.contains_key("icm-test-0000000000000000"));
    }

    /// Audit regression: every store access here treated a poisoned Mutex
    /// as a permanent fault ("store poisoned", 500), unlike web.rs's
    /// lock_store (fixed in #372) — a single panic anywhere in Store while
    /// the lock was held would permanently break recall/store/consolidate/
    /// stats/topics for the rest of the process.
    #[test]
    fn lock_store_recovers_from_a_poisoned_mutex() {
        let state = AppState {
            store: Arc::new(Mutex::new(Store::in_memory().unwrap())),
            embedder: None,
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            mcp_compact: false,
            auto_consolidate: AutoConsolidate::default(),
            daemon_working_directory: std::env::current_dir().unwrap().canonicalize().unwrap(),
            token: None,
        };

        // Poison the mutex: panic while holding the guard on another thread.
        let poisoner = state.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.store.lock().unwrap();
            panic!("intentional poison");
        })
        .join();
        assert!(state.store.is_poisoned(), "setup: mutex must be poisoned");

        // The recovering lock still yields a working store.
        let store = lock_store(&state);
        assert!(
            store.stats().is_ok(),
            "store must remain usable after poison"
        );
    }

    /// Manual-testing finding (against the real HTTP server): a third,
    /// independent /consolidate implementation — same bug class as #400
    /// (cmd_consolidate/tool_consolidate) — never attached an embedding
    /// to the merged memory it creates, even though `state.embedder_ref()`
    /// is right there and every sibling handler (store/recall/embed_all)
    /// already uses it.
    #[tokio::test]
    async fn handle_consolidate_attaches_an_embedding_to_the_merged_memory() {
        use icm_core::IcmResult;

        struct StubEmbedder;
        impl Embedder for StubEmbedder {
            fn embed(&self, _text: &str) -> IcmResult<Vec<f32>> {
                Ok(vec![0.4_f32; 64])
            }
            fn embed_batch(&self, texts: &[&str]) -> IcmResult<Vec<Vec<f32>>> {
                texts.iter().map(|t| self.embed(t)).collect()
            }
            fn dimensions(&self) -> usize {
                64
            }
        }

        let store = Store::in_memory_with_dims(64).unwrap();
        store
            .store(Memory::new(
                "http-test".into(),
                "expendable 1".into(),
                Importance::Medium,
            ))
            .unwrap();
        store
            .store(Memory::new(
                "http-test".into(),
                "expendable 2".into(),
                Importance::Medium,
            ))
            .unwrap();

        let state = AppState {
            store: Arc::new(Mutex::new(store)),
            embedder: Some(Arc::new(StubEmbedder)),
            mcp_sessions: Arc::new(Mutex::new(HashMap::new())),
            mcp_compact: false,
            auto_consolidate: AutoConsolidate::default(),
            daemon_working_directory: std::env::current_dir().unwrap().canonicalize().unwrap(),
            token: None,
        };

        let resp = handle_consolidate(
            State(state.clone()),
            HeaderMap::new(),
            Query(FormatQuery::default()),
            Json(ConsolidateReq {
                topic: "http-test".into(),
                keep_originals: false,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let store = lock_store(&state);
        let memories = store.get_by_topic("http-test").unwrap();
        assert_eq!(memories.len(), 1);
        assert!(
            memories[0].embedding.is_some(),
            "consolidated memory must have an embedding attached"
        );
    }
}
