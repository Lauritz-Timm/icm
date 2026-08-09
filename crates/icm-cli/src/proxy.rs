//! Line-framed stdio MCP bridge to a warm loopback HTTP service.

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::{general_purpose::STANDARD as BASE64, Engine as _};
use clap::Args;
use icm_mcp::protocol::JsonRpcResponse;
use serde_json::Value;

use crate::mcp_http::{encode_working_directory, WORKING_DIRECTORY_HEADER};

const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SESSION_NOT_FOUND: &str = "upstream MCP session ended";

#[derive(Args, Debug)]
pub struct ProxyArgs {
    /// Base URL of the warm ICM HTTP service (HTTP loopback only)
    #[arg(long, value_name = "BASE_URL")]
    url: String,

    /// Request compact MCP responses
    #[arg(long)]
    compact: bool,

    /// Read the bearer token from this file
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
}

struct ProxyState {
    protocol_version: String,
    session_id: Option<String>,
    initialized: bool,
    initialize_request: Option<Vec<u8>>,
    initialized_notification: Option<Vec<u8>>,
    working_directory: String,
}

#[derive(Debug)]
struct LocalInputError {
    code: i64,
    message: String,
}

impl LocalInputError {
    fn parse(error: serde_json::Error) -> Self {
        Self {
            code: -32700,
            message: format!("parse error: {error}"),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct MessageMeta {
    id: Option<Value>,
    method: String,
    name: Option<String>,
    protocol_version: String,
}

impl MessageMeta {
    fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

pub fn run(args: &ProxyArgs) -> Result<()> {
    let endpoint = endpoint_url(&args.url, args.compact)?;
    let token = resolve_token(args.token_file.as_deref())?;
    let agent = proxy_agent();
    let mut state = ProxyState {
        protocol_version: DEFAULT_PROTOCOL_VERSION.to_owned(),
        session_id: None,
        initialized: false,
        initialize_request: None,
        initialized_notification: None,
        working_directory: proxy_working_directory()?,
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut buffer = Vec::new();

    let result: Result<()> = (|| {
        while let Some(within_limit) = read_capped_line(&mut reader, &mut buffer)? {
            if !within_limit {
                write_error(
                    &mut writer,
                    Value::Null,
                    -32600,
                    &format!("proxy request exceeds {MAX_REQUEST_BYTES} bytes"),
                )?;
                continue;
            }
            if buffer.last() == Some(&b'\n') {
                buffer.pop();
                if buffer.last() == Some(&b'\r') {
                    buffer.pop();
                }
            }
            if buffer.iter().all(u8::is_ascii_whitespace) {
                continue;
            }

            let meta = match message_meta(&buffer, &state) {
                Ok(meta) => meta,
                Err(error) => {
                    write_error(&mut writer, Value::Null, error.code, &error.message)?;
                    continue;
                }
            };
            match forward(
                &agent,
                &endpoint,
                token.as_deref(),
                &mut state,
                &meta,
                &buffer,
            ) {
                Ok(Some(body)) => write_body(&mut writer, &body)?,
                Ok(None) => {}
                Err(error) if error == SESSION_NOT_FOUND => anyhow::bail!(error),
                Err(error) if meta.is_notification() => {
                    eprintln!("[icm proxy] notification failed: {error}");
                }
                Err(error) => write_error(
                    &mut writer,
                    meta.id.clone().unwrap_or(Value::Null),
                    -32000,
                    &error,
                )?,
            }
        }
        Ok(())
    })();
    finish_with_cleanup(result, || {
        cleanup_session(&agent, &endpoint, token.as_deref(), &state)
    })
}

fn proxy_working_directory() -> Result<String> {
    let directory = std::env::current_dir()
        .context("cannot resolve proxy working directory")?
        .canonicalize()
        .context("cannot canonicalize proxy working directory")?;
    let directory = directory
        .to_str()
        .context("proxy working directory is not UTF-8")?;
    Ok(encode_working_directory(directory))
}

fn proxy_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(RESPONSE_READ_TIMEOUT)
        .timeout_write(CONNECT_TIMEOUT)
        .build()
}

fn finish_with_cleanup(
    result: Result<()>,
    cleanup: impl FnOnce() -> Result<(), String>,
) -> Result<()> {
    if let Err(error) = cleanup() {
        eprintln!("[icm proxy] session cleanup failed: {error}");
    }
    result
}

fn endpoint_url(base: &str, compact: bool) -> Result<String> {
    let parsed = ureq::get(base).request_url().context("invalid proxy URL")?;
    let url = parsed.as_url();
    if url.scheme() != "http" {
        anyhow::bail!("proxy URL must use http");
    }
    let raw_authority = base
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default()
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if raw_authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("proxy URL must not contain userinfo");
    }
    if url.fragment().is_some() {
        anyhow::bail!("proxy URL must not contain a fragment");
    }
    let host = url.host_str().context("proxy URL has no host")?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let ip: IpAddr = host
        .parse()
        .context("proxy URL host must be a loopback IP address")?;
    if !ip.is_loopback() {
        anyhow::bail!("proxy URL host must be loopback");
    }

    let mut endpoint = url.clone();
    endpoint
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("proxy URL cannot be a base URL"))?
        .pop_if_empty()
        .push("mcp");
    if compact {
        endpoint.query_pairs_mut().append_pair("compact", "true");
    }
    Ok(endpoint.into())
}

fn resolve_token(path: Option<&Path>) -> Result<Option<String>> {
    let environment = std::env::var_os("ICM_PROXY_TOKEN");
    if path.is_some() && environment.is_some() {
        anyhow::bail!("--token-file and ICM_PROXY_TOKEN are mutually exclusive");
    }
    let raw = if let Some(path) = path {
        let file = File::open(path)
            .with_context(|| format!("failed to read proxy token file {}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_TOKEN_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .context("failed to read proxy token file")?;
        if bytes.len() > MAX_TOKEN_BYTES {
            anyhow::bail!("proxy token file exceeds {MAX_TOKEN_BYTES} bytes");
        }
        String::from_utf8(bytes).context("proxy token file is not UTF-8")?
    } else if let Some(token) = environment {
        token
            .into_string()
            .map_err(|_| anyhow::anyhow!("ICM_PROXY_TOKEN is not UTF-8"))?
    } else {
        return Ok(None);
    };
    let token = raw.trim().to_owned();
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        anyhow::bail!("proxy token is empty or contains invalid characters");
    }
    Ok(Some(token))
}

fn message_meta(raw: &[u8], state: &ProxyState) -> Result<MessageMeta, LocalInputError> {
    let value: Value = serde_json::from_slice(raw).map_err(LocalInputError::parse)?;
    let object = value
        .as_object()
        .ok_or_else(|| LocalInputError::invalid("invalid JSON-RPC request: expected an object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(LocalInputError::invalid(
            "invalid JSON-RPC request: expected version 2.0",
        ));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty())
        .ok_or_else(|| {
            LocalInputError::invalid("invalid JSON-RPC request: method must be a non-empty string")
        })?
        .to_owned();
    let name = match method.as_str() {
        "tools/call" | "prompts/get" => value.pointer("/params/name"),
        "resources/read" => value.pointer("/params/uri"),
        _ => None,
    }
    .and_then(Value::as_str)
    .map(str::to_owned);
    let protocol_version = if state.initialized {
        state.protocol_version.clone()
    } else {
        value
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .or_else(|| value.pointer("/params/protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or(&state.protocol_version)
            .to_owned()
    };
    for (name, value, limit) in [
        ("method", method.as_str(), 256),
        ("protocol version", protocol_version.as_str(), 64),
    ] {
        if value.len() > limit
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
        {
            return Err(LocalInputError::invalid(format!(
                "invalid {name} for HTTP forwarding"
            )));
        }
    }
    if name.as_ref().is_some_and(|value| value.len() > 4_096) {
        return Err(LocalInputError::invalid(
            "invalid MCP name for HTTP forwarding",
        ));
    }
    Ok(MessageMeta {
        id: object.get("id").cloned(),
        method,
        name,
        protocol_version,
    })
}

fn encode_header_value(value: &str) -> String {
    let plain = !value.is_empty()
        && !value.starts_with([' ', '\t'])
        && !value.ends_with([' ', '\t'])
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    if plain {
        value.to_owned()
    } else {
        format!("=?base64?{}?=", BASE64.encode(value))
    }
}

fn forward(
    agent: &ureq::Agent,
    endpoint: &str,
    token: Option<&str>,
    state: &mut ProxyState,
    meta: &MessageMeta,
    raw: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    match forward_once(agent, endpoint, token, state, meta, raw) {
        Err(error) if error == SESSION_NOT_FOUND => {
            recover_session(
                agent,
                endpoint,
                token,
                state,
                meta.method != "notifications/initialized",
            )?;
            let retry_meta = message_meta(raw, state).map_err(|error| {
                format!("stored proxy request became invalid: {}", error.message)
            })?;
            forward_once(agent, endpoint, token, state, &retry_meta, raw)
        }
        result => result,
    }
}

fn recover_session(
    agent: &ureq::Agent,
    endpoint: &str,
    token: Option<&str>,
    state: &mut ProxyState,
    replay_initialized_notification: bool,
) -> Result<(), String> {
    let initialize_request = state
        .initialize_request
        .clone()
        .ok_or_else(|| SESSION_NOT_FOUND.to_owned())?;
    let initialized_notification = replay_initialized_notification
        .then(|| state.initialized_notification.clone())
        .flatten();
    reset_session_state(state);
    let initialize_meta = message_meta(&initialize_request, state)
        .map_err(|error| format!("stored initialize request is invalid: {}", error.message))?;
    // The initialize response establishes proxy state but is never forwarded
    // to stdio. The single direct retry below prevents a stale session loop.
    forward_once(
        agent,
        endpoint,
        token,
        state,
        &initialize_meta,
        &initialize_request,
    )?;
    if !state.initialized {
        return Err("upstream initialize response did not establish a session".into());
    }
    if let Some(notification) = initialized_notification {
        let notification_meta = message_meta(&notification, state).map_err(|error| {
            format!(
                "stored initialized notification is invalid: {}",
                error.message
            )
        })?;
        forward_once(
            agent,
            endpoint,
            token,
            state,
            &notification_meta,
            &notification,
        )?;
    }
    Ok(())
}

fn reset_session_state(state: &mut ProxyState) {
    state.protocol_version = DEFAULT_PROTOCOL_VERSION.to_owned();
    state.session_id = None;
    state.initialized = false;
    state.initialize_request = None;
    state.initialized_notification = None;
}

fn apply_initialize_response(
    state: &mut ProxyState,
    raw: &[u8],
    response_value: &Value,
    response_session: Option<String>,
) -> Result<(), String> {
    if response_value.get("error").is_some() {
        return Ok(());
    }
    let Some(version) = response_value
        .pointer("/result/protocolVersion")
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    let session_id = if matches!(version, "2025-06-18" | "2025-11-25") {
        match response_session {
            Some(session)
                if !session.is_empty()
                    && session.len() <= 128
                    && session.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) =>
            {
                Some(session)
            }
            Some(_) => {
                reset_session_state(state);
                return Err("upstream returned an invalid MCP session ID".into());
            }
            None => {
                reset_session_state(state);
                return Err("upstream omitted required MCP session ID".into());
            }
        }
    } else {
        None
    };
    state.protocol_version = version.to_owned();
    state.session_id = session_id;
    state.initialized = true;
    state.initialize_request = Some(raw.to_vec());
    state.initialized_notification = None;
    Ok(())
}

fn forward_once(
    agent: &ureq::Agent,
    endpoint: &str,
    token: Option<&str>,
    state: &mut ProxyState,
    meta: &MessageMeta,
    raw: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let mut request = agent
        .post(endpoint)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream")
        .set("Accept-Encoding", "identity")
        .set(WORKING_DIRECTORY_HEADER, &state.working_directory);
    if meta.protocol_version == "2026-07-28" {
        request = request.set("Mcp-Method", &meta.method);
        if let Some(name) = meta.name.as_deref() {
            request = request.set("Mcp-Name", &encode_header_value(name));
        }
    }
    // The initialize body advertises the client's requested revision. Do not
    // turn that unnegotiated value into a transport assertion: the service
    // must be able to select a supported fallback first.
    if let Some(version) = protocol_version_header(meta) {
        request = request.set("Mcp-Protocol-Version", version);
    }
    let sent_session_id = if matches!(meta.protocol_version.as_str(), "2025-06-18" | "2025-11-25") {
        if let Some(session_id) = state.session_id.as_deref() {
            request = request.set("Mcp-Session-Id", session_id);
            Some(session_id)
        } else {
            None
        }
    } else {
        None
    };
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }

    let response = match request.send_bytes(raw) {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(_)) => return Err("upstream request failed".into()),
    };
    let status = response.status();
    if status == 404 && sent_session_id.is_some() {
        return Err(SESSION_NOT_FOUND.into());
    }
    let response_type = response.content_type().trim().to_owned();
    let content_length = response
        .header("Content-Length")
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| "upstream returned an invalid content length".to_owned())?;
    let response_session = response.header("Mcp-Session-Id").map(str::to_owned);
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| "upstream response could not be read completely".to_owned())?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(format!(
            "upstream response exceeds {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    if content_length.is_some_and(|length| length != body.len()) {
        return Err("upstream response was truncated".into());
    }
    if meta.is_notification() && status == 202 && body.is_empty() {
        if meta.method == "notifications/initialized" {
            state.initialized_notification = Some(raw.to_vec());
        }
        return Ok(None);
    }
    let (body, response_value) = decode_response_body(body, &response_type, meta, status)?;
    if !(200..300).contains(&status) {
        if response_value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || !response_value.get("error").is_some_and(Value::is_object)
        {
            return Err(format!(
                "upstream returned invalid HTTP {status} JSON-RPC error"
            ));
        }
        return if meta.is_notification() {
            Err(format!("upstream returned HTTP {status}"))
        } else {
            Ok(Some(body))
        };
    }

    if meta.method == "notifications/initialized" && meta.is_notification() {
        state.initialized_notification = Some(raw.to_vec());
    }
    if meta.method == "initialize" {
        apply_initialize_response(state, raw, &response_value, response_session)?;
    }
    Ok((!meta.is_notification()).then_some(body))
}

fn decode_response_body(
    body: Vec<u8>,
    content_type: &str,
    meta: &MessageMeta,
    status: u16,
) -> Result<(Vec<u8>, Value), String> {
    if content_type.eq_ignore_ascii_case("application/json") {
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| "upstream response is not valid JSON".to_owned())?;
        if let Some(request_id) = meta.id.as_ref() {
            let response_id = value.get("id");
            let transport_error_without_id =
                !(200..300).contains(&status) && response_id.is_none_or(Value::is_null);
            if response_id != Some(request_id) && !transport_error_without_id {
                return Err("upstream response ID does not match request ID".into());
            }
        }
        return Ok((body, value));
    }
    if !content_type.eq_ignore_ascii_case("text/event-stream") {
        return Err("upstream response content-type is not MCP JSON or SSE".into());
    }
    if !(200..300).contains(&status) || meta.id.is_none() {
        return Err("upstream returned an invalid MCP SSE response".into());
    }

    // One stdio request maps to one finite POST response. There is no GET
    // stream to poll or resume; closing before the final response is an error.
    let events = sse_data_events(&body)?;
    let (last, notifications) = events
        .split_last()
        .ok_or_else(|| "upstream SSE response contains no JSON-RPC messages".to_owned())?;
    let mut forwarded = Vec::new();
    for event in notifications {
        let value: Value = serde_json::from_slice(event)
            .map_err(|_| "upstream SSE notification is not valid JSON".to_owned())?;
        if value.get("id").is_some() || value.get("method").and_then(Value::as_str).is_none() {
            return Err("upstream SSE contains an invalid JSON-RPC notification".into());
        }
        serde_json::to_writer(&mut forwarded, &value)
            .map_err(|_| "upstream SSE message could not be serialized".to_owned())?;
        forwarded.push(b'\n');
    }
    let value: Value = serde_json::from_slice(last)
        .map_err(|_| "upstream SSE final response is not valid JSON".to_owned())?;
    if value.get("id") != meta.id.as_ref() {
        return Err("upstream SSE response ID does not match request ID".into());
    }
    serde_json::to_writer(&mut forwarded, &value)
        .map_err(|_| "upstream SSE message could not be serialized".to_owned())?;
    Ok((forwarded, value))
}

fn sse_data_events(body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let body = std::str::from_utf8(body)
        .map_err(|_| "upstream SSE response is not UTF-8".to_owned())?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut events = Vec::new();
    let mut data: Vec<&str> = Vec::new();
    for line in body.split('\n') {
        if line.is_empty() {
            if !data.is_empty() {
                if data.iter().any(|value| !value.is_empty()) {
                    events.push(data.join("\n").into_bytes());
                }
                data.clear();
            }
        } else if let Some(value) = line.strip_prefix("data:") {
            data.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    if !data.is_empty() && data.iter().any(|value| !value.is_empty()) {
        events.push(data.join("\n").into_bytes());
    }
    Ok(events)
}

fn protocol_version_header(meta: &MessageMeta) -> Option<&str> {
    (meta.method != "initialize").then_some(meta.protocol_version.as_str())
}

fn cleanup_session(
    agent: &ureq::Agent,
    endpoint: &str,
    token: Option<&str>,
    state: &ProxyState,
) -> Result<(), String> {
    let Some(session_id) = state.session_id.as_deref() else {
        return Ok(());
    };
    let mut request = agent
        .delete(endpoint)
        .set("Mcp-Session-Id", session_id)
        .set("Mcp-Protocol-Version", &state.protocol_version)
        .set(WORKING_DIRECTORY_HEADER, &state.working_directory);
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    match request.call() {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(404 | 405, _)) => Ok(()),
        Err(ureq::Error::Status(status, _)) => Err(format!("upstream returned HTTP {status}")),
        Err(ureq::Error::Transport(_)) => Err("upstream request failed".into()),
    }
}

fn write_error(writer: &mut impl Write, id: Value, code: i64, message: &str) -> Result<()> {
    serde_json::to_writer(
        &mut *writer,
        &JsonRpcResponse::err(id, code, message.to_owned()),
    )?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn write_body(writer: &mut impl Write, body: &[u8]) -> Result<()> {
    writer.write_all(body)?;
    if !body.ends_with(b"\n") {
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn read_capped_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> io::Result<Option<bool>> {
    buffer.clear();
    let read = reader
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_until(b'\n', buffer)?;
    if read == 0 {
        return Ok(None);
    }
    if buffer.last() != Some(&b'\n') && read == MAX_REQUEST_BYTES + 1 {
        let mut scratch = Vec::with_capacity(64 * 1024);
        loop {
            scratch.clear();
            let drained = reader.take(1024 * 1024).read_until(b'\n', &mut scratch)?;
            if drained == 0 || scratch.last() == Some(&b'\n') {
                break;
            }
        }
        return Ok(Some(false));
    }
    Ok(Some(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;

    #[test]
    fn endpoint_and_metadata_stay_inside_the_proxy_contract() {
        assert_eq!(
            endpoint_url("http://127.0.0.1:1234/", false).unwrap(),
            "http://127.0.0.1:1234/mcp"
        );
        assert_eq!(
            endpoint_url("http://127.0.0.1:1234/base/path/", true).unwrap(),
            "http://127.0.0.1:1234/base/path/mcp?compact=true"
        );
        assert_eq!(
            endpoint_url("http://[::1]:1234/", false).unwrap(),
            "http://[::1]:1234/mcp"
        );
        for invalid in [
            "https://127.0.0.1:1234/",
            "http://example.com/",
            "http://user@127.0.0.1:1234/",
            "http://127.0.0.1:1234/#fragment",
        ] {
            assert!(endpoint_url(invalid, false).is_err(), "accepted {invalid}");
        }

        let modern = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"icm_memory_recall","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
        let mut state = ProxyState {
            protocol_version: DEFAULT_PROTOCOL_VERSION.into(),
            session_id: None,
            initialized: false,
            initialize_request: None,
            initialized_notification: None,
            working_directory: "/tmp/client project".into(),
        };
        let meta = message_meta(modern, &state).unwrap();
        assert_eq!(meta.protocol_version, "2026-07-28");
        assert_eq!(meta.method, "tools/call");
        assert_eq!(meta.name.as_deref(), Some("icm_memory_recall"));
        let resource = r#"{"jsonrpc":"2.0","id":8,"method":"resources/read","params":{"uri":"Hello, 世界","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
        let meta = message_meta(resource.as_bytes(), &state).unwrap();
        assert_eq!(meta.name.as_deref(), Some("Hello, 世界"));
        assert_eq!(
            encode_header_value(meta.name.as_deref().unwrap()),
            "=?base64?SGVsbG8sIOS4lueVjA==?="
        );
        assert_eq!(
            encode_header_value("=?base64?literal?="),
            "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="
        );

        state.protocol_version = "2025-11-25".into();
        state.session_id = Some("session".into());
        state.initialized = true;
        assert_eq!(
            message_meta(modern, &state).unwrap().protocol_version,
            "2025-11-25"
        );
    }

    #[test]
    fn initialize_does_not_assert_an_unnegotiated_protocol_header() {
        let state = ProxyState {
            protocol_version: DEFAULT_PROTOCOL_VERSION.into(),
            session_id: None,
            initialized: false,
            initialize_request: None,
            initialized_notification: None,
            working_directory: "/tmp/client project".into(),
        };
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#;
        let meta = message_meta(initialize, &state).unwrap();
        assert_eq!(protocol_version_header(&meta), None);

        let state = ProxyState {
            protocol_version: "2025-11-25".into(),
            session_id: Some("session".into()),
            initialized: true,
            initialize_request: None,
            initialized_notification: None,
            working_directory: "/tmp/client project".into(),
        };
        let listed = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let meta = message_meta(listed, &state).unwrap();
        assert_eq!(protocol_version_header(&meta), Some("2025-11-25"));
    }

    #[test]
    fn proxy_keeps_connects_short_without_capping_tool_calls_at_five_seconds() {
        let configuration = format!("{:?}", proxy_agent());
        assert!(configuration.contains("timeout_connect: Some(5s)"));
        assert!(configuration.contains("timeout_read: Some(300s)"));
        assert!(configuration.contains("timeout_write: Some(5s)"));
        assert!(configuration.contains("timeout: None"));
    }

    #[test]
    fn proxy_decodes_finite_sse_and_accepts_transport_errors_without_ids() {
        let meta = MessageMeta {
            id: Some(json!(7)),
            method: "tools/call".into(),
            name: Some("icm_memory_stats".into()),
            protocol_version: "2026-07-28".into(),
        };
        let sse = br#": heartbeat

id: priming

data:

data: {"jsonrpc":"2.0",
data: "method":"notifications/progress",
data: "params":{}}

data: {"jsonrpc":"2.0",
data: "id":7,
data: "result":{"ok":true}}

"#;
        let (forwarded, response) =
            decode_response_body(sse.to_vec(), "text/event-stream", &meta, 200).unwrap();
        assert_eq!(response["result"]["ok"], true);
        let lines: Vec<_> = forwarded.split(|byte| *byte == b'\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines
            .iter()
            .all(|line| serde_json::from_slice::<Value>(line).is_ok()));

        let unfinished = b"id: priming\n\ndata:\n\n";
        assert_eq!(
            decode_response_body(unfinished.to_vec(), "text/event-stream", &meta, 200).unwrap_err(),
            "upstream SSE response contains no JSON-RPC messages"
        );

        let error = br#"{"jsonrpc":"2.0","error":{"code":-32020,"message":"mismatch"}}"#;
        let (forwarded, response) =
            decode_response_body(error.to_vec(), "application/json", &meta, 400).unwrap();
        assert_eq!(forwarded, error);
        assert_eq!(response["error"]["code"], -32020);

        let wrong_id = br#"{"jsonrpc":"2.0","id":8,"error":{"code":-32020,"message":"mismatch"}}"#;
        assert_eq!(
            decode_response_body(wrong_id.to_vec(), "application/json", &meta, 400).unwrap_err(),
            "upstream response ID does not match request ID"
        );
    }

    #[test]
    fn local_input_errors_keep_standard_json_rpc_codes() {
        let state = ProxyState {
            protocol_version: DEFAULT_PROTOCOL_VERSION.into(),
            session_id: None,
            initialized: false,
            initialize_request: None,
            initialized_notification: None,
            working_directory: "/tmp/client project".into(),
        };
        for (raw, expected_code) in [
            (
                br#"{"jsonrpc":"2.0","id":1,"method":"ping""# as &[u8],
                -32700,
            ),
            (br#"{"jsonrpc":"2.0","id":1}"#, -32600),
        ] {
            let error = message_meta(raw, &state).expect_err("invalid local input");
            assert_eq!(error.code, expected_code);
            let mut output = Vec::new();
            write_error(&mut output, Value::Null, error.code, &error.message).unwrap();
            let response: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(response["error"]["code"], expected_code);
        }
    }

    #[test]
    fn invalid_initialize_session_resets_proxy_state() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": "2025-11-25"}
        });
        for response_session in [None, Some("bad\nsession".to_owned())] {
            let mut state = ProxyState {
                protocol_version: "2025-06-18".into(),
                session_id: Some("old".into()),
                initialized: true,
                initialize_request: Some(raw.to_vec()),
                initialized_notification: Some(
                    br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
                ),
                working_directory: "/tmp/client project".into(),
            };
            assert!(
                apply_initialize_response(&mut state, raw, &response, response_session,).is_err()
            );
            assert_eq!(state.protocol_version, DEFAULT_PROTOCOL_VERSION);
            assert!(!state.initialized);
            assert!(state.session_id.is_none());
            assert!(state.initialize_request.is_none());
            assert!(state.initialized_notification.is_none());
        }
    }

    #[test]
    fn cleanup_runs_before_an_error_result_is_returned() {
        let called = Cell::new(false);
        let result = finish_with_cleanup(Err(anyhow::anyhow!("failed")), || {
            called.set(true);
            Ok(())
        });
        assert!(called.get());
        assert!(result.is_err());
    }
}
