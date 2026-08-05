use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::sandbox::{ScenarioSandbox, UserStatePaths};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Exchange {
    pub request: String,
    pub response: Option<String>,
    pub duration_micros: u128,
}

pub struct McpClient {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout_rx: Receiver<std::io::Result<String>>,
    stderr_rx: Receiver<Vec<u8>>,
    pub exchanges: Vec<Exchange>,
}

impl McpClient {
    pub fn spawn(
        candidate: &Path,
        sandbox: &ScenarioSandbox,
        compact: bool,
        user_state: &UserStatePaths,
    ) -> Result<Self> {
        if !candidate.is_absolute() {
            anyhow::bail!("candidate path must be absolute: {}", candidate.display());
        }
        let mut arguments = vec![
            "--db".to_owned(),
            sandbox.db.to_string_lossy().into_owned(),
            "--no-embeddings".to_owned(),
            "serve".to_owned(),
        ];
        if compact {
            arguments.push("--compact".to_owned());
        }
        Self::spawn_with_args(candidate, sandbox, &arguments, user_state)
    }

    pub fn spawn_with_args(
        candidate: &Path,
        sandbox: &ScenarioSandbox,
        arguments: &[String],
        user_state: &UserStatePaths,
    ) -> Result<Self> {
        if !candidate.is_absolute() {
            anyhow::bail!("candidate path must be absolute: {}", candidate.display());
        }
        sandbox.verify_child_context(arguments, user_state)?;
        let mut command = Command::new(candidate);
        command.args(arguments);
        command
            .env_clear()
            .envs(sandbox.environment.clone())
            .current_dir(&sandbox.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .with_context(|| format!("spawning candidate {}", candidate.display()))?;
        let stdin = child.stdin.take().context("candidate stdin unavailable")?;
        let stdout = child
            .stdout
            .take()
            .context("candidate stdout unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("candidate stderr unavailable")?;

        let (stdout_tx, stdout_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if stdout_tx.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = stdout_tx.send(Err(error));
                        break;
                    }
                }
            }
        });

        let (stderr_tx, stderr_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut bytes = Vec::new();
            let _ = reader.read_to_end(&mut bytes);
            let _ = stderr_tx.send(bytes);
        });

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout_rx,
            stderr_rx,
            exchanges: Vec::new(),
        })
    }

    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    pub fn request(&mut self, value: Value) -> Result<Value> {
        let raw = serde_json::to_string(&value)?;
        let response = self.send_raw(&raw, true)?;
        let raw_response = response.context("request unexpectedly produced no response")?;
        serde_json::from_str(raw_response.trim_end())
            .with_context(|| format!("parsing candidate response {raw_response:?}"))
    }

    pub fn request_raw(&mut self, value: Value) -> Result<String> {
        let raw = serde_json::to_string(&value)?;
        self.send_raw(&raw, true)?
            .context("request unexpectedly produced no response")
    }

    pub fn notify(&mut self, value: Value) -> Result<()> {
        let raw = serde_json::to_string(&value)?;
        let response = self.send_raw(&raw, false)?;
        if response.is_some() {
            anyhow::bail!("notification incorrectly produced a response");
        }
        Ok(())
    }

    pub fn send_raw(
        &mut self,
        raw_without_newline: &str,
        expect_response: bool,
    ) -> Result<Option<String>> {
        let request = format!("{raw_without_newline}\n");
        let start = Instant::now();
        let stdin = self.stdin.as_mut().context("candidate stdin closed")?;
        stdin.write_all(request.as_bytes())?;
        stdin.flush()?;

        let response = if expect_response {
            let line = self
                .stdout_rx
                .recv_timeout(RESPONSE_TIMEOUT)
                .context("timed out waiting for MCP response")??;
            Some(line)
        } else {
            match self.stdout_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(line)) => Some(line),
                Ok(Err(error)) => return Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => None,
            }
        };

        self.exchanges.push(Exchange {
            request,
            response: response.clone(),
            duration_micros: start.elapsed().as_micros(),
        });
        Ok(response)
    }

    pub fn initialize_legacy(&mut self) -> Result<Value> {
        self.request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "icm-cleanroom-eval", "version": "1"}
            }
        }))
    }

    pub fn initialize_modern(&mut self, version: &str) -> Result<Value> {
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {"tools": {}, "resources": {}},
                "clientInfo": {"name": "icm-cleanroom-eval", "version": "1"}
            }
        }))?;
        if response.get("result").is_some() {
            self.notify(json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }))?;
        }
        Ok(response)
    }

    pub fn request_2026(&mut self, id: u64, method: &str, params: Value) -> Result<Value> {
        self.request(modern_request(id, method, params, true))
    }

    pub fn request_2026_without_client_info(
        &mut self,
        id: u64,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        self.request(modern_request(id, method, params, false))
    }

    pub fn shutdown(mut self) -> Result<ProcessCapture> {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let status = self.child.wait().context("waiting for candidate")?;
        let stderr = self
            .stderr_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        let mut stdout = String::new();
        loop {
            match self.stdout_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(line)) => stdout.push_str(&line),
                Ok(Err(error)) => return Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }
        Ok(ProcessCapture {
            exit_code: status.code(),
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exchanges: std::mem::take(&mut self.exchanges),
        })
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessCapture {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub exchanges: Vec<Exchange>,
}

pub fn result(value: &Value) -> Result<&Value> {
    value
        .get("result")
        .with_context(|| format!("JSON-RPC response has no result: {value}"))
}

pub fn error_code(value: &Value) -> Option<i64> {
    value.pointer("/error/code").and_then(Value::as_i64)
}

pub fn text_content(value: &Value) -> Result<String> {
    let content = result(value)?
        .get("content")
        .and_then(Value::as_array)
        .context("tool response missing result.content array")?;
    let mut output = String::new();
    for item in content {
        if item.get("type").and_then(Value::as_str) == Some("text") {
            output.push_str(item.get("text").and_then(Value::as_str).unwrap_or_default());
        }
    }
    Ok(output)
}

pub fn tool_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    })
}

pub fn tools_list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}})
}

pub fn modern_request(
    id: u64,
    method: &str,
    mut params: Value,
    include_client_info: bool,
) -> Value {
    let object = params
        .as_object_mut()
        .expect("modern request params must be an object");
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        META_PROTOCOL_VERSION.to_owned(),
        Value::String(MODERN_PROTOCOL_VERSION.to_owned()),
    );
    metadata.insert(META_CLIENT_CAPABILITIES.to_owned(), json!({}));
    if include_client_info {
        metadata.insert(
            META_CLIENT_INFO.to_owned(),
            json!({"name":"icm-cleanroom-eval","version":"1"}),
        );
    }
    object.insert("_meta".to_owned(), Value::Object(metadata));
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_has_stable_key_order() {
        let raw = serde_json::to_string(&tool_call(7, "x", json!({}))).unwrap();
        assert!(raw.starts_with("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\""));
    }

    #[test]
    fn modern_metadata_is_nested_and_uses_reserved_full_keys() {
        let request = modern_request(1, "server/discover", json!({}), true);
        assert!(request.get("_meta").is_none());
        assert_eq!(
            request.pointer(&format!(
                "/params/_meta/{}",
                META_PROTOCOL_VERSION.replace('~', "~0").replace('/', "~1")
            )),
            Some(&Value::String(MODERN_PROTOCOL_VERSION.to_owned()))
        );
        assert_eq!(
            request.pointer(&format!(
                "/params/_meta/{}",
                META_CLIENT_CAPABILITIES
                    .replace('~', "~0")
                    .replace('/', "~1")
            )),
            Some(&json!({}))
        );
    }
}
