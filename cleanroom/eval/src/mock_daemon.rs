use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

const MAX_REQUEST_BODY: usize = 2 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestRecord {
    sequence: u64,
    connection_id: u64,
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    authorization: Option<String>,
    body: String,
    model_instance_id: &'static str,
    model_load_count: u64,
    peer_address: String,
    local_address: String,
}

pub fn run(record_path: &Path, mode: &str, ipv6: bool) -> Result<()> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(record_path)?;
    let bind = if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    };
    let listener = TcpListener::bind(bind).context("binding loopback mock daemon")?;
    let address = listener.local_addr()?;
    println!("READY http://{address}/");
    std::io::stdout().flush()?;

    for (connection_index, connection) in listener.incoming().enumerate() {
        let connection_id = connection_index as u64 + 1;
        let mut stream = connection.context("accepting mock daemon connection")?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let peer_address = stream.peer_addr()?;
        let local_address = stream.local_addr()?;
        if !peer_address.ip().is_loopback() || !local_address.ip().is_loopback() {
            anyhow::bail!(
                "mock integration socket was not loopback: peer={peer_address}, local={local_address}"
            );
        }
        let request = read_http_request(&mut stream)?;
        if request.target.ends_with("/__shutdown") {
            write_json_response(&mut stream, 200, "application/json", "{\"shutdown\":true}")?;
            break;
        }
        let record = RequestRecord {
            sequence: connection_id,
            connection_id,
            method: request.method.clone(),
            target: request.target.clone(),
            headers: request.headers.clone(),
            authorization: request.authorization.clone(),
            body: request.body.clone(),
            model_instance_id: "synthetic-model-instance-001",
            model_load_count: 1,
            peer_address: peer_address.to_string(),
            local_address: local_address.to_string(),
        };
        append_record(record_path, &record)?;
        if request.target.contains("force-error") || mode == "no-retry" {
            write_json_response(
                &mut stream,
                503,
                "application/json",
                "{\"error\":\"synthetic unavailable\"}",
            )?;
            continue;
        }
        let response = mock_mcp_response(&request.body, mode);
        let response_json = serde_json::to_string(&response)?;
        match mode {
            "redirect" => {
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{address}/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                write_raw(&mut stream, response.as_bytes())?;
            }
            "bad-content-type" => {
                write_json_response(&mut stream, 200, "text/plain", &response_json)?
            }
            "oversized-response" => {
                let oversized = json!({
                    "jsonrpc":"2.0",
                    "id":request_id(&request.body),
                    "result":{"padding":"x".repeat(10 * 1024 * 1024 + 1)}
                });
                write_json_response(
                    &mut stream,
                    200,
                    "application/json",
                    &serde_json::to_string(&oversized)?,
                )?;
            }
            "invalid-utf8" => write_raw(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n\xff\xfe",
            )?,
            "sse" => write_json_response(&mut stream, 200, "text/event-stream", &response_json)?,
            "truncated" => {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{\"jsonrpc\":",
                    response_json.len() + 100
                );
                write_raw(&mut stream, header.as_bytes())?;
            }
            "timeout" => {
                thread::sleep(Duration::from_secs(12));
            }
            "disappear" => {}
            "hop-by-hop-response" => {
                let raw = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nProxy-Authenticate: synthetic-secret\r\nKeep-Alive: timeout=99\r\n\r\n{}",
                    response_json.len(), response_json
                );
                write_raw(&mut stream, raw.as_bytes())?;
            }
            "legacy-session" if request_method(&request.body) == "initialize" => {
                let raw = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nMcp-Session-Id: synthetic-legacy-session-001\r\nConnection: close\r\n\r\n{}",
                    response_json.len(), response_json
                );
                write_raw(&mut stream, raw.as_bytes())?;
            }
            _ => write_json_response(&mut stream, 200, "application/json", &response_json)?,
        }
    }
    Ok(())
}

struct HttpRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    authorization: Option<String>,
    body: String,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            anyhow::bail!("connection closed before HTTP headers completed");
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() > 128 * 1024 {
            anyhow::bail!("mock HTTP headers exceeded 128 KiB");
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().context("missing HTTP request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .context("missing HTTP method")?
        .to_owned();
    let target = request_parts
        .next()
        .context("missing HTTP target")?
        .to_owned();
    let mut content_length = 0_usize;
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            if name == "content-length" {
                content_length = value.parse()?;
            }
            headers.insert(name, value);
        }
    }
    if content_length > MAX_REQUEST_BODY {
        anyhow::bail!("mock received a request body above its independent 2 MiB ceiling");
    }
    while bytes.len() - header_end < content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            anyhow::bail!("connection closed before HTTP body completed");
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let body = String::from_utf8(bytes[header_end..header_end + content_length].to_vec())?;
    let authorization = headers.get("authorization").cloned();
    Ok(HttpRequest {
        method,
        target,
        headers,
        authorization,
        body,
    })
}

fn request_id(body: &str) -> Value {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(Value::Null)
}

fn request_method(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn mock_mcp_response(body: &str, mode: &str) -> Value {
    let request: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let mut id = request.get("id").cloned().unwrap_or(Value::Null);
    if mode == "id-mismatch" {
        id = json!("synthetic-mismatched-id");
    }
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion":request.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("2025-11-25"),
            "capabilities":{},
            "serverInfo":{"name":"icm-cleanroom-mock","version":"1"}
        }),
        "tools/list" => json!({
            "tools": [],
            "ttlMs": 3600000,
            "cacheScope": "private",
            "resultType": "complete",
            "_meta": {"io.modelcontextprotocol/serverInfo":{"name":"icm-cleanroom-mock","version":"1"}},
            "modelInstanceId": "synthetic-model-instance-001",
            "modelLoadCount": 1
        }),
        "ping" => json!({
            "resultType": "complete",
            "_meta": {"io.modelcontextprotocol/serverInfo":{"name":"icm-cleanroom-mock","version":"1"}},
            "modelInstanceId": "synthetic-model-instance-001",
            "modelLoadCount": 1
        }),
        _ => json!({
            "content": [{"type": "text", "text": "synthetic daemon response"}],
            "structuredContent": {
                "modelInstanceId": "synthetic-model-instance-001",
                "modelLoadCount": 1
            },
            "resultType": "complete",
            "_meta": {"io.modelcontextprotocol/serverInfo":{"name":"icm-cleanroom-mock","version":"1"}}
        }),
    };
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn append_record(path: &Path, record: &RequestRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        503 => "Service Unavailable",
        _ => "Synthetic",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    write_raw(stream, response.as_bytes())
}

fn write_raw(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_response_preserves_or_adversarially_changes_request_id() {
        let normal = mock_mcp_response(r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#, "normal");
        assert_eq!(normal["id"], 9);
        assert_eq!(normal["result"]["modelLoadCount"], 1);
        let mismatched =
            mock_mcp_response(r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#, "id-mismatch");
        assert_ne!(mismatched["id"], 9);
    }
}
