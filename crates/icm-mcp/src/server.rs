//! Bounded stdio framing for the transport-neutral MCP service.

use std::io::{self, BufRead, Read, Write};

use icm_core::Embedder;
use icm_store::Store;
use serde_json::Value;
use tracing::error;

use crate::protocol::{JsonRpcMessage, JsonRpcResponse};
use crate::service::{ConnectionState, McpService};
use crate::tools::AutoConsolidate;

/// Maximum allowed line length (10 MiB). The cap is applied while reading,
/// before the complete caller-controlled frame can be allocated.
pub const MAX_LINE_LEN: usize = 10 * 1024 * 1024;

/// Read one newline-delimited frame while capping caller-controlled allocation.
///
/// The complete oversized frame is drained before returning so the next call
/// starts at a frame boundary. Transports with a smaller protocol-specific cap
/// (for example the HTTP proxy) can reuse this framing primitive.
pub fn read_capped_line_with_limit(
    reader: &mut impl BufRead,
    buffer: &mut Vec<u8>,
    max_line_len: usize,
) -> io::Result<Option<bool>> {
    buffer.clear();
    let bytes_read = reader
        .take(max_line_len as u64 + 1)
        .read_until(b'\n', buffer)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    if buffer.last() != Some(&b'\n') && bytes_read == max_line_len + 1 {
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

fn read_capped_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> io::Result<Option<bool>> {
    read_capped_line_with_limit(reader, buffer, MAX_LINE_LEN)
}

/// Run the MCP server on stdio until stdin closes.
pub fn run_server(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    compact: bool,
    auto_consolidate: AutoConsolidate,
) -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    run_server_with_io(
        store,
        embedder,
        compact,
        auto_consolidate,
        &mut reader,
        &mut writer,
    )
}

/// Generic framing adapter used by stdio and hermetic transport tests.
pub fn run_server_with_io(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    compact: bool,
    auto_consolidate: AutoConsolidate,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> anyhow::Result<()> {
    let service = McpService::new(store, embedder, compact, auto_consolidate);
    let mut state = ConnectionState::default();
    let mut buffer = Vec::new();

    loop {
        let within_limit = match read_capped_line(reader, &mut buffer) {
            Ok(Some(within_limit)) => within_limit,
            Ok(None) => break,
            Err(read_error) => {
                error!("stdin read error: {read_error}");
                break;
            }
        };
        if !within_limit {
            error!("line too long (max {MAX_LINE_LEN} bytes)");
            write_response(
                writer,
                &JsonRpcResponse::err(
                    Value::Null,
                    -32600,
                    format!("line too long (max {MAX_LINE_LEN} bytes)"),
                ),
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
        let line = match std::str::from_utf8(&buffer) {
            Ok(line) => line,
            Err(parse_error) => {
                write_response(
                    writer,
                    &JsonRpcResponse::err(
                        Value::Null,
                        -32700,
                        format!("parse error: {parse_error}"),
                    ),
                )?;
                continue;
            }
        };
        let wire_value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(parse_error) => {
                error!("invalid JSON-RPC: {parse_error}");
                write_response(
                    writer,
                    &JsonRpcResponse::err(
                        Value::Null,
                        -32700,
                        format!("parse error: {parse_error}"),
                    ),
                )?;
                continue;
            }
        };
        let message: JsonRpcMessage = match serde_json::from_value(wire_value) {
            Ok(message) => message,
            Err(request_error) => {
                write_response(
                    writer,
                    &JsonRpcResponse::err(
                        Value::Null,
                        -32600,
                        format!("invalid request: {request_error}"),
                    ),
                )?;
                continue;
            }
        };

        if let Some(response) = service.handle(&mut state, message) {
            write_response(writer, &response)?;
        }
    }
    Ok(())
}

fn write_response(writer: &mut impl Write, response: &JsonRpcResponse) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, response)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use serde_json::json;

    #[test]
    fn in_memory_transport_runs_complete_2024_sequence() {
        let store = Store::in_memory().unwrap();
        let input = [
            json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }
            }),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        ]
        .into_iter()
        .map(|request| format!("{}\n", serde_json::to_string(&request).unwrap()))
        .collect::<String>();
        let mut reader = Cursor::new(input.into_bytes());
        let mut output = Vec::new();
        run_server_with_io(
            &store,
            None,
            false,
            AutoConsolidate::default(),
            &mut reader,
            &mut output,
        )
        .unwrap();
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["result"]["protocolVersion"], "2024-11-05");
        assert!(responses[1]["result"]["tools"].is_array());
    }

    #[test]
    fn oversized_frame_is_drained_before_the_next_request() {
        let mut input = vec![b'x'; MAX_LINE_LEN + 1];
        input.extend_from_slice(b"\n{}");
        let mut reader = Cursor::new(input);
        let mut buffer = Vec::new();
        assert_eq!(
            read_capped_line(&mut reader, &mut buffer).unwrap(),
            Some(false)
        );
        assert_eq!(
            read_capped_line(&mut reader, &mut buffer).unwrap(),
            Some(true)
        );
        assert_eq!(buffer, b"{}");
    }
}
