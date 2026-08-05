use anyhow::{Context, Result};
use serde_json::Value;

pub fn validate_tool_output(contract: &Value, tool: &str, actual: &Value) -> Result<()> {
    reject_embedding(actual, "$structuredContent")?;
    let schema = contract
        .pointer(&format!("/tools/{tool}"))
        .with_context(|| format!("no frozen output schema for {tool}"))?;
    validate(contract, schema, actual, "$structuredContent")
}

pub fn validate(root: &Value, schema: &Value, actual: &Value, path: &str) -> Result<()> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let pointer = reference
            .strip_prefix('#')
            .context("only local JSON Schema references are supported")?;
        let target = root
            .pointer(pointer)
            .with_context(|| format!("unresolved schema reference {reference}"))?;
        return validate(root, target, actual, path);
    }
    if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
        let successes = options
            .iter()
            .filter(|option| validate(root, option, actual, path).is_ok())
            .count();
        if successes != 1 {
            anyhow::bail!("{path}: expected exactly one oneOf branch, got {successes}");
        }
        return Ok(());
    }
    if let Some(expected) = schema.get("const") {
        if actual != expected {
            anyhow::bail!("{path}: expected constant {expected}, got {actual}");
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.contains(actual) {
            anyhow::bail!("{path}: value {actual} not in enum {values:?}");
        }
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        let matches = match kind {
            "object" => actual.is_object(),
            "array" => actual.is_array(),
            "string" => actual.is_string(),
            "integer" => actual.as_i64().is_some() || actual.as_u64().is_some(),
            "number" => actual.is_number(),
            "boolean" => actual.is_boolean(),
            "null" => actual.is_null(),
            other => anyhow::bail!("{path}: unsupported schema type {other}"),
        };
        if !matches {
            anyhow::bail!("{path}: expected {kind}, got {actual}");
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
        let value = actual
            .as_f64()
            .with_context(|| format!("{path}: minimum applied to non-number"))?;
        if value < minimum {
            anyhow::bail!("{path}: {value} is below minimum {minimum}");
        }
    }
    if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64) {
        let length = actual
            .as_str()
            .with_context(|| format!("{path}: minLength applied to non-string"))?
            .chars()
            .count();
        if length < min_length as usize {
            anyhow::bail!("{path}: string length {length} is below {min_length}");
        }
    }
    if let Some(object) = actual.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    anyhow::bail!("{path}: required property {key} is absent");
                }
            }
        }
        if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
            let properties = properties.context("closed object has no properties")?;
            for key in object.keys() {
                if !properties.contains_key(key) {
                    anyhow::bail!("{path}: additional property {key} is forbidden");
                }
            }
        }
        if let Some(properties) = properties {
            for (key, value) in object {
                if let Some(child_schema) = properties.get(key) {
                    validate(root, child_schema, value, &format!("{path}.{key}"))?;
                }
            }
        }
    }
    if let (Some(array), Some(items)) = (actual.as_array(), schema.get("items")) {
        for (index, item) in array.iter().enumerate() {
            validate(root, items, item, &format!("{path}[{index}]"))?;
        }
    }
    if schema.get("format").and_then(Value::as_str) == Some("date-time") {
        let text = actual
            .as_str()
            .with_context(|| format!("{path}: date-time is not a string"))?;
        chrono::DateTime::parse_from_rfc3339(text)
            .with_context(|| format!("{path}: invalid RFC3339 date-time {text}"))?;
        if !text.ends_with('Z') {
            anyhow::bail!("{path}: timestamp must retain UTC Z spelling: {text}");
        }
    }
    Ok(())
}

pub fn reject_embedding(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key.eq_ignore_ascii_case("embedding") || key.eq_ignore_ascii_case("embeddings") {
                    anyhow::bail!("{path}.{key}: embedding data is forbidden");
                }
                reject_embedding(child, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                reject_embedding(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn closed_objects_reject_extra_fields() {
        let root = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"value": {"type": "string"}},
            "required": ["value"]
        });
        assert!(validate(&root, &root, &json!({"value": "x"}), "$").is_ok());
        assert!(validate(&root, &root, &json!({"value": "x", "extra": 1}), "$").is_err());
    }

    #[test]
    fn embeddings_are_rejected_at_any_depth() {
        assert!(reject_embedding(&json!({"nested": [{"embedding": [1.0]}]}), "$").is_err());
    }
}
