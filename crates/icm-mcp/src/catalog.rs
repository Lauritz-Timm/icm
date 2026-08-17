//! The immutable MCP tool catalog.
//!
//! A registration contains every fact needed to list and dispatch a tool.
//! The ordered registration vector is the only order source, and the lookup
//! map points back into that same vector.

use std::any::TypeId;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use icm_core::Embedder;
use icm_store::Store;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::inputs::ModernToolInput;
use crate::protocol::{ProtocolRevision, ToolResult};
use crate::tools::AutoConsolidate;

pub type ToolHandler = for<'a> fn(&ToolContext<'a>, &Value) -> ToolResult;
type InputValidator = fn(&Value) -> Result<(), String>;
type InputNormalizer = fn(&Value) -> Value;
type OutputValidator = fn(&Value, &Value) -> Result<(), String>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbedderRequirement {
    Unused,
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputValidation {
    Legacy2024Unchecked,
    Legacy2024,
    Modern,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolRequirements {
    minimum_protocol_revision: ProtocolRevision,
    store: bool,
    embedder: EmbedderRequirement,
    filesystem_read: bool,
    required_client_capabilities: &'static [&'static str],
    structured_output_from_revision: Option<ProtocolRevision>,
    legacy_visible: bool,
}

impl ToolRequirements {
    pub(crate) const STORE: Self = Self {
        minimum_protocol_revision: ProtocolRevision::V2024_11_05,
        store: true,
        embedder: EmbedderRequirement::Unused,
        filesystem_read: false,
        required_client_capabilities: &[],
        structured_output_from_revision: None,
        legacy_visible: true,
    };

    pub(crate) const fn with_optional_embedder(mut self) -> Self {
        self.embedder = EmbedderRequirement::Optional;
        self
    }

    pub(crate) const fn with_required_embedder(mut self) -> Self {
        self.embedder = EmbedderRequirement::Required;
        self
    }

    pub(crate) const fn with_filesystem_read(mut self) -> Self {
        self.filesystem_read = true;
        self
    }

    fn is_available(self, has_embedder: bool) -> bool {
        self.embedder != EmbedderRequirement::Required || has_embedder
    }

    fn as_value(self) -> Value {
        let embedder = match self.embedder {
            EmbedderRequirement::Unused => "unused",
            EmbedderRequirement::Optional => "optional",
            EmbedderRequirement::Required => "required",
        };
        json!({
            "minimumProtocolRevision": self.minimum_protocol_revision.as_str(),
            "serverFacilities": {
                "store": if self.store { "required" } else { "unused" },
                "embedder": embedder,
                "filesystemRead": if self.filesystem_read { "required" } else { "unused" },
            },
            "requiredClientCapabilities": self.required_client_capabilities,
            "structuredOutputFromRevision": self
                .structured_output_from_revision
                .map(ProtocolRevision::as_str),
            "legacyVisible": self.legacy_visible,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolAnnotations {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

impl ToolAnnotations {
    pub const fn new(
        read_only: bool,
        destructive: bool,
        idempotent: bool,
        open_world: bool,
    ) -> Self {
        Self {
            read_only,
            destructive,
            idempotent,
            open_world,
        }
    }

    fn as_value(self) -> Value {
        json!({
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        })
    }
}

pub struct ToolContext<'a> {
    pub store: &'a Store,
    pub embedder: Option<&'a dyn Embedder>,
    pub compact: bool,
    pub auto_consolidate: AutoConsolidate,
    pub working_directory: &'a Path,
    pub enforce_directory_boundary: bool,
}

pub struct ToolSpec {
    name: &'static str,
    description: &'static str,
    legacy_input_schema: Value,
    modern_input_schema: Value,
    modern_output_schema: Option<Value>,
    modern_output_type: Option<TypeId>,
    validate_output: Option<OutputValidator>,
    legacy_input_normalizer: Option<InputNormalizer>,
    annotations: ToolAnnotations,
    requirements: ToolRequirements,
    validate_input: InputValidator,
    handler: ToolHandler,
}

impl ToolSpec {
    pub fn typed<I>(
        name: &'static str,
        description: &'static str,
        legacy_input_schema: Value,
        legacy_input_normalizer: Option<InputNormalizer>,
        annotations: ToolAnnotations,
        requirements: ToolRequirements,
        handler: ToolHandler,
    ) -> Self
    where
        I: ModernToolInput,
    {
        let modern_input_schema = generated_input_schema::<I>(&legacy_input_schema);

        Self {
            name,
            description,
            legacy_input_schema,
            modern_input_schema,
            modern_output_schema: None,
            modern_output_type: None,
            validate_output: None,
            legacy_input_normalizer,
            annotations,
            requirements,
            validate_input: deserialize_input::<I>,
            handler,
        }
    }

    pub(crate) fn with_output<O>(mut self) -> Self
    where
        O: DeserializeOwned + JsonSchema + 'static,
    {
        self.modern_output_schema = Some(generated_output_schema::<O>());
        self.requirements.structured_output_from_revision = Some(ProtocolRevision::V2025_06_18);
        self.modern_output_type = Some(TypeId::of::<O>());
        self.validate_output = Some(validate_output::<O>);
        self
    }

    fn legacy_definition(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.legacy_input_schema,
        })
    }

    fn modern_definition(&self) -> Value {
        let mut definition = json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.modern_input_schema,
            "annotations": self.annotations.as_value(),
            "_meta": {
                "com.github.rtk-ai.icm/requirements": self.requirements.as_value(),
            },
        });
        if let Some(output_schema) = &self.modern_output_schema {
            definition
                .as_object_mut()
                .expect("tool definitions have object roots")
                .insert("outputSchema".into(), output_schema.clone());
        }
        definition
    }

    fn validate_modern_input(&self, arguments: &Value) -> Result<(), String> {
        (self.validate_input)(arguments)?;
        validate_schema_constraints(arguments, &self.modern_input_schema, "$", 0)
    }

    fn legacy_validation_input(&self, arguments: &Value) -> Value {
        let mut filtered = arguments.clone();
        let Some(object) = filtered.as_object_mut() else {
            return filtered;
        };
        let declared_properties = self
            .legacy_input_schema
            .get("properties")
            .and_then(Value::as_object);
        object.retain(|name, _| {
            declared_properties.is_some_and(|properties| properties.contains_key(name))
        });
        filtered
    }
}

fn deserialize_input<I>(arguments: &Value) -> Result<(), String>
where
    I: DeserializeOwned,
{
    serde_json::from_value::<I>(arguments.clone())
        .map(|_| ())
        .map_err(|error| bounded_error(error.to_string()))
}

fn validate_output<O>(output: &Value, schema: &Value) -> Result<(), String>
where
    O: DeserializeOwned,
{
    serde_json::from_value::<O>(output.clone())
        .map_err(|error| bounded_error(error.to_string()))?;
    validate_schema_constraints(output, schema, "$", 0)
}

fn generated_input_schema<I>(legacy: &Value) -> Value
where
    I: ModernToolInput,
{
    let mut generated = serde_json::to_value(schemars::schema_for!(I))
        .expect("generated tool input schema must serialize");
    let object = generated
        .as_object_mut()
        .expect("tool input schema root must be an object");
    object.insert("additionalProperties".into(), Value::Bool(false));
    object
        .entry("required")
        .or_insert_with(|| Value::Array(Vec::new()));

    // The frozen 2024 projection carries carefully worded descriptions,
    // defaults, and numeric bounds. Copy those annotations onto the schema
    // generated from the Rust DTO; field shape and requiredness still come
    // solely from the type.
    if let (Some(modern_properties), Some(legacy_properties)) = (
        object.get_mut("properties").and_then(Value::as_object_mut),
        legacy.get("properties").and_then(Value::as_object),
    ) {
        for (name, legacy_property) in legacy_properties {
            let Some(modern_property) = modern_properties
                .get_mut(name)
                .and_then(Value::as_object_mut)
            else {
                continue;
            };
            for metadata_key in ["description", "default", "minimum", "maximum"] {
                if let Some(value) = legacy_property.get(metadata_key) {
                    modern_property.insert(metadata_key.into(), value.clone());
                }
            }
        }
    }

    I::refine_schema(&mut generated);

    generated
}

fn generated_output_schema<O>() -> Value
where
    O: JsonSchema,
{
    let mut settings = schemars::generate::SchemaSettings::draft2020_12().for_serialize();
    settings.meta_schema = None;
    let schema = settings.into_generator().into_root_schema_for::<O>();
    let mut value = serde_json::to_value(schema).expect("generated output schema must serialize");
    normalize_output_schema(&mut value);
    value
}

fn normalize_output_schema(value: &mut Value) {
    let Value::Object(object) = value else {
        if let Value::Array(values) = value {
            values.iter_mut().for_each(normalize_output_schema);
        }
        return;
    };

    object.remove("title");
    if object.get("format").and_then(Value::as_str) != Some("date-time") {
        object.remove("format");
    }
    object.values_mut().for_each(normalize_output_schema);

    if object.contains_key("const") {
        object.remove("type");
    }

    if let Some(Value::Array(types)) = object.get("type") {
        let non_null: Vec<_> = types
            .iter()
            .filter(|value| value.as_str() != Some("null"))
            .cloned()
            .collect();
        if non_null.len() == 1 && non_null.len() + 1 == types.len() {
            let Some(non_null_type) = non_null.into_iter().next() else {
                return;
            };
            let mut non_null_schema = std::mem::take(object);
            non_null_schema.insert("type".into(), non_null_type);
            if let Some(Value::Array(values)) = non_null_schema.get_mut("enum") {
                values.retain(|value| !value.is_null());
            }
            object.insert("oneOf".into(), json!([non_null_schema, { "type": "null" }]));
            return;
        }
    }

    let nullable_any_of = object
        .get("anyOf")
        .and_then(Value::as_array)
        .is_some_and(|variants| {
            variants.len() == 2
                && variants
                    .iter()
                    .any(|variant| variant.get("type").and_then(Value::as_str) == Some("null"))
        });
    if nullable_any_of {
        if let Some(variants) = object.remove("anyOf") {
            object.insert("oneOf".into(), variants);
        }
    }
}

fn validate_schema_constraints(
    value: &Value,
    schema: &Value,
    path: &str,
    depth: usize,
) -> Result<(), String> {
    validate_schema_constraints_at(value, schema, schema, path, depth)
}

fn validate_schema_constraints_at(
    value: &Value,
    schema: &Value,
    root_schema: &Value,
    path: &str,
    depth: usize,
) -> Result<(), String> {
    if depth > 32 {
        return Err("input nesting exceeds maximum depth".into());
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let Some(referenced) = reference
            .strip_prefix('#')
            .and_then(|pointer| root_schema.pointer(pointer))
        else {
            return Err(format!("{path} contains an unresolved schema reference"));
        };
        return validate_schema_constraints_at(value, referenced, root_schema, path, depth + 1);
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_i64) {
        if value.as_i64().is_some_and(|actual| actual < minimum) {
            return Err(format!("{path} must be at least {minimum}"));
        }
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_i64) {
        if value.as_i64().is_some_and(|actual| actual > maximum) {
            return Err(format!("{path} must be at most {maximum}"));
        }
    }
    if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
        if value
            .as_str()
            .is_some_and(|actual| actual.chars().count() < minimum as usize)
        {
            return Err(format!("{path} is shorter than {minimum} characters"));
        }
    }
    if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64) {
        if value
            .as_str()
            .is_some_and(|actual| actual.chars().count() > maximum as usize)
        {
            return Err(format!("{path} is longer than {maximum} characters"));
        }
    }
    if let Some(maximum) = schema.get("x-icm-maxUtf8Bytes").and_then(Value::as_u64) {
        if value
            .as_str()
            .is_some_and(|actual| actual.len() > maximum as usize)
        {
            return Err(format!("{path} exceeds {maximum} UTF-8 bytes"));
        }
    }
    if schema.get("x-icm-trimmedNonEmpty") == Some(&Value::Bool(true))
        && value
            .as_str()
            .is_some_and(|actual| actual.trim().is_empty())
    {
        return Err(format!("{path} must not be empty or whitespace"));
    }

    if let (Some(properties), Some(object)) = (
        schema.get("properties").and_then(Value::as_object),
        value.as_object(),
    ) {
        for (name, child) in object {
            if let Some(child_schema) = properties.get(name) {
                validate_schema_constraints_at(
                    child,
                    child_schema,
                    root_schema,
                    &format!("{path}.{name}"),
                    depth + 1,
                )?;
            }
        }
    }
    if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
        for (index, child) in array.iter().enumerate() {
            validate_schema_constraints_at(
                child,
                items,
                root_schema,
                &format!("{path}[{index}]"),
                depth + 1,
            )?;
        }
    }
    Ok(())
}

fn bounded_error(mut message: String) -> String {
    const MAX_ERROR_BYTES: usize = 512;
    if message.len() > MAX_ERROR_BYTES {
        let mut end = MAX_ERROR_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push('…');
    }
    message
}

pub enum DispatchResult {
    UnknownTool,
    InvalidInput(String),
    ToolResult(ToolResult),
}

pub struct ToolCatalog {
    registrations: Vec<ToolSpec>,
    by_name: HashMap<&'static str, usize>,
    has_embedder: bool,
    legacy_list: Value,
    modern_list: Value,
}

impl ToolCatalog {
    pub fn new(registrations: Vec<ToolSpec>, has_embedder: bool) -> Result<Self, String> {
        let mut names = HashSet::with_capacity(registrations.len());
        for registration in &registrations {
            if !names.insert(registration.name) {
                return Err(format!(
                    "duplicate MCP tool registration: {}",
                    registration.name
                ));
            }
        }

        let by_name = registrations
            .iter()
            .enumerate()
            .map(|(index, registration)| (registration.name, index))
            .collect();

        let legacy_tools: Vec<Value> = registrations
            .iter()
            .filter(|registration| {
                registration.requirements.legacy_visible
                    && registration.requirements.is_available(has_embedder)
            })
            .map(ToolSpec::legacy_definition)
            .collect();
        let modern_tools: Vec<Value> = registrations
            .iter()
            .filter(|registration| registration.requirements.is_available(has_embedder))
            .map(ToolSpec::modern_definition)
            .collect();

        Ok(Self {
            registrations,
            by_name,
            has_embedder,
            legacy_list: json!({ "tools": legacy_tools }),
            modern_list: json!({ "tools": modern_tools }),
        })
    }

    pub fn legacy_list(&self) -> Value {
        self.legacy_list.clone()
    }

    pub fn modern_list(&self) -> Value {
        self.modern_list.clone()
    }

    pub fn dispatch(
        &self,
        context: &ToolContext<'_>,
        name: &str,
        arguments: &Value,
        validation: InputValidation,
    ) -> DispatchResult {
        let Some(index) = self.by_name.get(name) else {
            return DispatchResult::UnknownTool;
        };
        let registration = &self.registrations[*index];
        if validation == InputValidation::Modern
            && !registration.requirements.is_available(self.has_embedder)
        {
            return DispatchResult::UnknownTool;
        }
        let normalized_arguments = matches!(
            validation,
            InputValidation::Legacy2024Unchecked | InputValidation::Legacy2024
        )
        .then_some(registration.legacy_input_normalizer)
        .flatten()
        .map(|normalize| normalize(arguments));
        let dispatch_arguments = normalized_arguments.as_ref().unwrap_or(arguments);
        if matches!(
            validation,
            InputValidation::Legacy2024 | InputValidation::Modern
        ) {
            let legacy_arguments = (validation == InputValidation::Legacy2024)
                .then(|| registration.legacy_validation_input(dispatch_arguments));
            let validation_arguments = legacy_arguments.as_ref().unwrap_or(dispatch_arguments);
            if let Err(message) = registration.validate_modern_input(validation_arguments) {
                return DispatchResult::InvalidInput(message);
            }
        }
        let result = (registration.handler)(context, dispatch_arguments);
        if validation == InputValidation::Modern && !result.is_error {
            let type_matches = result.structured_content_type() == registration.modern_output_type;
            let value_matches = registration.validate_output.is_none_or(|validate_output| {
                result
                    .structured_content
                    .as_deref()
                    .zip(registration.modern_output_schema.as_ref())
                    .is_some_and(|(output, schema)| validate_output(output, schema).is_ok())
            });
            if !type_matches || !value_matches {
                return DispatchResult::ToolResult(ToolResult::error(format!(
                    "tool {} emitted output that does not match its advertised schema",
                    registration.name
                )));
            }
        }
        DispatchResult::ToolResult(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_TOOLS: [(&str, ToolAnnotations); 31] = [
        (
            "icm_memory_store",
            ToolAnnotations::new(false, true, false, false),
        ),
        (
            "icm_memory_recall",
            ToolAnnotations::new(false, true, false, false),
        ),
        (
            "icm_memory_forget",
            ToolAnnotations::new(false, true, true, false),
        ),
        (
            "icm_memory_forget_topic",
            ToolAnnotations::new(false, true, true, false),
        ),
        ("icm_learn", ToolAnnotations::new(false, true, false, true)),
        (
            "icm_memory_consolidate",
            ToolAnnotations::new(false, true, false, false),
        ),
        (
            "icm_memory_list_topics",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memory_stats",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memory_update",
            ToolAnnotations::new(false, true, false, false),
        ),
        (
            "icm_memory_health",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memoir_create",
            ToolAnnotations::new(false, false, false, false),
        ),
        (
            "icm_memoir_list",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memoir_show",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memoir_add_concept",
            ToolAnnotations::new(false, false, false, false),
        ),
        (
            "icm_memoir_refine",
            ToolAnnotations::new(false, true, false, false),
        ),
        (
            "icm_memoir_search",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memoir_link",
            ToolAnnotations::new(false, false, false, false),
        ),
        (
            "icm_memoir_inspect",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memoir_export",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memory_extract_patterns",
            ToolAnnotations::new(false, false, false, false),
        ),
        (
            "icm_memoir_search_all",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_feedback_record",
            ToolAnnotations::new(false, false, false, false),
        ),
        (
            "icm_feedback_search",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_feedback_stats",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_transcript_start_session",
            ToolAnnotations::new(false, false, false, false),
        ),
        (
            "icm_transcript_record",
            ToolAnnotations::new(false, false, false, false),
        ),
        (
            "icm_transcript_search",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_transcript_show",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_transcript_stats",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_wake_up",
            ToolAnnotations::new(true, false, true, false),
        ),
        (
            "icm_memory_embed_all",
            ToolAnnotations::new(false, false, true, false),
        ),
    ];

    const STRUCTURED_TOOLS: [&str; 11] = [
        "icm_memory_recall",
        "icm_memory_list_topics",
        "icm_memory_stats",
        "icm_feedback_record",
        "icm_feedback_search",
        "icm_feedback_stats",
        "icm_transcript_start_session",
        "icm_transcript_record",
        "icm_transcript_search",
        "icm_transcript_show",
        "icm_transcript_stats",
    ];

    #[test]
    fn annotation_projection_has_all_four_explicit_fields() {
        let value = ToolAnnotations::new(true, false, true, false).as_value();
        assert_eq!(value.as_object().map(serde_json::Map::len), Some(4));
        assert_eq!(value["readOnlyHint"], true);
        assert_eq!(value["destructiveHint"], false);
        assert_eq!(value["idempotentHint"], true);
        assert_eq!(value["openWorldHint"], false);
    }

    #[test]
    fn catalog_is_the_single_order_list_and_dispatch_source() {
        let without_embedder = crate::tools::build_catalog(false);
        let expected_without_embedder: Vec<&str> =
            EXPECTED_TOOLS[..30].iter().map(|(name, _)| *name).collect();
        let without_projection = without_embedder.legacy_list();
        assert_eq!(
            without_projection["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected_without_embedder
        );

        let with_embedder = crate::tools::build_catalog(true);
        let with_projection = with_embedder.legacy_list();
        assert_eq!(
            with_projection["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            EXPECTED_TOOLS
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
        );

        let store = Store::in_memory().unwrap();
        let working_directory = std::env::current_dir().unwrap();
        let context = ToolContext {
            store: &store,
            embedder: None,
            compact: false,
            auto_consolidate: AutoConsolidate::default(),
            working_directory: &working_directory,
            enforce_directory_boundary: true,
        };
        for (name, _) in EXPECTED_TOOLS {
            assert!(matches!(
                with_embedder.dispatch(
                    &context,
                    name,
                    &json!({"__catalog_probe": true}),
                    InputValidation::Modern
                ),
                DispatchResult::InvalidInput(_)
            ));
        }
        assert!(matches!(
            without_embedder.dispatch(
                &context,
                "icm_memory_embed_all",
                &json!({"__catalog_probe": true}),
                InputValidation::Modern
            ),
            DispatchResult::UnknownTool
        ));
    }

    #[test]
    fn modern_projection_has_exact_annotations_and_typed_output_schemas() {
        let catalog = crate::tools::build_catalog(true);
        let projection = catalog.modern_list();
        let tools = projection["tools"].as_array().unwrap();
        assert_eq!(tools.len(), EXPECTED_TOOLS.len());

        for (tool, (expected_name, expected_annotations)) in tools.iter().zip(EXPECTED_TOOLS) {
            assert_eq!(tool["name"], expected_name);
            assert_eq!(tool["annotations"], expected_annotations.as_value());
            assert_eq!(
                tool.pointer("/inputSchema/additionalProperties"),
                Some(&Value::Bool(false))
            );
            assert!(tool
                .pointer("/inputSchema/required")
                .is_some_and(Value::is_array));
            let requirements = &tool["_meta"]["com.github.rtk-ai.icm/requirements"];
            assert_eq!(requirements["minimumProtocolRevision"], "2024-11-05");
            assert_eq!(requirements["serverFacilities"]["store"], "required");
            assert_eq!(requirements["requiredClientCapabilities"], json!([]));
            assert_eq!(
                requirements["structuredOutputFromRevision"],
                if STRUCTURED_TOOLS.contains(&expected_name) {
                    json!("2025-06-18")
                } else {
                    Value::Null
                }
            );
            assert_eq!(requirements["legacyVisible"], true);
            let expected_embedder = if expected_name == "icm_memory_embed_all" {
                "required"
            } else if matches!(
                expected_name,
                "icm_memory_store"
                    | "icm_memory_recall"
                    | "icm_memory_consolidate"
                    | "icm_memory_update"
                    | "icm_feedback_record"
                    | "icm_feedback_search"
            ) {
                "optional"
            } else {
                "unused"
            };
            assert_eq!(
                requirements["serverFacilities"]["embedder"],
                expected_embedder
            );
            assert_eq!(
                requirements["serverFacilities"]["filesystemRead"],
                if expected_name == "icm_learn" {
                    "required"
                } else {
                    "unused"
                }
            );
            assert_eq!(
                tool.get("outputSchema").is_some(),
                STRUCTURED_TOOLS.contains(&expected_name)
            );
            if let Some(schema) = tool.get("outputSchema") {
                assert_eq!(
                    schema.get("additionalProperties"),
                    Some(&Value::Bool(false))
                );
                assert!(!contains_key(schema, "embedding"));
            }
        }
    }

    #[derive(schemars::JsonSchema, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct OutputProbe {
        nested: OutputProbeNested,
    }

    #[derive(schemars::JsonSchema, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct OutputProbeNested {
        #[schemars(length(min = 1))]
        value: String,
    }

    fn output_probe(name: &'static str, handler: ToolHandler) -> ToolSpec {
        ToolSpec::typed::<crate::inputs::MemoryStatsInput>(
            name,
            "test-only emitted output probe",
            json!({"type": "object", "properties": {}}),
            None,
            ToolAnnotations::new(true, false, true, false),
            ToolRequirements::STORE,
            handler,
        )
        .with_output::<OutputProbe>()
    }

    fn valid_output_probe(_: &ToolContext<'_>, _: &Value) -> ToolResult {
        ToolResult::structured(
            "legacy".into(),
            "modern".into(),
            &OutputProbe {
                nested: OutputProbeNested {
                    value: "valid".into(),
                },
            },
        )
    }

    fn malformed_output_probe(context: &ToolContext<'_>, arguments: &Value) -> ToolResult {
        let mut result = valid_output_probe(context, arguments);
        result.structured_content.as_mut().unwrap()["nested"]["value"] = json!("");
        result
    }

    fn missing_output_probe(context: &ToolContext<'_>, arguments: &Value) -> ToolResult {
        let mut result = valid_output_probe(context, arguments);
        result.structured_content = None;
        result
    }

    #[test]
    fn dispatch_validates_the_actual_emitted_output_value() {
        let catalog = ToolCatalog::new(
            vec![
                output_probe("valid_output", valid_output_probe),
                output_probe("malformed_output", malformed_output_probe),
                output_probe("missing_output", missing_output_probe),
            ],
            false,
        )
        .unwrap();
        let store = Store::in_memory().unwrap();
        let working_directory = std::env::current_dir().unwrap();
        let context = ToolContext {
            store: &store,
            embedder: None,
            compact: false,
            auto_consolidate: AutoConsolidate::default(),
            working_directory: &working_directory,
            enforce_directory_boundary: true,
        };

        for (name, is_error) in [
            ("valid_output", false),
            ("malformed_output", true),
            ("missing_output", true),
        ] {
            let DispatchResult::ToolResult(result) =
                catalog.dispatch(&context, name, &json!({}), InputValidation::Modern)
            else {
                panic!("probe should reach its handler");
            };
            assert_eq!(result.is_error, is_error);
        }
    }

    #[test]
    fn dispatch_rejects_structured_output_type_drift() {
        let catalog = ToolCatalog::new(
            vec![ToolSpec::typed::<crate::inputs::MemoryStatsInput>(
                "typed_output_probe",
                "test-only output type probe",
                json!({"type": "object", "properties": {}}),
                None,
                ToolAnnotations::new(true, false, true, false),
                ToolRequirements::STORE,
                |_, _| {
                    ToolResult::structured(
                        "legacy".into(),
                        "modern".into(),
                        &json!({"unexpected": true}),
                    )
                },
            )
            .with_output::<crate::outputs::MemoryStatsOutput>()],
            false,
        )
        .unwrap();
        let store = Store::in_memory().unwrap();
        let working_directory = std::env::current_dir().unwrap();
        let context = ToolContext {
            store: &store,
            embedder: None,
            compact: false,
            auto_consolidate: AutoConsolidate::default(),
            working_directory: &working_directory,
            enforce_directory_boundary: true,
        };

        let DispatchResult::ToolResult(result) = catalog.dispatch(
            &context,
            "typed_output_probe",
            &json!({}),
            InputValidation::Modern,
        ) else {
            panic!("probe should reach its handler");
        };
        assert!(result.is_error);
        assert_eq!(
            result.content[0].text,
            "tool typed_output_probe emitted output that does not match its advertised schema"
        );
    }

    fn contains_key(value: &Value, needle: &str) -> bool {
        match value {
            Value::Object(object) => {
                object.contains_key(needle)
                    || object.values().any(|value| contains_key(value, needle))
            }
            Value::Array(array) => array.iter().any(|value| contains_key(value, needle)),
            _ => false,
        }
    }

    #[test]
    fn modern_schema_and_validator_share_the_frozen_core_bounds() {
        let catalog = crate::tools::build_catalog(false);
        let projection = catalog.modern_list();
        let tools = projection["tools"].as_array().unwrap();
        let store = tools
            .iter()
            .find(|tool| tool["name"] == "icm_memory_store")
            .unwrap();
        assert_eq!(
            store.pointer("/inputSchema/properties/topic/maxLength"),
            Some(&json!(255))
        );
        assert_eq!(
            store.pointer("/inputSchema/properties/content/x-icm-maxUtf8Bytes"),
            Some(&json!(65_536))
        );
        assert_eq!(
            store.pointer("/inputSchema/properties/topic/x-icm-maxUtf8Bytes"),
            Some(&json!(255))
        );
        let recall = tools
            .iter()
            .find(|tool| tool["name"] == "icm_memory_recall")
            .unwrap();
        assert_eq!(
            recall.pointer("/inputSchema/properties/limit/minimum"),
            Some(&json!(1))
        );
        assert_eq!(
            recall.pointer("/inputSchema/properties/limit/maximum"),
            Some(&json!(100))
        );

        for (tool_name, field, maximum) in [
            ("icm_memoir_create", "name", 255),
            ("icm_memoir_create", "description", 10_000),
            ("icm_memoir_add_concept", "name", 255),
            ("icm_memoir_add_concept", "definition", 10_000),
            ("icm_memoir_refine", "name", 255),
            ("icm_memoir_refine", "definition", 10_000),
        ] {
            let tool = tools.iter().find(|tool| tool["name"] == tool_name).unwrap();
            assert_eq!(
                tool.pointer(&format!("/inputSchema/properties/{field}/maxLength")),
                Some(&json!(maximum))
            );
            assert_eq!(
                tool.pointer(&format!(
                    "/inputSchema/properties/{field}/x-icm-maxUtf8Bytes"
                )),
                Some(&json!(maximum))
            );
        }
    }

    #[test]
    fn memoir_schema_byte_limits_match_catalog_runtime_validation() {
        let catalog = crate::tools::build_catalog(false);
        let store = Store::in_memory().unwrap();
        let working_directory = std::env::current_dir().unwrap();
        let context = ToolContext {
            store: &store,
            embedder: None,
            compact: false,
            auto_consolidate: AutoConsolidate::default(),
            working_directory: &working_directory,
            enforce_directory_boundary: true,
        };

        let exact_name = "n".repeat(255);
        let exact_description = "é".repeat(5_000);
        assert!(matches!(
            catalog.dispatch(
                &context,
                "icm_memoir_create",
                &json!({"name":exact_name,"description":exact_description}),
                InputValidation::Modern
            ),
            DispatchResult::ToolResult(_)
        ));

        for arguments in [
            json!({"name":"n".repeat(256)}),
            json!({"name":"é".repeat(128)}),
            json!({"name":"short","description":"d".repeat(10_001)}),
            json!({"name":"short","description":"é".repeat(5_001)}),
        ] {
            assert!(matches!(
                catalog.dispatch(
                    &context,
                    "icm_memoir_create",
                    &arguments,
                    InputValidation::Modern
                ),
                DispatchResult::InvalidInput(_)
            ));
        }

        let exact_concept_name = "c".repeat(255);
        assert!(matches!(
            catalog.dispatch(
                &context,
                "icm_memoir_add_concept",
                &json!({
                    "memoir":exact_name,
                    "name":exact_concept_name,
                    "definition":"d".repeat(10_000)
                }),
                InputValidation::Modern
            ),
            DispatchResult::ToolResult(_)
        ));
        assert!(matches!(
            catalog.dispatch(
                &context,
                "icm_memoir_refine",
                &json!({
                    "memoir":exact_name,
                    "name":exact_concept_name,
                    "definition":"é".repeat(5_000)
                }),
                InputValidation::Modern
            ),
            DispatchResult::ToolResult(_)
        ));

        for (tool, arguments) in [
            (
                "icm_memoir_add_concept",
                json!({"memoir":"m","name":"é".repeat(128),"definition":"valid"}),
            ),
            (
                "icm_memoir_add_concept",
                json!({"memoir":"m","name":"valid","definition":"é".repeat(5_001)}),
            ),
            (
                "icm_memoir_refine",
                json!({"memoir":"m","name":"n".repeat(256),"definition":"valid"}),
            ),
            (
                "icm_memoir_refine",
                json!({"memoir":"m","name":"valid","definition":"d".repeat(10_001)}),
            ),
        ] {
            assert!(matches!(
                catalog.dispatch(&context, tool, &arguments, InputValidation::Modern),
                DispatchResult::InvalidInput(_)
            ));
        }
    }
}
