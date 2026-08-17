//! Typed MCP tool inputs.
//!
//! These types are the modern input contract. The catalog derives closed JSON
//! Schemas from them and deserializes every modern call before dispatch. The
//! separate legacy schema projection remains a frozen compatibility artifact.

#![allow(dead_code)]

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

pub trait ModernToolInput: DeserializeOwned + JsonSchema {
    fn refine_schema(_schema: &mut Value) {}
}

fn property<'a>(schema: &'a mut Value, name: &str) -> &'a mut serde_json::Map<String, Value> {
    schema
        .pointer_mut(&format!("/properties/{name}"))
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("generated input schema is missing property {name}"))
}

fn string_bounds(
    schema: &mut Value,
    name: &str,
    minimum_code_points: Option<u64>,
    maximum_code_points: Option<u64>,
    maximum_utf8_bytes: Option<u64>,
) {
    let property = property(schema, name);
    if let Some(minimum) = minimum_code_points {
        property.insert("minLength".into(), json!(minimum));
    }
    if let Some(maximum) = maximum_code_points {
        property.insert("maxLength".into(), json!(maximum));
    }
    if let Some(maximum) = maximum_utf8_bytes {
        // JSON Schema has no UTF-8 byte-length keyword. Keep the portable
        // code-point ceiling and publish the exact byte contract as a local
        // annotation that the catalog validator enforces before dispatch.
        property.insert("x-icm-maxUtf8Bytes".into(), json!(maximum));
    }
}

fn integer_bounds(schema: &mut Value, name: &str, minimum: i64, maximum: i64) {
    let property = property(schema, name);
    property.insert("minimum".into(), json!(minimum));
    property.insert("maximum".into(), json!(maximum));
}

fn topic_bounds(schema: &mut Value, name: &str) {
    string_bounds(schema, name, Some(1), Some(255), Some(255));
    property(schema, name).insert("x-icm-trimmedNonEmpty".into(), Value::Bool(true));
}

fn content_bounds(schema: &mut Value, name: &str) {
    string_bounds(schema, name, Some(1), Some(65_536), Some(65_536));
    property(schema, name).insert("x-icm-trimmedNonEmpty".into(), Value::Bool(true));
}

macro_rules! default_contract {
    ($($name:ty),+ $(,)?) => {
        $(impl ModernToolInput for $name {})+
    };
}

macro_rules! empty_input {
    ($name:ident) => {
        #[derive(Debug, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {}
    };
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportanceInput {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationInput {
    PartOf,
    DependsOn,
    RelatedTo,
    Contradicts,
    Refines,
    AlternativeTo,
    CausedBy,
    InstanceOf,
    SupersededBy,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormatInput {
    Json,
    Dot,
    Ascii,
    Ai,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TranscriptRoleInput {
    User,
    Assistant,
    System,
    Tool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WakeUpFormatInput {
    Markdown,
    Plain,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryStoreInput {
    pub topic: String,
    pub content: String,
    pub importance: Option<ImportanceInput>,
    pub keywords: Option<Vec<String>>,
    pub raw_excerpt: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecallInput {
    pub query: String,
    pub topic: Option<String>,
    pub limit: Option<i64>,
    pub keyword: Option<String>,
    pub project: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryForgetInput {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopicInput {
    pub topic: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearnInput {
    pub directory: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryConsolidateInput {
    pub topic: String,
    pub summary: String,
}

empty_input!(MemoryListTopicsInput);
empty_input!(MemoryStatsInput);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryUpdateInput {
    pub id: String,
    pub content: String,
    pub importance: Option<ImportanceInput>,
    pub keywords: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryHealthInput {
    pub topic: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirCreateInput {
    pub name: String,
    pub description: Option<String>,
}

empty_input!(MemoirListInput);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NameInput {
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirAddConceptInput {
    pub memoir: String,
    pub name: String,
    pub definition: String,
    pub labels: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirRefineInput {
    pub memoir: String,
    pub name: String,
    pub definition: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirSearchInput {
    pub memoir: String,
    pub query: String,
    pub label: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirLinkInput {
    pub memoir: String,
    pub r#from: String,
    pub to: String,
    pub relation: RelationInput,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirInspectInput {
    pub memoir: String,
    pub name: String,
    pub depth: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirExportInput {
    pub name: String,
    pub format: Option<ExportFormatInput>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractPatternsInput {
    pub topic: String,
    pub memoir: Option<String>,
    pub min_cluster_size: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoirSearchAllInput {
    pub query: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackRecordInput {
    pub topic: String,
    pub context: String,
    pub predicted: String,
    pub corrected: String,
    pub reason: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackSearchInput {
    pub query: String,
    pub topic: Option<String>,
    pub limit: Option<i64>,
}

empty_input!(FeedbackStatsInput);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TranscriptStartInput {
    pub agent: Option<String>,
    pub project: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TranscriptRecordInput {
    pub session_id: String,
    pub role: TranscriptRoleInput,
    pub content: String,
    pub tool_name: Option<String>,
    pub tokens: Option<i64>,
    pub metadata: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TranscriptSearchInput {
    pub query: String,
    pub session_id: Option<String>,
    pub project: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TranscriptShowInput {
    pub session_id: String,
    pub limit: Option<i64>,
}

empty_input!(TranscriptStatsInput);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeUpInput {
    pub project: Option<String>,
    pub max_tokens: Option<i64>,
    pub format: Option<WakeUpFormatInput>,
    pub include_preferences: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbedAllInput {
    pub topic: Option<String>,
}

impl ModernToolInput for MemoryStoreInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
        content_bounds(schema, "content");
        string_bounds(schema, "raw_excerpt", None, Some(65_536), Some(65_536));
    }
}

impl ModernToolInput for MemoryRecallInput {
    fn refine_schema(schema: &mut Value) {
        string_bounds(schema, "query", Some(1), Some(65_536), Some(65_536));
        property(schema, "query").insert("x-icm-trimmedNonEmpty".into(), Value::Bool(true));
        topic_bounds(schema, "topic");
        integer_bounds(schema, "limit", 1, 100);
    }
}

impl ModernToolInput for TopicInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
    }
}

impl ModernToolInput for MemoryConsolidateInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
        content_bounds(schema, "summary");
    }
}

impl ModernToolInput for MemoryUpdateInput {
    fn refine_schema(schema: &mut Value) {
        content_bounds(schema, "content");
    }
}

impl ModernToolInput for MemoryHealthInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
    }
}

impl ModernToolInput for MemoirCreateInput {
    fn refine_schema(schema: &mut Value) {
        string_bounds(schema, "name", None, Some(255), Some(255));
        string_bounds(schema, "description", None, Some(10_000), Some(10_000));
    }
}

impl ModernToolInput for MemoirAddConceptInput {
    fn refine_schema(schema: &mut Value) {
        string_bounds(schema, "name", None, Some(255), Some(255));
        string_bounds(schema, "definition", None, Some(10_000), Some(10_000));
    }
}

impl ModernToolInput for MemoirRefineInput {
    fn refine_schema(schema: &mut Value) {
        string_bounds(schema, "name", None, Some(255), Some(255));
        string_bounds(schema, "definition", None, Some(10_000), Some(10_000));
    }
}

impl ModernToolInput for MemoirSearchInput {
    fn refine_schema(schema: &mut Value) {
        integer_bounds(schema, "limit", 1, 100);
    }
}

impl ModernToolInput for MemoirInspectInput {
    fn refine_schema(schema: &mut Value) {
        integer_bounds(schema, "depth", 1, 3);
    }
}

impl ModernToolInput for ExtractPatternsInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
        integer_bounds(schema, "min_cluster_size", 2, 50);
    }
}

impl ModernToolInput for MemoirSearchAllInput {
    fn refine_schema(schema: &mut Value) {
        integer_bounds(schema, "limit", 1, 100);
    }
}

impl ModernToolInput for FeedbackRecordInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
        for name in ["context", "predicted", "corrected", "reason"] {
            string_bounds(schema, name, None, Some(20_000), Some(20_000));
        }
    }
}

impl ModernToolInput for FeedbackSearchInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
        integer_bounds(schema, "limit", 1, 100);
    }
}

impl ModernToolInput for TranscriptSearchInput {
    fn refine_schema(schema: &mut Value) {
        integer_bounds(schema, "limit", 1, 50);
    }
}

impl ModernToolInput for TranscriptShowInput {
    fn refine_schema(schema: &mut Value) {
        integer_bounds(schema, "limit", 1, 2_000);
    }
}

impl ModernToolInput for WakeUpInput {
    fn refine_schema(schema: &mut Value) {
        integer_bounds(schema, "max_tokens", 20, 4_000);
    }
}

impl ModernToolInput for EmbedAllInput {
    fn refine_schema(schema: &mut Value) {
        topic_bounds(schema, "topic");
    }
}

default_contract!(
    MemoryForgetInput,
    LearnInput,
    MemoryListTopicsInput,
    MemoryStatsInput,
    MemoirListInput,
    NameInput,
    MemoirLinkInput,
    MemoirExportInput,
    FeedbackStatsInput,
    TranscriptStartInput,
    TranscriptRecordInput,
    TranscriptStatsInput,
);
