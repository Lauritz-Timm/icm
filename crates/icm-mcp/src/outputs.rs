//! Typed MCP tool outputs.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use icm_core::{Importance, Memory, MemorySource, Scope, StoreStats};
use schemars::JsonSchema;
use serde::Serialize;

const MAX_RECALL_RAW_EXCERPT_BYTES: usize = 2_048;

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(transparent)]
struct Nullable<T>(Option<T>);

#[derive(Clone, Copy, Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SearchMode {
    Hybrid,
    FullText,
    Keyword,
}

#[derive(Clone, Copy, Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "lowercase")]
enum ImportanceOutput {
    Critical,
    High,
    Medium,
    Low,
}

impl From<Importance> for ImportanceOutput {
    fn from(value: Importance) -> Self {
        match value {
            Importance::Critical => Self::Critical,
            Importance::High => Self::High,
            Importance::Medium => Self::Medium,
            Importance::Low => Self::Low,
        }
    }
}

#[derive(Clone, Copy, Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "lowercase")]
enum ScopeOutput {
    User,
    Project,
    Org,
}

impl From<Scope> for ScopeOutput {
    fn from(value: Scope) -> Self {
        match value {
            Scope::User => Self::User,
            Scope::Project => Self::Project,
            Scope::Org => Self::Org,
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum MemorySourceOutput {
    Manual,
    Conversation {
        thread_id: String,
    },
    ClaudeCode {
        session_id: String,
        file_path: Nullable<String>,
    },
}

impl From<&MemorySource> for MemorySourceOutput {
    fn from(value: &MemorySource) -> Self {
        match value {
            MemorySource::Manual => Self::Manual,
            MemorySource::Conversation { thread_id } => Self::Conversation {
                thread_id: thread_id.clone(),
            },
            MemorySource::ClaudeCode {
                session_id,
                file_path,
            } => Self::ClaudeCode {
                session_id: session_id.clone(),
                file_path: Nullable(file_path.clone()),
            },
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(rename = "memory")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemoryOutput {
    #[schemars(length(min = 1))]
    id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_accessed: DateTime<Utc>,
    access_count: u32,
    weight: f32,
    topic: String,
    summary: String,
    raw_excerpt: Nullable<String>,
    raw_excerpt_truncated: bool,
    raw_excerpt_bytes: Nullable<usize>,
    keywords: Vec<String>,
    importance: ImportanceOutput,
    source: MemorySourceOutput,
    related_ids: Vec<String>,
    scope: ScopeOutput,
    score: Nullable<f32>,
}

impl MemoryOutput {
    fn from_memory(memory: &Memory, score: Option<f32>, visible_ids: &HashSet<&str>) -> Self {
        let (raw_excerpt, raw_excerpt_truncated, raw_excerpt_bytes) =
            bounded_raw_excerpt(memory.raw_excerpt.as_deref());
        Self {
            id: memory.id.clone(),
            created_at: memory.created_at,
            updated_at: memory.updated_at,
            last_accessed: memory.last_accessed,
            access_count: memory.access_count,
            weight: memory.weight,
            topic: memory.topic.clone(),
            summary: memory.summary.clone(),
            raw_excerpt: Nullable(raw_excerpt),
            raw_excerpt_truncated,
            raw_excerpt_bytes: Nullable(raw_excerpt_bytes),
            keywords: memory.keywords.clone(),
            importance: memory.importance.into(),
            source: (&memory.source).into(),
            related_ids: memory
                .related_ids
                .iter()
                .filter(|id| visible_ids.contains(id.as_str()))
                .cloned()
                .collect(),
            scope: memory.scope.into(),
            score: Nullable(score),
        }
    }
}

fn bounded_raw_excerpt(raw: Option<&str>) -> (Option<String>, bool, Option<usize>) {
    let Some(raw) = raw else {
        return (None, false, None);
    };
    let (excerpt, truncated) = truncate_recall_raw(raw);
    (Some(excerpt.to_owned()), truncated, Some(raw.len()))
}

pub(crate) fn truncate_recall_raw(raw: &str) -> (&str, bool) {
    if raw.len() <= MAX_RECALL_RAW_EXCERPT_BYTES {
        return (raw, false);
    }
    let mut end = MAX_RECALL_RAW_EXCERPT_BYTES;
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    (&raw[..end], true)
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MemoryRecallOutput {
    query: String,
    effective_project: Nullable<String>,
    search_mode: SearchMode,
    memories: Vec<MemoryOutput>,
}

impl MemoryRecallOutput {
    pub(crate) fn new(
        query: &str,
        effective_project: Option<&str>,
        search_mode: SearchMode,
        memories: &[(Memory, f32)],
        include_scores: bool,
    ) -> Self {
        let visible_ids: HashSet<&str> = memories
            .iter()
            .map(|(memory, _)| memory.id.as_str())
            .collect();
        Self {
            query: query.to_owned(),
            effective_project: Nullable(effective_project.map(str::to_owned)),
            search_mode,
            memories: memories
                .iter()
                .map(|(memory, score)| {
                    MemoryOutput::from_memory(
                        memory,
                        include_scores.then_some(*score),
                        &visible_ids,
                    )
                })
                .collect(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.memories.len()
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TopicCountOutput {
    topic: String,
    count: usize,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MemoryTopicsOutput {
    topics: Vec<TopicCountOutput>,
    total_topics: usize,
    total_memories: usize,
}

impl MemoryTopicsOutput {
    pub(crate) fn new(topics: &[(String, usize)]) -> Self {
        Self {
            topics: topics
                .iter()
                .map(|(topic, count)| TopicCountOutput {
                    topic: topic.clone(),
                    count: *count,
                })
                .collect(),
            total_topics: topics.len(),
            total_memories: topics.iter().map(|(_, count)| count).sum(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.topics.len()
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MemoryStatsOutput {
    total_memories: usize,
    total_topics: usize,
    average_weight: f32,
    oldest_memory: Nullable<DateTime<Utc>>,
    newest_memory: Nullable<DateTime<Utc>>,
}

impl From<StoreStats> for MemoryStatsOutput {
    fn from(value: StoreStats) -> Self {
        Self {
            total_memories: value.total_memories,
            total_topics: value.total_topics,
            average_weight: value.avg_weight,
            oldest_memory: Nullable(value.oldest_memory),
            newest_memory: Nullable(value.newest_memory),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_output_bounds_raw_excerpt_and_never_contains_embedding() {
        let mut memory = Memory::new("topic".into(), "summary".into(), Importance::Medium);
        memory.raw_excerpt = Some(format!("{}é", "x".repeat(MAX_RECALL_RAW_EXCERPT_BYTES - 1)));
        memory.embedding = Some(vec![0.1, 0.2]);
        let visible = Memory::new("topic".into(), "visible".into(), Importance::Medium);
        memory.related_ids = vec![visible.id.clone(), "hidden-id".into()];

        let value = serde_json::to_value(MemoryRecallOutput::new(
            "query",
            None,
            SearchMode::FullText,
            &[(memory, -1.0), (visible, -1.0)],
            false,
        ))
        .unwrap();
        let first = &value["memories"][0];
        assert_eq!(first["rawExcerptTruncated"], true);
        assert_eq!(first["rawExcerptBytes"], MAX_RECALL_RAW_EXCERPT_BYTES + 1);
        assert!(first["rawExcerpt"]
            .as_str()
            .unwrap()
            .is_char_boundary(2_047));
        assert!(first.get("embedding").is_none());
        assert_eq!(
            first["relatedIds"],
            serde_json::json!([value["memories"][1]["id"]])
        );
    }
}

use icm_core::{Feedback, FeedbackStats, Message, Role, Session, TranscriptHit, TranscriptStats};

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TranscriptStartOutput {
    #[schemars(length(min = 1))]
    session_id: String,
}

impl TranscriptStartOutput {
    pub(crate) fn new(session_id: String) -> Self {
        Self { session_id }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TranscriptRecordOutput {
    #[schemars(length(min = 1))]
    message_id: String,
}

impl TranscriptRecordOutput {
    pub(crate) fn new(message_id: String) -> Self {
        Self { message_id }
    }
}

#[derive(Clone, Copy, Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "lowercase")]
enum TranscriptRoleOutput {
    User,
    Assistant,
    System,
    Tool,
}

impl From<Role> for TranscriptRoleOutput {
    fn from(value: Role) -> Self {
        match value {
            Role::User => Self::User,
            Role::Assistant => Self::Assistant,
            Role::System => Self::System,
            Role::Tool => Self::Tool,
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(rename = "message")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TranscriptMessageOutput {
    id: String,
    session_id: String,
    role: TranscriptRoleOutput,
    content: String,
    tool_name: Nullable<String>,
    tokens: Nullable<i64>,
    timestamp: DateTime<Utc>,
    metadata: String,
}

impl From<&Message> for TranscriptMessageOutput {
    fn from(value: &Message) -> Self {
        Self {
            id: value.id.clone(),
            session_id: value.session_id.clone(),
            role: value.role.into(),
            content: value.content.clone(),
            tool_name: Nullable(value.tool_name.clone()),
            tokens: Nullable(value.tokens),
            timestamp: value.ts,
            metadata: value.metadata.clone(),
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(rename = "session")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TranscriptSessionOutput {
    id: String,
    agent: String,
    project: Nullable<String>,
    started_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    metadata: String,
}

impl From<&Session> for TranscriptSessionOutput {
    fn from(value: &Session) -> Self {
        Self {
            id: value.id.clone(),
            agent: value.agent.clone(),
            project: Nullable(value.project.clone()),
            started_at: value.started_at,
            updated_at: value.updated_at,
            metadata: value.metadata.clone(),
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TranscriptHitOutput {
    message: TranscriptMessageOutput,
    session: TranscriptSessionOutput,
    score: f64,
}

impl From<&TranscriptHit> for TranscriptHitOutput {
    fn from(value: &TranscriptHit) -> Self {
        Self {
            message: (&value.message).into(),
            session: (&value.session).into(),
            score: value.score,
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TranscriptSearchOutput {
    hits: Vec<TranscriptHitOutput>,
}

impl TranscriptSearchOutput {
    pub(crate) fn new(hits: &[TranscriptHit]) -> Self {
        Self {
            hits: hits.iter().map(Into::into).collect(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.hits.len()
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TranscriptShowOutput {
    session: TranscriptSessionOutput,
    messages: Vec<TranscriptMessageOutput>,
}

impl TranscriptShowOutput {
    pub(crate) fn new(session: &Session, messages: &[Message]) -> Self {
        Self {
            session: session.into(),
            messages: messages.iter().map(Into::into).collect(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.messages.len()
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleCountOutput {
    role: String,
    count: usize,
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentCountOutput {
    agent: String,
    count: usize,
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionCountOutput {
    session_id: String,
    message_count: usize,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TranscriptStatsOutput {
    total_sessions: usize,
    total_messages: usize,
    total_bytes: u64,
    by_role: Vec<RoleCountOutput>,
    by_agent: Vec<AgentCountOutput>,
    top_sessions: Vec<SessionCountOutput>,
    oldest: Nullable<DateTime<Utc>>,
    newest: Nullable<DateTime<Utc>>,
}

impl From<TranscriptStats> for TranscriptStatsOutput {
    fn from(value: TranscriptStats) -> Self {
        Self {
            total_sessions: value.total_sessions,
            total_messages: value.total_messages,
            total_bytes: value.total_bytes,
            by_role: value
                .by_role
                .into_iter()
                .map(|(role, count)| RoleCountOutput { role, count })
                .collect(),
            by_agent: value
                .by_agent
                .into_iter()
                .map(|(agent, count)| AgentCountOutput { agent, count })
                .collect(),
            top_sessions: value
                .top_sessions
                .into_iter()
                .map(|(session_id, message_count)| SessionCountOutput {
                    session_id,
                    message_count,
                })
                .collect(),
            oldest: Nullable(value.oldest),
            newest: Nullable(value.newest),
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(rename = "feedback")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FeedbackOutput {
    id: String,
    topic: String,
    context: String,
    predicted: String,
    corrected: String,
    reason: Nullable<String>,
    source: String,
    created_at: DateTime<Utc>,
    applied_count: u32,
}

impl From<&Feedback> for FeedbackOutput {
    fn from(value: &Feedback) -> Self {
        Self {
            id: value.id.clone(),
            topic: value.topic.clone(),
            context: value.context.clone(),
            predicted: value.predicted.clone(),
            corrected: value.corrected.clone(),
            reason: Nullable(value.reason.clone()),
            source: value.source.clone(),
            created_at: value.created_at,
            applied_count: value.applied_count,
        }
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FeedbackSearchOutput {
    feedback: Vec<FeedbackOutput>,
}

impl FeedbackSearchOutput {
    pub(crate) fn new(feedback: &[Feedback]) -> Self {
        Self {
            feedback: feedback.iter().map(Into::into).collect(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.feedback.len()
    }
}

#[derive(Debug, JsonSchema, Serialize)]
#[schemars(inline)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppliedCountOutput {
    feedback_id: String,
    count: u32,
}

#[derive(Debug, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FeedbackStatsOutput {
    total: usize,
    by_topic: Vec<TopicCountOutput>,
    most_applied: Vec<AppliedCountOutput>,
}

impl From<FeedbackStats> for FeedbackStatsOutput {
    fn from(value: FeedbackStats) -> Self {
        Self {
            total: value.total,
            by_topic: value
                .by_topic
                .into_iter()
                .map(|(topic, count)| TopicCountOutput { topic, count })
                .collect(),
            most_applied: value
                .most_applied
                .into_iter()
                .map(|(feedback_id, count)| AppliedCountOutput { feedback_id, count })
                .collect(),
        }
    }
}
