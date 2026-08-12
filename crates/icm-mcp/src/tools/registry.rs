//! Static MCP tool registrations and compatibility schema projections.

use serde_json::{json, Value};

use crate::catalog::{ToolAnnotations, ToolCatalog, ToolRequirements, ToolSpec};
use crate::inputs::{
    EmbedAllInput, ExtractPatternsInput, FeedbackRecordInput, FeedbackSearchInput,
    FeedbackStatsInput, LearnInput, MemoirAddConceptInput, MemoirCreateInput, MemoirExportInput,
    MemoirInspectInput, MemoirLinkInput, MemoirListInput, MemoirRefineInput, MemoirSearchAllInput,
    MemoirSearchInput, MemoryConsolidateInput, MemoryForgetInput, MemoryHealthInput,
    MemoryListTopicsInput, MemoryRecallInput, MemoryStatsInput, MemoryStoreInput,
    MemoryUpdateInput, NameInput, TopicInput, TranscriptRecordInput, TranscriptSearchInput,
    TranscriptShowInput, TranscriptStartInput, TranscriptStatsInput, WakeUpInput,
};

use super::handlers::{
    tool_consolidate, tool_embed_all, tool_extract_patterns, tool_feedback_record,
    tool_feedback_search, tool_feedback_stats, tool_forget, tool_forget_topic, tool_health,
    tool_learn_bounded, tool_list_topics, tool_memoir_add_concept, tool_memoir_create,
    tool_memoir_export, tool_memoir_inspect, tool_memoir_link, tool_memoir_list,
    tool_memoir_refine, tool_memoir_search, tool_memoir_search_all, tool_memoir_show, tool_recall,
    tool_stats, tool_store, tool_transcript_record, tool_transcript_search, tool_transcript_show,
    tool_transcript_start_session, tool_transcript_stats, tool_update, tool_wake_up,
};

fn normalize_legacy_recall_input(arguments: &Value) -> Value {
    let mut normalized = arguments.clone();
    let Some(object) = normalized.as_object_mut() else {
        return normalized;
    };
    let Some(limit) = object.get("limit").filter(|limit| limit.is_number()) else {
        return normalized;
    };

    // The frozen 2024 handler read limits as i64, defaulted unrepresentable
    // numeric values to five, and clamped the result to its advertised 1..20
    // range. Normalize only for that catalog projection; the modern DTO keeps
    // its strict 1..100 contract and reaches the handler unchanged.
    let normalized_limit = limit.as_i64().unwrap_or(5).clamp(1, 20);
    object.insert("limit".into(), json!(normalized_limit));
    normalized
}

macro_rules! tool_spec {
    (
        $input:ty,
        json!({
            "name": $name:literal,
            "description": $description:literal,
            "inputSchema": $input_schema:tt
        }),
        $annotations:expr,
        $handler:expr
    ) => {
        ToolSpec::typed::<$input>(
            $name,
            $description,
            json!($input_schema),
            None,
            $annotations,
            ToolRequirements::STORE,
            $handler,
        )
    };
    (
        $input:ty,
        json!({
            "name": $name:literal,
            "description": $description:literal,
            "inputSchema": $input_schema:tt
        }),
        legacy_normalizer: $legacy_normalizer:expr,
        $annotations:expr,
        $handler:expr
    ) => {
        ToolSpec::typed::<$input>(
            $name,
            $description,
            json!($input_schema),
            Some($legacy_normalizer),
            $annotations,
            ToolRequirements::STORE,
            $handler,
        )
    };
    (
        $input:ty,
        json!({
            "name": $name:literal,
            "description": $description:literal,
            "inputSchema": $input_schema:tt
        }),
        requirements: $requirements:expr,
        $annotations:expr,
        $handler:expr
    ) => {
        ToolSpec::typed::<$input>(
            $name,
            $description,
            json!($input_schema),
            None,
            $annotations,
            $requirements,
            $handler,
        )
    };
    (
        $input:ty,
        json!({
            "name": $name:literal,
            "description": $description:literal,
            "inputSchema": $input_schema:tt
        }),
        legacy_normalizer: $legacy_normalizer:expr,
        requirements: $requirements:expr,
        $annotations:expr,
        $handler:expr
    ) => {
        ToolSpec::typed::<$input>(
            $name,
            $description,
            json!($input_schema),
            Some($legacy_normalizer),
            $annotations,
            $requirements,
            $handler,
        )
    };
}

pub(crate) fn build_catalog(has_embedder: bool) -> ToolCatalog {
    let tools = vec![
        // --- Memory tools ---
        tool_spec!(
            MemoryStoreInput,
            json!({
                "name": "icm_memory_store",
                "description": "Store important information in ICM long-term memory. Use to save decisions, preferences, project context, resolved errors — anything that should persist between sessions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Category/namespace. Use the canonical topics from the server instructions: 'decisions-{project}', 'preferences', 'errors-resolved', 'context-{project}' — mixed-language topic names fragment the memory."
                        },
                        "content": {
                            "type": "string",
                            "description": "Information to memorize — be concise but complete"
                        },
                        "importance": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                            "default": "medium",
                            "description": "critical=never forgotten, high=slow decay, medium=normal, low=fast decay"
                        },
                        "keywords": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Keywords to improve search"
                        },
                        "raw_excerpt": {
                            "type": "string",
                            "description": "Optional verbatim (code, exact error message, etc.)"
                        }
                    },
                    "required": ["topic", "content"]
                }
            }),
            requirements: ToolRequirements::STORE.with_optional_embedder(),
            ToolAnnotations::new(false, true, false, false),
            |context, args| tool_store(
                context.store,
                context.embedder,
                args,
                context.compact,
                context.auto_consolidate
            )
        ),
        tool_spec!(
            MemoryRecallInput,
            json!({
                "name": "icm_memory_recall",
                "description": "Search ICM long-term memory. Use to find past decisions, project context, preferences, or solutions to previously encountered problems.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Natural language search query"
                        },
                        "topic": {
                            "type": "string",
                            "description": "Filter by specific topic (optional)"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 5,
                            "minimum": 1,
                            "maximum": 20,
                            "description": "Max number of results"
                        },
                        "keyword": {
                            "type": "string",
                            "description": "Filter results by keyword (exact match on memory keywords)"
                        },
                        "project": {
                            "type": "string",
                            "description": "Project filter (segment-aware). Defaults to the server's cwd directory name. Pass an empty string to disable the filter and search across all projects."
                        }
                    },
                    "required": ["query"]
                }
            }),
            legacy_normalizer: normalize_legacy_recall_input,
            requirements: ToolRequirements::STORE.with_optional_embedder(),
            ToolAnnotations::new(false, true, false, false),
            tool_recall
        ),
        tool_spec!(
            MemoryForgetInput,
            json!({
                "name": "icm_memory_forget",
                "description": "Delete a specific memory by its ID. Use when information is obsolete or incorrect.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Memory ID to delete"
                        }
                    },
                    "required": ["id"]
                }
            }),
            ToolAnnotations::new(false, true, true, false),
            |context, args| tool_forget(context.store, args)
        ),
        tool_spec!(
            TopicInput,
            json!({
                "name": "icm_memory_forget_topic",
                "description": "Delete ALL memories in a topic. Use to clear an entire topic at once.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Topic whose memories should all be deleted"
                        }
                    },
                    "required": ["topic"]
                }
            }),
            ToolAnnotations::new(false, true, true, false),
            |context, args| tool_forget_topic(context.store, args)
        ),
        tool_spec!(
            LearnInput,
            json!({
                "name": "icm_learn",
                "description": "Scan a project directory and create a Memoir knowledge graph with its structure, dependencies, modules, and config files.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "directory": {
                            "type": "string",
                            "description": "Project directory to scan (default: current working directory)"
                        },
                        "name": {
                            "type": "string",
                            "description": "Memoir name (default: directory name)"
                        }
                    }
                }
            }),
            requirements: ToolRequirements::STORE.with_filesystem_read(),
            ToolAnnotations::new(false, true, false, true),
            tool_learn_bounded
        ),
        tool_spec!(
            MemoryConsolidateInput,
            json!({
                "name": "icm_memory_consolidate",
                "description": "Consolidate all memories of a topic into a single summary. Useful when a topic accumulates too many entries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Topic to consolidate"
                        },
                        "summary": {
                            "type": "string",
                            "description": "Consolidated summary to replace all memories in the topic"
                        }
                    },
                    "required": ["topic", "summary"]
                }
            }),
            requirements: ToolRequirements::STORE.with_optional_embedder(),
            ToolAnnotations::new(false, true, false, false),
            |context, args| tool_consolidate(context.store, context.embedder, args)
        ),
        tool_spec!(
            MemoryListTopicsInput,
            json!({
                "name": "icm_memory_list_topics",
                "description": "List all available topics in memory with their counts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, _| tool_list_topics(context.store)
        ),
        tool_spec!(
            MemoryStatsInput,
            json!({
                "name": "icm_memory_stats",
                "description": "Get global ICM memory statistics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, _| tool_stats(context.store)
        ),
        tool_spec!(
            MemoryUpdateInput,
            json!({
                "name": "icm_memory_update",
                "description": "Update an existing memory in-place. Use to correct, refresh, or extend a memory without creating a duplicate.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Memory ID to update"
                        },
                        "content": {
                            "type": "string",
                            "description": "New content (replaces existing summary)"
                        },
                        "importance": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low"],
                            "description": "New importance level (optional, keeps existing if not set)"
                        },
                        "keywords": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "New keywords (optional, keeps existing if not set)"
                        }
                    },
                    "required": ["id", "content"]
                }
            }),
            requirements: ToolRequirements::STORE.with_optional_embedder(),
            ToolAnnotations::new(false, true, false, false),
            |context, args| tool_update(context.store, context.embedder, args)
        ),
        tool_spec!(
            MemoryHealthInput,
            json!({
                "name": "icm_memory_health",
                "description": "Get health stats for all topics: entry count, staleness, consolidation needs. Use to audit memory hygiene.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Check a specific topic (optional — checks all if omitted)"
                        }
                    }
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_health(context.store, args)
        ),
        // --- Memoir tools ---
        tool_spec!(
            MemoirCreateInput,
            json!({
                "name": "icm_memoir_create",
                "description": "Create a new memoir — a permanent knowledge container. Memoirs hold concepts that never decay.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Unique human-readable name for the memoir"
                        },
                        "description": {
                            "type": "string",
                            "description": "Description of what this memoir is for"
                        }
                    },
                    "required": ["name"]
                }
            }),
            ToolAnnotations::new(false, false, false, false),
            |context, args| tool_memoir_create(context.store, args)
        ),
        tool_spec!(
            MemoirListInput,
            json!({
                "name": "icm_memoir_list",
                "description": "List all memoirs with their concept counts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, _| tool_memoir_list(context.store)
        ),
        tool_spec!(
            NameInput,
            json!({
                "name": "icm_memoir_show",
                "description": "Show a memoir's stats, labels, and all its concepts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Memoir name"
                        }
                    },
                    "required": ["name"]
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_memoir_show(context.store, args)
        ),
        tool_spec!(
            MemoirAddConceptInput,
            json!({
                "name": "icm_memoir_add_concept",
                "description": "Add a permanent concept to a memoir. Concepts are knowledge nodes that get refined, never decayed.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "memoir": {
                            "type": "string",
                            "description": "Memoir name"
                        },
                        "name": {
                            "type": "string",
                            "description": "Concept name (unique within memoir)"
                        },
                        "definition": {
                            "type": "string",
                            "description": "Dense description of the concept"
                        },
                        "labels": {
                            "type": "string",
                            "description": "Comma-separated labels (namespace:value or plain tag). E.g. 'domain:arch,type:decision'"
                        }
                    },
                    "required": ["memoir", "name", "definition"]
                }
            }),
            ToolAnnotations::new(false, false, false, false),
            |context, args| tool_memoir_add_concept(context.store, args)
        ),
        tool_spec!(
            MemoirRefineInput,
            json!({
                "name": "icm_memoir_refine",
                "description": "Refine an existing concept with a new, improved definition. Bumps revision and boosts confidence.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "memoir": {
                            "type": "string",
                            "description": "Memoir name"
                        },
                        "name": {
                            "type": "string",
                            "description": "Concept name"
                        },
                        "definition": {
                            "type": "string",
                            "description": "New, refined definition"
                        }
                    },
                    "required": ["memoir", "name", "definition"]
                }
            }),
            ToolAnnotations::new(false, true, false, false),
            |context, args| tool_memoir_refine(context.store, args)
        ),
        tool_spec!(
            MemoirSearchInput,
            json!({
                "name": "icm_memoir_search",
                "description": "Full-text search concepts within a memoir.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "memoir": {
                            "type": "string",
                            "description": "Memoir name"
                        },
                        "query": {
                            "type": "string",
                            "description": "Search query"
                        },
                        "label": {
                            "type": "string",
                            "description": "Filter by label (e.g. 'domain:tech')"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 10,
                            "description": "Max results"
                        }
                    },
                    "required": ["memoir", "query"]
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_memoir_search(context.store, args)
        ),
        tool_spec!(
            MemoirLinkInput,
            json!({
                "name": "icm_memoir_link",
                "description": "Create a directed, typed edge between two concepts in the same memoir.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "memoir": {
                            "type": "string",
                            "description": "Memoir name"
                        },
                        "from": {
                            "type": "string",
                            "description": "Source concept name"
                        },
                        "to": {
                            "type": "string",
                            "description": "Target concept name"
                        },
                        "relation": {
                            "type": "string",
                            "enum": ["part_of", "depends_on", "related_to", "contradicts", "refines", "alternative_to", "caused_by", "instance_of", "superseded_by"],
                            "description": "Relation type"
                        }
                    },
                    "required": ["memoir", "from", "to", "relation"]
                }
            }),
            ToolAnnotations::new(false, false, false, false),
            |context, args| tool_memoir_link(context.store, args)
        ),
        tool_spec!(
            MemoirInspectInput,
            json!({
                "name": "icm_memoir_inspect",
                "description": "Inspect a concept and its graph neighborhood (BFS).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "memoir": {
                            "type": "string",
                            "description": "Memoir name"
                        },
                        "name": {
                            "type": "string",
                            "description": "Concept name"
                        },
                        "depth": {
                            "type": "integer",
                            "default": 1,
                            "description": "BFS depth"
                        }
                    },
                    "required": ["memoir", "name"]
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_memoir_inspect(context.store, args)
        ),
        tool_spec!(
            MemoirExportInput,
            json!({
                "name": "icm_memoir_export",
                "description": "Export a memoir's full concept graph. Formats: json (structured), dot (Graphviz), ascii (visual), ai (compact markdown for LLM context).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Memoir name"
                        },
                        "format": {
                            "type": "string",
                            "enum": ["json", "dot", "ascii", "ai"],
                            "default": "json",
                            "description": "Output format: json (structured), dot (Graphviz), ascii (visual graph), ai (compact markdown for LLM)"
                        }
                    },
                    "required": ["name"]
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_memoir_export(context.store, args)
        ),
        tool_spec!(
            ExtractPatternsInput,
            json!({
                "name": "icm_memory_extract_patterns",
                "description": "Detect recurring patterns in a topic by keyword similarity. Optionally create concepts in a memoir from detected patterns.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Topic to analyze for patterns"
                        },
                        "memoir": {
                            "type": "string",
                            "description": "Memoir name — if provided, creates concepts from detected patterns"
                        },
                        "min_cluster_size": {
                            "type": "integer",
                            "default": 3,
                            "minimum": 2,
                            "description": "Minimum number of similar memories to form a pattern (default: 3)"
                        }
                    },
                    "required": ["topic"]
                }
            }),
            ToolAnnotations::new(false, false, false, false),
            |context, args| tool_extract_patterns(context.store, args)
        ),
        tool_spec!(
            MemoirSearchAllInput,
            json!({
                "name": "icm_memoir_search_all",
                "description": "Full-text search concepts across all memoirs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 10,
                            "description": "Max results"
                        }
                    },
                    "required": ["query"]
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_memoir_search_all(context.store, args)
        ),
        // --- Feedback tools ---
        tool_spec!(
            FeedbackRecordInput,
            json!({
                "name": "icm_feedback_record",
                "description": "Record a correction/feedback when an AI prediction was wrong. Helps improve future predictions by learning from mistakes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Category/namespace for this feedback (e.g. 'triage-owner/repo', 'pr-analysis')"
                        },
                        "context": {
                            "type": "string",
                            "description": "What was the situation / input that led to the prediction"
                        },
                        "predicted": {
                            "type": "string",
                            "description": "What the AI predicted or did"
                        },
                        "corrected": {
                            "type": "string",
                            "description": "What the correct answer/action should have been"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Why the correction was made (optional)"
                        },
                        "source": {
                            "type": "string",
                            "description": "Which tool/pipeline generated the prediction (optional)"
                        }
                    },
                    "required": ["topic", "context", "predicted", "corrected"]
                }
            }),
            requirements: ToolRequirements::STORE.with_optional_embedder(),
            ToolAnnotations::new(false, false, false, false),
            |context, args| tool_feedback_record(
                context.store,
                context.embedder,
                args,
                context.compact
            )
        ),
        tool_spec!(
            FeedbackSearchInput,
            json!({
                "name": "icm_feedback_search",
                "description": "Search past feedback/corrections to inform current predictions. Use before making predictions to learn from past mistakes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query to find relevant past corrections"
                        },
                        "topic": {
                            "type": "string",
                            "description": "Filter by topic (optional)"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 5,
                            "minimum": 1,
                            "maximum": 20,
                            "description": "Max number of results"
                        }
                    },
                    "required": ["query"]
                }
            }),
            requirements: ToolRequirements::STORE.with_optional_embedder(),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_feedback_search(context.store, context.embedder, args)
        ),
        tool_spec!(
            FeedbackStatsInput,
            json!({
                "name": "icm_feedback_stats",
                "description": "Get feedback statistics: total count, breakdown by topic, most applied corrections.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, _| tool_feedback_stats(context.store)
        ),
        // --- Transcript tools (verbatim session replay) ---
        tool_spec!(
            TranscriptStartInput,
            json!({
                "name": "icm_transcript_start_session",
                "description": "Create a new transcript session for verbatim message capture. Returns the session_id used by subsequent icm_transcript_record calls. Use once per conversation or debugging session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent": {
                            "type": "string",
                            "description": "Agent identifier (e.g. 'claude-code', 'cursor', 'gemini-cli'). Default: 'mcp'."
                        },
                        "project": {
                            "type": "string",
                            "description": "Project name (optional; usually cwd basename or repo slug)"
                        },
                        "metadata": {
                            "type": "string",
                            "description": "Arbitrary JSON metadata (optional)"
                        }
                    }
                }
            }),
            ToolAnnotations::new(false, false, false, false),
            |context, args| tool_transcript_start_session(context.store, args)
        ),
        tool_spec!(
            TranscriptRecordInput,
            json!({
                "name": "icm_transcript_record",
                "description": "Append a verbatim message to a transcript session. Stores the raw content with no summarization. Use once per user turn, assistant reply, or tool call for full replay fidelity.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "Session id from icm_transcript_start_session"
                        },
                        "role": {
                            "type": "string",
                            "enum": ["user", "assistant", "system", "tool"],
                            "description": "Message role"
                        },
                        "content": {
                            "type": "string",
                            "description": "Raw message content (stored verbatim)"
                        },
                        "tool_name": {
                            "type": "string",
                            "description": "Tool name if role=tool (optional)"
                        },
                        "tokens": {
                            "type": "integer",
                            "description": "Token count for billing / stats (optional)"
                        },
                        "metadata": {
                            "type": "string",
                            "description": "Arbitrary JSON metadata (optional)"
                        }
                    },
                    "required": ["session_id", "role", "content"]
                }
            }),
            ToolAnnotations::new(false, false, false, false),
            |context, args| tool_transcript_record(context.store, args)
        ),
        tool_spec!(
            TranscriptSearchInput,
            json!({
                "name": "icm_transcript_search",
                "description": "Full-text search across recorded transcript messages (FTS5 BM25). Supports boolean operators, phrase matches, and prefix queries. Use to recall exact quotes or debug past decisions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "FTS5 query: 'postgres OR mysql', '\"exact phrase\"', 'auth*'"
                        },
                        "session_id": {
                            "type": "string",
                            "description": "Restrict to one session (optional)"
                        },
                        "project": {
                            "type": "string",
                            "description": "Restrict to one project (optional)"
                        },
                        "limit": {
                            "type": "integer",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 50
                        }
                    },
                    "required": ["query"]
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_transcript_search(context.store, args)
        ),
        tool_spec!(
            TranscriptShowInput,
            json!({
                "name": "icm_transcript_show",
                "description": "Replay the full message thread of a transcript session, chronologically. Returns up to `limit` messages with role, content, tool name, timestamp.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 200, "minimum": 1, "maximum": 2000 }
                    },
                    "required": ["session_id"]
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_transcript_show(context.store, args)
        ),
        tool_spec!(
            TranscriptStatsInput,
            json!({
                "name": "icm_transcript_stats",
                "description": "Global transcript statistics: session count, message count, total bytes, breakdown by role and agent, top sessions by message count.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, _| tool_transcript_stats(context.store)
        ),
        tool_spec!(
            WakeUpInput,
            json!({
                "name": "icm_wake_up",
                "description": "Build a compact critical-facts pack for LLM system-prompt injection. Selects critical/high memories (and preferences) optionally scoped by project, ranks by importance × recency × weight, and truncates to a token budget. Use at session start to hydrate an agent with the most load-bearing context.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project": {
                            "type": "string",
                            "description": "Project name filter (substring match against topic). Preferences/identity memories are always included."
                        },
                        "max_tokens": {
                            "type": "integer",
                            "default": 200,
                            "minimum": 20,
                            "maximum": 4000,
                            "description": "Approximate token budget (1 token ≈ 4 characters)"
                        },
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "plain"],
                            "default": "markdown",
                            "description": "Output format"
                        },
                        "include_preferences": {
                            "type": "boolean",
                            "default": true,
                            "description": "Include global preferences/identity memories regardless of the project filter"
                        }
                    }
                }
            }),
            ToolAnnotations::new(true, false, true, false),
            |context, args| tool_wake_up(context.store, args)
        ),
        tool_spec!(
            EmbedAllInput,
            json!({
                "name": "icm_memory_embed_all",
                "description": "Generate embeddings for all memories that don't have one yet. Use this to backfill vector search capability.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {
                            "type": "string",
                            "description": "Only embed memories in this topic (optional)"
                        }
                    }
                }
            }),
            requirements: ToolRequirements::STORE.with_required_embedder(),
            ToolAnnotations::new(false, false, true, false),
            |context, args| tool_embed_all(context.store, context.embedder, args)
        ),
    ];

    ToolCatalog::new(tools, has_embedder).expect("static MCP tool registrations must be valid")
}
