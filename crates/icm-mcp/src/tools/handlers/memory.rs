//! MCP memory tool handlers.

use serde_json::Value;

use chrono::Utc;
use icm_core::{
    build_wake_up, format_local, Embedder, Memory, MemoryStore, WakeUpFormat, WakeUpOptions,
    MSG_NO_MEMORIES,
};
use icm_store::Store;

use crate::catalog::ToolContext;
use crate::outputs::{MemoryRecallOutput, MemoryStatsOutput, MemoryTopicsOutput, SearchMode};
use crate::protocol::ToolResult;

use super::common::{
    format_memory_output, get_i64, get_str, parse_keywords, resolve_memoir, AutoConsolidate,
    MAX_CONTENT_LEN, MAX_TOPIC_LEN,
};

pub(in crate::tools) fn tool_wake_up(store: &Store, args: &Value) -> ToolResult {
    // Normalize the project filter: empty string or "-" both mean "disabled",
    // mirroring the CLI convention.
    let project = match get_str(args, "project") {
        Some("") | Some("-") => None,
        other => other,
    };
    // Clamp token budget to [20, 4000] to guard against accidental blowups.
    let max_tokens = get_i64(args, "max_tokens", 200).clamp(20, 4000) as usize;
    let format = match get_str(args, "format").unwrap_or("markdown") {
        "plain" => WakeUpFormat::Plain,
        _ => WakeUpFormat::Markdown,
    };
    let include_preferences = args
        .get("include_preferences")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let opts = WakeUpOptions {
        project,
        max_tokens,
        format,
        include_preferences,
    };

    match build_wake_up(store, &opts) {
        Ok(pack) => ToolResult::text(pack),
        Err(e) => ToolResult::error(format!("wake_up failed: {e}")),
    }
}

pub(in crate::tools) fn tool_store(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    args: &Value,
    compact: bool,
    auto_consolidate: AutoConsolidate,
) -> ToolResult {
    let topic = match get_str(args, "topic") {
        Some(t) => t,
        None => return ToolResult::error("missing required field: topic".into()),
    };
    let content = match get_str(args, "content") {
        Some(c) => c,
        None => return ToolResult::error("missing required field: content".into()),
    };
    let topic = topic.trim();

    // Preserve the compatibility handler's validation wording before handing
    // the actual operation to the shared transport-neutral implementation.
    if topic.is_empty() {
        return ToolResult::error("topic must not be empty".into());
    }
    if content.trim().is_empty() {
        return ToolResult::error("content must not be empty".into());
    }
    if topic.len() > MAX_TOPIC_LEN {
        return ToolResult::error(format!(
            "topic exceeds maximum length ({} > {MAX_TOPIC_LEN} UTF-8 bytes)",
            topic.len()
        ));
    }
    if content.len() > MAX_CONTENT_LEN {
        return ToolResult::error(format!(
            "content exceeds maximum length ({} > {MAX_CONTENT_LEN} UTF-8 bytes)",
            content.len()
        ));
    }

    let importance = get_str(args, "importance")
        .unwrap_or("medium")
        .parse()
        .unwrap_or(icm_core::Importance::Medium);
    let keywords = parse_keywords(args);
    let result = match crate::memory::store_memory(
        store,
        embedder,
        &crate::memory::StoreOptions {
            topic,
            content,
            importance,
            keywords: &keywords,
            raw_excerpt: get_str(args, "raw_excerpt"),
            auto_consolidate,
        },
    ) {
        Ok(result) => result,
        Err(error) => return ToolResult::error(format!("failed to store: {error}")),
    };

    if result.deduplicated {
        return if compact {
            ToolResult::text(format!("ok:{}", result.memory.id))
        } else {
            ToolResult::text(format!(
                "Updated existing memory (similarity {:.2}): {}",
                result.similarity.unwrap_or_default(),
                result.memory.id
            ))
        };
    }

    let link_suffix = if result.linked_ids.is_empty() {
        String::new()
    } else {
        format!(
            " (+{} link{})",
            result.linked_ids.len(),
            if result.linked_ids.len() == 1 {
                ""
            } else {
                "s"
            }
        )
    };
    let consolidation_message = result.consolidation_message.unwrap_or_default();

    if compact {
        if consolidation_message.is_empty() {
            ToolResult::text(format!("ok:{}{link_suffix}", result.memory.id))
        } else {
            ToolResult::text(format!(
                "ok:{}{link_suffix}\n{consolidation_message}",
                result.memory.id
            ))
        }
    } else if consolidation_message.is_empty() {
        let hint = match store.count_by_topic(topic) {
            Ok(count) if count > 7 => format!(
                "\nNote: Topic '{topic}' has {count} entries — consider consolidating with icm_memory_consolidate."
            ),
            _ => String::new(),
        };
        ToolResult::text(format!(
            "Stored memory: {}{link_suffix}{hint}",
            result.memory.id
        ))
    } else {
        ToolResult::text(format!(
            "Stored memory: {}{link_suffix}\n{consolidation_message}",
            result.memory.id
        ))
    }
}

fn recall_result(
    query: &str,
    project: Option<&str>,
    search_mode: SearchMode,
    memories: &[(Memory, f32)],
    compact: bool,
    include_scores: bool,
) -> ToolResult {
    let legacy = if memories.is_empty() {
        MSG_NO_MEMORIES.into()
    } else {
        format_memory_output(memories, compact)
    };
    let output = MemoryRecallOutput::new(query, project, search_mode, memories, include_scores);
    ToolResult::structured(legacy, format!("Found {} memories.", output.len()), &output)
}

pub(in crate::tools) fn tool_recall(context: &ToolContext<'_>, args: &Value) -> ToolResult {
    let query = match get_str(args, "query") {
        Some(q) => q,
        None => return ToolResult::error("missing required field: query".into()),
    };
    let limit = get_i64(args, "limit", 5).clamp(1, 100) as usize;
    let project = get_str(args, "project");
    let recall = match crate::memory::recall_memories(
        context.store,
        context.embedder,
        &crate::memory::RecallOptions {
            query,
            limit,
            topic: get_str(args, "topic"),
            keyword: get_str(args, "keyword"),
            project,
            working_directory: context.working_directory,
        },
    ) {
        Ok(recall) => recall,
        Err(error) => return ToolResult::error(format!("search error: {error}")),
    };

    let include_scores = recall.search_mode == crate::memory::RecallSearchMode::Hybrid;
    let memories: Vec<(Memory, f32)> = recall
        .hits
        .into_iter()
        .map(|(memory, score)| (memory, score.unwrap_or(-1.0)))
        .collect();
    let search_mode = match recall.search_mode {
        crate::memory::RecallSearchMode::Hybrid => SearchMode::Hybrid,
        crate::memory::RecallSearchMode::FullText => SearchMode::FullText,
        crate::memory::RecallSearchMode::Keyword => SearchMode::Keyword,
    };
    recall_result(
        query,
        recall.effective_project.as_deref(),
        search_mode,
        &memories,
        context.compact,
        include_scores,
    )
}

pub(in crate::tools) fn tool_forget(store: &Store, args: &Value) -> ToolResult {
    let id = match get_str(args, "id") {
        Some(id) => id,
        None => return ToolResult::error("missing required field: id".into()),
    };

    match store.delete(id) {
        Ok(()) => ToolResult::text(format!("Deleted memory: {id}")),
        Err(e) => ToolResult::error(format!("failed to delete: {e}")),
    }
}

pub(in crate::tools) fn tool_forget_topic(store: &Store, args: &Value) -> ToolResult {
    let topic = match get_str(args, "topic") {
        Some(t) => t,
        None => return ToolResult::error("missing required field: topic".into()),
    };

    let memories = match store.get_by_topic(topic) {
        Ok(m) => m,
        Err(e) => return ToolResult::error(format!("failed to get memories: {e}")),
    };

    let count = memories.len();
    for m in &memories {
        if let Err(e) = store.delete(&m.id) {
            return ToolResult::error(format!("failed to delete memory {}: {e}", m.id));
        }
    }

    ToolResult::text(format!("Deleted {count} memories from topic: {topic}"))
}

pub(in crate::tools) fn tool_learn(store: &Store, args: &Value) -> ToolResult {
    let dir_str = get_str(args, "directory").unwrap_or(".");
    let dir = std::path::PathBuf::from(dir_str);

    if !dir.exists() || !dir.is_dir() {
        return ToolResult::error(format!("directory not found: {}", dir.display()));
    }

    let name = get_str(args, "name");

    match icm_core::learn_project(store, &dir, name) {
        Ok(result) => ToolResult::text(result.to_string()),
        Err(e) => ToolResult::error(format!("learn failed: {e}")),
    }
}

pub(in crate::tools) fn tool_learn_bounded(context: &ToolContext<'_>, args: &Value) -> ToolResult {
    if !context.enforce_directory_boundary {
        return tool_learn(context.store, args);
    }
    let requested = get_str(args, "directory").unwrap_or(".");
    let requested = std::path::Path::new(requested);
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        context.working_directory.join(requested)
    };
    let root = match context.working_directory.canonicalize() {
        Ok(root) => root,
        Err(_) => {
            return ToolResult::error(
                "server working directory could not be resolved safely".into(),
            )
        }
    };
    let candidate = match candidate.canonicalize() {
        Ok(candidate) => candidate,
        Err(_) => {
            return ToolResult::error(format!("directory not found: {}", candidate.display()))
        }
    };
    if !candidate.starts_with(&root) {
        return ToolResult::error(
            "directory must remain within the server working directory".into(),
        );
    }
    let mut bounded_args = args.clone();
    bounded_args["directory"] = Value::String(candidate.to_string_lossy().into_owned());
    tool_learn(context.store, &bounded_args)
}

pub(in crate::tools) fn tool_consolidate(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    args: &Value,
) -> ToolResult {
    let topic = match get_str(args, "topic") {
        Some(t) => t,
        None => return ToolResult::error("missing required field: topic".into()),
    };
    let summary = match get_str(args, "summary") {
        Some(s) => s,
        None => return ToolResult::error("missing required field: summary".into()),
    };

    let mut consolidated = Memory::new(topic.into(), summary.into(), icm_core::Importance::High);
    // Same bug class as #394/#395/cmd_consolidate: this tool never attached
    // an embedding to the merged memory it creates.
    if let Some(emb) = embedder {
        if let Ok(vec) = emb.embed(&consolidated.embed_text()) {
            consolidated.embedding = Some(vec);
        }
    }

    match store.consolidate_topic(topic, consolidated) {
        Ok(()) => ToolResult::text(format!("Consolidated topic: {topic}")),
        Err(e) => ToolResult::error(format!("failed to consolidate: {e}")),
    }
}

pub(in crate::tools) fn tool_list_topics(store: &Store) -> ToolResult {
    match store.list_topics() {
        Ok(topics) => {
            let structured = MemoryTopicsOutput::new(&topics);
            if topics.is_empty() {
                return ToolResult::structured(
                    "No topics yet.".into(),
                    "Found 0 topics.".into(),
                    &structured,
                );
            }

            // Group topics by scope prefix (before ':')
            let mut scoped: std::collections::BTreeMap<String, Vec<(String, usize)>> =
                std::collections::BTreeMap::new();
            let mut unscoped: Vec<(String, usize)> = Vec::new();

            for (topic, count) in &topics {
                if let Some((prefix, _rest)) = topic.split_once(':') {
                    scoped
                        .entry(prefix.to_string())
                        .or_default()
                        .push((topic.clone(), *count));
                } else {
                    unscoped.push((topic.clone(), *count));
                }
            }

            let mut output = String::from("Topics:\n");

            // Show unscoped topics first
            for (topic, count) in &unscoped {
                output.push_str(&format!("  {topic}: {count} memories\n"));
            }

            // Show scoped topics grouped by prefix
            for (prefix, sub_topics) in &scoped {
                let total: usize = sub_topics.iter().map(|(_, c)| c).sum();
                output.push_str(&format!("  [{prefix}] ({total} total):\n"));
                for (topic, count) in sub_topics {
                    output.push_str(&format!("    {topic}: {count} memories\n"));
                }
            }

            ToolResult::structured(
                output,
                format!("Found {} topics.", structured.len()),
                &structured,
            )
        }
        Err(e) => ToolResult::error(format!("failed to list topics: {e}")),
    }
}

pub(in crate::tools) fn tool_stats(store: &Store) -> ToolResult {
    match store.stats() {
        Ok(stats) => {
            let structured = MemoryStatsOutput::from(stats.clone());
            let mut output = format!(
                "Memories: {}\nTopics: {}\nAvg weight: {:.3}\n",
                stats.total_memories, stats.total_topics, stats.avg_weight
            );
            if let Some(oldest) = stats.oldest_memory {
                output.push_str(&format!(
                    "Oldest: {}\n",
                    format_local(&oldest, "%Y-%m-%d %H:%M")
                ));
            }
            if let Some(newest) = stats.newest_memory {
                output.push_str(&format!(
                    "Newest: {}\n",
                    format_local(&newest, "%Y-%m-%d %H:%M")
                ));
            }
            ToolResult::structured(output, "Returned memory statistics.".into(), &structured)
        }
        Err(e) => ToolResult::error(format!("failed to get stats: {e}")),
    }
}

pub(in crate::tools) fn tool_update(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    args: &Value,
) -> ToolResult {
    let id = match get_str(args, "id") {
        Some(id) => id,
        None => return ToolResult::error("missing required field: id".into()),
    };
    let content = match get_str(args, "content") {
        Some(c) => c,
        None => return ToolResult::error("missing required field: content".into()),
    };

    let mut memory = match store.get(id) {
        Ok(Some(m)) => m,
        Ok(None) => return ToolResult::error(format!("memory not found: {id}")),
        Err(e) => return ToolResult::error(format!("db error: {e}")),
    };

    memory.summary = content.to_string();
    memory.updated_at = Utc::now();
    memory.weight = 1.0; // Reset weight on update (refreshed content)

    if let Some(imp_str) = get_str(args, "importance") {
        if let Ok(imp) = imp_str.parse() {
            memory.importance = imp;
        }
    }

    let kw = parse_keywords(args);
    if !kw.is_empty() {
        memory.keywords = kw;
    }

    // Re-embed if embedder available
    if let Some(emb) = embedder {
        if let Ok(vec) = emb.embed(&memory.embed_text()) {
            memory.embedding = Some(vec);
        }
    }

    match store.update(&memory) {
        Ok(()) => ToolResult::text(format!("Updated memory: {id}")),
        Err(e) => ToolResult::error(format!("failed to update: {e}")),
    }
}

pub(in crate::tools) fn tool_health(store: &Store, args: &Value) -> ToolResult {
    let specific_topic = get_str(args, "topic");

    let topics = if let Some(t) = specific_topic {
        vec![(t.to_string(), 0usize)]
    } else {
        match store.list_topics() {
            Ok(t) => t,
            Err(e) => return ToolResult::error(format!("failed to list topics: {e}")),
        }
    };

    if topics.is_empty() {
        return ToolResult::text("No topics yet.".into());
    }

    let mut output = String::from("Memory Health Report:\n\n");
    let mut total_stale = 0usize;
    let mut topics_needing_consolidation = 0usize;

    for (topic, _) in &topics {
        match store.topic_health(topic) {
            Ok(health) => {
                let status = health.status();

                output.push_str(&format!(
                    "  {topic}: {status}\n    entries: {}  avg_weight: {:.2}  stale: {}  avg_access: {:.1}\n",
                    health.entry_count, health.avg_weight, health.stale_count, health.avg_access_count
                ));

                if health.needs_consolidation {
                    topics_needing_consolidation += 1;
                }
                total_stale += health.stale_count;
            }
            Err(_) => {
                output.push_str(&format!("  {topic}: (error reading)\n"));
            }
        }
    }

    output.push_str(&format!(
        "\nSummary: {} topics, {} need consolidation, {} stale entries total\n",
        topics.len(),
        topics_needing_consolidation,
        total_stale
    ));

    ToolResult::text(output)
}

pub(in crate::tools) fn tool_extract_patterns(store: &Store, args: &Value) -> ToolResult {
    let topic = match get_str(args, "topic") {
        Some(t) => t,
        None => return ToolResult::error("missing required field: topic".into()),
    };
    let min_cluster_size = get_i64(args, "min_cluster_size", 3).clamp(2, 50) as usize;
    let memoir_name = get_str(args, "memoir");

    let patterns = match store.detect_patterns(topic, min_cluster_size) {
        Ok(p) => p,
        Err(e) => return ToolResult::error(format!("pattern detection failed: {e}")),
    };

    if patterns.is_empty() {
        return ToolResult::text(format!(
            "No patterns detected in topic '{topic}' (min cluster size: {min_cluster_size})."
        ));
    }

    let mut output = format!(
        "Detected {} pattern(s) in topic '{topic}':\n\n",
        patterns.len()
    );

    // If memoir is provided, resolve it and create concepts
    let memoir_id = if let Some(mname) = memoir_name {
        match resolve_memoir(store, mname) {
            Ok(m) => Some(m.id),
            Err(e) => return e,
        }
    } else {
        None
    };

    for (i, cluster) in patterns.iter().enumerate() {
        output.push_str(&format!(
            "Pattern {}: {} memories\n  Keywords: {}\n  Representative: {}\n",
            i + 1,
            cluster.count,
            cluster.keywords.join(", "),
            cluster.representative_summary,
        ));

        if let Some(ref mid) = memoir_id {
            match store.extract_pattern_as_concept(cluster, mid) {
                Ok(concept_id) => {
                    output.push_str(&format!("  -> Created concept: {concept_id}\n"));
                }
                Err(e) => {
                    output.push_str(&format!("  -> Failed to create concept: {e}\n"));
                }
            }
        }

        output.push('\n');
    }

    if memoir_id.is_some() {
        output.push_str(&format!(
            "Created {} concept(s) in memoir '{}'.\n",
            patterns.len(),
            memoir_name.unwrap_or("?")
        ));
    }

    ToolResult::text(output)
}

pub(in crate::tools) fn tool_embed_all(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    args: &Value,
) -> ToolResult {
    let embedder = match embedder {
        Some(e) => e,
        None => return ToolResult::error("embeddings not available".into()),
    };

    let topic_filter = get_str(args, "topic");

    // Get all memories in a single query
    let memories = if let Some(t) = topic_filter {
        match store.get_by_topic(t) {
            Ok(m) => m,
            Err(e) => return ToolResult::error(format!("failed to list memories: {e}")),
        }
    } else {
        match store.list_all() {
            Ok(m) => m,
            Err(e) => return ToolResult::error(format!("failed to list memories: {e}")),
        }
    };

    // Filter to only those without embeddings
    let to_embed: Vec<&Memory> = memories.iter().filter(|m| m.embedding.is_none()).collect();

    if to_embed.is_empty() {
        return ToolResult::text("All memories already have embeddings.".into());
    }

    let total = to_embed.len();

    // Batch embed all texts at once
    let texts: Vec<String> = to_embed.iter().map(|m| m.embed_text()).collect();
    let text_refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();

    let embeddings = match embedder.embed_batch(&text_refs) {
        Ok(vecs) => vecs,
        Err(e) => return ToolResult::error(format!("batch embedding failed: {e}")),
    };

    let mut embedded = 0;
    let mut errors = 0;

    for (mem, vec) in to_embed.iter().zip(embeddings) {
        let mut updated = (*mem).clone();
        updated.embedding = Some(vec);
        if store.update(&updated).is_ok() {
            embedded += 1;
        } else {
            errors += 1;
        }
    }

    ToolResult::text(format!(
        "Embedded {embedded}/{total} memories ({errors} errors)"
    ))
}
