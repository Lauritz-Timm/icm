//! MCP memory tool handlers.

use chrono::Utc;
use serde_json::Value;

use icm_core::{
    add_backrefs, auto_link_memory, build_wake_up, find_similar_memory, format_local,
    is_preference_topic, keyword_matches, project_matches, topic_matches, AutoLinkOptions,
    Embedder, Memory, MemoryStore, WakeUpFormat, WakeUpOptions, DEDUP_SIMILARITY_THRESHOLD,
    MSG_NO_MEMORIES,
};
use icm_store::Store;

use crate::catalog::ToolContext;
use crate::protocol::ToolResult;

use super::common::{
    format_memory_output, get_i64, get_str, parse_keywords, resolve_memoir, try_auto_consolidate,
    AutoConsolidate, MAX_CONTENT_LEN, MAX_TOPIC_LEN,
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

    // Empty-string validation: the inputSchema marks `topic` and
    // `content` as required, but JSON allows passing `""` which slips
    // past the structural check. Reject explicitly so callers don't
    // silently end up with a memory under a blank topic that they
    // can't meaningfully recall.
    if topic.trim().is_empty() {
        return ToolResult::error("topic must not be empty".into());
    }
    if content.trim().is_empty() {
        return ToolResult::error("content must not be empty".into());
    }

    // Input length validation
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

    let importance_str = get_str(args, "importance").unwrap_or("medium");
    let importance = importance_str
        .parse()
        .unwrap_or(icm_core::Importance::Medium);

    let mut memory = Memory::new(topic.into(), content.into(), importance);

    let kw = parse_keywords(args);
    if !kw.is_empty() {
        memory.keywords = kw;
    }

    if let Some(raw) = get_str(args, "raw_excerpt") {
        memory.raw_excerpt = Some(raw.into());
    }

    // Auto-embed if embedder is available
    let embed_text = memory.embed_text();
    let embed_vec = if let Some(emb) = embedder {
        match emb.embed(&embed_text) {
            Ok(vec) => Some(vec),
            Err(e) => {
                tracing::warn!("embedding failed: {e}");
                None
            }
        }
    } else {
        None
    };

    if let Some(ref vec) = embed_vec {
        memory.embedding = Some(vec.clone());
    }

    // Dedup check: if a very similar memory exists in the same topic, update it instead
    if let Some(ref query_emb) = embed_vec {
        if let Ok(Some((existing, score))) = find_similar_memory(
            store,
            &embed_text,
            query_emb,
            topic,
            DEDUP_SIMILARITY_THRESHOLD,
        ) {
            let updated = Memory {
                id: existing.id.clone(),
                created_at: existing.created_at,
                last_accessed: existing.last_accessed,
                access_count: existing.access_count,
                weight: 1.0,
                topic: existing.topic.clone(),
                summary: content.to_string(),
                raw_excerpt: get_str(args, "raw_excerpt")
                    .map(|r| r.into())
                    .or_else(|| existing.raw_excerpt.clone()),
                keywords: {
                    let kw = parse_keywords(args);
                    if kw.is_empty() {
                        existing.keywords.clone()
                    } else {
                        kw
                    }
                },
                embedding: Some(query_emb.clone()),
                // Never let a near-dup merge downgrade importance: an MCP
                // caller that omits `importance` defaults to Medium, which
                // would otherwise silently demote an existing Critical
                // memory into decay/prune eligibility (audit finding).
                importance: icm_core::max_importance(existing.importance, importance),
                source: existing.source.clone(),
                related_ids: existing.related_ids.clone(),
                updated_at: Utc::now(),
                scope: existing.scope,
            };
            if let Err(e) = store.update(&updated) {
                return ToolResult::error(format!("failed to update: {e}"));
            }
            return if compact {
                ToolResult::text(format!("ok:{}", updated.id))
            } else {
                ToolResult::text(format!(
                    "Updated existing memory (similarity {score:.2}): {}",
                    updated.id
                ))
            };
        }
    }

    // Auto-link: populate `related_ids` with similar existing memories BEFORE
    // storing, so the new memory lands in the DB with its forward edges
    // already set. Back-refs are added AFTER storing so the linked memories
    // point to an id that exists in the DB.
    let auto_link_opts = AutoLinkOptions::default();
    let linked_ids = if memory.embedding.is_some() {
        auto_link_memory(store, &mut memory, &auto_link_opts).unwrap_or_else(|e| {
            tracing::warn!("auto-link failed: {e}");
            Vec::new()
        })
    } else {
        Vec::new()
    };

    match store.store(memory) {
        Ok(id) => {
            // Best-effort back-ref update. Failure here leaves an asymmetric
            // edge (forward-only) but does not fail the store call.
            if !linked_ids.is_empty() {
                if let Err(e) = add_backrefs(store, &id, &linked_ids) {
                    tracing::warn!("auto-link back-ref update failed: {e}");
                }
            }

            let link_suffix = if linked_ids.is_empty() {
                String::new()
            } else {
                format!(
                    " (+{} link{})",
                    linked_ids.len(),
                    if linked_ids.len() == 1 { "" } else { "s" }
                )
            };

            if compact {
                // Try auto-consolidation even in compact mode
                let consolidation_msg =
                    try_auto_consolidate(store, embedder, topic, auto_consolidate);
                if consolidation_msg.is_empty() {
                    ToolResult::text(format!("ok:{id}{link_suffix}"))
                } else {
                    ToolResult::text(format!("ok:{id}{link_suffix}\n{consolidation_msg}"))
                }
            } else {
                let consolidation_msg =
                    try_auto_consolidate(store, embedder, topic, auto_consolidate);
                if consolidation_msg.is_empty() {
                    // Still show a nudge if approaching threshold
                    let hint = if let Ok(count) = store.count_by_topic(topic) {
                        if count > 7 {
                            format!(
                                "\nNote: Topic '{topic}' has {count} entries — consider consolidating with icm_memory_consolidate."
                            )
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    ToolResult::text(format!("Stored memory: {id}{link_suffix}{hint}"))
                } else {
                    ToolResult::text(format!(
                        "Stored memory: {id}{link_suffix}\n{consolidation_msg}"
                    ))
                }
            }
        }
        Err(e) => ToolResult::error(format!("failed to store: {e}")),
    }
}

pub(in crate::tools) fn tool_recall(context: &ToolContext<'_>, args: &Value) -> ToolResult {
    let store = context.store;
    let embedder = context.embedder;
    let compact = context.compact;
    // Auto-decay if >24h since last decay
    if let Err(e) = store.maybe_auto_decay() {
        tracing::warn!(error = %e, "auto-decay failed during recall");
    }

    let query = match get_str(args, "query") {
        Some(q) => q,
        None => return ToolResult::error("missing required field: query".into()),
    };
    // The modern input contract extends the historical advertised maximum
    // from 20 to the frozen Phase 2 boundary of 100. Keep the handler cap in
    // lockstep so valid modern calls are not silently truncated.
    let limit = get_i64(args, "limit", 5).clamp(1, 100) as usize;
    let topic = get_str(args, "topic");
    let keyword = get_str(args, "keyword");

    // Project filter: same hard segment-aware filter applied to the CLI
    // `recall_context` path (extract.rs) so MCP-side recall can't leak
    // memories from other projects. Caller can override via the explicit
    // `project` arg (empty string disables the filter); otherwise we
    // derive it from the server's cwd via the shared icm-core detection
    // (git remote first) — the CLI hooks store under that name, so a raw
    // cwd basename would silently miss on renamed checkouts (audit finding).
    let project_arg = get_str(args, "project");
    let cwd_project =
        icm_core::project::project_from_path(&context.working_directory.to_string_lossy());
    let project: Option<String> = match project_arg {
        Some("") => None,
        Some(p) => Some(p.to_string()),
        None => cwd_project,
    };
    let project_filter = |m: &Memory| -> bool {
        match project.as_deref() {
            None => true,
            Some(p) => is_preference_topic(&m.topic) || project_matches(&m.topic, Some(p)),
        }
    };

    // Audit finding: filters were applied AFTER the store already truncated
    // to `limit` — if the top-`limit` global hits all belonged to other
    // projects/topics, filtering left nothing and recall reported "no
    // memories" even though relevant matches existed further down the
    // ranked list. When any filter is active, request a much larger
    // candidate pool so filtering has enough to work with, then truncate to
    // the caller's requested `limit` at the very end (capped — this is a
    // memory-scoped search, not a paginated export).
    let filters_active = project.is_some() || topic.is_some() || keyword.is_some();
    let query_limit = if filters_active {
        (limit * 10).min(200)
    } else {
        limit
    };

    // Try hybrid search if embedder is available
    if let Some(emb) = embedder {
        if let Ok(query_emb) = emb.embed_query(query) {
            if let Ok(results) = store.search_hybrid(query, &query_emb, query_limit) {
                let mut scored_results = results;
                scored_results.retain(|(m, _)| project_filter(m));
                if let Some(t) = topic {
                    scored_results.retain(|(m, _)| topic_matches(&m.topic, t));
                }
                if let Some(kw) = keyword {
                    scored_results.retain(|(m, _)| keyword_matches(&m.keywords, kw));
                }

                // Graph-aware expansion: follow `related_ids` one hop from
                // each primary hit and fold neighbors into the result set.
                // Neighbors carry a discounted score so they rank below
                // direct matches but can displace weak primary results.
                //
                // Audit R13b: neighbors are fetched by id without going
                // through the project / topic / keyword filters above,
                // so a project-A primary hit can pull in a project-B
                // neighbor via auto-linked `related_ids`. Re-apply the
                // filters to `expanded` so the caller's scope is honored.
                let max_neighbors = (query_limit / 3).max(1);
                let mut expanded = store
                    .expand_with_neighbors(&scored_results, max_neighbors, 0.5, query_limit)
                    .unwrap_or(scored_results);
                expanded.retain(|(m, _)| project_filter(m));
                if let Some(t) = topic {
                    expanded.retain(|(m, _)| topic_matches(&m.topic, t));
                }
                if let Some(kw) = keyword {
                    expanded.retain(|(m, _)| keyword_matches(&m.keywords, kw));
                }
                expanded.truncate(limit);

                // Batch update access counts (includes expanded neighbors)
                let ids: Vec<&str> = expanded.iter().map(|(m, _)| m.id.as_str()).collect();
                let _ = store.batch_update_access(&ids);

                if expanded.is_empty() {
                    return ToolResult::text(MSG_NO_MEMORIES.into());
                }

                return ToolResult::text(format_memory_output(&expanded, compact));
            }
        }
    }

    // Fallback: FTS then keywords
    let mut results = match store.search_fts(query, query_limit) {
        Ok(r) => r,
        Err(e) => return ToolResult::error(format!("search error: {e}")),
    };

    if results.is_empty() {
        let keywords: Vec<&str> = query.split_whitespace().collect();
        results = match store.search_by_keywords(&keywords, query_limit) {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("search error: {e}")),
        };
    }

    results.retain(|m| project_filter(m));
    if let Some(t) = topic {
        results.retain(|m| topic_matches(&m.topic, t));
    }
    if let Some(kw) = keyword {
        results.retain(|m| keyword_matches(&m.keywords, kw));
    }
    results.truncate(limit);

    // Convert to scored format with a sentinel score of 1.0 (FTS fallback
    // doesn't expose a real similarity score, but we still want the graph
    // expansion to score neighbors relative to their primary parent).
    let scored: Vec<(Memory, f32)> = results.into_iter().map(|m| (m, 1.0)).collect();

    // Graph-aware expansion also applies in the fallback path so that
    // keyword-only deployments benefit from auto-linked memories.
    // Same R13b re-filter as the hybrid path.
    let max_neighbors = (limit / 3).max(1);
    let mut expanded = store
        .expand_with_neighbors(&scored, max_neighbors, 0.5, limit)
        .unwrap_or(scored);
    expanded.retain(|(m, _)| project_filter(m));
    if let Some(t) = topic {
        expanded.retain(|(m, _)| topic_matches(&m.topic, t));
    }
    if let Some(kw) = keyword {
        expanded.retain(|(m, _)| keyword_matches(&m.keywords, kw));
    }

    // Batch update access counts (includes expanded neighbors)
    let ids: Vec<&str> = expanded.iter().map(|(m, _)| m.id.as_str()).collect();
    let _ = store.batch_update_access(&ids);

    if expanded.is_empty() {
        return ToolResult::text(MSG_NO_MEMORIES.into());
    }

    // FTS-path results have synthetic scores — reset to -1.0 for display
    // so we don't claim a hybrid-search confidence we didn't compute.
    let for_display: Vec<(Memory, f32)> = expanded.into_iter().map(|(m, _)| (m, -1.0)).collect();
    ToolResult::text(format_memory_output(&for_display, compact))
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
            if topics.is_empty() {
                return ToolResult::text("No topics yet.".into());
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

            ToolResult::text(output)
        }
        Err(e) => ToolResult::error(format!("failed to list topics: {e}")),
    }
}

pub(in crate::tools) fn tool_stats(store: &Store) -> ToolResult {
    match store.stats() {
        Ok(stats) => {
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
            ToolResult::text(output)
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
