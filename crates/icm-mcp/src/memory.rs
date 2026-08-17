//! Shared memory operations used by MCP tools and the warm HTTP API.
//!
//! Keeping the search and write policy here prevents the transports from
//! drifting: near-duplicate handling, graph linking, scoped filtering,
//! candidate expansion, access bookkeeping, and auto-consolidation all use
//! the same implementation.

use std::{collections::HashSet, path::Path};

use chrono::Utc;
use icm_core::{
    add_backrefs, auto_link_memory, find_similar_memory, is_preference_topic, keyword_matches,
    max_importance, project_matches, topic_matches, AutoLinkOptions, Embedder, IcmResult,
    Importance, Memory, MemoryStore, DEDUP_SIMILARITY_THRESHOLD,
};
use icm_store::Store;

/// Historical default threshold for auto-consolidation.
pub const AUTO_CONSOLIDATE_THRESHOLD: usize = 10;

/// Auto-consolidation policy threaded through all long-lived server paths.
#[derive(Clone, Copy, Debug)]
pub struct AutoConsolidate {
    pub enabled: bool,
    pub threshold: usize,
}

impl Default for AutoConsolidate {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: AUTO_CONSOLIDATE_THRESHOLD,
        }
    }
}

/// Maximum UTF-8 byte length accepted for a memory topic.
pub const MAX_TOPIC_LEN: usize = 255;

/// Maximum UTF-8 byte length accepted for memory content.
pub const MAX_CONTENT_LEN: usize = 64 * 1024;

/// Options for [`store_memory`].
pub struct StoreOptions<'a> {
    pub topic: &'a str,
    pub content: &'a str,
    pub importance: Importance,
    pub keywords: &'a [String],
    pub raw_excerpt: Option<&'a str>,
    pub auto_consolidate: AutoConsolidate,
}

/// Result of a canonical memory write.
#[derive(Debug)]
pub struct StoreResult {
    /// The row created or updated by the operation.
    pub memory: Memory,
    /// Forward links added to a newly stored row.
    pub linked_ids: Vec<String>,
    /// Whether an embedding near-duplicate was updated instead of inserted.
    pub deduplicated: bool,
    /// Similarity score when [`deduplicated`] is true.
    pub similarity: Option<f32>,
    /// Human-readable auto-consolidation notice, if a rollup happened.
    pub consolidation_message: Option<String>,
}

/// Search mode used by [`recall_memories`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallSearchMode {
    Hybrid,
    FullText,
    Keyword,
}

/// Options for [`recall_memories`].
pub struct RecallOptions<'a> {
    pub query: &'a str,
    pub limit: usize,
    pub topic: Option<&'a str>,
    pub keyword: Option<&'a str>,
    /// `Some("")` explicitly disables project filtering. `None` derives the
    /// project from `working_directory`, matching MCP's cwd policy.
    pub project: Option<&'a str>,
    pub working_directory: &'a Path,
}

/// Result of a canonical recall operation.
#[derive(Debug)]
pub struct RecallResult {
    pub hits: Vec<(Memory, Option<f32>)>,
    pub effective_project: Option<String>,
    pub search_mode: RecallSearchMode,
}

/// Apply the shared project/topic/keyword scope used by every recall path.
pub fn matches_memory_filters(
    memory: &Memory,
    project: Option<&str>,
    topic: Option<&str>,
    keyword: Option<&str>,
) -> bool {
    if let Some(project) = project {
        if !is_preference_topic(&memory.topic) && !project_matches(&memory.topic, Some(project)) {
            return false;
        }
    }
    topic.is_none_or(|value| topic_matches(&memory.topic, value))
        && keyword.is_none_or(|value| keyword_matches(&memory.keywords, value))
}

/// Try to auto-consolidate a topic if the configured policy allows it.
/// Returns the status message and, when a rollup occurred, its replacement row.
pub fn try_auto_consolidate(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    topic: &str,
    auto: AutoConsolidate,
) -> (String, Option<Memory>) {
    if !auto.enabled {
        return (String::new(), None);
    }
    match store.auto_consolidate_with_embedder(topic, auto.threshold, embedder) {
        Ok(true) => {
            // Consolidation replaces all non-critical rows with a new ULID.
            // Return that canonical row so callers never expose the deleted
            // pre-consolidation id. The marker is written by the store's
            // auto-consolidation implementation and is scoped to this topic.
            let consolidated = store.get_by_topic(topic).ok().and_then(|memories| {
                memories
                    .into_iter()
                    .filter(|memory| {
                        memory
                            .raw_excerpt
                            .as_deref()
                            .is_some_and(|raw| raw.starts_with("auto-consolidated from "))
                    })
                    .max_by_key(|memory| memory.updated_at)
            });
            (
                format!(
                    "Auto-consolidated topic '{topic}' (exceeded {} entries).",
                    auto.threshold
                ),
                consolidated,
            )
        }
        Ok(false) => (String::new(), None),
        Err(error) => {
            tracing::warn!("auto-consolidation failed for topic '{topic}': {error}");
            (String::new(), None)
        }
    }
}

/// Perform the canonical MCP memory-store operation.
///
/// This deliberately keeps the historical behavior of the MCP handler:
/// embedding failures, auto-link failures, and auto-consolidation failures are
/// best-effort, while validation and database writes remain errors.
pub fn store_memory(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    options: &StoreOptions<'_>,
) -> IcmResult<StoreResult> {
    let topic = options.topic.trim();
    if topic.is_empty() {
        return Err(icm_core::IcmError::InvalidInput(
            "topic must not be empty".into(),
        ));
    }
    if options.content.trim().is_empty() {
        return Err(icm_core::IcmError::InvalidInput(
            "content must not be empty".into(),
        ));
    }
    if topic.len() > MAX_TOPIC_LEN {
        return Err(icm_core::IcmError::InvalidInput(format!(
            "topic exceeds maximum length ({} > {MAX_TOPIC_LEN} UTF-8 bytes)",
            topic.len()
        )));
    }
    if options.content.len() > MAX_CONTENT_LEN {
        return Err(icm_core::IcmError::InvalidInput(format!(
            "content exceeds maximum length ({} > {MAX_CONTENT_LEN} UTF-8 bytes)",
            options.content.len()
        )));
    }

    let mut memory = Memory::new(
        topic.to_owned(),
        options.content.to_owned(),
        options.importance,
    );
    memory.keywords = options.keywords.to_vec();
    if let Some(raw_excerpt) = options.raw_excerpt {
        memory.raw_excerpt = Some(raw_excerpt.to_owned());
    }

    let embed_text = memory.embed_text();
    let embed_vec = embedder.and_then(|embedder| match embedder.embed(&embed_text) {
        Ok(vector) => Some(vector),
        Err(error) => {
            tracing::warn!("embedding failed: {error}");
            None
        }
    });
    if let Some(vector) = &embed_vec {
        memory.embedding = Some(vector.clone());
    }

    if let Some(query_embedding) = &embed_vec {
        if let Ok(Some((existing, similarity))) = find_similar_memory(
            store,
            &embed_text,
            query_embedding,
            topic,
            DEDUP_SIMILARITY_THRESHOLD,
        ) {
            let updated = Memory {
                id: existing.id.clone(),
                created_at: existing.created_at,
                updated_at: Utc::now(),
                last_accessed: existing.last_accessed,
                access_count: existing.access_count,
                weight: 1.0,
                topic: existing.topic.clone(),
                summary: options.content.to_owned(),
                raw_excerpt: options
                    .raw_excerpt
                    .map(str::to_owned)
                    .or_else(|| existing.raw_excerpt.clone()),
                keywords: if options.keywords.is_empty() {
                    existing.keywords.clone()
                } else {
                    options.keywords.to_vec()
                },
                embedding: Some(query_embedding.clone()),
                importance: max_importance(existing.importance, options.importance),
                source: existing.source.clone(),
                related_ids: existing.related_ids.clone(),
                scope: existing.scope,
            };
            store.update(&updated)?;
            return Ok(StoreResult {
                memory: updated,
                linked_ids: Vec::new(),
                deduplicated: true,
                similarity: Some(similarity),
                consolidation_message: None,
            });
        }
    }

    let linked_ids = if memory.embedding.is_some() {
        auto_link_memory(store, &mut memory, &AutoLinkOptions::default()).unwrap_or_else(|error| {
            tracing::warn!("auto-link failed: {error}");
            Vec::new()
        })
    } else {
        Vec::new()
    };

    let id = store.store(memory.clone())?;
    if !linked_ids.is_empty() {
        if let Err(error) = add_backrefs(store, &id, &linked_ids) {
            tracing::warn!("auto-link back-ref update failed: {error}");
        }
    }

    let (consolidation_message, consolidated) =
        try_auto_consolidate(store, embedder, topic, options.auto_consolidate);
    let canonical = match store.get(&id) {
        Ok(Some(current)) => current,
        Ok(None) | Err(_) => {
            // A successful write without a readable row is unexpected, but
            // never return an id that is known to have been removed by
            // consolidation. Keep this best-effort fallback for legacy
            // backend behavior while preferring the canonical rollup above.
            consolidated.unwrap_or(memory)
        }
    };

    Ok(StoreResult {
        memory: canonical,
        linked_ids,
        deduplicated: false,
        similarity: None,
        consolidation_message: (!consolidation_message.is_empty()).then_some(consolidation_message),
    })
}

/// Expand graph neighbors while applying the caller's scope before the
/// neighbor cap. The store helper caps raw candidates before transport-level
/// filtering, which can let out-of-scope neighbors starve valid ones.
fn expand_with_filtered_neighbors<F>(
    store: &Store,
    initial: &[(Memory, f32)],
    max_neighbors: usize,
    hop_discount: f32,
    max_total: usize,
    filter: F,
) -> icm_core::IcmResult<Vec<(Memory, f32)>>
where
    F: Fn(&Memory) -> bool,
{
    if max_neighbors == 0 || initial.is_empty() {
        let mut result = initial.to_vec();
        result.truncate(max_total);
        return Ok(result);
    }

    let initial_ids: HashSet<&str> = initial
        .iter()
        .map(|(memory, _)| memory.id.as_str())
        .collect();
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for (memory, score) in initial {
        for neighbor_id in &memory.related_ids {
            if initial_ids.contains(neighbor_id.as_str()) || !seen.insert(neighbor_id.as_str()) {
                continue;
            }
            candidates.push((neighbor_id.clone(), *score));
        }
    }
    if candidates.is_empty() {
        let mut result = initial.to_vec();
        result.truncate(max_total);
        return Ok(result);
    }

    let ids: Vec<&str> = candidates.iter().map(|(id, _)| id.as_str()).collect();
    let fetched = store.get_many(&ids)?;
    let mut neighbors = Vec::new();
    for (id, parent_score) in candidates {
        let Some(memory) = fetched.get(&id) else {
            continue;
        };
        if !filter(memory) {
            continue;
        }
        neighbors.push((memory.clone(), parent_score * hop_discount));
        if neighbors.len() >= max_neighbors {
            break;
        }
    }

    let mut result = initial.to_vec();
    result.extend(neighbors);
    result.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    result.truncate(max_total);
    Ok(result)
}

/// Perform the canonical MCP memory-store operation.
pub fn recall_memories(
    store: &Store,
    embedder: Option<&dyn Embedder>,
    options: &RecallOptions<'_>,
) -> IcmResult<RecallResult> {
    if let Err(error) = store.maybe_auto_decay() {
        tracing::warn!(error = %error, "auto-decay failed during recall");
    }

    let limit = options.limit.clamp(1, 100);
    let effective_project = match options.project {
        Some("") => None,
        Some(project) => Some(project.to_owned()),
        None => icm_core::project::project_from_path(&options.working_directory.to_string_lossy()),
    };
    let project = effective_project.as_deref();
    let memory_filter =
        |memory: &Memory| matches_memory_filters(memory, project, options.topic, options.keyword);
    let filters_active = project.is_some() || options.topic.is_some() || options.keyword.is_some();
    let query_limit = if filters_active {
        (limit * 10).min(200)
    } else {
        limit
    };

    if let Some(embedder) = embedder {
        if let Ok(query_embedding) = embedder.embed_query(options.query) {
            if let Ok(results) = store.search_hybrid(options.query, &query_embedding, query_limit) {
                let mut scored_results = results;
                scored_results.retain(|(memory, _)| memory_filter(memory));
                let max_neighbors = (query_limit / 3).max(1);
                let mut expanded = if filters_active {
                    expand_with_filtered_neighbors(
                        store,
                        &scored_results,
                        max_neighbors,
                        0.5,
                        query_limit,
                        memory_filter,
                    )
                    .unwrap_or_else(|_| scored_results.clone())
                } else {
                    store
                        .expand_with_neighbors(&scored_results, max_neighbors, 0.5, query_limit)
                        .unwrap_or_else(|_| scored_results.clone())
                };
                expanded.retain(|(memory, _)| memory_filter(memory));
                expanded.truncate(limit);
                update_recall_access(store, &mut expanded);
                return Ok(RecallResult {
                    hits: expanded
                        .into_iter()
                        .map(|(memory, score)| (memory, Some(score)))
                        .collect(),
                    effective_project,
                    search_mode: RecallSearchMode::Hybrid,
                });
            }
        }
    }

    let mut search_mode = RecallSearchMode::FullText;
    let mut results = store.search_fts(options.query, query_limit)?;
    if results.is_empty() {
        search_mode = RecallSearchMode::Keyword;
        let keywords: Vec<&str> = options.query.split_whitespace().collect();
        results = store.search_by_keywords(&keywords, query_limit)?;
    }
    results.retain(|memory| memory_filter(memory));
    results.truncate(limit);
    let scored: Vec<(Memory, f32)> = results.into_iter().map(|memory| (memory, 1.0)).collect();
    let max_neighbors = (limit / 3).max(1);
    let mut expanded = if filters_active {
        expand_with_filtered_neighbors(store, &scored, max_neighbors, 0.5, limit, memory_filter)
            .unwrap_or_else(|_| scored.clone())
    } else {
        store
            .expand_with_neighbors(&scored, max_neighbors, 0.5, limit)
            .unwrap_or_else(|_| scored.clone())
    };
    expanded.retain(|(memory, _)| memory_filter(memory));
    update_recall_access(store, &mut expanded);

    Ok(RecallResult {
        hits: expanded
            .into_iter()
            .map(|(memory, _)| (memory, None))
            .collect(),
        effective_project,
        search_mode,
    })
}

fn update_recall_access(store: &Store, memories: &mut [(Memory, f32)]) {
    let ids: Vec<&str> = memories
        .iter()
        .map(|(memory, _)| memory.id.as_str())
        .collect();
    match store.batch_update_access(&ids) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }
    let Ok(mut refreshed) = store.get_many(&ids) else {
        return;
    };
    for (memory, _) in memories {
        if let Some(current) = refreshed.remove(&memory.id) {
            *memory = current;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct FixedEmbedder;

    impl Embedder for FixedEmbedder {
        fn embed(&self, _text: &str) -> IcmResult<Vec<f32>> {
            Ok(vec![1.0; 384])
        }

        fn embed_query(&self, _text: &str) -> IcmResult<Vec<f32>> {
            Ok(vec![1.0; 384])
        }

        fn embed_batch(&self, texts: &[&str]) -> IcmResult<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|_| vec![1.0; 384]).collect())
        }

        fn dimensions(&self) -> usize {
            384
        }
    }

    fn options<'a>(topic: &'a str, content: &'a str) -> StoreOptions<'a> {
        StoreOptions {
            topic,
            content,
            importance: Importance::Medium,
            keywords: &[],
            raw_excerpt: None,
            auto_consolidate: AutoConsolidate {
                enabled: false,
                threshold: 10,
            },
        }
    }

    #[test]
    fn store_memory_deduplicates_embedding_near_duplicates() {
        let store = Store::in_memory().unwrap();
        let embedder = FixedEmbedder;
        let first = store_memory(&store, Some(&embedder), &options(" topic ", "first")).unwrap();
        let second = store_memory(&store, Some(&embedder), &options("topic", "second")).unwrap();
        assert_eq!(first.memory.topic, "topic");
        assert!(!first.deduplicated);
        assert!(second.deduplicated);
        assert_eq!(second.memory.id, first.memory.id);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn store_memory_auto_links_and_adds_backrefs() {
        let store = Store::in_memory_with_dims(384).unwrap();
        let existing = Memory::new(
            "related".into(),
            "existing related memory".into(),
            Importance::High,
        );
        let existing_id = existing.id.clone();
        let mut existing = existing;
        existing.embedding = Some(vec![1.0; 384]);
        store.store(existing).unwrap();

        let embedder = FixedEmbedder;
        let result = store_memory(
            &store,
            Some(&embedder),
            &StoreOptions {
                topic: "new-topic",
                content: "new related memory",
                importance: Importance::Medium,
                keywords: &[],
                raw_excerpt: None,
                auto_consolidate: AutoConsolidate {
                    enabled: false,
                    threshold: 10,
                },
            },
        )
        .unwrap();
        assert_eq!(result.linked_ids, vec![existing_id.clone()]);
        let stored = store.get(&result.memory.id).unwrap().unwrap();
        assert_eq!(stored.related_ids, vec![existing_id.clone()]);
        let backref = store.get(&existing_id).unwrap().unwrap();
        assert!(backref.related_ids.contains(&result.memory.id));
    }

    #[test]
    fn store_memory_returns_the_rollup_row_after_consolidation() {
        let store = Store::in_memory().unwrap();
        let result = store_memory(
            &store,
            None,
            &StoreOptions {
                topic: "rollup",
                content: "first detail",
                importance: Importance::Medium,
                keywords: &[],
                raw_excerpt: None,
                auto_consolidate: AutoConsolidate {
                    enabled: true,
                    threshold: 1,
                },
            },
        )
        .unwrap();
        assert!(result.consolidation_message.is_some());
        let current = store
            .get(&result.memory.id)
            .unwrap()
            .expect("store result must identify the replacement rollup row");
        assert_eq!(
            current.raw_excerpt.as_deref(),
            Some("auto-consolidated from 1 memories")
        );
    }

    #[test]
    fn store_memory_auto_consolidates_at_the_configured_threshold() {
        let store = Store::in_memory().unwrap();
        let auto = AutoConsolidate {
            enabled: true,
            threshold: 3,
        };
        for index in 0..3 {
            let result = store_memory(
                &store,
                None,
                &StoreOptions {
                    topic: "rollup",
                    content: &format!("unique detail {index}"),
                    importance: Importance::Medium,
                    keywords: &[],
                    raw_excerpt: None,
                    auto_consolidate: auto,
                },
            )
            .unwrap();
            if index < 2 {
                assert!(result.consolidation_message.is_none());
            } else {
                assert!(result.consolidation_message.is_some());
            }
        }
        assert_eq!(store.count_by_topic("rollup").unwrap(), 1);
    }

    #[test]
    fn recall_memory_filters_before_limit_and_expands_neighbors() {
        let store = Store::in_memory().unwrap();
        let mut parent = Memory::new("target".into(), "needle parent".into(), Importance::High);
        let neighbor = Memory::new(
            "target".into(),
            "unrelated neighbor".into(),
            Importance::Medium,
        );
        let neighbor_id = neighbor.id.clone();
        let foreign = Memory::new(
            "foreign".into(),
            "out-of-scope neighbor".into(),
            Importance::High,
        );
        let foreign_id = foreign.id.clone();
        // Put the out-of-scope neighbor first so filtering must happen before
        // the one-neighbor expansion cap is applied.
        parent.related_ids.push(foreign_id);
        parent.related_ids.push(neighbor_id.clone());
        store.store(parent.clone()).unwrap();
        store.store(neighbor).unwrap();
        store.store(foreign).unwrap();
        for index in 0..12 {
            store
                .store(Memory::new(
                    "noise".into(),
                    format!("needle noise {index}"),
                    Importance::Low,
                ))
                .unwrap();
        }
        // Keep the parent relationship after the store's row normalization.
        store.update(&parent).unwrap();

        let cwd = PathBuf::from("/");
        let result = recall_memories(
            &store,
            None,
            &RecallOptions {
                query: "needle",
                limit: 2,
                topic: Some("target"),
                keyword: None,
                project: Some(""),
                working_directory: &cwd,
            },
        )
        .unwrap();
        let ids: Vec<&str> = result
            .hits
            .iter()
            .map(|(memory, _)| memory.id.as_str())
            .collect();
        assert!(ids.contains(&parent.id.as_str()));
        assert!(ids.contains(&neighbor_id.as_str()));
        assert_eq!(result.hits[0].0.access_count, 1);
        assert_eq!(result.hits[1].0.access_count, 1);
    }

    #[test]
    fn recall_memory_refreshes_access_fields() {
        let store = Store::in_memory().unwrap();
        store
            .store(Memory::new(
                "topic".into(),
                "needle phrase".into(),
                Importance::High,
            ))
            .unwrap();
        let cwd = PathBuf::from("/");
        let result = recall_memories(
            &store,
            None,
            &RecallOptions {
                query: "needle",
                limit: 5,
                topic: Some("topic"),
                keyword: None,
                project: Some(""),
                working_directory: &cwd,
            },
        )
        .unwrap();
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].0.access_count, 1);
    }
}
