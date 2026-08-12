//! MCP memoir tool handlers.

use serde_json::Value;

use icm_core::{Concept, ConceptLink, Label, Memoir, MemoirStore, Relation};
use icm_store::Store;

use crate::protocol::ToolResult;

use super::common::{get_i64, get_str, resolve_memoir};

pub(in crate::tools) fn tool_memoir_create(store: &Store, args: &Value) -> ToolResult {
    let name = match get_str(args, "name") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: name".into()),
    };
    if name.len() > 255 {
        return ToolResult::error(format!(
            "name too long: {} UTF-8 bytes (max 255)",
            name.len()
        ));
    }
    let description = get_str(args, "description").unwrap_or("");
    if description.len() > 10_000 {
        return ToolResult::error(format!(
            "description too long: {} UTF-8 bytes (max 10000)",
            description.len()
        ));
    }

    let memoir = Memoir::new(name.into(), description.into());
    match store.create_memoir(memoir) {
        Ok(id) => ToolResult::text(format!("Created memoir '{name}': {id}")),
        Err(e) => ToolResult::error(format!("failed to create memoir: {e}")),
    }
}

pub(in crate::tools) fn tool_memoir_list(store: &Store) -> ToolResult {
    let memoirs = match store.list_memoirs() {
        Ok(m) => m,
        Err(e) => return ToolResult::error(format!("failed to list memoirs: {e}")),
    };

    if memoirs.is_empty() {
        return ToolResult::text("No memoirs yet.".into());
    }

    let counts = store.batch_memoir_concept_counts().unwrap_or_default();
    let mut output = String::from("Memoirs:\n");
    for m in &memoirs {
        let concept_count = counts.get(&m.id).copied().unwrap_or(0);
        output.push_str(&format!(
            "  {} ({} concepts) — {}\n",
            m.name, concept_count, m.description
        ));
    }
    ToolResult::text(output)
}

pub(in crate::tools) fn tool_memoir_show(store: &Store, args: &Value) -> ToolResult {
    let name = match get_str(args, "name") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: name".into()),
    };

    let memoir = match resolve_memoir(store, name) {
        Ok(m) => m,
        Err(e) => return e,
    };
    let stats = match store.memoir_stats(&memoir.id) {
        Ok(s) => s,
        Err(e) => return ToolResult::error(format!("failed to get stats: {e}")),
    };
    let concepts = match store.list_concepts(&memoir.id) {
        Ok(c) => c,
        Err(e) => return ToolResult::error(format!("failed to list concepts: {e}")),
    };

    let mut output = format!(
        "Memoir: {}\nDescription: {}\nConcepts: {}\nLinks: {}\nAvg confidence: {:.2}\n",
        memoir.name,
        memoir.description,
        stats.total_concepts,
        stats.total_links,
        stats.avg_confidence
    );

    if !stats.label_counts.is_empty() {
        output.push_str("Labels:\n");
        for (label, count) in &stats.label_counts {
            output.push_str(&format!("  {label} ({count})\n"));
        }
    }

    if !concepts.is_empty() {
        output.push_str("\nConcepts:\n");
        for c in &concepts {
            let labels_str = c.format_labels();
            output.push_str(&format!(
                "  {} [r{} c{:.2}]{}\n    {}\n",
                c.name,
                c.revision,
                c.confidence,
                if labels_str.is_empty() {
                    String::new()
                } else {
                    format!(" ({labels_str})")
                },
                c.definition
            ));
        }
    }

    ToolResult::text(output)
}

pub(in crate::tools) fn tool_memoir_add_concept(store: &Store, args: &Value) -> ToolResult {
    let memoir_name = match get_str(args, "memoir") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: memoir".into()),
    };
    let name = match get_str(args, "name") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: name".into()),
    };
    if name.len() > 255 {
        return ToolResult::error(format!(
            "concept name too long: {} UTF-8 bytes (max 255)",
            name.len()
        ));
    }
    let definition = match get_str(args, "definition") {
        Some(d) => d,
        None => return ToolResult::error("missing required field: definition".into()),
    };
    if definition.len() > 10_000 {
        return ToolResult::error(format!(
            "definition too long: {} UTF-8 bytes (max 10000)",
            definition.len()
        ));
    }

    let memoir = match resolve_memoir(store, memoir_name) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let mut concept = Concept::new(memoir.id, name.into(), definition.into());

    if let Some(labels_str) = get_str(args, "labels") {
        concept.labels = labels_str
            .split(',')
            .filter_map(|s| s.trim().parse::<Label>().ok())
            .collect();
    }

    match store.add_concept(concept) {
        Ok(id) => ToolResult::text(format!(
            "Added concept '{name}' to memoir '{memoir_name}': {id}"
        )),
        Err(e) => ToolResult::error(format!("failed to add concept: {e}")),
    }
}

pub(in crate::tools) fn tool_memoir_refine(store: &Store, args: &Value) -> ToolResult {
    let memoir_name = match get_str(args, "memoir") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: memoir".into()),
    };
    let name = match get_str(args, "name") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: name".into()),
    };
    if name.len() > 255 {
        return ToolResult::error(format!(
            "concept name too long: {} UTF-8 bytes (max 255)",
            name.len()
        ));
    }
    let definition = match get_str(args, "definition") {
        Some(d) => d,
        None => return ToolResult::error("missing required field: definition".into()),
    };
    if definition.len() > 10_000 {
        return ToolResult::error(format!(
            "definition too long: {} UTF-8 bytes (max 10000)",
            definition.len()
        ));
    }

    let memoir = match resolve_memoir(store, memoir_name) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let concept = match store.get_concept_by_name(&memoir.id, name) {
        Ok(Some(c)) => c,
        Ok(None) => return ToolResult::error(format!("concept not found: {name}")),
        Err(e) => return ToolResult::error(format!("db error: {e}")),
    };

    if let Err(e) = store.refine_concept(&concept.id, definition, &[]) {
        return ToolResult::error(format!("failed to refine: {e}"));
    }

    let updated = match store.get_concept(&concept.id) {
        Ok(Some(c)) => c,
        _ => return ToolResult::text(format!("Refined concept '{name}'")),
    };

    ToolResult::text(format!(
        "Refined '{name}' (r{}, confidence={:.2})",
        updated.revision, updated.confidence
    ))
}

pub(in crate::tools) fn tool_memoir_search(store: &Store, args: &Value) -> ToolResult {
    let memoir_name = match get_str(args, "memoir") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: memoir".into()),
    };
    let query = match get_str(args, "query") {
        Some(q) => q,
        None => return ToolResult::error("missing required field: query".into()),
    };
    let limit = get_i64(args, "limit", 10).clamp(1, 100) as usize;
    let label_str = get_str(args, "label");

    let memoir = match resolve_memoir(store, memoir_name) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let results = if let Some(lbl) = label_str {
        let parsed: Label = match lbl.parse() {
            Ok(l) => l,
            Err(e) => return ToolResult::error(format!("invalid label: {e}")),
        };
        let mut by_label = match store.search_concepts_by_label(&memoir.id, &parsed, limit) {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("search error: {e}")),
        };
        if !query.is_empty() {
            let q = query.to_lowercase();
            by_label.retain(|c| {
                c.name.to_lowercase().contains(&q) || c.definition.to_lowercase().contains(&q)
            });
        }
        by_label
    } else {
        match store.search_concepts_fts(&memoir.id, query, limit) {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("search error: {e}")),
        }
    };

    if results.is_empty() {
        return ToolResult::text("No concepts found.".into());
    }

    let mut output = String::new();
    for c in &results {
        let labels_str = c.format_labels();
        output.push_str(&format!(
            "--- {} [r{} c{:.2}] ---\n  {}\n",
            c.name, c.revision, c.confidence, c.definition
        ));
        if !labels_str.is_empty() {
            output.push_str(&format!("  labels: {labels_str}\n"));
        }
        output.push('\n');
    }

    ToolResult::text(output)
}

pub(in crate::tools) fn tool_memoir_search_all(store: &Store, args: &Value) -> ToolResult {
    let query = match get_str(args, "query") {
        Some(q) => q,
        None => return ToolResult::error("missing required field: query".into()),
    };
    let limit = get_i64(args, "limit", 10).clamp(1, 100) as usize;

    let results = match store.search_all_concepts_fts(query, limit) {
        Ok(r) => r,
        Err(e) => return ToolResult::error(format!("search error: {e}")),
    };

    if results.is_empty() {
        return ToolResult::text("No concepts found.".into());
    }

    // Group by memoir for readable output
    let memoirs: std::collections::HashMap<String, String> = store
        .list_memoirs()
        .unwrap_or_default()
        .into_iter()
        .map(|m| (m.id.clone(), m.name))
        .collect();

    let mut output = String::new();
    for c in &results {
        let memoir_name = memoirs.get(&c.memoir_id).map(|s| s.as_str()).unwrap_or("?");
        let labels_str = c.format_labels();
        output.push_str(&format!(
            "--- {} ({}) [r{} c{:.2}] ---\n  {}\n",
            c.name, memoir_name, c.revision, c.confidence, c.definition
        ));
        if !labels_str.is_empty() {
            output.push_str(&format!("  labels: {labels_str}\n"));
        }
        output.push('\n');
    }

    ToolResult::text(output)
}

pub(in crate::tools) fn tool_memoir_link(store: &Store, args: &Value) -> ToolResult {
    let memoir_name = match get_str(args, "memoir") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: memoir".into()),
    };
    let from_name = match get_str(args, "from") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: from".into()),
    };
    let to_name = match get_str(args, "to") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: to".into()),
    };
    let relation_str = match get_str(args, "relation") {
        Some(r) => r,
        None => return ToolResult::error("missing required field: relation".into()),
    };

    let relation: Relation = match relation_str.parse() {
        Ok(r) => r,
        // `Relation::from_str`'s error already reads "invalid relation:
        // <value>" — re-prefixing here doubled it to "invalid relation:
        // invalid relation: <value>".
        Err(e) => return ToolResult::error(e),
    };

    let memoir = match resolve_memoir(store, memoir_name) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let from = match store.get_concept_by_name(&memoir.id, from_name) {
        Ok(Some(c)) => c,
        Ok(None) => return ToolResult::error(format!("concept not found: {from_name}")),
        Err(e) => return ToolResult::error(format!("db error: {e}")),
    };
    let to = match store.get_concept_by_name(&memoir.id, to_name) {
        Ok(Some(c)) => c,
        Ok(None) => return ToolResult::error(format!("concept not found: {to_name}")),
        Err(e) => return ToolResult::error(format!("db error: {e}")),
    };

    let link = ConceptLink::new(from.id, to.id, relation);
    match store.add_link(link) {
        Ok(id) => ToolResult::text(format!(
            "Linked: {from_name} --{relation}--> {to_name} ({id})"
        )),
        Err(e) => ToolResult::error(format!("failed to link: {e}")),
    }
}

pub(in crate::tools) fn tool_memoir_inspect(store: &Store, args: &Value) -> ToolResult {
    let memoir_name = match get_str(args, "memoir") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: memoir".into()),
    };
    let name = match get_str(args, "name") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: name".into()),
    };
    let depth = get_i64(args, "depth", 1).clamp(1, 3) as usize;

    let memoir = match resolve_memoir(store, memoir_name) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let concept = match store.get_concept_by_name(&memoir.id, name) {
        Ok(Some(c)) => c,
        Ok(None) => return ToolResult::error(format!("concept not found: {name}")),
        Err(e) => return ToolResult::error(format!("db error: {e}")),
    };

    let labels_str = concept.format_labels();

    let mut output = format!(
        "Concept: {}\n  id: {}\n  definition: {}\n  confidence: {:.2}\n  revision: {}\n",
        concept.name, concept.id, concept.definition, concept.confidence, concept.revision
    );
    if !labels_str.is_empty() {
        output.push_str(&format!("  labels: {labels_str}\n"));
    }

    let (neighbors, links) = match store.get_neighborhood(&concept.id, depth) {
        Ok(r) => r,
        Err(e) => return ToolResult::error(format!("graph error: {e}")),
    };

    if links.is_empty() {
        output.push_str("\n(no links)\n");
    } else {
        let name_map: std::collections::HashMap<&str, &str> = neighbors
            .iter()
            .map(|c| (c.id.as_str(), c.name.as_str()))
            .collect();
        output.push_str(&format!("\nGraph (depth={depth}):\n"));
        for link in &links {
            let src = name_map.get(link.source_id.as_str()).unwrap_or(&"?");
            let tgt = name_map.get(link.target_id.as_str()).unwrap_or(&"?");
            output.push_str(&format!("  {src} --{}--> {tgt}\n", link.relation));
        }
    }

    ToolResult::text(output)
}

pub(in crate::tools) fn tool_memoir_export(store: &Store, args: &Value) -> ToolResult {
    let memoir_name = match get_str(args, "name") {
        Some(n) => n,
        None => return ToolResult::error("missing required field: name".into()),
    };
    let format = get_str(args, "format").unwrap_or("json");

    let memoir = match resolve_memoir(store, memoir_name) {
        Ok(m) => m,
        Err(e) => return e,
    };

    let concepts = match store.list_concepts(&memoir.id) {
        Ok(c) => c,
        Err(e) => return ToolResult::error(format!("db error: {e}")),
    };

    // Batch load all links for this memoir (single query)
    let links = match store.get_links_for_memoir(&memoir.id) {
        Ok(l) => l,
        Err(e) => return ToolResult::error(format!("db error: {e}")),
    };

    let id_to_name: std::collections::HashMap<&str, &str> = concepts
        .iter()
        .map(|c| (c.id.as_str(), c.name.as_str()))
        .collect();

    match format {
        "json" => {
            let json_concepts: Vec<serde_json::Value> = concepts
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "name": c.name,
                        "definition": c.definition,
                        "labels": c.labels.iter().map(|l| l.to_string()).collect::<Vec<_>>(),
                        "confidence": c.confidence,
                        "revision": c.revision,
                    })
                })
                .collect();

            let json_links: Vec<serde_json::Value> = links
                .iter()
                .filter_map(|l| {
                    let src = id_to_name.get(l.source_id.as_str())?;
                    let tgt = id_to_name.get(l.target_id.as_str())?;
                    Some(serde_json::json!({
                        "source": src,
                        "target": tgt,
                        "relation": l.relation.to_string(),
                        "weight": l.weight,
                    }))
                })
                .collect();

            let output = serde_json::json!({
                "memoir": { "name": memoir.name, "description": memoir.description },
                "concepts": json_concepts,
                "links": json_links,
            });

            ToolResult::text(
                serde_json::to_string_pretty(&output)
                    .unwrap_or_else(|e| format!("json error: {e}")),
            )
        }
        "dot" => {
            // Every value below is caller-controlled (memoir/concept names,
            // definitions, relation labels) and lands inside a DOT string
            // literal. Escape backslash-then-quote on all of them, not just
            // the definition tooltip, or a name containing `"` breaks out of
            // its literal and injects arbitrary DOT attributes/statements.
            fn dot_escape(s: &str) -> String {
                s.replace('\\', "\\\\").replace('"', "\\\"")
            }

            let mut out = format!(
                "digraph \"{}\" {{\n  rankdir=LR;\n  node [shape=box, style=\"rounded,filled\", fillcolor=white];\n\n",
                dot_escape(&memoir.name)
            );
            for c in &concepts {
                let escaped_def = dot_escape(&c.definition);
                let escaped_name = dot_escape(&c.name);
                let color = c.confidence_color();
                out.push_str(&format!(
                    "  \"{}\" [tooltip=\"{}\" fillcolor=\"{}\" label=\"{}\\n({:.0}%)\"];\n",
                    escaped_name,
                    escaped_def,
                    color,
                    escaped_name,
                    c.confidence * 100.0
                ));
            }
            out.push('\n');
            for l in &links {
                if let (Some(src), Some(tgt)) = (
                    id_to_name.get(l.source_id.as_str()),
                    id_to_name.get(l.target_id.as_str()),
                ) {
                    let pw = 0.5 + l.weight * 2.0;
                    out.push_str(&format!(
                        "  \"{}\" -> \"{}\" [label=\"{}\" penwidth={:.1}];\n",
                        dot_escape(src),
                        dot_escape(tgt),
                        dot_escape(&l.relation.to_string()),
                        pw
                    ));
                }
            }
            out.push_str("}\n");
            ToolResult::text(out)
        }
        "ascii" => {
            let mut out = format!("╔══ {} ══╗\n", memoir.name);
            if !memoir.description.is_empty() {
                out.push_str(&format!("║ {}\n", memoir.description));
            }
            out.push_str(&format!(
                "║ {} concepts, {} links\n",
                concepts.len(),
                links.len()
            ));
            out.push_str(&format!("╚{}╝\n\n", "═".repeat(memoir.name.len() + 6)));

            let mut outgoing: std::collections::HashMap<&str, Vec<(String, &str)>> =
                std::collections::HashMap::new();
            let mut incoming: std::collections::HashMap<&str, Vec<(String, &str)>> =
                std::collections::HashMap::new();
            for l in &links {
                if let (Some(&src), Some(&tgt)) = (
                    id_to_name.get(l.source_id.as_str()),
                    id_to_name.get(l.target_id.as_str()),
                ) {
                    outgoing
                        .entry(src)
                        .or_default()
                        .push((l.relation.to_string(), tgt));
                    incoming
                        .entry(tgt)
                        .or_default()
                        .push((l.relation.to_string(), src));
                }
            }

            for c in &concepts {
                let labels_str = if c.labels.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", c.format_labels())
                };
                out.push_str(&format!(
                    "┌─ {}{} {}\n",
                    c.name,
                    labels_str,
                    c.confidence_bar()
                ));
                out.push_str(&format!("│  {}\n", c.definition));
                if let Some(outs) = outgoing.get(c.name.as_str()) {
                    for (rel, tgt) in outs {
                        out.push_str(&format!("│  ──{}──> {}\n", rel, tgt));
                    }
                }
                if let Some(ins) = incoming.get(c.name.as_str()) {
                    for (rel, src) in ins {
                        out.push_str(&format!("│  <──{}── {}\n", rel, src));
                    }
                }
                out.push_str("└─\n");
            }
            ToolResult::text(out)
        }
        "ai" => {
            let mut out = format!("# Memoir: {} — {}\n\n", memoir.name, memoir.description);
            out.push_str(&format!("## Concepts ({})\n", concepts.len()));
            for c in &concepts {
                let labels_str = if c.labels.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", c.format_labels())
                };
                out.push_str(&format!(
                    "- **{}**{} (confidence: {:.0}%): {}\n",
                    c.name,
                    labels_str,
                    c.confidence * 100.0,
                    c.definition
                ));
            }
            if !links.is_empty() {
                out.push_str(&format!("\n## Relations ({})\n", links.len()));
                for l in &links {
                    if let (Some(src), Some(tgt)) = (
                        id_to_name.get(l.source_id.as_str()),
                        id_to_name.get(l.target_id.as_str()),
                    ) {
                        out.push_str(&format!(
                            "- {} ──{}──> {} (w:{:.1})\n",
                            src, l.relation, tgt, l.weight
                        ));
                    }
                }
            }
            ToolResult::text(out)
        }
        _ => ToolResult::error(format!(
            "unsupported format: {format} (use 'json', 'dot', 'ascii', or 'ai')"
        )),
    }
}
