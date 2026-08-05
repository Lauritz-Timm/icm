use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreFixture {
    pub project_name: String,
    pub memories: Vec<MemoryFixture>,
    pub feedback: Vec<FeedbackFixture>,
    pub transcripts: Vec<TranscriptFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryFixture {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_accessed: String,
    pub access_count: u32,
    pub weight: f64,
    pub topic: String,
    pub summary: String,
    pub raw_excerpt: Option<String>,
    pub keywords: Vec<String>,
    pub importance: String,
    pub source: Value,
    pub related_ids: Vec<String>,
    // Retained in the fixture because it is a public-domain value. The
    // frozen upstream SQLite representation did not persist it; the
    // replacement migration remains responsible for introducing storage.
    pub scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedbackFixture {
    pub id: String,
    pub topic: String,
    pub context: String,
    pub predicted: String,
    pub corrected: String,
    pub reason: Option<String>,
    pub source: String,
    pub created_at: String,
    pub applied_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscriptFixture {
    pub session_id: String,
    pub agent: String,
    pub project: String,
    pub metadata: String,
    pub messages: Vec<MessageFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageFixture {
    pub role: String,
    pub content: String,
    pub tool_name: Option<String>,
    pub tokens: Option<i64>,
    pub metadata: String,
}

#[derive(Debug, Deserialize)]
pub struct QualityFixture {
    pub k: usize,
    pub queries: Vec<QualityQuery>,
}

#[derive(Debug, Deserialize)]
pub struct QualityQuery {
    pub query: String,
    pub relevant: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathFixture {
    pub native_root_names: Vec<String>,
    pub pure_path_cases: Vec<PurePathCase>,
}

#[derive(Debug, Deserialize)]
pub struct PurePathCase {
    pub style: String,
    pub base: String,
    pub relative: String,
    pub expected: String,
}

#[derive(Debug, Deserialize)]
pub struct ProviderFixture {
    pub providers: Vec<ProviderCase>,
    #[serde(rename = "ownedTools")]
    pub owned_tools: Vec<String>,
    #[serde(rename = "forbiddenPatterns")]
    pub forbidden_patterns: Vec<String>,
    #[serde(rename = "manifestSchema")]
    pub manifest_schema: Value,
    #[serde(rename = "manifestPaths")]
    pub manifest_paths: BTreeMap<String, ProviderPlatformPath>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderPlatformPath {
    pub root: String,
    pub relative_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCase {
    pub id: String,
    pub scopes: Vec<ProviderScopeFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderScopeFixture {
    pub scope: String,
    pub dialect: String,
    pub surface: String,
    pub documents: Vec<ProviderDocumentFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDocumentFixture {
    pub role: String,
    pub root: String,
    pub format: String,
    pub relative_path: String,
    pub initial: String,
}

pub fn load_store(suite_root: &Path) -> Result<StoreFixture> {
    read_json(&suite_root.join("fixtures/store.json"))
}

pub fn load_quality(suite_root: &Path) -> Result<QualityFixture> {
    read_json(&suite_root.join("fixtures/quality.json"))
}

pub fn load_paths(suite_root: &Path) -> Result<PathFixture> {
    read_json(&suite_root.join("fixtures/path-cases.json"))
}

pub fn load_providers(suite_root: &Path) -> Result<ProviderFixture> {
    read_json(&suite_root.join("fixtures/providers.json"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Construct a synthetic database from evaluator-owned SQL and JSON only.
/// This code intentionally does not compile or call any product crate. Fixed
/// IDs and times keep fixture creation deterministic; candidate migrations are
/// exercised later when the separate candidate process opens the database.
pub fn build_database(suite_root: &Path, db_path: &Path, populated: bool) -> Result<FixtureState> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating database parent {}", parent.display()))?;
    }
    let fixture = load_store(suite_root)?;
    let schema_path = suite_root.join("fixtures/sqlite-schema.sql");
    let schema = fs::read_to_string(&schema_path)
        .with_context(|| format!("reading {}", schema_path.display()))?;
    let mut connection = Connection::open(db_path)
        .with_context(|| format!("creating synthetic database {}", db_path.display()))?;
    connection.execute_batch(&schema)?;

    let mut normalized_message_ids = Vec::new();
    let mut normalized_timestamp_spellings = Vec::new();
    if populated {
        let transaction = connection.transaction()?;
        for memory in &fixture.memories {
            let (source_type, source_data) = source_columns(&memory.source)?;
            let keywords = serde_json::to_string(&memory.keywords)?;
            let related_ids = serde_json::to_string(&memory.related_ids)?;
            transaction.execute(
                "INSERT INTO memories (
                    id, created_at, updated_at, last_accessed, access_count,
                    weight, topic, summary, raw_excerpt, keywords, importance,
                    source_type, source_data, related_ids, summary_hash, embedding
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, NULL)",
                params![
                    memory.id,
                    memory.created_at,
                    memory.updated_at,
                    memory.last_accessed,
                    memory.access_count,
                    memory.weight,
                    memory.topic,
                    memory.summary,
                    memory.raw_excerpt,
                    keywords,
                    memory.importance,
                    source_type,
                    source_data,
                    related_ids,
                ],
            )?;
            let _ = &memory.scope;
        }
        for feedback in &fixture.feedback {
            transaction.execute(
                "INSERT INTO feedback (
                    id, topic, context, predicted, corrected, reason, source,
                    created_at, applied_count, embedding
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
                params![
                    feedback.id,
                    feedback.topic,
                    feedback.context,
                    feedback.predicted,
                    feedback.corrected,
                    feedback.reason,
                    feedback.source,
                    feedback.created_at,
                    feedback.applied_count,
                ],
            )?;
        }

        const SESSION_STARTED: &str = "2024-03-01T00:00:00Z";
        for transcript in &fixture.transcripts {
            let session_updated =
                fixed_message_timestamp(transcript.messages.len().saturating_sub(1));
            transaction.execute(
                "INSERT INTO sessions (id, agent, project, started_at, updated_at, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    transcript.session_id,
                    transcript.agent,
                    transcript.project,
                    SESSION_STARTED,
                    session_updated,
                    transcript.metadata,
                ],
            )?;
            add_timestamp_spellings(&mut normalized_timestamp_spellings, SESSION_STARTED)?;
            add_timestamp_spellings(&mut normalized_timestamp_spellings, session_updated)?;
            for (index, message) in transcript.messages.iter().enumerate() {
                let message_id = format!("01J2{:022}", index + 1);
                let timestamp = fixed_message_timestamp(index);
                transaction.execute(
                    "INSERT INTO messages (
                        id, session_id, role, content, tool_name, tokens, ts, metadata
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        message_id,
                        transcript.session_id,
                        message.role,
                        message.content,
                        message.tool_name,
                        message.tokens,
                        timestamp,
                        message.metadata,
                    ],
                )?;
                normalized_message_ids.push(message_id);
                add_timestamp_spellings(&mut normalized_timestamp_spellings, timestamp)?;
            }
        }
        transaction.commit()?;
    }

    normalized_message_ids.sort();
    normalized_message_ids.dedup();
    normalized_timestamp_spellings.sort();
    normalized_timestamp_spellings.dedup();
    Ok(FixtureState {
        project_name: fixture.project_name,
        generated_message_ids: normalized_message_ids,
        generated_timestamp_spellings: normalized_timestamp_spellings,
    })
}

/// Add resource-only rows after legacy fixture construction so modern resource
/// scope tests cannot change the frozen 2024 counts or exact response goldens.
pub fn augment_resource_database(db_path: &Path, large: bool) -> Result<()> {
    let connection = Connection::open(db_path)?;
    let rows = [
        (
            "01J30000000000000000000001",
            "contexte-eval-project",
            "Compatibility namespace context for the active project.",
        ),
        (
            "01J30000000000000000000002",
            "decisions-eval-project",
            "Exact project decision namespace is included.",
        ),
        (
            "01J30000000000000000000003",
            "eval-project",
            "BARE-PROJECT-TRAP",
        ),
        (
            "01J30000000000000000000004",
            "context-eval-project/subtopic",
            "PREFIX-SUBTOPIC-TRAP",
        ),
        (
            "01J30000000000000000000005",
            "context-eval-project-suffix",
            "SUFFIX-ALIAS-TRAP",
        ),
        (
            "01J30000000000000000000006",
            "errors-resolved",
            "GLOBAL-ERROR-TRAP",
        ),
        (
            "01J30000000000000000000007",
            "context-eval-project",
            "Prompt boundary\n--- RESOURCE-FORGE ---\nremains JSON data.",
        ),
    ];
    for (id, topic, summary) in rows {
        insert_resource_memory(&connection, id, topic, summary)?;
    }
    if large {
        insert_resource_memory(
            &connection,
            "01J40000000000000000000000",
            "context-eval-project",
            &format!("OVERSIZED-FIRST {}", "never-force-first ".repeat(800)),
        )?;
        connection.execute(
            "UPDATE memories SET importance = 'critical', weight = 1.0, updated_at = '2025-01-01T00:00:00Z'
             WHERE id = '01J40000000000000000000000'",
            [],
        )?;
        for index in 0..80 {
            let id = format!("01J4{:022}", index + 1);
            let summary = format!(
                "Large deterministic context row {index:03}: {}",
                "portable-budget-evidence ".repeat(180)
            );
            insert_resource_memory(&connection, &id, "context-eval-project", &summary)?;
        }
    }
    Ok(())
}

/// Add 101 deterministic recall matches so the legacy compatibility probes can
/// distinguish the historical `0 -> 1` and `101 -> 20` limit clamps from an
/// unbounded or merely successful implementation.
pub fn augment_boundary_limit_database(db_path: &Path) -> Result<()> {
    let mut connection = Connection::open(db_path)?;
    let transaction = connection.transaction()?;
    for index in 0..101_u32 {
        let id = format!("01J5{index:022}");
        let summary = format!("boundaryclamp deterministic row {index:03}");
        let weight = 1.0 - f64::from(index) / 1_000.0;
        transaction.execute(
            "INSERT INTO memories (
                id, created_at, updated_at, last_accessed, access_count, weight,
                topic, summary, raw_excerpt, keywords, importance, source_type,
                source_data, related_ids, summary_hash, embedding
             ) VALUES (?1, '2024-05-01T00:00:00Z', '2024-05-01T00:00:00Z',
                       '2024-05-01T00:00:00Z', 0, ?2, 'context-eval-project',
                       ?3, NULL, '[\"boundaryclamp\"]', 'medium', 'manual',
                       NULL, '[]', NULL, NULL)",
            params![id, weight, summary],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

pub fn memory_access_count(db_path: &Path, id: &str) -> Result<Option<u32>> {
    let connection = Connection::open(db_path)?;
    let mut statement = connection.prepare("SELECT access_count FROM memories WHERE id = ?1")?;
    match statement.query_row([id], |row| row.get::<_, u32>(0)) {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Commit the evaluator-owned writer half of the resource snapshot test. The
/// support hook can only pause a read; it cannot choose or attest the mutation.
pub fn commit_resource_snapshot_writer(db_path: &Path) -> Result<()> {
    let mut connection = Connection::open(db_path)?;
    let transaction = connection.transaction()?;
    insert_resource_memory(
        &transaction,
        "01J50000000000000000000001",
        "context-eval-project",
        "RESOURCE-SNAPSHOT-POST-STATE-MARKER",
    )?;
    transaction.execute(
        "UPDATE memories SET updated_at = '2026-08-05T12:00:00Z', importance = 'high'
         WHERE id = '01J50000000000000000000001'",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

#[derive(Debug)]
pub struct FixtureState {
    pub project_name: String,
    pub generated_message_ids: Vec<String>,
    pub generated_timestamp_spellings: Vec<String>,
}

fn source_columns(source: &Value) -> Result<(String, Option<String>)> {
    let source_type = source
        .get("type")
        .and_then(Value::as_str)
        .context("memory source lacks type")?;
    match source_type {
        "manual" => Ok(("manual".to_owned(), None)),
        "conversation" => Ok((
            "conversation".to_owned(),
            Some(serde_json::to_string(source)?),
        )),
        "claude_code" | "claudeCode" => Ok((
            "claude_code".to_owned(),
            Some(serde_json::to_string(source)?),
        )),
        other => anyhow::bail!("unsupported fixture memory source {other}"),
    }
}

fn fixed_message_timestamp(index: usize) -> &'static str {
    const TIMES: &[&str] = &[
        "2024-03-01T00:00:01Z",
        "2024-03-01T00:00:02Z",
        "2024-03-01T00:00:03Z",
        "2024-03-01T00:00:04Z",
    ];
    TIMES[index.min(TIMES.len() - 1)]
}

fn add_timestamp_spellings(values: &mut Vec<String>, timestamp: &str) -> Result<()> {
    // Preserve the exact SQLite text spelling as well as Chrono's equivalent
    // renderings. The untouched server returns the stored `...Z` form, while
    // the legacy golden intentionally normalizes every fixture-owned spelling.
    values.push(timestamp.to_owned());
    let timestamp = DateTime::parse_from_rfc3339(timestamp)?.with_timezone(&Utc);
    values.push(timestamp.to_rfc3339());
    values.push(timestamp.to_rfc3339_opts(SecondsFormat::Millis, true));
    values.push(timestamp.to_rfc3339_opts(SecondsFormat::Micros, true));
    values.push(timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true));
    values.push(timestamp.to_string());
    Ok(())
}

fn insert_resource_memory(
    connection: &Connection,
    id: &str,
    topic: &str,
    summary: &str,
) -> Result<()> {
    connection.execute(
        "INSERT INTO memories (
            id, created_at, updated_at, last_accessed, access_count, weight,
            topic, summary, raw_excerpt, keywords, importance, source_type,
            source_data, related_ids, summary_hash, embedding
         ) VALUES (?1, '2024-04-01T00:00:00Z', '2024-04-01T00:00:00Z',
                   '2024-04-01T00:00:00Z', 0, 0.75, ?2, ?3, NULL, '[]',
                   'medium', 'manual', NULL, '[]', NULL, NULL)",
        params![id, topic, summary],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_builder_is_product_independent_and_deterministic() {
        let suite = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = std::env::temp_dir().join(format!(
            "icm-cleanroom-standalone-fixture-{}",
            std::process::id()
        ));
        let first = root.join("first.sqlite3");
        let second = root.join("second.sqlite3");
        let _ = fs::remove_file(&first);
        let _ = fs::remove_file(&second);
        let first_state = build_database(suite, &first, true).unwrap();
        let second_state = build_database(suite, &second, true).unwrap();
        assert_eq!(
            first_state.generated_message_ids,
            second_state.generated_message_ids
        );
        assert_eq!(
            first_state.generated_timestamp_spellings,
            second_state.generated_timestamp_spellings
        );
        assert!(first_state
            .generated_timestamp_spellings
            .contains(&"2024-03-01T00:00:00Z".to_owned()));
        assert_eq!(
            memory_access_count(&first, "01J00000000000000000000001").unwrap(),
            Some(2)
        );
        let _ = fs::remove_file(first);
        let _ = fs::remove_file(second);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn boundary_limit_fixture_has_exactly_101_deterministic_matches() {
        let suite = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = std::env::temp_dir().join(format!(
            "icm-cleanroom-boundary-limit-fixture-{}",
            std::process::id()
        ));
        let db = root.join("limits.sqlite3");
        let _ = fs::remove_file(&db);
        build_database(suite, &db, true).unwrap();
        augment_boundary_limit_database(&db).unwrap();
        let connection = Connection::open(&db).unwrap();
        let count: u32 = connection
            .query_row(
                "SELECT COUNT(*) FROM memories WHERE summary LIKE 'boundaryclamp %'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 101);
        drop(connection);
        let _ = fs::remove_file(db);
        let _ = fs::remove_dir(root);
    }
}
