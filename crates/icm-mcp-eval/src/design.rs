use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fixtures::{load_paths, load_providers};
use crate::mcp::{
    meta_key_is_valid, ERA_LOCKED_ERROR_CODE, INVALID_META_KEY_FIXTURE,
    LIFECYCLE_VIOLATION_ERROR_CODE,
};
use crate::sandbox::{join_pure, sha256_bytes, sha256_file, REQUIRED_ENV};
use crate::schema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DesignVerification {
    pub design_version: u64,
    pub fixture_hashes: BTreeMap<String, String>,
    pub contract_hashes: BTreeMap<String, String>,
    pub scenario_count: usize,
    pub tool_count: usize,
    pub structured_tool_count: usize,
    pub golden_scenario_count: usize,
    pub acceptance_thresholds_sha256: String,
    pub bound_threshold_count: usize,
    pub acceptance_thresholds: AcceptanceThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceThresholds {
    pub resource_max_portable_tokens: usize,
    pub resource_max_wire_bytes: usize,
    pub modern_recall_max_wire_bytes: usize,
    pub modern_concise_text_max_bytes: usize,
    pub proxy_client_count: usize,
    pub proxy_calls_per_client: usize,
    pub daemon_count: usize,
    pub daemon_model_load_count: usize,
    pub unsupported_baseline_requires_wire_or_cli_evidence: bool,
    pub retrieval_k: usize,
    pub retrieval_hit_at_3_minimum: f64,
    pub retrieval_recall_at_3_minimum: f64,
    pub retrieval_ndcg_at_3_minimum: f64,
}

pub const ACCEPTANCE_THRESHOLD_KEYS: &[&str] = &[
    "resourceMaxPortableTokens",
    "resourceMaxWireBytes",
    "modernRecallMaxWireBytes",
    "modernConciseTextMaxBytes",
    "proxyClientCount",
    "proxyCallsPerClient",
    "daemonCount",
    "daemonModelLoadCount",
    "unsupportedBaselineRequiresWireOrCliEvidence",
    "retrievalK",
    "retrievalHitAt3Minimum",
    "retrievalRecallAt3Minimum",
    "retrievalNdcgAt3Minimum",
];

const BASELINE_SOURCE_COMMIT: &str = "e2acd39fd9b77619b6ed9f0ee47828c04f9dfb40";
const BASELINE_EVALUATOR_COMMIT: &str = "4571bf9f4b0c4e4ac3aea5710b7dbdce07bec49c";
const BASELINE_ROOTS: [&str; 2] = ["<ROOT_WITH_SPACES>", "<ROOT_WITH_UNICODE>"];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineFile {
    receipt: BaselineReceipt,
    latency_micros: BaselineLatencyMetrics,
    payload_wire_bytes: BaselinePayloadWireBytes,
    retrieval: BaselineRetrievalMetrics,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineLatencyMetrics {
    #[serde(rename = "tools/list")]
    tools_list: BaselineLatency,
    #[serde(rename = "memory/recall")]
    memory_recall: BaselineLatency,
    #[serde(rename = "memory/stats")]
    memory_stats: BaselineLatency,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineLatency {
    median: u64,
    p95: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselinePayloadWireBytes {
    #[serde(rename = "tools/list")]
    tools_list: u64,
    #[serde(rename = "memory/recall")]
    memory_recall: u64,
    #[serde(rename = "memory/stats")]
    memory_stats: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineRetrievalMetrics {
    hit_at_3: f64,
    recall_at_3: f64,
    ndcg_at_3: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineReceipt {
    receipt_version: u64,
    mode: String,
    source_commit: String,
    candidate_sha256: String,
    evaluator_commit: String,
    design_version: u64,
    scenario_count: usize,
    status_counts: BTreeMap<String, usize>,
    legacy_golden_sha256: String,
    normalized_report_sha256: String,
    raw_exchanges: Vec<BaselineRawExchange>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BaselineRawExchange {
    root: String,
    sha256: String,
    bytes: u64,
    lines: u64,
}

pub fn verify(suite_root: &Path) -> Result<DesignVerification> {
    let design: Value = read_json(&suite_root.join("contracts/preregistered-design.json"))?;
    let design_version = design
        .get("designVersion")
        .and_then(Value::as_u64)
        .context("missing designVersion")?;
    if design_version != 12 {
        anyhow::bail!("expected preregistration designVersion 12");
    }
    let expected_provenance = serde_json::json!({
        "initialDesignFrozenAt": "2026-08-05",
        "initialDesignFrozenBeforeReplacementImplementation": true,
        "laterRevisionsArePostImplementationAuditSpecCorrections": true,
        "version9FrozenBeforeInitialFinalCandidateRun": true,
        "version10FrozenBeforeCorrectedCandidateRun": true,
        "version11FrozenBeforeDefinitiveTwoRootSelfTest": true,
        "version12FrozenBeforeCorrectedTwoRootSelfTest": true,
        "scenarioInventoryAndThresholdsUnchanged": true,
        "version9Revision": "Provider/OpenCode and HTTP session/Origin audit/spec corrections.",
        "version10Revision": "Align the evaluator with the final provider journal and revision-sensitive proxy headers, and close portable provider-state, Git-ancestry, and cross-scenario canary gaps.",
        "version11Revision": "Remove stale modern text ULID normalization rules: modern IDs are normalized in structuredContent while concise text intentionally does not duplicate them.",
        "version12Revision": "Declare exact normalization pointers for the remaining dynamic structured IDs and RFC3339 timestamps exposed by the v11 two-root diff; scenarios and thresholds remain unchanged."
    });
    if design.get("provenance") != Some(&expected_provenance) {
        anyhow::bail!("design provenance differs from the frozen v12 audit record");
    }

    verify_environment(&design)?;
    let fixture_hashes = verify_fixture_hashes(suite_root)?;
    let contract_hashes = verify_contracts(suite_root, &design)?;
    let scenarios = expected_scenarios(&design)?;
    verify_unique(&scenarios, "scenario")?;
    let declared_scenario_count = design
        .get("scenarioCount")
        .and_then(Value::as_u64)
        .context("scenarioCount missing")? as usize;
    if scenarios.len() != declared_scenario_count {
        anyhow::bail!(
            "scenario inventory count mismatch: executable={}, declared={}",
            scenarios.len(),
            declared_scenario_count
        );
    }
    verify_paths(suite_root)?;
    // This frozen flag governs fixture construction, which must remain
    // independent of product crates. The ordinary MCP execution lane is a
    // separate, intentional production-service integration check.
    if design
        .pointer("/fixtureConstruction/productCratePathDependenciesAllowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        anyhow::bail!("fixture construction must remain product-crate independent");
    }
    verify_product_independence(suite_root)?;
    let (acceptance_thresholds, acceptance_thresholds_sha256, bound_threshold_count) =
        verify_threshold_bindings(&design, &scenarios)?;

    let annotations: Value = read_json(&suite_root.join("contracts/tool-annotations.json"))?;
    let legacy = design
        .pointer("/legacyCatalog/withoutEmbedder")
        .and_then(Value::as_array)
        .context("legacy catalog missing")?;
    let mut expected_tools: Vec<String> = legacy
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    expected_tools.push(
        design
            .pointer("/legacyCatalog/embedderConditionalTail")
            .and_then(Value::as_str)
            .context("conditional embedder tool missing")?
            .to_owned(),
    );
    let annotation_object = annotations
        .as_object()
        .context("annotations must be an object")?;
    let annotation_tools: BTreeSet<_> = annotation_object.keys().cloned().collect();
    let expected_tool_set: BTreeSet<_> = expected_tools.iter().cloned().collect();
    if annotation_tools != expected_tool_set {
        anyhow::bail!("annotation tool set differs from frozen legacy catalog");
    }
    for (tool, annotation) in annotation_object {
        let object = annotation
            .as_object()
            .with_context(|| format!("annotation for {tool} is not an object"))?;
        let keys: BTreeSet<_> = object.keys().map(String::as_str).collect();
        let expected = BTreeSet::from([
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ]);
        if keys != expected || object.values().any(|value| !value.is_boolean()) {
            anyhow::bail!("annotation for {tool} is not the exact four-boolean contract");
        }
    }

    let schemas: Value = read_json(&suite_root.join("contracts/modern-output-schemas.json"))?;
    let structured_tools = schemas
        .get("tools")
        .and_then(Value::as_object)
        .context("modern schemas missing tools")?;
    let structured_tool_count = structured_tools.len();
    if structured_tool_count != 11 {
        anyhow::bail!("expected 11 modern structured output schemas, got {structured_tool_count}");
    }
    for (tool, output_schema) in structured_tools {
        schema::verify_independent_schema(output_schema).with_context(|| {
            format!("frozen output schema for {tool} is not independently self-contained")
        })?;
    }
    let golden: BTreeMap<String, String> = serde_json::from_slice(&fs::read(
        suite_root.join("goldens/legacy-baseline.sha256.json"),
    )?)?;
    let mut expected_golden: BTreeSet<String> = design
        .pointer("/scenarioInventory/legacy")
        .and_then(Value::as_array)
        .context("legacy scenarios missing")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    for dynamic in [
        "legacy.transcript-start",
        "legacy.transcript-record-all-roles",
        "legacy.feedback-record",
    ] {
        expected_golden.remove(dynamic);
    }
    let actual_golden: BTreeSet<_> = golden.keys().cloned().collect();
    if actual_golden != expected_golden
        || golden.values().any(|hash| {
            hash.len() != 64
                || !hash
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
    {
        anyhow::bail!("legacy golden hash manifest is incomplete or malformed");
    }
    let legacy_golden_sha256 =
        sha256_file(&suite_root.join("goldens/legacy-baseline.sha256.json"))?;
    verify_baseline_receipt(suite_root, &design, scenarios.len(), &legacy_golden_sha256)?;
    Ok(DesignVerification {
        design_version,
        fixture_hashes,
        contract_hashes,
        scenario_count: scenarios.len(),
        tool_count: expected_tools.len(),
        structured_tool_count,
        golden_scenario_count: golden.len(),
        acceptance_thresholds_sha256,
        bound_threshold_count,
        acceptance_thresholds,
    })
}

pub fn load_design(suite_root: &Path) -> Result<Value> {
    read_json(&suite_root.join("contracts/preregistered-design.json"))
}

pub fn expected_scenarios(design: &Value) -> Result<Vec<String>> {
    let inventory = design
        .get("scenarioInventory")
        .and_then(Value::as_object)
        .context("scenarioInventory missing")?;
    let mut scenarios = Vec::new();
    for category in [
        "isolation",
        "legacy",
        "modern",
        "resource",
        "proxy",
        "boundaries",
        "metrics",
    ] {
        for id in inventory
            .get(category)
            .and_then(Value::as_array)
            .with_context(|| format!("scenarioInventory.{category} missing"))?
        {
            scenarios.push(
                id.as_str()
                    .with_context(|| format!("non-string scenario in {category}"))?
                    .to_owned(),
            );
        }
    }
    let providers = inventory
        .get("providerAxes")
        .and_then(Value::as_object)
        .and_then(|axes| axes.get("providers"))
        .and_then(Value::as_array)
        .context("provider axes missing providers")?;
    let cases = inventory
        .get("providerAxes")
        .and_then(Value::as_object)
        .and_then(|axes| axes.get("cases"))
        .and_then(Value::as_array)
        .context("provider axes missing cases")?;
    for provider in providers.iter().filter_map(Value::as_str) {
        for case in cases.iter().filter_map(Value::as_str) {
            scenarios.push(format!("provider.{provider}.{case}"));
        }
    }
    Ok(scenarios)
}

fn verify_environment(design: &Value) -> Result<()> {
    let actual: BTreeSet<_> = design
        .get("environmentAllowlist")
        .and_then(Value::as_array)
        .context("environmentAllowlist missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected: BTreeSet<_> = REQUIRED_ENV.iter().copied().collect();
    if actual != expected {
        anyhow::bail!("design environment allowlist differs from runner allowlist");
    }
    Ok(())
}

fn verify_fixture_hashes(suite_root: &Path) -> Result<BTreeMap<String, String>> {
    let manifest_path = suite_root.join("fixtures/checksums.sha256");
    let manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let mut hashes = BTreeMap::new();
    for (line_number, line) in manifest.lines().enumerate() {
        let (hash, name) = line
            .split_once("  ")
            .with_context(|| format!("invalid checksum line {}", line_number + 1))?;
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            anyhow::bail!("unsafe fixture checksum path {name}");
        }
        let actual = sha256_file(&suite_root.join("fixtures").join(name))?;
        if actual != hash {
            anyhow::bail!("fixture hash mismatch for {name}: expected {hash}, got {actual}");
        }
        hashes.insert(name.to_owned(), actual);
    }
    let expected: BTreeSet<_> = [
        "path-cases.json",
        "providers.json",
        "quality.json",
        "sqlite-schema.sql",
        "store.json",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<_> = hashes.keys().map(String::as_str).collect();
    if actual != expected {
        anyhow::bail!("fixture checksum coverage is not exactly 100%");
    }
    Ok(hashes)
}

fn verify_contracts(suite_root: &Path, design: &Value) -> Result<BTreeMap<String, String>> {
    let manifest_path = suite_root.join("contracts/checksums.sha256");
    let manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let mut hashes = BTreeMap::new();
    for (line_number, line) in manifest.lines().enumerate() {
        let (hash, name) = line
            .split_once("  ")
            .with_context(|| format!("invalid contract checksum line {}", line_number + 1))?;
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            anyhow::bail!("unsafe contract checksum path {name}");
        }
        let path = suite_root.join("contracts").join(name);
        let actual = sha256_file(&path)?;
        if actual != hash {
            anyhow::bail!("contract hash mismatch for {name}: expected {hash}, got {actual}");
        }
        if name.ends_with(".json") {
            let _: Value = read_json(&path)?;
        }
        hashes.insert(name.to_owned(), actual);
    }
    let expected: BTreeSet<_> = [
        "mcp-2026-wire-contract.json",
        "modern-output-schemas.json",
        "normalization-rules.json",
        "preregistered-design.json",
        "provider-contracts.json",
        "proxy-contracts.json",
        "tool-annotations.json",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<_> = hashes.keys().map(String::as_str).collect();
    if actual != expected {
        anyhow::bail!("contract checksum coverage is not exactly 100%");
    }

    let wire: Value = read_json(&suite_root.join("contracts/mcp-2026-wire-contract.json"))?;
    let era_locked_code = wire
        .pointer("/errors/eraLocked/code")
        .and_then(Value::as_i64)
        .context("era-locked application error code missing")?;
    let lifecycle_code = wire
        .pointer("/errors/lifecycleViolation/code")
        .and_then(Value::as_i64)
        .context("lifecycle application error code missing")?;
    if wire.get("contractVersion").and_then(Value::as_u64) != Some(2)
        || wire.get("accessedAt").and_then(Value::as_str) != Some("2026-08-05")
        || wire.get("runtimeNetworkRequired").and_then(Value::as_bool) != Some(false)
        || wire
            .pointer("/request/metadataLocation")
            .and_then(Value::as_str)
            != Some("/params/_meta")
        || wire
            .pointer("/request/discoveryMethod")
            .and_then(Value::as_str)
            != Some("server/discover")
        || wire
            .pointer("/request/topLevelMetadataDoesNotSatisfyRequiredMetadata")
            .and_then(Value::as_bool)
            != Some(true)
        || wire
            .pointer("/request/invalidMetadataKeyFixture")
            .and_then(Value::as_str)
            != Some(INVALID_META_KEY_FIXTURE)
        || wire
            .pointer("/request/validBareMetadataKeyExample")
            .and_then(Value::as_str)
            != Some("invalid")
        || era_locked_code != ERA_LOCKED_ERROR_CODE
        || lifecycle_code != LIFECYCLE_VIOLATION_ERROR_CODE
        || (-32768..=-32000).contains(&era_locked_code)
        || (-32768..=-32000).contains(&lifecycle_code)
        || wire
            .pointer("/connectionEra/modernRequestsStateless")
            .and_then(Value::as_bool)
            != Some(true)
        || wire
            .pointer("/connectionEra/concurrentDualEraServiceRequiredByMcp")
            .and_then(Value::as_bool)
            != Some(false)
        || wire.pointer("/resource/uri").and_then(Value::as_str)
            != Some("icm://active-project/context")
        || wire
            .pointer("/resource/portableBudget/algorithm")
            .and_then(Value::as_str)
            != Some("utf8-bytes-v1")
        || wire
            .pointer("/resource/portableBudget/maxPortableTokens")
            .and_then(Value::as_u64)
            != Some(2048)
        || wire
            .pointer("/resource/portableBudget/maxSerializedTextBytes")
            .and_then(Value::as_u64)
            != Some(2048)
    {
        anyhow::bail!("offline MCP wire contract differs from executable semantics");
    }
    if !meta_key_is_valid("invalid")
        || !meta_key_is_valid("com.example/evaluation")
        || meta_key_is_valid(INVALID_META_KEY_FIXTURE)
    {
        anyhow::bail!("frozen metadata-key fixtures differ from the final MCP grammar");
    }
    let design_urls: BTreeSet<_> = design
        .pointer("/officialSources/urls")
        .and_then(Value::as_array)
        .context("official source URL list missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let wire_urls: BTreeSet<_> = wire
        .get("sources")
        .and_then(Value::as_array)
        .context("wire source URL list missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if design_urls != wire_urls || wire_urls.len() != 4 {
        anyhow::bail!("official source URL pins differ between design and offline wire contract");
    }
    let provider: Value = read_json(&suite_root.join("contracts/provider-contracts.json"))?;
    if provider.pointer("/cli/scopes") != Some(&serde_json::json!(["project-local", "user"]))
        || provider.pointer("/cli/prefix") != Some(&serde_json::json!(["provider"]))
        || provider
            .pointer("/cli/nonInteractiveConfirmationFlag")
            .and_then(Value::as_str)
            != Some("--yes")
        || provider.pointer("/trustedTools")
            != Some(&serde_json::json!([
                "icm_memory_recall",
                "icm_memory_store"
            ]))
    {
        anyhow::bail!("provider contract differs from the frozen nested CLI/exact-tool contract");
    }
    let proxy: Value = read_json(&suite_root.join("contracts/proxy-contracts.json"))?;
    if proxy.pointer("/cli/command").and_then(Value::as_str)
        != Some("proxy --url <base-url> [--compact] [--token-file <path>]")
        || proxy
            .pointer("/endpoint/loopbackOnly")
            .and_then(Value::as_bool)
            != Some(true)
    {
        anyhow::bail!("proxy contract differs from the black-box contract");
    }
    let normalization: Value = read_json(&suite_root.join("contracts/normalization-rules.json"))?;
    crate::normalization::verify_contract(&suite_root.join("contracts/normalization-rules.json"))?;
    if normalization.get("default").and_then(Value::as_str) != Some("preserve")
        || normalization
            .get("shapeChangesAllowed")
            .and_then(Value::as_bool)
            != Some(false)
        || normalization
            .get("recursiveKeyMatchingAllowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        anyhow::bail!("normalization contract permits undeclared normalization");
    }
    Ok(hashes)
}

fn verify_baseline_receipt(
    suite_root: &Path,
    design: &Value,
    scenario_count: usize,
    legacy_golden_sha256: &str,
) -> Result<()> {
    let path = suite_root.join("goldens/baseline-metrics.json");
    let expected_sha256 = design
        .get("baselineMetricsSha256")
        .and_then(Value::as_str)
        .context("baselineMetricsSha256 missing from preregistered design")?;
    validate_digest("baseline metrics", expected_sha256, 64)?;
    let actual_sha256 = sha256_file(&path)?;
    if actual_sha256 != expected_sha256 {
        anyhow::bail!(
            "baseline metrics hash differs from the preregistered design: expected {expected_sha256}, got {actual_sha256}"
        );
    }
    let file: BaselineFile = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;
    validate_baseline_metrics(&file)?;
    validate_baseline_receipt(&file.receipt, scenario_count, legacy_golden_sha256)
}

fn validate_baseline_metrics(file: &BaselineFile) -> Result<()> {
    let latencies = [
        &file.latency_micros.tools_list,
        &file.latency_micros.memory_recall,
        &file.latency_micros.memory_stats,
    ];
    if latencies
        .iter()
        .any(|metrics| metrics.median == 0 || metrics.p95 == 0)
    {
        anyhow::bail!("baseline latency metrics must be positive");
    }
    if [
        file.payload_wire_bytes.tools_list,
        file.payload_wire_bytes.memory_recall,
        file.payload_wire_bytes.memory_stats,
    ]
    .contains(&0)
    {
        anyhow::bail!("baseline payload wire metrics must be positive");
    }
    let retrieval = [
        file.retrieval.hit_at_3,
        file.retrieval.recall_at_3,
        file.retrieval.ndcg_at_3,
    ];
    if retrieval
        .iter()
        .any(|metric| !metric.is_finite() || !(0.0..=1.0).contains(metric))
    {
        anyhow::bail!("baseline retrieval metrics must be finite fractions");
    }
    Ok(())
}

fn validate_baseline_receipt(
    receipt: &BaselineReceipt,
    scenario_count: usize,
    legacy_golden_sha256: &str,
) -> Result<()> {
    if receipt.receipt_version != 1 {
        anyhow::bail!("baseline receipt version must be 1");
    }
    if receipt.mode != "record-baseline" {
        anyhow::bail!("baseline receipt mode must be record-baseline");
    }
    if receipt.source_commit != BASELINE_SOURCE_COMMIT {
        anyhow::bail!(
            "baseline source commit differs: expected {BASELINE_SOURCE_COMMIT}, got {}",
            receipt.source_commit
        );
    }
    validate_digest("baseline candidate", &receipt.candidate_sha256, 64)?;
    validate_digest("baseline evaluator commit", &receipt.evaluator_commit, 40)?;
    if receipt.evaluator_commit != BASELINE_EVALUATOR_COMMIT {
        anyhow::bail!(
            "baseline evaluator commit differs: expected {BASELINE_EVALUATOR_COMMIT}, got {}",
            receipt.evaluator_commit
        );
    }
    if receipt.design_version != 12 {
        anyhow::bail!("baseline receipt designVersion must be 12");
    }
    if receipt.scenario_count != scenario_count || receipt.scenario_count != 294 {
        anyhow::bail!(
            "baseline receipt scenario count differs: expected {scenario_count}, got {}",
            receipt.scenario_count
        );
    }
    if receipt.status_counts
        != BTreeMap::from([
            ("FAIL".to_owned(), 21),
            ("PASS".to_owned(), 62),
            ("UNSUPPORTED_BASELINE".to_owned(), 211),
        ])
    {
        anyhow::bail!("baseline receipt status counts differ from the frozen observation");
    }
    if receipt.status_counts.values().sum::<usize>() != receipt.scenario_count {
        anyhow::bail!("baseline receipt status counts do not sum to scenario count");
    }
    validate_digest("baseline legacy golden", &receipt.legacy_golden_sha256, 64)?;
    if receipt.legacy_golden_sha256 != legacy_golden_sha256 {
        anyhow::bail!("baseline receipt legacy golden hash differs from the verified golden");
    }
    validate_digest(
        "baseline normalized report",
        &receipt.normalized_report_sha256,
        64,
    )?;
    if receipt.raw_exchanges.len() != BASELINE_ROOTS.len() {
        anyhow::bail!("baseline receipt must contain two raw-exchange records");
    }
    for (exchange, expected_root) in receipt.raw_exchanges.iter().zip(BASELINE_ROOTS) {
        if exchange.root != expected_root {
            anyhow::bail!(
                "baseline raw-exchange root differs: expected {expected_root}, got {}",
                exchange.root
            );
        }
        validate_digest("baseline raw exchanges", &exchange.sha256, 64)?;
        if exchange.bytes == 0 || exchange.lines == 0 {
            anyhow::bail!("baseline raw-exchange size metadata must be nonzero");
        }
    }
    Ok(())
}

fn validate_digest(label: &str, value: &str, length: usize) -> Result<()> {
    if !is_lower_hex(value, length) {
        anyhow::bail!("{label} is not a lowercase {length}-character SHA-256/commit digest");
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn verify_product_independence(suite_root: &Path) -> Result<()> {
    let cargo = fs::read_to_string(suite_root.join("Cargo.toml"))?;
    let parsed: toml::Value = cargo.parse()?;
    // The fixture schema/data remain evaluator-owned, as frozen by the design
    // contract. The integrated lane intentionally links only the production
    // MCP/storage crates; arbitrary path dependencies could reintroduce
    // evaluator-specific service implementations or ambient host state.
    const ALLOWED_PRODUCT_CRATES: &[&str] = &["icm-store", "icm-mcp"];
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(dependencies) = parsed.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, value) in dependencies {
            let Some(table) = value.as_table() else {
                continue;
            };
            if table.contains_key("path") && !ALLOWED_PRODUCT_CRATES.contains(&name.as_str()) {
                anyhow::bail!("evaluator Cargo.toml contains a forbidden path dependency: {name}");
            }
        }
    }
    Ok(())
}

fn verify_threshold_bindings(
    design: &Value,
    scenarios: &[String],
) -> Result<(AcceptanceThresholds, String, usize)> {
    let threshold_value = design
        .get("acceptanceThresholds")
        .context("acceptanceThresholds missing")?
        .clone();
    let thresholds: AcceptanceThresholds = serde_json::from_value(threshold_value.clone())?;
    let expected: BTreeSet<_> = ACCEPTANCE_THRESHOLD_KEYS.iter().copied().collect();
    let actual: BTreeSet<_> = threshold_value
        .as_object()
        .context("acceptanceThresholds must be an object")?
        .keys()
        .map(String::as_str)
        .collect();
    let bindings = design
        .get("acceptanceBindings")
        .and_then(Value::as_object)
        .context("acceptanceBindings must be an object")?;
    let bound: BTreeSet<_> = bindings.keys().map(String::as_str).collect();
    if actual != expected || bound != expected {
        anyhow::bail!(
            "threshold names, typed fields, and executable bindings differ: thresholds={actual:?}, bindings={bound:?}, expected={expected:?}"
        );
    }
    for (key, binding) in bindings {
        let object = binding
            .as_object()
            .with_context(|| format!("acceptance binding {key} is not an object"))?;
        let exact = object.get("scenario").and_then(Value::as_str);
        let prefix = object.get("scenarioPrefix").and_then(Value::as_str);
        if object
            .get("gate")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || exact.is_some() == prefix.is_some()
        {
            anyhow::bail!("acceptance binding {key} lacks exact scenario and gate");
        }
        if let Some(exact) = exact {
            if !scenarios.iter().any(|scenario| scenario == exact) {
                anyhow::bail!("acceptance binding {key} references absent scenario {exact}");
            }
        }
        if let Some(prefix) = prefix {
            if prefix.is_empty()
                || !scenarios
                    .iter()
                    .any(|scenario| scenario.starts_with(prefix))
            {
                anyhow::bail!(
                    "acceptance binding {key} prefix {prefix:?} matches no executable scenario"
                );
            }
        }
    }
    let metric_refs: BTreeSet<_> = design
        .pointer("/metrics/retrieval/thresholdRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let expected_metric_refs: BTreeSet<_> = ACCEPTANCE_THRESHOLD_KEYS
        .iter()
        .copied()
        .filter(|key| key.starts_with("retrieval"))
        .collect();
    if metric_refs != expected_metric_refs {
        anyhow::bail!(
            "metric thresholdRefs differ from typed executable metric thresholds: {metric_refs:?} != {expected_metric_refs:?}"
        );
    }
    if design
        .get("metrics")
        .and_then(|metrics| metrics.get("estimatedWireTokens"))
        != Some(&Value::String(
            "ceil(wireBytes / 4), reporting only".to_owned(),
        ))
    {
        anyhow::bail!("estimated wire tokens must remain explicitly reporting-only");
    }
    let canonical = serde_json::to_vec(&thresholds)?;
    Ok((thresholds, sha256_bytes(&canonical), bindings.len()))
}

fn verify_paths(suite_root: &Path) -> Result<()> {
    let paths = load_paths(suite_root)?;
    if paths.native_root_names.len() < 3
        || !paths
            .native_root_names
            .iter()
            .any(|name| name.contains(' '))
        || !paths.native_root_names.iter().any(|name| !name.is_ascii())
    {
        anyhow::bail!("native root fixtures must include plain, spaces, and Unicode cases");
    }
    for case in paths.pure_path_cases {
        let actual = join_pure(&case.style, &case.base, &case.relative)?;
        if actual != case.expected {
            anyhow::bail!(
                "pure path mismatch: expected {}, got {actual}",
                case.expected
            );
        }
    }
    let providers = load_providers(suite_root)?;
    if providers.providers.len() != 5
        || providers.owned_tools != ["icm_memory_recall", "icm_memory_store"]
        || providers.forbidden_patterns.is_empty()
        || providers
            .manifest_schema
            .get("currentVersion")
            .and_then(Value::as_u64)
            != Some(2)
    {
        anyhow::bail!("provider fixture axes are incomplete");
    }
    let manifest_expectations = [
        ("linux", "xdg-data", "icm/install-manifest.json"),
        (
            "macos",
            "home",
            "Library/Application Support/icm/install-manifest.json",
        ),
        ("windows", "appdata", "icm/icm/data/install-manifest.json"),
    ];
    for (platform, root, relative) in manifest_expectations {
        let spec = providers
            .manifest_paths
            .get(platform)
            .with_context(|| format!("provider fixture lacks {platform} manifest path"))?;
        if spec.root != root || spec.relative_path != relative {
            anyhow::bail!("provider {platform} production-default manifest path is wrong");
        }
    }
    for provider in &providers.providers {
        let scopes: BTreeSet<_> = provider
            .scopes
            .iter()
            .map(|scope| scope.scope.as_str())
            .collect();
        if scopes != BTreeSet::from(["project-local", "user"])
            || provider.scopes.iter().any(|scope| {
                scope.documents.is_empty()
                    || scope.documents.iter().any(|document| {
                        document.role.is_empty()
                            || document.root.is_empty()
                            || document.relative_path.is_empty()
                    })
            })
        {
            anyhow::bail!("provider {} does not cover both exact scopes", provider.id);
        }
    }
    Ok(())
}

fn verify_unique(values: &[String], label: &str) -> Result<()> {
    let unique: BTreeSet<_> = values.iter().collect();
    if unique.len() != values.len() {
        anyhow::bail!("duplicate {label} identifiers in preregistration");
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> BaselineFile {
        serde_json::from_str(include_str!("../goldens/baseline-metrics.json")).unwrap()
    }

    #[test]
    fn baseline_receipt_rejects_unknown_fields() {
        let mut value: Value =
            serde_json::from_str(include_str!("../goldens/baseline-metrics.json")).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<BaselineFile>(value).is_err());
    }

    #[test]
    fn baseline_receipt_rejects_tampered_digest() {
        let mut value = file();
        value.receipt.normalized_report_sha256 = "bad".to_owned();
        assert!(validate_baseline_receipt(
            &value.receipt,
            value.receipt.scenario_count,
            &value.receipt.legacy_golden_sha256,
        )
        .is_err());
    }
}
