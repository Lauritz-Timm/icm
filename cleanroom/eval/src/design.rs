use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fixtures::{load_paths, load_providers};
use crate::sandbox::{join_pure, sha256_bytes, sha256_file, REQUIRED_ENV};

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
    pub baseline_metrics_sha256: String,
    pub acceptance_thresholds_sha256: String,
    pub bound_threshold_count: usize,
    pub acceptance_thresholds: AcceptanceThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceThresholds {
    pub legacy_deterministic_parity: f64,
    pub legacy_catalog_order_parity: f64,
    pub legacy_required_field_parity: f64,
    pub modern_schema_coverage: f64,
    pub modern_required_field_coverage: f64,
    pub actual_structured_emissions_valid: f64,
    pub boundary_pass_rate: f64,
    pub resource_max_portable_tokens: usize,
    pub resource_max_wire_bytes: usize,
    pub modern_recall_max_wire_bytes: usize,
    pub modern_concise_text_max_bytes: usize,
    pub proxy_client_count: usize,
    pub proxy_calls_per_client: usize,
    pub daemon_count: usize,
    pub daemon_model_load_count: usize,
    pub unsupported_baseline_requires_wire_or_cli_evidence: bool,
    pub latency_block_count: usize,
    pub latency_warmups_per_operation: usize,
    pub latency_samples_per_block: usize,
    pub latency_median_ratio_numerator: u128,
    pub latency_median_ratio_denominator: u128,
    pub latency_median_allowance_micros: u128,
    pub latency_p95_ratio_numerator: u128,
    pub latency_p95_ratio_denominator: u128,
    pub latency_p95_allowance_micros: u128,
    pub latency_noise_floor_micros: u128,
    pub retrieval_k: usize,
    pub retrieval_hit_at_3_minimum: f64,
    pub retrieval_recall_at_3_minimum: f64,
    pub retrieval_ndcg_at_3_minimum: f64,
}

pub const ACCEPTANCE_THRESHOLD_KEYS: &[&str] = &[
    "legacyDeterministicParity",
    "legacyCatalogOrderParity",
    "legacyRequiredFieldParity",
    "modernSchemaCoverage",
    "modernRequiredFieldCoverage",
    "actualStructuredEmissionsValid",
    "boundaryPassRate",
    "resourceMaxPortableTokens",
    "resourceMaxWireBytes",
    "modernRecallMaxWireBytes",
    "modernConciseTextMaxBytes",
    "proxyClientCount",
    "proxyCallsPerClient",
    "daemonCount",
    "daemonModelLoadCount",
    "unsupportedBaselineRequiresWireOrCliEvidence",
    "latencyBlockCount",
    "latencyWarmupsPerOperation",
    "latencySamplesPerBlock",
    "latencyMedianRatioNumerator",
    "latencyMedianRatioDenominator",
    "latencyMedianAllowanceMicros",
    "latencyP95RatioNumerator",
    "latencyP95RatioDenominator",
    "latencyP95AllowanceMicros",
    "latencyNoiseFloorMicros",
    "retrievalK",
    "retrievalHitAt3Minimum",
    "retrievalRecallAt3Minimum",
    "retrievalNdcgAt3Minimum",
];

pub fn verify(suite_root: &Path) -> Result<DesignVerification> {
    let design: Value = read_json(&suite_root.join("contracts/preregistered-design.json"))?;
    if design
        .get("frozenBeforeReplacementCode")
        .and_then(Value::as_bool)
        != Some(true)
    {
        anyhow::bail!("design is not marked frozen-before-replacement-code");
    }
    let design_version = design
        .get("designVersion")
        .and_then(Value::as_u64)
        .context("missing designVersion")?;

    verify_environment(&design)?;
    let fixture_hashes = verify_fixture_hashes(suite_root)?;
    let contract_hashes = verify_contracts(suite_root, &design)?;
    let scenarios = expected_scenarios(&design)?;
    verify_unique(&scenarios, "scenario")?;
    let declared_scenario_count = design
        .get("scenarioCount")
        .and_then(Value::as_u64)
        .context("scenarioCount missing")? as usize;
    if scenarios.len() != declared_scenario_count || declared_scenario_count != 326 {
        anyhow::bail!(
            "scenario inventory count mismatch: executable={}, declared={}, required=326",
            scenarios.len(),
            declared_scenario_count
        );
    }
    verify_paths(suite_root)?;
    verify_no_host_paths(suite_root)?;
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
    let structured_tool_count = schemas
        .get("tools")
        .and_then(Value::as_object)
        .context("modern schemas missing tools")?
        .len();
    if structured_tool_count != 11 {
        anyhow::bail!("expected 11 modern structured output schemas, got {structured_tool_count}");
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
    let metrics_path = suite_root.join("goldens/baseline-metrics.json");
    let baseline_metrics: Value = read_json(&metrics_path)?;
    let expected_operations: BTreeSet<_> = ["tools/list", "memory/recall", "memory/stats"]
        .into_iter()
        .collect();
    let actual_operations: BTreeSet<_> = baseline_metrics
        .get("latencyMicros")
        .and_then(Value::as_object)
        .context("baseline metrics lack latencyMicros")?
        .keys()
        .map(String::as_str)
        .collect();
    if actual_operations != expected_operations
        || baseline_metrics
            .get("candidateSha256")
            .and_then(Value::as_str)
            .is_none_or(|hash| hash.len() != 64)
    {
        anyhow::bail!("baseline metric golden is incomplete");
    }
    for operation in expected_operations {
        for statistic in ["median", "p95"] {
            if baseline_metrics
                .pointer(&format!(
                    "/latencyMicros/{}/{statistic}",
                    operation.replace('/', "~1")
                ))
                .and_then(Value::as_u64)
                .is_none_or(|value| value == 0)
            {
                anyhow::bail!("baseline latency {operation}.{statistic} is absent or zero");
            }
        }
    }
    let baseline_metrics_sha256 = sha256_file(&metrics_path)?;

    Ok(DesignVerification {
        design_version,
        fixture_hashes,
        contract_hashes,
        scenario_count: scenarios.len(),
        tool_count: expected_tools.len(),
        structured_tool_count,
        golden_scenario_count: golden.len(),
        baseline_metrics_sha256,
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
    for id in inventory
        .get("providerEngine")
        .and_then(Value::as_array)
        .context("scenarioInventory.providerEngine missing")?
    {
        scenarios.push(
            id.as_str()
                .context("non-string provider engine scenario")?
                .to_owned(),
        );
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
    if wire.get("accessedAt").and_then(Value::as_str) != Some("2026-08-05")
        || wire.get("runtimeNetworkRequired").and_then(Value::as_bool) != Some(false)
        || wire
            .pointer("/request/metadataLocation")
            .and_then(Value::as_str)
            != Some("/params/_meta")
        || wire
            .pointer("/request/discoveryMethod")
            .and_then(Value::as_str)
            != Some("server/discover")
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
        anyhow::bail!("offline MCP wire contract differs from the frozen v4 semantics");
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
        || proxy
            .pointer("/evidence/candidateSelfAttestationAccepted")
            .and_then(Value::as_bool)
            != Some(false)
    {
        anyhow::bail!("proxy contract differs from the frozen v4 black-box contract");
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

fn verify_product_independence(suite_root: &Path) -> Result<()> {
    let cargo = fs::read_to_string(suite_root.join("Cargo.toml"))?;
    let parsed: toml::Value = cargo.parse()?;
    if parsed
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .is_some_and(|dependencies| {
            dependencies.values().any(|value| {
                value
                    .as_table()
                    .is_some_and(|table| table.contains_key("path"))
            })
        })
    {
        anyhow::bail!("evaluator Cargo.toml contains a forbidden path dependency");
    }
    for file in recursive_files(&suite_root.join("src"))? {
        let source = fs::read_to_string(&file)?;
        for forbidden in [["icm", "core"].join("_"), ["icm", "store"].join("_")] {
            if source.contains(&forbidden) {
                anyhow::bail!(
                    "evaluator source {} references forbidden product crate {forbidden}",
                    file.display()
                );
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
    let metric_refs: BTreeSet<_> = ["latency", "retrieval"]
        .into_iter()
        .flat_map(|section| {
            design
                .pointer(&format!("/metrics/{section}/thresholdRefs"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
        })
        .collect();
    let expected_metric_refs: BTreeSet<_> = ACCEPTANCE_THRESHOLD_KEYS
        .iter()
        .copied()
        .filter(|key| key.starts_with("latency") || key.starts_with("retrieval"))
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

fn verify_no_host_paths(suite_root: &Path) -> Result<()> {
    let paths = [
        suite_root.join("src"),
        suite_root.join("contracts"),
        suite_root.join("Cargo.toml"),
    ];
    for path in paths {
        for file in recursive_files(&path)? {
            let content = fs::read_to_string(&file)
                .with_context(|| format!("reading source as UTF-8 {}", file.display()))?;
            let host_prefixes = [
                ["/", "home", "/"].concat(),
                ["/", "Users", "/"].concat(),
                ["C:", "\\", "Users", "\\"].concat(),
                ["/", "var", "/", "folders", "/"].concat(),
            ];
            for forbidden in host_prefixes {
                if content.contains(&forbidden) {
                    anyhow::bail!(
                        "host-specific absolute path {forbidden:?} in {}",
                        file.display()
                    );
                }
            }
            let shell_markers = [
                ["Command::new(\"", "sh", "\")"].concat(),
                ["Command::new(\"", "bash", "\")"].concat(),
                ["Command::new(\"", "zsh", "\")"].concat(),
                ["cmd", ".exe", " /", "C"].concat(),
            ];
            for forbidden in shell_markers {
                if content.contains(&forbidden) {
                    anyhow::bail!("shell orchestration {forbidden:?} in {}", file.display());
                }
            }
        }
    }
    Ok(())
}

fn recursive_files(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            files.extend(recursive_files(&entry.path())?);
        } else {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
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
