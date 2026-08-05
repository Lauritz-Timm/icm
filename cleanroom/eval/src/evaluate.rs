use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::design::{self, DesignVerification};
use crate::fixtures::{
    augment_resource_database, build_database, commit_resource_snapshot_writer, load_paths,
    load_providers, load_quality, memory_access_count, FixtureState, ProviderCase,
    ProviderDocumentFixture, ProviderFixture, ProviderScopeFixture,
};
use crate::mcp::{
    error_code, modern_request, result, text_content, tool_call, tools_list, Exchange, McpClient,
    ERA_LOCKED_ERROR_CODE, INVALID_META_KEY_FIXTURE, LIFECYCLE_VIOLATION_ERROR_CODE,
    META_CLIENT_CAPABILITIES, META_CLIENT_INFO, META_PROTOCOL_VERSION, META_SERVER_INFO,
};
use crate::metrics::{
    extract_ranked_fixture_ids, retrieval_metrics, size_metrics, summarize_blocks, LatencySummary,
    RetrievalMetrics, SizeMetrics,
};
use crate::sandbox::{
    canary_checkpoint, join_pure, materialize_resolved, resolve_existing, resolve_intent,
    scan_for_real_path_leaks, sha256_bytes, sha256_file, validate_runner_roots,
    verify_canaries_since, ScenarioSandbox, UserStatePaths,
};
use crate::schema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationMode {
    RecordBaseline,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioStatus {
    Pass,
    Fail,
    UnsupportedBaseline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioResult {
    pub id: String,
    pub status: ScenarioStatus,
    pub detail: Value,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationReport {
    pub report_version: u64,
    pub mode: EvaluationMode,
    pub candidate_sha256: String,
    pub design: DesignVerification,
    pub scenarios: Vec<ScenarioResult>,
    pub metrics: MetricReport,
    pub status_counts: BTreeMap<String, usize>,
    pub portable_acceptance: bool,
    pub legacy_observation: BTreeMap<String, String>,
    pub raw_exchange_sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricReport {
    pub payload_sizes: BTreeMap<String, SizeMetrics>,
    pub latency: BTreeMap<String, LatencySummary>,
    pub latency_interpretation: BTreeMap<String, String>,
    pub retrieval: Option<RetrievalMetrics>,
    pub supplemental_pss_kib: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RawScenario<'a> {
    scenario: &'a str,
    exchanges: &'a [Exchange],
    stdout: &'a str,
    stderr: &'a str,
}

struct Execution {
    detail: Value,
    transcript: String,
    unsupported_evidence: Option<UnsupportedEvidence>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum UnsupportedEvidence {
    Wire {
        methods: Vec<String>,
        statuses: Vec<String>,
        response_count: usize,
    },
    Cli {
        arguments: Vec<String>,
        exit_code: i32,
    },
}

pub struct Runner {
    suite_root: PathBuf,
    candidate: PathBuf,
    work_root: PathBuf,
    evidence_root: PathBuf,
    run_label: String,
    mode: EvaluationMode,
    user_state: UserStatePaths,
    workspace_root: PathBuf,
    design: Value,
    verification: DesignVerification,
    golden: BTreeMap<String, String>,
    observed_legacy: BTreeMap<String, String>,
    raw_lines: Vec<String>,
    metrics: MetricReport,
}

impl Runner {
    pub fn new(
        workspace_root: PathBuf,
        suite_root: PathBuf,
        candidate: PathBuf,
        work_root: PathBuf,
        evidence_root: PathBuf,
        run_label: String,
        mode: EvaluationMode,
    ) -> Result<Self> {
        let user_state = UserStatePaths::from_environment()?;
        let workspace_root = resolve_existing(&workspace_root)?;
        let suite_root = resolve_existing(&suite_root)?;
        let candidate = resolve_existing(&candidate)?;
        let work_root = resolve_intent(&work_root)?;
        let evidence_root = resolve_intent(&evidence_root)?;
        validate_runner_roots(
            &workspace_root,
            &suite_root,
            &work_root,
            &evidence_root,
            &user_state,
        )?;
        let work_root = materialize_resolved(&work_root)?;
        let evidence_root = materialize_resolved(&evidence_root)?;
        let verification = design::verify(&suite_root)?;
        let design = design::load_design(&suite_root)?;
        let golden_path = suite_root.join("goldens/legacy-baseline.sha256.json");
        let golden = if golden_path.exists() {
            serde_json::from_slice(&fs::read(&golden_path)?)?
        } else {
            BTreeMap::new()
        };
        if mode == EvaluationMode::Candidate && golden.is_empty() {
            anyhow::bail!("candidate mode requires committed goldens/legacy-baseline.sha256.json");
        }
        Ok(Self {
            suite_root,
            candidate,
            work_root,
            evidence_root,
            run_label,
            mode,
            user_state,
            workspace_root,
            design,
            verification,
            golden,
            observed_legacy: BTreeMap::new(),
            raw_lines: Vec::new(),
            metrics: MetricReport::default(),
        })
    }

    pub fn run(mut self) -> Result<(EvaluationReport, PathBuf)> {
        let expected = design::expected_scenarios(&self.design)?;
        let mut scenarios = Vec::with_capacity(expected.len());
        for id in &expected {
            let checkpoint = canary_checkpoint()?;
            let execution = self.dispatch(id);
            let canary_verification = verify_canaries_since(checkpoint);
            let result = match (execution, canary_verification) {
                (Ok(result), Ok(())) => result,
                (Err(error), Ok(())) | (Ok(_), Err(error)) => self.failed(id, error),
                (Err(execution_error), Err(canary_error)) => self.failed(
                    id,
                    anyhow::anyhow!(
                        "{execution_error:#}; scenario canary verification also failed: {canary_error:#}"
                    ),
                ),
            };
            scenarios.push(result);
        }

        let actual_ids: BTreeSet<_> = scenarios
            .iter()
            .map(|scenario| scenario.id.as_str())
            .collect();
        let expected_ids: BTreeSet<_> = expected.iter().map(String::as_str).collect();
        if actual_ids != expected_ids || scenarios.len() != expected.len() {
            anyhow::bail!("runner scenario coverage differs from frozen inventory");
        }

        let mut status_counts = BTreeMap::new();
        for scenario in &scenarios {
            let key = match scenario.status {
                ScenarioStatus::Pass => "PASS",
                ScenarioStatus::Fail => "FAIL",
                ScenarioStatus::UnsupportedBaseline => "UNSUPPORTED_BASELINE",
            };
            *status_counts.entry(key.to_owned()).or_insert(0) += 1;
        }
        let portable_acceptance = scenarios
            .iter()
            .all(|scenario| scenario.status == ScenarioStatus::Pass);

        fs::create_dir_all(&self.evidence_root)?;
        let raw_path = self
            .evidence_root
            .join(format!("{}-raw-exchanges.jsonl", self.run_label));
        let raw_text = if self.raw_lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", self.raw_lines.join("\n"))
        };
        fs::write(&raw_path, &raw_text)?;
        let raw_exchange_sha256 = sha256_bytes(raw_text.as_bytes());
        let report = EvaluationReport {
            report_version: 1,
            mode: self.mode,
            candidate_sha256: sha256_file(&self.candidate)?,
            design: self.verification,
            scenarios,
            metrics: self.metrics,
            status_counts,
            portable_acceptance,
            legacy_observation: self.observed_legacy,
            raw_exchange_sha256,
        };
        let report_path = self
            .evidence_root
            .join(format!("{}-result.json", self.run_label));
        fs::write(
            &report_path,
            format!("{}\n", serde_json::to_string_pretty(&report)?),
        )?;
        Ok((report, report_path))
    }

    fn dispatch(&mut self, id: &str) -> Result<ScenarioResult> {
        if id.starts_with("iso.") {
            self.run_isolation(id)
        } else if id.starts_with("legacy.") {
            self.run_legacy(id)
        } else if id.starts_with("modern.") {
            self.run_modern(id)
        } else if id.starts_with("resource.") {
            self.run_resource(id)
        } else if id.starts_with("provider.engine.") {
            self.run_provider_engine(id)
        } else if id.starts_with("provider.") {
            self.run_provider(id)
        } else if id.starts_with("proxy.") {
            self.run_proxy(id)
        } else if id.starts_with("boundary.") {
            self.run_boundary(id)
        } else if id.starts_with("metrics.") {
            self.run_metric(id)
        } else {
            anyhow::bail!("no runner for preregistered scenario {id}")
        }
    }

    fn run_isolation(&mut self, id: &str) -> Result<ScenarioResult> {
        let special_work_root = match id {
            "iso.spaces-path" => self.work_root.join("root with spaces"),
            "iso.unicode-path" => self.work_root.join("røød-東京-🧪"),
            _ => self.work_root.clone(),
        };
        fs::create_dir_all(&special_work_root)?;
        let sandbox = ScenarioSandbox::create(&special_work_root, &self.run_label, id, false)?;
        let detail = match id {
            "iso.fixture-hashes" => json!({"fixtureHashes": self.verification.fixture_hashes}),
            "iso.env-allowlist" => json!({
                "clearedBeforeSpawn": true,
                "keys": sandbox.environment.keys().map(|key| key.to_string_lossy()).collect::<Vec<_>>()
            }),
            "iso.path-containment" => {
                sandbox.verify()?;
                json!({"allSyntheticPathsContained": true})
            }
            "iso.canary-integrity-nondisclosure" | "iso.child-input-real-state-exclusion" => {
                let mut execution = self.execute_mcp(
                    id,
                    McpExecutionConfig {
                        populated: false,
                        fixture_profile: FixtureProfile::Standard,
                        compact: false,
                        init: Init::Legacy,
                        fault_database: false,
                    },
                    |client, _, _| {
                        let value = client
                            .request(json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}))?;
                        Ok(json!({"pingResult": result(&value)?}))
                    },
                )?;
                execution.detail = if id == "iso.canary-integrity-nondisclosure" {
                    json!({
                        "protocolProbe": execution.detail,
                        "canaryOutsideScenarioRoot": true,
                        "canaryBytesUnchanged": true,
                        "absentFromStdoutStderrAndRawExchanges": true,
                        "absentFromEntireScenarioTree": true,
                        "arbitrarySilentReadDetectionClaimed": false
                    })
                } else {
                    json!({
                        "protocolProbe": execution.detail,
                        "childEnvironmentArgumentsAndCwdExcludeInheritedRealState": true,
                        "realStatePathAbsentFromCapturedOutput": true
                    })
                };
                return self.finish_execution(id, execution, false);
            }
            "iso.configured-endpoints-loopback" => {
                sandbox.verify_loopback_configuration()?;
                let mut daemon = self.start_mock_daemon(&sandbox)?;
                probe_mock_daemon(&daemon.url)?;
                shutdown_mock_daemon(&daemon.url)?;
                let status = daemon.child.wait_timeout(Duration::from_secs(5))?;
                if !status.success() {
                    anyhow::bail!("loopback evidence daemon exited unsuccessfully: {status}");
                }
                let records = read_json_lines(&daemon.record_path)?;
                let endpoint_evidence = recorded_loopback_evidence(&records)?;
                json!({
                    "configuredProxyEndpointsLoopback": true,
                    "recordedIntegrationPeerAndLocalLoopback": true,
                    "recordedEndpointEvidence": endpoint_evidence,
                    "osFirewallEnforcementClaimed": false,
                    "arbitrarySocketObservationClaimed": false
                })
            }
            "iso.mock-daemon-raii-cleanup" => {
                let daemon = self.start_mock_daemon(&sandbox)?;
                let address = loopback_address_from_url(&daemon.url)?;
                let pid = daemon.child.id()?;
                drop(daemon);
                if TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_ok() {
                    anyhow::bail!("mock daemon still accepted connections after RAII cleanup");
                }
                json!({
                    "guardDroppedWithoutShutdownRequest": true,
                    "childReaped": true,
                    "listenerClosed": true,
                    "pid": pid
                })
            }
            "iso.posix-path" | "iso.windows-path" => {
                let style = id.trim_start_matches("iso.").trim_end_matches("-path");
                let paths = load_paths(&self.suite_root)?;
                let checked = paths
                    .pure_path_cases
                    .iter()
                    .filter(|case| case.style == style)
                    .map(|case| {
                        Ok(join_pure(&case.style, &case.base, &case.relative)? == case.expected)
                    })
                    .collect::<Result<Vec<_>>>()?;
                if checked.is_empty() || checked.iter().any(|ok| !ok) {
                    anyhow::bail!("pure {style} path cases did not match");
                }
                json!({"style": style, "caseCount": checked.len()})
            }
            "iso.spaces-path" | "iso.unicode-path" => {
                if id == "iso.spaces-path" && !sandbox.root.to_string_lossy().contains(' ') {
                    anyhow::bail!("space path scenario root has no space");
                }
                if id == "iso.unicode-path" && sandbox.root.to_string_lossy().is_ascii() {
                    anyhow::bail!("Unicode path scenario root is ASCII-only");
                }
                let state = build_database(&self.suite_root, &sandbox.db, true)?;
                let mut client =
                    McpClient::spawn(&self.candidate, &sandbox, false, &self.user_state)?;
                client.initialize_legacy()?;
                let response = client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"Unicode café 東京", "project":"", "limit":3}),
                ))?;
                let text = text_content(&response)?;
                let capture = client.shutdown()?;
                self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
                self.verify_capture(
                    &sandbox,
                    &capture.exchanges,
                    &capture.stdout,
                    &capture.stderr,
                )?;
                json!({"fixtureProject": state.project_name, "responseContainsUnicode": text.contains("東京")})
            }
            "iso.two-root-equality" => {
                let first = self.isolation_fingerprint(id, "root with spaces")?;
                let second = self.isolation_fingerprint(id, "røød-東京-🧪")?;
                if first != second {
                    anyhow::bail!("normalized fingerprints differ across roots");
                }
                json!({"normalizedSha256": sha256_bytes(first.as_bytes()), "equal": true})
            }
            "iso.standalone-fixture-independence" => {
                let first = sandbox.artifact_dir.join("standalone-first.sqlite3");
                let second = sandbox.artifact_dir.join("standalone-second.sqlite3");
                let first_state = build_database(&self.suite_root, &first, true)?;
                let second_state = build_database(&self.suite_root, &second, true)?;
                if first_state.generated_message_ids != second_state.generated_message_ids
                    || first_state.generated_timestamp_spellings
                        != second_state.generated_timestamp_spellings
                    || memory_access_count(&first, "01J00000000000000000000001")? != Some(2)
                    || memory_access_count(&second, "01J00000000000000000000001")? != Some(2)
                {
                    anyhow::bail!("standalone fixture construction is not deterministic");
                }
                json!({
                    "productCrateDependencies": 0,
                    "schemaSha256": self.verification.fixture_hashes.get("sqlite-schema.sql"),
                    "fixedMessageIdCount": first_state.generated_message_ids.len(),
                    "logicalEquality": true
                })
            }
            "iso.offline-contract-fixture" => {
                let contract: Value = serde_json::from_slice(&fs::read(
                    self.suite_root
                        .join("contracts/mcp-2026-wire-contract.json"),
                )?)?;
                if contract.get("runtimeNetworkRequired") != Some(&Value::Bool(false))
                    || contract.get("accessedAt").and_then(Value::as_str) != Some("2026-08-05")
                {
                    anyhow::bail!("offline MCP contract stamp differs");
                }
                json!({
                    "runtimeNetworkRequired": false,
                    "accessedAt": "2026-08-05",
                    "contractSha256": self.verification.contract_hashes.get("mcp-2026-wire-contract.json")
                })
            }
            "iso.normalization-pointer-allowlist" => {
                let original = json!({"pid":99,"nested":{"pid":100,"dynamic":7},"items":[1,2,3]});
                let normalized = crate::normalization::normalize_detail(
                    "iso.mock-daemon-raii-cleanup",
                    original,
                )?;
                if normalized.pointer("/pid") != Some(&json!("<PROCESS_ID>"))
                    || normalized.pointer("/nested/pid") != Some(&json!(100))
                    || normalized.pointer("/nested/dynamic") != Some(&json!(7))
                    || normalized.pointer("/items") != Some(&json!([1, 2, 3]))
                {
                    anyhow::bail!("normalization changed an undeclared value or shape");
                }
                json!({"exactPointerOnly":true,"unknownSameNamedKeyPreserved":true,"shapePreserved":true})
            }
            "iso.threshold-bindings" => {
                let missing = UnsupportedEvidence::Wire {
                    methods: Vec::new(),
                    statuses: Vec::new(),
                    response_count: 0,
                };
                if validate_unsupported_evidence(&missing).is_ok() {
                    anyhow::bail!("unsupported result without evidence was accepted");
                }
                json!({
                    "typedThresholdCount": self.verification.bound_threshold_count,
                    "thresholdSha256": self.verification.acceptance_thresholds_sha256,
                    "missingUnsupportedEvidenceRejected": true
                })
            }
            _ => anyhow::bail!("unknown isolation scenario {id}"),
        };
        sandbox.verify()?;
        self.passed(id, detail, "")
    }

    fn isolation_fingerprint(&mut self, id: &str, root_name: &str) -> Result<String> {
        let root = self.work_root.join(root_name);
        fs::create_dir_all(&root)?;
        let sandbox =
            ScenarioSandbox::create(&root, &format!("{}-fingerprint", self.run_label), id, false)?;
        build_database(&self.suite_root, &sandbox.db, true)?;
        let mut client = McpClient::spawn(&self.candidate, &sandbox, false, &self.user_state)?;
        client.initialize_legacy()?;
        client.request(tools_list(2))?;
        let capture = client.shutdown()?;
        self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
        self.verify_capture(
            &sandbox,
            &capture.exchanges,
            &capture.stdout,
            &capture.stderr,
        )?;
        Ok(normalize_transcript(
            &capture.exchanges,
            &FixtureState {
                project_name: "eval-project".into(),
                generated_message_ids: vec![],
                generated_timestamp_spellings: vec![],
            },
        ))
    }

    fn run_legacy(&mut self, id: &str) -> Result<ScenarioResult> {
        let populated = !matches!(
            id,
            "legacy.list-empty" | "legacy.recall-empty" | "legacy.stats-empty-exact"
        );
        let compact = id == "legacy.recall-compact-bytes";
        let init = if id == "legacy.initialize-exact" {
            Init::None
        } else {
            Init::Legacy
        };
        let execution = self.execute_mcp(id, McpExecutionConfig {
            populated,
            fixture_profile: FixtureProfile::Standard,
            compact,
            init,
            fault_database: false,
        }, |client, state, sandbox| {
            let response = match id {
                "legacy.initialize-exact" => client.initialize_legacy()?,
                "legacy.ping" => client.request(json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}))?,
                "legacy.tools-list-exact" | "legacy.tools-list-order" | "legacy.tools-list-required-fields" => {
                    client.request(tools_list(2))?
                }
                "legacy.list-empty" | "legacy.list-populated-group-order" => client.request(tool_call(
                    2,
                    "icm_memory_list_topics",
                    json!({}),
                ))?,
                "legacy.recall-empty" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"does-not-exist", "project":""}),
                ))?,
                "legacy.recall-single-exact" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"SQLite WAL", "project":"", "limit":1}),
                ))?,
                "legacy.recall-multi-order" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"MCP schema", "project":"", "limit":5}),
                ))?,
                "legacy.recall-compact-bytes" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"SQLite WAL", "project":"", "limit":3}),
                ))?,
                "legacy.recall-project-isolation" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"Secret marker", "project":&state.project_name, "limit":10}),
                ))?,
                "legacy.recall-preferences-global" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"concise evidence", "project":"different-project", "limit":10}),
                ))?,
                "legacy.recall-topic-filter" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"permission", "project":"", "topic":"decisions:eval-project", "limit":10}),
                ))?,
                "legacy.recall-keyword-filter" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"Output schemas", "project":"", "keyword":"camelcase", "limit":10}),
                ))?,
                "legacy.recall-access-mutation" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"SQLite WAL", "project":"", "limit":1}),
                ))?,
                "legacy.stats-empty-exact" | "legacy.stats-populated-values" => client.request(tool_call(
                    2,
                    "icm_memory_stats",
                    json!({}),
                ))?,
                "legacy.transcript-start" => client.request(tool_call(
                    2,
                    "icm_transcript_start_session",
                    json!({"agent":"synthetic-new-agent", "project":"eval-project", "metadata":"{\"new\":true}"}),
                ))?,
                "legacy.transcript-record-all-roles" => {
                    let mut last = Value::Null;
                    for (index, role) in ["system", "user", "assistant", "tool"].iter().enumerate() {
                        last = client.request(tool_call(
                            2 + index as u64,
                            "icm_transcript_record",
                            json!({
                                "session_id":"synthetic-session-fixed-001",
                                "role":role,
                                "content":format!("boundary role {role}"),
                                "tool_name": if *role == "tool" { Some("synthetic_tool") } else { None },
                                "tokens": index + 1,
                                "metadata":"{\"boundary\":true}"
                            }),
                        ))?;
                    }
                    last
                }
                "legacy.transcript-search-order" => client.request(tool_call(
                    2,
                    "icm_transcript_search",
                    json!({"query":"SQLite WAL", "project":"eval-project", "limit":10}),
                ))?,
                "legacy.transcript-show-order" => client.request(tool_call(
                    2,
                    "icm_transcript_show",
                    json!({"session_id":"synthetic-session-fixed-001", "limit":10, "offset":0}),
                ))?,
                "legacy.transcript-stats-values" => client.request(tool_call(
                    2,
                    "icm_transcript_stats",
                    json!({}),
                ))?,
                "legacy.feedback-record" => client.request(tool_call(
                    2,
                    "icm_feedback_record",
                    json!({
                        "topic":"routing",
                        "context":"Synthetic new documentation change",
                        "predicted":"database reviewer",
                        "corrected":"documentation reviewer",
                        "reason":"fixture",
                        "source":"cleanroom-evaluator"
                    }),
                ))?,
                "legacy.feedback-search-order" => client.request(tool_call(
                    2,
                    "icm_feedback_search",
                    json!({"query":"documentation reviewer", "topic":"routing", "limit":10}),
                ))?,
                "legacy.feedback-stats-values" => client.request(tool_call(
                    2,
                    "icm_feedback_stats",
                    json!({}),
                ))?,
                "legacy.unknown-tool" => client.request(tool_call(2, "icm_does_not_exist", json!({})))?,
                "legacy.method-not-found" => client.request(json!({"jsonrpc":"2.0","id":2,"method":"does/not/exist","params":{}}))?,
                "legacy.invalid-json" => {
                    let raw = client.send_raw("{not-json", true)?.context("invalid JSON got no response")?;
                    serde_json::from_str(raw.trim_end())?
                }
                "legacy.missing-params" => client.request(json!({"jsonrpc":"2.0","id":2,"method":"tools/call"}))?,
                "legacy.null-id" => client.request(json!({"jsonrpc":"2.0","id":null,"method":"ping","params":{}}))?,
                "legacy.notification-no-response" => {
                    client.notify(json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}))?;
                    return Ok(json!({"notificationResponse": false}));
                }
                _ => anyhow::bail!("unknown legacy scenario {id}"),
            };
            validate_legacy(id, &response, sandbox)?;
            let access_count_after = if id == "legacy.recall-access-mutation" {
                memory_access_count(&sandbox.db, "01J00000000000000000000001")?
            } else {
                None
            };
            Ok(json!({
                "response": response,
                "text": text_content(&response).ok(),
                "fixtureProject": state.project_name,
                "accessCountAfter": access_count_after
            }))
        })?;

        if id == "legacy.recall-access-mutation" {
            let count = execution
                .detail
                .get("accessCountAfter")
                .and_then(Value::as_u64)
                .context("recalled fixture vanished before access mutation check")?;
            if count <= 2 {
                anyhow::bail!("recall did not increment access count: observed {count}");
            }
        }
        self.finish_execution(id, execution, deterministic_legacy(id))
    }

    fn run_modern(&mut self, id: &str) -> Result<ScenarioResult> {
        let suite_root = self.suite_root.clone();
        let design = self.design.clone();
        let thresholds = self.verification.acceptance_thresholds.clone();
        let execution = self.execute_mcp(
            id,
            McpExecutionConfig {
                populated: true,
                fixture_profile: FixtureProfile::Standard,
                compact: false,
                init: Init::None,
                fault_database: false,
            },
            |client, _, _| {
                let response = match id {
                    "modern.lifecycle-2024-complete" => {
                        let initialized = client.request(json!({
                            "jsonrpc":"2.0","id":1,"method":"initialize",
                            "params":{
                                "protocolVersion":"2024-11-05",
                                "capabilities":{},
                                "clientInfo":{"name":"icm-cleanroom-eval","version":"1"}
                            }
                        }))?;
                        client.notify(json!({
                            "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                        }))?;
                        let listed = client.request(tools_list(2))?;
                        json!({"__lifecycleResponses":[initialized,listed]})
                    }
                    "modern.lifecycle-tools-list-before-initialize" => {
                        client.request(tools_list(1))?
                    }
                    "modern.lifecycle-tools-call-before-initialize" => client.request(tool_call(
                        1,
                        "icm_memory_stats",
                        json!({}),
                    ))?,
                    "modern.lifecycle-request-before-initialized" => {
                        client.request(json!({
                            "jsonrpc":"2.0","id":1,"method":"initialize",
                            "params":{
                                "protocolVersion":"2025-11-25",
                                "capabilities":{},
                                "clientInfo":{"name":"icm-cleanroom-eval","version":"1"}
                            }
                        }))?;
                        client.request(tools_list(2))?
                    }
                    "modern.lifecycle-duplicate-initialized" => {
                        client.initialize_modern("2025-11-25")?;
                        client.notify(json!({
                            "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                        }))?;
                        client.request(tools_list(2))?
                    }
                    "modern.lifecycle-second-initialize-era-change" => {
                        client.initialize_modern("2025-11-25")?;
                        client.request(json!({
                            "jsonrpc":"2.0","id":2,"method":"initialize",
                            "params":{
                                "protocolVersion":"2024-11-05",
                                "capabilities":{},
                                "clientInfo":{"name":"icm-cleanroom-eval","version":"1"}
                            }
                        }))?
                    }
                    "modern.lifecycle-initialized-before-initialize" => {
                        client.notify(json!({
                            "jsonrpc":"2.0","method":"notifications/initialized","params":{}
                        }))?;
                        client.request(json!({
                            "jsonrpc":"2.0","id":1,"method":"initialize",
                            "params":{
                                "protocolVersion":"2025-11-25",
                                "capabilities":{},
                                "clientInfo":{"name":"icm-cleanroom-eval","version":"1"}
                            }
                        }))?
                    }
                    "modern.2025-06-initialize" => client.initialize_modern("2025-06-18")?,
                    "modern.2025-11-initialize" => client.initialize_modern("2025-11-25")?,
                    "modern.initialize-invalid-version" => client.initialize_modern("2099-01-01")?,
                    "modern.initialize-malformed-capabilities" => client.request(json!({
                        "jsonrpc":"2.0", "id":1, "method":"initialize",
                        "params":{"protocolVersion":"2025-11-25","capabilities":[],"clientInfo":{"name":"eval","version":"1"}}
                    }))?,
                    "modern.initialize-malformed-client-info" => client.request(json!({
                        "jsonrpc":"2.0", "id":1, "method":"initialize",
                        "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":"invalid"}
                    }))?,
                    "modern.reject-switch-to-2026-after-initialize" => {
                        client.initialize_modern("2025-11-25")?;
                        client.request_2026(2, "server/discover", json!({}))?
                    }
                    "modern.2026-discover" => {
                        client.request_2026(1, "server/discover", json!({}))?
                    }
                    "modern.2026-client-info-optional" => client
                        .request_2026_without_client_info(1, "server/discover", json!({}))?,
                    "modern.2026-missing-meta" => {
                        client.request_2026(1, "server/discover", json!({}))?;
                        client.request(json!({
                            "jsonrpc":"2.0", "id":2, "method":"server/discover", "params":{}
                        }))?
                    }
                    "modern.2026-malformed-meta" => client.request(json!({
                        "jsonrpc":"2.0", "id":1, "method":"server/discover",
                        "params":{"_meta":[]}
                    }))?,
                    "modern.2026-unsupported-version" => {
                        let mut request = modern_request(1, "server/discover", json!({}), true);
                        request["params"]["_meta"][META_PROTOCOL_VERSION] = json!("2099-01-01");
                        client.request(request)?
                    }
                    "modern.reject-switch-to-initialize-after-discover" => {
                        client.request_2026(1, "server/discover", json!({}))?;
                        client.initialize_modern("2025-11-25")?
                    }
                    "modern.2025-06-tools-list-projection" => {
                        client.initialize_modern("2025-06-18")?;
                        client.request(tools_list(2))?
                    }
                    "modern.2025-11-tools-list-projection" => {
                        client.initialize_modern("2025-11-25")?;
                        client.request(tools_list(2))?
                    }
                    "modern.2025-06-structured-recall" => {
                        client.initialize_modern("2025-06-18")?;
                        client.request(tool_call(
                            2,
                            "icm_memory_recall",
                            json!({"query":"SQLite WAL","project":"","limit":3}),
                        ))?
                    }
                    "modern.2025-11-structured-recall" => {
                        client.initialize_modern("2025-11-25")?;
                        client.request(tool_call(
                            2,
                            "icm_memory_recall",
                            json!({"query":"SQLite WAL","project":"","limit":3}),
                        ))?
                    }
                    "modern.2025-resources-list-projection" => {
                        client.initialize_modern("2025-11-25")?;
                        client.request(json!({
                            "jsonrpc":"2.0", "id":2, "method":"resources/list", "params":{}
                        }))?
                    }
                    "modern.2025-resources-read-projection" => {
                        client.initialize_modern("2025-11-25")?;
                        client.request(json!({
                            "jsonrpc":"2.0", "id":2, "method":"resources/read",
                            "params":{"uri":"icm://active-project/context"}
                        }))?
                    }
                    "modern.2026-missing-protocol-version" => {
                        let mut request = modern_request(1, "server/discover", json!({}), true);
                        request["params"]["_meta"]
                            .as_object_mut()
                            .context("generated metadata is not an object")?
                            .remove(META_PROTOCOL_VERSION);
                        client.request(request)?
                    }
                    "modern.2026-missing-client-capabilities" => {
                        let mut request = modern_request(1, "server/discover", json!({}), true);
                        request["params"]["_meta"]
                            .as_object_mut()
                            .context("generated metadata is not an object")?
                            .remove(META_CLIENT_CAPABILITIES);
                        client.request(request)?
                    }
                    "modern.2026-malformed-client-capabilities" => {
                        let mut request = modern_request(1, "server/discover", json!({}), true);
                        request["params"]["_meta"][META_CLIENT_CAPABILITIES] = json!([]);
                        client.request(request)?
                    }
                    "modern.2026-malformed-client-info" => {
                        let mut request = modern_request(1, "server/discover", json!({}), true);
                        request["params"]["_meta"][META_CLIENT_INFO] = json!("invalid");
                        client.request(request)?
                    }
                    "modern.2026-misplaced-top-level-meta" => {
                        let valid = modern_request(1, "server/discover", json!({}), true);
                        client.request(json!({
                            "jsonrpc":"2.0", "id":1, "method":"server/discover",
                            "params":{}, "_meta":valid["params"]["_meta"].clone()
                        }))?
                    }
                    "modern.2026-valid-extension-key" => {
                        let mut request = modern_request(1, "server/discover", json!({}), true);
                        request["params"]["_meta"]["com.example/evaluation"] =
                            json!({"opaque":true});
                        client.request(request)?
                    }
                    "modern.2026-invalid-meta-key" => {
                        let mut request = modern_request(1, "server/discover", json!({}), true);
                        request["params"]["_meta"][INVALID_META_KEY_FIXTURE] = json!({});
                        client.request(request)?
                    }
                    "modern.tools-list-order"
                    | "modern.tools-list-annotations"
                    | "modern.tools-list-output-schemas"
                    | "modern.tools-list-cache-metadata"
                    | "modern.tools-list-required-fields"
                    | "modern.tools-list-closed-schemas"
                    | "modern.annotation-memory-store-destructive"
                    | "modern.annotation-memory-recall-destructive"
                    | "modern.annotation-read-only-consistency"
                    | "modern.annotation-idempotence-consistency"
                    | "modern.annotation-open-world-learn-only" => {
                        client.request_2026(1, "tools/list", json!({}))?
                    }
                    "modern.structured-memory-recall"
                    | "modern.concise-text-no-duplication" => modern_tool_call(
                        client,
                        1,
                        "icm_memory_recall",
                        json!({"query":"SQLite WAL","project":"","limit":3}),
                    )?,
                    "modern.structured-memory-list" => {
                        modern_tool_call(client, 1, "icm_memory_list_topics", json!({}))?
                    }
                    "modern.structured-memory-stats" => {
                        modern_tool_call(client, 1, "icm_memory_stats", json!({}))?
                    }
                    "modern.structured-transcript-start" => modern_tool_call(
                        client,
                        1,
                        "icm_transcript_start_session",
                        json!({"agent":"modern-eval","project":"eval-project"}),
                    )?,
                    "modern.structured-transcript-record" => modern_tool_call(
                        client,
                        1,
                        "icm_transcript_record",
                        json!({"session_id":"synthetic-session-fixed-001","role":"user","content":"modern record"}),
                    )?,
                    "modern.structured-transcript-search" => modern_tool_call(
                        client,
                        1,
                        "icm_transcript_search",
                        json!({"query":"SQLite WAL","project":"eval-project","limit":10}),
                    )?,
                    "modern.structured-transcript-show" => modern_tool_call(
                        client,
                        1,
                        "icm_transcript_show",
                        json!({"session_id":"synthetic-session-fixed-001"}),
                    )?,
                    "modern.structured-transcript-stats" => {
                        modern_tool_call(client, 1, "icm_transcript_stats", json!({}))?
                    }
                    "modern.structured-feedback-record" => modern_tool_call(
                        client,
                        1,
                        "icm_feedback_record",
                        json!({"topic":"modern","context":"synthetic","predicted":"a","corrected":"b","reason":null,"source":"eval"}),
                    )?,
                    "modern.structured-feedback-search" => modern_tool_call(
                        client,
                        1,
                        "icm_feedback_search",
                        json!({"query":"documentation reviewer","limit":10}),
                    )?,
                    "modern.structured-feedback-stats" => {
                        modern_tool_call(client, 1, "icm_feedback_stats", json!({}))?
                    }
                    "modern.schema-valid-real-emissions" => {
                        let requests = modern_emission_requests();
                        let mut responses = Vec::new();
                        for (index, (tool, arguments)) in requests.into_iter().enumerate() {
                            let response = modern_tool_call(
                                client,
                                index as u64 + 1,
                                tool,
                                arguments,
                            )?;
                            let modern_shape = response
                                .pointer("/result/resultType")
                                .and_then(Value::as_str)
                                == Some("complete")
                                && response
                                    .pointer("/result/structuredContent")
                                    .is_some();
                            responses.push(response);
                            if index == 0 && !modern_shape {
                                break;
                            }
                        }
                        json!({"__evaluationResponses":responses})
                    }
                    _ => anyhow::bail!("unknown modern scenario {id}"),
                };
                let mut detail = validate_modern(&suite_root, &design, id, &response)?;
                if id == "modern.structured-memory-recall" {
                    let raw_bytes = client
                        .exchanges
                        .last()
                        .and_then(|exchange| exchange.response.as_ref())
                        .context("modern recall raw response missing")?
                        .len();
                    if raw_bytes > thresholds.modern_recall_max_wire_bytes {
                        anyhow::bail!(
                            "modern recall raw frame {raw_bytes} exceeds bound {}",
                            thresholds.modern_recall_max_wire_bytes
                        );
                    }
                    detail["wireBytes"] = json!(raw_bytes);
                }
                Ok(detail)
            },
        )?;
        let supported = execution
            .detail
            .get("supported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if supported {
            self.finish_execution(id, execution, false)
        } else {
            self.finish_unsupported(id, execution)
        }
    }

    fn run_resource(&mut self, id: &str) -> Result<ScenarioResult> {
        let populated = id != "resource.empty";
        let thresholds = self.verification.acceptance_thresholds.clone();
        if matches!(
            id,
            "resource.internal-failure"
                | "resource.templates-method-not-found"
                | "resource.snapshot-concurrency"
        ) {
            let probe = self.execute_mcp(
                id,
                McpExecutionConfig {
                    populated: true,
                    fixture_profile: FixtureProfile::Resource,
                    compact: false,
                    init: Init::None,
                    fault_database: false,
                },
                |client, _, _| {
                    let response = client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/context"}),
                    )?;
                    validate_resource("resource.read-values", &response, &thresholds)
                },
            )?;
            if !probe
                .detail
                .get("supported")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return self.finish_unsupported(id, probe);
            }
            if id == "resource.snapshot-concurrency" {
                return self.run_resource_snapshot(id);
            }
        }
        let execution = self.execute_mcp(
            id,
            McpExecutionConfig {
                populated,
                fixture_profile: if id == "resource.empty" {
                    FixtureProfile::Standard
                } else if matches!(
                    id,
                    "resource.token-truncation"
                        | "resource.bounded-read"
                        | "resource.no-force-first"
                        | "resource.row-limit"
                        | "resource.field-limit"
                ) {
                    FixtureProfile::ResourceLarge
                } else {
                    FixtureProfile::Resource
                },
                compact: false,
                init: Init::None,
                fault_database: id == "resource.internal-failure",
            },
            |client, _, sandbox| {
                let response = match id {
                    "resource.list-single-fixed-uri" | "resource.descriptor-exact" => {
                        client.request_2026(1, "resources/list", json!({}))?
                    }
                    "resource.no-templates-capability" => {
                        client.request_2026(1, "server/discover", json!({}))?
                    }
                    "resource.templates-method-not-found" => {
                        client.request_2026(1, "resources/templates/list", json!({}))?
                    }
                    "resource.read-values"
                    | "resource.empty"
                    | "resource.excludes-preferences"
                    | "resource.excludes-other-project"
                    | "resource.exact-project-topic-scope"
                    | "resource.bounded-read"
                    | "resource.cache-metadata"
                    | "resource.internal-failure"
                    | "resource.includes-context-topic"
                    | "resource.includes-contexte-topic"
                    | "resource.includes-decisions-topic"
                    | "resource.excludes-bare-project"
                    | "resource.excludes-prefix-subtopic"
                    | "resource.excludes-suffix-alias"
                    | "resource.excludes-errors-resolved"
                    | "resource.budget-accounting-exact"
                    | "resource.wire-byte-budget"
                    | "resource.no-force-first"
                    | "resource.row-limit"
                    | "resource.field-limit"
                    | "resource.read-only-access-count"
                    | "resource.prompt-injection-sanitized" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/context"}),
                    )?,
                    "resource.malformed-uri" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"not a valid uri"}),
                    )?,
                    "resource.unknown-uri" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/unknown"}),
                    )?,
                    "resource.uri-trailing-slash" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/context/"}),
                    )?,
                    "resource.uri-query" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/context?topic=x"}),
                    )?,
                    "resource.uri-fragment" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/context#fragment"}),
                    )?,
                    "resource.uri-user-info" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://user@active-project/context"}),
                    )?,
                    "resource.uri-authority-case" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://ACTIVE-PROJECT/context"}),
                    )?,
                    "resource.caller-max-tokens-rejected" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/context","maxTokens":32}),
                    )?,
                    "resource.token-truncation" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/context"}),
                    )?,
                    "resource.error-data-sanitized" => client.request_2026(
                        1,
                        "resources/read",
                        json!({"uri":"icm://active-project/unknown"}),
                    )?,
                    _ => anyhow::bail!("unknown resource scenario {id}"),
                };
                let mut detail = validate_resource(id, &response, &thresholds)?;
                if id == "resource.read-only-access-count"
                    && detail.get("supported").and_then(Value::as_bool) == Some(true)
                {
                    let count = memory_access_count(&sandbox.db, "01J00000000000000000000001")?;
                    if count != Some(2) {
                        anyhow::bail!("resource read mutated memory access count: {count:?}");
                    }
                    detail["accessCountBefore"] = json!(2);
                    detail["accessCountAfter"] = json!(count);
                }
                Ok(detail)
            },
        )?;
        let supported = execution
            .detail
            .get("supported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if supported {
            self.finish_execution(id, execution, false)
        } else {
            self.finish_unsupported(id, execution)
        }
    }

    fn run_resource_snapshot(&mut self, id: &str) -> Result<ScenarioResult> {
        let sandbox = ScenarioSandbox::create(&self.work_root, &self.run_label, id, false)?;
        let fixture = build_database(&self.suite_root, &sandbox.db, true)?;
        augment_resource_database(&sandbox.db, false)?;
        let pre_response = self.capture_resource_response(id, &sandbox)?;
        let pre_text = resource_text(&pre_response)?.to_owned();

        let ready_path = sandbox.artifact_dir.join("snapshot.ready");
        let release_path = sandbox.artifact_dir.join("snapshot.release");
        let response_path = sandbox.artifact_dir.join("snapshot-response.json");
        let event_path = sandbox.artifact_dir.join("snapshot-events.jsonl");
        let writer_db = sandbox.db.clone();
        let writer_ready = ready_path.clone();
        let writer_release = release_path.clone();
        let writer = thread::spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(8);
            while !writer_ready.is_file() {
                if Instant::now() >= deadline {
                    anyhow::bail!("support hook never exposed the controlled read barrier");
                }
                thread::sleep(Duration::from_millis(20));
            }
            commit_resource_snapshot_writer(&writer_db)?;
            fs::write(&writer_release, b"evaluator-writer-committed\n")?;
            Ok(())
        });
        let support_result = self.run_evaluator_support(
            id,
            &sandbox,
            &[
                "resource-snapshot".to_owned(),
                "--db".to_owned(),
                sandbox.db.to_string_lossy().into_owned(),
                "--ready-file".to_owned(),
                ready_path.to_string_lossy().into_owned(),
                "--release-file".to_owned(),
                release_path.to_string_lossy().into_owned(),
                "--response-file".to_owned(),
                response_path.to_string_lossy().into_owned(),
                "--event-journal".to_owned(),
                event_path.to_string_lossy().into_owned(),
            ],
        );
        let writer_result = writer
            .join()
            .map_err(|_| anyhow::anyhow!("resource snapshot writer thread panicked"))?;
        writer_result?;
        let _support_stdout = support_result?;

        let post_response = self.capture_resource_response(id, &sandbox)?;
        let post_text = resource_text(&post_response)?.to_owned();
        if pre_text == post_text || !post_text.contains("RESOURCE-SNAPSHOT-POST-STATE-MARKER") {
            anyhow::bail!("evaluator-controlled writer did not produce a distinct post state");
        }
        let response_bytes = fs::read(&response_path)
            .context("resource support did not write the raw response artifact")?;
        let support_response: Value = serde_json::from_slice(&response_bytes)
            .context("resource support response artifact is not JSON")?;
        let support_text = resource_text(&support_response)?;
        let observed_state = if support_text == pre_text {
            "pre"
        } else if support_text == post_text {
            "post"
        } else {
            anyhow::bail!("concurrent resource read exposed a mixed or fabricated state");
        };
        let event_bytes =
            fs::read(&event_path).context("resource support did not write its event journal")?;
        let events = validate_support_event_journal(
            &event_bytes,
            &[
                "read-start",
                "snapshot-acquired",
                "barrier-ready",
                "barrier-released",
                "read-complete",
            ],
            Some(("read-complete", sha256_bytes(&response_bytes))),
        )?;
        sandbox.verify()?;
        self.passed(
            id,
            json!({
                "supported": true,
                "fixtureProject": fixture.project_name,
                "observedAtomicState": observed_state,
                "preTextSha256": sha256_bytes(pre_text.as_bytes()),
                "postTextSha256": sha256_bytes(post_text.as_bytes()),
                "responseArtifactSha256": sha256_bytes(&response_bytes),
                "eventJournalSha256": sha256_bytes(&event_bytes),
                "eventCount": events.len()
            }),
            "",
        )
    }

    fn capture_resource_response(&mut self, id: &str, sandbox: &ScenarioSandbox) -> Result<Value> {
        let mut client = McpClient::spawn(&self.candidate, sandbox, false, &self.user_state)?;
        let response = client.request_2026(
            1,
            "resources/read",
            json!({"uri":"icm://active-project/context"}),
        )?;
        let detail = validate_resource(
            "resource.read-values",
            &response,
            &self.verification.acceptance_thresholds,
        )?;
        if detail.get("supported").and_then(Value::as_bool) != Some(true) {
            anyhow::bail!("snapshot control read unexpectedly lacks resource support");
        }
        let capture = client.shutdown()?;
        self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
        self.verify_capture(
            sandbox,
            &capture.exchanges,
            &capture.stdout,
            &capture.stderr,
        )?;
        Ok(response)
    }

    fn run_provider(&mut self, id: &str) -> Result<ScenarioResult> {
        let mut parts = id.splitn(3, '.');
        let _prefix = parts.next();
        let provider_id = parts
            .next()
            .context("provider scenario missing provider ID")?;
        let case_id = parts.next().context("provider scenario missing case ID")?;
        let fixture = load_providers(&self.suite_root)?;
        let provider = fixture
            .providers
            .iter()
            .find(|provider| provider.id == provider_id)
            .with_context(|| format!("no provider fixture for {provider_id}"))?;
        let probe_sandbox = ScenarioSandbox::create(
            &self.work_root,
            &self.run_label,
            &format!("{id}.probe"),
            false,
        )?;
        let help =
            self.run_candidate_command(id, &probe_sandbox, &["provider".into(), "--help".into()])?;
        if !help.status_success {
            probe_sandbox.verify()?;
            let execution = Execution {
                detail: json!({
                    "supported": false,
                    "probeExitCode": help.exit_code,
                    "probeStdout": help.stdout,
                    "probeStderr": help.stderr
                }),
                transcript: help.transcript.clone(),
                unsupported_evidence: cli_unsupported_evidence(&help, &["provider", "--help"]),
            };
            return self.finish_unsupported(id, execution);
        }
        let mut scope_results = Vec::new();
        for scope in &provider.scopes {
            scope_results.push(self.run_provider_scope(id, case_id, provider, scope, &fixture)?);
        }
        self.passed(
            id,
            json!({
                "supported": true,
                "provider": provider_id,
                "case": case_id,
                "scopes": scope_results,
                "doctorExercised": case_id == "exact-path-and-scope"
            }),
            &help.transcript,
        )
    }

    fn run_provider_scope(
        &mut self,
        id: &str,
        case_id: &str,
        provider: &ProviderCase,
        scope: &ProviderScopeFixture,
        fixture: &ProviderFixture,
    ) -> Result<Value> {
        let scoped_id = format!("{id}.{}", scope.scope);
        let sandbox = ScenarioSandbox::create(&self.work_root, &self.run_label, &scoped_id, false)?;
        let document_paths = provider_document_paths(&sandbox, scope)?;
        for (document, path) in scope.documents.iter().zip(&document_paths) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &document.initial)?;
        }
        prepare_provider_adversary(case_id, &provider.id, scope, &document_paths)?;
        #[cfg(windows)]
        if case_id == "symlink-reparse-zero-write" {
            use std::os::windows::fs::MetadataExt;

            let link_directory = document_paths
                .first()
                .and_then(|path| path.parent())
                .context("provider reparse fixture has no parent directory")?;
            let event_path = sandbox.artifact_dir.join("provider-reparse-events.jsonl");
            let support_stdout = self.run_evaluator_support(
                id,
                &sandbox,
                &[
                    "provider-reparse".to_owned(),
                    "--link-directory".to_owned(),
                    link_directory.to_string_lossy().into_owned(),
                    "--event-journal".to_owned(),
                    event_path.to_string_lossy().into_owned(),
                ],
            )?;
            let attributes = fs::metadata(link_directory)?.file_attributes();
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                anyhow::bail!("Windows provider fixture lacks a real reparse-point attribute");
            }
            let event_bytes = fs::read(&event_path)?;
            validate_support_event_journal(
                &event_bytes,
                &["source-moved", "junction-created", "metadata-observed"],
                None,
            )?;
            let _ = support_stdout;
        }
        let mut watched_paths = document_paths.clone();
        let mut before = read_document_set(scope, &document_paths)?;
        let mut watched_before = read_path_set(&watched_paths)?;
        let manifest_path = provider_manifest_path(&sandbox, fixture)?;
        let manifest_before = fs::read(&manifest_path).ok();

        let mut commands: Vec<(&str, bool)> = match case_id {
            "explicit-opt-in" => Vec::new(),
            "exact-path-and-scope" => vec![("doctor", true), ("trust", true)],
            "idempotent-reapply" => vec![("trust", true), ("trust", true)],
            "strip-owned-values-only" => vec![("trust", true), ("strip", true)],
            "uninstall-owned-values-only" => vec![("trust", true), ("uninstall", true)],
            "shadowing-fails-closed" => {
                vec![("doctor", true), ("trust", scope.scope == "project-local")]
            }
            "normalization-collision-fails-closed" | "ambiguous-path-zero-write" => {
                vec![("doctor", true), ("trust", false)]
            }
            "external-equal-adopted-not-owned" => {
                vec![("doctor", true), ("trust", true)]
            }
            "malformed-config-zero-write"
            | "unknown-dialect-zero-write"
            | "symlink-reparse-zero-write" => vec![("trust", false)],
            "exact-registration-syntax"
            | "exact-trust-syntax"
            | "apply-preserves-unrelated-bytes"
            | "deny-confirm-ask-monotone"
            | "exactly-two-tools"
            | "no-server-wildcard"
            | "permissions-preserved"
            | "provenance-after-each-mutation" => vec![("trust", true)],
            other => anyhow::bail!("unknown provider case {other}"),
        };

        let mut command_results = Vec::new();
        let mut server_id = None;
        let mut first_apply = None;
        for (index, (operation, expected_success)) in commands.drain(..).enumerate() {
            let arguments = if operation == "uninstall" {
                vec![
                    "uninstall".to_owned(),
                    "--yes".to_owned(),
                    "--no-backup".to_owned(),
                ]
            } else {
                let mut arguments = vec![
                    "provider".to_owned(),
                    operation.to_owned(),
                    "--provider".to_owned(),
                    provider.id.clone(),
                    "--scope".to_owned(),
                    scope.scope.clone(),
                ];
                if operation != "doctor" {
                    arguments.push("--yes".to_owned());
                }
                arguments
            };
            let capture = self.run_candidate_command(id, &sandbox, &arguments)?;
            if capture.status_success != expected_success {
                anyhow::bail!(
                    "provider {} {} {} success={} expected={expected_success}: {}",
                    provider.id,
                    scope.scope,
                    operation,
                    capture.status_success,
                    capture.stderr
                );
            }
            let mut canonical_stdout_sha256 = sha256_bytes(capture.stdout.as_bytes());
            if expected_success && operation != "uninstall" {
                let plan = parse_provider_plan(&capture.raw_stdout)?;
                validate_provider_plan(&plan, provider, scope, &document_paths, fixture, &sandbox)?;
                let observed = plan
                    .get("serverId")
                    .and_then(Value::as_str)
                    .context("resolved plan serverId is not a string")?
                    .to_owned();
                canonical_stdout_sha256 =
                    canonical_provider_plan_sha256(&plan, &observed, &sandbox)?;
                if server_id.as_ref().is_some_and(|prior| prior != &observed) {
                    anyhow::bail!("installation-scoped serverId changed within one provider plan");
                }
                server_id = Some(observed);
                if operation == "doctor"
                    && matches!(
                        case_id,
                        "external-equal-adopted-not-owned"
                            | "shadowing-fails-closed"
                            | "normalization-collision-fails-closed"
                            | "ambiguous-path-zero-write"
                    )
                {
                    let extra_paths = seed_dynamic_provider_adversary(
                        case_id,
                        provider,
                        scope,
                        &sandbox,
                        server_id.as_deref().expect("server id assigned above"),
                        &document_paths,
                        fixture,
                    )?;
                    watched_paths.extend(extra_paths);
                    watched_paths.sort();
                    watched_paths.dedup();
                    before = read_document_set(scope, &document_paths)?;
                    watched_before = read_path_set(&watched_paths)?;
                }
            }
            if case_id == "idempotent-reapply" && operation == "trust" {
                let current = read_document_set(scope, &document_paths)?;
                if index == 0 {
                    first_apply = Some(current);
                } else if first_apply.as_ref() != Some(&current) {
                    anyhow::bail!("provider reapply changed document bytes");
                }
            }
            command_results.push(json!({
                "operation": operation,
                "arguments": arguments,
                "exitCode": capture.exit_code,
                "stdoutSha256": canonical_stdout_sha256,
                "stderr": capture.stderr
            }));
        }

        let after = read_document_set(scope, &document_paths)?;
        let watched_after = read_path_set(&watched_paths)?;
        let manifest_after = fs::read(&manifest_path).ok();
        if after.values().any(|bytes| {
            !matches!(case_id, "malformed-config-zero-write")
                && !String::from_utf8_lossy(bytes).contains("unchanged")
        }) {
            anyhow::bail!("provider mutation removed an unrelated sentinel");
        }
        let zero_write = case_id == "explicit-opt-in"
            || (case_id == "shadowing-fails-closed" && scope.scope == "user")
            || matches!(
                case_id,
                "normalization-collision-fails-closed"
                    | "malformed-config-zero-write"
                    | "unknown-dialect-zero-write"
                    | "ambiguous-path-zero-write"
                    | "symlink-reparse-zero-write"
            );
        if zero_write
            && (after != before
                || watched_after != watched_before
                || manifest_after != manifest_before)
        {
            anyhow::bail!("fail-closed provider case performed a target or manifest write");
        }

        if let Some(server_id) = server_id.as_deref() {
            match case_id {
                "strip-owned-values-only" | "uninstall-owned-values-only" => {
                    validate_provider_stripped(
                        provider,
                        scope,
                        &document_paths,
                        server_id,
                        fixture,
                    )?;
                }
                _ if !zero_write => {
                    validate_provider_trusted(
                        provider,
                        scope,
                        &document_paths,
                        server_id,
                        fixture,
                    )?;
                }
                _ => {}
            }
        }

        let manifest = manifest_after
            .as_deref()
            .map(serde_json::from_slice::<Value>)
            .transpose()?;
        if matches!(
            case_id,
            "provenance-after-each-mutation"
                | "strip-owned-values-only"
                | "uninstall-owned-values-only"
                | "external-equal-adopted-not-owned"
        ) {
            validate_manifest(
                manifest
                    .as_ref()
                    .context("production-default install manifest absent")?,
                &provider.id,
                &scope.scope,
                &document_paths,
                &fixture.manifest_schema,
                matches!(case_id, "external-equal-adopted-not-owned"),
            )?;
        }
        sandbox.verify()?;
        Ok(json!({
            "scope": scope.scope,
            "surface": scope.surface,
            "dialect": scope.dialect,
            "documentHashesBefore": hash_document_set(&before),
            "documentHashesAfter": hash_document_set(&after),
            "manifestPath": normalize_sandbox_path(&manifest_path, &sandbox),
            "manifestSha256": manifest_after.as_deref().map(sha256_bytes),
            "serverId": server_id,
            "commands": command_results
        }))
    }

    fn run_provider_engine(&mut self, id: &str) -> Result<ScenarioResult> {
        let sandbox = ScenarioSandbox::create(&self.work_root, &self.run_label, id, false)?;
        let help =
            self.run_candidate_command(id, &sandbox, &["provider".into(), "--help".into()])?;
        if !help.status_success {
            sandbox.verify()?;
            return self.finish_unsupported(
                id,
                Execution {
                    detail: json!({
                        "supported":false,
                        "reason":"provider-engine-production-surface-absent",
                        "probeExitCode":help.exit_code,
                        "probeStdout":help.stdout,
                        "probeStderr":help.stderr
                    }),
                    transcript: help.transcript.clone(),
                    unsupported_evidence: cli_unsupported_evidence(&help, &["provider", "--help"]),
                },
            );
        }
        let world = sandbox.artifact_dir.join("provider-engine-world");
        fs::create_dir_all(&world)?;
        let target_a = world.join("target-a.json");
        let target_b = world.join("target-b.json");
        let manifest_path = world.join("install-manifest.json");
        fs::write(
            &target_a,
            b"{\"sentinel\":\"target-a-unchanged\",\"ownedRules\":[],\"externalRules\":[]}",
        )?;
        fs::write(
            &target_b,
            b"{\"sentinel\":\"target-b-unchanged\",\"ownedRules\":[],\"externalRules\":[]}",
        )?;
        let manifest_seed = if id == "provider.engine.schema1-migration-legacy-unproven" {
            json!({"version":1,"legacyRules":[{"rule":"legacy-equal","provenOwned":false}]})
        } else if id == "provider.engine.newer-manifest-read-only" {
            json!({"version":999,"futureSentinel":"newer-manifest-unchanged"})
        } else {
            json!({"version":2,"providerOwnership":[]})
        };
        fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest_seed)?)?;
        if id == "provider.engine.orphan-temp-owned-only" {
            fs::write(world.join(".icm-owned-transaction.tmp"), b"owned-temp")?;
            fs::write(world.join("user-unowned.tmp"), b"unowned-temp-unchanged")?;
        }
        let before = hash_regular_files(&world)?;
        let event_path = sandbox.artifact_dir.join("provider-engine-events.jsonl");
        let _output = self.run_evaluator_support(
            id,
            &sandbox,
            &[
                "provider-engine".to_owned(),
                "--case".to_owned(),
                id.to_owned(),
                "--world".to_owned(),
                world.to_string_lossy().into_owned(),
                "--event-journal".to_owned(),
                event_path.to_string_lossy().into_owned(),
            ],
        )?;
        let after = hash_regular_files(&world)?;
        let event_bytes = fs::read(&event_path)
            .context("provider engine support did not write an event journal")?;
        let events = validate_provider_engine_case(id, &world, &before, &after, &event_bytes)?;
        sandbox.verify()?;
        self.passed(
            id,
            json!({
                "supported":true,
                "filesBefore":before,
                "filesAfter":after,
                "eventCount":events.len(),
                "eventJournalSha256":sha256_bytes(&event_bytes)
            }),
            "",
        )
    }

    fn run_proxy(&mut self, id: &str) -> Result<ScenarioResult> {
        let mut sandbox = ScenarioSandbox::create(&self.work_root, &self.run_label, id, false)?;
        let help = self.run_candidate_command(id, &sandbox, &["proxy".into(), "--help".into()])?;
        if !help.status_success {
            sandbox.verify()?;
            let execution = Execution {
                detail: json!({
                    "supported": false,
                    "probeExitCode": help.exit_code,
                    "probeStdout": help.stdout,
                    "probeStderr": help.stderr,
                    "baselineProof": id == "proxy.unsupported-baseline-proof"
                }),
                transcript: help.transcript.clone(),
                unsupported_evidence: cli_unsupported_evidence(&help, &["proxy", "--help"]),
            };
            if id == "proxy.unsupported-baseline-proof" {
                return self.finish_execution(id, execution, false);
            }
            return self.finish_unsupported(id, execution);
        }
        if id == "proxy.unsupported-baseline-proof" {
            return self.passed(
                id,
                json!({"supported": true, "note":"candidate support does not erase recorded baseline proof"}),
                &help.transcript,
            );
        }

        if matches!(
            id,
            "proxy.real-daemon-tools-list"
                | "proxy.real-daemon-tool-call"
                | "proxy.daemon-one-store-model"
                | "proxy.real-daemon-cleanup"
        ) {
            return self.run_real_daemon_proxy(id, &sandbox);
        }

        if matches!(
            id,
            "proxy.proxy-zero-store-model" | "proxy.dns-rebinding-target-pin"
        ) {
            return self.run_proxy_internal_observation(id, &sandbox);
        }

        if matches!(
            id,
            "proxy.userinfo-fragment-rejected" | "proxy.non-loopback-rejected"
        ) {
            return self.run_proxy_rejected_endpoint(id, &sandbox);
        }

        if id == "proxy.connection-failure" {
            let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
            let address = listener.local_addr()?;
            drop(listener);
            let url = format!("http://{address}/");
            let mut client = McpClient::spawn_with_args(
                &self.candidate,
                &sandbox,
                &["proxy".into(), "--url".into(), url],
                &self.user_state,
            )?;
            let response = client.request(tools_list(1))?;
            if response.get("error").is_none()
                && response.pointer("/result/isError") != Some(&Value::Bool(true))
            {
                anyhow::bail!("proxy connection failure did not propagate an error");
            }
            let capture = client.shutdown()?;
            self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
            self.verify_capture(
                &sandbox,
                &capture.exchanges,
                &capture.stdout,
                &capture.stderr,
            )?;
            return self.passed(
                id,
                json!({"supported":true,"connectionFailurePropagated":true}),
                &normalize_transcript(&capture.exchanges, &empty_fixture_state()),
            );
        }

        let daemon_mode = match id {
            "proxy.redirect-rejected" => "redirect",
            "proxy.bad-content-type" => "bad-content-type",
            "proxy.oversized-response" => "oversized-response",
            "proxy.invalid-utf8-response" => "invalid-utf8",
            "proxy.sse-response-rejected" => "sse",
            "proxy.truncated-response" => "truncated",
            "proxy.request-timeout" => "timeout",
            "proxy.response-id-mismatch" => "id-mismatch",
            "proxy.no-automatic-retry" | "proxy.credential-redaction" => "no-retry",
            "proxy.legacy-session-continuity" => "legacy-session",
            "proxy.hop-by-hop-headers" => "hop-by-hop-response",
            "proxy.daemon-disappearance" => "disappear",
            _ => "normal",
        };
        let ipv6 = id == "proxy.ipv6-loopback";
        let mut daemon = self.start_mock_daemon_mode(&sandbox, daemon_mode, ipv6)?;
        let mut url = daemon.url.clone();
        let mut token_file = None;
        let mut compact = false;
        match id {
            "proxy.trailing-slash-url" => {}
            "proxy.base-path-url" => url.push_str("base/path/"),
            "proxy.compact-query" => compact = true,
            "proxy.bearer-auth" | "proxy.token-file-auth" | "proxy.credential-source-conflict" => {
                let path = sandbox.artifact_dir.join("proxy-token.txt");
                fs::write(&path, "synthetic-token-001\n")?;
                token_file = Some(path);
            }
            "proxy.http-error-propagation" => url.push_str("force-error/"),
            "proxy.token-env-auth" | "proxy.credential-redaction" => {
                sandbox.environment.insert(
                    std::ffi::OsString::from("ICM_PROXY_TOKEN"),
                    std::ffi::OsString::from("synthetic-token-001"),
                );
            }
            "proxy.ambient-proxy-disabled" => {
                sandbox.environment.remove(std::ffi::OsStr::new("NO_PROXY"));
                sandbox.environment.remove(std::ffi::OsStr::new("no_proxy"));
            }
            _ => {}
        }
        if id == "proxy.credential-source-conflict" {
            sandbox.environment.insert(
                std::ffi::OsString::from("ICM_PROXY_TOKEN"),
                std::ffi::OsString::from("synthetic-token-001"),
            );
        }

        let client_count = if matches!(
            id,
            "proxy.three-client-topology"
                | "proxy.single-mock-model-load"
                | "proxy.distinct-proxy-processes"
                | "proxy.daemon-process-remains-one"
        ) {
            self.verification.acceptance_thresholds.proxy_client_count
        } else {
            1
        };
        let mut proxy_pids = Vec::new();
        let mut responses = Vec::new();
        let mut proxy_transcripts = Vec::new();
        let mut request_bodies = Vec::new();
        let mut observed_errors = Vec::new();
        let expected_proxy_error = matches!(
            id,
            "proxy.redirect-rejected"
                | "proxy.bad-content-type"
                | "proxy.oversized-response"
                | "proxy.invalid-utf8-response"
                | "proxy.sse-response-rejected"
                | "proxy.truncated-response"
                | "proxy.request-timeout"
                | "proxy.response-id-mismatch"
                | "proxy.request-size-bound"
                | "proxy.credential-source-conflict"
                | "proxy.credential-redaction"
                | "proxy.no-automatic-retry"
                | "proxy.daemon-disappearance"
        );
        for index in 0..client_count {
            let mut args = vec!["proxy".to_owned(), "--url".to_owned(), url.clone()];
            if let Some(token_file) = &token_file {
                args.push("--token-file".to_owned());
                args.push(token_file.to_string_lossy().into_owned());
            }
            if compact {
                args.push("--compact".to_owned());
            }
            let mut client =
                McpClient::spawn_with_args(&self.candidate, &sandbox, &args, &self.user_state)?;
            proxy_pids.push(client.process_id());
            if id == "proxy.legacy-session-continuity" {
                let initialized = client.initialize_modern("2025-11-25")?;
                if proxy_response_is_error(&initialized) {
                    anyhow::bail!("legacy proxy initialization failed");
                }
                responses.push(initialized);
            }
            if id == "proxy.notification-forwarding" {
                client.notify(json!({
                    "jsonrpc":"2.0",
                    "method":"notifications/eval",
                    "params":{"marker":"synthetic-notification"}
                }))?;
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    if read_json_lines(&daemon.record_path)
                        .unwrap_or_default()
                        .iter()
                        .any(|record| {
                            record
                                .get("body")
                                .and_then(Value::as_str)
                                .is_some_and(|body| body.contains("synthetic-notification"))
                        })
                    {
                        break;
                    }
                    if Instant::now() >= deadline {
                        anyhow::bail!(
                            "notification did not cross evaluator-owned readiness barrier"
                        );
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
            let call_count = if expected_proxy_error {
                1
            } else if matches!(
                id,
                "proxy.legacy-session-continuity" | "proxy.modern-stateless-no-session"
            ) {
                2
            } else if id == "proxy.notification-forwarding" {
                0
            } else {
                self.verification
                    .acceptance_thresholds
                    .proxy_calls_per_client
            };
            for call_index in 0..call_count {
                let request_id = index
                    * self
                        .verification
                        .acceptance_thresholds
                        .proxy_calls_per_client
                    + call_index
                    + 1;
                let request = match id {
                    "proxy.real-daemon-tool-call" => tool_call(
                        request_id as u64,
                        "icm_memory_recall",
                        json!({"query":"synthetic"}),
                    ),
                    "proxy.modern-stateless-no-session" => {
                        modern_request(request_id as u64, "tools/list", json!({}), true)
                    }
                    "proxy.request-size-bound" => json!({
                        "jsonrpc":"2.0",
                        "id":request_id,
                        "method":"tools/list",
                        "params":{"padding":"x".repeat(3 * 1024 * 1024)}
                    }),
                    _ => json!({
                        "jsonrpc":"2.0",
                        "id":request_id,
                        "method":"tools/list",
                        "params":{}
                    }),
                };
                request_bodies.push(format!("{}\n", serde_json::to_string(&request)?));
                match client.request(request) {
                    Ok(response) => {
                        if proxy_response_is_error(&response) {
                            observed_errors.push(format!("response:{response}"));
                        }
                        responses.push(response);
                    }
                    Err(error) => observed_errors.push(format!("transport:{error:#}")),
                }
            }
            if let Some(pss) = read_pss_kib(client.process_id()) {
                self.metrics
                    .supplemental_pss_kib
                    .insert(format!("{id}.proxy-{index}"), pss);
            }
            let capture = client.shutdown()?;
            self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
            self.verify_capture(
                &sandbox,
                &capture.exchanges,
                &capture.stdout,
                &capture.stderr,
            )?;
            proxy_transcripts.push(normalize_transcript(
                &capture.exchanges,
                &empty_fixture_state(),
            ));
        }

        if expected_proxy_error && observed_errors.is_empty() {
            anyhow::bail!("adversarial proxy scenario produced no bounded proxy error");
        }
        if !expected_proxy_error && !observed_errors.is_empty() {
            anyhow::bail!("successful proxy scenario produced errors: {observed_errors:?}");
        }
        if id == "proxy.credential-redaction"
            && observed_errors
                .iter()
                .any(|error| error.contains("synthetic-token-001"))
        {
            anyhow::bail!("proxy error disclosed credential material");
        }

        let daemon_pid = daemon.child.id()?;
        if let Some(pss) = read_pss_kib(daemon_pid) {
            self.metrics
                .supplemental_pss_kib
                .insert(format!("{id}.daemon"), pss);
        }
        let daemon_status = if daemon_mode == "timeout" {
            daemon.child.terminate()?
        } else {
            shutdown_mock_daemon(&daemon.url)?;
            daemon.child.wait_timeout(Duration::from_secs(5))?
        };
        let records = read_json_lines(&daemon.record_path)?;
        if daemon_mode != "timeout" && !daemon_status.success() {
            anyhow::bail!("mock daemon exited unsuccessfully: {daemon_status}");
        }
        let endpoint_evidence = recorded_loopback_evidence(&records)?;

        match id {
            "proxy.trailing-slash-url" => assert_target_suffix(&records, "/mcp")?,
            "proxy.base-path-url" => assert_target_contains(&records, "/base/path/mcp")?,
            "proxy.compact-query" => assert_target_contains(&records, "compact=true")?,
            "proxy.bearer-auth" => {
                if records.iter().any(|record| {
                    record.get("authorization").and_then(Value::as_str)
                        != Some("Bearer synthetic-token-001")
                }) {
                    anyhow::bail!("proxy did not forward exact bearer token");
                }
            }
            "proxy.token-file-auth" | "proxy.token-env-auth" => {
                if records.is_empty()
                    || records.iter().any(|record| {
                        record.get("authorization").and_then(Value::as_str)
                            != Some("Bearer synthetic-token-001")
                    })
                {
                    anyhow::bail!("proxy did not use the exact selected bearer credential");
                }
            }
            "proxy.no-auth" => {
                if records.iter().any(|record| {
                    !record
                        .get("authorization")
                        .unwrap_or(&Value::Null)
                        .is_null()
                }) {
                    anyhow::bail!("proxy added authorization when none was configured");
                }
            }
            "proxy.exact-request-body" => {
                let actual = records
                    .first()
                    .and_then(|record| record.get("body"))
                    .and_then(Value::as_str)
                    .context("mock record has no body")?;
                if actual != request_bodies[0].trim_end() {
                    anyhow::bail!("proxy changed JSON-RPC request body");
                }
            }
            "proxy.exact-response-body" => {
                if responses
                    .first()
                    .and_then(|value| value.pointer("/result/modelInstanceId"))
                    .and_then(Value::as_str)
                    != Some("synthetic-model-instance-001")
                {
                    anyhow::bail!("proxy changed mock daemon response body");
                }
            }
            "proxy.http-error-propagation" => {
                if responses
                    .first()
                    .and_then(|value| value.get("error"))
                    .is_none()
                    && responses
                        .first()
                        .and_then(|value| value.pointer("/result/isError"))
                        != Some(&Value::Bool(true))
                {
                    anyhow::bail!("proxy did not propagate HTTP 503");
                }
            }
            "proxy.three-client-topology" | "proxy.distinct-proxy-processes" => {
                let unique: BTreeSet<_> = proxy_pids.iter().copied().collect();
                if unique.len() != self.verification.acceptance_thresholds.proxy_client_count {
                    anyhow::bail!("proxy process count differs from typed client threshold");
                }
            }
            "proxy.single-mock-model-load" => {
                if records.iter().any(|record| {
                    record.get("modelLoadCount").and_then(Value::as_u64)
                        != Some(
                            self.verification
                                .acceptance_thresholds
                                .daemon_model_load_count as u64,
                        )
                }) {
                    anyhow::bail!("mock model loaded more than once");
                }
            }
            "proxy.daemon-process-remains-one" => {
                let required_requests = self
                    .verification
                    .acceptance_thresholds
                    .proxy_client_count
                    .saturating_mul(
                        self.verification
                            .acceptance_thresholds
                            .proxy_calls_per_client,
                    );
                if daemon_pid == 0
                    || records.len() < required_requests
                    || self.verification.acceptance_thresholds.daemon_count != 1
                {
                    anyhow::bail!("shared daemon topology evidence incomplete");
                }
            }
            "proxy.daemon-one-store-model" => {
                if records.is_empty()
                    || records.iter().any(|record| {
                        record.get("modelLoadCount").and_then(Value::as_u64)
                            != Some(
                                self.verification
                                    .acceptance_thresholds
                                    .daemon_model_load_count as u64,
                            )
                    })
                {
                    anyhow::bail!("evaluator-owned daemon model construction count is not one");
                }
            }
            "proxy.origin-host-headers" => {
                let authority = daemon
                    .url
                    .strip_prefix("http://")
                    .and_then(|value| value.split('/').next())
                    .context("daemon URL lacks authority")?;
                for record in &records {
                    let headers = record
                        .get("headers")
                        .and_then(Value::as_object)
                        .context("daemon record lacks headers")?;
                    if headers.get("host").and_then(Value::as_str) != Some(authority)
                        || headers.get("origin").is_some()
                        || headers.get("content-type").and_then(Value::as_str)
                            != Some("application/json")
                    {
                        anyhow::bail!(
                            "proxy Host/Origin/Content-Type headers differ from contract"
                        );
                    }
                }
            }
            "proxy.redirect-rejected"
            | "proxy.bad-content-type"
            | "proxy.oversized-response"
            | "proxy.invalid-utf8-response"
            | "proxy.sse-response-rejected"
            | "proxy.truncated-response"
            | "proxy.request-timeout"
            | "proxy.response-id-mismatch"
            | "proxy.daemon-disappearance" => {
                if records.len() != 1 || observed_errors.is_empty() {
                    anyhow::bail!("adversarial daemon response was not rejected exactly once");
                }
            }
            "proxy.request-size-bound" | "proxy.credential-source-conflict" => {
                if !records.is_empty() {
                    anyhow::bail!("proxy forwarded a request that had to be rejected locally");
                }
            }
            "proxy.credential-redaction" => {
                let combined = format!(
                    "{}\n{}",
                    observed_errors.join("\n"),
                    proxy_transcripts.join("\n")
                );
                if combined.contains("synthetic-token-001") {
                    anyhow::bail!("proxy disclosed bearer material in a captured error");
                }
            }
            "proxy.hop-by-hop-headers" => {
                for record in &records {
                    let headers = record
                        .get("headers")
                        .and_then(Value::as_object)
                        .context("daemon record lacks headers")?;
                    for forbidden in [
                        "proxy-authorization",
                        "proxy-authenticate",
                        "keep-alive",
                        "transfer-encoding",
                        "upgrade",
                    ] {
                        if headers.contains_key(forbidden) {
                            anyhow::bail!("proxy forwarded hop-by-hop request header {forbidden}");
                        }
                    }
                }
                if responses.iter().any(|response| {
                    serde_json::to_string(response)
                        .is_ok_and(|text| text.contains("synthetic-secret"))
                }) {
                    anyhow::bail!("proxy exposed a hop-by-hop response header");
                }
            }
            "proxy.no-automatic-retry" => {
                if records.len() != 1 {
                    anyhow::bail!("proxy automatically retried an upstream failure");
                }
            }
            "proxy.ambient-proxy-disabled" => {
                if records.is_empty() {
                    anyhow::bail!("proxy honored poisoned ambient proxy variables instead of reaching loopback directly");
                }
                assert_recorded_loopback_endpoints(&records)?;
            }
            "proxy.legacy-session-continuity" => {
                let calls: Vec<_> = records
                    .iter()
                    .filter(|record| recorded_method(record).as_deref() == Some("tools/list"))
                    .collect();
                if records.len() != 4 || proxy_pids.len() != 1 || calls.len() != 2 {
                    anyhow::bail!("legacy MCP session ID was not continuous across proxy calls");
                }
                for call in calls {
                    assert_proxy_transport_headers(
                        call,
                        "2025-11-25",
                        Some("synthetic-legacy-session-001"),
                    )?;
                }
            }
            "proxy.modern-stateless-no-session" => {
                if records.len() != 2
                    || records.iter().any(|record| {
                        record
                            .get("headers")
                            .and_then(Value::as_object)
                            .is_some_and(|headers| {
                                headers.keys().any(|name| name.contains("session"))
                            })
                    })
                {
                    anyhow::bail!("modern stateless forwarding leaked transport session state");
                }
                for record in &records {
                    assert_proxy_transport_headers(record, "2026-07-28", None)?;
                }
            }
            "proxy.notification-forwarding" => {
                if records.len() != 1
                    || records[0]
                        .get("body")
                        .and_then(Value::as_str)
                        .and_then(|body| serde_json::from_str::<Value>(body).ok())
                        .and_then(|body| body.get("method").cloned())
                        != Some(Value::String("notifications/eval".to_owned()))
                {
                    anyhow::bail!("proxy did not forward the exact notification body");
                }
            }
            "proxy.ipv6-loopback" => {
                if records.is_empty()
                    || records.iter().any(|record| {
                        ["localAddress", "peerAddress"].iter().any(|field| {
                            record
                                .get(*field)
                                .and_then(Value::as_str)
                                .and_then(|address| address.parse::<SocketAddr>().ok())
                                .is_none_or(|address| {
                                    !address.is_ipv6() || !address.ip().is_loopback()
                                })
                        })
                    })
                {
                    anyhow::bail!("proxy IPv6 integration did not remain on ::1");
                }
            }
            "proxy.real-daemon-tools-list" => {
                if records.iter().any(|record| {
                    record
                        .get("body")
                        .and_then(Value::as_str)
                        .and_then(|body| serde_json::from_str::<Value>(body).ok())
                        .and_then(|body| body.get("method").cloned())
                        != Some(Value::String("tools/list".to_owned()))
                }) {
                    anyhow::bail!("proxy tools/list integration forwarded another method");
                }
            }
            "proxy.real-daemon-tool-call" => {
                if records.iter().any(|record| {
                    record
                        .get("body")
                        .and_then(Value::as_str)
                        .and_then(|body| serde_json::from_str::<Value>(body).ok())
                        .and_then(|body| body.get("method").cloned())
                        != Some(Value::String("tools/call".to_owned()))
                }) {
                    anyhow::bail!("proxy tools/call integration forwarded another method");
                }
            }
            "proxy.clean-shutdown" if !daemon_status.success() => {
                anyhow::bail!("daemon did not shut down cleanly");
            }
            _ => {}
        }
        sandbox.verify()?;
        let transcript = proxy_transcripts.join("\n");
        self.passed(
            id,
            json!({
                "supported": true,
                "proxyPidsDistinct": proxy_pids.iter().copied().collect::<BTreeSet<_>>().len(),
                "daemonPidRecorded": daemon_pid > 0,
                "requestCount": records.len(),
                "configuredEndpointLoopback": true,
                "recordedIntegrationSocketsLoopback": true,
                "recordedEndpointEvidence": endpoint_evidence,
                "modelLoadCounts": records.iter().filter_map(|record| record.get("modelLoadCount").and_then(Value::as_u64)).collect::<Vec<_>>()
            }),
            &transcript,
        )
    }

    fn run_real_daemon_proxy(
        &mut self,
        id: &str,
        sandbox: &ScenarioSandbox,
    ) -> Result<ScenarioResult> {
        build_database(&self.suite_root, &sandbox.db, true)?;
        fs::write(
            &sandbox.config,
            "[embeddings]\nenabled = true\nprovider = \"mock\"\n\n[memory]\nauto_consolidate_enabled = false\n",
        )?;
        let mut daemon = self.start_real_candidate_daemon(sandbox)?;
        let mut proxy = McpClient::spawn_with_args(
            &self.candidate,
            sandbox,
            &["proxy".to_owned(), "--url".to_owned(), daemon.url.clone()],
            &self.user_state,
        )?;
        let request = if id == "proxy.real-daemon-tool-call" {
            tool_call(
                1,
                "icm_memory_recall",
                json!({"query":"SQLite","project":"","limit":3}),
            )
        } else {
            tools_list(1)
        };
        let response = proxy.request(request)?;
        if proxy_response_is_error(&response) {
            anyhow::bail!("real candidate daemon E2E returned a proxy error: {response}");
        }
        if id == "proxy.real-daemon-tools-list"
            && response
                .pointer("/result/tools")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            anyhow::bail!("real daemon tools/list returned no product catalog");
        }
        if id == "proxy.real-daemon-tool-call"
            && response
                .pointer("/result/content")
                .and_then(Value::as_array)
                .is_none()
        {
            anyhow::bail!("real daemon tools/call returned no MCP content");
        }
        let proxy_pid = proxy.process_id();
        let capture = proxy.shutdown()?;
        self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
        self.verify_capture(
            sandbox,
            &capture.exchanges,
            &capture.stdout,
            &capture.stderr,
        )?;
        let daemon_pid = daemon.child.id()?;
        let daemon_status = daemon.child.terminate()?;
        let stderr = daemon
            .stderr_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        let event_bytes = fs::read(&daemon.event_path)
            .context("real daemon evaluation-build lifecycle journal is absent")?;
        let events = validate_support_event_journal(
            &event_bytes,
            &[
                "daemon-start",
                "store-constructed",
                "model-constructed",
                "http-ready",
            ],
            None,
        )?;
        let store_count = events
            .iter()
            .filter(|event| event.get("event").and_then(Value::as_str) == Some("store-constructed"))
            .count();
        let model_count = events
            .iter()
            .filter(|event| event.get("event").and_then(Value::as_str) == Some("model-constructed"))
            .count();
        if store_count != 1 || model_count != 1 {
            anyhow::bail!(
                "real daemon constructed store/model {store_count}/{model_count} times instead of 1/1"
            );
        }
        if daemon_status.success() {
            // A terminated long-running server may report either a signal or a
            // graceful status; process reaping, not the platform status code,
            // is the portable cleanup invariant.
        }
        sandbox.verify_nondisclosure(&String::from_utf8_lossy(&stderr))?;
        sandbox.verify()?;
        self.passed(
            id,
            json!({
                "supported":true,
                "realCandidateDaemon":true,
                "proxyPid":proxy_pid,
                "daemonPid":daemon_pid,
                "daemonReaped":true,
                "storeConstructionCount":store_count,
                "modelConstructionCount":model_count,
                "eventJournalSha256":sha256_bytes(&event_bytes),
                "responseSha256":sha256_bytes(serde_json::to_string(&response)?.as_bytes())
            }),
            &normalize_transcript(&capture.exchanges, &empty_fixture_state()),
        )
    }

    fn start_real_candidate_daemon(&self, sandbox: &ScenarioSandbox) -> Result<RealDaemon> {
        let data_root = sandbox_env_path(sandbox, "XDG_DATA_HOME")?;
        let event_path = data_root
            .join("icm")
            .join("evaluator-only-daemon-events.jsonl");
        let arguments = vec![
            "--db".to_owned(),
            sandbox.db.to_string_lossy().into_owned(),
            "serve".to_owned(),
            "--http".to_owned(),
            "127.0.0.1:0".to_owned(),
        ];
        sandbox.verify_child_context(&arguments, &self.user_state)?;
        let mut command = Command::new(&self.candidate);
        command
            .args(&arguments)
            .env_clear()
            .envs(sandbox.environment.clone())
            .current_dir(&sandbox.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child =
            ChildGuard::spawn(command).context("starting real candidate HTTP daemon")?;
        let stdout = child
            .child_mut()?
            .stdout
            .take()
            .context("real daemon stdout unavailable")?;
        let stderr = child
            .child_mut()?
            .stderr
            .take()
            .context("real daemon stderr unavailable")?;
        let (ready_tx, ready_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = String::new();
            let result = reader.read_line(&mut ready).map(|_| ready);
            let _ = ready_tx.send(result);
            let mut discard = Vec::new();
            let _ = reader.read_to_end(&mut discard);
        });
        let (stderr_tx, stderr_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut bytes = Vec::new();
            let _ = reader.read_to_end(&mut bytes);
            let _ = stderr_tx.send(bytes);
        });
        let ready = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .context("timed out waiting for real daemon readiness")??;
        let url = ready
            .trim()
            .strip_prefix("READY ")
            .context("real daemon did not emit exact READY URL")?
            .to_owned();
        loopback_address_from_url(&url)?;
        Ok(RealDaemon {
            child,
            url,
            event_path,
            stderr_rx,
        })
    }

    fn run_proxy_internal_observation(
        &mut self,
        id: &str,
        sandbox: &ScenarioSandbox,
    ) -> Result<ScenarioResult> {
        let mut daemon = self.start_mock_daemon_mode(sandbox, "normal", false)?;
        let event_path = sandbox.artifact_dir.join("proxy-observation-events.jsonl");
        let counter_path = sandbox.artifact_dir.join("proxy-observation-counters.json");
        let exchange_path = sandbox.artifact_dir.join("proxy-observation-exchange.json");
        let _support_stdout = self.run_evaluator_support(
            id,
            sandbox,
            &[
                "proxy-observe".to_owned(),
                "--case".to_owned(),
                id.to_owned(),
                "--url".to_owned(),
                daemon.url.clone(),
                "--event-journal".to_owned(),
                event_path.to_string_lossy().into_owned(),
                "--counter-file".to_owned(),
                counter_path.to_string_lossy().into_owned(),
                "--exchange-file".to_owned(),
                exchange_path.to_string_lossy().into_owned(),
            ],
        )?;
        shutdown_mock_daemon(&daemon.url)?;
        let status = daemon.child.wait_timeout(Duration::from_secs(5))?;
        if !status.success() {
            anyhow::bail!("proxy observation daemon exited unsuccessfully");
        }
        let records = read_json_lines(&daemon.record_path)?;
        assert_recorded_loopback_endpoints(&records)?;
        let exchange_bytes = fs::read(&exchange_path)
            .context("proxy internal observation lacks raw exchange artifact")?;
        let exchange: Value = serde_json::from_slice(&exchange_bytes)
            .context("proxy internal exchange artifact is not JSON")?;
        let request = exchange
            .get("request")
            .and_then(Value::as_str)
            .context("proxy internal exchange lacks raw request")?;
        let recorded_body = records
            .first()
            .and_then(|record| record.get("body"))
            .and_then(Value::as_str)
            .context("observation daemon recorded no raw request")?;
        if request.trim_end() != recorded_body
            || exchange.get("response").and_then(Value::as_str).is_none()
        {
            anyhow::bail!("proxy support exchange does not match evaluator-owned daemon bytes");
        }
        let counters: Value = serde_json::from_slice(&fs::read(&counter_path)?)?;
        if counters
            .get("proxyStoreModelConstructions")
            .and_then(Value::as_u64)
            != Some(0)
        {
            anyhow::bail!("proxy process constructed store/model state");
        }
        if id == "proxy.dns-rebinding-target-pin"
            && (counters
                .pointer("/resolver/initialAddress")
                .and_then(Value::as_str)
                != Some("127.0.0.1")
                || counters
                    .pointer("/resolver/reboundAddress")
                    .and_then(Value::as_str)
                    != Some("127.0.0.2")
                || counters.pointer("/resolver/connectedAddresses") != Some(&json!(["127.0.0.1"])))
        {
            anyhow::bail!("injected resolver trace does not prove one pinned initial address");
        }
        let event_bytes =
            fs::read(&event_path).context("proxy internal observation lacks event journal")?;
        let events = validate_support_event_journal(
            &event_bytes,
            &[
                "observation-installed",
                "proxy-start",
                "request-forwarded",
                "response-received",
                "proxy-stop",
            ],
            Some(("response-received", sha256_bytes(&exchange_bytes))),
        )?;
        sandbox.verify()?;
        self.passed(
            id,
            json!({
                "supported":true,
                "rawExchangeSha256":sha256_bytes(&exchange_bytes),
                "eventJournalSha256":sha256_bytes(&event_bytes),
                "counterSha256":sha256_file(&counter_path)?,
                "eventCount":events.len(),
                "daemonRecordCount":records.len()
            }),
            "",
        )
    }

    fn run_proxy_rejected_endpoint(
        &mut self,
        id: &str,
        sandbox: &ScenarioSandbox,
    ) -> Result<ScenarioResult> {
        let mut daemon = if id == "proxy.userinfo-fragment-rejected" {
            Some(self.start_mock_daemon_mode(sandbox, "normal", false)?)
        } else {
            None
        };
        let urls = if let Some(daemon) = daemon.as_ref() {
            let authority = daemon
                .url
                .strip_prefix("http://")
                .and_then(|value| value.split('/').next())
                .context("mock daemon URL lacks authority")?;
            vec![
                format!("http://synthetic-user@{authority}/"),
                format!("http://{authority}/#synthetic-fragment"),
            ]
        } else {
            vec!["http://192.0.2.1:9/".to_owned()]
        };
        let mut outcomes = Vec::new();
        for url in &urls {
            let start = Instant::now();
            let mut client = McpClient::spawn_with_args(
                &self.candidate,
                sandbox,
                &["proxy".to_owned(), "--url".to_owned(), url.clone()],
                &self.user_state,
            )?;
            let rejected = match client.request(tools_list(1)) {
                Ok(response) => proxy_response_is_error(&response),
                Err(_) => true,
            };
            let elapsed = start.elapsed();
            let capture = client.shutdown()?;
            self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
            self.verify_capture(
                sandbox,
                &capture.exchanges,
                &capture.stdout,
                &capture.stderr,
            )?;
            if !rejected || elapsed > Duration::from_secs(10) {
                anyhow::bail!(
                    "proxy did not reject forbidden endpoint within its bounded response window"
                );
            }
            outcomes.push(json!({"urlKind":if url.contains('@') {"userinfo"} else if url.contains('#') {"fragment"} else {"non-loopback"},"rejected":true}));
        }
        if let Some(daemon) = daemon.as_mut() {
            let before_shutdown = read_json_lines(&daemon.record_path).unwrap_or_default();
            if !before_shutdown.is_empty() {
                anyhow::bail!("proxy connected before rejecting userinfo/fragment URL");
            }
            shutdown_mock_daemon(&daemon.url)?;
            let status = daemon.child.wait_timeout(Duration::from_secs(5))?;
            if !status.success() {
                anyhow::bail!("endpoint rejection daemon failed during cleanup");
            }
        }
        sandbox.verify()?;
        self.passed(id, json!({"supported":true,"outcomes":outcomes}), "")
    }

    fn run_boundary(&mut self, id: &str) -> Result<ScenarioResult> {
        let execution = self.execute_mcp(id, McpExecutionConfig {
            populated: true,
            fixture_profile: FixtureProfile::Standard,
            compact: false,
            init: Init::Legacy,
            fault_database: false,
        }, |client, _, _| {
            let response = match id {
                "boundary.empty-object" => {
                    client.request(tool_call(2, "icm_memory_store", json!({})))?
                }
                "boundary.empty-string" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"","content":""}),
                ))?,
                "boundary.whitespace" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"   \t","content":"  \n"}),
                ))?,
                "boundary.null" => client.request(json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{"name":"icm_memory_store","arguments":null}
                }))?,
                "boundary.wrong-json-type" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"boundary","content":42}),
                ))?,
                "boundary.unknown-field" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"boundary","content":"valid","unknownField":true}),
                ))?,
                "boundary.max-topic-255" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"t".repeat(255),"content":"valid"}),
                ))?,
                "boundary.topic-256" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"t".repeat(256),"content":"valid"}),
                ))?,
                "boundary.max-content-65536" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"boundary","content":"c".repeat(65_536)}),
                ))?,
                "boundary.content-65537" => client.request(tool_call(
                    2,
                    "icm_memory_store",
                    json!({"topic":"boundary","content":"c".repeat(65_537)}),
                ))?,
                "boundary.limit-min" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"SQLite","project":"","limit":1}),
                ))?,
                "boundary.limit-max" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"memory","project":"","limit":100}),
                ))?,
                "boundary.limit-under" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"SQLite","project":"","limit":0}),
                ))?,
                "boundary.limit-over" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"SQLite","project":"","limit":101}),
                ))?,
                "boundary.unicode" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"café 東京 🧪","project":"","limit":10}),
                ))?,
                "boundary.rtl-zero-width" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"مرحبا\u{200b}","project":"","limit":10}),
                ))?,
                "boundary.newline-delimiter-injection" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"Delimiter attack","project":"","limit":10}),
                ))?,
                "boundary.sql-injection" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"' OR 1=1; DROP TABLE memories; --","project":"","limit":10}),
                ))?,
                "boundary.fts-injection" => client.request(tool_call(
                    2,
                    "icm_memory_recall",
                    json!({"query":"NEAR(\"unterminated * OR NOT","project":"","limit":10}),
                ))?,
                "boundary.path-traversal" => client.request(tool_call(
                    2,
                    "icm_learn",
                    json!({"directory":"../","name":"path-traversal-attempt"}),
                ))?,
                "boundary.malformed-uri" => client.request(json!({
                    "jsonrpc":"2.0","id":2,"method":"resources/read",
                    "params":{"uri":"icm://../../real-user-state"}
                }))?,
                "boundary.oversized-line" => {
                    let oversized = format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\",\"params\":{{\"padding\":\"{}\"}}}}",
                        "x".repeat(10 * 1024 * 1024 + 1)
                    );
                    let raw = client
                        .send_raw(&oversized, true)?
                        .context("oversized request produced no bounded error response")?;
                    serde_json::from_str(raw.trim_end())?
                }
                _ => anyhow::bail!("unknown boundary scenario {id}"),
            };

            let expected_error = matches!(
                id,
                "boundary.empty-object"
                    | "boundary.empty-string"
                    | "boundary.whitespace"
                    | "boundary.null"
                    | "boundary.wrong-json-type"
                    | "boundary.unknown-field"
                    | "boundary.topic-256"
                    | "boundary.content-65537"
                    | "boundary.limit-under"
                    | "boundary.limit-over"
                    | "boundary.path-traversal"
                    | "boundary.malformed-uri"
                    | "boundary.oversized-line"
            );
            let is_error = response.get("error").is_some()
                || response.pointer("/result/isError") == Some(&Value::Bool(true));
            if expected_error != is_error {
                anyhow::bail!(
                    "boundary contract expected error={expected_error}, observed error={is_error}"
                );
            }
            if id == "boundary.newline-delimiter-injection" {
                let text = text_content(&response)?;
                if !text.contains("line two") {
                    anyhow::bail!("delimiter fixture was not retrieved");
                }
            }
            Ok(json!({
                "expectedError": expected_error,
                "observedError": is_error,
                "jsonRpcErrorCode": error_code(&response),
                "responseBytes": serde_json::to_vec(&response)?.len()
            }))
        })?;
        self.finish_execution(id, execution, false)
    }

    fn run_metric(&mut self, id: &str) -> Result<ScenarioResult> {
        match id {
            "metrics.payload-sizes" => self.run_payload_metrics(id),
            "metrics.latency-five-blocks" => self.run_latency_metrics(id),
            "metrics.retrieval-quality" => self.run_retrieval_metrics(id),
            _ => anyhow::bail!("unknown metric scenario {id}"),
        }
    }

    fn run_payload_metrics(&mut self, id: &str) -> Result<ScenarioResult> {
        let execution = self.execute_mcp(
            id,
            McpExecutionConfig {
                populated: true,
                fixture_profile: FixtureProfile::Standard,
                compact: false,
                init: Init::Legacy,
                fault_database: false,
            },
            |client, _, _| {
                let requests = [
                    ("tools/list", tools_list(2)),
                    (
                        "memory/recall",
                        tool_call(
                            3,
                            "icm_memory_recall",
                            json!({"query":"SQLite WAL","project":"","limit":3}),
                        ),
                    ),
                    ("memory/stats", tool_call(4, "icm_memory_stats", json!({}))),
                ];
                let mut output = serde_json::Map::new();
                for (name, request) in requests {
                    let raw = client.request_raw(request)?;
                    let value: Value = serde_json::from_str(raw.trim_end())?;
                    output.insert(
                        name.to_owned(),
                        serde_json::to_value(size_metrics(&raw, &value))?,
                    );
                }
                Ok(Value::Object(output))
            },
        )?;
        let object = execution
            .detail
            .as_object()
            .context("payload metrics detail is not object")?;
        for (name, value) in object {
            self.metrics
                .payload_sizes
                .insert(name.clone(), serde_json::from_value(value.clone())?);
        }
        self.finish_execution(id, execution, false)
    }

    fn run_latency_metrics(&mut self, id: &str) -> Result<ScenarioResult> {
        let thresholds = self.verification.acceptance_thresholds.clone();
        let execution = self.execute_mcp(
            id,
            McpExecutionConfig {
                populated: true,
                fixture_profile: FixtureProfile::Standard,
                compact: false,
                init: Init::Legacy,
                fault_database: false,
            },
            |client, _, _| {
                type RequestFactory = fn(u64) -> Value;
                let operations: [(&str, RequestFactory); 3] = [
                    ("tools/list", tools_list),
                    ("memory/recall", |call_id| {
                        tool_call(
                            call_id,
                            "icm_memory_recall",
                            json!({"query":"SQLite WAL","project":"","limit":3}),
                        )
                    }),
                    ("memory/stats", |call_id| {
                        tool_call(call_id, "icm_memory_stats", json!({}))
                    }),
                ];
                let mut output = serde_json::Map::new();
                let mut call_id = 10_u64;
                for (name, request) in operations {
                    for _ in 0..thresholds.latency_warmups_per_operation {
                        client.request(request(call_id))?;
                        call_id += 1;
                    }
                    let mut blocks = Vec::new();
                    for _ in 0..thresholds.latency_block_count {
                        let mut block = Vec::new();
                        for _ in 0..thresholds.latency_samples_per_block {
                            let start = Instant::now();
                            client.request(request(call_id))?;
                            block.push(start.elapsed().as_micros());
                            call_id += 1;
                        }
                        blocks.push(block);
                    }
                    output.insert(
                        name.to_owned(),
                        serde_json::to_value(summarize_blocks(&blocks))?,
                    );
                }
                Ok(Value::Object(output))
            },
        )?;
        let object = execution
            .detail
            .as_object()
            .context("latency detail is not object")?;
        for (name, value) in object {
            let actual: LatencySummary = serde_json::from_value(value.clone())?;
            if !latency_shape_matches(&actual, &self.verification.acceptance_thresholds) {
                anyhow::bail!("latency metric {name} lacks exact typed block/sample evidence");
            }
            self.metrics.latency.insert(name.clone(), actual);
        }
        if self.mode == EvaluationMode::Candidate {
            let baseline: Value = serde_json::from_slice(&fs::read(
                self.suite_root.join("goldens/baseline-metrics.json"),
            )?)?;
            for (name, actual) in &self.metrics.latency {
                let pointer_name = name.replace('/', "~1");
                let baseline_median = baseline
                    .pointer(&format!("/latencyMicros/{pointer_name}/median"))
                    .and_then(Value::as_u64)
                    .with_context(|| format!("baseline median absent for {name}"))?
                    as u128;
                let baseline_p95 = baseline
                    .pointer(&format!("/latencyMicros/{pointer_name}/p95"))
                    .and_then(Value::as_u64)
                    .with_context(|| format!("baseline p95 absent for {name}"))?
                    as u128;
                let (median_limit, p95_limit) = latency_limits(
                    baseline_median,
                    baseline_p95,
                    &self.verification.acceptance_thresholds,
                )?;
                if actual.median_micros > median_limit || actual.p95_micros > p95_limit {
                    anyhow::bail!(
                        "latency regression for {name}: median {} > {median_limit} or p95 {} > {p95_limit} microseconds",
                        actual.median_micros,
                        actual.p95_micros
                    );
                }
                let interpretation = if baseline_median > actual.median_micros
                    && baseline_median - actual.median_micros
                        <= self
                            .verification
                            .acceptance_thresholds
                            .latency_noise_floor_micros
                {
                    "inconclusive-below-noise-floor"
                } else if baseline_median > actual.median_micros {
                    "measured-lower-latency"
                } else {
                    "not-lower"
                };
                self.metrics
                    .latency_interpretation
                    .insert(name.clone(), interpretation.to_owned());
            }
        }
        self.finish_execution(id, execution, false)
    }

    fn run_retrieval_metrics(&mut self, id: &str) -> Result<ScenarioResult> {
        let quality = load_quality(&self.suite_root)?;
        let thresholds = self.verification.acceptance_thresholds.clone();
        if quality.k != thresholds.retrieval_k {
            anyhow::bail!(
                "quality fixture k={} differs from typed frozen value {}",
                quality.k,
                thresholds.retrieval_k
            );
        }
        let execution = self.execute_mcp(
            id,
            McpExecutionConfig {
                populated: true,
                fixture_profile: FixtureProfile::Standard,
                compact: false,
                init: Init::Legacy,
                fault_database: false,
            },
            |client, _, _| {
                let mut rankings = Vec::new();
                for (index, query) in quality.queries.iter().enumerate() {
                    let response = client.request(tool_call(
                        2 + index as u64,
                        "icm_memory_recall",
                        json!({"query":query.query,"project":"","limit":thresholds.retrieval_k}),
                    ))?;
                    let actual = extract_ranked_fixture_ids(&text_content(&response)?);
                    rankings.push((actual, query.relevant.clone()));
                }
                Ok(serde_json::to_value(retrieval_metrics(&rankings))?)
            },
        )?;
        let metrics: RetrievalMetrics = serde_json::from_value(execution.detail.clone())?;
        if !retrieval_meets_thresholds(&metrics, &self.verification.acceptance_thresholds) {
            anyhow::bail!(
                "retrieval quality below typed gate: Hit@3={}, Recall@3={}, nDCG@3={}",
                metrics.hit_at_3,
                metrics.recall_at_3,
                metrics.ndcg_at_3
            );
        }
        self.metrics.retrieval = Some(metrics);
        self.finish_execution(id, execution, false)
    }

    fn execute_mcp<F>(
        &mut self,
        id: &str,
        config: McpExecutionConfig,
        operation: F,
    ) -> Result<Execution>
    where
        F: FnOnce(&mut McpClient, &FixtureState, &ScenarioSandbox) -> Result<Value>,
    {
        let sandbox =
            ScenarioSandbox::create(&self.work_root, &self.run_label, id, config.compact)?;
        let state = build_database(&self.suite_root, &sandbox.db, config.populated)?;
        match config.fixture_profile {
            FixtureProfile::Standard => {}
            FixtureProfile::Resource => augment_resource_database(&sandbox.db, false)?,
            FixtureProfile::ResourceLarge => augment_resource_database(&sandbox.db, true)?,
        }
        if config.fault_database {
            poison_memory_table(&sandbox.db)?;
        }
        let mut client =
            McpClient::spawn(&self.candidate, &sandbox, config.compact, &self.user_state)?;
        let operation_result = (|| {
            match config.init {
                Init::None => {}
                Init::Legacy => {
                    client.initialize_legacy()?;
                }
            }
            operation(&mut client, &state, &sandbox)
        })();
        let capture = client.shutdown()?;
        self.verify_capture(
            &sandbox,
            &capture.exchanges,
            &capture.stdout,
            &capture.stderr,
        )?;
        self.record_raw(id, &capture.exchanges, &capture.stdout, &capture.stderr)?;
        let transcript = normalize_transcript(&capture.exchanges, &state);
        sandbox.verify()?;
        let detail = operation_result?;
        let unsupported_evidence = wire_unsupported_evidence(&capture.exchanges);
        Ok(Execution {
            detail,
            transcript,
            unsupported_evidence,
        })
    }

    fn finish_execution(
        &mut self,
        id: &str,
        execution: Execution,
        exact_legacy: bool,
    ) -> Result<ScenarioResult> {
        let Execution {
            detail, transcript, ..
        } = execution;
        if exact_legacy {
            self.observed_legacy
                .insert(id.to_owned(), transcript.clone());
            if self.mode == EvaluationMode::Candidate {
                let expected = self
                    .golden
                    .get(id)
                    .with_context(|| format!("committed legacy golden missing {id}"))?;
                let observed_hash = sha256_bytes(transcript.as_bytes());
                if expected != &observed_hash {
                    return Ok(self.failed(
                        id,
                        anyhow::anyhow!(
                            "legacy raw response parity mismatch: expected sha256 {}, observed sha256 {}",
                            expected,
                            observed_hash
                        ),
                    ));
                }
            }
        }
        self.passed(id, detail, &transcript)
    }

    fn finish_unsupported(&mut self, id: &str, execution: Execution) -> Result<ScenarioResult> {
        let mut detail = execution.detail;
        let transcript = execution.transcript;
        if self
            .verification
            .acceptance_thresholds
            .unsupported_baseline_requires_wire_or_cli_evidence
        {
            let evidence = execution
                .unsupported_evidence
                .as_ref()
                .context("unsupported result lacks recognized wire or CLI probe evidence")?;
            validate_unsupported_evidence(evidence)?;
            let object = detail
                .as_object_mut()
                .context("unsupported detail must be an object")?;
            object.insert(
                "unsupportedEvidence".to_owned(),
                serde_json::to_value(evidence)?,
            );
        }
        let evidence_sha256 = evidence_hash(&detail, &transcript)?;
        let status = if self.mode == EvaluationMode::RecordBaseline {
            ScenarioStatus::UnsupportedBaseline
        } else {
            ScenarioStatus::Fail
        };
        Ok(ScenarioResult {
            id: id.to_owned(),
            status,
            detail,
            evidence_sha256,
        })
    }

    fn passed(&self, id: &str, detail: Value, transcript: &str) -> Result<ScenarioResult> {
        Ok(ScenarioResult {
            id: id.to_owned(),
            status: ScenarioStatus::Pass,
            evidence_sha256: evidence_hash(&detail, transcript)?,
            detail,
        })
    }

    fn failed(&self, id: &str, error: anyhow::Error) -> ScenarioResult {
        let mut message = format!("{error:#}");
        for (path, replacement) in [
            (&self.work_root, "<WORK_ROOT>"),
            (&self.evidence_root, "<EVIDENCE_ROOT>"),
            (&self.suite_root, "<SUITE_ROOT>"),
            (&self.candidate, "<CANDIDATE>"),
            (&self.workspace_root, "<WORKSPACE_ROOT>"),
        ] {
            message = message.replace(&path.to_string_lossy().to_string(), replacement);
        }
        let detail = json!({"error": message});
        ScenarioResult {
            id: id.to_owned(),
            status: ScenarioStatus::Fail,
            evidence_sha256: evidence_hash(&detail, "").unwrap_or_else(|_| "hash-error".into()),
            detail,
        }
    }

    fn record_raw(
        &mut self,
        id: &str,
        exchanges: &[Exchange],
        stdout: &str,
        stderr: &str,
    ) -> Result<()> {
        let record = RawScenario {
            scenario: id,
            exchanges,
            stdout,
            stderr,
        };
        self.raw_lines.push(serde_json::to_string(&record)?);
        Ok(())
    }

    fn verify_capture(
        &self,
        sandbox: &ScenarioSandbox,
        exchanges: &[Exchange],
        stdout: &str,
        stderr: &str,
    ) -> Result<()> {
        let mut text = serde_json::to_string(exchanges)?;
        text.push_str(stdout);
        text.push_str(stderr);
        text = text.replace(
            &sandbox.root.to_string_lossy().to_string(),
            "<SCENARIO_ROOT>",
        );
        sandbox.verify_nondisclosure(&text)?;
        scan_for_real_path_leaks(&text, self.user_state.leak_strings())?;
        sandbox.verify()
    }

    fn run_candidate_command(
        &mut self,
        id: &str,
        sandbox: &ScenarioSandbox,
        arguments: &[String],
    ) -> Result<CommandCapture> {
        sandbox.verify_child_context(arguments, &self.user_state)?;
        let mut command = Command::new(&self.candidate);
        command
            .args(arguments)
            .env_clear()
            .envs(sandbox.environment.clone())
            .current_dir(&sandbox.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_guarded_command(command, Duration::from_secs(10))
            .with_context(|| format!("running candidate subcommand for {id}"))?;
        let root = sandbox.root.to_string_lossy();
        let raw_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stdout = raw_stdout.replace(root.as_ref(), "<SCENARIO_ROOT>");
        let stderr =
            String::from_utf8_lossy(&output.stderr).replace(root.as_ref(), "<SCENARIO_ROOT>");
        sandbox.verify_nondisclosure(&format!("{stdout}\n{stderr}"))?;
        scan_for_real_path_leaks(
            &format!("{stdout}\n{stderr}"),
            self.user_state.leak_strings(),
        )?;
        sandbox.verify()?;
        let normalized_arguments: Vec<_> = arguments
            .iter()
            .map(|argument| argument.replace(root.as_ref(), "<SCENARIO_ROOT>"))
            .collect();
        let transcript = serde_json::to_string(&json!({
            "arguments": normalized_arguments,
            "exitCode": output.status.code(),
            "stdout": stdout,
            "stderr": stderr
        }))?;
        self.raw_lines.push(serde_json::to_string(&json!({
            "scenario": id,
            "command": serde_json::from_str::<Value>(&transcript)?
        }))?);
        Ok(CommandCapture {
            status_success: output.status.success(),
            exit_code: output.status.code(),
            raw_stdout,
            stdout,
            stderr,
            transcript,
        })
    }

    fn run_evaluator_support(
        &mut self,
        id: &str,
        sandbox: &ScenarioSandbox,
        arguments: &[String],
    ) -> Result<Value> {
        let candidate_parent = self
            .candidate
            .parent()
            .context("candidate has no parent directory")?;
        let support_name = if cfg!(windows) {
            "icm-eval-support.exe"
        } else {
            "icm-eval-support"
        };
        let support = candidate_parent.join(support_name);
        if !support.is_file() {
            anyhow::bail!(
                "candidate supports the production feature but required compile-time evaluator-only support binary is absent: {}",
                support.display()
            );
        }
        sandbox.verify_child_context(arguments, &self.user_state)?;
        let mut command = Command::new(&support);
        command
            .args(arguments)
            .env_clear()
            .envs(sandbox.environment.clone())
            .current_dir(&sandbox.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_guarded_command(command, Duration::from_secs(20))
            .with_context(|| format!("running evaluator-only support for {id}"))?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            anyhow::bail!("evaluator-only support failed for {id}: {stderr}");
        }
        sandbox.verify_nondisclosure(&format!("{stdout}\n{stderr}"))?;
        scan_for_real_path_leaks(
            &format!("{stdout}\n{stderr}"),
            self.user_state.leak_strings(),
        )?;
        let value: Value = serde_json::from_str(stdout.trim())
            .context("evaluator-only support stdout is not one JSON object")?;
        self.raw_lines.push(serde_json::to_string(&json!({
            "scenario":id,
            "evaluatorSupport":{
                "binary":"icm-eval-support",
                "arguments":arguments,
                "result":value
            }
        }))?);
        Ok(value)
    }

    fn start_mock_daemon(&self, sandbox: &ScenarioSandbox) -> Result<MockDaemon> {
        self.start_mock_daemon_mode(sandbox, "normal", false)
    }

    fn start_mock_daemon_mode(
        &self,
        sandbox: &ScenarioSandbox,
        mode: &str,
        ipv6: bool,
    ) -> Result<MockDaemon> {
        let executable = std::env::current_exe().context("resolving evaluator executable")?;
        let record_path = sandbox.artifact_dir.join("mock-daemon-requests.jsonl");
        let arguments = vec![
            "__mock-daemon".to_owned(),
            "--record".to_owned(),
            record_path.to_string_lossy().into_owned(),
            "--mode".to_owned(),
            mode.to_owned(),
            "--ipv6".to_owned(),
            ipv6.to_string(),
        ];
        sandbox.verify_child_context(&arguments, &self.user_state)?;
        let mut command = Command::new(executable);
        command
            .args(&arguments)
            .env_clear()
            .envs(sandbox.environment.clone())
            .current_dir(&sandbox.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = ChildGuard::spawn(command).context("starting deterministic mock daemon")?;
        let stdout = child
            .child_mut()?
            .stdout
            .take()
            .context("mock daemon stdout unavailable")?;
        let (ready_tx, ready_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = String::new();
            let result = reader.read_line(&mut ready).map(|_| ready);
            let _ = ready_tx.send(result);
        });
        let ready = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .context("timed out waiting for mock daemon readiness")??;
        let url = ready
            .trim()
            .strip_prefix("READY ")
            .context("mock daemon did not emit READY URL")?
            .to_owned();
        let address = loopback_address_from_url(&url)?;
        if ipv6 != address.is_ipv6() {
            anyhow::bail!("mock daemon IP family differs from requested family: {url}");
        }
        Ok(MockDaemon {
            child,
            url,
            record_path,
        })
    }
}

#[derive(Clone, Copy)]
enum Init {
    None,
    Legacy,
}

#[derive(Debug, Clone, Copy)]
enum FixtureProfile {
    Standard,
    Resource,
    ResourceLarge,
}

#[derive(Clone, Copy)]
struct McpExecutionConfig {
    populated: bool,
    fixture_profile: FixtureProfile,
    compact: bool,
    init: Init,
    fault_database: bool,
}

struct CommandCapture {
    status_success: bool,
    exit_code: Option<i32>,
    raw_stdout: String,
    stdout: String,
    stderr: String,
    transcript: String,
}

struct MockDaemon {
    child: ChildGuard,
    url: String,
    record_path: PathBuf,
}

struct RealDaemon {
    child: ChildGuard,
    url: String,
    event_path: PathBuf,
    stderr_rx: mpsc::Receiver<Vec<u8>>,
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn(mut command: Command) -> Result<Self> {
        Ok(Self {
            child: Some(command.spawn()?),
        })
    }

    fn child_mut(&mut self) -> Result<&mut Child> {
        self.child.as_mut().context("child process is unavailable")
    }

    fn id(&self) -> Result<u32> {
        Ok(self
            .child
            .as_ref()
            .context("child process is unavailable")?
            .id())
    }

    fn wait_timeout(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child_mut()?.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "child process {} exceeded {:?} timeout",
                    self.id()?,
                    timeout
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate(&mut self) -> Result<ExitStatus> {
        let child = self.child_mut()?;
        let _ = child.kill();
        child.wait().context("waiting for terminated child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }
}

fn run_guarded_command(command: Command, timeout: Duration) -> Result<Output> {
    let mut child = ChildGuard::spawn(command)?;
    let stdout = child
        .child_mut()?
        .stdout
        .take()
        .context("guarded command stdout unavailable")?;
    let stderr = child
        .child_mut()?
        .stderr
        .take()
        .context("guarded command stderr unavailable")?;
    let (stdout_tx, stdout_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut bytes = Vec::new();
        let result = reader.read_to_end(&mut bytes).map(|_| bytes);
        let _ = stdout_tx.send(result);
    });
    let (stderr_tx, stderr_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut bytes = Vec::new();
        let result = reader.read_to_end(&mut bytes).map(|_| bytes);
        let _ = stderr_tx.send(result);
    });
    let status = child.wait_timeout(timeout)?;
    let stdout = stdout_rx
        .recv_timeout(Duration::from_secs(2))
        .context("timed out collecting guarded command stdout")??;
    let stderr = stderr_rx
        .recv_timeout(Duration::from_secs(2))
        .context("timed out collecting guarded command stderr")??;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn validate_legacy(id: &str, response: &Value, _sandbox: &ScenarioSandbox) -> Result<()> {
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        anyhow::bail!("legacy response is not JSON-RPC 2.0: {response}");
    }
    match id {
        "legacy.initialize-exact" => {
            if response
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                != Some("2024-11-05")
                || !response
                    .pointer("/result/capabilities/tools")
                    .is_some_and(Value::is_object)
                || response
                    .pointer("/result/serverInfo/name")
                    .and_then(Value::as_str)
                    != Some("icm")
            {
                anyhow::bail!("legacy initialize contract mismatch: {response}");
            }
        }
        "legacy.ping" => {
            if result(response)? != &json!({}) {
                anyhow::bail!("legacy ping result is not an empty object");
            }
        }
        "legacy.tools-list-exact" | "legacy.tools-list-order" => {
            let names = tool_names(response)?;
            if names != LEGACY_TOOLS {
                anyhow::bail!("legacy tool catalog/order mismatch: {names:?}");
            }
        }
        "legacy.tools-list-required-fields" => {
            let tools = result(response)?
                .get("tools")
                .and_then(Value::as_array)
                .context("tools/list result has no tools")?;
            for tool in tools {
                let name = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .context("tool has no name")?;
                let actual: Vec<_> = tool
                    .pointer("/inputSchema/required")
                    .and_then(Value::as_array)
                    .map(|values| values.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if actual != required_fields(name) {
                    anyhow::bail!("required fields differ for {name}: {actual:?}");
                }
            }
        }
        "legacy.recall-project-isolation" => {
            if text_content(response)?.contains("ORCHID-LEAK") {
                anyhow::bail!("project-filtered recall leaked other-project marker");
            }
        }
        "legacy.recall-preferences-global" => {
            if !text_content(response)?.contains("concise") {
                anyhow::bail!("global preference did not bypass project filter");
            }
        }
        "legacy.recall-topic-filter" => {
            let text = text_content(response)?;
            if !text.contains("Provider permission") || text.contains("SQLite WAL") {
                anyhow::bail!("topic filter output mismatch");
            }
        }
        "legacy.recall-keyword-filter" => {
            let text = text_content(response)?;
            if !text.contains("Output schemas") || text.contains("generate JSON schemas") {
                anyhow::bail!("keyword filter output mismatch");
            }
        }
        "legacy.recall-empty" => {
            let text = text_content(response)?.to_ascii_lowercase();
            if !(text.contains("no memor") || text.contains("not found")) {
                anyhow::bail!("empty recall did not return an explicit empty result");
            }
        }
        "legacy.list-empty" => {
            let text = text_content(response)?.to_ascii_lowercase();
            if !(text.contains("no topic") || text.trim().is_empty()) {
                anyhow::bail!("empty topic list did not return an explicit empty result");
            }
        }
        "legacy.stats-populated-values" => {
            if !text_content(response)?.contains("12") {
                anyhow::bail!("populated stats do not report 12 fixture memories");
            }
        }
        "legacy.transcript-search-order" => {
            if !text_content(response)?.contains("SQLite WAL") {
                anyhow::bail!("transcript search missed fixed fixture");
            }
        }
        "legacy.transcript-show-order" => {
            let text = text_content(response)?;
            let positions: Vec<_> = [
                "Synthetic transcript",
                "Explain SQLite",
                "Readers coexist",
                "journal_mode",
            ]
            .iter()
            .map(|needle| {
                text.find(needle)
                    .with_context(|| format!("missing transcript message {needle}"))
            })
            .collect::<Result<_>>()?;
            if !positions.windows(2).all(|pair| pair[0] < pair[1]) {
                anyhow::bail!("transcript show did not retain chronological ordering");
            }
        }
        "legacy.feedback-search-order" => {
            if !text_content(response)?.contains("documentation reviewer") {
                anyhow::bail!("feedback search missed fixed fixture");
            }
        }
        "legacy.unknown-tool" => require_tool_error(response)?,
        "legacy.method-not-found" => require_error_code(response, -32601)?,
        "legacy.invalid-json" => require_error_code(response, -32700)?,
        "legacy.missing-params" => require_error_code(response, -32602)?,
        "legacy.null-id" => {
            if response.get("id") != Some(&Value::Null) || result(response)? != &json!({}) {
                anyhow::bail!("explicit null request ID was not echoed");
            }
        }
        other
            if other.starts_with("legacy.")
                && (response.get("error").is_some()
                    || response.pointer("/result/isError") == Some(&Value::Bool(true))) =>
        {
            anyhow::bail!("legacy happy-path scenario returned error: {response}");
        }
        _ => {}
    }
    Ok(())
}

fn validate_modern(suite_root: &Path, design: &Value, id: &str, response: &Value) -> Result<Value> {
    if id == "modern.schema-valid-real-emissions" {
        return validate_all_modern_emissions(suite_root, response);
    }
    if id.starts_with("modern.lifecycle-") {
        return validate_protocol_lifecycle(id, response);
    }
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        anyhow::bail!("modern response does not contain jsonrpc=2.0: {response}");
    }
    if error_code(response) == Some(-32601) {
        return Ok(
            json!({"supported":false,"response":response,"reason":"modern-method-not-found"}),
        );
    }
    let thresholds: crate::design::AcceptanceThresholds = serde_json::from_value(
        design
            .get("acceptanceThresholds")
            .context("acceptance thresholds missing")?
            .clone(),
    )?;
    match id {
        "modern.2025-06-initialize" | "modern.2025-11-initialize" => {
            let expected = if id.contains("2025-06") {
                "2025-06-18"
            } else {
                "2025-11-25"
            };
            if response
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                != Some(expected)
            {
                return Ok(json!({
                    "supported":false,"response":response,"reason":"initialized-modern-version-not-negotiated"
                }));
            }
            let initialized = result(response)?;
            require_absent(initialized, &["resultType", "ttlMs", "cacheScope"])?;
            if !initialized
                .pointer("/capabilities/tools")
                .is_some_and(Value::is_object)
                || !initialized
                    .pointer("/capabilities/resources")
                    .is_some_and(Value::is_object)
            {
                anyhow::bail!("initialized-modern capabilities must advertise tools and resources");
            }
        }
        "modern.initialize-invalid-version" => {
            if response
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                == Some("2024-11-05")
            {
                return Ok(
                    json!({"supported":false,"response":response,"reason":"legacy-only-negotiation"}),
                );
            }
            if response
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                != Some("2025-11-25")
            {
                anyhow::bail!(
                    "unknown initialize version must negotiate newest initialized revision"
                );
            }
        }
        "modern.initialize-malformed-capabilities" | "modern.initialize-malformed-client-info" => {
            if error_code(response) != Some(-32602) {
                if response
                    .pointer("/result/protocolVersion")
                    .and_then(Value::as_str)
                    == Some("2024-11-05")
                {
                    return Ok(
                        json!({"supported":false,"response":response,"reason":"legacy-ignored-modern-initialize-shape"}),
                    );
                }
                anyhow::bail!("malformed initialize parameters must return -32602: {response}");
            }
        }
        "modern.reject-switch-to-2026-after-initialize"
        | "modern.reject-switch-to-initialize-after-discover" => {
            if error_code(response) != Some(ERA_LOCKED_ERROR_CODE) {
                return Ok(
                    json!({"supported":false,"response":response,"reason":"frozen-era-lock-error-absent"}),
                );
            }
            if response.pointer("/error/message").and_then(Value::as_str)
                != Some("protocol era is locked for this connection; open a new connection")
                || response.pointer("/error/data/kind").and_then(Value::as_str)
                    != Some("protocolEraLocked")
                || response
                    .pointer("/error/data/selectedEra")
                    .and_then(Value::as_str)
                    .is_none()
                || response
                    .pointer("/error/data/requestedEra")
                    .and_then(Value::as_str)
                    .is_none()
            {
                anyhow::bail!("era lock error is not the frozen actionable envelope: {response}");
            }
        }
        "modern.2026-unsupported-version" => {
            if error_code(response) != Some(-32022)
                || response
                    .pointer("/error/data/requested")
                    .and_then(Value::as_str)
                    != Some("2099-01-01")
                || response.pointer("/error/data/supported")
                    != Some(&json!([
                        "2026-07-28",
                        "2025-11-25",
                        "2025-06-18",
                        "2024-11-05"
                    ]))
            {
                anyhow::bail!("unsupported 2026 version must return exact -32022 data: {response}");
            }
        }
        "modern.2026-missing-meta"
        | "modern.2026-malformed-meta"
        | "modern.2026-missing-protocol-version"
        | "modern.2026-missing-client-capabilities"
        | "modern.2026-malformed-client-capabilities"
        | "modern.2026-malformed-client-info"
        | "modern.2026-misplaced-top-level-meta"
        | "modern.2026-invalid-meta-key" => {
            if error_code(response) != Some(-32602) {
                anyhow::bail!("invalid 2026 metadata must return -32602: {response}");
            }
        }
        "modern.2026-discover"
        | "modern.2026-client-info-optional"
        | "modern.2026-valid-extension-key" => validate_discovery(response)?,
        "modern.2025-06-tools-list-projection" | "modern.2025-11-tools-list-projection" => {
            let projection = result(response)?;
            require_absent(projection, &["resultType", "ttlMs", "cacheScope"])?;
            if projection
                .get("tools")
                .and_then(Value::as_array)
                .is_none_or(|tools| tools.is_empty())
                || projection.pointer("/tools/0/annotations").is_none()
                || projection.pointer("/tools/0/outputSchema").is_none()
            {
                return Ok(
                    json!({"supported":false,"response":response,"reason":"2025-tool-projection-absent"}),
                );
            }
        }
        "modern.2025-06-structured-recall" | "modern.2025-11-structured-recall" => {
            let projection = result(response)?;
            require_absent(projection, &["resultType", "ttlMs", "cacheScope"])?;
            let Some(structured) = projection.get("structuredContent") else {
                return Ok(
                    json!({"supported":false,"response":response,"reason":"2025-structured-projection-absent"}),
                );
            };
            let contract: Value = serde_json::from_slice(&fs::read(
                suite_root.join("contracts/modern-output-schemas.json"),
            )?)?;
            schema::validate_tool_output(&contract, "icm_memory_recall", structured)?;
        }
        "modern.2025-resources-list-projection" | "modern.2025-resources-read-projection" => {
            let projection = result(response)?;
            require_absent(projection, &["resultType", "ttlMs", "cacheScope"])?;
            if projection.pointer("/_meta/ttlMs").and_then(Value::as_u64) != Some(0)
                || projection
                    .pointer("/_meta/cacheScope")
                    .and_then(Value::as_str)
                    != Some("private")
            {
                anyhow::bail!(
                    "2025 resource projection must be immediately stale/private in result._meta"
                );
            }
        }
        other if is_modern_tool_list_scenario(other) => {
            validate_modern_tool_list(suite_root, other, response)?;
        }
        other
            if other.starts_with("modern.structured-")
                || other == "modern.concise-text-no-duplication" =>
        {
            let modern_result = result(response)?;
            let Some(structured) = modern_result.get("structuredContent") else {
                return Ok(
                    json!({"supported":false,"response":response,"reason":"structuredContent-absent"}),
                );
            };
            require_modern_success(response, false)?;
            require_tool_success_shape(modern_result)?;
            let tool = structured_tool_for_scenario(other);
            let contract: Value = serde_json::from_slice(&fs::read(
                suite_root.join("contracts/modern-output-schemas.json"),
            )?)?;
            schema::validate_tool_output(&contract, tool, structured)?;
            if other == "modern.concise-text-no-duplication" {
                let text = text_content(response)?;
                let structured_json = serde_json::to_string(structured)?;
                if text.len() > thresholds.modern_concise_text_max_bytes
                    || text.contains(&structured_json)
                {
                    anyhow::bail!(
                        "modern text duplicates structured payload or exceeds {} bytes",
                        thresholds.modern_concise_text_max_bytes
                    );
                }
            }
        }
        _ => anyhow::bail!("no modern validator for preregistered scenario {id}"),
    }
    Ok(json!({"supported":true,"response":response}))
}

fn validate_protocol_lifecycle(id: &str, response: &Value) -> Result<Value> {
    if id == "modern.lifecycle-2024-complete" {
        let responses = response
            .get("__lifecycleResponses")
            .and_then(Value::as_array)
            .context("2024 lifecycle wrapper lacks responses")?;
        if responses.len() != 2
            || responses[0]
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                != Some("2024-11-05")
            || responses[1]
                .pointer("/result/tools")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            anyhow::bail!("complete 2024 initialize→initialized→request lifecycle failed");
        }
        require_absent(
            result(&responses[1])?,
            &["resultType", "ttlMs", "cacheScope"],
        )?;
        return Ok(json!({"supported":true,"responses":responses}));
    }
    let (kind, state, method) = match id {
        "modern.lifecycle-tools-list-before-initialize" => {
            ("initialize-required", "uninitialized", "tools/list")
        }
        "modern.lifecycle-tools-call-before-initialize" => {
            ("initialize-required", "uninitialized", "tools/call")
        }
        "modern.lifecycle-request-before-initialized" => (
            "initialized-notification-required",
            "initialize-responded",
            "tools/list",
        ),
        "modern.lifecycle-duplicate-initialized" => (
            "initialized-already-received",
            "protocol-error",
            "notifications/initialized",
        ),
        "modern.lifecycle-second-initialize-era-change" => {
            ("initialize-already-completed", "initialized", "initialize")
        }
        "modern.lifecycle-initialized-before-initialize" => (
            "initialized-before-initialize",
            "protocol-error",
            "notifications/initialized",
        ),
        other => anyhow::bail!("unknown protocol lifecycle scenario {other}"),
    };
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || error_code(response) != Some(LIFECYCLE_VIOLATION_ERROR_CODE)
        || response.pointer("/error/message").and_then(Value::as_str)
            != Some("protocol lifecycle violation; open a new connection")
        || response.pointer("/error/data")
            != Some(&json!({"kind":kind,"state":state,"method":method}))
    {
        anyhow::bail!(
            "protocol lifecycle violation differs from exact frozen envelope: {response}"
        );
    }
    Ok(json!({"supported":true,"response":response}))
}

fn is_modern_tool_list_scenario(id: &str) -> bool {
    matches!(
        id,
        "modern.tools-list-order"
            | "modern.tools-list-annotations"
            | "modern.tools-list-output-schemas"
            | "modern.tools-list-cache-metadata"
            | "modern.tools-list-required-fields"
            | "modern.tools-list-closed-schemas"
            | "modern.annotation-memory-store-destructive"
            | "modern.annotation-memory-recall-destructive"
            | "modern.annotation-read-only-consistency"
            | "modern.annotation-idempotence-consistency"
            | "modern.annotation-open-world-learn-only"
    )
}

fn validate_discovery(response: &Value) -> Result<()> {
    let discovered = require_modern_success(response, true)?;
    if discovered.get("supportedVersions")
        != Some(&json!([
            "2026-07-28",
            "2025-11-25",
            "2025-06-18",
            "2024-11-05"
        ]))
        || discovered.get("capabilities") != Some(&json!({"tools":{},"resources":{}}))
        || discovered
            .get("instructions")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        anyhow::bail!("2026 discovery result differs from exact frozen contract: {response}");
    }
    validate_cache(discovered, 3_600_000, "private")
}

fn validate_modern_tool_list(suite_root: &Path, id: &str, response: &Value) -> Result<()> {
    let modern_result = require_modern_success(response, true)?;
    validate_cache(modern_result, 3_600_000, "private")?;
    let names = tool_names(response)?;
    if names != LEGACY_TOOLS {
        anyhow::bail!("modern tool order changed legacy catalog: {names:?}");
    }
    let tools = modern_result
        .get("tools")
        .and_then(Value::as_array)
        .context("modern tools/list lacks tools")?;
    let annotations: Value = serde_json::from_slice(&fs::read(
        suite_root.join("contracts/tool-annotations.json"),
    )?)?;
    let schemas = if id == "modern.tools-list-output-schemas" {
        Some(serde_json::from_slice::<Value>(&fs::read(
            suite_root.join("contracts/modern-output-schemas.json"),
        )?)?)
    } else {
        None
    };
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .context("modern tool has no name")?;
        if tool.get("annotations") != annotations.get(name) {
            anyhow::bail!("modern annotations differ for {name}");
        }
        if id == "modern.tools-list-required-fields" {
            let actual: BTreeSet<_> = tool
                .pointer("/inputSchema/required")
                .and_then(Value::as_array)
                .context("modern inputSchema.required missing")?
                .iter()
                .filter_map(Value::as_str)
                .collect();
            let expected: BTreeSet<_> = required_fields(name).iter().copied().collect();
            if actual != expected {
                anyhow::bail!("modern required fields differ for {name}: {actual:?}");
            }
        }
        if id == "modern.tools-list-closed-schemas"
            && tool.pointer("/inputSchema/additionalProperties") != Some(&Value::Bool(false))
        {
            anyhow::bail!("modern input schema for {name} is not closed");
        }
        if let Some(expected) = schemas
            .as_ref()
            .and_then(|schemas| schemas.pointer(&format!("/tools/{name}")))
        {
            let advertised = tool
                .get("outputSchema")
                .with_context(|| format!("modern outputSchema missing for {name}"))?;
            schema::verify_independent_schema(advertised).with_context(|| {
                format!("modern outputSchema for {name} is not independently self-contained")
            })?;
            if advertised != expected {
                anyhow::bail!("modern outputSchema differs for {name}");
            }
        }
        if id == "modern.tools-list-closed-schemas"
            && tool.get("outputSchema").is_some_and(|advertised| {
                advertised.get("additionalProperties") != Some(&Value::Bool(false))
            })
        {
            anyhow::bail!("modern output schema for {name} is not closed");
        }
    }
    match id {
        "modern.annotation-memory-store-destructive" => {
            require_annotation(&annotations, "icm_memory_store", "destructiveHint", true)?;
        }
        "modern.annotation-memory-recall-destructive" => {
            require_annotation(&annotations, "icm_memory_recall", "destructiveHint", true)?;
        }
        "modern.annotation-read-only-consistency" => {
            for (tool, value) in annotations
                .as_object()
                .context("annotation object missing")?
            {
                if value.get("readOnlyHint") == Some(&Value::Bool(true))
                    && value.get("destructiveHint") != Some(&Value::Bool(false))
                {
                    anyhow::bail!("read-only tool {tool} is marked destructive");
                }
            }
        }
        "modern.annotation-idempotence-consistency" => {
            require_annotation(&annotations, "icm_memory_forget", "idempotentHint", true)?;
            require_annotation(
                &annotations,
                "icm_transcript_record",
                "idempotentHint",
                false,
            )?;
        }
        "modern.annotation-open-world-learn-only" => {
            for (tool, value) in annotations
                .as_object()
                .context("annotation object missing")?
            {
                let expected = tool == "icm_learn";
                if value.get("openWorldHint") != Some(&Value::Bool(expected)) {
                    anyhow::bail!("open-world annotation differs for {tool}");
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_all_modern_emissions(suite_root: &Path, response: &Value) -> Result<Value> {
    let responses = response
        .get("__evaluationResponses")
        .and_then(Value::as_array)
        .context("aggregate modern emissions wrapper missing")?;
    if responses.first().is_none_or(|first| {
        first.pointer("/result/resultType").and_then(Value::as_str) != Some("complete")
            || first.pointer("/result/structuredContent").is_none()
    }) {
        return Ok(
            json!({"supported":false,"responses":responses,"reason":"structuredContent-absent"}),
        );
    }
    let requests = modern_emission_requests();
    if responses.len() != requests.len() || responses.len() != 11 {
        anyhow::bail!(
            "actual structured emission coverage is {} of 11",
            responses.len()
        );
    }
    let contract: Value = serde_json::from_slice(&fs::read(
        suite_root.join("contracts/modern-output-schemas.json"),
    )?)?;
    for (response, (tool, _)) in responses.iter().zip(requests) {
        let modern_result = require_modern_success(response, false)?;
        require_tool_success_shape(modern_result)?;
        let structured = modern_result
            .get("structuredContent")
            .context("structuredContent missing")?;
        schema::validate_tool_output(&contract, tool, structured)?;
    }
    Ok(json!({"supported":true,"responses":responses,"validatedToolCount":11}))
}

fn require_modern_success(response: &Value, cacheable: bool) -> Result<&Value> {
    let modern_result = result(response)?;
    if modern_result.get("resultType").and_then(Value::as_str) != Some("complete") {
        anyhow::bail!("2026 success result lacks resultType=complete: {response}");
    }
    let server_info = modern_result
        .pointer(&format!(
            "/_meta/{}",
            META_SERVER_INFO.replace('~', "~0").replace('/', "~1")
        ))
        .context("2026 result lacks required product serverInfo metadata")?;
    for field in ["name", "version"] {
        if server_info
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            anyhow::bail!("2026 serverInfo.{field} is absent or empty");
        }
    }
    if !cacheable {
        require_absent(modern_result, &["ttlMs", "cacheScope"])?;
    }
    Ok(modern_result)
}

fn validate_cache(value: &Value, ttl_ms: u64, scope: &str) -> Result<()> {
    if value.get("ttlMs").and_then(Value::as_u64) != Some(ttl_ms)
        || value.get("cacheScope").and_then(Value::as_str) != Some(scope)
        || !matches!(scope, "public" | "private")
    {
        anyhow::bail!("cache metadata differs: expected ttlMs={ttl_ms}, cacheScope={scope}");
    }
    Ok(())
}

fn require_absent(value: &Value, fields: &[&str]) -> Result<()> {
    for field in fields {
        if value.get(*field).is_some() {
            anyhow::bail!("field {field} must be absent in this protocol projection");
        }
    }
    Ok(())
}

fn require_tool_success_shape(value: &Value) -> Result<()> {
    if value.get("content").and_then(Value::as_array).is_none()
        || value
            .get("isError")
            .is_some_and(|is_error| is_error != &Value::Bool(false))
    {
        anyhow::bail!("modern successful tool result has invalid content/isError shape");
    }
    Ok(())
}

fn require_annotation(annotations: &Value, tool: &str, field: &str, expected: bool) -> Result<()> {
    if annotations.pointer(&format!("/{tool}/{field}")) != Some(&Value::Bool(expected)) {
        anyhow::bail!("annotation {tool}.{field} differs from {expected}");
    }
    Ok(())
}

fn validate_resource(
    id: &str,
    response: &Value,
    thresholds: &crate::design::AcceptanceThresholds,
) -> Result<Value> {
    if id == "resource.no-templates-capability" {
        if error_code(response) == Some(-32601) {
            return Ok(
                json!({"supported":false,"response":response,"reason":"server-discover-method-not-found"}),
            );
        }
        validate_discovery(response)?;
        if response
            .pointer("/result/capabilities/resourceTemplates")
            .is_some()
            || response
                .pointer("/result/capabilities/resources/templates")
                .is_some()
        {
            anyhow::bail!(
                "resource templates were advertised despite the frozen no-template contract"
            );
        }
        return Ok(json!({"supported":true,"response":response}));
    }
    if id == "resource.templates-method-not-found" {
        if error_code(response) != Some(-32601) {
            anyhow::bail!("unadvertised resources/templates/list must return -32601");
        }
        return Ok(json!({"supported":true,"response":response}));
    }
    if error_code(response) == Some(-32601) {
        return Ok(
            json!({"supported":false,"response":response,"reason":"resources-method-not-found"}),
        );
    }

    let invalid_uri = match id {
        "resource.malformed-uri" => Some("not a valid uri"),
        "resource.unknown-uri" | "resource.error-data-sanitized" => {
            Some("icm://active-project/unknown")
        }
        "resource.uri-trailing-slash" => Some("icm://active-project/context/"),
        "resource.uri-query" => Some("icm://active-project/context?topic=x"),
        "resource.uri-fragment" => Some("icm://active-project/context#fragment"),
        "resource.uri-user-info" => Some("icm://user@active-project/context"),
        "resource.uri-authority-case" => Some("icm://ACTIVE-PROJECT/context"),
        _ => None,
    };
    if let Some(requested) = invalid_uri {
        if error_code(response) != Some(-32602)
            || response.pointer("/error/data") != Some(&json!({"uri":requested}))
        {
            anyhow::bail!("invalid/unknown 2026 resource URI must return exact -32602 data");
        }
        let serialized = serde_json::to_string(response)?;
        for forbidden in ["sqlite", "SELECT ", "database/", "synthetic-home"] {
            if serialized.contains(forbidden) {
                anyhow::bail!("resource URI error leaked internal detail {forbidden:?}");
            }
        }
        return Ok(json!({"supported":true,"response":response}));
    }
    if id == "resource.caller-max-tokens-rejected" {
        if error_code(response) != Some(-32602) {
            anyhow::bail!("nonstandard resource maxTokens must be rejected with -32602");
        }
        return Ok(json!({"supported":true,"response":response}));
    }
    if id == "resource.internal-failure" {
        if error_code(response) != Some(-32603) {
            anyhow::bail!("resource internal failure must return -32603: {response}");
        }
        let serialized = serde_json::to_string(response)?;
        for forbidden in ["sqlite", "SQL", "database/", "memories"] {
            if serialized.contains(forbidden) {
                anyhow::bail!("resource internal error leaked {forbidden:?}");
            }
        }
        return Ok(json!({"supported":true,"response":response}));
    }
    if matches!(
        id,
        "resource.list-single-fixed-uri" | "resource.descriptor-exact"
    ) {
        let resource_result = require_modern_success(response, true)?;
        validate_cache(resource_result, 3_600_000, "private")?;
        let resources = resource_result
            .get("resources")
            .and_then(Value::as_array)
            .context("resources/list missing resources")?;
        if resources.len() != 1 {
            anyhow::bail!("resources/list must return exactly one fixed descriptor");
        }
        let descriptor = resources[0]
            .as_object()
            .context("resource descriptor is not an object")?;
        require_exact_keys(
            descriptor,
            &[
                "uri",
                "name",
                "title",
                "description",
                "mimeType",
                "annotations",
            ],
            "resource descriptor",
        )?;
        if descriptor.get("uri").and_then(Value::as_str) != Some("icm://active-project/context")
            || descriptor.get("name").and_then(Value::as_str) != Some("active-project-context")
            || descriptor.get("mimeType").and_then(Value::as_str) != Some("application/json")
            || descriptor
                .get("title")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || descriptor
                .get("description")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || descriptor
                .get("annotations")
                .and_then(|annotations| annotations.get("audience"))
                != Some(&json!(["assistant"]))
            || descriptor
                .get("annotations")
                .and_then(|annotations| annotations.get("priority"))
                .and_then(Value::as_f64)
                != Some(1.0)
        {
            anyhow::bail!("resource descriptor differs from the exact frozen contract");
        }
        return Ok(json!({"supported":true,"response":response}));
    }

    let parsed = validate_resource_read(response, thresholds)?;
    let text = response
        .pointer("/result/contents/0/text")
        .and_then(Value::as_str)
        .context("validated resource text disappeared")?;
    let memories = parsed
        .get("memories")
        .and_then(Value::as_array)
        .context("validated resource memories disappeared")?;
    let topics = parsed
        .get("topics")
        .and_then(Value::as_array)
        .context("validated resource topics disappeared")?;
    let summaries: Vec<_> = memories
        .iter()
        .filter_map(|memory| memory.get("summary").and_then(Value::as_str))
        .collect();
    let ids: BTreeSet<_> = memories
        .iter()
        .filter_map(|memory| memory.get("id").and_then(Value::as_str))
        .collect();
    let reasons: BTreeSet<_> = parsed
        .get("truncationReasons")
        .and_then(Value::as_array)
        .context("truncation reasons missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    match id {
        "resource.read-values" | "resource.includes-context-topic" => {
            if !summaries
                .iter()
                .any(|summary| summary.contains("SQLite WAL"))
            {
                anyhow::bail!("context resource missed exact context- project row");
            }
        }
        "resource.empty" => {
            if !memories.is_empty()
                || parsed.get("truncated") != Some(&Value::Bool(false))
                || parsed.get("truncationReasons") != Some(&json!([]))
                || parsed.get("omittedAtLeast").and_then(Value::as_u64) != Some(0)
            {
                anyhow::bail!("empty resource is not the explicit frozen empty DTO");
            }
        }
        "resource.excludes-preferences" => {
            if text.contains("concise and evidence") {
                anyhow::bail!("context resource leaked preferences");
            }
        }
        "resource.excludes-other-project" => {
            if text.contains("ORCHID-LEAK") {
                anyhow::bail!("context resource leaked another project");
            }
        }
        "resource.exact-project-topic-scope" => {
            if topics
                != json!([
                    "context-eval-project",
                    "contexte-eval-project",
                    "decisions-eval-project"
                ])
                .as_array()
                .expect("literal array")
                || !ids.contains("01J00000000000000000000001")
                || ids.contains("01J00000000000000000000003")
                || ids.contains("01J00000000000000000000005")
            {
                anyhow::bail!("resource exact topic/project/scope selection differs");
            }
        }
        "resource.includes-contexte-topic" => {
            if !summaries
                .iter()
                .any(|summary| summary.contains("Compatibility namespace"))
            {
                anyhow::bail!("contexte- compatibility namespace was not included");
            }
        }
        "resource.includes-decisions-topic" => {
            if !summaries
                .iter()
                .any(|summary| summary.contains("decision namespace"))
            {
                anyhow::bail!("decisions- namespace was not included");
            }
        }
        "resource.excludes-bare-project" => reject_resource_trap(text, "BARE-PROJECT-TRAP")?,
        "resource.excludes-prefix-subtopic" => reject_resource_trap(text, "PREFIX-SUBTOPIC-TRAP")?,
        "resource.excludes-suffix-alias" => reject_resource_trap(text, "SUFFIX-ALIAS-TRAP")?,
        "resource.excludes-errors-resolved" => reject_resource_trap(text, "GLOBAL-ERROR-TRAP")?,
        "resource.token-truncation" => {
            if parsed.get("truncated") != Some(&Value::Bool(true))
                || !reasons.contains("tokenBudget")
                || parsed
                    .get("omittedAtLeast")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    == 0
            {
                anyhow::bail!("large resource fixture did not prove token-budget truncation");
            }
        }
        "resource.bounded-read" | "resource.row-limit" => {
            if memories.len() > 64 || !reasons.contains("rowLimit") {
                anyhow::bail!("resource did not prove bounded rowLimit+1 access");
            }
        }
        "resource.field-limit" => {
            if !reasons.contains("fieldLimit")
                || !memories
                    .iter()
                    .any(|memory| memory.get("fieldTruncated") == Some(&Value::Bool(true)))
            {
                anyhow::bail!("resource did not expose bounded field truncation");
            }
        }
        "resource.no-force-first" => {
            if text.len() > thresholds.resource_max_wire_bytes
                || parsed
                    .pointer("/budget/usedPortableTokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX)
                    > thresholds.resource_max_portable_tokens as u64
            {
                anyhow::bail!("resource force-included an item beyond the hard budget");
            }
        }
        "resource.prompt-injection-sanitized" => {
            if text.contains("\n--- RESOURCE-FORGE") || !text.contains("\\n--- RESOURCE-FORGE") {
                anyhow::bail!("resource JSON did not escape the synthetic prompt delimiter");
            }
        }
        "resource.cache-metadata"
        | "resource.budget-accounting-exact"
        | "resource.wire-byte-budget"
        | "resource.read-only-access-count" => {}
        _ => {}
    }
    Ok(json!({
        "supported":true,
        "response":response,
        "resourceTextBytes":text.len(),
        "usedPortableTokens":parsed.pointer("/budget/usedPortableTokens")
    }))
}

fn validate_resource_read(
    response: &Value,
    thresholds: &crate::design::AcceptanceThresholds,
) -> Result<Value> {
    let resource_result = require_modern_success(response, true)?;
    validate_cache(resource_result, 0, "private")?;
    let contents = resource_result
        .get("contents")
        .and_then(Value::as_array)
        .context("resources/read missing contents")?;
    if contents.len() != 1
        || contents[0].get("uri").and_then(Value::as_str) != Some("icm://active-project/context")
        || contents[0].get("mimeType").and_then(Value::as_str) != Some("application/json")
    {
        anyhow::bail!("resource read did not return one exact JSON content item");
    }
    let text = contents[0]
        .get("text")
        .and_then(Value::as_str)
        .context("resource JSON text missing")?;
    let text_bytes = text.len();
    if text_bytes > thresholds.resource_max_wire_bytes
        || text_bytes > thresholds.resource_max_portable_tokens
    {
        anyhow::bail!(
            "resource text is {text_bytes} bytes, above typed portable/wire bounds {}/{}",
            thresholds.resource_max_portable_tokens,
            thresholds.resource_max_wire_bytes
        );
    }
    let parsed: Value = serde_json::from_str(text).context("resource text is not valid JSON")?;
    let object = parsed
        .as_object()
        .context("resource JSON root is not an object")?;
    require_exact_keys(
        object,
        &[
            "project",
            "topics",
            "memories",
            "truncated",
            "truncationReasons",
            "omittedAtLeast",
            "budget",
        ],
        "active-project context",
    )?;
    if parsed.get("project").and_then(Value::as_str) != Some("eval-project")
        || parsed.get("topics")
            != Some(&json!([
                "context-eval-project",
                "contexte-eval-project",
                "decisions-eval-project"
            ]))
        || !parsed.get("truncated").is_some_and(Value::is_boolean)
        || parsed
            .get("omittedAtLeast")
            .and_then(Value::as_u64)
            .is_none()
    {
        anyhow::bail!("active-project context root fields differ from frozen DTO");
    }
    let budget = parsed
        .get("budget")
        .and_then(Value::as_object)
        .context("resource budget is not an object")?;
    require_exact_keys(
        budget,
        &["maxPortableTokens", "usedPortableTokens", "algorithm"],
        "resource budget",
    )?;
    if budget.get("maxPortableTokens").and_then(Value::as_u64)
        != Some(thresholds.resource_max_portable_tokens as u64)
        || budget.get("usedPortableTokens").and_then(Value::as_u64) != Some(text_bytes as u64)
        || budget.get("algorithm").and_then(Value::as_str) != Some("utf8-bytes-v1")
    {
        anyhow::bail!("resource budget does not use exact utf8-bytes-v1 accounting");
    }
    let reasons = parsed
        .get("truncationReasons")
        .and_then(Value::as_array)
        .context("resource truncationReasons is not an array")?;
    let mut unique_reasons = BTreeSet::new();
    for reason in reasons {
        let reason = reason
            .as_str()
            .context("resource truncation reason is not a string")?;
        if !matches!(reason, "rowLimit" | "fieldLimit" | "tokenBudget")
            || !unique_reasons.insert(reason)
        {
            anyhow::bail!("resource truncation reason is invalid or duplicated: {reason}");
        }
    }
    let memories = parsed
        .get("memories")
        .and_then(Value::as_array)
        .context("resource memories is not an array")?;
    for memory in memories {
        let object = memory
            .as_object()
            .context("resource memory is not an object")?;
        require_exact_keys(
            object,
            &[
                "id",
                "topic",
                "summary",
                "importance",
                "weight",
                "updatedAt",
                "fieldTruncated",
            ],
            "resource memory",
        )?;
        if !memory.get("fieldTruncated").is_some_and(Value::is_boolean)
            || !matches!(
                memory.get("importance").and_then(Value::as_str),
                Some("critical" | "high" | "medium" | "low")
            )
            || chrono::DateTime::parse_from_rfc3339(
                memory
                    .get("updatedAt")
                    .and_then(Value::as_str)
                    .context("resource memory updatedAt missing")?,
            )
            .is_err()
        {
            anyhow::bail!("resource memory field type differs from frozen DTO");
        }
    }
    Ok(parsed)
}

fn require_exact_keys(
    object: &serde_json::Map<String, Value>,
    expected: &[&str],
    label: &str,
) -> Result<()> {
    let actual: BTreeSet<_> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if actual != expected {
        anyhow::bail!("{label} keys differ: {actual:?} != {expected:?}");
    }
    Ok(())
}

fn reject_resource_trap(text: &str, trap: &str) -> Result<()> {
    if text.contains(trap) {
        anyhow::bail!("resource leaked excluded topic trap {trap}");
    }
    Ok(())
}

const LEGACY_TOOLS: &[&str] = &[
    "icm_memory_store",
    "icm_memory_recall",
    "icm_memory_forget",
    "icm_memory_forget_topic",
    "icm_learn",
    "icm_memory_consolidate",
    "icm_memory_list_topics",
    "icm_memory_stats",
    "icm_memory_update",
    "icm_memory_health",
    "icm_memoir_create",
    "icm_memoir_list",
    "icm_memoir_show",
    "icm_memoir_add_concept",
    "icm_memoir_refine",
    "icm_memoir_search",
    "icm_memoir_link",
    "icm_memoir_inspect",
    "icm_memoir_export",
    "icm_memory_extract_patterns",
    "icm_memoir_search_all",
    "icm_feedback_record",
    "icm_feedback_search",
    "icm_feedback_stats",
    "icm_transcript_start_session",
    "icm_transcript_record",
    "icm_transcript_search",
    "icm_transcript_show",
    "icm_transcript_stats",
    "icm_wake_up",
];

fn required_fields(tool: &str) -> &'static [&'static str] {
    match tool {
        "icm_memory_store" => &["topic", "content"],
        "icm_memory_recall" => &["query"],
        "icm_memory_forget" => &["id"],
        "icm_memory_forget_topic" => &["topic"],
        "icm_memory_consolidate" => &["topic", "summary"],
        "icm_memory_update" => &["id", "content"],
        "icm_memoir_create" => &["name"],
        "icm_memoir_show" => &["name"],
        "icm_memoir_add_concept" | "icm_memoir_refine" => &["memoir", "name", "definition"],
        "icm_memoir_search" => &["memoir", "query"],
        "icm_memoir_link" => &["memoir", "from", "to", "relation"],
        "icm_memoir_inspect" => &["memoir", "name"],
        "icm_memoir_export" => &["name"],
        "icm_memory_extract_patterns" => &["topic"],
        "icm_memoir_search_all" => &["query"],
        "icm_feedback_record" => &["topic", "context", "predicted", "corrected"],
        "icm_feedback_search" => &["query"],
        "icm_transcript_record" => &["session_id", "role", "content"],
        "icm_transcript_search" => &["query"],
        "icm_transcript_show" => &["session_id"],
        _ => &[],
    }
}

fn tool_names(response: &Value) -> Result<Vec<&str>> {
    result(response)?
        .get("tools")
        .and_then(Value::as_array)
        .context("tools/list response has no tools array")?
        .iter()
        .map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .context("tool has no name")
        })
        .collect()
}

fn require_tool_error(response: &Value) -> Result<()> {
    if response.pointer("/result/isError") != Some(&Value::Bool(true)) {
        anyhow::bail!("expected MCP tool error: {response}");
    }
    Ok(())
}

fn require_error_code(response: &Value, expected: i64) -> Result<()> {
    if error_code(response) != Some(expected) {
        anyhow::bail!("expected JSON-RPC error {expected}: {response}");
    }
    Ok(())
}

fn modern_tool_call(
    client: &mut McpClient,
    id: u64,
    name: &str,
    arguments: Value,
) -> Result<Value> {
    client.request_2026(id, "tools/call", json!({"name":name,"arguments":arguments}))
}

fn modern_emission_requests() -> Vec<(&'static str, Value)> {
    vec![
        (
            "icm_memory_recall",
            json!({"query":"SQLite WAL","project":"","limit":3}),
        ),
        ("icm_memory_list_topics", json!({})),
        ("icm_memory_stats", json!({})),
        (
            "icm_transcript_start_session",
            json!({"agent":"modern-aggregate","project":"eval-project"}),
        ),
        (
            "icm_transcript_record",
            json!({"session_id":"synthetic-session-fixed-001","role":"user","content":"aggregate emission"}),
        ),
        (
            "icm_transcript_search",
            json!({"query":"SQLite WAL","project":"eval-project","limit":10}),
        ),
        (
            "icm_transcript_show",
            json!({"session_id":"synthetic-session-fixed-001"}),
        ),
        ("icm_transcript_stats", json!({})),
        (
            "icm_feedback_record",
            json!({"topic":"modern","context":"aggregate","predicted":"a","corrected":"b","reason":null,"source":"eval"}),
        ),
        (
            "icm_feedback_search",
            json!({"query":"documentation reviewer","limit":10}),
        ),
        ("icm_feedback_stats", json!({})),
    ]
}

fn structured_tool_for_scenario(id: &str) -> &'static str {
    match id {
        "modern.structured-memory-list" => "icm_memory_list_topics",
        "modern.structured-memory-stats" => "icm_memory_stats",
        "modern.structured-transcript-start" => "icm_transcript_start_session",
        "modern.structured-transcript-record" => "icm_transcript_record",
        "modern.structured-transcript-search" => "icm_transcript_search",
        "modern.structured-transcript-show" => "icm_transcript_show",
        "modern.structured-transcript-stats" => "icm_transcript_stats",
        "modern.structured-feedback-record" => "icm_feedback_record",
        "modern.structured-feedback-search" => "icm_feedback_search",
        "modern.structured-feedback-stats" => "icm_feedback_stats",
        _ => "icm_memory_recall",
    }
}

fn deterministic_legacy(id: &str) -> bool {
    !matches!(
        id,
        "legacy.transcript-start" | "legacy.transcript-record-all-roles" | "legacy.feedback-record"
    )
}

fn normalize_transcript(exchanges: &[Exchange], state: &FixtureState) -> String {
    let mut text = exchanges
        .iter()
        .filter_map(|exchange| exchange.response.as_deref())
        .collect::<String>();
    for id in &state.generated_message_ids {
        text = text.replace(id, "<GENERATED_MESSAGE_ID>");
    }
    let mut timestamps = state.generated_timestamp_spellings.clone();
    timestamps.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for timestamp in timestamps {
        text = text.replace(&timestamp, "<GENERATED_TRANSCRIPT_TIMESTAMP>");
    }
    text
}

fn empty_fixture_state() -> FixtureState {
    FixtureState {
        project_name: "eval-project".into(),
        generated_message_ids: vec![],
        generated_timestamp_spellings: vec![],
    }
}

fn evidence_hash(detail: &Value, transcript: &str) -> Result<String> {
    let mut bytes = serde_json::to_vec(detail)?;
    bytes.extend_from_slice(transcript.as_bytes());
    Ok(sha256_bytes(&bytes))
}

fn wire_unsupported_evidence(exchanges: &[Exchange]) -> Option<UnsupportedEvidence> {
    let mut methods = Vec::new();
    let mut statuses = Vec::new();
    let mut response_count = 0;
    for exchange in exchanges {
        let request: Value = serde_json::from_str(exchange.request.trim_end()).ok()?;
        if let Some(method) = request.get("method").and_then(Value::as_str) {
            methods.push(method.to_owned());
        }
        if let Some(raw) = &exchange.response {
            let response: Value = serde_json::from_str(raw.trim_end()).ok()?;
            response_count += 1;
            if let Some(code) = error_code(&response) {
                statuses.push(format!("error:{code}"));
            } else if response.get("result").is_some() {
                statuses.push("result".to_owned());
            } else {
                statuses.push("invalid-envelope".to_owned());
            }
        }
    }
    (!methods.is_empty() && response_count > 0).then_some(UnsupportedEvidence::Wire {
        methods,
        statuses,
        response_count,
    })
}

fn cli_unsupported_evidence(
    capture: &CommandCapture,
    arguments: &[&str],
) -> Option<UnsupportedEvidence> {
    let exit_code = capture.exit_code?;
    (!arguments.is_empty()).then_some(UnsupportedEvidence::Cli {
        arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
        exit_code,
    })
}

fn validate_unsupported_evidence(evidence: &UnsupportedEvidence) -> Result<()> {
    match evidence {
        UnsupportedEvidence::Wire {
            methods,
            statuses,
            response_count,
        } => {
            if methods.is_empty()
                || *response_count == 0
                || statuses.len() != *response_count
                || methods.iter().any(String::is_empty)
                || statuses
                    .iter()
                    .any(|status| status != "result" && !status.starts_with("error:"))
            {
                anyhow::bail!("wire unsupported evidence lacks recognized method/status");
            }
        }
        UnsupportedEvidence::Cli {
            arguments,
            exit_code,
        } => {
            if arguments.is_empty() || arguments.iter().any(String::is_empty) || *exit_code == 0 {
                anyhow::bail!("CLI unsupported evidence lacks command/nonzero exit code");
            }
        }
    }
    Ok(())
}

fn native_relative(relative: &str) -> PathBuf {
    relative
        .split(['/', '\\'])
        .filter(|component| !component.is_empty() && *component != ".")
        .fold(PathBuf::new(), |path, component| path.join(component))
}

fn provider_document_paths(
    sandbox: &ScenarioSandbox,
    scope: &ProviderScopeFixture,
) -> Result<Vec<PathBuf>> {
    provider_document_paths_for_platform(sandbox, scope, current_platform_family())
}

fn provider_document_paths_for_platform(
    sandbox: &ScenarioSandbox,
    scope: &ProviderScopeFixture,
    platform: PlatformFamily,
) -> Result<Vec<PathBuf>> {
    scope
        .documents
        .iter()
        .map(|document| {
            let root = provider_symbolic_root(sandbox, &document.root, platform)?;
            Ok(root.join(native_relative(&document.relative_path)))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlatformFamily {
    Linux,
    Macos,
    Windows,
}

fn current_platform_family() -> PlatformFamily {
    if cfg!(target_os = "windows") {
        PlatformFamily::Windows
    } else if cfg!(target_os = "macos") {
        PlatformFamily::Macos
    } else {
        PlatformFamily::Linux
    }
}

fn sandbox_env_path(sandbox: &ScenarioSandbox, key: &str) -> Result<PathBuf> {
    sandbox
        .environment
        .get(std::ffi::OsStr::new(key))
        .map(PathBuf::from)
        .with_context(|| format!("sandbox lacks {key}"))
}

fn provider_symbolic_root(
    sandbox: &ScenarioSandbox,
    symbol: &str,
    platform: PlatformFamily,
) -> Result<PathBuf> {
    let home = sandbox.home.clone();
    let xdg_config = sandbox_env_path(sandbox, "XDG_CONFIG_HOME")?;
    let appdata = sandbox_env_path(sandbox, "APPDATA")?;
    Ok(match symbol {
        "project" => sandbox.cwd.clone(),
        "home" | "claude-user-home" => home,
        "xdg-config" => xdg_config,
        "xdg-data" => sandbox_env_path(sandbox, "XDG_DATA_HOME")?,
        "appdata" => appdata,
        "codex-user-config" => sandbox_env_path(sandbox, "CODEX_HOME")?,
        "claude-user-config" => sandbox_env_path(sandbox, "CLAUDE_CONFIG_DIR")?,
        "cursor-user-config" => home.join(".cursor"),
        "opencode-user-config" => match platform {
            PlatformFamily::Linux => xdg_config.join("opencode"),
            PlatformFamily::Macos => home.join("Library/Application Support/opencode"),
            PlatformFamily::Windows => appdata.join("opencode"),
        },
        "zed-user-config" => match platform {
            PlatformFamily::Linux => xdg_config.join("zed"),
            PlatformFamily::Macos => home.join("Library/Application Support/Zed"),
            PlatformFamily::Windows => appdata.join("Zed"),
        },
        other => anyhow::bail!("unknown provider document root {other}"),
    })
}

fn provider_manifest_path(sandbox: &ScenarioSandbox, fixture: &ProviderFixture) -> Result<PathBuf> {
    provider_manifest_path_for_platform(sandbox, fixture, current_platform_family())
}

fn provider_manifest_path_for_platform(
    sandbox: &ScenarioSandbox,
    fixture: &ProviderFixture,
    platform: PlatformFamily,
) -> Result<PathBuf> {
    let key = match platform {
        PlatformFamily::Linux => "linux",
        PlatformFamily::Macos => "macos",
        PlatformFamily::Windows => "windows",
    };
    let spec = fixture
        .manifest_paths
        .get(key)
        .with_context(|| format!("provider fixture lacks {key} manifest path"))?;
    let root = provider_symbolic_root(sandbox, &spec.root, platform)?;
    Ok(root.join(native_relative(&spec.relative_path)))
}

fn prepare_provider_adversary(
    case_id: &str,
    provider: &str,
    scope: &ProviderScopeFixture,
    paths: &[PathBuf],
) -> Result<()> {
    match case_id {
        "malformed-config-zero-write" => {
            for (document, path) in scope.documents.iter().zip(paths) {
                fs::write(
                    path,
                    if document.format == "toml" {
                        "[broken"
                    } else {
                        "{broken"
                    },
                )?;
            }
        }
        "unknown-dialect-zero-write" => {
            for (document, path) in scope.documents.iter().zip(paths) {
                let value = match (provider, document.format.as_str(), document.role.as_str()) {
                    ("codex", "toml", _) => "[sentinel]\nkeep = \"unknown-dialect-unchanged\"\n\n[permissions]\nallow = [\"mcp__foreign__tool\"]\n",
                    ("claude-code" | "cursor", "json", "permission") => "{\"sentinel\":{\"keep\":\"unknown-dialect-unchanged\"},\"permission\":[{\"action\":\"foreign_*\",\"resource\":\"*\",\"effect\":\"allow\"}]}",
                    ("opencode", "json", _) => "{\"sentinel\":{\"keep\":\"unknown-dialect-unchanged\"},\"mcp\":{\"servers\":{}},\"permission\":{\"foreign_*\":\"allow\"},\"permissions\":[{\"action\":\"foreign_*\",\"resource\":\"*\",\"effect\":\"allow\"}]}",
                    ("zed", "json", _) => "{\"sentinel\":{\"keep\":\"unknown-dialect-unchanged\"},\"context_servers\":{},\"agent\":{\"tool_permissions\":[{\"tool\":\"foreign\",\"effect\":\"allow\"}]}}",
                    (_, _, _) => continue,
                };
                fs::write(path, value)?;
            }
        }
        "symlink-reparse-zero-write" => {
            #[cfg(windows)]
            {
                // Windows reparse metadata is injected by the non-shippable
                // support hook in run_provider_scope; no elevated symlink API
                // is used by the portable evaluator.
                let _ = (scope, paths);
                return Ok(());
            }
            #[cfg(not(windows))]
            {
                let first = paths
                    .first()
                    .context("provider has no configuration document")?;
                let target = first.with_file_name("symlink-target.fixture");
                fs::write(&target, fs::read(first)?)?;
                fs::remove_file(first)?;
                create_file_symlink(&target, first)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link)?;
    Ok(())
}

fn read_document_set(
    scope: &ProviderScopeFixture,
    paths: &[PathBuf],
) -> Result<BTreeMap<String, Vec<u8>>> {
    scope
        .documents
        .iter()
        .zip(paths)
        .map(|(document, path)| {
            Ok((
                format!("{}:{}", document.role, document.relative_path),
                fs::read(path)
                    .with_context(|| format!("reading provider document {}", path.display()))?,
            ))
        })
        .collect()
}

fn read_path_set(paths: &[PathBuf]) -> Result<BTreeMap<String, Vec<u8>>> {
    paths
        .iter()
        .map(|path| {
            Ok((
                path.to_string_lossy().into_owned(),
                fs::read(path)
                    .with_context(|| format!("reading watched provider path {}", path.display()))?,
            ))
        })
        .collect()
}

fn seed_dynamic_provider_adversary(
    case_id: &str,
    provider: &ProviderCase,
    scope: &ProviderScopeFixture,
    sandbox: &ScenarioSandbox,
    server_id: &str,
    document_paths: &[PathBuf],
    fixture: &ProviderFixture,
) -> Result<Vec<PathBuf>> {
    match case_id {
        "external-equal-adopted-not-owned" => {
            seed_provider_values(
                &provider.id,
                scope,
                document_paths,
                &[server_id],
                &fixture.owned_tools,
                true,
            )?;
            Ok(Vec::new())
        }
        "normalization-collision-fails-closed" => {
            seed_provider_values(
                &provider.id,
                scope,
                document_paths,
                &["icm-a", "icm_a"],
                &fixture.owned_tools,
                true,
            )?;
            Ok(Vec::new())
        }
        "shadowing-fails-closed" => {
            let alternate = provider
                .scopes
                .iter()
                .find(|candidate| candidate.scope != scope.scope)
                .context("provider fixture lacks alternate real scope")?;
            let alternate_paths = provider_document_paths(sandbox, alternate)?;
            for (document, path) in alternate.documents.iter().zip(&alternate_paths) {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, &document.initial)?;
            }
            seed_provider_values(
                &provider.id,
                alternate,
                &alternate_paths,
                &[server_id],
                &fixture.owned_tools,
                true,
            )?;
            Ok(alternate_paths)
        }
        "ambiguous-path-zero-write" => {
            let alternate_paths: Vec<_> = scope
                .documents
                .iter()
                .zip(document_paths)
                .map(|(document, path)| {
                    if document.format == "toml" {
                        path.with_file_name("config.local.toml")
                    } else {
                        path.with_extension("jsonc")
                    }
                })
                .collect();
            for (document, path) in scope.documents.iter().zip(&alternate_paths) {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, &document.initial)?;
            }
            seed_provider_values(
                &provider.id,
                scope,
                document_paths,
                &[server_id],
                &fixture.owned_tools,
                true,
            )?;
            seed_provider_values(
                &provider.id,
                scope,
                &alternate_paths,
                &[server_id],
                &fixture.owned_tools,
                true,
            )?;
            Ok(alternate_paths)
        }
        _ => Ok(Vec::new()),
    }
}

fn seed_provider_values(
    provider: &str,
    scope: &ProviderScopeFixture,
    paths: &[PathBuf],
    server_ids: &[&str],
    tools: &[String],
    include_permissions: bool,
) -> Result<()> {
    for (document, path) in scope.documents.iter().zip(paths) {
        let text = fs::read_to_string(path)?;
        if document.format == "toml" {
            if provider != "codex" {
                anyhow::bail!("only Codex uses the frozen TOML provider dialect");
            }
            let mut output = text;
            for server_id in server_ids {
                output.push_str(&format!(
                    "\n[mcp_servers.{server_id}]\ncommand = \"external-icm-command\"\nenabled_tools = [{}]\n",
                    tools
                        .iter()
                        .map(|tool| format!("\"{tool}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                if include_permissions {
                    for tool in tools {
                        output.push_str(&format!(
                            "\n[mcp_servers.{server_id}.tools.{tool}]\napproval_mode = \"approve\"\n"
                        ));
                    }
                }
            }
            fs::write(path, output)?;
            continue;
        }

        let mut value: Value = serde_json::from_str(&text)?;
        let object = value
            .as_object_mut()
            .context("provider document root is not an object")?;
        for server_id in server_ids {
            if document.role.contains("registration") {
                match provider {
                    "claude-code" | "cursor" => {
                        object
                            .entry("mcpServers")
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .context("mcpServers is not an object")?
                            .insert(
                                (*server_id).to_owned(),
                                json!({"command":"external-icm-command"}),
                            );
                    }
                    "opencode" => {
                        object
                            .entry("mcp")
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .context("OpenCode mcp is not an object")?
                            .entry("servers")
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .context("OpenCode mcp.servers is not an object")?
                            .insert(
                                (*server_id).to_owned(),
                                json!({"command":"external-icm-command"}),
                            );
                    }
                    "zed" => {
                        object
                            .entry("context_servers")
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .context("Zed context_servers is not an object")?
                            .insert(
                                (*server_id).to_owned(),
                                json!({"command":"external-icm-command"}),
                            );
                    }
                    other => anyhow::bail!("unknown JSON provider {other}"),
                }
            }
        }
        if include_permissions && document.role.contains("permission") {
            match provider {
                "claude-code" | "cursor" => {
                    let allow = object
                        .entry("permissions")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .context("permissions is not an object")?
                        .entry("allow")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .context("permissions.allow is not an array")?;
                    for server_id in server_ids {
                        for tool in tools {
                            let rule = if provider == "claude-code" {
                                format!("mcp__{server_id}__{tool}")
                            } else {
                                format!("Mcp({server_id}:{tool})")
                            };
                            if !allow.contains(&Value::String(rule.clone())) {
                                allow.push(Value::String(rule));
                            }
                        }
                    }
                }
                "opencode" => {
                    let permission = object
                        .entry("permission")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .context("OpenCode permission is not an array")?;
                    for server_id in server_ids {
                        let normalized = server_id.replace('-', "_");
                        for tool in tools {
                            permission.push(json!({
                                "action":format!("{normalized}_{tool}"),
                                "resource":"*",
                                "effect":"allow"
                            }));
                        }
                    }
                }
                "zed" => {
                    let tool_permissions = object
                        .entry("agent")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .context("Zed agent is not an object")?
                        .entry("tool_permissions")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .context("Zed tool_permissions is not an object")?
                        .entry("tools")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .context("Zed tool permissions tools is not an object")?;
                    for server_id in server_ids {
                        for tool in tools {
                            tool_permissions.insert(
                                format!("mcp:{server_id}:{tool}"),
                                json!({"default":"allow"}),
                            );
                        }
                    }
                }
                other => anyhow::bail!("unknown permission provider {other}"),
            }
        }
        fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    }
    Ok(())
}

fn hash_document_set(documents: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    documents
        .iter()
        .map(|(name, bytes)| (name.clone(), sha256_bytes(bytes)))
        .collect()
}

fn normalize_sandbox_path(path: &Path, sandbox: &ScenarioSandbox) -> String {
    path.to_string_lossy()
        .replace(sandbox.root.to_string_lossy().as_ref(), "<SCENARIO_ROOT>")
}

fn parse_provider_plan(stdout: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(stdout.trim())
        .with_context(|| format!("provider command stdout is not one JSON object: {stdout:?}"))?;
    let plan = value.get("resolvedPlan").unwrap_or(&value);
    if !plan.is_object() {
        anyhow::bail!("provider resolvedPlan is not an object");
    }
    Ok(plan.clone())
}

fn validate_provider_plan(
    plan: &Value,
    provider: &ProviderCase,
    scope: &ProviderScopeFixture,
    document_paths: &[PathBuf],
    fixture: &ProviderFixture,
    sandbox: &ScenarioSandbox,
) -> Result<()> {
    require_exact_keys(
        plan.as_object()
            .context("provider resolved plan is not an object")?,
        &[
            "paths",
            "surface",
            "scope",
            "dialect",
            "serverId",
            "toolRules",
            "blockingRules",
            "ownershipDisposition",
        ],
        "provider resolved plan",
    )?;
    for field in [
        "paths",
        "surface",
        "scope",
        "dialect",
        "serverId",
        "toolRules",
        "blockingRules",
        "ownershipDisposition",
    ] {
        if plan.get(field).is_none() {
            anyhow::bail!("provider resolved plan lacks {field}");
        }
    }
    if plan.get("scope").and_then(Value::as_str) != Some(scope.scope.as_str())
        || plan.get("surface").and_then(Value::as_str) != Some(scope.surface.as_str())
        || plan.get("dialect").and_then(Value::as_str) != Some(scope.dialect.as_str())
    {
        anyhow::bail!("provider resolved plan scope/surface/dialect mismatch");
    }
    let server_id = plan
        .get("serverId")
        .and_then(Value::as_str)
        .context("provider resolved plan serverId is not a string")?;
    if server_id == "icm"
        || server_id.is_empty()
        || !server_id
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
    {
        anyhow::bail!("provider serverId is not installation-scoped lowercase-alphanumeric");
    }
    let expected_paths: BTreeSet<_> = document_paths
        .iter()
        .map(|path| normalize_sandbox_path(path, sandbox))
        .collect();
    let actual_paths: BTreeSet<_> = plan
        .get("paths")
        .and_then(Value::as_array)
        .context("provider plan paths is not an array")?
        .iter()
        .map(|path| {
            let path = path
                .as_str()
                .context("provider plan path is not a string")?;
            let resolved = Path::new(path);
            if !resolved.is_absolute() || !resolved.starts_with(&sandbox.root) {
                anyhow::bail!("provider plan path escapes the synthetic scenario root");
            }
            Ok(normalize_sandbox_path(resolved, sandbox))
        })
        .collect::<Result<_>>()?;
    if actual_paths != expected_paths {
        anyhow::bail!("provider plan paths differ from exact scope document paths");
    }
    let expected_tool_rules = provider_tool_rules(&provider.id, server_id, &fixture.owned_tools)?;
    let actual_tool_rules: BTreeSet<_> = plan
        .get("toolRules")
        .and_then(Value::as_array)
        .context("provider plan toolRules is not an array")?
        .iter()
        .map(|rule| {
            rule.as_str()
                .context("provider plan tool rule is not a string")
                .map(str::to_owned)
        })
        .collect::<Result<_>>()?;
    if actual_tool_rules != expected_tool_rules {
        anyhow::bail!("provider plan does not contain the exact two frozen tool rules");
    }
    let expected_blocking = provider_blocking_rules(&provider.id);
    let actual_blocking: BTreeSet<_> = plan
        .get("blockingRules")
        .and_then(Value::as_array)
        .context("provider plan blockingRules is not an array")?
        .iter()
        .map(|rule| {
            rule.as_str()
                .context("provider blocking rule is not a string")
                .map(str::to_owned)
        })
        .collect::<Result<_>>()?;
    if actual_blocking != expected_blocking {
        anyhow::bail!("provider plan blockingRules differ from seeded restrictions");
    }
    let dispositions = plan
        .get("ownershipDisposition")
        .and_then(Value::as_array)
        .context("provider plan ownershipDisposition is not an array")?;
    if dispositions.is_empty() {
        anyhow::bail!("provider plan ownershipDisposition is empty");
    }
    for disposition in dispositions {
        let object = disposition
            .as_object()
            .context("ownership disposition is not an object")?;
        for field in ["path", "rule", "disposition"] {
            if object.get(field).and_then(Value::as_str).is_none() {
                anyhow::bail!("ownership disposition lacks string {field}");
            }
        }
        if !matches!(
            object.get("disposition").and_then(Value::as_str),
            Some("new-owned" | "preexisting-adopted" | "blocked-existing" | "owned-existing")
        ) {
            anyhow::bail!("ownership disposition uses an unfrozen state");
        }
    }
    Ok(())
}

fn canonical_provider_plan_sha256(
    plan: &Value,
    server_id: &str,
    sandbox: &ScenarioSandbox,
) -> Result<String> {
    let mut canonical = plan.clone();
    *canonical
        .get_mut("serverId")
        .context("canonical provider plan lacks serverId")? =
        Value::String("<SERVER_ID>".to_owned());
    let paths = canonical
        .get_mut("paths")
        .and_then(Value::as_array_mut)
        .context("canonical provider plan paths is not an array")?;
    for path in paths {
        let raw = path
            .as_str()
            .context("provider plan path is not a string")?;
        let resolved = Path::new(raw);
        if !resolved.is_absolute() || !resolved.starts_with(&sandbox.root) {
            anyhow::bail!("provider plan path escapes synthetic root during canonicalization");
        }
        *path = Value::String(normalize_sandbox_path(resolved, sandbox));
    }
    for field in ["toolRules", "ownershipDisposition"] {
        let value = canonical
            .get_mut(field)
            .with_context(|| format!("canonical provider plan lacks {field}"))?;
        replace_server_id_in_declared_plan_field(value, server_id)?;
    }
    for disposition in canonical
        .get_mut("ownershipDisposition")
        .and_then(Value::as_array_mut)
        .context("canonical ownershipDisposition is not an array")?
    {
        let path = disposition
            .get_mut("path")
            .context("canonical ownership disposition lacks path")?;
        let raw = path
            .as_str()
            .context("canonical ownership disposition path is not a string")?;
        let resolved = Path::new(raw);
        if !resolved.is_absolute() || !resolved.starts_with(&sandbox.root) {
            anyhow::bail!("ownership disposition path escapes synthetic root");
        }
        *path = Value::String(normalize_sandbox_path(resolved, sandbox));
    }
    Ok(sha256_bytes(&serde_json::to_vec(&canonical)?))
}

fn replace_server_id_in_declared_plan_field(value: &mut Value, server_id: &str) -> Result<()> {
    match value {
        Value::String(text) => *text = text.replace(server_id, "<SERVER_ID>"),
        Value::Array(values) => {
            for value in values {
                replace_server_id_in_declared_plan_field(value, server_id)?;
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "path" | "rule" | "disposition") {
                    replace_server_id_in_declared_plan_field(value, server_id)?;
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn provider_tool_rules(
    provider: &str,
    server_id: &str,
    tools: &[String],
) -> Result<BTreeSet<String>> {
    let normalized_server = server_id.replace('-', "_");
    tools
        .iter()
        .map(|tool| {
            Ok(match provider {
                "codex" => format!("mcp_servers.{server_id}.tools.{tool}.approval_mode=approve"),
                "claude-code" => format!("mcp__{server_id}__{tool}"),
                "cursor" => format!("Mcp({server_id}:{tool})"),
                "opencode" => format!("{normalized_server}_{tool}|*|allow"),
                "zed" => {
                    format!("agent.tool_permissions.tools.mcp:{server_id}:{tool}.default=allow")
                }
                other => anyhow::bail!("unknown provider {other}"),
            })
        })
        .collect()
}

fn provider_blocking_rules(provider: &str) -> BTreeSet<String> {
    let rules: &[&str] = match provider {
        "codex" => &["mcp_servers.existing.tools.existing_tool.approval_mode=deny"],
        "claude-code" => &["permissions.deny:Bash(rm:*)", "permissions.ask:WebFetch(*)"],
        "cursor" => &["permissions.deny:Shell(rm:*)", "ideTrust=prompt-only"],
        "opencode" => &[
            "existing_*|*|ask",
            "dangerous_*|*|deny",
            "last-matching-rule-wins",
        ],
        "zed" => &[
            "agent.tool_permissions.default=confirm",
            "agent.tool_permissions.tools.dangerous.write.default=deny",
        ],
        _ => return BTreeSet::new(),
    };
    rules.iter().map(|rule| (*rule).to_owned()).collect()
}

fn validate_provider_trusted(
    provider: &ProviderCase,
    scope: &ProviderScopeFixture,
    paths: &[PathBuf],
    server_id: &str,
    fixture: &ProviderFixture,
) -> Result<()> {
    for (document, path) in scope.documents.iter().zip(paths) {
        let text = fs::read_to_string(path)?;
        for forbidden in &fixture.forbidden_patterns {
            if [format!("\"{forbidden}\""), format!("'{forbidden}'")]
                .iter()
                .any(|needle| text.contains(needle))
            {
                anyhow::bail!("provider config contains forbidden wildcard {forbidden}");
            }
        }
        if document.role.contains("registration") {
            validate_provider_registration(&provider.id, document, &text, server_id)?;
        }
        if document.role.contains("permission") {
            validate_provider_permissions(
                &provider.id,
                document,
                &text,
                server_id,
                &fixture.owned_tools,
            )?;
        }
    }
    Ok(())
}

fn validate_provider_stripped(
    provider: &ProviderCase,
    scope: &ProviderScopeFixture,
    paths: &[PathBuf],
    server_id: &str,
    fixture: &ProviderFixture,
) -> Result<()> {
    let rules = provider_tool_rules(&provider.id, server_id, &fixture.owned_tools)?;
    for (document, path) in scope.documents.iter().zip(paths) {
        let text = fs::read_to_string(path)?;
        if !text.contains("unchanged") {
            anyhow::bail!("strip/uninstall removed unrelated provider bytes");
        }
        if text.contains(server_id)
            || fixture.owned_tools.iter().any(|tool| text.contains(tool))
            || rules.iter().any(|rule| text.contains(rule))
        {
            anyhow::bail!("strip/uninstall retained an owned registration or trust rule");
        }
        parse_provider_document(document, &text)?;
    }
    Ok(())
}

fn parse_provider_document(document: &ProviderDocumentFixture, text: &str) -> Result<Value> {
    match document.format.as_str() {
        "json" => serde_json::from_str(text).context("parsing provider JSON document"),
        "toml" => {
            let value: toml::Value =
                toml::from_str(text).context("parsing provider TOML document")?;
            serde_json::to_value(value).context("converting provider TOML document")
        }
        other => anyhow::bail!("unknown provider document format {other}"),
    }
}

fn validate_provider_registration(
    provider: &str,
    document: &ProviderDocumentFixture,
    text: &str,
    server_id: &str,
) -> Result<()> {
    let parsed = parse_provider_document(document, text)?;
    let registration = match provider {
        "codex" => parsed.pointer(&format!("/mcp_servers/{server_id}")),
        "claude-code" | "cursor" => parsed.pointer(&format!("/mcpServers/{server_id}")),
        "opencode" => parsed.pointer(&format!("/mcp/servers/{server_id}")),
        "zed" => parsed.pointer(&format!("/context_servers/{server_id}")),
        other => anyhow::bail!("unknown provider {other}"),
    };
    if registration.is_none_or(Value::is_null) {
        anyhow::bail!("provider registration is absent from exact registration surface");
    }
    Ok(())
}

fn validate_provider_permissions(
    provider: &str,
    document: &ProviderDocumentFixture,
    text: &str,
    server_id: &str,
    tools: &[String],
) -> Result<()> {
    let parsed = parse_provider_document(document, text)?;
    match provider {
        "codex" => {
            let enabled: BTreeSet<_> = parsed
                .pointer(&format!("/mcp_servers/{server_id}/enabled_tools"))
                .and_then(Value::as_array)
                .context("Codex registration lacks enabled_tools")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .context("Codex enabled tool is not a string")
                        .map(str::to_owned)
                })
                .collect::<Result<_>>()?;
            let expected: BTreeSet<_> = tools.iter().cloned().collect();
            if enabled != expected {
                anyhow::bail!("Codex enabled_tools is not exactly the two owned tools");
            }
            for tool in tools {
                if parsed.pointer(&format!(
                    "/mcp_servers/{server_id}/tools/{tool}/approval_mode"
                )) != Some(&Value::String("approve".to_owned()))
                {
                    anyhow::bail!("Codex tool approval is not exact approve");
                }
            }
        }
        "claude-code" => {
            let allow = parsed
                .pointer("/permissions/allow")
                .and_then(Value::as_array)
                .context("Claude allow list absent")?;
            for tool in tools {
                let expected = Value::String(format!("mcp__{server_id}__{tool}"));
                if !allow.contains(&expected) {
                    anyhow::bail!("Claude exact tool allow rule absent");
                }
            }
            if parsed
                .pointer("/permissions/deny")
                .and_then(Value::as_array)
                .is_none_or(|rules| !rules.contains(&Value::String("Bash(rm:*)".to_owned())))
                || parsed
                    .pointer("/permissions/ask")
                    .and_then(Value::as_array)
                    .is_none_or(|rules| !rules.contains(&Value::String("WebFetch(*)".to_owned())))
            {
                anyhow::bail!("Claude blocking precedence rules were not preserved");
            }
        }
        "cursor" => {
            let allow = parsed
                .pointer("/permissions/allow")
                .and_then(Value::as_array)
                .context("Cursor allow list absent")?;
            for tool in tools {
                if !allow.contains(&Value::String(format!("Mcp({server_id}:{tool})"))) {
                    anyhow::bail!("Cursor exact tool allow rule absent");
                }
            }
            if parsed
                .pointer("/permissions/deny")
                .and_then(Value::as_array)
                .is_none_or(|rules| !rules.contains(&Value::String("Shell(rm:*)".to_owned())))
            {
                anyhow::bail!("Cursor deny rule was not preserved");
            }
        }
        "opencode" => {
            let rules = parsed
                .get("permission")
                .and_then(Value::as_array)
                .context("OpenCode v2 permission list absent")?;
            let normalized_server = server_id.replace('-', "_");
            for tool in tools {
                let expected = json!({"action":format!("{normalized_server}_{tool}"),"resource":"*","effect":"allow"});
                if !rules.contains(&expected) {
                    anyhow::bail!("OpenCode exact v2 allow rule absent");
                }
            }
            if !rules.contains(&json!({"action":"dangerous_*","resource":"*","effect":"deny"})) {
                anyhow::bail!("OpenCode blocking rule was not preserved");
            }
        }
        "zed" => {
            for tool in tools {
                let key = format!("mcp:{server_id}:{tool}");
                if parsed.pointer(&format!(
                    "/agent/tool_permissions/tools/{}/default",
                    json_pointer_escape(&key)
                )) != Some(&Value::String("allow".to_owned()))
                {
                    anyhow::bail!("Zed exact tool permission absent");
                }
            }
            if parsed.pointer("/agent/tool_permissions/default")
                != Some(&Value::String("confirm".to_owned()))
                || parsed.pointer("/agent/tool_permissions/tools/dangerous.write/default")
                    != Some(&Value::String("deny".to_owned()))
            {
                anyhow::bail!("Zed inherited blocking rules were not preserved");
            }
        }
        other => anyhow::bail!("unknown provider {other}"),
    }
    Ok(())
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn resource_text(response: &Value) -> Result<&str> {
    response
        .pointer("/result/contents/0/text")
        .and_then(Value::as_str)
        .context("resource response lacks result.contents[0].text")
}

fn validate_support_event_journal(
    bytes: &[u8],
    required_order: &[&str],
    artifact: Option<(&str, String)>,
) -> Result<Vec<Value>> {
    let text = std::str::from_utf8(bytes).context("support event journal is not UTF-8")?;
    let events: Vec<Value> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("support journal line is not JSON"))
        .collect::<Result<_>>()?;
    if events.is_empty() {
        anyhow::bail!("support event journal is empty");
    }
    let mut previous_nanos = 0_u64;
    for (index, event) in events.iter().enumerate() {
        if event.get("sequence").and_then(Value::as_u64) != Some((index + 1) as u64) {
            anyhow::bail!("support event sequence is not contiguous from one");
        }
        let nanos = event
            .get("monotonicNanos")
            .and_then(Value::as_u64)
            .context("support event lacks monotonicNanos")?;
        if nanos < previous_nanos {
            anyhow::bail!("support event monotonicNanos regressed");
        }
        previous_nanos = nanos;
        if event.get("event").and_then(Value::as_str).is_none() {
            anyhow::bail!("support journal event name is absent");
        }
    }
    let names: Vec<_> = events
        .iter()
        .filter_map(|event| event.get("event").and_then(Value::as_str))
        .collect();
    let mut cursor = 0_usize;
    for required in required_order {
        let offset = names[cursor..]
            .iter()
            .position(|name| name == required)
            .with_context(|| format!("support journal lacks ordered event {required}"))?;
        cursor += offset + 1;
    }
    if let Some((event_name, expected_hash)) = artifact {
        let event = events
            .iter()
            .find(|event| event.get("event").and_then(Value::as_str) == Some(event_name))
            .with_context(|| format!("support journal lacks artifact event {event_name}"))?;
        if event.get("artifactSha256").and_then(Value::as_str) != Some(expected_hash.as_str()) {
            anyhow::bail!("support journal artifact hash differs from evaluator-read bytes");
        }
    }
    Ok(events)
}

fn hash_regular_files(root: &Path) -> Result<BTreeMap<String, String>> {
    fn visit(root: &Path, current: &Path, output: &mut BTreeMap<String, String>) -> Result<()> {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                visit(root, &path, output)?;
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .context("provider engine file escaped world")?
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(relative, sha256_file(&path)?);
            }
        }
        Ok(())
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output)?;
    Ok(output)
}

fn validate_provider_engine_case(
    id: &str,
    world: &Path,
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    event_bytes: &[u8],
) -> Result<Vec<Value>> {
    let required: &[&str] = match id {
        "provider.engine.schema1-migration-legacy-unproven" => &[
            "case-start",
            "manifest-read",
            "schema-migrated",
            "manifest-commit",
        ],
        "provider.engine.newer-manifest-read-only" => &[
            "case-start",
            "manifest-read",
            "newer-schema-rejected",
            "case-stop",
        ],
        "provider.engine.journal-intent-before-target" => &[
            "case-start",
            "intent-durable",
            "target-write",
            "target-readback",
            "manifest-commit",
        ],
        "provider.engine.target-hash-readback" => &[
            "case-start",
            "target-write",
            "target-readback",
            "manifest-commit",
        ],
        id if id.contains("recovery") => &[
            "case-start",
            "recovery-detected",
            "semantic-compare",
            "recovery-decision",
            "case-stop",
        ],
        id if id.contains("concurrent") || id.contains("external-") => &[
            "case-start",
            "lock-acquired",
            "writer-observed",
            "lock-released",
            "case-stop",
        ],
        "provider.engine.lock-loss-no-write" => &[
            "case-start",
            "lock-acquired",
            "lock-lost",
            "write-aborted",
            "case-stop",
        ],
        "provider.engine.orphan-temp-owned-only" => &[
            "case-start",
            "orphan-scan",
            "owned-temp-removed",
            "case-stop",
        ],
        _ => anyhow::bail!("unknown provider engine case {id}"),
    };
    let events = validate_support_event_journal(event_bytes, required, None)?;
    let target_a_path = world.join("target-a.json");
    let target_b_path = world.join("target-b.json");
    let manifest_path = world.join("install-manifest.json");
    let target_a: Value = serde_json::from_slice(&fs::read(&target_a_path)?)?;
    let target_b: Value = serde_json::from_slice(&fs::read(&target_b_path)?)?;
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if target_a.get("sentinel").and_then(Value::as_str) != Some("target-a-unchanged")
        || target_b.get("sentinel").and_then(Value::as_str) != Some("target-b-unchanged")
    {
        anyhow::bail!("provider engine removed unrelated target sentinel data");
    }

    for event in events
        .iter()
        .filter(|event| event.get("event").and_then(Value::as_str) == Some("target-readback"))
    {
        let relative = event
            .get("path")
            .and_then(Value::as_str)
            .context("target-readback event lacks path")?;
        let path = world.join(native_relative(relative));
        let actual_hash = sha256_file(&path)?;
        if !path.starts_with(world)
            || event.get("artifactSha256").and_then(Value::as_str) != Some(actual_hash.as_str())
        {
            anyhow::bail!("target-readback event hash differs from evaluator-read target");
        }
    }

    match id {
        "provider.engine.schema1-migration-legacy-unproven" => {
            if manifest.get("version").and_then(Value::as_u64) != Some(2)
                || manifest
                    .pointer("/providerOwnership/0/owned")
                    .and_then(Value::as_bool)
                    != Some(false)
            {
                anyhow::bail!("schema-1 migration falsely proved legacy ownership");
            }
        }
        "provider.engine.newer-manifest-read-only" | "provider.engine.lock-loss-no-write" => {
            if after != before {
                anyhow::bail!("read-only/lock-loss provider engine case changed world files");
            }
        }
        "provider.engine.recovery-overlap-conflict" | "provider.engine.external-overlap-writer" => {
            if after.get("target-a.json") != before.get("target-a.json")
                || !events.iter().any(|event| {
                    event.get("event").and_then(Value::as_str) == Some("recovery-decision")
                        || event.get("event").and_then(Value::as_str) == Some("conflict")
                })
            {
                anyhow::bail!("overlap conflict did not fail closed on target bytes");
            }
        }
        "provider.engine.concurrent-different-providers" => {
            require_owned_rule(&target_a, "provider-a:icm_memory_recall", 1)?;
            require_owned_rule(&target_b, "provider-b:icm_memory_recall", 1)?;
        }
        "provider.engine.concurrent-apply-strip" => {
            require_owned_rule(&target_a, "provider-a:icm_memory_recall", 0)?;
            if manifest
                .pointer("/providerOwnership/0/state")
                .and_then(Value::as_str)
                != Some("removed")
            {
                anyhow::bail!("apply/strip race did not leave an ownership tombstone");
            }
        }
        "provider.engine.external-disjoint-writer" | "provider.engine.recovery-disjoint-edit" => {
            if target_a
                .get("externalRules")
                .and_then(Value::as_array)
                .is_none_or(|rules| !rules.contains(&Value::String("external-disjoint".to_owned())))
            {
                anyhow::bail!("provider engine lost an external disjoint edit");
            }
        }
        "provider.engine.orphan-temp-owned-only" => {
            if world.join(".icm-owned-transaction.tmp").exists()
                || fs::read(world.join("user-unowned.tmp"))? != b"unowned-temp-unchanged"
            {
                anyhow::bail!("orphan cleanup removed unowned temp or retained owned temp");
            }
        }
        "provider.engine.concurrent-identical-apply" => {
            require_owned_rule(&target_a, "provider-a:icm_memory_recall", 1)?;
        }
        _ => {}
    }
    Ok(events)
}

fn require_owned_rule(target: &Value, rule: &str, count: usize) -> Result<()> {
    let actual = target
        .get("ownedRules")
        .and_then(Value::as_array)
        .context("provider engine target lacks ownedRules")?
        .iter()
        .filter(|value| value.as_str() == Some(rule))
        .count();
    if actual != count {
        anyhow::bail!("provider engine owned rule {rule:?} count {actual}, expected {count}");
    }
    Ok(())
}

fn validate_manifest(
    manifest: &Value,
    provider: &str,
    scope: &str,
    document_paths: &[PathBuf],
    schema: &Value,
    require_adopted: bool,
) -> Result<()> {
    let version = schema
        .get("currentVersion")
        .and_then(Value::as_u64)
        .context("fixture manifest schema lacks currentVersion")?;
    if manifest.get("version").and_then(Value::as_u64) != Some(version) {
        anyhow::bail!("install manifest version mismatch");
    }
    let ownership_field = schema
        .get("topLevelOwnershipField")
        .and_then(Value::as_str)
        .context("fixture manifest schema lacks topLevelOwnershipField")?;
    let entries = manifest
        .get(ownership_field)
        .and_then(Value::as_array)
        .context("install manifest lacks provider ownership array")?;
    let required = schema
        .get("requiredOwnershipFields")
        .and_then(Value::as_array)
        .context("fixture manifest schema lacks requiredOwnershipFields")?;
    let matching: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.get("provider").and_then(Value::as_str) == Some(provider)
                && entry.get("scope").and_then(Value::as_str) == Some(scope)
        })
        .collect();
    if matching.is_empty() {
        anyhow::bail!("install manifest has no ownership records for provider/scope");
    }
    let expected_paths: BTreeSet<_> = document_paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let mut adopted = false;
    for entry in matching {
        for field in required {
            let field = field
                .as_str()
                .context("manifest required field is not a string")?;
            if entry.get(field).is_none() {
                anyhow::bail!("ownership manifest entry lacks {field}");
            }
        }
        let path = entry
            .get("configPath")
            .and_then(Value::as_str)
            .context("manifest configPath is not a string")?;
        if !expected_paths.contains(path) {
            anyhow::bail!("ownership manifest references a non-scope configuration path");
        }
        for hash_field in ["beforeHash", "afterHash"] {
            let hash = entry
                .get(hash_field)
                .and_then(Value::as_str)
                .context("manifest hash is not a string")?;
            if hash.len() != 64 || !hash.chars().all(|character| character.is_ascii_hexdigit()) {
                anyhow::bail!("ownership manifest {hash_field} is not a SHA-256");
            }
        }
        let written_at = entry
            .get("writtenAt")
            .and_then(Value::as_str)
            .context("manifest writtenAt is not a string")?;
        chrono::DateTime::parse_from_rfc3339(written_at)
            .context("manifest writtenAt is not RFC 3339")?;
        let owned = entry
            .get("owned")
            .and_then(Value::as_bool)
            .context("manifest owned is not boolean")?;
        let preexisting = entry
            .get("preexisting")
            .and_then(Value::as_bool)
            .context("manifest preexisting is not boolean")?;
        adopted |= preexisting && !owned;
    }
    if require_adopted && !adopted {
        anyhow::bail!("externally equal provider rule was falsely recorded as owned");
    }
    Ok(())
}

fn assert_target_suffix(records: &[Value], expected: &str) -> Result<()> {
    let target = records
        .first()
        .and_then(|record| record.get("target"))
        .and_then(Value::as_str)
        .context("mock record target absent")?;
    if !target.ends_with(expected) {
        anyhow::bail!("proxy target {target:?} does not end with {expected:?}");
    }
    Ok(())
}

fn proxy_response_is_error(response: &Value) -> bool {
    response.get("error").is_some()
        || response.pointer("/result/isError") == Some(&Value::Bool(true))
}

fn recorded_method(record: &Value) -> Option<String> {
    record
        .get("body")
        .and_then(Value::as_str)
        .and_then(|body| serde_json::from_str::<Value>(body).ok())
        .and_then(|body| {
            body.get("method")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

fn assert_proxy_transport_headers(
    record: &Value,
    protocol_version: &str,
    session_id: Option<&str>,
) -> Result<()> {
    let body: Value = serde_json::from_str(
        record
            .get("body")
            .and_then(Value::as_str)
            .context("proxy record lacks body")?,
    )?;
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .context("proxy body lacks method")?;
    let name = body
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let headers = record
        .get("headers")
        .and_then(Value::as_object)
        .context("proxy record lacks headers")?;
    if headers.get("mcp-protocol-version").and_then(Value::as_str) != Some(protocol_version)
        || headers.get("mcp-method").and_then(Value::as_str) != Some(method)
        || headers.get("mcp-name").and_then(Value::as_str) != Some(name)
        || headers.get("mcp-session-id").and_then(Value::as_str) != session_id
    {
        anyhow::bail!("proxy transport headers do not match the forwarded MCP body/era/session");
    }
    Ok(())
}

fn assert_target_contains(records: &[Value], expected: &str) -> Result<()> {
    let target = records
        .first()
        .and_then(|record| record.get("target"))
        .and_then(Value::as_str)
        .context("mock record target absent")?;
    if !target.contains(expected) {
        anyhow::bail!("proxy target {target:?} does not contain {expected:?}");
    }
    Ok(())
}

fn assert_recorded_loopback_endpoints(records: &[Value]) -> Result<()> {
    if records.is_empty() {
        anyhow::bail!("mock daemon recorded no integration sockets");
    }
    for record in records {
        for field in ["peerAddress", "localAddress"] {
            let address: SocketAddr = record
                .get(field)
                .and_then(Value::as_str)
                .with_context(|| format!("mock record lacks {field}"))?
                .parse()?;
            if !address.ip().is_loopback() {
                anyhow::bail!("mock {field} was not loopback: {address}");
            }
        }
    }
    Ok(())
}

fn recorded_loopback_evidence(records: &[Value]) -> Result<Value> {
    assert_recorded_loopback_endpoints(records)?;
    let mut peer_ips = BTreeSet::new();
    let mut local_ips = BTreeSet::new();
    for record in records {
        let peer: SocketAddr = record
            .get("peerAddress")
            .and_then(Value::as_str)
            .context("mock record lacks peerAddress")?
            .parse()?;
        let local: SocketAddr = record
            .get("localAddress")
            .and_then(Value::as_str)
            .context("mock record lacks localAddress")?
            .parse()?;
        peer_ips.insert(peer.ip().to_string());
        local_ips.insert(local.ip().to_string());
    }
    Ok(json!({
        "recordCount": records.len(),
        "peerIps": peer_ips,
        "localIps": local_ips
    }))
}

fn shutdown_mock_daemon(base_url: &str) -> Result<()> {
    let address = loopback_address_from_url(base_url)?;
    let without_scheme = base_url
        .strip_prefix("http://")
        .context("mock daemon URL is not HTTP")?;
    let authority = without_scheme
        .split('/')
        .next()
        .context("mock URL lacks authority")?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let request = format!(
        "POST /__shutdown HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    if !response.starts_with(b"HTTP/1.1 200") {
        anyhow::bail!("mock daemon shutdown response was not HTTP 200");
    }
    Ok(())
}

fn probe_mock_daemon(base_url: &str) -> Result<()> {
    let address = loopback_address_from_url(base_url)?;
    let without_scheme = base_url
        .strip_prefix("http://")
        .context("mock daemon URL is not HTTP")?;
    let authority = without_scheme
        .split('/')
        .next()
        .context("mock URL lacks authority")?;
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    if !response.starts_with(b"HTTP/1.1 200") {
        anyhow::bail!("mock daemon integration probe response was not HTTP 200");
    }
    Ok(())
}

fn loopback_address_from_url(base_url: &str) -> Result<SocketAddr> {
    let without_scheme = base_url
        .strip_prefix("http://")
        .context("mock daemon URL is not HTTP")?;
    let authority = without_scheme
        .split('/')
        .next()
        .context("mock URL lacks authority")?;
    let address: SocketAddr = authority.parse()?;
    if !address.ip().is_loopback() {
        anyhow::bail!("mock daemon address is not loopback: {address}");
    }
    Ok(address)
}

fn read_json_lines(path: &Path) -> Result<Vec<Value>> {
    let file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .map(|line| Ok(serde_json::from_str(&line?)?))
        .collect()
}

fn read_pss_kib(pid: u32) -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let path = PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
        .join("proc")
        .join(pid.to_string())
        .join("smaps_rollup");
    let content = fs::read_to_string(path).ok()?;
    content.lines().find_map(|line| {
        let value = line.strip_prefix("Pss:")?.split_whitespace().next()?;
        value.parse().ok()
    })
}

fn poison_memory_table(db_path: &Path) -> Result<()> {
    let connection = rusqlite::Connection::open(db_path)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = OFF;
         ALTER TABLE memories RENAME TO memories_eval_original;
         CREATE TABLE memories (id TEXT PRIMARY KEY);",
    )?;
    Ok(())
}

fn latency_shape_matches(
    actual: &LatencySummary,
    thresholds: &crate::design::AcceptanceThresholds,
) -> bool {
    actual.block_medians_micros.len() == thresholds.latency_block_count
        && actual.sample_count
            == thresholds
                .latency_block_count
                .saturating_mul(thresholds.latency_samples_per_block)
}

fn latency_limits(
    baseline_median: u128,
    baseline_p95: u128,
    thresholds: &crate::design::AcceptanceThresholds,
) -> Result<(u128, u128)> {
    if thresholds.latency_median_ratio_denominator == 0
        || thresholds.latency_p95_ratio_denominator == 0
    {
        anyhow::bail!("latency ratio denominator must be nonzero");
    }
    let median = baseline_median.saturating_mul(thresholds.latency_median_ratio_numerator)
        / thresholds.latency_median_ratio_denominator
        + thresholds.latency_median_allowance_micros;
    let p95 = baseline_p95.saturating_mul(thresholds.latency_p95_ratio_numerator)
        / thresholds.latency_p95_ratio_denominator
        + thresholds.latency_p95_allowance_micros;
    Ok((median, p95))
}

fn retrieval_meets_thresholds(
    metrics: &RetrievalMetrics,
    thresholds: &crate::design::AcceptanceThresholds,
) -> bool {
    metrics.hit_at_3 >= thresholds.retrieval_hit_at_3_minimum
        && metrics.recall_at_3 >= thresholds.retrieval_recall_at_3_minimum
        && metrics.ndcg_at_3 >= thresholds.retrieval_ndcg_at_3_minimum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modern_tool_list_response_without_output_schemas() -> Value {
        let suite = Path::new(env!("CARGO_MANIFEST_DIR"));
        let annotations: Value = serde_json::from_slice(
            &fs::read(suite.join("contracts/tool-annotations.json")).unwrap(),
        )
        .unwrap();
        let tools: Vec<_> = LEGACY_TOOLS
            .iter()
            .map(|name| {
                json!({
                    "name": name,
                    "annotations": annotations.get(*name).unwrap(),
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {},
                        "required": required_fields(name)
                    }
                })
            })
            .collect();
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "resultType": "complete",
                "tools": tools,
                "ttlMs": 3_600_000,
                "cacheScope": "private",
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "icm-test",
                        "version": "0"
                    }
                }
            }
        })
    }

    #[test]
    fn frozen_legacy_order_has_thirty_tools() {
        assert_eq!(LEGACY_TOOLS.len(), 30);
        assert_eq!(LEGACY_TOOLS.first(), Some(&"icm_memory_store"));
        assert_eq!(LEGACY_TOOLS.last(), Some(&"icm_wake_up"));
    }

    #[test]
    fn phase_two_tool_list_gates_do_not_require_phase_three_output_schemas() {
        let suite = Path::new(env!("CARGO_MANIFEST_DIR"));
        let response = modern_tool_list_response_without_output_schemas();
        for id in [
            "modern.tools-list-order",
            "modern.tools-list-annotations",
            "modern.tools-list-cache-metadata",
            "modern.tools-list-required-fields",
            "modern.tools-list-closed-schemas",
            "modern.annotation-memory-store-destructive",
            "modern.annotation-memory-recall-destructive",
            "modern.annotation-read-only-consistency",
            "modern.annotation-idempotence-consistency",
            "modern.annotation-open-world-learn-only",
        ] {
            validate_modern_tool_list(suite, id, &response).unwrap_or_else(|error| {
                panic!("{id} unexpectedly required outputSchema: {error:#}")
            });
        }
        assert!(
            validate_modern_tool_list(suite, "modern.tools-list-output-schemas", &response)
                .is_err()
        );
    }

    #[test]
    fn native_relative_accepts_both_fixture_separators() {
        assert_eq!(
            native_relative("a/b\\c"),
            PathBuf::from("a").join("b").join("c")
        );
    }

    #[test]
    fn provider_platform_paths_stay_inside_synthetic_roots() {
        let suite = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixture = load_providers(suite).unwrap();
        let work = std::env::temp_dir().join(format!(
            "icm-provider-platform-fixture-{}",
            std::process::id()
        ));
        let sandbox = ScenarioSandbox::create(&work, "platforms", "provider-paths", false).unwrap();
        let xdg_config = sandbox_env_path(&sandbox, "XDG_CONFIG_HOME").unwrap();
        let xdg_data = sandbox_env_path(&sandbox, "XDG_DATA_HOME").unwrap();
        let appdata = sandbox_env_path(&sandbox, "APPDATA").unwrap();

        assert_eq!(
            provider_manifest_path_for_platform(&sandbox, &fixture, PlatformFamily::Linux).unwrap(),
            xdg_data.join("icm/install-manifest.json")
        );
        assert_eq!(
            provider_manifest_path_for_platform(&sandbox, &fixture, PlatformFamily::Macos).unwrap(),
            sandbox
                .home
                .join("Library/Application Support/icm/install-manifest.json")
        );
        assert_eq!(
            provider_manifest_path_for_platform(&sandbox, &fixture, PlatformFamily::Windows)
                .unwrap(),
            appdata.join("icm/icm/data/install-manifest.json")
        );

        let codex = fixture
            .providers
            .iter()
            .find(|provider| provider.id == "codex")
            .unwrap()
            .scopes
            .iter()
            .find(|scope| scope.scope == "user")
            .unwrap();
        let codex_home = sandbox_env_path(&sandbox, "CODEX_HOME").unwrap();
        for platform in [
            PlatformFamily::Linux,
            PlatformFamily::Macos,
            PlatformFamily::Windows,
        ] {
            assert_eq!(
                provider_document_paths_for_platform(&sandbox, codex, platform).unwrap(),
                vec![codex_home.join("config.toml")]
            );
        }

        let claude = fixture
            .providers
            .iter()
            .find(|provider| provider.id == "claude-code")
            .unwrap()
            .scopes
            .iter()
            .find(|scope| scope.scope == "user")
            .unwrap();
        let claude_config = sandbox_env_path(&sandbox, "CLAUDE_CONFIG_DIR").unwrap();
        for platform in [
            PlatformFamily::Linux,
            PlatformFamily::Macos,
            PlatformFamily::Windows,
        ] {
            assert_eq!(
                provider_document_paths_for_platform(&sandbox, claude, platform).unwrap(),
                vec![
                    sandbox.home.join(".claude.json"),
                    claude_config.join("settings.json")
                ]
            );
        }

        for (provider_id, linux, macos, windows) in [
            (
                "opencode",
                xdg_config.join("opencode/opencode.json"),
                sandbox
                    .home
                    .join("Library/Application Support/opencode/opencode.json"),
                appdata.join("opencode/opencode.json"),
            ),
            (
                "zed",
                xdg_config.join("zed/settings.json"),
                sandbox
                    .home
                    .join("Library/Application Support/Zed/settings.json"),
                appdata.join("Zed/settings.json"),
            ),
        ] {
            let scope = fixture
                .providers
                .iter()
                .find(|provider| provider.id == provider_id)
                .unwrap()
                .scopes
                .iter()
                .find(|scope| scope.scope == "user")
                .unwrap();
            assert_eq!(
                provider_document_paths_for_platform(&sandbox, scope, PlatformFamily::Linux)
                    .unwrap(),
                vec![linux]
            );
            assert_eq!(
                provider_document_paths_for_platform(&sandbox, scope, PlatformFamily::Macos)
                    .unwrap(),
                vec![macos]
            );
            assert_eq!(
                provider_document_paths_for_platform(&sandbox, scope, PlatformFamily::Windows)
                    .unwrap(),
                vec![windows]
            );
        }
        sandbox.verify().unwrap();
        let _ = fs::remove_dir_all(work);
    }

    #[test]
    fn child_guard_drop_kills_and_reaps_a_waiting_child() {
        const CHILD_MARKER: &str = "ICM_EVAL_SYNTHETIC_CLEANUP_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            thread::sleep(Duration::from_secs(30));
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let mut command = Command::new(executable);
        command
            .arg("--exact")
            .arg("evaluate::tests::child_guard_drop_kills_and_reaps_a_waiting_child")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut guard = ChildGuard::spawn(command).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(guard.child_mut().unwrap().try_wait().unwrap().is_none());
        drop(guard);
    }

    #[test]
    fn typed_metric_threshold_changes_gate_outcome() {
        let mut thresholds: crate::design::AcceptanceThresholds = serde_json::from_value(json!({
            "legacyDeterministicParity":1.0,
            "legacyCatalogOrderParity":1.0,
            "legacyRequiredFieldParity":1.0,
            "modernSchemaCoverage":1.0,
            "modernRequiredFieldCoverage":1.0,
            "actualStructuredEmissionsValid":1.0,
            "boundaryPassRate":1.0,
            "resourceMaxPortableTokens":2048,
            "resourceMaxWireBytes":2048,
            "modernRecallMaxWireBytes":8192,
            "modernConciseTextMaxBytes":256,
            "proxyClientCount":3,
            "proxyCallsPerClient":3,
            "daemonCount":1,
            "daemonModelLoadCount":1,
            "unsupportedBaselineRequiresWireOrCliEvidence":true,
            "latencyBlockCount":5,
            "latencyWarmupsPerOperation":5,
            "latencySamplesPerBlock":20,
            "latencyMedianRatioNumerator":3,
            "latencyMedianRatioDenominator":2,
            "latencyMedianAllowanceMicros":5000,
            "latencyP95RatioNumerator":2,
            "latencyP95RatioDenominator":1,
            "latencyP95AllowanceMicros":10000,
            "latencyNoiseFloorMicros":2000,
            "retrievalK":3,
            "retrievalHitAt3Minimum":1.0,
            "retrievalRecallAt3Minimum":0.9,
            "retrievalNdcgAt3Minimum":0.95
        }))
        .unwrap();
        let metrics = RetrievalMetrics {
            queries: 1,
            hit_at_3: 1.0,
            recall_at_3: 0.92,
            ndcg_at_3: 0.96,
        };
        assert!(retrieval_meets_thresholds(&metrics, &thresholds));
        thresholds.retrieval_recall_at_3_minimum = 0.93;
        assert!(!retrieval_meets_thresholds(&metrics, &thresholds));

        let summary = LatencySummary {
            block_medians_micros: vec![1; 5],
            median_micros: 1,
            p95_micros: 1,
            sample_count: 100,
        };
        assert!(latency_shape_matches(&summary, &thresholds));
        thresholds.latency_block_count = 4;
        assert!(!latency_shape_matches(&summary, &thresholds));
    }

    #[test]
    fn unsupported_without_concrete_probe_evidence_is_rejected() {
        let empty_wire = UnsupportedEvidence::Wire {
            methods: Vec::new(),
            statuses: Vec::new(),
            response_count: 0,
        };
        assert!(validate_unsupported_evidence(&empty_wire).is_err());
        let zero_exit = UnsupportedEvidence::Cli {
            arguments: vec!["proxy".into(), "--help".into()],
            exit_code: 0,
        };
        assert!(validate_unsupported_evidence(&zero_exit).is_err());
        let valid = UnsupportedEvidence::Wire {
            methods: vec!["server/discover".into()],
            statuses: vec!["error:-32601".into()],
            response_count: 1,
        };
        assert!(validate_unsupported_evidence(&valid).is_ok());
    }
}
