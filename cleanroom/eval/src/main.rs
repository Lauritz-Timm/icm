mod design;
mod evaluate;
mod fixtures;
mod mcp;
mod metrics;
mod mock_daemon;
mod normalization;
mod sandbox;
mod schema;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use evaluate::{EvaluationMode, EvaluationReport, Runner};
use serde_json::json;

fn main() {
    if let Err(error) = run() {
        eprintln!("icm-cleanroom-eval: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().context("missing evaluator command")?;
    let options = parse_options(arguments.collect())?;
    match command.as_str() {
        "verify-design" => {
            reject_unknown(&options, &["suite-root"])?;
            let suite_root = required_path(&options, "suite-root")?;
            let verification = design::verify(&suite_root)?;
            println!("{}", serde_json::to_string_pretty(&verification)?);
        }
        "record-baseline" | "run" => {
            reject_unknown(
                &options,
                &[
                    "workspace-root",
                    "suite-root",
                    "candidate",
                    "work-root",
                    "evidence-root",
                    "run-label",
                ],
            )?;
            let mode = if command == "record-baseline" {
                EvaluationMode::RecordBaseline
            } else {
                EvaluationMode::Candidate
            };
            let runner = runner_from_options(&options, mode)?;
            let (report, path) = runner.run()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "report": path,
                    "portableAcceptance": report.portable_acceptance,
                    "statusCounts": report.status_counts,
                    "legacyObservationCount": report.legacy_observation.len()
                }))?
            );
            if mode == EvaluationMode::Candidate && !report.portable_acceptance {
                anyhow::bail!("candidate failed one or more preregistered acceptance scenarios");
            }
        }
        "self-test" => {
            reject_unknown(
                &options,
                &[
                    "workspace-root",
                    "suite-root",
                    "candidate",
                    "work-root",
                    "evidence-root",
                    "run-label",
                    "expect",
                ],
            )?;
            run_self_test(&options)?;
        }
        "golden-from-report" => {
            reject_unknown(&options, &["report"])?;
            let report: EvaluationReport =
                serde_json::from_slice(&fs::read(required_path(&options, "report")?)?)?;
            let hashes: BTreeMap<_, _> = report
                .legacy_observation
                .iter()
                .map(|(id, raw)| (id, sandbox::sha256_bytes(raw.as_bytes())))
                .collect();
            println!("{}", serde_json::to_string_pretty(&hashes)?);
        }
        "__mock-daemon" => {
            reject_unknown(&options, &["record", "mode", "ipv6"])?;
            let mode = options.get("mode").map(String::as_str).unwrap_or("normal");
            let ipv6 = options.get("ipv6").map(String::as_str) == Some("true");
            mock_daemon::run(&required_path(&options, "record")?, mode, ipv6)?;
        }
        _ => anyhow::bail!(
            "unknown command {command:?}; expected verify-design, record-baseline, run, self-test, or golden-from-report"
        ),
    }
    Ok(())
}

fn runner_from_options(options: &BTreeMap<String, String>, mode: EvaluationMode) -> Result<Runner> {
    let run_label = options
        .get("run-label")
        .cloned()
        .unwrap_or_else(|| match mode {
            EvaluationMode::RecordBaseline => "baseline".into(),
            EvaluationMode::Candidate => "candidate".into(),
        });
    Runner::new(
        required_path(options, "workspace-root")?,
        required_path(options, "suite-root")?,
        required_path(options, "candidate")?,
        required_path(options, "work-root")?,
        required_path(options, "evidence-root")?,
        run_label,
        mode,
    )
}

fn run_self_test(options: &BTreeMap<String, String>) -> Result<()> {
    let workspace_root = required_path(options, "workspace-root")?;
    let suite_root = required_path(options, "suite-root")?;
    let candidate = required_path(options, "candidate")?;
    let base_work = required_path(options, "work-root")?;
    let evidence = required_path(options, "evidence-root")?;
    let label = options
        .get("run-label")
        .cloned()
        .unwrap_or_else(|| "self-test".into());
    let expectation = options
        .get("expect")
        .map(String::as_str)
        .unwrap_or("baseline");
    let mode = match expectation {
        "baseline" => EvaluationMode::RecordBaseline,
        "candidate" => EvaluationMode::Candidate,
        other => {
            anyhow::bail!("unknown self-test expectation {other:?}; expected baseline or candidate")
        }
    };
    let roots = [
        base_work.join("root with spaces"),
        base_work.join("røød-東京-🧪"),
    ];
    let mut normalized = Vec::new();
    let mut report_paths = Vec::new();
    let mut status_counts = Vec::new();
    for (index, root) in roots.iter().enumerate() {
        let runner = Runner::new(
            workspace_root.clone(),
            suite_root.clone(),
            candidate.clone(),
            root.clone(),
            evidence.clone(),
            format!("{label}-root-{}", index + 1),
            mode,
        )?;
        let (report, path) = runner.run()?;
        if mode == EvaluationMode::Candidate && !report.portable_acceptance {
            anyhow::bail!(
                "candidate self-test root {} failed portable acceptance",
                index + 1
            );
        }
        normalized.push(normalization::normalize_report(&report)?);
        status_counts.push(report.status_counts.clone());
        report_paths.push(path);
    }
    if normalized[0] != normalized[1] {
        let first = sandbox::sha256_bytes(&normalized[0]);
        let second = sandbox::sha256_bytes(&normalized[1]);
        anyhow::bail!("two-root normalized results differ: {first} != {second}");
    }
    fs::create_dir_all(&evidence)?;
    let result_path = evidence.join(format!("{label}-result.json"));
    fs::write(
        &result_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({
                "equal": true,
                "expectation": expectation,
                "normalizedSha256": sandbox::sha256_bytes(&normalized[0]),
                "statusCounts": status_counts,
                "roots": ["<ROOT_WITH_SPACES>", "<ROOT_WITH_UNICODE>"],
                "reportNames": report_paths.iter().filter_map(|path| path.file_name()).map(|name| name.to_string_lossy()).collect::<Vec<_>>()
            }))?
        ),
    )?;
    println!("{}", result_path.display());
    Ok(())
}

fn parse_options(arguments: Vec<String>) -> Result<BTreeMap<String, String>> {
    let mut output = BTreeMap::new();
    let mut iterator = arguments.into_iter();
    while let Some(flag) = iterator.next() {
        let key = flag
            .strip_prefix("--")
            .with_context(|| format!("expected --option, got {flag:?}"))?
            .to_owned();
        let value = iterator
            .next()
            .with_context(|| format!("missing value for --{key}"))?;
        if output.insert(key.clone(), value).is_some() {
            anyhow::bail!("duplicate option --{key}");
        }
    }
    Ok(output)
}

fn reject_unknown(options: &BTreeMap<String, String>, allowed: &[&str]) -> Result<()> {
    for key in options.keys() {
        if !allowed.contains(&key.as_str()) {
            anyhow::bail!("unknown option --{key}");
        }
    }
    Ok(())
}

fn required_path(options: &BTreeMap<String, String>, key: &str) -> Result<PathBuf> {
    options
        .get(key)
        .map(PathBuf::from)
        .with_context(|| format!("missing --{key}"))
}
