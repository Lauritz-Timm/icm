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
use std::path::{Path, PathBuf};

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
                ],
            )?;
            run_self_test(&options)?;
        }
        "archive" => {
            reject_unknown(
                &options,
                &[
                    "workspace-root",
                    "suite-root",
                    "evidence-root",
                    "output-root",
                ],
            )?;
            let workspace_root = required_path(&options, "workspace-root")?;
            let suite_root = required_path(&options, "suite-root")?;
            let evidence_root = required_path(&options, "evidence-root")?;
            let output_root = required_path(&options, "output-root")?;
            let manifest = archive(
                &workspace_root,
                &suite_root,
                &evidence_root,
                &output_root,
            )?;
            println!("{}", manifest.display());
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
            "unknown command {command:?}; expected verify-design, record-baseline, run, self-test, archive, or golden-from-report"
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
    let roots = [
        base_work.join("root with spaces"),
        base_work.join("røød-東京-🧪"),
    ];
    let mut normalized = Vec::new();
    let mut report_paths = Vec::new();
    for (index, root) in roots.iter().enumerate() {
        let runner = Runner::new(
            workspace_root.clone(),
            suite_root.clone(),
            candidate.clone(),
            root.clone(),
            evidence.clone(),
            format!("{label}-root-{}", index + 1),
            EvaluationMode::RecordBaseline,
        )?;
        let (report, path) = runner.run()?;
        normalized.push(normalization::normalize_report(&report)?);
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
                "normalizedSha256": sandbox::sha256_bytes(&normalized[0]),
                "roots": ["<ROOT_WITH_SPACES>", "<ROOT_WITH_UNICODE>"],
                "reportNames": report_paths.iter().filter_map(|path| path.file_name()).map(|name| name.to_string_lossy()).collect::<Vec<_>>()
            }))?
        ),
    )?;
    println!("{}", result_path.display());
    Ok(())
}

fn archive(
    workspace_root: &Path,
    suite_root: &Path,
    evidence_root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    let user_state = sandbox::UserStatePaths::from_environment()?;
    let workspace_root = sandbox::resolve_existing(workspace_root)?;
    let suite_root = sandbox::resolve_existing(suite_root)?;
    let evidence_root = sandbox::resolve_existing(evidence_root)?;
    let output_root = sandbox::resolve_intent(output_root)?;
    let report_source = suite_root
        .parent()
        .context("suite root has no cleanroom parent")?
        .join("reports")
        .join("evaluation-designer.md");
    let report_source = sandbox::resolve_existing(&report_source)?;
    sandbox::validate_archive_roots(
        &workspace_root,
        &suite_root,
        &evidence_root,
        &report_source,
        &output_root,
        &user_state,
    )?;
    let output_root = sandbox::materialize_resolved(&output_root)?;
    let package_root = output_root.join("icm-cleanroom-evaluation");
    if package_root.exists() {
        anyhow::bail!("archive output already exists: {}", package_root.display());
    }
    let suite_destination = package_root.join("eval");
    let evidence_destination = package_root.join("evidence");
    copy_tree_filtered(&suite_root, &suite_destination)?;
    let report_destination = package_root.join("report").join("evaluation-designer.md");
    if let Some(parent) = report_destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&report_source, &report_destination).with_context(|| {
        format!(
            "copying evaluator report {} to {}",
            report_source.display(),
            report_destination.display()
        )
    })?;
    copy_tree_filtered(&evidence_root, &evidence_destination)?;
    let mut files = recursive_files(&package_root)?;
    files.sort();
    let mut lines = Vec::new();
    for file in files {
        let relative = file.strip_prefix(&package_root)?;
        lines.push(format!(
            "{}  {}",
            sandbox::sha256_file(&file)?,
            relative.to_string_lossy().replace('\\', "/")
        ));
    }
    let manifest = package_root.join("MANIFEST.sha256");
    fs::write(&manifest, format!("{}\n", lines.join("\n")))?;
    Ok(manifest)
}

fn copy_tree_filtered(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source).with_context(|| format!("reading {}", source.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" || name == ".runs" {
            continue;
        }
        let target = destination.join(&name);
        if entry.file_type()?.is_dir() {
            copy_tree_filtered(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn recursive_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut output = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            output.extend(recursive_files(&entry.path())?);
        } else {
            output.push(entry.path());
        }
    }
    Ok(output)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_output_must_not_overlap_any_source() {
        let workspace = std::env::temp_dir().join(format!(
            "icm-cleanroom-archive-policy-test-{}",
            std::process::id()
        ));
        let suite = workspace.join("cleanroom/eval");
        let evidence = workspace.join("evidence");
        let report = workspace.join("cleanroom/reports/evaluation-designer.md");
        let output = suite.join("archive");
        let error = sandbox::validate_archive_roots(
            &workspace,
            &suite,
            &evidence,
            &report,
            &output,
            &sandbox::UserStatePaths::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlapping roots"));
    }
}
