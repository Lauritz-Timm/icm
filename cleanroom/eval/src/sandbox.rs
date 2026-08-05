use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

pub const REQUIRED_ENV: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "ICM_CONFIG",
    "ICM_DB_BACKEND",
    "ICM_READONLY",
    "ICM_PROXY_TOKEN",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "PATH",
    "TZ",
    "LANG",
    "LC_ALL",
    "NO_PROXY",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "RUST_BACKTRACE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
];

#[derive(Debug, Clone)]
pub struct ScenarioSandbox {
    pub root: PathBuf,
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub db: PathBuf,
    pub config: PathBuf,
    pub artifact_dir: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub canary_path: PathBuf,
    pub canary_secret: String,
    pub canary_hash: String,
}

#[derive(Clone)]
struct CanaryRecord {
    root: PathBuf,
    path: PathBuf,
    hash: String,
    secret: String,
}

static CANARY_REGISTRY: OnceLock<Mutex<Vec<CanaryRecord>>> = OnceLock::new();

fn canary_registry() -> &'static Mutex<Vec<CanaryRecord>> {
    CANARY_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn canary_checkpoint() -> Result<usize> {
    Ok(canary_registry()
        .lock()
        .map_err(|_| anyhow::anyhow!("canary registry lock poisoned"))?
        .len())
}

pub fn verify_canaries_since(checkpoint: usize) -> Result<()> {
    let records = canary_registry()
        .lock()
        .map_err(|_| anyhow::anyhow!("canary registry lock poisoned"))?
        .get(checkpoint..)
        .context("invalid canary registry checkpoint")?
        .to_vec();
    for record in records {
        verify_canary_record(&record)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct UserStatePaths {
    homes: Vec<PathBuf>,
    state_dirs: Vec<PathBuf>,
    leak_strings: Vec<String>,
}

impl UserStatePaths {
    pub fn from_environment() -> Result<Self> {
        let mut homes = BTreeSet::new();
        let mut state_dirs = BTreeSet::new();
        let mut leak_strings = BTreeSet::new();
        for key in ["HOME", "USERPROFILE"] {
            if let Some(value) = env::var_os(key) {
                let path = resolve_intent(Path::new(&value))?;
                homes.insert(path);
                let text = value.to_string_lossy().into_owned();
                if text.len() > 3 {
                    leak_strings.insert(text);
                }
            }
        }
        let explicit_state_keys = [
            "APPDATA",
            "LOCALAPPDATA",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
        ];
        for key in explicit_state_keys {
            if let Some(value) = env::var_os(key) {
                let path = resolve_intent(Path::new(&value))?;
                state_dirs.insert(path);
                let text = value.to_string_lossy().into_owned();
                if text.len() > 3 {
                    leak_strings.insert(text);
                }
            }
        }
        add_standard_state_defaults(
            &homes,
            &mut state_dirs,
            env::var_os("XDG_CONFIG_HOME").is_none(),
            env::var_os("XDG_CACHE_HOME").is_none(),
            env::var_os("XDG_DATA_HOME").is_none(),
        )?;
        Ok(Self {
            homes: homes.into_iter().collect(),
            state_dirs: state_dirs.into_iter().collect(),
            leak_strings: leak_strings.into_iter().collect(),
        })
    }

    pub fn leak_strings(&self) -> &[String] {
        &self.leak_strings
    }

    fn validate_workspace(&self, workspace: &Path) -> Result<()> {
        if self.homes.iter().any(|home| workspace == home) {
            anyhow::bail!(
                "workspace root must not equal inherited HOME/USERPROFILE: {}",
                workspace.display()
            );
        }
        if let Some(state) = self
            .state_dirs
            .iter()
            .find(|state| workspace == state.as_path() || workspace.starts_with(state))
        {
            anyhow::bail!(
                "workspace root must not be an inherited user-state directory or descendant: {} is within {}",
                workspace.display(),
                state.display()
            );
        }
        Ok(())
    }

    fn validate_child_path(&self, path: &Path, sandbox_root: &Path, label: &str) -> Result<()> {
        let path = resolve_intent(path)?;
        if path.starts_with(sandbox_root) {
            return Ok(());
        }
        if let Some(home) = self.homes.iter().find(|home| path == home.as_path()) {
            anyhow::bail!(
                "child {label} exposes inherited home path {}",
                home.display()
            );
        }
        if let Some(state) = self
            .state_dirs
            .iter()
            .find(|state| path == state.as_path() || path.starts_with(state))
        {
            anyhow::bail!(
                "child {label} exposes inherited user-state path {}",
                state.display()
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn synthetic(homes: Vec<PathBuf>, state_dirs: Vec<PathBuf>) -> Self {
        Self {
            homes,
            state_dirs,
            leak_strings: Vec::new(),
        }
    }

    #[cfg(test)]
    fn synthetic_with_standard_defaults(homes: Vec<PathBuf>) -> Self {
        let homes: BTreeSet<_> = homes.into_iter().collect();
        let mut state_dirs = BTreeSet::new();
        add_standard_state_defaults(&homes, &mut state_dirs, true, true, true).unwrap();
        Self {
            homes: homes.into_iter().collect(),
            state_dirs: state_dirs.into_iter().collect(),
            leak_strings: Vec::new(),
        }
    }
}

fn add_standard_state_defaults(
    homes: &BTreeSet<PathBuf>,
    state_dirs: &mut BTreeSet<PathBuf>,
    default_xdg_config: bool,
    default_xdg_cache: bool,
    default_xdg_data: bool,
) -> Result<()> {
    for home in homes {
        if default_xdg_config {
            state_dirs.insert(resolve_intent(&home.join(".config"))?);
        }
        if default_xdg_cache {
            state_dirs.insert(resolve_intent(&home.join(".cache"))?);
        }
        if default_xdg_data {
            state_dirs.insert(resolve_intent(&home.join(".local").join("share"))?);
        }
        state_dirs.insert(resolve_intent(
            &home.join("Library").join("Application Support"),
        )?);
        state_dirs.insert(resolve_intent(&home.join("Library").join("Caches"))?);
    }
    Ok(())
}

impl ScenarioSandbox {
    pub fn create(work_root: &Path, run: &str, scenario: &str, compact: bool) -> Result<Self> {
        ensure_safe_root(work_root)?;
        let run_root = work_root.join(safe_component(run));
        let root = run_root.join(safe_component(scenario));
        ensure_lexically_within(&root, work_root)?;
        if root.exists() {
            fs::remove_dir_all(&root)
                .with_context(|| format!("resetting scenario root {}", root.display()))?;
        }

        let home = root.join("synthetic-home");
        let cwd = root.join("eval-project");
        let config_dir = root.join("xdg-config");
        let cache_dir = root.join("xdg-cache");
        let data_dir = root.join("xdg-data");
        let temp_dir = root.join("temp");
        let appdata = root.join("windows-appdata");
        let local_appdata = root.join("windows-local-appdata");
        let empty_path = root.join("empty-path");
        let artifact_dir = root.join("artifacts");
        let codex_home = root.join("codex-home");
        let claude_config = root.join("claude-config");
        let db = root.join("database").join("memories.sqlite3");
        let config = config_dir.join("icm").join("config.toml");

        for dir in [
            &home,
            &cwd,
            &config_dir,
            &cache_dir,
            &data_dir,
            &temp_dir,
            &appdata,
            &local_appdata,
            &empty_path,
            &artifact_dir,
            &codex_home,
            &claude_config,
        ] {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        if let Some(parent) = config.parent() {
            fs::create_dir_all(parent)?;
        }
        let config_text = format!(
            "[embeddings]\nenabled = false\n\n[memory]\nauto_consolidate_enabled = false\n\n[mcp]\ncompact = {compact}\n"
        );
        fs::write(&config, config_text)
            .with_context(|| format!("writing synthetic config {}", config.display()))?;

        fs::create_dir_all(&run_root)?;
        let canary_secret = format!(
            "ICM_EVAL_CANARY_V4_{}",
            sha256_bytes(format!("icm-cleanroom-v4|{run}|{scenario}").as_bytes())
        );
        let canary_dir = run_root.join(".canaries");
        fs::create_dir_all(&canary_dir)?;
        let canary_path = canary_dir.join(format!(
            "{}.sentinel",
            sha256_bytes(format!("path|{run}|{scenario}").as_bytes())
        ));
        fs::write(&canary_path, format!("{canary_secret}\n"))?;
        let canary_hash = sha256_file(&canary_path)?;

        let mut environment = BTreeMap::new();
        let entries: [(&str, &Path); 13] = [
            ("HOME", &home),
            ("USERPROFILE", &home),
            ("APPDATA", &appdata),
            ("LOCALAPPDATA", &local_appdata),
            ("XDG_CONFIG_HOME", &config_dir),
            ("XDG_CACHE_HOME", &cache_dir),
            ("XDG_DATA_HOME", &data_dir),
            ("TMPDIR", &temp_dir),
            ("TEMP", &temp_dir),
            ("TMP", &temp_dir),
            ("ICM_CONFIG", &config),
            ("CODEX_HOME", &codex_home),
            ("CLAUDE_CONFIG_DIR", &claude_config),
        ];
        for (key, path) in entries {
            environment.insert(OsString::from(key), path.as_os_str().to_owned());
        }
        environment.insert(OsString::from("ICM_DB_BACKEND"), OsString::from("sqlite"));
        environment.insert(OsString::from("ICM_READONLY"), OsString::from("0"));
        environment.insert(OsString::from("PATH"), empty_path.as_os_str().to_owned());
        environment.insert(OsString::from("TZ"), OsString::from("UTC"));
        environment.insert(OsString::from("LANG"), OsString::from("C.UTF-8"));
        environment.insert(OsString::from("LC_ALL"), OsString::from("C.UTF-8"));
        environment.insert(
            OsString::from("NO_PROXY"),
            OsString::from("127.0.0.1,localhost,::1"),
        );
        environment.insert(
            OsString::from("no_proxy"),
            OsString::from("127.0.0.1,localhost,::1"),
        );
        let blocked_proxy = OsString::from("http://127.0.0.1:9");
        environment.insert(OsString::from("HTTP_PROXY"), blocked_proxy.clone());
        environment.insert(OsString::from("HTTPS_PROXY"), blocked_proxy.clone());
        environment.insert(OsString::from("ALL_PROXY"), blocked_proxy);
        environment.insert(OsString::from("RUST_BACKTRACE"), OsString::from("0"));

        // Windows requires these process-bootstrap variables. They are OS
        // locations, not user/provider state, and remain explicitly allowlisted.
        for key in ["SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"] {
            if let Some(value) = env::var_os(key) {
                environment.insert(OsString::from(key), value);
            }
        }

        let sandbox = Self {
            root,
            home,
            cwd,
            db,
            config,
            artifact_dir,
            environment,
            canary_path,
            canary_secret,
            canary_hash,
        };
        canary_registry()
            .lock()
            .map_err(|_| anyhow::anyhow!("canary registry lock poisoned"))?
            .push(CanaryRecord {
                root: sandbox.root.clone(),
                path: sandbox.canary_path.clone(),
                hash: sandbox.canary_hash.clone(),
                secret: sandbox.canary_secret.clone(),
            });
        Ok(sandbox)
    }

    pub fn verify(&self) -> Result<()> {
        for path in [
            &self.home,
            &self.cwd,
            &self.db,
            &self.config,
            &self.artifact_dir,
        ] {
            ensure_lexically_within(path, &self.root)?;
        }
        verify_canary_record(&CanaryRecord {
            root: self.root.clone(),
            path: self.canary_path.clone(),
            hash: self.canary_hash.clone(),
            secret: self.canary_secret.clone(),
        })?;
        let actual: BTreeSet<String> = self
            .environment
            .keys()
            .map(|key| key.to_string_lossy().into_owned())
            .collect();
        let allowed: BTreeSet<String> = REQUIRED_ENV.iter().map(|s| (*s).to_owned()).collect();
        let unexpected: Vec<_> = actual.difference(&allowed).cloned().collect();
        if !unexpected.is_empty() {
            anyhow::bail!("environment contains non-allowlisted keys: {unexpected:?}");
        }
        Ok(())
    }

    pub fn verify_nondisclosure(&self, text: &str) -> Result<()> {
        if text
            .as_bytes()
            .windows(self.canary_secret.len())
            .any(|window| window == self.canary_secret.as_bytes())
        {
            anyhow::bail!("synthetic canary secret appeared in candidate capture");
        }
        Ok(())
    }

    pub fn verify_loopback_configuration(&self) -> Result<()> {
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            let value = self
                .environment
                .get(std::ffi::OsStr::new(key))
                .with_context(|| format!("missing configured {key}"))?
                .to_string_lossy();
            let address = parse_http_socket_address(&value)?;
            if !address.ip().is_loopback() {
                anyhow::bail!("configured {key} is not loopback: {value}");
            }
        }
        for key in ["NO_PROXY", "no_proxy"] {
            let value = self
                .environment
                .get(std::ffi::OsStr::new(key))
                .with_context(|| format!("missing configured {key}"))?
                .to_string_lossy();
            for token in value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if !matches!(token, "127.0.0.1" | "localhost" | "::1") {
                    anyhow::bail!("configured {key} contains non-loopback exemption: {token}");
                }
            }
        }
        Ok(())
    }

    pub fn verify_child_context(
        &self,
        arguments: &[String],
        user_state: &UserStatePaths,
    ) -> Result<()> {
        user_state.validate_child_path(&self.cwd, &self.root, "cwd")?;
        for (key, value) in &self.environment {
            let key = key.to_string_lossy();
            if matches!(
                key.as_ref(),
                "SYSTEMROOT" | "WINDIR" | "COMSPEC" | "PATHEXT"
            ) {
                continue;
            }
            let path = Path::new(value);
            if path.is_absolute() {
                user_state.validate_child_path(path, &self.root, &format!("environment {key}"))?;
            }
        }
        for (index, argument) in arguments.iter().enumerate() {
            let path = Path::new(argument);
            if path.is_absolute() {
                user_state.validate_child_path(path, &self.root, &format!("argument {index}"))?;
            }
        }
        Ok(())
    }
}

pub fn scan_for_real_path_leaks(text: &str, inherited_paths: &[String]) -> Result<()> {
    let leaks: Vec<_> = inherited_paths
        .iter()
        .filter(|path| text.contains(path.as_str()))
        .cloned()
        .collect();
    if leaks.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("candidate output leaked inherited user paths: {leaks:?}")
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("hashing {}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn resolve_existing(path: &Path) -> Result<PathBuf> {
    let resolved = resolve_intent(path)?;
    resolved
        .canonicalize()
        .with_context(|| format!("canonicalizing existing path {}", resolved.display()))
}

pub fn resolve_intent(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("path must not be empty");
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let normalized = normalize_lexical(&absolute)?;
    let mut ancestor = normalized.clone();
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .context("path has no existing ancestor")?
            .to_os_string();
        suffix.push(name);
        if !ancestor.pop() {
            anyhow::bail!("path has no existing ancestor: {}", normalized.display());
        }
    }
    let mut resolved = ancestor
        .canonicalize()
        .with_context(|| format!("canonicalizing ancestor {}", ancestor.display()))?;
    for component in suffix.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

pub fn materialize_resolved(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        anyhow::bail!(
            "materialized root must already be absolute: {}",
            path.display()
        );
    }
    fs::create_dir_all(path)
        .with_context(|| format!("creating configured root {}", path.display()))?;
    let actual = path
        .canonicalize()
        .with_context(|| format!("canonicalizing created root {}", path.display()))?;
    if actual != path {
        anyhow::bail!(
            "configured root changed resolution during creation: {} became {}",
            path.display(),
            actual.display()
        );
    }
    Ok(actual)
}

pub fn validate_runner_roots(
    workspace: &Path,
    suite: &Path,
    work: &Path,
    evidence: &Path,
    user_state: &UserStatePaths,
) -> Result<()> {
    user_state.validate_workspace(workspace)?;
    for (label, root) in [("suite", suite), ("work", work), ("evidence", evidence)] {
        validate_workspace_child(workspace, root, label, user_state)?;
    }
    reject_overlap(suite, "suite", work, "work")?;
    reject_overlap(suite, "suite", evidence, "evidence")?;
    reject_overlap(work, "work", evidence, "evidence")?;
    Ok(())
}

pub fn validate_archive_roots(
    workspace: &Path,
    suite: &Path,
    evidence: &Path,
    report: &Path,
    output: &Path,
    user_state: &UserStatePaths,
) -> Result<()> {
    user_state.validate_workspace(workspace)?;
    for (label, root) in [
        ("suite source", suite),
        ("evidence source", evidence),
        ("report source", report),
        ("archive output", output),
    ] {
        validate_workspace_child(workspace, root, label, user_state)?;
    }
    reject_overlap(suite, "suite source", evidence, "evidence source")?;
    reject_overlap(suite, "suite source", report, "report source")?;
    reject_overlap(evidence, "evidence source", report, "report source")?;
    reject_overlap(suite, "suite source", output, "archive output")?;
    reject_overlap(evidence, "evidence source", output, "archive output")?;
    reject_overlap(report, "report source", output, "archive output")?;
    Ok(())
}

pub fn reject_overlap(
    first: &Path,
    first_label: &str,
    second: &Path,
    second_label: &str,
) -> Result<()> {
    if paths_overlap(first, second) {
        anyhow::bail!(
            "overlapping roots are forbidden: {first_label} {} and {second_label} {}",
            first.display(),
            second.display()
        );
    }
    Ok(())
}

fn validate_workspace_child(
    workspace: &Path,
    root: &Path,
    label: &str,
    user_state: &UserStatePaths,
) -> Result<()> {
    if root == workspace || !root.starts_with(workspace) {
        anyhow::bail!(
            "{label} root must be a strict child of explicit workspace root {}: {}",
            workspace.display(),
            root.display()
        );
    }
    if user_state.homes.iter().any(|home| root == home) {
        anyhow::bail!(
            "{label} root equals inherited HOME/USERPROFILE: {}",
            root.display()
        );
    }
    if let Some(state) = user_state
        .state_dirs
        .iter()
        .find(|state| root == state.as_path() || root.starts_with(state))
    {
        anyhow::bail!(
            "{label} root is an inherited user-state directory or descendant: {} is within {}",
            root.display(),
            state.display()
        );
    }
    Ok(())
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first == second || first.starts_with(second) || second.starts_with(first)
}

fn parse_http_socket_address(value: &str) -> Result<SocketAddr> {
    let authority = value
        .strip_prefix("http://")
        .context("configured proxy is not an http:// socket URL")?
        .trim_end_matches('/');
    authority
        .parse()
        .with_context(|| format!("configured proxy has invalid socket address: {value}"))
}

fn scan_tree_for_secret(root: &Path, secret: &[u8]) -> Result<()> {
    for entry in
        fs::read_dir(root).with_context(|| format!("scanning artifacts {}", root.display()))?
    {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "candidate artifact symlink is forbidden: {}",
                entry.path().display()
            );
        }
        if metadata.is_dir() {
            scan_tree_for_secret(&entry.path(), secret)?;
        } else if metadata.is_file() {
            let bytes = fs::read(entry.path())?;
            if bytes.windows(secret.len()).any(|window| window == secret) {
                anyhow::bail!(
                    "synthetic canary secret appeared in candidate artifact {}",
                    entry.path().display()
                );
            }
        }
    }
    Ok(())
}

fn verify_canary_record(record: &CanaryRecord) -> Result<()> {
    let current_canary = sha256_file(&record.path)?;
    if current_canary != record.hash {
        anyhow::bail!("contamination canary changed: {}", record.path.display());
    }
    scan_tree_for_secret(&record.root, record.secret.as_bytes())
}

pub fn ensure_lexically_within(path: &Path, root: &Path) -> Result<()> {
    let normalized_path = normalize_lexical(path)?;
    let normalized_root = normalize_lexical(root)?;
    if !normalized_path.starts_with(&normalized_root) {
        anyhow::bail!(
            "path escapes configured root: {} is not within {}",
            path.display(),
            root.display()
        );
    }
    Ok(())
}

fn ensure_safe_root(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("work root must not be empty");
    }
    let count = path.components().count();
    if count < 2 {
        anyhow::bail!("work root is too broad: {}", path.display());
    }
    Ok(())
}

fn normalize_lexical(path: &Path) -> Result<PathBuf> {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !output.pop() {
                    anyhow::bail!("unresolved parent component in {}", path.display());
                }
            }
            other => output.push(other.as_os_str()),
        }
    }
    Ok(output)
}

pub fn safe_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn join_pure(style: &str, base: &str, relative: &str) -> Result<String> {
    let separator = match style {
        "posix" => '/',
        "windows" => '\\',
        _ => anyhow::bail!("unknown pure path style {style}"),
    };
    let trimmed_base = base.trim_end_matches(['/', '\\']);
    let trimmed_relative = relative.trim_start_matches(['/', '\\']);
    Ok(format!("{trimmed_base}{separator}{trimmed_relative}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "icm-cleanroom-sandbox-test-{}-{}",
                std::process::id(),
                NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn pure_paths_do_not_depend_on_host_os() {
        assert_eq!(
            join_pure("posix", "/a b", ".config/x").unwrap(),
            "/a b/.config/x"
        );
        assert_eq!(
            join_pure("windows", "C:\\A", "AppData\\x").unwrap(),
            "C:\\A\\AppData\\x"
        );
    }

    #[test]
    fn safe_component_removes_separators() {
        assert_eq!(safe_component("a/b\\c"), "a_b_c");
    }

    #[test]
    fn dedicated_workspace_below_home_is_allowed() {
        let root = TestRoot::new();
        let home = root.0.join("home");
        let workspace = home.join("workspace");
        let suite = workspace.join("suite");
        let work = workspace.join("work");
        let evidence = workspace.join("evidence");
        for path in [&home, &workspace, &suite] {
            fs::create_dir_all(path).unwrap();
        }
        let state = UserStatePaths::synthetic(vec![home], vec![]);
        validate_runner_roots(&workspace, &suite, &work, &evidence, &state).unwrap();
    }

    #[test]
    fn home_and_user_state_roots_are_rejected() {
        let root = TestRoot::new();
        let home = root.0.join("home");
        let workspace = home.join("workspace");
        let state_dir = workspace.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        let state = UserStatePaths::synthetic(vec![home.clone()], vec![state_dir.clone()]);
        let home_error = validate_runner_roots(
            &home,
            &home.join("suite"),
            &home.join("work"),
            &home.join("evidence"),
            &state,
        )
        .unwrap_err();
        assert!(home_error.to_string().contains("must not equal"));

        let state_error = validate_runner_roots(
            &workspace,
            &workspace.join("suite"),
            &state_dir.join("work"),
            &workspace.join("evidence"),
            &state,
        )
        .unwrap_err();
        assert!(state_error.to_string().contains("user-state"));
    }

    #[test]
    fn default_user_state_is_rejected_when_explicit_xdg_is_unset() {
        let root = TestRoot::new();
        let home = root.0.join("home");
        let workspace = home.join(".config").join("evaluation-workspace");
        fs::create_dir_all(&workspace).unwrap();
        let state = UserStatePaths::synthetic_with_standard_defaults(vec![home]);
        let error = validate_runner_roots(
            &workspace,
            &workspace.join("suite"),
            &workspace.join("work"),
            &workspace.join("evidence"),
            &state,
        )
        .unwrap_err();
        assert!(error.to_string().contains("user-state"));
    }

    #[test]
    fn overlapping_work_and_evidence_are_rejected() {
        let root = TestRoot::new();
        let workspace = root.0.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let state = UserStatePaths::synthetic(vec![], vec![]);
        let error = validate_runner_roots(
            &workspace,
            &workspace.join("suite"),
            &workspace.join("work"),
            &workspace.join("work/evidence"),
            &state,
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlapping roots"));
    }

    #[test]
    fn canary_exposure_in_capture_or_any_scenario_file_is_detected() {
        let root = TestRoot::new();
        let sandbox =
            ScenarioSandbox::create(&root.0.join("work"), "run", "scenario", false).unwrap();
        assert!(sandbox
            .verify_nondisclosure(&sandbox.canary_secret)
            .is_err());
        fs::write(
            sandbox.root.join("temp").join("leak.bin"),
            format!("prefix:{}:suffix", sandbox.canary_secret),
        )
        .unwrap();
        assert!(sandbox.verify().is_err());
    }

    #[test]
    fn configured_endpoints_are_loopback() {
        let root = TestRoot::new();
        let sandbox =
            ScenarioSandbox::create(&root.0.join("work"), "run", "loopback", false).unwrap();
        sandbox.verify_loopback_configuration().unwrap();
    }
}
