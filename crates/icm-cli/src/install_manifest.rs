//! Install manifest written by `icm init`.
//!
//! Every time `icm init` configures an AI tool, it records the touched
//! path here. The manifest persists across invocations: subsequent
//! `icm init` runs update entries in place, and `icm uninstall` consumes
//! it to know exactly what to clean up — without
//! having to derive the surface from a hard-coded list.
//!
//! Path: `<icm-data-dir>/install-manifest.json`
//! - Linux/WSL: `~/.local/share/icm/install-manifest.json`
//! - macOS:     `~/Library/Application Support/icm/install-manifest.json`
//! - Windows:   `%APPDATA%\icm\icm\data\install-manifest.json`
//!
//! Schema is versioned (`schema_version`; legacy `version` is accepted)
//! so future migrations stay backwards-compatible.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::provider_journal::{ProviderOwnership, SpliceJournal, SpliceRecord};

const CURRENT_SCHEMA: u32 = 2;
const LEGACY_SCHEMA: u32 = 1;

/// Top-level install manifest persisted at `<data_dir>/install-manifest.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallManifest {
    /// Bumped on incompatible field changes. Always read on load; reject
    /// unknown versions with a clear error so older binaries don't
    /// silently truncate a newer manifest.
    #[serde(alias = "version")]
    pub schema_version: u32,
    /// Version of the `icm` binary that wrote / last updated this file.
    pub icm_version: String,
    /// ISO-8601 timestamp of the last write.
    pub updated_at: String,
    /// One entry per configuration target.
    pub entries: Vec<ManifestEntry>,
    /// Public, bounded schema-v2 provider operation and ownership journal.
    #[serde(
        default,
        rename = "providerOwnership",
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_ownership: Option<ProviderOwnership>,
    /// Exact source inverses are private implementation state. They are never
    /// emitted into the public install manifest.
    #[serde(skip)]
    pub provider_splices: Vec<SpliceRecord>,
}

/// OS-backed lock shared by every current manifest writer. The lock file is
/// intentionally retained: unlinking a locked file permits two processes to
/// lock different inodes under the same name.
pub(crate) struct ManifestLock {
    _file: File,
    manifest_path: PathBuf,
}

/// One configuration mutation recorded by init.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ManifestEntry {
    /// Absolute path of the configuration file ICM wrote to.
    pub path: PathBuf,
    /// Human-readable label of the AI tool ("Claude Code", "Codex CLI",
    /// "OpenCode plugin", "Cursor rule", ...).
    pub tool: String,
    /// What kind of mutation init performed at this path.
    pub kind: EntryKind,
    /// SHA-256 of the file contents before init touched it. `None` when
    /// the file did not exist (a pure-create write).
    pub sha256_before: Option<String>,
    /// File size in bytes before init touched it. 0 for pure creates.
    pub bytes_before: u64,
}

/// What `cmd_init` did at this path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum EntryKind {
    /// JSON file with an `mcpServers.icm` (or sibling) entry inserted.
    JsonMcpServer,
    /// JSON file with hook entries inserted (Claude/Gemini/Codex shape).
    JsonHooks,
    /// JSON file with Copilot's `bash` field hooks.
    JsonCopilotHooks,
    /// TOML file (Codex `config.toml`) with `[mcp_servers.icm]`.
    TomlMcpServer,
    /// YAML file (Continue.dev) with a `- name: icm` block appended.
    YamlContinue,
    /// Markdown file with an `<!-- icm:start --> ... <!-- icm:end -->`
    /// block injected.
    MarkdownBlock,
    /// Whole-file artifact owned solely by init (skill / plugin).
    OwnedFile,
}

impl InstallManifest {
    /// Empty manifest scaffold.
    pub fn empty() -> Self {
        Self {
            schema_version: LEGACY_SCHEMA,
            icm_version: env!("CARGO_PKG_VERSION").to_string(),
            updated_at: iso_timestamp(),
            entries: Vec::new(),
            provider_ownership: None,
            provider_splices: Vec::new(),
        }
    }

    /// Migrate to the schema-v2 provider journal and assign a durable 128-bit
    /// installation/server identity. Legacy snapshots confer no deletion
    /// authority. Returns true when the caller must save before target writes.
    pub(crate) fn ensure_provider_ownership(&mut self) -> Result<bool> {
        if let Some(ownership) = &self.provider_ownership {
            ownership.validate()?;
            return Ok(false);
        }
        self.schema_version = CURRENT_SCHEMA;
        let installation_id = random_identifier("icm")?;
        self.provider_ownership = Some(ProviderOwnership::from_legacy_unproven(installation_id)?);
        Ok(true)
    }

    pub(crate) fn installation_id(&self) -> Result<&str> {
        let id = self
            .provider_ownership
            .as_ref()
            .map(|ownership| ownership.installation_id.as_str())
            .context("install manifest has no installation identity")?;
        validate_installation_id(id)?;
        Ok(id)
    }

    /// Read the manifest at `path`, or return an empty one if the file
    /// does not exist yet. Rejects unknown `schema_version`s loudly.
    pub fn load(path: &Path) -> Result<Self> {
        reject_symlink_components(path)?;
        let mut m = match secure_read(path)? {
            Some(raw) => serde_json::from_slice(&raw)
                .with_context(|| format!("invalid JSON in manifest {}", path.display()))?,
            None => Self::empty(),
        };
        if !(LEGACY_SCHEMA..=CURRENT_SCHEMA).contains(&m.schema_version) {
            anyhow::bail!(
                "install manifest {} was written by a newer icm \
                (unsupported schema {}; maximum {}). Upgrade icm or back up the manifest \
                before re-running init.",
                path.display(),
                m.schema_version,
                CURRENT_SCHEMA,
            );
        }
        if let Some(sidecar) = load_provider_ledger(path)? {
            m.schema_version = CURRENT_SCHEMA;
            m.provider_ownership = Some(sidecar.provider_ownership);
            m.provider_splices = sidecar.records;
        }
        match (m.schema_version, &m.provider_ownership) {
            (LEGACY_SCHEMA, None) => {}
            (CURRENT_SCHEMA, Some(ownership)) => ownership.validate()?,
            (LEGACY_SCHEMA, Some(_)) => {
                anyhow::bail!("schema-1 install manifest cannot contain providerOwnership")
            }
            (CURRENT_SCHEMA, None) => {
                anyhow::bail!("schema-2 install manifest must contain providerOwnership")
            }
            _ => unreachable!("schema range was validated above"),
        }
        Ok(m)
    }

    /// Acquire the cross-process lock used for a provider config plus its
    /// provenance. Callers that hold this across config writes must use
    /// `save_locked` to avoid recursively locking the same file.
    pub(crate) fn lock(path: &Path) -> Result<ManifestLock> {
        let lock_path = sibling_path(path, ".lock");
        prepare_parent(&lock_path)?;
        reject_symlink_components(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&lock_path)
            .with_context(|| format!("cannot open manifest lock {}", lock_path.display()))?;
        file.lock()
            .with_context(|| format!("cannot lock manifest {}", path.display()))?;
        reject_symlink_components(&lock_path)?;
        Ok(ManifestLock {
            _file: file,
            manifest_path: path.to_path_buf(),
        })
    }

    /// Write the manifest, creating the parent directory if needed.
    /// Bumps `updated_at` and `icm_version` on every save.
    pub fn save(&mut self, path: &Path) -> Result<()> {
        let lock = Self::lock(path)?;
        // Only provider.rs mutates provider state. The sidecar wins over a
        // stale snapshot held by another long-lived manifest writer.
        if let Some(sidecar) = load_provider_ledger(path)? {
            self.schema_version = CURRENT_SCHEMA;
            self.provider_ownership = Some(sidecar.provider_ownership);
            self.provider_splices = sidecar.records;
        }
        self.save_locked(path, &lock)
    }

    /// Save while the caller holds `InstallManifest::lock(path)`.
    pub(crate) fn save_locked(&mut self, path: &Path, lock: &ManifestLock) -> Result<()> {
        if lock.manifest_path != path {
            anyhow::bail!("manifest lock does not cover {}", path.display());
        }
        if self.provider_ownership.is_some() {
            self.schema_version = CURRENT_SCHEMA;
        }
        self.updated_at = iso_timestamp();
        self.icm_version = env!("CARGO_PKG_VERSION").to_string();
        prepare_parent(path)?;
        if let Some(ownership) = &self.provider_ownership {
            let sidecar = SpliceJournal {
                version: CURRENT_SCHEMA,
                provider_ownership: ownership.clone(),
                records: self.provider_splices.clone(),
            };
            let ledger_json = sidecar.to_json()?;
            secure_atomic_write(&sibling_path(path, ".provider-ownership"), &ledger_json)
                .with_context(|| format!("cannot write provider ledger for {}", path.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        secure_atomic_write(path, json.as_bytes())
            .with_context(|| format!("cannot write manifest {}", path.display()))?;
        Ok(())
    }

    /// Record (or update) an entry for `path`. If an entry with the
    /// same path already exists, its metadata is left intact —
    /// `sha256_before` reflects the state **before init ever touched
    /// the path**, not the state before this particular run.
    pub fn record(&mut self, entry: ManifestEntry) {
        if self.entries.iter().any(|e| e.path == entry.path) {
            return;
        }
        self.entries.push(entry);
    }

    /// Build a `ManifestEntry` by inspecting `path` on disk. Caller
    /// should invoke this **before** the mutation so the hash captures
    /// the pre-mutation state.
    pub fn entry_from_disk(path: &Path, tool: &str, kind: EntryKind) -> Result<ManifestEntry> {
        if !path.exists() {
            return Ok(ManifestEntry {
                path: path.to_path_buf(),
                tool: tool.to_string(),
                kind,
                sha256_before: None,
                bytes_before: 0,
            });
        }
        let meta =
            std::fs::metadata(path).with_context(|| format!("cannot stat {}", path.display()))?;
        let bytes_before = meta.len();
        let sha256_before = Some(sha256_of(path)?);
        Ok(ManifestEntry {
            path: path.to_path_buf(),
            tool: tool.to_string(),
            kind,
            sha256_before,
            bytes_before,
        })
    }

    /// Number of recorded entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self
                .provider_ownership
                .as_ref()
                .is_none_or(|ownership| ownership.owned_fragments.is_empty())
    }
}

fn load_provider_ledger(path: &Path) -> Result<Option<SpliceJournal>> {
    let ledger_path = sibling_path(path, ".provider-ownership");
    reject_symlink_components(&ledger_path)?;
    let raw = match secure_read(&ledger_path)? {
        Some(raw) => raw,
        None => return Ok(None),
    };
    SpliceJournal::from_json(&raw)
        .with_context(|| format!("invalid provider ledger {}", ledger_path.display()))
        .map(Some)
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

fn prepare_parent(path: &Path) -> Result<()> {
    reject_symlink_components(path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
        reject_symlink_components(parent)?;
    }
    Ok(())
}

/// Atomically replace a file without following symlinked targets or using a
/// predictable temporary pathname. `create_new` makes pre-created temp links
/// harmless; the final rename replaces a link rather than following it.
pub(crate) fn secure_atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    secure_atomic_write_inner(path, content, None)
}

/// Same as `secure_atomic_write`, but rechecks the exact expected target bytes
/// after the temporary file is durable and immediately before replacement.
pub(crate) fn secure_atomic_write_if_unchanged(
    path: &Path,
    expected: Option<&[u8]>,
    content: &[u8],
) -> Result<()> {
    secure_atomic_write_inner(path, content, Some(expected))
}

fn secure_atomic_write_inner(
    path: &Path,
    content: &[u8],
    expected: Option<Option<&[u8]>>,
) -> Result<()> {
    prepare_parent(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_name().unwrap_or_default().to_string_lossy();
    let existing_permissions = std::fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.permissions());
    let mut last_error = None;
    for _ in 0..128 {
        let nonce = random_128_bit_hex()?;
        let temp = parent.join(format!(".{stem}.icm-{nonce}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = match options.open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot create temporary file for {}", path.display())
                })
            }
        };
        let result = (|| -> Result<()> {
            file.write_all(content)
                .with_context(|| format!("cannot write temporary file for {}", path.display()))?;
            if let Some(permissions) = &existing_permissions {
                file.set_permissions(permissions.clone()).with_context(|| {
                    format!("cannot preserve permissions for {}", path.display())
                })?;
            }
            file.sync_all()
                .with_context(|| format!("cannot sync temporary file for {}", path.display()))?;
            reject_symlink_components(path)?;
            if let Some(expected) = expected {
                let current = secure_read(path)?;
                if current.as_deref() != expected {
                    anyhow::bail!("{} changed before atomic replacement", path.display());
                }
            }
            std::fs::rename(&temp, path)
                .with_context(|| format!("cannot replace {}", path.display()))?;
            #[cfg(unix)]
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| format!("cannot sync directory {}", parent.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        return result;
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("temporary name exhaustion")))
        .with_context(|| format!("cannot create temporary file for {}", path.display()))
}

fn validate_installation_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        anyhow::bail!("install manifest contains an invalid installation identity");
    }
    Ok(())
}

pub(crate) fn random_identifier(prefix: &str) -> Result<String> {
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_lowercase()) {
        anyhow::bail!("random identifier prefix must be lowercase ASCII");
    }
    Ok(format!("{prefix}{}", random_128_bit_hex()?))
}

fn random_128_bit_hex() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        anyhow::anyhow!("cannot read the operating-system random source ({error})")
    })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Read a regular file without following a final symlink and verify that its
/// pathname still identifies the opened file after the read.
pub(crate) fn secure_read(path: &Path) -> Result<Option<Vec<u8>>> {
    reject_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("cannot open {}", path.display())),
    };
    let opened = file
        .metadata()
        .with_context(|| format!("cannot stat {}", path.display()))?;
    if !opened.is_file() {
        anyhow::bail!("refusing non-regular file {}", path.display());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    reject_symlink_components(path)?;
    let current =
        std::fs::metadata(path).with_context(|| format!("cannot restat {}", path.display()))?;
    if !same_file(&opened, &current) {
        anyhow::bail!("{} changed while it was being read", path.display());
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.file_type() == right.file_type()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

/// Reject symlinks at the target and in every existing parent component.
/// Missing suffix components are allowed so callers can create new config
/// directories after the already-existing prefix has been validated.
pub(crate) fn reject_symlink_components(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("cannot resolve current directory")?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!("refusing symlinked path component {}", current.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect path component {}", current.display())
                })
            }
        }
    }
    Ok(())
}

/// Resolve the manifest path from `ProjectDirs`. Falls back to
/// `<cwd>/install-manifest.json` only when ProjectDirs is unavailable
/// (stripped sandboxes).
pub(crate) fn default_manifest_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return directories::BaseDirs::new()
            .map(|dirs| {
                dirs.home_dir()
                    .join("Library/Application Support/icm/install-manifest.json")
            })
            .unwrap_or_else(|| PathBuf::from("install-manifest.json"));
    }
    #[cfg(not(target_os = "macos"))]
    directories::ProjectDirs::from("dev", "icm", "icm")
        .map(|dirs| dirs.data_dir().join("install-manifest.json"))
        .unwrap_or_else(|| PathBuf::from("install-manifest.json"))
}

fn sha256_of(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// `YYYY-MM-DDTHH:MM:SSZ` UTC. Manifest is JSON so colons are fine
/// here, unlike the backup directory name.
pub(crate) fn iso_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = epoch_to_ymdhms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn epoch_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let sec_of_day = secs % 86_400;
    let h = (sec_of_day / 3600) as u32;
    let mi = ((sec_of_day % 3600) / 60) as u32;
    let s = (sec_of_day % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if mo <= 2 { y + 1 } else { y };
    (y as i32, mo, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_manifest_has_legacy_schema_and_no_provider_state() {
        let m = InstallManifest::empty();
        assert_eq!(m.schema_version, LEGACY_SCHEMA);
        assert!(m.entries.is_empty());
        assert!(!m.icm_version.is_empty());
        assert!(m.provider_ownership.is_none());
    }

    #[test]
    fn installation_identity_is_random_128_bit_hex_and_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("install-manifest.json");
        let mut manifest = InstallManifest::empty();
        assert!(manifest.ensure_provider_ownership().unwrap());
        let first = manifest.installation_id().unwrap().to_owned();
        assert_eq!(first.len(), 35);
        assert!(first.starts_with("icm"));
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
        assert!(!manifest.ensure_provider_ownership().unwrap());
        assert_eq!(manifest.installation_id().unwrap(), first);
        manifest.save(&path).unwrap();
        assert_eq!(
            InstallManifest::load(&path)
                .unwrap()
                .installation_id()
                .unwrap(),
            first
        );
    }

    #[test]
    fn load_returns_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.json");
        let m = InstallManifest::load(&missing).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/install-manifest.json");
        let mut m = InstallManifest::empty();
        m.record(ManifestEntry {
            path: PathBuf::from("/x/.claude.json"),
            tool: "Claude Code".into(),
            kind: EntryKind::JsonMcpServer,
            sha256_before: Some("abc".into()),
            bytes_before: 42,
        });
        m.save(&path).unwrap();

        let m2 = InstallManifest::load(&path).unwrap();
        assert_eq!(m2.entries.len(), 1);
        assert_eq!(m2.entries[0].tool, "Claude Code");
        assert_eq!(m2.entries[0].kind, EntryKind::JsonMcpServer);
    }

    #[test]
    fn record_is_idempotent_per_path() {
        let mut m = InstallManifest::empty();
        let entry1 = ManifestEntry {
            path: PathBuf::from("/x"),
            tool: "A".into(),
            kind: EntryKind::JsonMcpServer,
            sha256_before: Some("aa".into()),
            bytes_before: 1,
        };
        let entry2 = ManifestEntry {
            path: PathBuf::from("/x"),
            tool: "B".into(),
            kind: EntryKind::TomlMcpServer,
            sha256_before: Some("bb".into()),
            bytes_before: 2,
        };
        m.record(entry1);
        m.record(entry2);
        assert_eq!(m.entries.len(), 1);
        // First write wins — preserves the pre-mutation state.
        assert_eq!(m.entries[0].tool, "A");
        assert_eq!(m.entries[0].sha256_before.as_deref(), Some("aa"));
    }

    #[test]
    fn entry_from_disk_captures_pre_mutation_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.json");
        std::fs::write(&path, "hello").unwrap();
        let entry = InstallManifest::entry_from_disk(&path, "Test", EntryKind::OwnedFile).unwrap();
        assert_eq!(entry.bytes_before, 5);
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            entry.sha256_before.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }

    #[test]
    fn entry_from_disk_handles_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no.json");
        let entry =
            InstallManifest::entry_from_disk(&missing, "Test", EntryKind::OwnedFile).unwrap();
        assert_eq!(entry.bytes_before, 0);
        assert!(entry.sha256_before.is_none());
    }

    #[test]
    fn load_rejects_unknown_schema_version() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("m.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"schema_version":{},"icm_version":"99","updated_at":"x","entries":[]}}"#,
                CURRENT_SCHEMA + 1
            ),
        )
        .unwrap();
        let err = InstallManifest::load(&path).unwrap_err();
        assert!(format!("{err:#}").contains("newer icm"));
    }

    #[test]
    fn load_rejects_schema_provider_ownership_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("m.json");
        std::fs::write(
            &path,
            r#"{"schema_version":2,"icm_version":"old","updated_at":"x","entries":[]}"#,
        )
        .unwrap();
        assert!(InstallManifest::load(&path)
            .unwrap_err()
            .to_string()
            .contains("schema-2"));

        let mut manifest = InstallManifest::empty();
        manifest.ensure_provider_ownership().unwrap();
        manifest.schema_version = LEGACY_SCHEMA;
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(InstallManifest::load(&path)
            .unwrap_err()
            .to_string()
            .contains("schema-1"));
    }

    #[test]
    fn v1_manifest_stays_v1_until_provider_migration() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("m.json");
        std::fs::write(
            &path,
            r#"{"schema_version":1,"icm_version":"old","updated_at":"x","entries":[]}"#,
        )
        .unwrap();
        let mut manifest = InstallManifest::load(&path).unwrap();
        assert!(manifest.provider_ownership.is_none());
        manifest.save(&path).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(value["schema_version"], LEGACY_SCHEMA);
        assert!(value.get("providerOwnership").is_none());
    }

    #[test]
    fn iso_timestamp_known_reference_point() {
        let (y, mo, d, h, mi, s) = epoch_to_ymdhms(1_700_000_000);
        assert_eq!((y, mo, d, h, mi, s), (2023, 11, 14, 22, 13, 20));
    }

    #[test]
    fn provider_ledger_survives_an_already_running_v1_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("install-manifest.json");
        let mut manifest = InstallManifest::empty();
        manifest.ensure_provider_ownership().unwrap();
        manifest.save(&path).unwrap();

        // A v1 process that loaded before the migration can still replace the
        // main file. It cannot know about or truncate the provider ledger.
        std::fs::write(
            &path,
            r#"{"schema_version":1,"icm_version":"old","updated_at":"x","entries":[]}"#,
        )
        .unwrap();
        let recovered = InstallManifest::load(&path).unwrap();
        assert_eq!(recovered.schema_version, CURRENT_SCHEMA);
        assert!(recovered.provider_ownership.is_some());
        assert_eq!(
            recovered.installation_id().unwrap(),
            manifest.installation_id().unwrap()
        );
    }

    #[test]
    fn stale_current_writer_preserves_provider_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("install-manifest.json");
        let mut stale = InstallManifest::empty();
        let mut provider = InstallManifest::empty();
        provider.ensure_provider_ownership().unwrap();
        provider.save(&path).unwrap();

        stale.record(ManifestEntry {
            path: tmp.path().join("other.json"),
            tool: "other".into(),
            kind: EntryKind::OwnedFile,
            sha256_before: None,
            bytes_before: 0,
        });
        stale.save(&path).unwrap();
        let loaded = InstallManifest::load(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(
            loaded.installation_id().unwrap(),
            provider.installation_id().unwrap()
        );
    }

    #[test]
    fn manifest_lock_excludes_a_second_file_descriptor() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("install-manifest.json");
        let first = InstallManifest::lock(&path).unwrap();
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(sibling_path(&path, ".lock"))
            .unwrap();
        assert!(second.try_lock().is_err());
        drop(first);
        second.try_lock().unwrap();
        second.unlock().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secure_write_ignores_predictable_temp_symlink_and_rejects_parent_symlink() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("settings.json");
        let victim = tmp.path().join("victim");
        let predictable = tmp.path().join("settings.json.icm-tmp");
        std::fs::write(&victim, "untouched").unwrap();
        symlink(&victim, &predictable).unwrap();
        secure_atomic_write(&target, b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        secure_atomic_write(&target, b"newer").unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let real_parent = tmp.path().join("real-parent");
        let linked_parent = tmp.path().join("linked-parent");
        std::fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(
            secure_atomic_write(&linked_parent.join("config.json"), b"{}")
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        assert!(!real_parent.join("config.json").exists());
    }
}
