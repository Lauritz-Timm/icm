#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::install_manifest::{
    default_manifest_path, random_identifier, secure_atomic_write_if_unchanged, secure_read,
    InstallManifest, ManifestLock,
};
use crate::provider_document::{
    insert as insert_source, remove_owned as remove_source_owned,
    try_remove_owned as try_remove_source_owned, validate_and_parse, Insert, ParsedSource,
    SourceFormat, SourcePath,
};
use crate::provider_journal::{
    DocumentOrigin, ExactTransform, OperationAction, OperationPhase, OwnedFragment, OwnershipDelta,
    OwnershipKind, ProviderDialect, ProviderId, ProviderOperation, ProviderScope, ProviderSurface,
    RequestedOperation, SourcePatch, SpliceRecord, TargetIntent, TransformKind,
    MAX_OWNED_FRAGMENTS,
};

const TOOLS: [&str; 2] = ["icm_memory_recall", "icm_memory_store"];

#[derive(Clone, Copy)]
struct ProviderDefinition {
    provider: Provider,
    id: ProviderId,
    surface: ProviderSurface,
    dialect: ProviderDialect,
    permission: PermissionShape,
    project: &'static [DocumentTemplate],
    user: &'static [DocumentTemplate],
}

#[derive(Clone, Copy)]
enum PermissionShape {
    Codex,
    Claude,
    Cursor,
    OpenCode,
    Zed,
}

#[derive(Clone, Copy)]
struct DocumentTemplate {
    location: Location,
    kind: DocumentKind,
}

#[derive(Clone, Copy)]
enum Location {
    Project(&'static str),
    Home(&'static str),
    CodexUser,
    ClaudeLegacyUser,
    ClaudeSettingsUser,
    OpenCodeUser,
    ZedUser,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DocumentKind {
    Codex,
    JsonRegistration,
    JsonPermissions,
    OpenCode,
    Zed,
}

impl DocumentKind {
    fn owns_rule(self, rule: &str) -> bool {
        match self {
            Self::Codex => rule.starts_with("mcp_servers."),
            Self::JsonRegistration => rule.starts_with("mcpServers."),
            Self::JsonPermissions => !rule.starts_with("mcpServers."),
            Self::OpenCode => rule.starts_with("mcp.servers.") || rule.contains("|*|"),
            Self::Zed => {
                rule.starts_with("context_servers.")
                    || rule.starts_with("agent.tool_permissions.tools.")
            }
        }
    }

    fn source_format(self, path: &Path) -> SourceFormat {
        if self == Self::Codex {
            SourceFormat::Toml
        } else if path
            .extension()
            .is_some_and(|extension| extension == "jsonc")
        {
            SourceFormat::Jsonc
        } else {
            SourceFormat::Json
        }
    }

    fn relevant_roots(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["mcp_servers"],
            Self::JsonRegistration => &["mcpServers"],
            Self::JsonPermissions => &["permissions"],
            Self::OpenCode => &["mcp", "permissions", "agents"],
            Self::Zed => &["context_servers", "agent"],
        }
    }
}

const CODEX_PROJECT: &[DocumentTemplate] = &[DocumentTemplate {
    location: Location::Project(".codex/config.toml"),
    kind: DocumentKind::Codex,
}];
const CODEX_USER: &[DocumentTemplate] = &[DocumentTemplate {
    location: Location::CodexUser,
    kind: DocumentKind::Codex,
}];
const CLAUDE_PROJECT: &[DocumentTemplate] = &[
    DocumentTemplate {
        location: Location::Project(".mcp.json"),
        kind: DocumentKind::JsonRegistration,
    },
    DocumentTemplate {
        location: Location::Project(".claude/settings.local.json"),
        kind: DocumentKind::JsonPermissions,
    },
];
const CLAUDE_USER: &[DocumentTemplate] = &[
    DocumentTemplate {
        location: Location::ClaudeLegacyUser,
        kind: DocumentKind::JsonRegistration,
    },
    DocumentTemplate {
        location: Location::ClaudeSettingsUser,
        kind: DocumentKind::JsonPermissions,
    },
];
const CURSOR_PROJECT: &[DocumentTemplate] = &[
    DocumentTemplate {
        location: Location::Project(".cursor/mcp.json"),
        kind: DocumentKind::JsonRegistration,
    },
    DocumentTemplate {
        location: Location::Project(".cursor/cli.json"),
        kind: DocumentKind::JsonPermissions,
    },
];
const CURSOR_USER: &[DocumentTemplate] = &[
    DocumentTemplate {
        location: Location::Home(".cursor/mcp.json"),
        kind: DocumentKind::JsonRegistration,
    },
    DocumentTemplate {
        location: Location::Home(".cursor/cli-config.json"),
        kind: DocumentKind::JsonPermissions,
    },
];
const OPENCODE_PROJECT: &[DocumentTemplate] = &[DocumentTemplate {
    location: Location::Project("opencode.json"),
    kind: DocumentKind::OpenCode,
}];
const OPENCODE_USER: &[DocumentTemplate] = &[DocumentTemplate {
    location: Location::OpenCodeUser,
    kind: DocumentKind::OpenCode,
}];
const ZED_PROJECT: &[DocumentTemplate] = &[DocumentTemplate {
    location: Location::Project(".zed/settings.json"),
    kind: DocumentKind::Zed,
}];
const ZED_USER: &[DocumentTemplate] = &[DocumentTemplate {
    location: Location::ZedUser,
    kind: DocumentKind::Zed,
}];

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_FIRST_DOCUMENT_WRITE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
fn fail_after_first_document_write<T>(operation: impl FnOnce() -> T) -> T {
    FAIL_AFTER_FIRST_DOCUMENT_WRITE.with(|fail| fail.set(true));
    let result = operation();
    FAIL_AFTER_FIRST_DOCUMENT_WRITE.with(|fail| fail.set(false));
    result
}

/// The source-controlled authorization allowlist. Paths, formats, rule
/// shapes, plan metadata, and lifecycle tests all derive from this table.
const PROVIDER_REGISTRY: &[ProviderDefinition] = &[
    ProviderDefinition {
        provider: Provider::Codex,
        id: ProviderId::Codex,
        surface: ProviderSurface::CombinedRegistrationAndPermission,
        dialect: ProviderDialect::CodexTomlV1,
        permission: PermissionShape::Codex,
        project: CODEX_PROJECT,
        user: CODEX_USER,
    },
    ProviderDefinition {
        provider: Provider::ClaudeCode,
        id: ProviderId::ClaudeCode,
        surface: ProviderSurface::SplitRegistrationAndPermission,
        dialect: ProviderDialect::ClaudeJsonV1,
        permission: PermissionShape::Claude,
        project: CLAUDE_PROJECT,
        user: CLAUDE_USER,
    },
    ProviderDefinition {
        provider: Provider::Cursor,
        id: ProviderId::Cursor,
        surface: ProviderSurface::SplitRegistrationAndPermission,
        dialect: ProviderDialect::CursorJsonV1,
        permission: PermissionShape::Cursor,
        project: CURSOR_PROJECT,
        user: CURSOR_USER,
    },
    ProviderDefinition {
        provider: Provider::OpenCode,
        id: ProviderId::OpenCode,
        surface: ProviderSurface::CombinedRegistrationAndPermission,
        dialect: ProviderDialect::OpenCodeJsonV2,
        permission: PermissionShape::OpenCode,
        project: OPENCODE_PROJECT,
        user: OPENCODE_USER,
    },
    ProviderDefinition {
        provider: Provider::Zed,
        id: ProviderId::Zed,
        surface: ProviderSurface::CombinedRegistrationAndPermission,
        dialect: ProviderDialect::ZedJsonV1,
        permission: PermissionShape::Zed,
        project: ZED_PROJECT,
        user: ZED_USER,
    },
];

#[derive(Args, Debug)]
pub(crate) struct ProviderArgs {
    #[command(subcommand)]
    action: ProviderAction,
}

#[derive(Subcommand, Debug)]
enum ProviderAction {
    /// Register the MCP server and trust exactly the two memory tools.
    Trust(MutationArgs),
    /// Remove only provider values previously written by ICM.
    Strip(MutationArgs),
    /// Resolve and validate a provider plan without changing files.
    Doctor(TargetArgs),
    /// Reconcile one interrupted provider mutation from its durable intent.
    Recover(MutationArgs),
}

#[derive(Args, Debug)]
struct MutationArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Confirm the provider configuration mutation.
    #[arg(long)]
    yes: bool,
}

#[derive(Args, Debug)]
struct TargetArgs {
    #[arg(long, value_enum)]
    provider: Provider,
    #[arg(long, value_enum)]
    scope: Scope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Provider {
    Codex,
    ClaudeCode,
    Cursor,
    #[value(name = "opencode")]
    OpenCode,
    Zed,
}

impl Provider {
    #[cfg(test)]
    fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::OpenCode => "opencode",
            Self::Zed => "zed",
        }
    }

    fn definition(self) -> &'static ProviderDefinition {
        PROVIDER_REGISTRY
            .iter()
            .find(|definition| definition.provider == self)
            .expect("every typed provider is registered")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Scope {
    ProjectLocal,
    User,
}

impl Scope {
    #[cfg(test)]
    const ALL: [Self; 2] = [Self::ProjectLocal, Self::User];

    fn as_str(self) -> &'static str {
        match self {
            Self::ProjectLocal => "project-local",
            Self::User => "user",
        }
    }

    fn journal_scope(self) -> ProviderScope {
        match self {
            Self::ProjectLocal => ProviderScope::ProjectLocal,
            Self::User => ProviderScope::User,
        }
    }
}

fn provider_from_journal(provider: ProviderId) -> Provider {
    match provider {
        ProviderId::Codex => Provider::Codex,
        ProviderId::ClaudeCode => Provider::ClaudeCode,
        ProviderId::Cursor => Provider::Cursor,
        ProviderId::OpenCode => Provider::OpenCode,
        ProviderId::Zed => Provider::Zed,
    }
}

fn scope_from_journal(scope: ProviderScope) -> Scope {
    match scope {
        ProviderScope::ProjectLocal => Scope::ProjectLocal,
        ProviderScope::User => Scope::User,
    }
}

fn opposite_scope(scope: Scope) -> Scope {
    match scope {
        Scope::ProjectLocal => Scope::User,
        Scope::User => Scope::ProjectLocal,
    }
}

struct ProviderSpec {
    definition: &'static ProviderDefinition,
    provider: Provider,
    scope: Scope,
    /// The one or more documents this lifecycle operation may mutate.
    documents: Vec<DocumentSpec>,
    /// Documents OpenCode merges to produce the effective configuration.
    inspection_documents: Vec<DocumentSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DocumentSpec {
    path: PathBuf,
    kind: DocumentKind,
}

struct Observation {
    path: PathBuf,
    rule: String,
    exists: bool,
    blocked: bool,
    expected: JsonValue,
}

#[derive(Clone)]
enum DocumentValue {
    Json(JsonValue),
    Toml(toml::Value),
}

struct PreparedSourceDocument {
    document: DocumentSpec,
    document_origin: DocumentOrigin,
    before: Vec<u8>,
    after: Vec<u8>,
    observations: Vec<Observation>,
    patches: BTreeMap<String, SourcePatch>,
}

struct PreparedRemovalDocument {
    document: DocumentSpec,
    before_state: DocumentOrigin,
    before: Vec<u8>,
    after: Option<Vec<u8>>,
    fragments: Vec<OwnedFragment>,
}

struct RebasedRecoveryDocument {
    document: DocumentSpec,
    before_state: DocumentOrigin,
    before: Vec<u8>,
    after: Option<Vec<u8>>,
}

struct RecoveryPlan {
    documents: Vec<RebasedRecoveryDocument>,
    replacement_paths: BTreeSet<String>,
    replacement_splices: Vec<SpliceRecord>,
    terminal_phase: OperationPhase,
}

type RecoveryStates = BTreeMap<String, (DocumentOrigin, Vec<u8>, String)>;

#[derive(Clone, Copy)]
enum LifecycleAction {
    Apply,
    Strip,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemovalMode {
    TrustOnly,
    Uninstall,
}

#[derive(Default)]
pub(crate) struct StripSummary {
    pub(crate) outcomes: Vec<StripPathOutcome>,
}

pub(crate) struct StripPathOutcome {
    pub(crate) path: PathBuf,
    pub(crate) entries_removed: usize,
    pub(crate) deleted: bool,
}

pub(crate) struct OwnedProviderPath {
    pub(crate) path: PathBuf,
    pub(crate) entries_owned: usize,
}

impl StripSummary {
    fn add(&mut self, other: Self) {
        self.outcomes.extend(other.outcomes);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedPlan {
    paths: Vec<String>,
    surface: ProviderSurface,
    scope: &'static str,
    dialect: ProviderDialect,
    server_id: String,
    tool_rules: Vec<String>,
    preserved_restrictions: Vec<String>,
    causal_blockers: Vec<String>,
    ownership_disposition: Vec<OwnershipDisposition>,
}

#[derive(Serialize)]
struct OwnershipDisposition {
    path: String,
    rule: String,
    disposition: &'static str,
}

impl ResolvedPlan {
    fn has_blocker(&self) -> bool {
        self.ownership_disposition
            .iter()
            .any(|item| item.disposition == "blocked-existing")
    }

    fn has_only_permission_blockers(&self) -> bool {
        self.has_blocker()
            && self.ownership_disposition.iter().all(|item| {
                item.disposition != "blocked-existing" || self.tool_rules.contains(&item.rule)
            })
    }
}

pub(crate) fn run(args: &ProviderArgs) -> Result<()> {
    let (plan, fail_after_plan) = match &args.action {
        ProviderAction::Doctor(target) => {
            let manifest = InstallManifest::load(&default_manifest_path())?;
            (
                resolve_plan(target.provider, target.scope, true, &manifest)?,
                false,
            )
        }
        ProviderAction::Trust(args) => {
            require_yes(args)?;
            let plan = mutate_target(&args.target, LifecycleAction::Apply)?;
            let blocked = plan.has_only_permission_blockers();
            (plan, blocked)
        }
        ProviderAction::Strip(args) => {
            require_yes(args)?;
            (mutate_target(&args.target, LifecycleAction::Strip)?, false)
        }
        ProviderAction::Recover(args) => {
            require_yes(args)?;
            (recover_target(&args.target)?, false)
        }
    };
    println!("{}", serde_json::to_string(&plan)?);
    if fail_after_plan {
        bail!("provider configuration contains a conflicting value");
    }
    Ok(())
}

fn recover_target(target: &TargetArgs) -> Result<ResolvedPlan> {
    let manifest_path = default_manifest_path();
    let lock = InstallManifest::lock(&manifest_path)?;
    let mut manifest = InstallManifest::load(&manifest_path)?;
    let server_id = installation_server_id(&manifest)?;
    recover_provenance(&mut manifest, target, &server_id, &manifest_path, &lock)?;
    resolve_plan(target.provider, target.scope, false, &manifest)
}

fn mutate_target(target: &TargetArgs, action: LifecycleAction) -> Result<ResolvedPlan> {
    let manifest_path = default_manifest_path();
    let lock = InstallManifest::lock(&manifest_path)?;
    let mut manifest = InstallManifest::load(&manifest_path)?;
    if matches!(action, LifecycleAction::Apply) {
        manifest.ensure_provider_ownership()?;
    }
    let server_id = match action {
        LifecycleAction::Apply => installation_server_id(&manifest)?,
        LifecycleAction::Strip => planning_server_id(&manifest),
    };
    reject_prepared_operations(&manifest)?;
    let enforce_resolution = matches!(action, LifecycleAction::Apply);
    let plan = resolve_plan(target.provider, target.scope, enforce_resolution, &manifest)?;
    let spec = provider_spec(target.provider, target.scope)?;
    match action {
        LifecycleAction::Apply => {
            if plan.has_blocker() {
                if plan.has_only_permission_blockers() {
                    return Ok(plan);
                }
                bail!("provider configuration contains a conflicting value");
            }
            apply_documents(&spec, &server_id, &mut manifest, &manifest_path, &lock)?;
        }
        LifecycleAction::Strip => {
            strip_documents(
                target.provider,
                target.scope,
                &spec.documents,
                RemovalMode::TrustOnly,
                &mut manifest,
                &manifest_path,
                &lock,
            )?;
        }
    }
    Ok(plan)
}

fn require_yes(args: &MutationArgs) -> Result<()> {
    if !args.yes {
        bail!("provider mutations require --yes");
    }
    Ok(())
}

fn reject_prepared_operations(manifest: &InstallManifest) -> Result<()> {
    if manifest
        .provider_ownership
        .as_ref()
        .is_some_and(|ownership| {
            ownership
                .operations
                .iter()
                .any(|operation| operation.phase == OperationPhase::Prepared)
        })
    {
        bail!("provider mutation recovery is required; run `icm provider recover ... --yes`");
    }
    Ok(())
}

pub(crate) fn owned_paths() -> Result<Vec<OwnedProviderPath>> {
    let manifest = InstallManifest::load(&default_manifest_path())?;
    Ok(group_owned_paths(&manifest))
}

fn group_owned_paths(manifest: &InstallManifest) -> Vec<OwnedProviderPath> {
    let mut paths = BTreeMap::<PathBuf, usize>::new();
    for fragment in manifest
        .provider_ownership
        .as_ref()
        .into_iter()
        .flat_map(|ownership| &ownership.owned_fragments)
        .filter(|fragment| fragment.ownership_kind == OwnershipKind::Owned)
    {
        *paths
            .entry(PathBuf::from(&fragment.canonical_path))
            .or_default() += 1;
    }
    paths
        .into_iter()
        .map(|(path, entries_owned)| OwnedProviderPath {
            path,
            entries_owned,
        })
        .collect()
}

/// Provider-uninstall path used by `icm uninstall`: remove owned trust first,
/// then the exact owned registration. The provider `strip` command passes
/// `TrustOnly` instead and deliberately retains registration.
pub(crate) fn strip_all_owned() -> Result<StripSummary> {
    let manifest_path = default_manifest_path();
    let lock = InstallManifest::lock(&manifest_path)?;
    let mut manifest = InstallManifest::load(&manifest_path)?;
    if manifest.provider_ownership.is_none() {
        return Ok(StripSummary::default());
    }
    reject_prepared_operations(&manifest)?;
    let mut targets = BTreeMap::<(Provider, Scope), BTreeSet<(PathBuf, DocumentKind)>>::new();
    for fragment in manifest
        .provider_ownership
        .as_ref()
        .expect("provider ownership was checked")
        .owned_fragments
        .iter()
        .filter(|fragment| fragment.ownership_kind == OwnershipKind::Owned)
    {
        let provider = provider_from_journal(fragment.provider);
        let scope = scope_from_journal(fragment.scope);
        let kind = owned_document_kind(provider, &fragment.semantic_selector)?;
        targets
            .entry((provider, scope))
            .or_default()
            .insert((PathBuf::from(&fragment.canonical_path), kind));
    }
    let mut summary = StripSummary::default();
    for ((provider, scope), documents) in targets {
        let documents = documents
            .into_iter()
            .map(|(path, kind)| DocumentSpec { path, kind })
            .collect::<Vec<_>>();
        let stripped = strip_documents(
            provider,
            scope,
            &documents,
            RemovalMode::Uninstall,
            &mut manifest,
            &manifest_path,
            &lock,
        )?;
        summary.add(stripped);
    }
    Ok(summary)
}

fn resolve_plan(
    provider: Provider,
    scope: Scope,
    enforce_resolution: bool,
    manifest: &InstallManifest,
) -> Result<ResolvedPlan> {
    if enforce_resolution && provider == Provider::OpenCode {
        reject_opencode_external_overrides(scope)?;
    }
    let spec = provider_spec(provider, scope)?;
    if enforce_resolution {
        validate_resolved_paths(&spec)?;
    }
    let server_id = planning_server_id(manifest);
    let observations = inspect(&spec, &server_id)?;
    let (preserved_restrictions, causal_blockers) = observed_restrictions(&spec, &server_id)?;

    if enforce_resolution {
        let opposite = provider_spec(provider, opposite_scope(scope))?;
        validate_resolved_paths(&opposite)?;
        reject_opposite_scope_binding(&inspect_local(&opposite, &server_id)?)?;
    }

    let ownership_disposition = observations
        .iter()
        .filter(|observation| {
            spec.documents
                .iter()
                .find(|document| document.path == observation.path)
                .is_none_or(|document| public_observation(document.kind, observation))
        })
        .map(|observation| -> Result<OwnershipDisposition> {
            let fragment = manifest.provider_ownership.as_ref().and_then(|ownership| {
                ownership.owned_fragments.iter().find(|fragment| {
                    fragment.provider == provider.definition().id
                        && fragment.scope == scope.journal_scope()
                        && Path::new(&fragment.canonical_path) == observation.path
                        && fragment.semantic_selector == observation.rule
                })
            });
            Ok(OwnershipDisposition {
                path: utf8_path(&observation.path)?.to_owned(),
                rule: observation.rule.clone(),
                disposition: if observation.blocked {
                    "blocked-existing"
                } else if fragment.is_some_and(|fragment| {
                    fragment.ownership_kind == OwnershipKind::Removed && !observation.exists
                }) {
                    "already-removed"
                } else if fragment.is_some_and(|fragment| {
                    fragment.ownership_kind == OwnershipKind::Owned && observation.exists
                }) {
                    "owned-existing"
                } else if observation.exists {
                    "preexisting-adopted"
                } else {
                    "new-owned"
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ResolvedPlan {
        paths: spec
            .documents
            .iter()
            .map(|document| utf8_path(&document.path).map(str::to_owned))
            .collect::<Result<Vec<_>>>()?,
        surface: spec.definition.surface,
        scope: spec.scope.as_str(),
        dialect: spec.definition.dialect,
        server_id: server_id.clone(),
        tool_rules: tool_rules(provider, &server_id),
        preserved_restrictions: preserved_restrictions.into_iter().collect(),
        causal_blockers: causal_blockers.into_iter().collect(),
        ownership_disposition,
    })
}

fn reject_opposite_scope_binding(observations: &[Observation]) -> Result<()> {
    if observations
        .first()
        .is_some_and(|registration| registration.exists || registration.blocked)
        || observations.iter().skip(1).any(|item| item.blocked)
    {
        bail!("the same provider identity is active in the opposite scope");
    }
    Ok(())
}

fn provider_spec(provider: Provider, scope: Scope) -> Result<ProviderSpec> {
    let definition = provider.definition();
    let home = directories::BaseDirs::new()
        .context("cannot resolve the user home directory")?
        .home_dir()
        .to_path_buf();
    let cwd = std::env::current_dir().context("cannot resolve current project directory")?;
    let xdg_config = env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    let templates = match scope {
        Scope::ProjectLocal => definition.project,
        Scope::User => definition.user,
    };
    let mut documents = templates
        .iter()
        .map(|template| -> Result<DocumentSpec> {
            let path = match template.location {
                Location::Project(relative) => project_path(provider, relative, &cwd)?,
                Location::Home(relative) => home.join(relative),
                Location::CodexUser => std::env::var_os("CODEX_HOME")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".codex"))
                    .join("config.toml"),
                Location::ClaudeLegacyUser => std::env::var_os("CLAUDE_CONFIG_DIR")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.clone())
                    .join(".claude.json"),
                Location::ClaudeSettingsUser => std::env::var_os("CLAUDE_CONFIG_DIR")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".claude"))
                    .join("settings.json"),
                Location::OpenCodeUser => xdg_config.join("opencode/opencode.json"),
                Location::ZedUser => platform_config_dir(&home, &xdg_config, "zed", "Zed", "Zed")
                    .join("settings.json"),
            };
            let path = if provider == Provider::OpenCode {
                path
            } else {
                provider_config_at(provider, &path)?
            };
            Ok(DocumentSpec {
                path,
                kind: template.kind,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut inspection_documents = documents.clone();
    if provider == Provider::OpenCode {
        let global = xdg_config.join("opencode/opencode.json");
        (documents, inspection_documents) = opencode_documents(scope, &cwd, &global)?;
    }
    if documents
        .iter()
        .any(|document| !document.path.is_absolute())
    {
        bail!("provider configuration roots must be absolute");
    }
    Ok(ProviderSpec {
        definition,
        provider,
        scope,
        documents,
        inspection_documents,
    })
}

fn opencode_documents(
    scope: Scope,
    cwd: &Path,
    global_default: &Path,
) -> Result<(Vec<DocumentSpec>, Vec<DocumentSpec>)> {
    if scope == Scope::User {
        let global = opencode_config_at(global_default)?;
        let target = global.unwrap_or_else(|| global_default.to_path_buf());
        let document = DocumentSpec {
            path: target,
            kind: DocumentKind::OpenCode,
        };
        return Ok((vec![document.clone()], vec![document]));
    }

    let directories = opencode_project_directories(cwd)?;
    let mut project = Vec::new();
    for directory in &directories {
        if let Some(path) = opencode_config_at(&directory.join("opencode.json"))? {
            project.push(path);
        }
    }
    for directory in &directories {
        if let Some(path) = opencode_config_at(&directory.join(".opencode/opencode.json"))? {
            project.push(path);
        }
    }

    let target = project
        .last()
        .cloned()
        .unwrap_or_else(|| cwd.join("opencode.json"));
    let mutation = DocumentSpec {
        path: target.clone(),
        kind: DocumentKind::OpenCode,
    };
    let global =
        opencode_config_at(global_default)?.unwrap_or_else(|| global_default.to_path_buf());
    let mut inspection = std::iter::once(global)
        .chain(project)
        .map(|path| DocumentSpec {
            path,
            kind: DocumentKind::OpenCode,
        })
        .collect::<Vec<_>>();
    if !inspection.iter().any(|document| document.path == target) {
        inspection.push(mutation.clone());
    }
    Ok((vec![mutation], inspection))
}

fn opencode_project_directories(cwd: &Path) -> Result<Vec<PathBuf>> {
    let root = project_root(cwd)?;
    let mut directories = cwd
        .ancestors()
        .take_while(|directory| *directory != root)
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    directories.push(root);
    directories.reverse();
    Ok(directories)
}

fn project_path(provider: Provider, relative: &str, cwd: &Path) -> Result<PathBuf> {
    let root = project_root(cwd)?;
    let root = if provider == Provider::ClaudeCode && relative == ".claude/settings.local.json" {
        main_checkout_root(&root)?
    } else {
        root
    };
    Ok(root.join(relative))
}

fn project_root(cwd: &Path) -> Result<PathBuf> {
    for directory in cwd.ancestors() {
        if path_present(&directory.join(".git"))? {
            return Ok(directory.to_path_buf());
        }
    }
    Ok(cwd.to_path_buf())
}

fn main_checkout_root(worktree_root: &Path) -> Result<PathBuf> {
    let marker = worktree_root.join(".git");
    if !path_present(&marker)? {
        return Ok(worktree_root.to_path_buf());
    }
    let metadata = std::fs::symlink_metadata(&marker)
        .with_context(|| format!("cannot inspect {}", marker.display()))?;
    if metadata.file_type().is_dir() {
        return Ok(worktree_root.to_path_buf());
    }
    let Some(marker) = secure_read(&marker)? else {
        return Ok(worktree_root.to_path_buf());
    };
    let marker = std::str::from_utf8(&marker).context("worktree .git file is not UTF-8")?;
    let Some(git_dir) = marker.trim().strip_prefix("gitdir:") else {
        return Ok(worktree_root.to_path_buf());
    };
    let git_dir = PathBuf::from(git_dir.trim());
    let git_dir = if git_dir.is_absolute() {
        git_dir
    } else {
        worktree_root.join(git_dir)
    };
    let Some(common_dir) = secure_read(&git_dir.join("commondir"))? else {
        return Ok(worktree_root.to_path_buf());
    };
    let common_dir = std::str::from_utf8(&common_dir).context("Git commondir is not UTF-8")?;
    let common_dir = git_dir
        .join(common_dir.trim())
        .canonicalize()
        .context("cannot resolve the main checkout Git directory")?;
    if common_dir.file_name().is_some_and(|name| name == ".git") {
        return common_dir
            .parent()
            .map(Path::to_path_buf)
            .context("main checkout Git directory has no parent");
    }
    bail!("linked worktree commondir is not a main checkout .git directory")
}

fn opencode_config_at(json: &Path) -> Result<Option<PathBuf>> {
    let jsonc = json.with_extension("jsonc");
    sole_config_candidate(json, &jsonc)
}

fn provider_config_at(provider: Provider, primary: &Path) -> Result<PathBuf> {
    let alternate = if provider == Provider::Codex {
        primary.with_file_name("config.local.toml")
    } else {
        primary.with_extension("jsonc")
    };
    Ok(sole_config_candidate(primary, &alternate)?.unwrap_or_else(|| primary.to_path_buf()))
}

fn sole_config_candidate(primary: &Path, alternate: &Path) -> Result<Option<PathBuf>> {
    match (path_present(primary)?, path_present(alternate)?) {
        (true, true) => bail!(
            "ambiguous provider configuration: both {} and {} exist",
            primary.display(),
            alternate.display()
        ),
        (true, false) => Ok(Some(primary.to_path_buf())),
        (false, true) => Ok(Some(alternate.to_path_buf())),
        (false, false) => Ok(None),
    }
}

fn path_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn reject_opencode_external_overrides(scope: Scope) -> Result<()> {
    for key in [
        "OPENCODE_CONFIG",
        "OPENCODE_CONFIG_DIR",
        "OPENCODE_CONFIG_CONTENT",
        "OPENCODE_PERMISSION",
    ] {
        if std::env::var_os(key).is_some_and(|value| !value.is_empty()) {
            bail!("cannot verify OpenCode trust while {key} supplies an external override");
        }
    }
    if scope == Scope::ProjectLocal
        && std::env::var_os("OPENCODE_DISABLE_PROJECT_CONFIG").is_some_and(|value| {
            matches!(
                value.to_string_lossy().to_ascii_lowercase().as_str(),
                "1" | "true"
            )
        })
    {
        bail!("OpenCode project configuration is disabled by the environment");
    }
    for path in managed_opencode_paths() {
        if path_present(&path)? {
            bail!(
                "cannot verify OpenCode trust while managed configuration exists at {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn managed_opencode_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    return vec![
        PathBuf::from("/etc/opencode/opencode.json"),
        PathBuf::from("/etc/opencode/opencode.jsonc"),
    ];
    #[cfg(target_os = "macos")]
    return vec![
        PathBuf::from("/Library/Application Support/opencode/opencode.json"),
        PathBuf::from("/Library/Application Support/opencode/opencode.jsonc"),
        PathBuf::from("/Library/Managed Preferences/ai.opencode.managed.plist"),
    ];
    #[cfg(target_os = "windows")]
    return env_path("ProgramData")
        .into_iter()
        .flat_map(|root| {
            ["opencode.json", "opencode.jsonc"].map(|file| root.join("opencode").join(file))
        })
        .collect();
    #[allow(unreachable_code)]
    Vec::new()
}

#[cfg(test)]
fn document(path: PathBuf, kind: DocumentKind) -> DocumentSpec {
    DocumentSpec { path, kind }
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn utf8_path(path: &Path) -> Result<&str> {
    path.to_str()
        .context("provider paths and executable names must be valid UTF-8")
}

fn platform_config_dir(
    home: &Path,
    xdg_config: &Path,
    linux: &str,
    macos: &str,
    windows: &str,
) -> PathBuf {
    #[cfg(target_os = "macos")]
    return home.join("Library/Application Support").join(macos);
    #[cfg(target_os = "windows")]
    return env_path("APPDATA")
        .unwrap_or_else(|| home.join("AppData/Roaming"))
        .join(windows);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (home, macos, windows);
        xdg_config.join(linux)
    }
}

fn installation_server_id(manifest: &InstallManifest) -> Result<String> {
    Ok(manifest.installation_id()?.to_owned())
}

fn planning_server_id(manifest: &InstallManifest) -> String {
    manifest
        .provider_ownership
        .as_ref()
        .map(|ownership| ownership.installation_id.clone())
        .unwrap_or_else(|| "icm".to_owned())
}

fn validate_resolved_paths(spec: &ProviderSpec) -> Result<()> {
    for document in &spec.documents {
        if spec.provider == Provider::OpenCode
            && path_present(&document.path)?
            && std::fs::metadata(&document.path)
                .with_context(|| format!("cannot inspect {}", document.path.display()))?
                .permissions()
                .readonly()
        {
            bail!(
                "highest-precedence OpenCode configuration is read-only: {}",
                document.path.display()
            );
        }
    }
    Ok(())
}

fn inspect(spec: &ProviderSpec, server_id: &str) -> Result<Vec<Observation>> {
    let mut observations = inspect_local(spec, server_id)?;
    if spec.provider == Provider::OpenCode {
        let effective = inspect_effective(spec, server_id)?;
        for observation in &mut observations {
            if let Some(effective) = effective
                .iter()
                .find(|effective| effective.rule == observation.rule)
            {
                observation.blocked |= effective.blocked;
            }
        }
    }
    Ok(observations)
}

fn inspect_local(spec: &ProviderSpec, server_id: &str) -> Result<Vec<Observation>> {
    let mut observations = Vec::new();
    for document in &spec.documents {
        let (_, value) = read_document(document)?;
        observations.extend(inspect_document(
            spec.provider,
            document,
            &value,
            server_id,
        )?);
    }
    Ok(observations)
}

fn inspect_effective(spec: &ProviderSpec, server_id: &str) -> Result<Vec<Observation>> {
    if spec.provider != Provider::OpenCode {
        return inspect_local(spec, server_id);
    }
    let target = spec
        .documents
        .first()
        .context("OpenCode registry has no mutation document")?;
    let effective = effective_opencode_value(spec)?;
    inspect_document(
        spec.provider,
        target,
        &DocumentValue::Json(effective),
        server_id,
    )
}

fn observed_restrictions(
    spec: &ProviderSpec,
    server_id: &str,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut preserved = BTreeSet::new();
    let mut causal = BTreeSet::new();
    let documents = if spec.provider == Provider::OpenCode {
        vec![DocumentValue::Json(effective_opencode_value(spec)?)]
    } else {
        spec.documents
            .iter()
            .map(|document| read_document(document).map(|(_, value)| value))
            .collect::<Result<Vec<_>>>()?
    };
    for value in &documents {
        match (spec.provider, value) {
            (Provider::Codex, DocumentValue::Toml(value)) => {
                let root = value.as_table().context("Codex root is not a table")?;
                for (id, server) in optional_table(root.get("mcp_servers"), "mcp_servers")? {
                    let Some(server) = server.as_table() else {
                        continue;
                    };
                    for tool in string_set(server.get("disabled_tools"))? {
                        let rendered = format!("mcp_servers.{id}.disabled_tools:{tool}");
                        if id == server_id && TOOLS.contains(&tool.as_str()) {
                            causal.insert(rendered);
                        } else {
                            preserved.insert(rendered);
                        }
                    }
                    let Some(tools) = server.get("tools").and_then(toml::Value::as_table) else {
                        continue;
                    };
                    for (tool, rule) in tools {
                        let Some(mode) = rule
                            .as_table()
                            .and_then(|rule| rule.get("approval_mode"))
                            .and_then(toml::Value::as_str)
                        else {
                            continue;
                        };
                        if mode == "approve" {
                            continue;
                        }
                        let rendered =
                            format!("mcp_servers.{id}.tools.{tool}.approval_mode={mode}");
                        if id == server_id && TOOLS.contains(&tool.as_str()) {
                            causal.insert(rendered);
                        } else {
                            preserved.insert(rendered);
                        }
                    }
                }
            }
            (Provider::ClaudeCode | Provider::Cursor, DocumentValue::Json(value)) => {
                let root = value.as_object().expect("validated JSON root");
                let permissions = root.get("permissions").and_then(JsonValue::as_object);
                for field in ["deny", "ask"] {
                    for pattern in json_string_set(
                        permissions.and_then(|permissions| permissions.get(field)),
                        &format!("permissions.{field}"),
                    )? {
                        let rendered = format!("permissions.{field}:{pattern}");
                        if TOOLS.iter().any(|tool| {
                            permission_rule(spec.provider, server_id, tool).is_ok_and(|rule| {
                                permission_matches(spec.provider, &pattern, &rule)
                            })
                        }) {
                            causal.insert(rendered);
                        } else {
                            preserved.insert(rendered);
                        }
                    }
                }
                if spec.provider == Provider::Cursor {
                    preserved.insert("ideTrust=prompt-only".to_owned());
                }
            }
            (Provider::OpenCode, DocumentValue::Json(value)) => {
                let root = value.as_object().expect("validated JSON root");
                if let Some(servers) = root
                    .get("mcp")
                    .and_then(JsonValue::as_object)
                    .and_then(|mcp| mcp.get("servers"))
                    .and_then(JsonValue::as_object)
                {
                    for (id, server) in servers {
                        if server.as_object().and_then(|server| server.get("disabled"))
                            == Some(&JsonValue::Bool(true))
                        {
                            let rendered = format!("mcp.servers.{id}.disabled=true");
                            if id == server_id {
                                causal.insert(rendered);
                            } else {
                                preserved.insert(rendered);
                            }
                        }
                    }
                }
                let rules =
                    opencode_permission_rules(root.get("permissions"), "OpenCode permissions")?;
                let managed_actions = TOOLS.map(|tool| format!("{server_id}_{tool}"));
                let effective = managed_actions
                    .iter()
                    .filter_map(|managed| {
                        rules.iter().rposition(|rule| {
                            glob_matches(
                                rule["action"].as_str().expect("validated action"),
                                managed,
                            ) && glob_matches(
                                rule["resource"].as_str().expect("validated resource"),
                                "*",
                            )
                        })
                    })
                    .collect::<BTreeSet<_>>();
                for (index, rule) in rules.into_iter().enumerate() {
                    let action = rule["action"].as_str().expect("validated action");
                    let resource = rule["resource"].as_str().expect("validated resource");
                    let effect = rule["effect"].as_str().expect("validated effect");
                    let rendered = format!("permissions:{action}|{resource}|{effect}");
                    let matches_managed = managed_actions.iter().any(|managed| {
                        glob_matches(action, managed) && glob_matches(resource, "*")
                    });
                    if matches_managed && effective.contains(&index) && effect != "allow" {
                        causal.insert(rendered);
                    } else if !matches_managed && effect != "allow" {
                        preserved.insert(rendered);
                    }
                }
                preserved.insert("last-matching-rule-wins".to_owned());
            }
            (Provider::Zed, DocumentValue::Json(value)) => {
                let tools = value
                    .pointer("/agent/tool_permissions/tools")
                    .and_then(JsonValue::as_object);
                if let Some(default) = value
                    .pointer("/agent/tool_permissions/default")
                    .and_then(JsonValue::as_str)
                {
                    preserved.insert(format!("agent.tool_permissions.default={default}"));
                }
                for (key, rule) in tools.into_iter().flatten() {
                    let Some(rule) = rule.as_object() else {
                        continue;
                    };
                    for field in ["always_deny", "always_confirm"] {
                        if let Some(values) =
                            rule.get(field).filter(|value| nonempty_json_array(value))
                        {
                            let rendered =
                                format!("agent.tool_permissions.tools.{key}.{field}={values}");
                            if TOOLS
                                .iter()
                                .any(|tool| key == &format!("mcp:{server_id}:{tool}"))
                            {
                                causal.insert(rendered);
                            } else {
                                preserved.insert(rendered);
                            }
                        }
                    }
                    let Some(default) = rule.get("default").and_then(JsonValue::as_str) else {
                        continue;
                    };
                    if default == "allow" {
                        continue;
                    }
                    let rendered = format!("agent.tool_permissions.tools.{key}.default={default}");
                    if TOOLS
                        .iter()
                        .any(|tool| key == &format!("mcp:{server_id}:{tool}"))
                    {
                        causal.insert(rendered);
                    } else {
                        preserved.insert(rendered);
                    }
                }
            }
            _ => {}
        }
    }
    Ok((preserved, causal))
}

fn effective_opencode_value(spec: &ProviderSpec) -> Result<JsonValue> {
    let mut effective = serde_json::json!({});
    for document in &spec.inspection_documents {
        let (_, value) = read_document(document)?;
        let DocumentValue::Json(value) = value else {
            bail!("OpenCode registry paired a document with the wrong format");
        };
        merge_json(&mut effective, value);
    }
    Ok(effective)
}

fn merge_json(target: &mut JsonValue, source: JsonValue) {
    match (target, source) {
        (JsonValue::Object(target), JsonValue::Object(source)) => {
            for (key, value) in source {
                match target.get_mut(&key) {
                    Some(target) => merge_json(target, value),
                    None => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, source) => *target = source,
    }
}

fn inspect_document(
    provider: Provider,
    document: &DocumentSpec,
    value: &DocumentValue,
    server_id: &str,
) -> Result<Vec<Observation>> {
    match (document.kind, value) {
        (DocumentKind::Codex, DocumentValue::Toml(value)) => {
            inspect_codex_value(&document.path, value, server_id)
        }
        (DocumentKind::JsonRegistration, DocumentValue::Json(value)) => {
            inspect_json_registration(provider, &document.path, value, server_id)
        }
        (DocumentKind::JsonPermissions, DocumentValue::Json(value)) => {
            inspect_json_permissions(provider, &document.path, value, server_id)
        }
        (DocumentKind::OpenCode, DocumentValue::Json(value)) => {
            inspect_opencode(&document.path, value, server_id)
        }
        (DocumentKind::Zed, DocumentValue::Json(value)) => {
            inspect_zed(&document.path, value, server_id)
        }
        _ => bail!("provider registry paired a document with the wrong format"),
    }
}

fn observation(
    path: &Path,
    rule: String,
    actual: Option<JsonValue>,
    expected: JsonValue,
    blocked: bool,
) -> Observation {
    let exists = actual.as_ref() == Some(&expected);
    let blocked = blocked || actual.as_ref().is_some_and(|actual| actual != &expected);
    Observation {
        path: path.to_path_buf(),
        rule,
        exists,
        blocked,
        expected,
    }
}

fn inspect_json_registration(
    provider: Provider,
    path: &Path,
    value: &JsonValue,
    server_id: &str,
) -> Result<Vec<Observation>> {
    let registration_root = value.as_object().expect("validated JSON root");
    reject_json_keys(
        registration_root,
        &["mcp", "context_servers", "permission", "agent"],
    )?;
    let servers = match registration_root.get("mcpServers") {
        Some(value) => Some(value.as_object().context("mcpServers is not an object")?),
        None => None,
    };
    reject_normalization_collisions(
        servers
            .into_iter()
            .flat_map(|servers| servers.keys().map(String::as_str)),
    )?;
    let actual = servers.and_then(|servers| servers.get(server_id)).cloned();
    let existing_registration = actual.as_ref();
    if let Some(value) = existing_registration {
        value
            .as_object()
            .context("existing provider registration is not an object")?;
    }
    Ok(vec![observation(
        path,
        format!("mcpServers.{server_id}"),
        actual,
        json_registration(provider)?,
        false,
    )])
}

fn inspect_json_permissions(
    provider: Provider,
    path: &Path,
    value: &JsonValue,
    server_id: &str,
) -> Result<Vec<Observation>> {
    let permission_root = value.as_object().expect("validated JSON root");
    reject_json_keys(
        permission_root,
        &[
            "permission",
            "mcp",
            "mcpServers",
            "context_servers",
            "agent",
        ],
    )?;
    let permissions = match permission_root.get("permissions") {
        Some(value) => Some(value.as_object().context("permissions is not an object")?),
        None => None,
    };
    let allow = json_string_set(
        permissions.and_then(|permissions| permissions.get("allow")),
        "permissions.allow",
    )?;
    let deny = json_string_set(
        permissions.and_then(|permissions| permissions.get("deny")),
        "permissions.deny",
    )?;
    let ask = json_string_set(
        permissions.and_then(|permissions| permissions.get("ask")),
        "permissions.ask",
    )?;
    let mut observations = Vec::new();
    for tool in TOOLS {
        let rule = permission_rule(provider, server_id, tool)?;
        let blocked = deny
            .iter()
            .chain(ask.iter())
            .any(|pattern| permission_matches(provider, pattern, &rule));
        let actual = allow
            .contains(&rule)
            .then(|| JsonValue::String(rule.clone()));
        observations.push(observation(
            path,
            rule.clone(),
            actual,
            JsonValue::String(rule),
            blocked,
        ));
    }
    Ok(observations)
}

fn permission_rule(provider: Provider, server_id: &str, tool: &str) -> Result<String> {
    match provider.definition().permission {
        PermissionShape::Claude => Ok(format!("mcp__{server_id}__{tool}")),
        PermissionShape::Cursor => Ok(format!("Mcp({server_id}:{tool})")),
        _ => bail!("provider does not use split JSON permissions"),
    }
}

fn permission_matches(provider: Provider, pattern: &str, rule: &str) -> bool {
    match provider.definition().permission {
        PermissionShape::Claude => {
            pattern == rule
                || rule
                    .strip_prefix(pattern)
                    .is_some_and(|suffix| suffix.starts_with("__"))
                || glob_matches(pattern, rule)
        }
        PermissionShape::Cursor => glob_matches(pattern, rule),
        _ => false,
    }
}

fn inspect_opencode(path: &Path, value: &JsonValue, server_id: &str) -> Result<Vec<Observation>> {
    let root = value.as_object().expect("validated JSON root");
    reject_json_keys(
        root,
        &["permission", "mcpServers", "context_servers", "agent"],
    )?;
    let mcp = match root.get("mcp") {
        Some(value) => Some(value.as_object().context("OpenCode mcp is not an object")?),
        None => None,
    };
    let servers = match mcp.and_then(|mcp| mcp.get("servers")) {
        Some(value) => Some(
            value
                .as_object()
                .context("OpenCode mcp.servers is not an object")?,
        ),
        None => None,
    };
    reject_normalization_collisions(
        servers
            .into_iter()
            .flat_map(|servers| servers.keys().map(String::as_str)),
    )?;
    let actual_registration = servers.and_then(|servers| servers.get(server_id)).cloned();
    let existing_registration = actual_registration.as_ref();
    if let Some(value) = existing_registration {
        value
            .as_object()
            .context("existing OpenCode provider registration is not an object")?;
    }
    let expected_registration = opencode_registration()?;
    let permissions = opencode_permission_rules(root.get("permissions"), "OpenCode permissions")?;
    let agent_permissions = match root.get("agents") {
        Some(value) => value
            .as_object()
            .context("OpenCode agents is not an object")?
            .iter()
            .map(|(id, agent)| {
                let agent = agent
                    .as_object()
                    .with_context(|| format!("OpenCode agent {id:?} is not an object"))?;
                opencode_permission_rules(
                    agent.get("permissions"),
                    &format!("OpenCode agent {id:?} permissions"),
                )
            })
            .collect::<Result<Vec<_>>>()?,
        None => Vec::new(),
    };
    let mut observations = vec![observation(
        path,
        format!("mcp.servers.{server_id}"),
        actual_registration,
        expected_registration,
        false,
    )];
    for tool in TOOLS {
        let action = format!("{server_id}_{tool}");
        let effect = opencode_permission_effect(&permissions, &action);
        let agent_blocked = agent_permissions.iter().any(|rules| {
            opencode_permission_effect(rules, &action).is_some_and(|effect| effect != "allow")
        });
        let exact = permissions.iter().find(|rule| {
            rule["action"].as_str() == Some(action.as_str())
                && rule["resource"].as_str() == Some("*")
                && rule["effect"].as_str() == Some("allow")
        });
        let expected = serde_json::json!({
            "action": action.clone(),
            "resource": "*",
            "effect": "allow"
        });
        observations.push(observation(
            path,
            format!("{action}|*|allow"),
            exact.map(|rule| JsonValue::Object((*rule).clone())),
            expected,
            effect.is_some_and(|effect| effect != "allow") || agent_blocked,
        ));
    }
    Ok(observations)
}

fn opencode_permission_rules<'a>(
    value: Option<&'a JsonValue>,
    field: &str,
) -> Result<Vec<&'a serde_json::Map<String, JsonValue>>> {
    value
        .map(|value| {
            value
                .as_array()
                .with_context(|| format!("{field} must be a v2 rule array"))?
                .iter()
                .map(|rule| {
                    let rule = rule
                        .as_object()
                        .with_context(|| format!("{field} rule is not an object"))?;
                    for key in ["action", "resource", "effect"] {
                        rule.get(key)
                            .and_then(JsonValue::as_str)
                            .with_context(|| format!("{field} rule lacks string {key}"))?;
                    }
                    Ok(rule)
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn opencode_permission_effect<'a>(
    rules: &'a [&'a serde_json::Map<String, JsonValue>],
    action: &str,
) -> Option<&'a str> {
    rules
        .iter()
        .rev()
        .find(|rule| {
            glob_matches(rule["action"].as_str().expect("validated action"), action)
                && glob_matches(rule["resource"].as_str().expect("validated resource"), "*")
        })
        .and_then(|rule| rule["effect"].as_str())
}

fn inspect_zed(path: &Path, value: &JsonValue, server_id: &str) -> Result<Vec<Observation>> {
    let root = value.as_object().expect("validated JSON root");
    reject_json_keys(root, &["permissions", "permission", "mcpServers", "mcp"])?;
    let servers = match root.get("context_servers") {
        Some(value) => Some(
            value
                .as_object()
                .context("Zed context_servers is not an object")?,
        ),
        None => None,
    };
    reject_normalization_collisions(
        servers
            .into_iter()
            .flat_map(|servers| servers.keys().map(String::as_str)),
    )?;
    let actual_registration = servers.and_then(|servers| servers.get(server_id)).cloned();
    let existing_registration = actual_registration.as_ref();
    if let Some(value) = existing_registration {
        value
            .as_object()
            .context("existing Zed provider registration is not an object")?;
    }
    let expected_registration = json_registration(Provider::Zed)?;
    let agent = match root.get("agent") {
        Some(value) => Some(value.as_object().context("Zed agent is not an object")?),
        None => None,
    };
    let permissions = match agent.and_then(|agent| agent.get("tool_permissions")) {
        Some(value) => Some(
            value
                .as_object()
                .context("Zed agent.tool_permissions is not an object")?,
        ),
        None => None,
    };
    let tools = match permissions.and_then(|permissions| permissions.get("tools")) {
        Some(value) => Some(
            value
                .as_object()
                .context("Zed agent.tool_permissions.tools is not an object")?,
        ),
        None => None,
    };
    let mut observations = vec![observation(
        path,
        format!("context_servers.{server_id}"),
        actual_registration,
        expected_registration,
        false,
    )];
    for tool in TOOLS {
        let key = format!("mcp:{server_id}:{tool}");
        let rule = tools
            .and_then(|tools| tools.get(&key))
            .map(|rule| {
                rule.as_object()
                    .context("Zed tool permission is not an object")
            })
            .transpose()?;
        let default = rule.and_then(|rule| rule.get("default")).cloned();
        let higher_precedence = rule.is_some_and(|rule| {
            ["always_deny", "always_confirm"]
                .iter()
                .any(|field| rule.get(*field).is_some_and(nonempty_json_array))
        });
        observations.push(observation(
            path,
            format!("agent.tool_permissions.tools.{key}.default=allow"),
            default,
            JsonValue::String("allow".to_owned()),
            higher_precedence,
        ));
    }
    Ok(observations)
}

fn nonempty_json_array(value: &JsonValue) -> bool {
    value.as_array().is_none_or(|values| !values.is_empty())
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let value = value.chars().collect::<Vec<_>>();
    let (mut pattern_at, mut value_at, mut star, mut retry_at) = (0, 0, None, 0);
    while value_at < value.len() {
        if pattern
            .get(pattern_at)
            .is_some_and(|token| *token == '?' || glob_chars_equal(*token, value[value_at]))
        {
            pattern_at += 1;
            value_at += 1;
        } else if pattern.get(pattern_at) == Some(&'*') {
            star = Some(pattern_at);
            pattern_at += 1;
            retry_at = value_at;
        } else if let Some(star_at) = star {
            pattern_at = star_at + 1;
            retry_at += 1;
            value_at = retry_at;
        } else {
            return false;
        }
    }
    pattern[pattern_at..].iter().all(|token| *token == '*')
}

fn glob_chars_equal(left: char, right: char) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(&right)
    } else {
        left == right
    }
}

fn reject_json_keys(root: &serde_json::Map<String, JsonValue>, keys: &[&str]) -> Result<()> {
    if keys.iter().any(|key| root.contains_key(*key)) {
        bail!("provider configuration uses an unknown or mixed dialect");
    }
    Ok(())
}

fn json_string_set(value: Option<&JsonValue>, field: &str) -> Result<BTreeSet<String>> {
    match value {
        None => Ok(BTreeSet::new()),
        Some(value) => value
            .as_array()
            .with_context(|| format!("{field} is not an array"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .with_context(|| format!("{field} contains a non-string value"))
            })
            .collect(),
    }
}

fn read_document(document: &DocumentSpec) -> Result<(Vec<u8>, DocumentValue)> {
    let bytes = read_provider_document(&document.path)?;
    let value = parse_document_source(document, &bytes)?;
    Ok((bytes, value))
}

fn read_document_snapshot(
    document: &DocumentSpec,
) -> Result<(DocumentOrigin, Vec<u8>, DocumentValue)> {
    let (state, bytes) = read_provider_document_snapshot(&document.path)?;
    let value = parse_document_source(document, &bytes)?;
    Ok((state, bytes, value))
}

fn parse_document_source(document: &DocumentSpec, bytes: &[u8]) -> Result<DocumentValue> {
    match validate_and_parse(
        document.kind.source_format(&document.path),
        bytes,
        document.kind.relevant_roots(),
    )
    .with_context(|| format!("invalid provider config {}", document.path.display()))?
    {
        ParsedSource::Json(value) => Ok(DocumentValue::Json(value)),
        ParsedSource::Toml(value) => Ok(DocumentValue::Toml(value)),
    }
}

fn inspect_codex_value(
    path: &Path,
    value: &toml::Value,
    server_id: &str,
) -> Result<Vec<Observation>> {
    let root = value
        .as_table()
        .with_context(|| format!("provider TOML root is not a table in {}", path.display()))?;
    if [
        "mcpServers",
        "mcp",
        "context_servers",
        "permissions",
        "permission",
    ]
    .iter()
    .any(|key| root.contains_key(*key))
    {
        bail!(
            "{} uses an unknown or mixed provider dialect",
            path.display()
        );
    }
    let servers = optional_table(root.get("mcp_servers"), "mcp_servers")?;
    reject_normalization_collisions(servers.keys().map(String::as_str))?;
    let server = servers
        .get(server_id)
        .map(|value| {
            value
                .as_table()
                .context("existing Codex provider registration is not a table")
        })
        .transpose()?;
    let expected_registration = codex_registration()?;
    let expected_registration_table = expected_registration
        .as_table()
        .expect("canonical Codex registration is a table");
    let registration_blocked = server.is_some_and(|server| {
        server.get("command") != expected_registration_table.get("command")
            || server.get("args") != expected_registration_table.get("args")
            || server.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "command" | "args" | "enabled_tools" | "disabled_tools" | "tools"
                )
            })
    });
    let mut observations = vec![Observation {
        path: path.to_path_buf(),
        rule: format!("mcp_servers.{server_id}"),
        exists: server.is_some(),
        blocked: registration_blocked,
        expected: serde_json::to_value(expected_registration)?,
    }];

    let enabled = server.and_then(|table| table.get("enabled_tools"));
    let (enabled_exists, enabled_blocked) = exact_tool_set(enabled)?;
    let disabled = string_set(server.and_then(|table| table.get("disabled_tools")))?;
    observations.push(Observation {
        path: path.to_path_buf(),
        rule: format!("mcp_servers.{server_id}.enabled_tools"),
        exists: enabled_exists,
        blocked: enabled_blocked || TOOLS.iter().any(|tool| disabled.contains(*tool)),
        expected: serde_json::json!(TOOLS),
    });

    for tool in TOOLS {
        let approval = server
            .and_then(|table| table.get("tools"))
            .map(|value| value.as_table().context("Codex tools is not a table"))
            .transpose()?
            .and_then(|tools| tools.get(tool))
            .map(|value| value.as_table().context("Codex tool rule is not a table"))
            .transpose()?
            .and_then(|rule| rule.get("approval_mode"));
        let exists = approval.and_then(toml::Value::as_str) == Some("approve");
        observations.push(Observation {
            path: path.to_path_buf(),
            rule: format!("mcp_servers.{server_id}.tools.{tool}.approval_mode=approve"),
            exists,
            blocked: approval.is_some() && !exists,
            expected: JsonValue::String("approve".to_owned()),
        });
    }
    Ok(observations)
}

fn reject_blocked_observations(observations: &[Observation]) -> Result<()> {
    if observations.iter().any(|observation| observation.blocked) {
        bail!("provider configuration contains a conflicting value");
    }
    Ok(())
}

fn reject_opencode_permission_shadowing(spec: &ProviderSpec) -> Result<()> {
    if spec.provider != Provider::OpenCode || spec.inspection_documents.len() < 2 {
        return Ok(());
    }
    let target = spec
        .documents
        .first()
        .context("OpenCode target is missing")?;
    let (_, target_value) = read_document(target)?;
    let DocumentValue::Json(target_value) = target_value else {
        bail!("OpenCode registry paired a document with the wrong format");
    };
    if target_value.get("permissions").is_some() {
        return Ok(());
    }
    for document in &spec.inspection_documents {
        if document.path == target.path {
            break;
        }
        let (_, value) = read_document(document)?;
        if matches!(value, DocumentValue::Json(value) if value.get("permissions").is_some()) {
            bail!(
                "writing {} would shadow lower-precedence OpenCode permissions",
                target.path.display()
            );
        }
    }
    Ok(())
}

fn prepare_source_document(
    spec: &ProviderSpec,
    document: &DocumentSpec,
    server_id: &str,
) -> Result<PreparedSourceDocument> {
    let (state, before, value) = read_document_snapshot(document)?;
    let observations = inspect_document(spec.provider, document, &value, server_id)?;
    reject_blocked_observations(&observations)?;
    let mut after = before.clone();
    let mut patches = BTreeMap::new();

    let observation = |rule: &str| -> Result<&Observation> {
        observations
            .iter()
            .find(|observation| observation.rule == rule)
            .with_context(|| format!("provider plan lacks rule {rule:?}"))
    };
    match document.kind {
        DocumentKind::Codex => {
            let registration_rule = format!("mcp_servers.{server_id}");
            if !observation(&registration_rule)?.exists {
                let registration = codex_registration()?;
                let registration = registration
                    .as_table()
                    .context("canonical Codex registration is not a table")?;
                let values = ["command", "args"]
                    .into_iter()
                    .map(|key| {
                        registration
                            .get(key)
                            .cloned()
                            .map(|value| (key.to_owned(), value))
                            .with_context(|| format!("Codex registration lacks {key}"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::TomlTable {
                        path: SourcePath::new(["mcp_servers", server_id]),
                        values,
                    },
                )?;
                patches.insert(registration_rule, patch);
            }

            let enabled_rule = format!("mcp_servers.{server_id}.enabled_tools");
            let internal_patch = if observation(&enabled_rule)?.exists {
                None
            } else {
                Some(apply_source_insert(
                    document,
                    &mut after,
                    Insert::TomlScalar {
                        table: SourcePath::new(["mcp_servers", server_id]),
                        key: "enabled_tools".to_owned(),
                        value: toml::Value::Array(
                            TOOLS
                                .iter()
                                .map(|tool| toml::Value::String((*tool).to_owned()))
                                .collect(),
                        ),
                    },
                )?)
            };

            let mut first_owned_tool = None;
            for tool in TOOLS {
                let rule = format!("mcp_servers.{server_id}.tools.{tool}.approval_mode=approve");
                if observation(&rule)?.exists {
                    continue;
                }
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::TomlScalar {
                        table: SourcePath::new(["mcp_servers", server_id, "tools", tool]),
                        key: "approval_mode".to_owned(),
                        value: toml::Value::String("approve".to_owned()),
                    },
                )?;
                first_owned_tool.get_or_insert_with(|| rule.clone());
                patches.insert(rule, patch);
            }
            if let Some(internal) = internal_patch {
                let owner = first_owned_tool
                    .context("Codex enabled_tools changed without an owned tool-rule insertion")?;
                merge_internal_patch(
                    patches
                        .get_mut(&owner)
                        .expect("owned Codex tool patch was recorded"),
                    internal,
                );
            }
        }
        DocumentKind::JsonRegistration => {
            let rule = format!("mcpServers.{server_id}");
            if !observation(&rule)?.exists {
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::JsonMember {
                        parent: SourcePath::new(["mcpServers"]),
                        key: server_id.to_owned(),
                        value: json_registration(spec.provider)?,
                    },
                )?;
                patches.insert(rule, patch);
            }
        }
        DocumentKind::JsonPermissions => {
            for rule in tool_rules(spec.provider, server_id) {
                if observation(&rule)?.exists {
                    continue;
                }
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::JsonArrayElement {
                        array: SourcePath::new(["permissions", "allow"]),
                        value: JsonValue::String(rule.clone()),
                    },
                )?;
                patches.insert(rule, patch);
            }
        }
        DocumentKind::OpenCode => {
            let registration_rule = format!("mcp.servers.{server_id}");
            if !observation(&registration_rule)?.exists {
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::JsonMember {
                        parent: SourcePath::new(["mcp", "servers"]),
                        key: server_id.to_owned(),
                        value: opencode_registration()?,
                    },
                )?;
                patches.insert(registration_rule, patch);
            }
            for tool in TOOLS {
                let rule = format!("{server_id}_{tool}|*|allow");
                if observation(&rule)?.exists {
                    continue;
                }
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::JsonArrayElement {
                        array: SourcePath::new(["permissions"]),
                        value: observation(&rule)?.expected.clone(),
                    },
                )?;
                patches.insert(rule, patch);
            }
        }
        DocumentKind::Zed => {
            let registration_rule = format!("context_servers.{server_id}");
            if !observation(&registration_rule)?.exists {
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::JsonMember {
                        parent: SourcePath::new(["context_servers"]),
                        key: server_id.to_owned(),
                        value: json_registration(Provider::Zed)?,
                    },
                )?;
                patches.insert(registration_rule, patch);
            }
            for tool in TOOLS {
                let key = format!("mcp:{server_id}:{tool}");
                let rule = format!("agent.tool_permissions.tools.{key}.default=allow");
                if observation(&rule)?.exists {
                    continue;
                }
                let patch = apply_source_insert(
                    document,
                    &mut after,
                    Insert::JsonMember {
                        parent: SourcePath::new(["agent", "tool_permissions", "tools"]),
                        key,
                        value: serde_json::json!({"default": "allow"}),
                    },
                )?;
                patches.insert(rule, patch);
            }
        }
    }

    let final_value = parse_document_source(document, &after)?;
    let final_observations = inspect_document(spec.provider, document, &final_value, server_id)?;
    if final_observations
        .iter()
        .any(|observation| !observation.exists || observation.blocked)
    {
        bail!("lossless provider patch did not produce the exact requested semantics");
    }
    Ok(PreparedSourceDocument {
        document: document.clone(),
        document_origin: state,
        before,
        after,
        observations,
        patches,
    })
}

fn apply_source_insert(
    document: &DocumentSpec,
    bytes: &mut Vec<u8>,
    operation: Insert,
) -> Result<SourcePatch> {
    let format = document.kind.source_format(&document.path);
    let applied = insert_source(bytes, format, document.kind.relevant_roots(), &operation)?;
    if !applied.changed() {
        bail!("provider source insertion unexpectedly made no change");
    }
    *bytes = applied.bytes;
    Ok(SourcePatch {
        format,
        owned: applied.owned,
        created: applied.created,
    })
}

fn merge_internal_patch(primary: &mut SourcePatch, internal: SourcePatch) {
    let mut created = internal.created;
    created.extend(internal.owned);
    created.append(&mut primary.created);
    primary.created = created;
}

fn prepare_trust_operation(
    manifest: &mut InstallManifest,
    spec: &ProviderSpec,
    documents: &[PreparedSourceDocument],
) -> Result<Option<String>> {
    let mut planned = Vec::new();
    let mut retired = BTreeSet::new();
    {
        let ownership = manifest
            .provider_ownership
            .as_ref()
            .context("provider ownership journal is not initialized")?;
        for document in documents {
            let path = utf8_path(&document.document.path)?.to_owned();
            for observation in document
                .observations
                .iter()
                .filter(|observation| public_observation(document.document.kind, observation))
            {
                let prior = ownership.owned_fragments.iter().find(|fragment| {
                    fragment.provider == spec.definition.id
                        && fragment.scope == spec.scope.journal_scope()
                        && fragment.canonical_path == path
                        && fragment.semantic_selector == observation.rule
                });
                if prior.is_some_and(|fragment| {
                    observation.exists
                        && matches!(
                            fragment.ownership_kind,
                            OwnershipKind::Owned | OwnershipKind::Adopted
                        )
                }) {
                    continue;
                }
                if let Some(fragment) = prior {
                    if fragment.ownership_kind != OwnershipKind::Removed {
                        bail!(
                            "provider ownership history requires explicit recovery before re-trust"
                        );
                    }
                    retired.insert((path.clone(), observation.rule.clone()));
                }
                let patch = (!observation.exists)
                    .then(|| {
                        document
                            .patches
                            .get(&observation.rule)
                            .cloned()
                            .with_context(|| {
                                format!("lossless patch is absent for {:?}", observation.rule)
                            })
                    })
                    .transpose()?;
                planned.push((document, observation, patch));
            }
        }
    }
    if !retired.is_empty() {
        let ownership = manifest
            .provider_ownership
            .as_mut()
            .context("provider ownership journal is not initialized")?;
        ownership.owned_fragments.retain(|fragment| {
            !(fragment.provider == spec.definition.id
                && fragment.scope == spec.scope.journal_scope()
                && fragment.ownership_kind == OwnershipKind::Removed
                && retired.contains(&(
                    fragment.canonical_path.clone(),
                    fragment.semantic_selector.clone(),
                )))
        });
    }
    if planned.is_empty() {
        return Ok(None);
    }
    let ownership = manifest
        .provider_ownership
        .as_ref()
        .context("provider ownership journal is not initialized")?;
    if ownership.owned_fragments.len() + planned.len() > MAX_OWNED_FRAGMENTS {
        bail!("provider journal owned-fragment retention bound exceeded");
    }

    let operation_id = random_identifier("op")?;
    let requested = RequestedOperation {
        provider: spec.definition.id,
        surface: spec.definition.surface,
        scope: spec.scope.journal_scope(),
        dialect: spec.definition.dialect,
        action: OperationAction::Trust,
    };
    let mut targets = Vec::with_capacity(planned.len());
    let mut records = Vec::new();
    for (document, observation, source_patch) in planned {
        let canonical_path = utf8_path(&document.document.path)?.to_owned();
        // Preserve the path's original origin when re-trusting a retained fragment.
        let document_origin = manifest
            .provider_splices
            .iter()
            .find(|record| {
                record.provider == requested.provider
                    && record.scope == requested.scope
                    && record.canonical_path == canonical_path
            })
            .map(|record| record.document_origin)
            .unwrap_or(document.document_origin);
        let fingerprint = fragment_fingerprint(
            document.document.kind,
            &observation.rule,
            &observation.expected,
        )?;
        let adopted = observation.exists;
        targets.push(TargetIntent {
            canonical_path: canonical_path.clone(),
            display_path: canonical_path.clone(),
            format: document
                .document
                .kind
                .source_format(&document.document.path),
            dialect: requested.dialect,
            before_hash: sha256(&document.before),
            expected_after_hash: sha256(&document.after),
            observed_after_hash: None,
            patch: ExactTransform {
                kind: if adopted {
                    crate::provider_journal::TransformKind::Adopt
                } else {
                    crate::provider_journal::TransformKind::Insert
                },
                selector: observation.rule.clone(),
                value_fingerprint: fingerprint.clone(),
            },
            inverse: ExactTransform {
                kind: if adopted {
                    crate::provider_journal::TransformKind::PreserveExternal
                } else {
                    crate::provider_journal::TransformKind::Remove
                },
                selector: observation.rule.clone(),
                value_fingerprint: fingerprint,
            },
            ownership_delta: OwnershipDelta {
                add: (!adopted)
                    .then(|| observation.rule.clone())
                    .into_iter()
                    .collect(),
                remove: Vec::new(),
            },
            phase: OperationPhase::Prepared,
        });
        if let Some(source_patch) = source_patch {
            records.push(SpliceRecord {
                provider: requested.provider,
                surface: requested.surface,
                scope: requested.scope,
                dialect: requested.dialect,
                canonical_path,
                semantic_selector: observation.rule.clone(),
                introducing_operation_id: operation_id.clone(),
                document_origin,
                source_patch,
            });
        }
    }
    let ownership = manifest
        .provider_ownership
        .as_mut()
        .context("provider ownership journal is not initialized")?;
    ownership.generation = ownership
        .generation
        .checked_add(1)
        .context("provider ownership generation overflow")?;
    ownership.push_operation(ProviderOperation {
        id: operation_id.clone(),
        requested,
        phase: OperationPhase::Prepared,
        targets,
    })?;
    manifest.provider_splices.extend(records);
    Ok(Some(operation_id))
}

fn public_observation(kind: DocumentKind, observation: &Observation) -> bool {
    kind != DocumentKind::Codex || !observation.rule.ends_with(".enabled_tools")
}

fn fragment_fingerprint(
    kind: DocumentKind,
    selector: &str,
    expected: &JsonValue,
) -> Result<String> {
    if is_registration_rule(kind, selector) {
        Ok(sha256(&serde_json::to_vec(expected)?))
    } else {
        Ok(sha256(selector.as_bytes()))
    }
}

fn owned_fragment(
    operation: &ProviderOperation,
    index: usize,
    target: &TargetIntent,
    generation: u64,
) -> OwnedFragment {
    OwnedFragment {
        id: format!("fragment{}{index}", operation.id),
        provider: operation.requested.provider,
        surface: operation.requested.surface,
        scope: operation.requested.scope,
        dialect: operation.requested.dialect,
        canonical_path: target.canonical_path.clone(),
        display_path: target.display_path.clone(),
        format: target.format,
        semantic_selector: target.patch.selector.clone(),
        value_fingerprint: target.patch.value_fingerprint.clone(),
        created_containers: Vec::new(),
        ownership_kind: if target.patch.kind == TransformKind::Adopt {
            OwnershipKind::Adopted
        } else {
            OwnershipKind::Owned
        },
        introducing_operation_id: operation.id.clone(),
        generation,
    }
}

fn finalize_operation(
    manifest: &mut InstallManifest,
    operation_id: &str,
    phase: OperationPhase,
) -> Result<()> {
    let operation = {
        let ownership = manifest
            .provider_ownership
            .as_mut()
            .context("provider ownership journal is not initialized")?;
        let operation = ownership
            .operations
            .iter_mut()
            .find(|operation| operation.id == operation_id)
            .context("provider operation disappeared before finalization")?;
        if operation.phase != OperationPhase::Prepared {
            bail!("provider operation is not prepared");
        }
        operation.phase = phase;
        for target in &mut operation.targets {
            target.phase = phase;
            target.observed_after_hash = Some(target.expected_after_hash.clone());
        }
        operation.clone()
    };
    let ownership = manifest
        .provider_ownership
        .as_mut()
        .expect("provider ownership was checked");
    let generation = ownership.generation;
    let removed_keys = match operation.requested.action {
        OperationAction::Trust => {
            for (index, target) in operation.targets.iter().enumerate() {
                if ownership.owned_fragments.iter().any(|fragment| {
                    fragment.provider == operation.requested.provider
                        && fragment.scope == operation.requested.scope
                        && fragment.canonical_path == target.canonical_path
                        && fragment.semantic_selector == target.patch.selector
                }) {
                    bail!("provider operation would duplicate semantic ownership");
                }
                ownership.push_fragment(owned_fragment(&operation, index, target, generation))?;
            }
            Vec::new()
        }
        OperationAction::Strip | OperationAction::Uninstall => {
            let mut removed = Vec::new();
            for target in &operation.targets {
                let fragment = ownership
                    .owned_fragments
                    .iter_mut()
                    .find(|fragment| {
                        fragment.provider == operation.requested.provider
                            && fragment.scope == operation.requested.scope
                            && fragment.canonical_path == target.canonical_path
                            && fragment.semantic_selector == target.patch.selector
                    })
                    .context("provider removal target has no owned fragment")?;
                fragment.ownership_kind = OwnershipKind::Removed;
                removed.push((target.canonical_path.clone(), target.patch.selector.clone()));
            }
            removed
        }
        OperationAction::Recover => {
            let mut removed = Vec::new();
            for (index, target) in operation.targets.iter().enumerate() {
                match target.patch.kind {
                    crate::provider_journal::TransformKind::Insert
                    | crate::provider_journal::TransformKind::Adopt => {
                        ownership
                            .push_fragment(owned_fragment(&operation, index, target, generation))?;
                    }
                    crate::provider_journal::TransformKind::Remove => {
                        let fragment = ownership
                            .owned_fragments
                            .iter_mut()
                            .find(|fragment| {
                                fragment.provider == operation.requested.provider
                                    && fragment.scope == operation.requested.scope
                                    && fragment.canonical_path == target.canonical_path
                                    && fragment.semantic_selector == target.patch.selector
                            })
                            .context("recovered removal target has no owned fragment")?;
                        fragment.ownership_kind = OwnershipKind::Removed;
                        removed
                            .push((target.canonical_path.clone(), target.patch.selector.clone()));
                    }
                    crate::provider_journal::TransformKind::PreserveExternal => {
                        bail!("provider recovery target has an invalid forward transform")
                    }
                }
            }
            removed
        }
    };
    ownership.validate()?;
    if !removed_keys.is_empty() {
        manifest.provider_splices.retain(|record| {
            record.provider != operation.requested.provider
                || record.scope != operation.requested.scope
                || removed_keys.iter().all(|(path, selector)| {
                    record.canonical_path != *path || record.semantic_selector != *selector
                })
        });
    }
    Ok(())
}

fn apply_documents(
    spec: &ProviderSpec,
    server_id: &str,
    manifest: &mut InstallManifest,
    manifest_path: &Path,
    lock: &ManifestLock,
) -> Result<()> {
    reject_blocked_observations(&inspect_effective(spec, server_id)?)?;
    reject_opencode_permission_shadowing(spec)?;
    let inspection_before = spec
        .inspection_documents
        .iter()
        .map(|document| {
            let (state, bytes) = read_provider_document_snapshot(&document.path)?;
            Ok((document.path.clone(), state, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    let prepared = spec
        .documents
        .iter()
        .map(|document| prepare_source_document(spec, document, server_id))
        .collect::<Result<Vec<_>>>()?;

    // Validate the complete split-provider plan before the first write.
    for (path, state, before) in &inspection_before {
        reject_provider_document_changed(path, *state, before)?;
    }
    for document in &prepared {
        reject_provider_document_changed(
            &document.document.path,
            document.document_origin,
            &document.before,
        )?;
    }
    let operation_id = prepare_trust_operation(manifest, spec, &prepared)?;
    let Some(operation_id) = operation_id else {
        return Ok(());
    };
    manifest.save_locked(manifest_path, lock)?;
    for document in &prepared {
        if document.after == document.before {
            continue;
        }
        write_provider_document(
            &document.document.path,
            document.document_origin,
            &document.before,
            Some(&document.after),
        )?;
        verify_provider_document(&document.document, Some(&document.after))?;
        #[cfg(test)]
        if FAIL_AFTER_FIRST_DOCUMENT_WRITE.with(|fail| fail.replace(false)) {
            bail!("injected provider interruption after first document write");
        }
    }
    finalize_operation(manifest, &operation_id, OperationPhase::Applied)?;
    manifest.save_locked(manifest_path, lock)?;
    Ok(())
}

fn json_registration(provider: Provider) -> Result<JsonValue> {
    let executable = std::env::current_exe().context("cannot resolve the icm executable")?;
    let executable = utf8_path(&executable)?;
    Ok(
        if matches!(provider, Provider::ClaudeCode | Provider::Cursor) {
            serde_json::json!({
                "type": "stdio",
                "command": executable,
                "args": ["serve"],
                "env": {}
            })
        } else {
            serde_json::json!({
                "command": executable,
                "args": ["serve"],
                "env": {}
            })
        },
    )
}

fn opencode_registration() -> Result<JsonValue> {
    let executable = std::env::current_exe().context("cannot resolve the icm executable")?;
    let executable = utf8_path(&executable)?;
    Ok(serde_json::json!({
        "type": "local",
        "command": [executable, "serve"]
    }))
}

fn write_provider_document(
    path: &Path,
    before_state: DocumentOrigin,
    before: &[u8],
    after: Option<&[u8]>,
) -> Result<()> {
    reject_provider_document_changed(path, before_state, before)?;
    match after {
        Some(after) => secure_atomic_write_if_unchanged(
            path,
            (before_state != DocumentOrigin::Missing).then_some(before),
            after,
        )
        .with_context(|| format!("cannot write provider config {}", path.display())),
        None => {
            std::fs::remove_file(path)
                .with_context(|| format!("cannot remove provider config {}", path.display()))?;
            #[cfg(unix)]
            File::open(path.parent().unwrap_or_else(|| Path::new(".")))
                .and_then(|directory| directory.sync_all())
                .with_context(|| {
                    format!(
                        "cannot sync provider config directory for {}",
                        path.display()
                    )
                })?;
            Ok(())
        }
    }
}

fn reject_provider_document_changed(
    path: &Path,
    before_state: DocumentOrigin,
    before: &[u8],
) -> Result<()> {
    let (current_state, current) = read_provider_document_snapshot(path)?;
    if current_state != before_state || current != before {
        bail!(
            "provider configuration changed while the mutation was being prepared: {}",
            path.display()
        );
    }
    Ok(())
}

fn verify_provider_document(document: &DocumentSpec, expected: Option<&[u8]>) -> Result<()> {
    match expected {
        Some(expected) => {
            let (state, bytes, _) = read_document_snapshot(document)?;
            if state == DocumentOrigin::Missing || sha256(&bytes) != sha256(expected) {
                bail!(
                    "provider configuration failed post-write verification: {}",
                    document.path.display()
                );
            }
        }
        None if secure_read(&document.path)?.is_none() => {}
        None => bail!(
            "provider configuration failed post-remove verification: {}",
            document.path.display()
        ),
    }
    Ok(())
}

fn read_provider_document(path: &Path) -> Result<Vec<u8>> {
    Ok(read_provider_document_snapshot(path)?.1)
}

fn read_provider_document_snapshot(path: &Path) -> Result<(DocumentOrigin, Vec<u8>)> {
    Ok(match secure_read(path)? {
        None => (DocumentOrigin::Missing, Vec::new()),
        Some(bytes) if bytes.is_empty() => (DocumentOrigin::Empty, bytes),
        Some(bytes) => (DocumentOrigin::Existing, bytes),
    })
}

fn codex_registration() -> Result<toml::Value> {
    let executable = std::env::current_exe().context("cannot resolve the icm executable")?;
    let executable = utf8_path(&executable)?;
    let mut registration = toml::map::Map::new();
    registration.insert(
        "command".to_owned(),
        toml::Value::String(executable.to_owned()),
    );
    registration.insert(
        "args".to_owned(),
        toml::Value::Array(vec![toml::Value::String("serve".to_owned())]),
    );
    registration.insert(
        "enabled_tools".to_owned(),
        toml::Value::Array(
            TOOLS
                .iter()
                .map(|tool| toml::Value::String((*tool).to_owned()))
                .collect(),
        ),
    );
    let tools = TOOLS
        .iter()
        .map(|tool| {
            let mut rule = toml::map::Map::new();
            rule.insert(
                "approval_mode".to_owned(),
                toml::Value::String("approve".to_owned()),
            );
            ((*tool).to_owned(), toml::Value::Table(rule))
        })
        .collect();
    registration.insert("tools".to_owned(), toml::Value::Table(tools));
    Ok(toml::Value::Table(registration))
}

fn strip_documents(
    provider: Provider,
    scope: Scope,
    documents: &[DocumentSpec],
    mode: RemovalMode,
    manifest: &mut InstallManifest,
    manifest_path: &Path,
    lock: &ManifestLock,
) -> Result<StripSummary> {
    let mut prepared = Vec::new();
    for document in documents {
        if let Some(document) = prepare_removal_document(manifest, provider, scope, document, mode)?
        {
            prepared.push(document);
        }
    }
    if prepared.is_empty() {
        return Ok(StripSummary::default());
    }
    for document in &prepared {
        reject_provider_document_changed(
            &document.document.path,
            document.before_state,
            &document.before,
        )?;
    }
    let operation_id = prepare_removal_operation(manifest, provider, scope, mode, &prepared)?;
    manifest.save_locked(manifest_path, lock)?;
    for document in &prepared {
        if document.after.as_deref() == Some(document.before.as_slice()) {
            continue;
        }
        write_provider_document(
            &document.document.path,
            document.before_state,
            &document.before,
            document.after.as_deref(),
        )?;
        verify_provider_document(&document.document, document.after.as_deref())?;
    }
    finalize_operation(manifest, &operation_id, OperationPhase::Removed)?;
    manifest.save_locked(manifest_path, lock)?;
    Ok(StripSummary {
        outcomes: prepared
            .into_iter()
            .map(|document| StripPathOutcome {
                path: document.document.path,
                entries_removed: document.fragments.len(),
                deleted: document.after.is_none(),
            })
            .collect(),
    })
}

fn prepare_removal_document(
    manifest: &InstallManifest,
    provider: Provider,
    scope: Scope,
    document: &DocumentSpec,
    mode: RemovalMode,
) -> Result<Option<PreparedRemovalDocument>> {
    let path = utf8_path(&document.path)?.to_owned();
    let fragments = manifest
        .provider_ownership
        .as_ref()
        .into_iter()
        .flat_map(|ownership| ownership.owned_fragments.iter())
        .filter(|fragment| {
            fragment.provider == provider.definition().id
                && fragment.scope == scope.journal_scope()
                && fragment.canonical_path == path
                && fragment.ownership_kind == OwnershipKind::Owned
                && (mode == RemovalMode::Uninstall
                    || !is_registration_rule(document.kind, &fragment.semantic_selector))
        })
        .cloned()
        .collect::<Vec<_>>();
    if fragments.is_empty() {
        return Ok(None);
    }
    let mut records = fragments
        .iter()
        .map(|fragment| {
            manifest
                .provider_splices
                .iter()
                .find(|record| {
                    record.provider == fragment.provider
                        && record.scope == fragment.scope
                        && record.canonical_path == fragment.canonical_path
                        && record.semantic_selector == fragment.semantic_selector
                        && record.introducing_operation_id == fragment.introducing_operation_id
                })
                .cloned()
                .with_context(|| {
                    format!(
                        "owned provider fragment {:?} has no exact source inverse",
                        fragment.semantic_selector
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    records.sort_by_key(|record| {
        manifest
            .provider_splices
            .iter()
            .position(|candidate| candidate == record)
            .unwrap_or(usize::MAX)
    });
    let (before_state, before) = read_provider_document_snapshot(&document.path)?;
    parse_document_source(document, &before)?;
    let after = remove_source_records(document, &before, &records)?;
    let document_origin = records[0].document_origin;
    if records
        .iter()
        .any(|record| record.document_origin != document_origin)
    {
        bail!("provider source inverses disagree about document origin");
    }
    let after = if document_origin == DocumentOrigin::Missing && after.is_empty() {
        None
    } else {
        Some(after)
    };
    Ok(Some(PreparedRemovalDocument {
        document: document.clone(),
        before_state,
        before,
        after,
        fragments,
    }))
}

fn remove_source_records(
    document: &DocumentSpec,
    before: &[u8],
    records: &[SpliceRecord],
) -> Result<Vec<u8>> {
    let mut after = before.to_vec();
    for record in records.iter().rev() {
        if let Some(owned) = &record.source_patch.owned {
            after = remove_source_owned(
                &after,
                record.source_patch.format,
                document.kind.relevant_roots(),
                owned,
            )?;
        }
        for created in record.source_patch.created.iter().rev() {
            if let Some(next) = try_remove_source_owned(
                &after,
                record.source_patch.format,
                document.kind.relevant_roots(),
                created,
            )? {
                after = next;
            }
        }
    }
    parse_document_source(document, &after)?;
    Ok(after)
}

fn prepare_removal_operation(
    manifest: &mut InstallManifest,
    provider: Provider,
    scope: Scope,
    mode: RemovalMode,
    documents: &[PreparedRemovalDocument],
) -> Result<String> {
    let operation_id = random_identifier("op")?;
    let requested = RequestedOperation {
        provider: provider.definition().id,
        surface: provider.definition().surface,
        scope: scope.journal_scope(),
        dialect: provider.definition().dialect,
        action: if mode == RemovalMode::Uninstall {
            OperationAction::Uninstall
        } else {
            OperationAction::Strip
        },
    };
    let mut targets = Vec::new();
    for document in documents {
        let after = document.after.as_deref().unwrap_or_default();
        for fragment in &document.fragments {
            targets.push(TargetIntent {
                canonical_path: fragment.canonical_path.clone(),
                display_path: fragment.display_path.clone(),
                format: fragment.format,
                dialect: fragment.dialect,
                before_hash: sha256(&document.before),
                expected_after_hash: sha256(after),
                observed_after_hash: None,
                patch: ExactTransform {
                    kind: crate::provider_journal::TransformKind::Remove,
                    selector: fragment.semantic_selector.clone(),
                    value_fingerprint: fragment.value_fingerprint.clone(),
                },
                inverse: ExactTransform {
                    kind: crate::provider_journal::TransformKind::Insert,
                    selector: fragment.semantic_selector.clone(),
                    value_fingerprint: fragment.value_fingerprint.clone(),
                },
                ownership_delta: OwnershipDelta {
                    add: Vec::new(),
                    remove: vec![fragment.semantic_selector.clone()],
                },
                phase: OperationPhase::Prepared,
            });
        }
    }
    let ownership = manifest
        .provider_ownership
        .as_mut()
        .context("provider ownership journal is not initialized")?;
    ownership.generation = ownership
        .generation
        .checked_add(1)
        .context("provider ownership generation overflow")?;
    ownership.push_operation(ProviderOperation {
        id: operation_id.clone(),
        requested,
        phase: OperationPhase::Prepared,
        targets,
    })?;
    Ok(operation_id)
}

fn owned_document_kind(provider: Provider, rule: &str) -> Result<DocumentKind> {
    provider
        .definition()
        .project
        .iter()
        .chain(provider.definition().user.iter())
        .map(|document| document.kind)
        .find(|kind| kind.owns_rule(rule))
        .with_context(|| format!("unknown owned provider rule {rule:?}"))
}

fn recover_provenance(
    manifest: &mut InstallManifest,
    target: &TargetArgs,
    server_id: &str,
    manifest_path: &Path,
    lock: &ManifestLock,
) -> Result<()> {
    let operations = manifest
        .provider_ownership
        .as_ref()
        .into_iter()
        .flat_map(|ownership| ownership.operations.iter())
        .filter(|operation| {
            operation.phase == OperationPhase::Prepared
                && operation.requested.provider == target.provider.definition().id
                && operation.requested.scope == target.scope.journal_scope()
        })
        .cloned()
        .collect::<Vec<_>>();
    for operation in operations {
        recover_operation(manifest, target, server_id, manifest_path, lock, &operation)?;
    }
    Ok(())
}

fn recover_operation(
    manifest: &mut InstallManifest,
    target: &TargetArgs,
    server_id: &str,
    manifest_path: &Path,
    lock: &ManifestLock,
    operation: &ProviderOperation,
) -> Result<()> {
    let mut documents = BTreeMap::<String, DocumentSpec>::new();
    for intent in &operation.targets {
        let kind = document_kind_for_target(operation.requested.provider, intent);
        documents
            .entry(intent.canonical_path.clone())
            .or_insert_with(|| DocumentSpec {
                path: PathBuf::from(&intent.canonical_path),
                kind,
            });
    }
    let mut states = RecoveryStates::new();
    for (path, document) in &documents {
        let (state, bytes) = read_provider_document_snapshot(&document.path)?;
        let current = sha256(&bytes);
        states.insert(path.clone(), (state, bytes, current));
    }
    for (path, document) in &documents {
        let (_, bytes, _) = states
            .get(path)
            .expect("recovery document state was captured");
        if let Err(error) = parse_document_source(document, bytes) {
            mark_operation_conflict(manifest, &operation.id, &states)?;
            manifest.save_locked(manifest_path, lock)?;
            return Err(error.context("prepared provider target is no longer parseable"));
        }
    }

    let plan =
        match prepare_recovery_plan(manifest, target, server_id, operation, &documents, &states) {
            Ok(plan) => plan,
            Err(error) => {
                mark_operation_conflict(manifest, &operation.id, &states)?;
                manifest.save_locked(manifest_path, lock)?;
                return Err(
                    error.context("prepared provider operation overlaps current configuration")
                );
            }
        };
    rebase_prepared_operation(manifest, &operation.id, &plan)?;
    // A disjoint edit changes both the target hashes and the exact source
    // inverse. Persist that rebased intent before touching a target.
    manifest.save_locked(manifest_path, lock)?;
    for document in &plan.documents {
        if document.after.as_deref() == Some(document.before.as_slice()) {
            continue;
        }
        write_provider_document(
            &document.document.path,
            document.before_state,
            &document.before,
            document.after.as_deref(),
        )?;
        verify_provider_document(&document.document, document.after.as_deref())?;
    }
    promote_recovery_operation(manifest, &operation.id)?;
    finalize_operation(manifest, &operation.id, plan.terminal_phase)?;
    manifest.save_locked(manifest_path, lock)
}

fn prepare_recovery_plan(
    manifest: &InstallManifest,
    target: &TargetArgs,
    server_id: &str,
    operation: &ProviderOperation,
    documents: &BTreeMap<String, DocumentSpec>,
    states: &RecoveryStates,
) -> Result<RecoveryPlan> {
    if operation.targets.iter().all(|target| {
        matches!(
            target.patch.kind,
            TransformKind::Insert | TransformKind::Adopt
        )
    }) {
        prepare_insertion_recovery(manifest, target, server_id, operation, documents, states)
    } else if operation
        .targets
        .iter()
        .all(|target| target.patch.kind == TransformKind::Remove)
    {
        prepare_removal_recovery(manifest, target, server_id, operation, documents, states)
    } else {
        bail!("prepared provider operation mixes incompatible transform kinds")
    }
}

fn prepare_insertion_recovery(
    manifest: &InstallManifest,
    target: &TargetArgs,
    server_id: &str,
    operation: &ProviderOperation,
    documents: &BTreeMap<String, DocumentSpec>,
    states: &RecoveryStates,
) -> Result<RecoveryPlan> {
    let recovery_documents = documents.values().cloned().collect::<Vec<_>>();
    let spec = ProviderSpec {
        definition: target.provider.definition(),
        provider: target.provider,
        scope: target.scope,
        documents: recovery_documents.clone(),
        inspection_documents: recovery_documents,
    };
    let mut plan = RecoveryPlan {
        documents: Vec::new(),
        replacement_paths: BTreeSet::new(),
        replacement_splices: Vec::new(),
        terminal_phase: OperationPhase::Applied,
    };
    for (path, document) in documents {
        let (before_state, before, _) = states
            .get(path)
            .context("provider recovery target state is absent")?;
        let prepared = prepare_source_document(&spec, document, server_id)?;
        let intents = operation
            .targets
            .iter()
            .filter(|intent| intent.canonical_path == *path)
            .collect::<Vec<_>>();
        let selectors = intents
            .iter()
            .map(|intent| intent.patch.selector.as_str())
            .collect::<BTreeSet<_>>();
        if prepared
            .patches
            .keys()
            .any(|selector| !selectors.contains(selector.as_str()))
        {
            bail!("recovery would repair a provider fragment outside its durable intent");
        }

        let mut inserted = Vec::new();
        for intent in &intents {
            let observation = prepared
                .observations
                .iter()
                .find(|observation| observation.rule == intent.patch.selector)
                .context("provider recovery intent has no semantic observation")?;
            if observation.blocked
                || fragment_fingerprint(document.kind, &observation.rule, &observation.expected)?
                    != intent.patch.value_fingerprint
            {
                bail!("provider recovery intent no longer has its exact semantic identity");
            }
            match intent.patch.kind {
                TransformKind::Insert => inserted.push(observation.exists),
                TransformKind::Adopt if observation.exists => {}
                TransformKind::Adopt => {
                    bail!("an adopted provider fragment changed during recovery")
                }
                _ => bail!("insertion recovery contains a non-insertion transform"),
            }
        }
        let all_inserted = inserted.iter().all(|exists| *exists);
        let none_inserted = inserted.iter().all(|exists| !*exists);
        if !all_inserted && !none_inserted {
            bail!("provider target contains only part of its prepared mutation");
        }

        let after = if all_inserted {
            validate_recovered_source_splices(manifest, operation, document, before)?;
            before.clone()
        } else {
            plan.replacement_paths.insert(path.clone());
            for intent in intents
                .iter()
                .filter(|intent| intent.patch.kind == TransformKind::Insert)
            {
                let source_patch = prepared
                    .patches
                    .get(&intent.patch.selector)
                    .cloned()
                    .context("rebased provider insertion lacks an exact source patch")?;
                plan.replacement_splices.push(SpliceRecord {
                    provider: operation.requested.provider,
                    surface: operation.requested.surface,
                    scope: operation.requested.scope,
                    dialect: operation.requested.dialect,
                    canonical_path: path.clone(),
                    semantic_selector: intent.patch.selector.clone(),
                    introducing_operation_id: operation.id.clone(),
                    document_origin: prepared.document_origin,
                    source_patch,
                });
            }
            prepared.after
        };
        plan.documents.push(RebasedRecoveryDocument {
            document: document.clone(),
            before_state: *before_state,
            before: before.clone(),
            after: Some(after),
        });
    }
    Ok(plan)
}

fn prepare_removal_recovery(
    manifest: &InstallManifest,
    target: &TargetArgs,
    server_id: &str,
    operation: &ProviderOperation,
    documents: &BTreeMap<String, DocumentSpec>,
    states: &RecoveryStates,
) -> Result<RecoveryPlan> {
    let mode = if operation.targets.iter().any(|target| {
        is_registration_rule(
            document_kind_for_target(operation.requested.provider, target),
            &target.patch.selector,
        )
    }) {
        RemovalMode::Uninstall
    } else {
        RemovalMode::TrustOnly
    };
    let mut plan = RecoveryPlan {
        documents: Vec::new(),
        replacement_paths: BTreeSet::new(),
        replacement_splices: Vec::new(),
        terminal_phase: OperationPhase::Removed,
    };
    for (path, document) in documents {
        let (before_state, before, _) = states
            .get(path)
            .context("provider recovery target state is absent")?;
        let value = parse_document_source(document, before)?;
        let observations = inspect_document(target.provider, document, &value, server_id)?;
        let intents = operation
            .targets
            .iter()
            .filter(|intent| intent.canonical_path == *path)
            .collect::<Vec<_>>();
        let mut present = Vec::new();
        for intent in &intents {
            let observation = observations
                .iter()
                .find(|observation| observation.rule == intent.patch.selector)
                .context("provider recovery intent has no semantic observation")?;
            if observation.blocked
                || fragment_fingerprint(document.kind, &observation.rule, &observation.expected)?
                    != intent.patch.value_fingerprint
            {
                bail!("provider removal target changed at its exact semantic location");
            }
            present.push(observation.exists);
        }
        let all_present = present.iter().all(|exists| *exists);
        let none_present = present.iter().all(|exists| !*exists);
        if !all_present && !none_present {
            bail!("provider target contains only part of its prepared removal");
        }
        let after = if all_present {
            let prepared =
                prepare_removal_document(manifest, target.provider, target.scope, document, mode)?
                    .context("prepared provider removal has no owned fragments")?;
            let planned = intents
                .iter()
                .map(|intent| intent.patch.selector.as_str())
                .collect::<BTreeSet<_>>();
            let recovered = prepared
                .fragments
                .iter()
                .map(|fragment| fragment.semantic_selector.as_str())
                .collect::<BTreeSet<_>>();
            if recovered != planned {
                bail!("rebased removal differs from its durable fragment set");
            }
            prepared.after
        } else {
            Some(before.clone())
        };
        plan.documents.push(RebasedRecoveryDocument {
            document: document.clone(),
            before_state: *before_state,
            before: before.clone(),
            after,
        });
    }
    Ok(plan)
}

fn validate_recovered_source_splices(
    manifest: &InstallManifest,
    operation: &ProviderOperation,
    document: &DocumentSpec,
    bytes: &[u8],
) -> Result<()> {
    let records = manifest
        .provider_splices
        .iter()
        .filter(|record| {
            record.introducing_operation_id == operation.id
                && Path::new(&record.canonical_path) == document.path
        })
        .cloned()
        .collect::<Vec<_>>();
    let expected = operation
        .targets
        .iter()
        .filter(|target| {
            Path::new(&target.canonical_path) == document.path
                && target.patch.kind == TransformKind::Insert
        })
        .map(|target| target.patch.selector.as_str())
        .collect::<BTreeSet<_>>();
    let actual = records
        .iter()
        .map(|record| record.semantic_selector.as_str())
        .collect::<BTreeSet<_>>();
    if records.len() != expected.len() || actual != expected {
        bail!("prepared provider insertion lacks exact source provenance");
    }
    remove_source_records(document, bytes, &records)?;
    Ok(())
}

fn rebase_prepared_operation(
    manifest: &mut InstallManifest,
    operation_id: &str,
    plan: &RecoveryPlan,
) -> Result<()> {
    let ownership = manifest
        .provider_ownership
        .as_mut()
        .context("provider ownership journal is not initialized")?;
    let operation = ownership
        .operations
        .iter_mut()
        .find(|operation| operation.id == operation_id)
        .context("provider recovery operation disappeared")?;
    if operation.phase != OperationPhase::Prepared {
        bail!("only a prepared provider operation can be rebased");
    }
    for target in &mut operation.targets {
        let document = plan
            .documents
            .iter()
            .find(|document| Path::new(&target.canonical_path) == document.document.path)
            .context("provider recovery plan omitted a target document")?;
        target.before_hash = sha256(&document.before);
        target.expected_after_hash = sha256(document.after.as_deref().unwrap_or_default());
        target.observed_after_hash = None;
    }
    manifest.provider_splices.retain(|record| {
        record.introducing_operation_id != operation_id
            || !plan.replacement_paths.contains(&record.canonical_path)
    });
    manifest
        .provider_splices
        .extend(plan.replacement_splices.iter().cloned());
    Ok(())
}

fn mark_operation_conflict(
    manifest: &mut InstallManifest,
    operation_id: &str,
    states: &BTreeMap<String, (DocumentOrigin, Vec<u8>, String)>,
) -> Result<()> {
    let discard_prepared_splices = manifest
        .provider_ownership
        .as_ref()
        .and_then(|ownership| {
            ownership
                .operations
                .iter()
                .find(|operation| operation.id == operation_id)
        })
        .is_some_and(|operation| {
            operation
                .targets
                .iter()
                .any(|target| target.patch.kind == crate::provider_journal::TransformKind::Insert)
        });
    promote_recovery_operation(manifest, operation_id)?;
    let ownership = manifest
        .provider_ownership
        .as_mut()
        .context("provider ownership journal is not initialized")?;
    let operation = ownership
        .operations
        .iter_mut()
        .find(|operation| operation.id == operation_id)
        .context("provider recovery operation disappeared")?;
    operation.phase = OperationPhase::Conflict;
    for target in &mut operation.targets {
        let current = states
            .get(&target.canonical_path)
            .context("provider recovery target state is absent")?
            .2
            .clone();
        target.phase = OperationPhase::Conflict;
        target.before_hash = current.clone();
        target.observed_after_hash = Some(current);
    }
    if discard_prepared_splices {
        manifest
            .provider_splices
            .retain(|record| record.introducing_operation_id != operation_id);
    }
    Ok(())
}

fn promote_recovery_operation(manifest: &mut InstallManifest, operation_id: &str) -> Result<()> {
    let ownership = manifest
        .provider_ownership
        .as_mut()
        .context("provider ownership journal is not initialized")?;
    let operation = ownership
        .operations
        .iter_mut()
        .find(|operation| operation.id == operation_id)
        .context("provider recovery operation disappeared")?;
    if operation.phase != OperationPhase::Prepared {
        bail!("only a prepared provider operation can be recovered");
    }
    ownership.generation = ownership
        .generation
        .checked_add(1)
        .context("provider ownership generation overflow")?;
    operation.requested.action = OperationAction::Recover;
    Ok(())
}

fn document_kind_for_target(provider: ProviderId, target: &TargetIntent) -> DocumentKind {
    match provider {
        ProviderId::Codex => DocumentKind::Codex,
        ProviderId::ClaudeCode | ProviderId::Cursor => {
            if target.patch.selector.starts_with("mcpServers.") {
                DocumentKind::JsonRegistration
            } else {
                DocumentKind::JsonPermissions
            }
        }
        ProviderId::OpenCode => DocumentKind::OpenCode,
        ProviderId::Zed => DocumentKind::Zed,
    }
}

fn is_registration_rule(kind: DocumentKind, rule: &str) -> bool {
    match kind {
        DocumentKind::Codex => {
            rule.starts_with("mcp_servers.")
                && !rule.contains(".enabled_tools")
                && !rule.contains(".tools.")
        }
        DocumentKind::JsonRegistration => true,
        DocumentKind::JsonPermissions => false,
        DocumentKind::OpenCode => rule.starts_with("mcp.servers."),
        DocumentKind::Zed => rule.starts_with("context_servers."),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn tool_rules(provider: Provider, server_id: &str) -> Vec<String> {
    TOOLS
        .iter()
        .map(|tool| match provider.definition().permission {
            PermissionShape::Codex => {
                format!("mcp_servers.{server_id}.tools.{tool}.approval_mode=approve")
            }
            PermissionShape::Claude => format!("mcp__{server_id}__{tool}"),
            PermissionShape::Cursor => format!("Mcp({server_id}:{tool})"),
            PermissionShape::OpenCode => format!("{server_id}_{tool}|*|allow"),
            PermissionShape::Zed => {
                format!("agent.tool_permissions.tools.mcp:{server_id}:{tool}.default=allow")
            }
        })
        .collect()
}

fn optional_table<'a>(
    value: Option<&'a toml::Value>,
    field: &str,
) -> Result<&'a toml::map::Map<String, toml::Value>> {
    static EMPTY: std::sync::OnceLock<toml::map::Map<String, toml::Value>> =
        std::sync::OnceLock::new();
    match value {
        Some(value) => value
            .as_table()
            .with_context(|| format!("{field} is not a table")),
        None => Ok(EMPTY.get_or_init(toml::map::Map::new)),
    }
}

fn string_set(value: Option<&toml::Value>) -> Result<BTreeSet<String>> {
    match value {
        None => Ok(BTreeSet::new()),
        Some(value) => value
            .as_array()
            .context("Codex tool list is not an array")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("Codex tool list contains a non-string value")
            })
            .collect(),
    }
}

fn exact_tool_set(value: Option<&toml::Value>) -> Result<(bool, bool)> {
    if value.is_none() {
        return Ok((false, false));
    }
    let actual = string_set(value)?;
    let expected: BTreeSet<_> = TOOLS.iter().copied().map(str::to_owned).collect();
    Ok((actual == expected, actual != expected))
}

fn reject_normalization_collisions<'a>(ids: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut normalized = BTreeMap::new();
    for id in ids {
        let key = id.replace('-', "_");
        if normalized
            .insert(key.clone(), id)
            .is_some_and(|prior| prior != id)
        {
            bail!("provider server IDs collide after normalization: {key}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_collisions_fail_closed() {
        assert!(reject_normalization_collisions(["icm-a", "icm_a"].into_iter()).is_err());
        assert!(reject_normalization_collisions(["icma", "icmb"].into_iter()).is_ok());
    }

    #[test]
    fn opposite_scope_permission_blockers_are_rejected() {
        let observations = vec![
            Observation {
                path: PathBuf::from("project.json"),
                rule: "registration".into(),
                exists: false,
                blocked: false,
                expected: JsonValue::Null,
            },
            Observation {
                path: PathBuf::from("project.json"),
                rule: "tool".into(),
                exists: false,
                blocked: true,
                expected: JsonValue::Null,
            },
        ];
        assert!(reject_opposite_scope_binding(&observations).is_err());
    }

    #[test]
    fn opposite_scope_registration_is_always_rejected() {
        assert_eq!(opposite_scope(Scope::ProjectLocal), Scope::User);
        assert_eq!(opposite_scope(Scope::User), Scope::ProjectLocal);
        let observations = vec![Observation {
            path: PathBuf::from("opposite.json"),
            rule: "registration".into(),
            exists: true,
            blocked: false,
            expected: JsonValue::Null,
        }];
        assert!(reject_opposite_scope_binding(&observations).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_provider_paths_fail_closed() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(vec![0xff]));
        assert!(utf8_path(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_provider_configs_are_rejected() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target.json");
        let link = tmp.path().join("settings.json");
        std::fs::write(&target, "{}").unwrap();
        symlink(&target, &link).unwrap();

        assert!(read_provider_document(&link)
            .unwrap_err()
            .to_string()
            .contains("symlink"));
        assert_eq!(std::fs::read_to_string(target).unwrap(), "{}");
    }

    #[test]
    fn stale_provider_config_writes_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        std::fs::write(&path, b"before").unwrap();
        let before = read_provider_document(&path).unwrap();
        std::fs::write(&path, b"concurrent edit").unwrap();

        assert!(write_provider_document(
            &path,
            DocumentOrigin::Existing,
            &before,
            Some(b"replacement")
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"concurrent edit");
    }

    #[test]
    fn malformed_provider_documents_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let json = document(tmp.path().join("bad.json"), DocumentKind::Zed);
        let toml = document(tmp.path().join("bad.toml"), DocumentKind::Codex);
        std::fs::write(&json.path, "{/* broken */").unwrap();
        std::fs::write(&toml.path, "[broken").unwrap();
        assert!(read_document(&json).is_err());
        assert!(read_document(&toml).is_err());
    }

    #[test]
    fn zed_settings_json_accepts_jsonc() {
        let tmp = tempfile::tempdir().unwrap();
        let settings = document(tmp.path().join("settings.jsonc"), DocumentKind::Zed);
        std::fs::write(&settings.path, "{ // comment\n \"sentinel\": true,\n}\n").unwrap();
        let (_, DocumentValue::Json(value)) = read_document(&settings).unwrap() else {
            panic!("Zed settings must be JSON");
        };
        assert_eq!(value["sentinel"], true);
    }

    #[test]
    fn opencode_uses_v2_wildcards_and_last_matching_permission() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opencode.json");
        std::fs::write(
            &path,
            r#"{"mcp":{"servers":{"icm123":{"type":"local","command":["external","serve"]}}},"permissions":[{"action":"icm?23_*_memory_*","resource":"*","effect":"allow"},{"action":"icm*memory?recall","resource":"?","effect":"deny"}],"agents":{"reviewer":{"permissions":[{"action":"icm123_icm_memory_store","resource":"*","effect":"ask"}]}}}"#,
        )
        .unwrap();
        let document = document(path, DocumentKind::OpenCode);
        let spec = ProviderSpec {
            definition: Provider::OpenCode.definition(),
            provider: Provider::OpenCode,
            scope: Scope::ProjectLocal,
            documents: vec![document.clone()],
            inspection_documents: vec![document],
        };

        let observations = inspect(&spec, "icm123").unwrap();
        assert!(observations[0].blocked);
        assert!(observations[1].blocked);
        assert!(observations[2].blocked);
        #[cfg(windows)]
        assert!(glob_matches("ICM?23_*", "icm123_store"));
    }

    #[test]
    fn opencode_reports_only_effective_managed_blockers() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opencode.json");
        let mut registration = opencode_registration().unwrap();
        registration["disabled"] = JsonValue::Bool(true);
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "mcp": {"servers": {
                    "existing": {"type":"local", "command":["external"], "disabled":true},
                    "icm123": registration
                }},
                "permissions": [
                    {"action":"existing_*", "resource":"*", "effect":"ask"},
                    {"action":"dangerous_*", "resource":"*", "effect":"deny"},
                    {"action":"icm123_icm_memory_recall", "resource":"*", "effect":"deny"},
                    {"action":"icm123_icm_memory_recall", "resource":"*", "effect":"allow"},
                    {"action":"icm123_icm_memory_store", "resource":"*", "effect":"ask"}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let document = document(path, DocumentKind::OpenCode);
        let spec = ProviderSpec {
            definition: Provider::OpenCode.definition(),
            provider: Provider::OpenCode,
            scope: Scope::ProjectLocal,
            documents: vec![document.clone()],
            inspection_documents: vec![document],
        };

        let (preserved, causal) = observed_restrictions(&spec, "icm123").unwrap();
        assert_eq!(
            preserved,
            BTreeSet::from([
                "last-matching-rule-wins".to_owned(),
                "mcp.servers.existing.disabled=true".to_owned(),
                "permissions:dangerous_*|*|deny".to_owned(),
                "permissions:existing_*|*|ask".to_owned(),
            ])
        );
        assert_eq!(
            causal,
            BTreeSet::from([
                "mcp.servers.icm123.disabled=true".to_owned(),
                "permissions:icm123_icm_memory_store|*|ask".to_owned(),
            ])
        );
    }

    #[test]
    fn project_templates_resolve_from_subdirectories_and_claude_uses_main_checkout_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("main");
        let git_dir = main.join(".git/worktrees/topic");
        let worktree = tmp.path().join("topic");
        let cwd = worktree.join("nested/deeper");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", git_dir.display()),
        )
        .unwrap();

        for definition in PROVIDER_REGISTRY
            .iter()
            .filter(|definition| definition.provider != Provider::OpenCode)
        {
            for template in definition.project {
                let Location::Project(relative) = template.location else {
                    continue;
                };
                let root = if definition.provider == Provider::ClaudeCode
                    && relative == ".claude/settings.local.json"
                {
                    &main
                } else {
                    &worktree
                };
                assert_eq!(
                    project_path(definition.provider, relative, &cwd).unwrap(),
                    root.join(relative)
                );
            }
        }
    }

    #[test]
    fn opencode_resolver_orders_layers_and_mutates_only_highest_jsonc() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let cwd = root.join("packages/web");
        let global = tmp.path().join("config/opencode.json");
        let root_direct = root.join("opencode.json");
        let cwd_direct = cwd.join("opencode.json");
        let root_dot = root.join(".opencode/opencode.json");
        let cwd_dot = cwd.join(".opencode/opencode.jsonc");
        for path in [&global, &root_direct, &cwd_direct, &root_dot, &cwd_dot] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(&global, r#"{"winner":"global"}"#).unwrap();
        std::fs::write(&root_direct, r#"{"winner":"root-direct"}"#).unwrap();
        std::fs::write(&cwd_direct, r#"{"winner":"cwd-direct"}"#).unwrap();
        std::fs::write(&root_dot, r#"{"winner":"root-dot"}"#).unwrap();
        std::fs::write(
            &cwd_dot,
            "{\n  // JSONC remains a supported mutation target\n  \"winner\": \"cwd-dot\",\n  \"permissions\": [{\"action\": \"dangerous_*\", \"resource\": \"*\", \"effect\": \"deny\"}],\n}\n",
        )
        .unwrap();

        let (documents, inspection_documents) =
            opencode_documents(Scope::ProjectLocal, &cwd, &global).unwrap();
        assert_eq!(documents[0].path, cwd_dot);
        assert_eq!(
            inspection_documents
                .iter()
                .map(|document| document.path.clone())
                .collect::<Vec<_>>(),
            vec![
                global.clone(),
                root_direct.clone(),
                cwd_direct.clone(),
                root_dot.clone(),
                cwd_dot.clone(),
            ]
        );
        let spec = ProviderSpec {
            definition: Provider::OpenCode.definition(),
            provider: Provider::OpenCode,
            scope: Scope::ProjectLocal,
            documents,
            inspection_documents,
        };
        assert_eq!(
            effective_opencode_value(&spec).unwrap()["winner"],
            "cwd-dot"
        );

        let untouched = [&global, &root_direct, &cwd_direct, &root_dot]
            .map(|path| std::fs::read(path).unwrap());
        let manifest_path = tmp.path().join("manifest.json");
        let lock = InstallManifest::lock(&manifest_path).unwrap();
        let mut manifest = InstallManifest::empty();
        manifest.provider_ownership =
            Some(crate::provider_journal::ProviderOwnership::empty("icm123").unwrap());
        apply_documents(&spec, "icm123", &mut manifest, &manifest_path, &lock).unwrap();
        assert_eq!(
            untouched,
            [&global, &root_direct, &cwd_direct, &root_dot]
                .map(|path| std::fs::read(path).unwrap())
        );
        assert!(inspect_effective(&spec, "icm123")
            .unwrap()
            .iter()
            .all(|observation| observation.exists && !observation.blocked));
        let (_, DocumentValue::Json(value)) =
            read_document(&document(cwd_dot, DocumentKind::OpenCode)).unwrap()
        else {
            panic!("OpenCode settings must be JSON");
        };
        assert_eq!(value["permissions"][0]["effect"], "deny");
    }

    #[test]
    fn opencode_resolver_rejects_json_and_jsonc_at_one_layer() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join("opencode.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("opencode.jsonc"), "{}").unwrap();
        assert!(opencode_documents(
            Scope::ProjectLocal,
            tmp.path(),
            &tmp.path().join("global/opencode.json")
        )
        .unwrap_err()
        .to_string()
        .contains("ambiguous provider"));
    }

    #[test]
    fn non_opencode_resolver_selects_one_candidate_and_rejects_two() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("settings.json");
        let alternate = tmp.path().join("settings.jsonc");
        assert_eq!(
            provider_config_at(Provider::Zed, &primary).unwrap(),
            primary
        );
        std::fs::write(&alternate, "{}").unwrap();
        assert_eq!(
            provider_config_at(Provider::Zed, &primary).unwrap(),
            alternate
        );
        std::fs::write(&primary, "{}").unwrap();
        assert!(provider_config_at(Provider::Zed, &primary).is_err());

        let codex = tmp.path().join("config.toml");
        let codex_local = tmp.path().join("config.local.toml");
        std::fs::write(&codex_local, "").unwrap();
        assert_eq!(
            provider_config_at(Provider::Codex, &codex).unwrap(),
            codex_local
        );
    }

    fn registry_test_spec(
        definition: &'static ProviderDefinition,
        scope: Scope,
        root: &Path,
    ) -> ProviderSpec {
        let templates = match scope {
            Scope::ProjectLocal => definition.project,
            Scope::User => definition.user,
        };
        let documents = templates
            .iter()
            .enumerate()
            .map(|(index, template)| {
                let extension = if template.kind == DocumentKind::Codex {
                    "toml"
                } else {
                    "json"
                };
                document(
                    root.join(format!(
                        "{}-{index}.{extension}",
                        definition.provider.as_str()
                    )),
                    template.kind,
                )
            })
            .collect::<Vec<_>>();
        ProviderSpec {
            definition,
            provider: definition.provider,
            scope,
            inspection_documents: documents.clone(),
            documents,
        }
    }

    fn registry_fixture(kind: DocumentKind) -> &'static [u8] {
        match kind {
            DocumentKind::Codex => include_bytes!("../tests/fixtures/providers/codex.toml"),
            DocumentKind::JsonRegistration => {
                include_bytes!("../tests/fixtures/providers/registration.json")
            }
            DocumentKind::JsonPermissions => {
                include_bytes!("../tests/fixtures/providers/permissions.json")
            }
            DocumentKind::OpenCode => include_bytes!("../tests/fixtures/providers/opencode.json"),
            DocumentKind::Zed => include_bytes!("../tests/fixtures/providers/zed.json"),
        }
    }

    fn seed_registry_documents(spec: &ProviderSpec) {
        for document in &spec.documents {
            std::fs::create_dir_all(document.path.parent().unwrap()).unwrap();
            std::fs::write(&document.path, registry_fixture(document.kind)).unwrap();
        }
    }

    fn prepared_zed_recovery(
        root: &Path,
    ) -> (
        ProviderSpec,
        PathBuf,
        ManifestLock,
        InstallManifest,
        String,
        Vec<u8>,
    ) {
        let document = document(root.join("settings.jsonc"), DocumentKind::Zed);
        std::fs::write(
            &document.path,
            b"{\n  // unrelated user bytes\n  \"sentinel\": \"before\",\n}\n",
        )
        .unwrap();
        let spec = ProviderSpec {
            definition: Provider::Zed.definition(),
            provider: Provider::Zed,
            scope: Scope::ProjectLocal,
            documents: vec![document.clone()],
            inspection_documents: vec![document],
        };
        let manifest_path = root.join("install-manifest.json");
        let lock = InstallManifest::lock(&manifest_path).unwrap();
        let mut manifest = InstallManifest::empty();
        manifest.provider_ownership =
            Some(crate::provider_journal::ProviderOwnership::empty("icm123").unwrap());
        let prepared = prepare_source_document(&spec, &spec.documents[0], "icm123").unwrap();
        let prepared_after = prepared.after.clone();
        let operation_id = prepare_trust_operation(&mut manifest, &spec, &[prepared])
            .unwrap()
            .unwrap();
        manifest.save_locked(&manifest_path, &lock).unwrap();
        (
            spec,
            manifest_path,
            lock,
            manifest,
            operation_id,
            prepared_after,
        )
    }

    #[test]
    fn recovery_rebases_disjoint_edits_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let (spec, manifest_path, lock, mut manifest, operation_id, _) =
            prepared_zed_recovery(tmp.path());
        let path = &spec.documents[0].path;
        let external = std::fs::read_to_string(path)
            .unwrap()
            .replace("\"before\"", "\"external-disjoint\"")
            .into_bytes();
        std::fs::write(path, &external).unwrap();
        let external_hash = sha256(&external);

        recover_provenance(
            &mut manifest,
            &TargetArgs {
                provider: Provider::Zed,
                scope: Scope::ProjectLocal,
            },
            "icm123",
            &manifest_path,
            &lock,
        )
        .unwrap();

        let final_bytes = std::fs::read(path).unwrap();
        assert!(String::from_utf8_lossy(&final_bytes).contains("external-disjoint"));
        assert!(String::from_utf8_lossy(&final_bytes).contains("unrelated user bytes"));
        assert!(inspect(&spec, "icm123")
            .unwrap()
            .iter()
            .all(|observation| observation.exists && !observation.blocked));
        let ownership = manifest.provider_ownership.as_ref().unwrap();
        let operation = ownership
            .operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .unwrap();
        assert_eq!(ownership.generation, 2);
        assert_eq!(operation.requested.action, OperationAction::Recover);
        assert_eq!(operation.phase, OperationPhase::Applied);
        assert!(operation.targets.iter().all(|target| {
            target.before_hash == external_hash
                && target.expected_after_hash == sha256(&final_bytes)
                && target.observed_after_hash.as_ref() == Some(&target.expected_after_hash)
        }));
        assert!(ownership
            .owned_fragments
            .iter()
            .all(|fragment| fragment.generation == 2));

        let manifest_bytes = std::fs::read(&manifest_path).unwrap();
        recover_provenance(
            &mut manifest,
            &TargetArgs {
                provider: Provider::Zed,
                scope: Scope::ProjectLocal,
            },
            "icm123",
            &manifest_path,
            &lock,
        )
        .unwrap();
        assert_eq!(std::fs::read(path).unwrap(), final_bytes);
        assert_eq!(std::fs::read(manifest_path).unwrap(), manifest_bytes);
    }

    #[test]
    fn recovery_finalizes_an_already_written_after_state() {
        let tmp = tempfile::tempdir().unwrap();
        let (spec, manifest_path, lock, mut manifest, operation_id, prepared_after) =
            prepared_zed_recovery(tmp.path());
        let path = &spec.documents[0].path;
        std::fs::write(path, &prepared_after).unwrap();
        let after_hash = sha256(&prepared_after);

        recover_provenance(
            &mut manifest,
            &TargetArgs {
                provider: Provider::Zed,
                scope: Scope::ProjectLocal,
            },
            "icm123",
            &manifest_path,
            &lock,
        )
        .unwrap();

        assert_eq!(std::fs::read(path).unwrap(), prepared_after);
        let ownership = manifest.provider_ownership.as_ref().unwrap();
        let operation = ownership
            .operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .unwrap();
        assert_eq!(ownership.generation, 2);
        assert_eq!(operation.requested.action, OperationAction::Recover);
        assert_eq!(operation.phase, OperationPhase::Applied);
        assert!(operation.targets.iter().all(|target| {
            target.before_hash == after_hash
                && target.expected_after_hash == after_hash
                && target.observed_after_hash.as_ref() == Some(&after_hash)
        }));
        assert_eq!(ownership.owned_fragments.len(), 3);
        assert!(ownership
            .owned_fragments
            .iter()
            .all(|fragment| fragment.generation == 2));
    }

    #[test]
    fn recovery_marks_semantic_overlap_without_writing_target() {
        let tmp = tempfile::tempdir().unwrap();
        let (spec, manifest_path, lock, mut manifest, operation_id, _) =
            prepared_zed_recovery(tmp.path());
        let path = &spec.documents[0].path;
        let desired_hash = manifest.provider_ownership.as_ref().unwrap().operations[0].targets[0]
            .expected_after_hash
            .clone();
        let conflict = br#"{"context_servers":{"icm123":{"command":"external"}}}"#;
        std::fs::write(path, conflict).unwrap();
        let conflict_hash = sha256(conflict);

        assert!(recover_provenance(
            &mut manifest,
            &TargetArgs {
                provider: Provider::Zed,
                scope: Scope::ProjectLocal,
            },
            "icm123",
            &manifest_path,
            &lock,
        )
        .is_err());

        assert_eq!(std::fs::read(path).unwrap(), conflict);
        let ownership = manifest.provider_ownership.as_ref().unwrap();
        let operation = ownership
            .operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .unwrap();
        assert_eq!(ownership.generation, 2);
        assert_eq!(operation.requested.action, OperationAction::Recover);
        assert_eq!(operation.phase, OperationPhase::Conflict);
        assert!(operation.targets.iter().all(|target| {
            target.before_hash == conflict_hash
                && target.expected_after_hash == desired_hash
                && target.observed_after_hash.as_ref() == Some(&conflict_hash)
        }));
        assert!(manifest.provider_splices.is_empty());
        assert!(ownership.owned_fragments.is_empty());
    }

    #[test]
    fn removal_recovery_rebases_disjoint_edits() {
        let tmp = tempfile::tempdir().unwrap();
        let document = document(tmp.path().join("settings.jsonc"), DocumentKind::Zed);
        std::fs::write(
            &document.path,
            b"{\n  // unrelated user bytes\n  \"sentinel\": \"before\",\n}\n",
        )
        .unwrap();
        let spec = ProviderSpec {
            definition: Provider::Zed.definition(),
            provider: Provider::Zed,
            scope: Scope::ProjectLocal,
            documents: vec![document.clone()],
            inspection_documents: vec![document],
        };
        let manifest_path = tmp.path().join("install-manifest.json");
        let lock = InstallManifest::lock(&manifest_path).unwrap();
        let mut manifest = InstallManifest::empty();
        manifest.provider_ownership =
            Some(crate::provider_journal::ProviderOwnership::empty("icm123").unwrap());
        apply_documents(&spec, "icm123", &mut manifest, &manifest_path, &lock).unwrap();

        let prepared = prepare_removal_document(
            &manifest,
            Provider::Zed,
            Scope::ProjectLocal,
            &spec.documents[0],
            RemovalMode::TrustOnly,
        )
        .unwrap()
        .unwrap();
        let operation_id = prepare_removal_operation(
            &mut manifest,
            Provider::Zed,
            Scope::ProjectLocal,
            RemovalMode::TrustOnly,
            &[prepared],
        )
        .unwrap();
        manifest.save_locked(&manifest_path, &lock).unwrap();

        let external = std::fs::read_to_string(&spec.documents[0].path)
            .unwrap()
            .replace("\"before\"", "\"external-disjoint\"")
            .into_bytes();
        std::fs::write(&spec.documents[0].path, &external).unwrap();
        let external_hash = sha256(&external);
        recover_provenance(
            &mut manifest,
            &TargetArgs {
                provider: Provider::Zed,
                scope: Scope::ProjectLocal,
            },
            "icm123",
            &manifest_path,
            &lock,
        )
        .unwrap();

        let final_bytes = std::fs::read(&spec.documents[0].path).unwrap();
        let observations = inspect(&spec, "icm123").unwrap();
        assert!(observations[0].exists);
        assert!(observations
            .iter()
            .skip(1)
            .all(|observation| !observation.exists));
        assert!(String::from_utf8_lossy(&final_bytes).contains("external-disjoint"));
        assert!(String::from_utf8_lossy(&final_bytes).contains("unrelated user bytes"));
        let ownership = manifest.provider_ownership.as_ref().unwrap();
        let operation = ownership
            .operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .unwrap();
        assert_eq!(ownership.generation, 3);
        assert_eq!(operation.requested.action, OperationAction::Recover);
        assert_eq!(operation.phase, OperationPhase::Removed);
        assert!(operation.targets.iter().all(|target| {
            target.before_hash == external_hash
                && target.expected_after_hash == sha256(&final_bytes)
                && target.observed_after_hash.as_ref() == Some(&target.expected_after_hash)
        }));
    }

    #[test]
    fn interrupted_apply_recovers_from_durable_preparation() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = registry_test_spec(Provider::ClaudeCode.definition(), Scope::User, tmp.path());
        let manifest_path = tmp.path().join("install-manifest.json");
        let lock = InstallManifest::lock(&manifest_path).unwrap();
        let mut manifest = InstallManifest::empty();
        manifest.provider_ownership =
            Some(crate::provider_journal::ProviderOwnership::empty("icm123").unwrap());

        let error = fail_after_first_document_write(|| {
            apply_documents(&spec, "icm123", &mut manifest, &manifest_path, &lock)
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("injected provider interruption after first document write"));
        assert_eq!(
            read_provider_document_snapshot(&spec.documents[0].path)
                .unwrap()
                .0,
            DocumentOrigin::Existing
        );
        assert_eq!(
            read_provider_document_snapshot(&spec.documents[1].path)
                .unwrap()
                .0,
            DocumentOrigin::Missing
        );

        let mut recovered = InstallManifest::load(&manifest_path).unwrap();
        assert!(recovered
            .provider_ownership
            .as_ref()
            .unwrap()
            .operations
            .iter()
            .any(|operation| operation.phase == OperationPhase::Prepared));
        recover_provenance(
            &mut recovered,
            &TargetArgs {
                provider: Provider::ClaudeCode,
                scope: Scope::User,
            },
            "icm123",
            &manifest_path,
            &lock,
        )
        .unwrap();
        assert!(inspect(&spec, "icm123")
            .unwrap()
            .iter()
            .all(|item| item.exists && !item.blocked));
        let operation = recovered
            .provider_ownership
            .as_ref()
            .unwrap()
            .operations
            .last()
            .unwrap();
        assert_eq!(operation.requested.action, OperationAction::Recover);
        assert_eq!(operation.phase, OperationPhase::Applied);
        assert!(operation.targets.iter().all(|target| {
            target.observed_after_hash.as_ref() == Some(&target.expected_after_hash)
        }));
    }

    #[test]
    fn missing_zed_config_retrust_after_strip_preserves_document_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = registry_test_spec(Provider::Zed.definition(), Scope::ProjectLocal, tmp.path());
        let manifest_path = tmp.path().join("install-manifest.json");
        let lock = InstallManifest::lock(&manifest_path).unwrap();
        let mut manifest = InstallManifest::empty();
        manifest.provider_ownership =
            Some(crate::provider_journal::ProviderOwnership::empty("icm123").unwrap());

        apply_documents(&spec, "icm123", &mut manifest, &manifest_path, &lock).unwrap();
        let first_bytes = std::fs::read(&spec.documents[0].path).unwrap();
        assert!(manifest
            .provider_splices
            .iter()
            .all(|record| record.document_origin == DocumentOrigin::Missing));

        strip_documents(
            Provider::Zed,
            Scope::ProjectLocal,
            &spec.documents,
            RemovalMode::TrustOnly,
            &mut manifest,
            &manifest_path,
            &lock,
        )
        .unwrap();
        assert!(spec.documents[0].path.exists());
        assert_eq!(manifest.provider_splices.len(), 1);
        assert_eq!(
            manifest.provider_splices[0].document_origin,
            DocumentOrigin::Missing
        );

        apply_documents(&spec, "icm123", &mut manifest, &manifest_path, &lock).unwrap();
        assert_eq!(std::fs::read(&spec.documents[0].path).unwrap(), first_bytes);
        assert!(inspect(&spec, "icm123")
            .unwrap()
            .iter()
            .all(|observation| observation.exists && !observation.blocked));
        assert!(manifest
            .provider_splices
            .iter()
            .all(|record| record.document_origin == DocumentOrigin::Missing));
        InstallManifest::load(&manifest_path).unwrap();
    }

    #[test]
    fn registry_drives_every_provider_and_scope_through_one_lifecycle() {
        let mut scenarios = 0;
        for definition in PROVIDER_REGISTRY {
            for scope in Scope::ALL {
                scenarios += 1;
                let tmp = tempfile::tempdir().unwrap();
                let spec = registry_test_spec(definition, scope, tmp.path());
                seed_registry_documents(&spec);
                let manifest_path = tmp.path().join("install-manifest.json");
                let lock = InstallManifest::lock(&manifest_path).unwrap();
                let mut manifest = InstallManifest::empty();
                let server_id = "icm123";
                manifest.provider_ownership =
                    Some(crate::provider_journal::ProviderOwnership::empty(server_id).unwrap());

                apply_documents(&spec, server_id, &mut manifest, &manifest_path, &lock).unwrap();
                let first_bytes = spec
                    .documents
                    .iter()
                    .map(|document| std::fs::read(&document.path).unwrap())
                    .collect::<Vec<_>>();
                let observations = inspect(&spec, server_id).unwrap();
                assert!(
                    observations.iter().all(|item| item.exists && !item.blocked),
                    "{} {} did not become trusted",
                    definition.provider.as_str(),
                    scope.as_str()
                );
                let ownership = manifest.provider_ownership.as_ref().unwrap();
                assert_eq!(ownership.generation, 1);
                assert_eq!(ownership.operations.len(), 1);
                assert_eq!(ownership.operations[0].targets.len(), 3);
                let owned = ownership
                    .owned_fragments
                    .iter()
                    .filter(|fragment| fragment.ownership_kind == OwnershipKind::Owned)
                    .collect::<Vec<_>>();
                assert_eq!(owned.len(), 3);
                let owned_paths = group_owned_paths(&manifest);
                assert_eq!(
                    owned_paths
                        .iter()
                        .map(|path| path.entries_owned)
                        .sum::<usize>(),
                    3
                );
                assert!(owned_paths.iter().all(|owned| spec
                    .documents
                    .iter()
                    .any(|document| document.path == owned.path)));
                let exact_tool_rules = tool_rules(definition.provider, server_id);
                assert_eq!(exact_tool_rules.len(), TOOLS.len());
                assert!(exact_tool_rules.iter().all(|rule| {
                    owned
                        .iter()
                        .any(|fragment| fragment.semantic_selector == *rule)
                        && TOOLS.iter().any(|tool| rule.contains(tool))
                }));
                assert!(!owned.iter().any(|fragment| {
                    fragment.semantic_selector == format!("mcp__{server_id}")
                        || fragment.semantic_selector == format!("mcp__{server_id}__*")
                        || fragment.semantic_selector == format!("Mcp({server_id}:*)")
                }));
                let owned_count = owned.len();
                let first_manifest = std::fs::read(&manifest_path).unwrap();

                apply_documents(&spec, server_id, &mut manifest, &manifest_path, &lock).unwrap();
                assert_eq!(
                    first_bytes,
                    spec.documents
                        .iter()
                        .map(|document| std::fs::read(&document.path).unwrap())
                        .collect::<Vec<_>>()
                );
                assert_eq!(first_manifest, std::fs::read(&manifest_path).unwrap());
                assert_eq!(
                    owned_count,
                    manifest
                        .provider_ownership
                        .as_ref()
                        .unwrap()
                        .owned_fragments
                        .iter()
                        .filter(|fragment| fragment.ownership_kind == OwnershipKind::Owned)
                        .count()
                );

                let summary = strip_documents(
                    definition.provider,
                    scope,
                    &spec.documents,
                    RemovalMode::TrustOnly,
                    &mut manifest,
                    &manifest_path,
                    &lock,
                )
                .unwrap();
                assert_eq!(
                    summary
                        .outcomes
                        .iter()
                        .map(|outcome| outcome.entries_removed)
                        .sum::<usize>(),
                    owned_count - 1
                );
                assert!(summary.outcomes.iter().all(|outcome| {
                    !outcome.deleted
                        && spec
                            .documents
                            .iter()
                            .any(|document| document.path == outcome.path)
                }));
                let stripped = inspect(&spec, server_id).unwrap();
                assert!(stripped[0].exists, "strip must retain registration");
                assert!(stripped.iter().skip(1).all(|item| !item.exists));
                assert_eq!(
                    manifest
                        .provider_ownership
                        .as_ref()
                        .unwrap()
                        .owned_fragments
                        .iter()
                        .filter(|fragment| fragment.ownership_kind == OwnershipKind::Owned)
                        .count(),
                    1
                );

                apply_documents(&spec, server_id, &mut manifest, &manifest_path, &lock).unwrap();
                assert!(inspect(&spec, server_id)
                    .unwrap()
                    .iter()
                    .all(|item| item.exists && !item.blocked));
                assert_eq!(
                    manifest
                        .provider_ownership
                        .as_ref()
                        .unwrap()
                        .owned_fragments
                        .iter()
                        .filter(|fragment| fragment.ownership_kind == OwnershipKind::Owned)
                        .count(),
                    owned_count
                );

                let uninstall = strip_documents(
                    definition.provider,
                    scope,
                    &spec.documents,
                    RemovalMode::Uninstall,
                    &mut manifest,
                    &manifest_path,
                    &lock,
                )
                .unwrap();
                assert_eq!(
                    uninstall
                        .outcomes
                        .iter()
                        .map(|outcome| outcome.entries_removed)
                        .sum::<usize>(),
                    owned_count
                );
                assert!(inspect(&spec, server_id)
                    .unwrap()
                    .iter()
                    .all(|item| !item.exists));
                assert!(!manifest
                    .provider_ownership
                    .as_ref()
                    .unwrap()
                    .owned_fragments
                    .iter()
                    .any(|fragment| fragment.ownership_kind == OwnershipKind::Owned));
                for document in &spec.documents {
                    match read_document(document).unwrap().1 {
                        DocumentValue::Json(value) => {
                            assert_eq!(value["sentinel"], "unchanged");
                            match document.kind {
                                DocumentKind::JsonPermissions => {
                                    assert_eq!(value["permissions"]["deny"][0], "Bash(rm:*)");
                                    assert_eq!(value["permissions"]["ask"][0], "WebFetch(*)");
                                }
                                DocumentKind::OpenCode => {
                                    assert_eq!(value["permissions"][0]["effect"], "deny")
                                }
                                DocumentKind::Zed => assert_eq!(
                                    value["agent"]["tool_permissions"]["tools"]["dangerous.write"]
                                        ["default"],
                                    "deny"
                                ),
                                _ => {}
                            }
                        }
                        DocumentValue::Toml(value) => {
                            assert_eq!(value["sentinel"]["keep"].as_str(), Some("unchanged"));
                            assert_eq!(
                                value["mcp_servers"]["external"]["tools"]["external_tool"]
                                    ["approval_mode"]
                                    .as_str(),
                                Some("deny")
                            );
                        }
                    }
                }

                apply_documents(&spec, server_id, &mut manifest, &manifest_path, &lock).unwrap();
                assert!(inspect(&spec, server_id)
                    .unwrap()
                    .iter()
                    .all(|item| item.exists && !item.blocked));
                let retrusted = manifest.provider_ownership.as_ref().unwrap();
                assert_eq!(retrusted.generation, 5);
                assert_eq!(
                    retrusted
                        .owned_fragments
                        .iter()
                        .filter(|fragment| fragment.ownership_kind == OwnershipKind::Owned)
                        .count(),
                    owned_count
                );
            }
        }
        assert_eq!(scenarios, PROVIDER_REGISTRY.len() * Scope::ALL.len());
    }
    #[test]
    fn wildcard_and_higher_precedence_blockers_are_effective() {
        let claude = serde_json::json!({
            "permissions": {
                "allow": ["mcp__icm123__icm_memory_recall"],
                "deny": ["mcp__icm123__*"]
            }
        });
        assert!(inspect_json_permissions(
            Provider::ClaudeCode,
            Path::new("claude.json"),
            &claude,
            "icm123"
        )
        .unwrap()
        .iter()
        .all(|item| item.blocked));

        let cursor = serde_json::json!({
            "permissions": {
                "allow": ["Mcp(icm123:icm_memory_recall)"],
                "deny": ["Mcp(icm123:*)"]
            }
        });
        assert!(inspect_json_permissions(
            Provider::Cursor,
            Path::new("cursor.json"),
            &cursor,
            "icm123"
        )
        .unwrap()
        .iter()
        .all(|item| item.blocked));

        let zed = serde_json::json!({
            "agent":{"tool_permissions":{"tools":{
                "mcp:icm123:icm_memory_recall":{
                    "default":"allow",
                    "always_confirm":[{"pattern":".*"}]
                }
            }}}
        });
        assert!(inspect_zed(Path::new("zed.json"), &zed, "icm123").unwrap()[1].blocked);
    }
}
