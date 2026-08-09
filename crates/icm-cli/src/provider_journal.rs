//! Closed schema-v2 provider ownership journal.
//!
//! The public `providerOwnership` value stores hashes and semantic ownership.
//! Exact ICM-authored source splices live in the private sidecar below; neither
//! representation stores a provider document snapshot.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use super::provider_document::{OwnedSplice, OwnedTarget, SourceFormat};

pub(crate) const SCHEMA_VERSION: u32 = 2;
pub(crate) const MAX_OPERATIONS: usize = 128;
pub(crate) const MAX_OWNED_FRAGMENTS: usize = 256;
pub(crate) const MAX_TARGETS_PER_OPERATION: usize = 64;
pub(crate) const MAX_CREATED_CONTAINERS: usize = 32;
const PRODUCER_VERSION: &str = "icm-provider-engine-v2";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderOwnership {
    pub(crate) schema_version: u32,
    pub(crate) min_reader_version: u32,
    pub(crate) producer_version: String,
    pub(crate) generation: u64,
    pub(crate) installation_id: String,
    pub(crate) operations: Vec<ProviderOperation>,
    pub(crate) owned_fragments: Vec<OwnedFragment>,
}

impl ProviderOwnership {
    pub(crate) fn empty(installation_id: impl Into<String>) -> Result<Self> {
        let journal = Self {
            schema_version: SCHEMA_VERSION,
            min_reader_version: SCHEMA_VERSION,
            producer_version: PRODUCER_VERSION.to_owned(),
            generation: 0,
            installation_id: installation_id.into(),
            operations: Vec::new(),
            owned_fragments: Vec::new(),
        };
        journal.validate()?;
        Ok(journal)
    }

    /// Schema-1 snapshots carry no fragment-level deletion authority.
    pub(crate) fn from_legacy_unproven(installation_id: impl Into<String>) -> Result<Self> {
        Self::empty(installation_id)
    }

    pub(crate) fn push_operation(&mut self, operation: ProviderOperation) -> Result<()> {
        ensure!(
            self.operations.len() < MAX_OPERATIONS,
            "provider journal operation retention bound exceeded"
        );
        operation.validate()?;
        ensure!(
            !self
                .operations
                .iter()
                .any(|existing| existing.id == operation.id),
            "provider journal duplicates operation id"
        );
        self.operations.push(operation);
        Ok(())
    }

    pub(crate) fn push_fragment(&mut self, fragment: OwnedFragment) -> Result<()> {
        ensure!(
            self.owned_fragments.len() < MAX_OWNED_FRAGMENTS,
            "provider journal owned-fragment retention bound exceeded"
        );
        self.owned_fragments.push(fragment);
        if let Err(error) = self.validate() {
            self.owned_fragments.pop();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported provider journal schema version {}",
            self.schema_version
        );
        ensure!(
            self.min_reader_version == SCHEMA_VERSION,
            "unsupported provider journal minimum reader version {}",
            self.min_reader_version
        );
        ensure!(
            valid_producer_version(&self.producer_version),
            "invalid provider journal producer version"
        );
        ensure!(
            valid_installation_id(&self.installation_id),
            "invalid provider journal installation id"
        );
        ensure!(
            self.operations.len() <= MAX_OPERATIONS,
            "provider journal operation retention bound exceeded"
        );
        ensure!(
            self.owned_fragments.len() <= MAX_OWNED_FRAGMENTS,
            "provider journal owned-fragment retention bound exceeded"
        );

        let mut operation_ids = BTreeSet::new();
        for operation in &self.operations {
            operation.validate()?;
            ensure!(
                operation_ids.insert(operation.id.as_str()),
                "provider journal duplicates operation id"
            );
        }

        let mut fragment_ids = BTreeSet::new();
        let mut semantic_fragments = BTreeSet::new();
        for fragment in &self.owned_fragments {
            fragment.validate(self.generation)?;
            ensure!(
                fragment_ids.insert(fragment.id.as_str()),
                "provider journal duplicates fragment id"
            );
            ensure!(
                semantic_fragments.insert((
                    fragment.provider,
                    fragment.scope,
                    fragment.canonical_path.as_str(),
                    fragment.semantic_selector.as_str(),
                )),
                "provider journal duplicates semantic fragment"
            );

            let operation = self
                .operations
                .iter()
                .find(|operation| operation.id == fragment.introducing_operation_id)
                .context("provider fragment references an unknown operation")?;
            ensure!(
                operation.requested.provider == fragment.provider
                    && operation.requested.surface == fragment.surface
                    && operation.requested.scope == fragment.scope
                    && operation.requested.dialect == fragment.dialect,
                "provider fragment identity differs from its introducing operation"
            );
            let target = operation
                .targets
                .iter()
                .find(|target| {
                    target.canonical_path == fragment.canonical_path
                        && target.patch.selector == fragment.semantic_selector
                })
                .context("provider fragment has no exact introducing target")?;
            ensure!(
                target.format == fragment.format
                    && target.dialect == fragment.dialect
                    && target.patch.value_fingerprint == fragment.value_fingerprint,
                "provider fragment differs from its introducing target"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderOperation {
    pub(crate) id: String,
    pub(crate) requested: RequestedOperation,
    pub(crate) phase: OperationPhase,
    pub(crate) targets: Vec<TargetIntent>,
}

impl ProviderOperation {
    fn validate(&self) -> Result<()> {
        ensure!(!self.id.is_empty(), "provider operation id is empty");
        ensure!(!self.targets.is_empty(), "provider operation has no target");
        ensure!(
            self.targets.len() <= MAX_TARGETS_PER_OPERATION,
            "provider operation target bound exceeded"
        );
        let mut targets = BTreeSet::new();
        for target in &self.targets {
            target.validate(&self.requested, self.phase)?;
            ensure!(
                targets.insert((
                    target.canonical_path.as_str(),
                    target.patch.selector.as_str()
                )),
                "provider operation duplicates a path/selector target"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestedOperation {
    pub(crate) provider: ProviderId,
    pub(crate) surface: ProviderSurface,
    pub(crate) scope: ProviderScope,
    pub(crate) dialect: ProviderDialect,
    pub(crate) action: OperationAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetIntent {
    pub(crate) canonical_path: String,
    pub(crate) display_path: String,
    pub(crate) format: SourceFormat,
    pub(crate) dialect: ProviderDialect,
    pub(crate) before_hash: String,
    pub(crate) expected_after_hash: String,
    pub(crate) observed_after_hash: Option<String>,
    pub(crate) patch: ExactTransform,
    pub(crate) inverse: ExactTransform,
    pub(crate) ownership_delta: OwnershipDelta,
    pub(crate) phase: OperationPhase,
}

impl TargetIntent {
    fn validate(
        &self,
        requested: &RequestedOperation,
        operation_phase: OperationPhase,
    ) -> Result<()> {
        ensure!(
            !self.canonical_path.is_empty() && self.display_path == self.canonical_path,
            "provider target path is invalid"
        );
        ensure!(
            self.dialect == requested.dialect && self.phase == operation_phase,
            "provider target dialect or phase differs from its operation"
        );
        ensure!(
            is_sha256(&self.before_hash) && is_sha256(&self.expected_after_hash),
            "provider target before/after hash is not SHA-256"
        );
        match (&self.observed_after_hash, self.phase) {
            (None, OperationPhase::Prepared) => {}
            (Some(hash), phase) if phase != OperationPhase::Prepared && is_sha256(hash) => {}
            _ => bail!("provider target observed hash does not match its phase"),
        }
        self.patch.validate()?;
        self.inverse.validate()?;
        ensure!(
            self.patch.selector == self.inverse.selector
                && self.patch.value_fingerprint == self.inverse.value_fingerprint,
            "provider patch and inverse identity differ"
        );
        self.ownership_delta.validate(&self.patch, &self.inverse)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExactTransform {
    pub(crate) kind: TransformKind,
    pub(crate) selector: String,
    pub(crate) value_fingerprint: String,
}

impl ExactTransform {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.selector.is_empty(),
            "provider transform selector is empty"
        );
        ensure!(
            is_sha256(&self.value_fingerprint),
            "provider transform fingerprint is not SHA-256"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnershipDelta {
    pub(crate) add: Vec<String>,
    pub(crate) remove: Vec<String>,
}

impl OwnershipDelta {
    fn validate(&self, patch: &ExactTransform, inverse: &ExactTransform) -> Result<()> {
        let add = exact_selector_set(&self.add)?;
        let remove = exact_selector_set(&self.remove)?;
        ensure!(
            add.is_disjoint(&remove),
            "provider ownership delta adds and removes the same selector"
        );
        let valid = match (patch.kind, inverse.kind) {
            (TransformKind::Insert, TransformKind::Remove) => {
                add == BTreeSet::from([patch.selector.as_str()]) && remove.is_empty()
            }
            (TransformKind::Remove, TransformKind::Insert) => {
                remove == BTreeSet::from([patch.selector.as_str()]) && add.is_empty()
            }
            (TransformKind::Adopt, TransformKind::PreserveExternal) => {
                add.is_empty() && remove.is_empty()
            }
            _ => false,
        };
        ensure!(
            valid,
            "provider ownership delta contradicts exact transforms"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedFragment {
    pub(crate) id: String,
    pub(crate) provider: ProviderId,
    pub(crate) surface: ProviderSurface,
    pub(crate) scope: ProviderScope,
    pub(crate) dialect: ProviderDialect,
    pub(crate) canonical_path: String,
    pub(crate) display_path: String,
    pub(crate) format: SourceFormat,
    pub(crate) semantic_selector: String,
    pub(crate) value_fingerprint: String,
    pub(crate) created_containers: Vec<String>,
    pub(crate) ownership_kind: OwnershipKind,
    pub(crate) introducing_operation_id: String,
    pub(crate) generation: u64,
}

impl OwnedFragment {
    fn validate(&self, journal_generation: u64) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && !self.semantic_selector.is_empty()
                && !self.introducing_operation_id.is_empty(),
            "provider fragment identity is empty"
        );
        ensure!(
            !self.canonical_path.is_empty() && self.display_path == self.canonical_path,
            "provider fragment path is invalid"
        );
        ensure!(
            is_sha256(&self.value_fingerprint),
            "provider fragment fingerprint is not SHA-256"
        );
        ensure!(
            self.generation > 0 && self.generation <= journal_generation,
            "provider fragment generation is invalid"
        );
        ensure!(
            self.created_containers.len() <= MAX_CREATED_CONTAINERS,
            "provider fragment created-container bound exceeded"
        );
        let containers: BTreeSet<_> = self.created_containers.iter().map(String::as_str).collect();
        ensure!(
            containers.len() == self.created_containers.len()
                && containers
                    .iter()
                    .all(|container| !container.is_empty() && container.starts_with('/')),
            "provider fragment created container is invalid"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProviderId {
    Codex,
    ClaudeCode,
    Cursor,
    #[serde(rename = "opencode")]
    OpenCode,
    Zed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProviderSurface {
    CombinedRegistrationAndPermission,
    SplitRegistrationAndPermission,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProviderScope {
    ProjectLocal,
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum ProviderDialect {
    #[serde(rename = "codex-toml-v1")]
    CodexTomlV1,
    #[serde(rename = "claude-json-v1")]
    ClaudeJsonV1,
    #[serde(rename = "cursor-json-v1")]
    CursorJsonV1,
    #[serde(rename = "opencode-json-v2")]
    OpenCodeJsonV2,
    #[serde(rename = "zed-json-v1")]
    ZedJsonV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OperationAction {
    Trust,
    Strip,
    Uninstall,
    Recover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OperationPhase {
    Prepared,
    Applied,
    Removed,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TransformKind {
    #[serde(rename = "insert-exact-fragment")]
    Insert,
    #[serde(rename = "remove-exact-fragment")]
    Remove,
    #[serde(rename = "adopt-exact-fragment")]
    Adopt,
    #[serde(rename = "preserve-external-fragment")]
    PreserveExternal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OwnershipKind {
    Owned,
    Adopted,
    Removed,
}

/// Private sidecar. It mirrors the public journal so stale manifest writers
/// cannot erase provider provenance, and adds only exact ICM-authored splices.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SpliceJournal {
    pub(crate) version: u32,
    pub(crate) provider_ownership: ProviderOwnership,
    pub(crate) records: Vec<SpliceRecord>,
}

impl SpliceJournal {
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self> {
        let journal: Self = serde_json::from_slice(bytes).context("invalid provider sidecar")?;
        journal.validate()?;
        Ok(journal)
    }

    pub(crate) fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec_pretty(self).context("cannot encode provider sidecar")
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == SCHEMA_VERSION,
            "unsupported provider sidecar version {}",
            self.version
        );
        self.provider_ownership.validate()?;
        ensure!(
            self.records.len() <= MAX_OWNED_FRAGMENTS,
            "provider sidecar record bound exceeded"
        );
        let mut keys = BTreeSet::new();
        let mut origins = BTreeMap::new();
        for record in &self.records {
            record.validate()?;
            ensure!(
                keys.insert((
                    record.provider,
                    record.scope,
                    record.dialect,
                    record.canonical_path.as_str(),
                    record.semantic_selector.as_str(),
                    record.introducing_operation_id.as_str(),
                )),
                "provider sidecar duplicates an exact splice record"
            );
            let origin_key = (
                record.provider,
                record.scope,
                record.canonical_path.as_str(),
            );
            if let Some(origin) = origins.insert(origin_key, record.document_origin) {
                ensure!(
                    origin == record.document_origin,
                    "provider sidecar disagrees on document origin"
                );
            }

            let operation = self
                .provider_ownership
                .operations
                .iter()
                .find(|operation| operation.id == record.introducing_operation_id)
                .context("provider sidecar splice references an unknown operation")?;
            ensure!(
                operation.requested.provider == record.provider
                    && operation.requested.surface == record.surface
                    && operation.requested.scope == record.scope
                    && operation.requested.dialect == record.dialect,
                "provider sidecar splice identity differs from its operation"
            );
            let target = operation
                .targets
                .iter()
                .find(|target| {
                    target.canonical_path == record.canonical_path
                        && target.patch.selector == record.semantic_selector
                })
                .context("provider sidecar splice has no exact operation target")?;
            ensure!(
                target.format == record.source_patch.format && target.dialect == record.dialect,
                "provider sidecar splice format differs from its operation target"
            );

            let fragment = self
                .provider_ownership
                .owned_fragments
                .iter()
                .find(|fragment| {
                    fragment.provider == record.provider
                        && fragment.surface == record.surface
                        && fragment.scope == record.scope
                        && fragment.dialect == record.dialect
                        && fragment.canonical_path == record.canonical_path
                        && fragment.semantic_selector == record.semantic_selector
                        && fragment.introducing_operation_id == record.introducing_operation_id
                });
            match operation.phase {
                OperationPhase::Prepared => ensure!(
                    fragment.is_none(),
                    "prepared provider splice prematurely claims fragment ownership"
                ),
                _ => ensure!(
                    fragment.is_some_and(|fragment| {
                        fragment.ownership_kind == OwnershipKind::Owned
                            && fragment.format == record.source_patch.format
                    }),
                    "terminal provider splice is not backed by active ownership"
                ),
            }
        }

        for fragment in &self.provider_ownership.owned_fragments {
            let records = self
                .records
                .iter()
                .filter(|record| {
                    fragment.provider == record.provider
                        && fragment.surface == record.surface
                        && fragment.scope == record.scope
                        && fragment.dialect == record.dialect
                        && fragment.canonical_path == record.canonical_path
                        && fragment.semantic_selector == record.semantic_selector
                        && fragment.introducing_operation_id == record.introducing_operation_id
                })
                .count();
            ensure!(
                records == usize::from(fragment.ownership_kind == OwnershipKind::Owned),
                "provider sidecar and fragment ownership are not an exact active bijection"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SpliceRecord {
    pub(crate) provider: ProviderId,
    pub(crate) surface: ProviderSurface,
    pub(crate) scope: ProviderScope,
    pub(crate) dialect: ProviderDialect,
    pub(crate) canonical_path: String,
    pub(crate) semantic_selector: String,
    pub(crate) introducing_operation_id: String,
    pub(crate) document_origin: DocumentOrigin,
    pub(crate) source_patch: SourcePatch,
}

impl SpliceRecord {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.canonical_path.is_empty()
                && !self.semantic_selector.is_empty()
                && !self.introducing_operation_id.is_empty(),
            "provider sidecar splice identity is empty"
        );
        self.source_patch
            .validate_for(self.dialect, &self.semantic_selector)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourcePatch {
    pub(crate) format: SourceFormat,
    pub(crate) owned: Option<OwnedSplice>,
    pub(crate) created: Vec<OwnedSplice>,
}

impl SourcePatch {
    fn validate_for(&self, dialect: ProviderDialect, selector: &str) -> Result<()> {
        ensure!(
            match dialect {
                ProviderDialect::CodexTomlV1 => self.format == SourceFormat::Toml,
                _ => matches!(self.format, SourceFormat::Json | SourceFormat::Jsonc),
            },
            "provider sidecar format differs from its dialect"
        );
        ensure!(
            self.created.len() <= MAX_CREATED_CONTAINERS,
            "provider sidecar created-splice bound exceeded"
        );
        let owned = self
            .owned
            .as_ref()
            .context("provider sidecar has no primary inverse splice")?;
        validate_splice(owned)?;
        ensure!(
            target_matches_selector(dialect, selector, &owned.target),
            "provider sidecar primary splice differs from its semantic selector"
        );
        for (index, splice) in self.created.iter().enumerate() {
            validate_splice(splice)?;
            ensure!(
                !self.created[..index].contains(splice),
                "provider sidecar duplicates a created splice"
            );
            ensure!(
                created_target_is_authorized(&splice.target, &owned.target, dialect, selector),
                "provider sidecar created splice is outside its primary target"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DocumentOrigin {
    Missing,
    Empty,
    Existing,
}

fn validate_splice(splice: &OwnedSplice) -> Result<()> {
    ensure!(
        !splice.inserted.is_empty(),
        "provider sidecar splice is empty"
    );
    let valid = match &splice.target {
        OwnedTarget::JsonRootObject => true,
        OwnedTarget::JsonMember { parent, key, .. } => {
            valid_source_path(parent, true) && !key.is_empty()
        }
        OwnedTarget::JsonArrayElement { array, .. } => valid_source_path(array, false),
        OwnedTarget::TomlTable { path, values } => {
            valid_source_path(path, false)
                && values.iter().all(|(key, _)| !key.is_empty())
                && values
                    .iter()
                    .map(|(key, _)| key)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == values.len()
        }
        OwnedTarget::TomlScalar { table, key, value } => {
            valid_source_path(table, false) && !key.is_empty() && !value.is_table()
        }
    };
    ensure!(valid, "provider sidecar splice target is invalid");
    Ok(())
}

fn valid_source_path(path: &super::provider_document::SourcePath, allow_root: bool) -> bool {
    (allow_root || !path.0.is_empty()) && path.0.iter().all(|segment| !segment.is_empty())
}

fn target_matches_selector(dialect: ProviderDialect, selector: &str, target: &OwnedTarget) -> bool {
    match (dialect, target) {
        (ProviderDialect::CodexTomlV1, OwnedTarget::TomlTable { path, values })
            if path.0.len() == 2 && path.0[0] == "mcp_servers" =>
        {
            selector == format!("mcp_servers.{}", path.0[1])
                && values
                    .iter()
                    .map(|(key, _)| key.as_str())
                    .collect::<BTreeSet<_>>()
                    == BTreeSet::from(["args", "command"])
        }
        (ProviderDialect::CodexTomlV1, OwnedTarget::TomlScalar { table, key, value })
            if table.0.len() == 4 && table.0[0] == "mcp_servers" && table.0[2] == "tools" =>
        {
            key == "approval_mode"
                && value.as_str() == Some("approve")
                && selector
                    == format!(
                        "mcp_servers.{}.tools.{}.approval_mode=approve",
                        table.0[1], table.0[3]
                    )
        }
        (
            ProviderDialect::ClaudeJsonV1 | ProviderDialect::CursorJsonV1,
            OwnedTarget::JsonMember { parent, key, .. },
        ) if source_path_is(parent, &["mcpServers"]) => selector == format!("mcpServers.{key}"),
        (
            ProviderDialect::ClaudeJsonV1 | ProviderDialect::CursorJsonV1,
            OwnedTarget::JsonArrayElement { array, value },
        ) if source_path_is(array, &["permissions", "allow"]) => value.as_str() == Some(selector),
        (ProviderDialect::OpenCodeJsonV2, OwnedTarget::JsonMember { parent, key, .. })
            if source_path_is(parent, &["mcp", "servers"]) =>
        {
            selector == format!("mcp.servers.{key}")
        }
        (ProviderDialect::OpenCodeJsonV2, OwnedTarget::JsonArrayElement { array, value })
            if source_path_is(array, &["permissions"]) =>
        {
            value.as_object().is_some_and(|rule| {
                let action = rule.get("action").and_then(serde_json::Value::as_str);
                let resource = rule.get("resource").and_then(serde_json::Value::as_str);
                let effect = rule.get("effect").and_then(serde_json::Value::as_str);
                rule.len() == 3
                    && action.is_some_and(|action| selector == format!("{action}|*|allow"))
                    && resource == Some("*")
                    && effect == Some("allow")
            })
        }
        (ProviderDialect::ZedJsonV1, OwnedTarget::JsonMember { parent, key, value })
            if source_path_is(parent, &["context_servers"]) =>
        {
            selector == format!("context_servers.{key}") && value.is_object()
        }
        (ProviderDialect::ZedJsonV1, OwnedTarget::JsonMember { parent, key, value })
            if source_path_is(parent, &["agent", "tool_permissions", "tools"]) =>
        {
            selector == format!("agent.tool_permissions.tools.{key}.default=allow")
                && value == &serde_json::json!({"default": "allow"})
        }
        _ => false,
    }
}

fn created_target_is_authorized(
    created: &OwnedTarget,
    primary: &OwnedTarget,
    dialect: ProviderDialect,
    selector: &str,
) -> bool {
    match created {
        OwnedTarget::JsonRootObject => {
            matches!(
                primary,
                OwnedTarget::JsonMember { .. } | OwnedTarget::JsonArrayElement { .. }
            )
        }
        OwnedTarget::JsonMember { parent, key, value }
            if value.as_object().is_some_and(serde_json::Map::is_empty)
                || value.as_array().is_some_and(Vec::is_empty) =>
        {
            let mut created_path = parent.0.clone();
            created_path.push(key.clone());
            json_target_path(primary)
                .is_some_and(|primary_path| is_path_prefix(&created_path, &primary_path))
        }
        OwnedTarget::TomlTable { path, values } if values.is_empty() => toml_target_path(primary)
            .is_some_and(|primary_path| is_path_prefix(&path.0, primary_path)),
        OwnedTarget::TomlScalar { table, key, value }
            if dialect == ProviderDialect::CodexTomlV1
                && key == "enabled_tools"
                && table.0.len() == 2
                && table.0[0] == "mcp_servers" =>
        {
            let expected = toml::Value::Array(vec![
                toml::Value::String("icm_memory_recall".to_owned()),
                toml::Value::String("icm_memory_store".to_owned()),
            ]);
            let same_server = matches!(
                primary,
                OwnedTarget::TomlScalar { table: primary, .. }
                    if primary.0.get(1) == table.0.get(1)
            );
            same_server && value == &expected && selector.starts_with("mcp_servers.")
        }
        _ => false,
    }
}

fn source_path_is(path: &super::provider_document::SourcePath, expected: &[&str]) -> bool {
    path.0
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn json_target_path(target: &OwnedTarget) -> Option<Vec<String>> {
    match target {
        OwnedTarget::JsonMember { parent, key, .. } => {
            let mut path = parent.0.clone();
            path.push(key.clone());
            Some(path)
        }
        OwnedTarget::JsonArrayElement { array, .. } => Some(array.0.clone()),
        _ => None,
    }
}

fn toml_target_path(target: &OwnedTarget) -> Option<&[String]> {
    match target {
        OwnedTarget::TomlTable { path, .. } => Some(&path.0),
        OwnedTarget::TomlScalar { table, .. } => Some(&table.0),
        _ => None,
    }
}

fn is_path_prefix(prefix: &[String], path: &[String]) -> bool {
    prefix.len() <= path.len() && prefix.iter().zip(path).all(|(left, right)| left == right)
}

fn exact_selector_set(values: &[String]) -> Result<BTreeSet<&str>> {
    let mut selectors = BTreeSet::new();
    for value in values {
        ensure!(!value.is_empty(), "provider ownership selector is empty");
        ensure!(
            selectors.insert(value.as_str()),
            "provider ownership delta duplicates a selector"
        );
    }
    Ok(selectors)
}

fn valid_producer_version(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

fn valid_installation_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::provider_document::SourcePath;

    fn hash(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn sample() -> ProviderOwnership {
        let selector = "mcp_servers.i123.tools.icm_memory_recall.approval_mode=approve";
        let fingerprint = hash('b');
        ProviderOwnership {
            schema_version: SCHEMA_VERSION,
            min_reader_version: SCHEMA_VERSION,
            producer_version: PRODUCER_VERSION.to_owned(),
            generation: 1,
            installation_id: "i123".to_owned(),
            operations: vec![ProviderOperation {
                id: "op1".to_owned(),
                requested: RequestedOperation {
                    provider: ProviderId::Codex,
                    surface: ProviderSurface::CombinedRegistrationAndPermission,
                    scope: ProviderScope::ProjectLocal,
                    dialect: ProviderDialect::CodexTomlV1,
                    action: OperationAction::Trust,
                },
                phase: OperationPhase::Applied,
                targets: vec![TargetIntent {
                    canonical_path: "config.toml".to_owned(),
                    display_path: "config.toml".to_owned(),
                    format: SourceFormat::Toml,
                    dialect: ProviderDialect::CodexTomlV1,
                    before_hash: hash('a'),
                    expected_after_hash: hash('c'),
                    observed_after_hash: Some(hash('c')),
                    patch: ExactTransform {
                        kind: TransformKind::Insert,
                        selector: selector.to_owned(),
                        value_fingerprint: fingerprint.clone(),
                    },
                    inverse: ExactTransform {
                        kind: TransformKind::Remove,
                        selector: selector.to_owned(),
                        value_fingerprint: fingerprint.clone(),
                    },
                    ownership_delta: OwnershipDelta {
                        add: vec![selector.to_owned()],
                        remove: Vec::new(),
                    },
                    phase: OperationPhase::Applied,
                }],
            }],
            owned_fragments: vec![OwnedFragment {
                id: "fragment1".to_owned(),
                provider: ProviderId::Codex,
                surface: ProviderSurface::CombinedRegistrationAndPermission,
                scope: ProviderScope::ProjectLocal,
                dialect: ProviderDialect::CodexTomlV1,
                canonical_path: "config.toml".to_owned(),
                display_path: "config.toml".to_owned(),
                format: SourceFormat::Toml,
                semantic_selector: selector.to_owned(),
                value_fingerprint: fingerprint,
                created_containers: Vec::new(),
                ownership_kind: OwnershipKind::Owned,
                introducing_operation_id: "op1".to_owned(),
                generation: 1,
            }],
        }
    }

    fn sample_record() -> SpliceRecord {
        SpliceRecord {
            provider: ProviderId::Codex,
            surface: ProviderSurface::CombinedRegistrationAndPermission,
            scope: ProviderScope::ProjectLocal,
            dialect: ProviderDialect::CodexTomlV1,
            canonical_path: "config.toml".to_owned(),
            semantic_selector: "mcp_servers.i123.tools.icm_memory_recall.approval_mode=approve"
                .to_owned(),
            introducing_operation_id: "op1".to_owned(),
            document_origin: DocumentOrigin::Existing,
            source_patch: SourcePatch {
                format: SourceFormat::Toml,
                owned: Some(OwnedSplice {
                    target: OwnedTarget::TomlScalar {
                        table: SourcePath(vec![
                            "mcp_servers".to_owned(),
                            "i123".to_owned(),
                            "tools".to_owned(),
                            "icm_memory_recall".to_owned(),
                        ]),
                        key: "approval_mode".to_owned(),
                        value: toml::Value::String("approve".to_owned()),
                    },
                    inserted: "\napproval_mode = \"approve\"".to_owned(),
                }),
                created: Vec::new(),
            },
        }
    }

    #[test]
    fn closed_schema_rejects_unknown_fields() {
        let mut value = serde_json::to_value(sample()).unwrap();
        value["future"] = json!(true);
        assert!(serde_json::from_value::<ProviderOwnership>(value).is_err());

        let mut value = serde_json::to_value(sample()).unwrap();
        value["operations"][0]["targets"][0]["patch"]["future"] = json!(true);
        assert!(serde_json::from_value::<ProviderOwnership>(value).is_err());
    }

    #[test]
    fn version_and_downgrade_are_rejected() {
        for (schema, reader) in [(1, 2), (3, 2), (2, 1), (2, 3)] {
            let mut journal = sample();
            journal.schema_version = schema;
            journal.min_reader_version = reader;
            assert!(journal.validate().is_err());
        }

        let mut value = serde_json::to_value(sample()).unwrap();
        value["operations"][0]["phase"] = json!("future-phase");
        assert!(serde_json::from_value::<ProviderOwnership>(value).is_err());

        assert_eq!(
            serde_json::to_value(ProviderId::OpenCode).unwrap(),
            "opencode"
        );
    }

    #[test]
    fn retention_bounds_fail_closed() {
        let mut journal = sample();
        journal.operations = (0..=MAX_OPERATIONS)
            .map(|index| {
                let mut operation = journal.operations[0].clone();
                operation.id = format!("op{index}");
                operation.targets[0].canonical_path = format!("config-{index}.toml");
                operation.targets[0].display_path = format!("config-{index}.toml");
                operation
            })
            .collect();
        journal.owned_fragments.clear();
        assert!(journal.validate().is_err());

        let mut journal = sample();
        let target = journal.operations[0].targets[0].clone();
        journal.operations[0].targets = (0..=MAX_TARGETS_PER_OPERATION)
            .map(|index| {
                let mut target = target.clone();
                target.canonical_path = format!("config-{index}.toml");
                target.display_path = format!("config-{index}.toml");
                target
            })
            .collect();
        journal.owned_fragments.clear();
        assert!(journal.validate().is_err());

        let mut journal = sample();
        journal.owned_fragments[0].created_containers = (0..=MAX_CREATED_CONTAINERS)
            .map(|index| format!("/container/{index}"))
            .collect();
        assert!(journal.validate().is_err());

        let mut journal = sample();
        let fragment = journal.owned_fragments[0].clone();
        journal.owned_fragments = (0..=MAX_OWNED_FRAGMENTS)
            .map(|index| {
                let mut fragment = fragment.clone();
                fragment.id = format!("fragment{index}");
                fragment.semantic_selector = format!("selector{index}");
                fragment
            })
            .collect();
        assert!(journal.validate().is_err());
    }

    #[test]
    fn operation_and_fragment_cross_references_are_exact() {
        let journal = sample();
        journal.validate().unwrap();

        let mut broken = journal.clone();
        broken.operations[0].targets[0].inverse.selector = "other".to_owned();
        assert!(broken.validate().is_err());

        let mut broken = journal.clone();
        broken.operations[0].targets[0].ownership_delta.add.clear();
        assert!(broken.validate().is_err());

        let mut broken = journal.clone();
        broken.owned_fragments[0].introducing_operation_id = "missing".to_owned();
        assert!(broken.validate().is_err());

        let mut tombstone = journal;
        tombstone.owned_fragments[0].ownership_kind = OwnershipKind::Removed;
        tombstone.validate().unwrap();
    }

    #[test]
    fn legacy_migration_claims_no_snapshot_ownership() {
        let journal = ProviderOwnership::from_legacy_unproven("i123").unwrap();
        let value = serde_json::to_value(journal).unwrap();
        assert_eq!(value["operations"], json!([]));
        assert_eq!(value["owned_fragments"], json!([]));
        assert!(value.to_string().find("bytes_before").is_none());
    }

    #[test]
    fn sidecar_carries_only_exact_authored_splices() {
        let ownership = sample();
        let mut sidecar = SpliceJournal {
            version: SCHEMA_VERSION,
            provider_ownership: ownership,
            records: vec![sample_record()],
        };
        sidecar.validate().unwrap();
        let encoded = sidecar.to_json().unwrap();
        assert!(SpliceJournal::from_json(&encoded).is_ok());

        sidecar.records[0]
            .source_patch
            .owned
            .as_mut()
            .unwrap()
            .inserted
            .clear();
        assert!(sidecar.validate().is_err());
    }

    #[test]
    fn splice_records_follow_prepared_owned_removed_transitions() {
        let mut prepared = sample();
        prepared.operations[0].phase = OperationPhase::Prepared;
        prepared.operations[0].targets[0].phase = OperationPhase::Prepared;
        prepared.operations[0].targets[0].observed_after_hash = None;
        prepared.owned_fragments.clear();
        let record = sample_record();
        SpliceJournal {
            version: SCHEMA_VERSION,
            provider_ownership: prepared,
            records: vec![record.clone()],
        }
        .validate()
        .unwrap();

        let applied = sample();
        assert!(SpliceJournal {
            version: SCHEMA_VERSION,
            provider_ownership: applied.clone(),
            records: vec![record.clone()],
        }
        .validate()
        .is_ok());
        assert!(SpliceJournal {
            version: SCHEMA_VERSION,
            provider_ownership: applied.clone(),
            records: Vec::new(),
        }
        .validate()
        .is_err());

        let mut removed = applied;
        removed.owned_fragments[0].ownership_kind = OwnershipKind::Removed;
        assert!(SpliceJournal {
            version: SCHEMA_VERSION,
            provider_ownership: removed.clone(),
            records: Vec::new(),
        }
        .validate()
        .is_ok());
        assert!(SpliceJournal {
            version: SCHEMA_VERSION,
            provider_ownership: removed,
            records: vec![record],
        }
        .validate()
        .is_err());
    }
}
