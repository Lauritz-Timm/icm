//! Lossless, fail-closed edits for provider-owned JSON, JSONC, and TOML.
//!
//! User documents are never serialized back from a value tree. We parse to
//! validate and locate a semantic parent, then splice only text authored by
//! ICM. The exact splice is the inverse recorded by the provider journal.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::ops::Range;

use anyhow::{bail, Context, Result};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::{Deserialize as DeriveDeserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_json_lenient::value::RawValue;
use toml_edit::{ImDocument, Item, Key, Table};

const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";
const MAX_JSON_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, DeriveDeserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SourceFormat {
    Json,
    Jsonc,
    Toml,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, DeriveDeserialize)]
#[serde(transparent)]
pub(crate) struct SourcePath(pub(crate) Vec<String>);

impl SourcePath {
    pub(crate) fn root() -> Self {
        Self::default()
    }

    pub(crate) fn new<I, S>(segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(segments.into_iter().map(Into::into).collect())
    }

    fn child(&self, segment: impl Into<String>) -> Self {
        let mut path = self.0.clone();
        path.push(segment.into());
        Self(path)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Insert {
    JsonMember {
        parent: SourcePath,
        key: String,
        value: JsonValue,
    },
    JsonArrayElement {
        array: SourcePath,
        value: JsonValue,
    },
    TomlTable {
        path: SourcePath,
        values: Vec<(String, toml::Value)>,
    },
    TomlScalar {
        table: SourcePath,
        key: String,
        value: toml::Value,
    },
}

/// The direct semantic node an authored splice created. Removal must prove this
/// node still exists at this exact location before touching source bytes.
#[derive(Clone, Debug, PartialEq, Serialize, DeriveDeserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum OwnedTarget {
    JsonRootObject,
    JsonMember {
        parent: SourcePath,
        key: String,
        value: JsonValue,
    },
    JsonArrayElement {
        array: SourcePath,
        value: JsonValue,
    },
    TomlTable {
        path: SourcePath,
        values: Vec<(String, toml::Value)>,
    },
    TomlScalar {
        table: SourcePath,
        key: String,
        value: toml::Value,
    },
}

/// An offset-independent inverse. `inserted` is exactly the UTF-8 fragment
/// authored by ICM, including any separator that ICM introduced.
#[derive(Clone, Debug, PartialEq, Serialize, DeriveDeserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OwnedSplice {
    pub(crate) target: OwnedTarget,
    pub(crate) inserted: String,
}

#[derive(Clone, Debug)]
pub(crate) struct AppliedInsert {
    pub(crate) bytes: Vec<u8>,
    pub(crate) owned: Option<OwnedSplice>,
    pub(crate) created: Vec<OwnedSplice>,
}

impl AppliedInsert {
    pub(crate) fn changed(&self) -> bool {
        self.owned.is_some() || !self.created.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ParsedSource {
    Json(JsonValue),
    Toml(toml::Value),
}

/// Parse a provider source without normalizing it. JSON duplicate rejection is
/// scoped to provider-owned roots so unrelated legacy content remains usable.
pub(crate) fn validate_and_parse(
    format: SourceFormat,
    bytes: &[u8],
    relevant_roots: &[&str],
) -> Result<ParsedSource> {
    let (_, body) = source_text(bytes)?;
    match format {
        SourceFormat::Json | SourceFormat::Jsonc => {
            let normalized = normalized_json(body, format)?;
            if normalized.trim().is_empty() {
                return Ok(ParsedSource::Json(JsonValue::Object(Default::default())));
            }

            let root = parse_raw::<&RawValue>(&normalized, SourceFormat::Json)
                .context("invalid provider JSON")?;
            let object = parse_raw_object(root, SourceFormat::Json)
                .context("provider JSON root must be an object")?;
            reject_relevant_duplicates(&object, relevant_roots, SourceFormat::Json)?;

            let value: JsonValue =
                parse_raw(&normalized, SourceFormat::Json).context("invalid provider JSON")?;
            if !value.is_object() {
                bail!("provider JSON root must be an object");
            }
            Ok(ParsedSource::Json(value))
        }
        SourceFormat::Toml => {
            if body.trim().is_empty() {
                return Ok(ParsedSource::Toml(toml::Value::Table(Default::default())));
            }
            ImDocument::parse(body).context("invalid provider TOML")?;
            let value = toml::from_str(body).context("invalid provider TOML")?;
            Ok(ParsedSource::Toml(value))
        }
    }
}

pub(crate) fn insert(
    bytes: &[u8],
    format: SourceFormat,
    relevant_roots: &[&str],
    operation: &Insert,
) -> Result<AppliedInsert> {
    validate_and_parse(format, bytes, relevant_roots)?;
    match operation {
        Insert::JsonMember { parent, key, value } => {
            ensure_json_format(format)?;
            let (mut next, created) =
                ensure_json_container(bytes, format, relevant_roots, parent, JsonKind::Object)?;
            let owned = append_json_member(&mut next, format, relevant_roots, parent, key, value)?;
            Ok(AppliedInsert {
                bytes: next,
                owned,
                created,
            })
        }
        Insert::JsonArrayElement { array, value } => {
            ensure_json_format(format)?;
            let (mut next, created) =
                ensure_json_container(bytes, format, relevant_roots, array, JsonKind::Array)?;
            let owned = append_json_array_element(&mut next, format, relevant_roots, array, value)?;
            Ok(AppliedInsert {
                bytes: next,
                owned,
                created,
            })
        }
        Insert::TomlTable { path, values } => {
            ensure_toml_format(format)?;
            insert_toml_table(bytes, relevant_roots, path, values)
        }
        Insert::TomlScalar { table, key, value } => {
            ensure_toml_format(format)?;
            insert_toml_scalar(bytes, relevant_roots, table, key, value)
        }
    }
}

/// Remove one exact owned fragment from its direct semantic target. Missing or
/// changed targets fail rather than falling back to a byte match elsewhere.
pub(crate) fn remove_owned(
    bytes: &[u8],
    format: SourceFormat,
    relevant_roots: &[&str],
    inverse: &OwnedSplice,
) -> Result<Vec<u8>> {
    try_remove_owned(bytes, format, relevant_roots, inverse)?.with_context(|| {
        format!(
            "owned provider fragment is absent or changed at {}",
            display_target(&inverse.target)
        )
    })
}

/// Best-effort exact removal for owned ancestor containers. A valid document
/// whose direct target is absent or changed returns `None`; malformed or
/// ambiguous source remains an error.
pub(crate) fn try_remove_owned(
    bytes: &[u8],
    format: SourceFormat,
    relevant_roots: &[&str],
    inverse: &OwnedSplice,
) -> Result<Option<Vec<u8>>> {
    if inverse.inserted.is_empty() {
        bail!("refusing an empty provider inverse");
    }
    validate_and_parse(format, bytes, relevant_roots)?;
    let (bom_len, body) = source_text(bytes)?;
    let Some((scope, direct)) = locate_owned_target(body, format, &inverse.target)? else {
        return Ok(None);
    };
    let Some(relative) = exact_matches(&body[scope.clone()], &inverse.inserted)
        .into_iter()
        .find(|offset| {
            let candidate = (scope.start + offset)..(scope.start + offset + inverse.inserted.len());
            candidate.start <= direct.start && candidate.end >= direct.end
        })
    else {
        return Ok(None);
    };

    let start = bom_len + scope.start + relative;
    let end = start + inverse.inserted.len();
    let mut next = bytes.to_vec();
    next.drain(start..end);
    if validate_and_parse(format, &next, relevant_roots).is_ok() {
        return Ok(Some(next));
    }

    // A disjoint edit can append a sibling after an item that was originally
    // the sole child, making that sibling's comma adjacent to our old splice.
    // Remove only that structural comma; never remove another value.
    if matches!(format, SourceFormat::Json | SourceFormat::Jsonc) {
        let comma_at = start;
        if next.get(comma_at) == Some(&b',') {
            let mut repaired = next;
            repaired.remove(comma_at);
            if validate_and_parse(format, &repaired, relevant_roots).is_ok() {
                return Ok(Some(repaired));
            }
        }
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonKind {
    Object,
    Array,
}

fn locate_owned_target(
    body: &str,
    format: SourceFormat,
    target: &OwnedTarget,
) -> Result<Option<(Range<usize>, Range<usize>)>> {
    match target {
        OwnedTarget::JsonRootObject => {
            ensure_json_format(format)?;
            let normalized = normalized_json(body, format)?;
            let root = parse_raw::<&RawValue>(&normalized, SourceFormat::Json)?;
            let value: JsonValue = parse_raw(root.get(), SourceFormat::Json)?;
            if value.as_object().is_none_or(|object| !object.is_empty()) {
                return Ok(None);
            }
            Ok(Some((0..body.len(), raw_range(&normalized, root)?)))
        }
        OwnedTarget::JsonMember { parent, key, value } => {
            ensure_json_format(format)?;
            let normalized = normalized_json(body, format)?;
            let Some(located) = locate_json_optional(&normalized, SourceFormat::Json, parent)?
            else {
                return Ok(None);
            };
            if first_json_token(located.raw.get(), SourceFormat::Json)? != Some(b'{') {
                return Ok(None);
            }
            let object = parse_raw_object(located.raw, SourceFormat::Json)?;
            let matches: Vec<_> = object.0.iter().filter(|(name, _)| name == key).collect();
            let [(_, raw)] = matches.as_slice() else {
                if matches.len() > 1 {
                    bail!("duplicate provider JSON key {key:?}");
                }
                return Ok(None);
            };
            let current: JsonValue = parse_raw(raw.get(), SourceFormat::Json)?;
            if current != *value {
                return Ok(None);
            }
            Ok(Some((located.range, raw_range(&normalized, raw)?)))
        }
        OwnedTarget::JsonArrayElement { array, value } => {
            ensure_json_format(format)?;
            let normalized = normalized_json(body, format)?;
            let Some(located) = locate_json_optional(&normalized, SourceFormat::Json, array)?
            else {
                return Ok(None);
            };
            if first_json_token(located.raw.get(), SourceFormat::Json)? != Some(b'[') {
                return Ok(None);
            }
            let mut matches = parse_raw_array(located.raw, SourceFormat::Json)?
                .into_iter()
                .filter_map(|raw| {
                    parse_raw::<JsonValue>(raw.get(), SourceFormat::Json)
                        .map(|current| (current == *value).then_some(raw))
                        .transpose()
                })
                .collect::<Result<Vec<_>>>()?;
            let [raw] = matches.as_mut_slice() else {
                if matches.len() > 1 {
                    bail!("provider JSON array contains multiple matching owned values");
                }
                return Ok(None);
            };
            Ok(Some((located.range, raw_range(&normalized, raw)?)))
        }
        OwnedTarget::TomlTable { path, values } => {
            ensure_toml_format(format)?;
            reject_duplicate_names(values.iter().map(|(key, _)| key.as_str()))?;
            if path.0.is_empty() {
                bail!("an owned TOML table needs a non-root path");
            }
            let document = ImDocument::parse(body).context("invalid provider TOML")?;
            let semantic: toml::Value = toml::from_str(body).context("invalid provider TOML")?;
            let Some(actual) = toml_value_at(&semantic, &path.0) else {
                return Ok(None);
            };
            let expected = toml::Value::Table(values.iter().cloned().collect());
            if actual != &expected {
                return Ok(None);
            }
            let Some(table) = toml_table_at_optional(&document, &path.0) else {
                return Ok(None);
            };
            let Some(direct) = table.span() else {
                return Ok(None);
            };
            Ok(Some((0..body.len(), direct)))
        }
        OwnedTarget::TomlScalar { table, key, value } => {
            ensure_toml_format(format)?;
            if table.0.is_empty() {
                bail!("an owned TOML scalar needs a non-root table");
            }
            let document = ImDocument::parse(body).context("invalid provider TOML")?;
            let semantic: toml::Value = toml::from_str(body).context("invalid provider TOML")?;
            let Some(actual) = toml_value_at(&semantic, &table.0)
                .and_then(toml::Value::as_table)
                .and_then(|values| values.get(key))
            else {
                return Ok(None);
            };
            if actual != value {
                return Ok(None);
            }
            let Some(source_table) = toml_table_at_optional(&document, &table.0) else {
                return Ok(None);
            };
            let Some(direct) = source_table.get(key).and_then(Item::span) else {
                return Ok(None);
            };
            let Some(scope) = source_table
                .span()
                .map(|span| span.start..after_physical_line(body, span.end))
            else {
                return Ok(None);
            };
            Ok(Some((scope, direct)))
        }
    }
}

struct RawObject<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for RawObject<'de> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawObjectVisitor;

        impl<'de> Visitor<'de> for RawObjectVisitor {
            type Value = RawObject<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    let value = map.next_value::<&'de RawValue>()?;
                    entries.push((key, value));
                }
                Ok(RawObject(entries))
            }
        }

        deserializer.deserialize_map(RawObjectVisitor)
    }
}

fn parse_raw<'a, T>(source: &'a str, format: SourceFormat) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut parser = serde_json_lenient::Deserializer::from_str(source);
    if format == SourceFormat::Json {
        parser.set_allow_comments(false);
        parser.set_ignore_trailing_commas(false);
    }
    let value = T::deserialize(&mut parser)?;
    parser.end()?;
    Ok(value)
}

fn parse_raw_object<'a>(raw: &'a RawValue, format: SourceFormat) -> Result<RawObject<'a>> {
    parse_raw(raw.get(), format)
}

fn parse_raw_array(raw: &RawValue, format: SourceFormat) -> Result<Vec<&RawValue>> {
    parse_raw(raw.get(), format)
}

fn reject_relevant_duplicates(
    root: &RawObject<'_>,
    relevant_roots: &[&str],
    format: SourceFormat,
) -> Result<()> {
    if relevant_roots.is_empty() {
        return reject_object_duplicates(root, format, 0);
    }

    for relevant in relevant_roots {
        let matches: Vec<_> = root.0.iter().filter(|(key, _)| key == relevant).collect();
        if matches.len() > 1 {
            bail!("duplicate provider JSON key {relevant:?}");
        }
        if let Some((_, value)) = matches.first() {
            reject_value_duplicates(value, format, 1)?;
        }
    }
    Ok(())
}

fn reject_object_duplicates(
    object: &RawObject<'_>,
    format: SourceFormat,
    depth: usize,
) -> Result<()> {
    if depth > MAX_JSON_DEPTH {
        bail!("provider JSON exceeds the supported nesting depth");
    }
    let mut keys = HashSet::new();
    for (key, value) in &object.0 {
        if !keys.insert(key) {
            bail!("duplicate provider JSON key {key:?}");
        }
        reject_value_duplicates(value, format, depth + 1)?;
    }
    Ok(())
}

fn reject_value_duplicates(raw: &RawValue, format: SourceFormat, depth: usize) -> Result<()> {
    if depth > MAX_JSON_DEPTH {
        bail!("provider JSON exceeds the supported nesting depth");
    }
    match first_json_token(raw.get(), format)? {
        Some(b'{') => reject_object_duplicates(&parse_raw_object(raw, format)?, format, depth),
        Some(b'[') => {
            for value in parse_raw_array(raw, format)? {
                reject_value_duplicates(value, format, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn ensure_json_container(
    bytes: &[u8],
    format: SourceFormat,
    relevant_roots: &[&str],
    path: &SourcePath,
    target_kind: JsonKind,
) -> Result<(Vec<u8>, Vec<OwnedSplice>)> {
    let mut next = bytes.to_vec();
    let mut created = Vec::new();
    let (_, body) = source_text(&next)?;
    if json_is_empty(body, format)? {
        let prefix = if body.is_empty() || ends_with_line_break(body) {
            ""
        } else {
            newline_for(body)
        };
        let inserted = format!("{prefix}{{}}");
        append_source(&mut next, &inserted);
        created.push(OwnedSplice {
            target: OwnedTarget::JsonRootObject,
            inserted,
        });
        validate_and_parse(format, &next, relevant_roots)?;
    }

    if path.0.is_empty() {
        if target_kind != JsonKind::Object {
            bail!("provider JSON root arrays are not supported");
        }
        return Ok((next, created));
    }

    let mut parent = SourcePath::root();
    for (index, segment) in path.0.iter().enumerate() {
        let kind = if index + 1 == path.0.len() {
            target_kind
        } else {
            JsonKind::Object
        };
        let (_, current_body) = source_text(&next)?;
        let normalized = normalized_json(current_body, format)?;
        let current = locate_json(&normalized, SourceFormat::Json, &parent)?;
        ensure_raw_kind(current.raw, SourceFormat::Json, JsonKind::Object, &parent)?;
        let object = parse_raw_object(current.raw, SourceFormat::Json)?;
        let matches: Vec<_> = object.0.iter().filter(|(key, _)| key == segment).collect();
        if matches.len() > 1 {
            bail!("duplicate provider JSON key {segment:?}");
        }
        if let Some((_, value)) = matches.first() {
            ensure_raw_kind(value, SourceFormat::Json, kind, &parent.child(segment))?;
        } else {
            let value = match kind {
                JsonKind::Object => JsonValue::Object(Default::default()),
                JsonKind::Array => JsonValue::Array(Vec::new()),
            };
            let owned =
                append_json_member(&mut next, format, relevant_roots, &parent, segment, &value)?
                    .expect("missing member must be inserted");
            created.push(owned);
        }
        parent = parent.child(segment);
    }
    Ok((next, created))
}

fn append_json_member(
    bytes: &mut Vec<u8>,
    format: SourceFormat,
    relevant_roots: &[&str],
    parent: &SourcePath,
    key: &str,
    value: &JsonValue,
) -> Result<Option<OwnedSplice>> {
    let (bom_len, body) = source_text(bytes)?;
    let normalized = normalized_json(body, format)?;
    let located = locate_json(&normalized, SourceFormat::Json, parent)?;
    ensure_raw_kind(located.raw, SourceFormat::Json, JsonKind::Object, parent)?;
    let object = parse_raw_object(located.raw, SourceFormat::Json)?;
    let matches: Vec<_> = object.0.iter().filter(|(name, _)| name == key).collect();
    if matches.len() > 1 {
        bail!("duplicate provider JSON key {key:?}");
    }
    if let Some((_, raw)) = matches.first() {
        let current: JsonValue = parse_raw(raw.get(), SourceFormat::Json)?;
        if current == *value {
            return Ok(None);
        }
        bail!("provider JSON key {key:?} already has a different value");
    }

    let encoded_key = serde_json::to_string(key)?;
    let encoded_value = serde_json::to_string(value)?;
    let encoded = format!("{encoded_key}:{encoded_value}");
    let (relative, inserted) = json_append_fragment(
        body,
        &normalized,
        located.range.clone(),
        object.0.iter().map(|(_, value)| *value).collect(),
        &encoded,
        format,
    )?;
    splice_text(bytes, bom_len + relative, &inserted);
    validate_and_parse(format, bytes, relevant_roots)?;
    Ok(Some(OwnedSplice {
        target: OwnedTarget::JsonMember {
            parent: parent.clone(),
            key: key.to_owned(),
            value: value.clone(),
        },
        inserted,
    }))
}

fn append_json_array_element(
    bytes: &mut Vec<u8>,
    format: SourceFormat,
    relevant_roots: &[&str],
    array: &SourcePath,
    value: &JsonValue,
) -> Result<Option<OwnedSplice>> {
    let (bom_len, body) = source_text(bytes)?;
    let normalized = normalized_json(body, format)?;
    let located = locate_json(&normalized, SourceFormat::Json, array)?;
    ensure_raw_kind(located.raw, SourceFormat::Json, JsonKind::Array, array)?;
    let values = parse_raw_array(located.raw, SourceFormat::Json)?;
    let mut equal = 0;
    for raw in &values {
        let current: JsonValue = parse_raw(raw.get(), SourceFormat::Json)?;
        equal += usize::from(current == *value);
    }
    match equal {
        0 => {}
        1 => return Ok(None),
        count => bail!("provider JSON array contains {count} matching values"),
    }

    let encoded = serde_json::to_string(value)?;
    let (relative, inserted) = json_append_fragment(
        body,
        &normalized,
        located.range.clone(),
        values,
        &encoded,
        format,
    )?;
    splice_text(bytes, bom_len + relative, &inserted);
    validate_and_parse(format, bytes, relevant_roots)?;
    Ok(Some(OwnedSplice {
        target: OwnedTarget::JsonArrayElement {
            array: array.clone(),
            value: value.clone(),
        },
        inserted,
    }))
}

fn json_append_fragment(
    body: &str,
    parsed_body: &str,
    container: Range<usize>,
    values: Vec<&RawValue>,
    encoded: &str,
    format: SourceFormat,
) -> Result<(usize, String)> {
    let close = container
        .end
        .checked_sub(1)
        .context("empty JSON container")?;
    if values.is_empty() {
        return Ok((close, encoded.to_owned()));
    }

    let last = raw_range(parsed_body, values[values.len() - 1])?;
    let suffix = &body[last.end..close];
    let after_trivia = skip_json_trivia(suffix, 0, format)?;
    let trailing_comma = suffix.as_bytes().get(after_trivia) == Some(&b',');
    let style = json_separator_style(body, &container, last.start);
    if trailing_comma {
        Ok((last.end + after_trivia + 1, format!("{style}{encoded},")))
    } else {
        Ok((last.end, format!(",{style}{encoded}")))
    }
}

struct LocatedRaw<'a> {
    raw: &'a RawValue,
    range: Range<usize>,
}

fn locate_json<'a>(
    body: &'a str,
    format: SourceFormat,
    path: &SourcePath,
) -> Result<LocatedRaw<'a>> {
    let mut raw = parse_raw::<&RawValue>(body, format)?;
    for segment in &path.0 {
        let object = parse_raw_object(raw, format)
            .with_context(|| format!("provider JSON {} is not an object", display_path(path)))?;
        let matches: Vec<_> = object.0.iter().filter(|(key, _)| key == segment).collect();
        match matches.as_slice() {
            [(_, value)] => raw = value,
            [] => bail!("provider JSON path {} is missing", display_path(path)),
            _ => bail!("duplicate provider JSON key {segment:?}"),
        }
    }
    Ok(LocatedRaw {
        range: raw_range(body, raw)?,
        raw,
    })
}

fn locate_json_optional<'a>(
    body: &'a str,
    format: SourceFormat,
    path: &SourcePath,
) -> Result<Option<LocatedRaw<'a>>> {
    let mut raw = parse_raw::<&RawValue>(body, format)?;
    for segment in &path.0 {
        if first_json_token(raw.get(), format)? != Some(b'{') {
            return Ok(None);
        }
        let object = parse_raw_object(raw, format)?;
        let matches: Vec<_> = object.0.iter().filter(|(key, _)| key == segment).collect();
        match matches.as_slice() {
            [(_, value)] => raw = value,
            [] => return Ok(None),
            _ => bail!("duplicate provider JSON key {segment:?}"),
        }
    }
    Ok(Some(LocatedRaw {
        range: raw_range(body, raw)?,
        raw,
    }))
}

fn ensure_raw_kind(
    raw: &RawValue,
    format: SourceFormat,
    expected: JsonKind,
    path: &SourcePath,
) -> Result<()> {
    let actual = match first_json_token(raw.get(), format)? {
        Some(b'{') => JsonKind::Object,
        Some(b'[') => JsonKind::Array,
        _ => bail!("provider JSON {} is not a container", display_path(path)),
    };
    if actual != expected {
        bail!(
            "provider JSON {} is a {:?}, expected {:?}",
            display_path(path),
            actual,
            expected
        );
    }
    Ok(())
}

fn raw_range(body: &str, raw: &RawValue) -> Result<Range<usize>> {
    let base = body.as_ptr() as usize;
    let start = (raw.get().as_ptr() as usize)
        .checked_sub(base)
        .context("JSON value is outside its source document")?;
    let end = start + raw.get().len();
    if end > body.len() {
        bail!("JSON value is outside its source document");
    }
    Ok(start..end)
}

fn json_separator_style(body: &str, container: &Range<usize>, last_start: usize) -> String {
    if !body[container.clone()].contains('\n') {
        return " ".to_owned();
    }
    let line_start = body[..last_start].rfind('\n').map_or(0, |index| index + 1);
    let indent: String = body[line_start..last_start]
        .chars()
        .take_while(|character| matches!(character, ' ' | '\t' | '\r'))
        .filter(|character| *character != '\r')
        .collect();
    format!("{}{}", newline_for(&body[container.clone()]), indent)
}

fn first_json_token(source: &str, format: SourceFormat) -> Result<Option<u8>> {
    let index = skip_json_trivia(source, 0, format)?;
    Ok(source.as_bytes().get(index).copied())
}

fn json_is_empty(source: &str, format: SourceFormat) -> Result<bool> {
    Ok(normalized_json(source, format)?.trim().is_empty())
}

/// Build a parser-only JSON view with exactly the same byte offsets as the
/// JSONC source. Only comments and commas immediately before `]` or `}` are
/// blanked; strings and line endings are untouched.
fn normalized_json(source: &str, format: SourceFormat) -> Result<Cow<'_, str>> {
    if format == SourceFormat::Json {
        return Ok(Cow::Borrowed(source));
    }

    let original = source.as_bytes();
    let mut normalized = original.to_vec();
    let mut index = 0;
    let mut in_string = false;
    while index < original.len() {
        if in_string {
            match original[index] {
                b'\\' => index = (index + 2).min(original.len()),
                b'"' => {
                    in_string = false;
                    index += 1;
                }
                _ => index += 1,
            }
            continue;
        }

        match (original[index], original.get(index + 1)) {
            (b'"', _) => {
                in_string = true;
                index += 1;
            }
            (b'/', Some(b'/')) => {
                normalized[index] = b' ';
                normalized[index + 1] = b' ';
                index += 2;
                while index < original.len() && !matches!(original[index], b'\r' | b'\n') {
                    normalized[index] = b' ';
                    index += 1;
                }
            }
            (b'/', Some(b'*')) => {
                normalized[index] = b' ';
                normalized[index + 1] = b' ';
                index += 2;
                let mut closed = false;
                while index < original.len() {
                    if original[index] == b'*' && original.get(index + 1) == Some(&b'/') {
                        normalized[index] = b' ';
                        normalized[index + 1] = b' ';
                        index += 2;
                        closed = true;
                        break;
                    }
                    if !matches!(original[index], b'\r' | b'\n') {
                        normalized[index] = b' ';
                    }
                    index += 1;
                }
                if !closed {
                    bail!("unterminated JSONC block comment");
                }
            }
            _ => index += 1,
        }
    }

    index = 0;
    in_string = false;
    while index < normalized.len() {
        if in_string {
            match normalized[index] {
                b'\\' => index = (index + 2).min(normalized.len()),
                b'"' => {
                    in_string = false;
                    index += 1;
                }
                _ => index += 1,
            }
            continue;
        }
        match normalized[index] {
            b'"' => {
                in_string = true;
                index += 1;
            }
            b',' => {
                let mut next = index + 1;
                while matches!(normalized.get(next), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                    next += 1;
                }
                if matches!(normalized.get(next), Some(b']' | b'}')) {
                    normalized[index] = b' ';
                }
                index += 1;
            }
            _ => index += 1,
        }
    }

    Ok(Cow::Owned(String::from_utf8(normalized).expect(
        "replacing source bytes with spaces preserves UTF-8",
    )))
}

fn skip_json_trivia(source: &str, mut index: usize, format: SourceFormat) -> Result<usize> {
    let bytes = source.as_bytes();
    loop {
        while matches!(bytes.get(index), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            index += 1;
        }
        if format != SourceFormat::Jsonc || bytes.get(index) != Some(&b'/') {
            return Ok(index);
        }
        match bytes.get(index + 1) {
            Some(b'/') => {
                index += 2;
                while !matches!(bytes.get(index), None | Some(b'\r' | b'\n')) {
                    index += 1;
                }
            }
            Some(b'*') => {
                index += 2;
                let Some(end) = source[index..].find("*/") else {
                    bail!("unterminated JSONC block comment");
                };
                index += end + 2;
            }
            _ => return Ok(index),
        }
    }
}

fn insert_toml_table(
    bytes: &[u8],
    relevant_roots: &[&str],
    path: &SourcePath,
    values: &[(String, toml::Value)],
) -> Result<AppliedInsert> {
    if path.0.is_empty() {
        bail!("a TOML provider table needs a non-root path");
    }
    reject_duplicate_names(values.iter().map(|(key, _)| key.as_str()))?;
    let (_, body) = source_text(bytes)?;
    let parsed = validate_and_parse(SourceFormat::Toml, bytes, relevant_roots)?;
    let ParsedSource::Toml(value) = parsed else {
        unreachable!()
    };
    if let Some(existing) = toml_value_at(&value, &path.0) {
        let Some(table) = existing.as_table() else {
            bail!("provider TOML {} is not a table", display_path(path));
        };
        if values
            .iter()
            .all(|(key, expected)| table.get(key) == Some(expected))
        {
            return Ok(AppliedInsert {
                bytes: bytes.to_vec(),
                owned: None,
                created: Vec::new(),
            });
        }
        bail!("provider TOML table {} already differs", display_path(path));
    }
    reject_toml_ancestor_conflict(&value, &path.0)?;

    let newline = newline_for(body);
    let mut block = format!("[{}]{newline}", toml_header(&path.0));
    for (key, value) in values {
        block.push_str(&toml_scalar_line(key, value, newline)?);
    }
    let prefix = if body.is_empty() || ends_with_line_break(body) {
        ""
    } else {
        newline
    };
    let inserted = format!("{prefix}{block}");
    let mut next = bytes.to_vec();
    append_source(&mut next, &inserted);
    validate_and_parse(SourceFormat::Toml, &next, relevant_roots)?;
    Ok(AppliedInsert {
        bytes: next,
        owned: Some(OwnedSplice {
            target: OwnedTarget::TomlTable {
                path: path.clone(),
                values: values.to_vec(),
            },
            inserted,
        }),
        created: Vec::new(),
    })
}

fn insert_toml_scalar(
    bytes: &[u8],
    relevant_roots: &[&str],
    table_path: &SourcePath,
    key: &str,
    value: &toml::Value,
) -> Result<AppliedInsert> {
    if value.is_table() {
        bail!("TOML table values require a table insertion");
    }
    if table_path.0.is_empty() {
        bail!("a provider TOML scalar needs a non-root table");
    }
    let mut next = bytes.to_vec();
    let mut created = Vec::new();
    let parsed = validate_and_parse(SourceFormat::Toml, &next, relevant_roots)?;
    let ParsedSource::Toml(root) = parsed else {
        unreachable!()
    };
    match toml_value_at(&root, &table_path.0) {
        Some(existing) if !existing.is_table() => {
            bail!("provider TOML {} is not a table", display_path(table_path));
        }
        Some(existing) => {
            let table = existing.as_table().expect("checked table");
            if let Some(current) = table.get(key) {
                if current == value {
                    return Ok(AppliedInsert {
                        bytes: next,
                        owned: None,
                        created,
                    });
                }
                bail!("provider TOML key {key:?} already has a different value");
            }
        }
        None if table_path.0.is_empty() => {}
        None => {
            reject_toml_ancestor_conflict(&root, &table_path.0)?;
            let (_, body) = source_text(&next)?;
            let newline = newline_for(body);
            let prefix = if body.is_empty() || ends_with_line_break(body) {
                ""
            } else {
                newline
            };
            let inserted = format!("{prefix}[{}]{newline}", toml_header(&table_path.0));
            append_source(&mut next, &inserted);
            created.push(OwnedSplice {
                target: OwnedTarget::TomlTable {
                    path: table_path.clone(),
                    values: Vec::new(),
                },
                inserted,
            });
            validate_and_parse(SourceFormat::Toml, &next, relevant_roots)?;
        }
    }

    let (bom_len, body) = source_text(&next)?;
    let document = ImDocument::parse(body).context("invalid provider TOML")?;
    let table = toml_table_at(&document, &table_path.0)?;
    let mut position = if table_path.0.is_empty() {
        table.span().map_or(0, |span| span.end)
    } else {
        table
            .span()
            .context("cannot safely splice an implicit TOML table")?
            .end
    };
    position = after_physical_line(body, position);
    let newline = newline_for(body);
    let prefix = if position == 0 || ends_with_line_break(&body[..position]) {
        ""
    } else {
        newline
    };
    let inserted = format!("{prefix}{}", toml_scalar_line(key, value, newline)?);
    splice_text(&mut next, bom_len + position, &inserted);
    validate_and_parse(SourceFormat::Toml, &next, relevant_roots)?;
    Ok(AppliedInsert {
        bytes: next,
        owned: Some(OwnedSplice {
            target: OwnedTarget::TomlScalar {
                table: table_path.clone(),
                key: key.to_owned(),
                value: value.clone(),
            },
            inserted,
        }),
        created,
    })
}

fn toml_table_at<'a>(document: &'a ImDocument<&str>, path: &[String]) -> Result<&'a Table> {
    let mut table = document.as_table();
    for segment in path {
        let item = table
            .get(segment)
            .with_context(|| format!("provider TOML path {:?} is missing", path))?;
        table = match item {
            Item::Table(table) => table,
            Item::Value(value) if value.is_inline_table() => {
                bail!("inline provider TOML tables are not safely mutable")
            }
            Item::ArrayOfTables(_) => {
                bail!("provider TOML arrays of tables are not safely mutable")
            }
            Item::None | Item::Value(_) => {
                bail!("provider TOML path {:?} is not a table", path)
            }
        };
    }
    Ok(table)
}

fn toml_table_at_optional<'a>(
    document: &'a ImDocument<&str>,
    path: &[String],
) -> Option<&'a Table> {
    let mut table = document.as_table();
    for segment in path {
        table = table.get(segment)?.as_table()?;
    }
    Some(table)
}

fn toml_value_at<'a>(root: &'a toml::Value, path: &[String]) -> Option<&'a toml::Value> {
    let mut value = root;
    for segment in path {
        value = value.as_table()?.get(segment)?;
    }
    Some(value)
}

fn reject_toml_ancestor_conflict(root: &toml::Value, path: &[String]) -> Result<()> {
    let mut value = root;
    for segment in path {
        let Some(next) = value.as_table().and_then(|table| table.get(segment)) else {
            return Ok(());
        };
        if !next.is_table() {
            bail!("provider TOML path segment {segment:?} is not a table");
        }
        value = next;
    }
    Ok(())
}

fn toml_header(path: &[String]) -> String {
    path.iter()
        .map(|segment| Key::new(segment).to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn toml_scalar_line(key: &str, value: &toml::Value, newline: &str) -> Result<String> {
    if value.is_table() {
        bail!("TOML table values require a table insertion");
    }
    let mut table = toml::map::Map::new();
    table.insert(key.to_owned(), value.clone());
    let rendered = toml::to_string(&toml::Value::Table(table))?;
    Ok(with_newline(&rendered, newline))
}

fn reject_duplicate_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(name) {
            bail!("duplicate provider key {name:?}");
        }
    }
    Ok(())
}

fn after_physical_line(body: &str, start: usize) -> usize {
    let Some(offset) = body[start..].find('\n') else {
        return body.len();
    };
    start + offset + 1
}

fn source_text(bytes: &[u8]) -> Result<(usize, &str)> {
    let bom_len = usize::from(bytes.starts_with(UTF8_BOM)) * UTF8_BOM.len();
    let body = std::str::from_utf8(&bytes[bom_len..]).context("provider document is not UTF-8")?;
    Ok((bom_len, body))
}

fn append_source(bytes: &mut Vec<u8>, inserted: &str) {
    bytes.extend_from_slice(inserted.as_bytes());
}

fn splice_text(bytes: &mut Vec<u8>, position: usize, inserted: &str) {
    bytes.splice(position..position, inserted.bytes());
}

fn exact_matches(source: &str, needle: &str) -> Vec<usize> {
    source
        .match_indices(needle)
        .map(|(index, _)| index)
        .collect()
}

fn newline_for(source: &str) -> &'static str {
    if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn with_newline(source: &str, newline: &str) -> String {
    if newline == "\n" {
        source.to_owned()
    } else {
        source.replace('\n', newline)
    }
}

fn ends_with_line_break(source: &str) -> bool {
    source.ends_with('\n') || source.ends_with('\r')
}

fn ensure_json_format(format: SourceFormat) -> Result<()> {
    if matches!(format, SourceFormat::Json | SourceFormat::Jsonc) {
        Ok(())
    } else {
        bail!("JSON insertion requested for TOML source")
    }
}

fn ensure_toml_format(format: SourceFormat) -> Result<()> {
    if format == SourceFormat::Toml {
        Ok(())
    } else {
        bail!("TOML insertion requested for JSON source")
    }
}

fn display_path(path: &SourcePath) -> String {
    if path.0.is_empty() {
        "<root>".to_owned()
    } else {
        path.0.join(".")
    }
}

fn display_target(target: &OwnedTarget) -> String {
    match target {
        OwnedTarget::JsonRootObject => "<json-root>".to_owned(),
        OwnedTarget::JsonMember { parent, key, .. } => {
            format!("{}.{}", display_path(parent), key)
        }
        OwnedTarget::JsonArrayElement { array, .. } => display_path(array),
        OwnedTarget::TomlTable { path, .. } => display_path(path),
        OwnedTarget::TomlScalar { table, key, .. } => {
            format!("{}.{}", display_path(table), key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossless_apply_strip_uninstall_round_trip() {
        let cases = [
            (
                SourceFormat::Json,
                br#"{"other" : 1, "mcpServers": {}}"#.to_vec(),
                Insert::JsonMember {
                    parent: SourcePath::new(["mcpServers"]),
                    key: "icm".into(),
                    value: serde_json::json!({"command": "icm", "args": ["mcp"]}),
                },
                vec!["mcpServers"],
            ),
            (
                SourceFormat::Jsonc,
                b"\xef\xbb\xbf{\r\n  // keep me\r\n  \"permissions\": {\r\n    \"allow\": [\r\n    ],\r\n  },\r\n}\r\n"
                    .to_vec(),
                Insert::JsonArrayElement {
                    array: SourcePath::new(["permissions", "allow"]),
                    value: JsonValue::String("mcp__icm__recall".into()),
                },
                vec!["permissions"],
            ),
            (
                SourceFormat::Toml,
                b"\xef\xbb\xbf# keep me\r\ntheme = \"dark\"\r\n".to_vec(),
                Insert::TomlTable {
                    path: SourcePath::new(["mcp_servers", "icm"]),
                    values: vec![("command".into(), toml::Value::String("icm".into()))],
                },
                vec![],
            ),
        ];

        for (format, original, operation, roots) in cases {
            let applied = insert(&original, format, &roots, &operation).unwrap();
            assert!(applied.changed());
            let mut stripped = applied.bytes;
            if let Some(owned) = applied.owned {
                stripped = remove_owned(&stripped, format, &roots, &owned).unwrap();
            }
            for created in applied.created.iter().rev() {
                stripped = remove_owned(&stripped, format, &roots, created).unwrap();
            }
            assert_eq!(stripped, original);
        }
    }

    #[test]
    fn relevant_duplicates_are_read_only() {
        let duplicate_json = br#"{"permissions":{"allow":[],"allow":[]},"legacy":1}"#;
        let before = duplicate_json.to_vec();
        assert!(insert(
            duplicate_json,
            SourceFormat::Json,
            &["permissions"],
            &Insert::JsonArrayElement {
                array: SourcePath::new(["permissions", "allow"]),
                value: JsonValue::String("mcp__icm__recall".into()),
            },
        )
        .is_err());
        assert_eq!(&duplicate_json[..], before.as_slice());

        let duplicate_toml = b"[mcp_servers.icm]\ncommand = \"icm\"\ncommand = \"other\"\n";
        assert!(validate_and_parse(SourceFormat::Toml, duplicate_toml, &[]).is_err());
    }

    #[test]
    fn disjoint_external_edit_survives_owned_inverse() {
        let original = br#"{"permissions":{"allow":[]},"theme":"dark"}"#;
        let applied = insert(
            original,
            SourceFormat::Json,
            &["permissions"],
            &Insert::JsonArrayElement {
                array: SourcePath::new(["permissions", "allow"]),
                value: JsonValue::String("mcp__icm__recall".into()),
            },
        )
        .unwrap();
        let owned = applied.owned.unwrap();
        let externally_edited = String::from_utf8(applied.bytes)
            .unwrap()
            .replace("\"theme\":\"dark\"", "\"theme\" : \"light\"");
        let stripped = remove_owned(
            externally_edited.as_bytes(),
            SourceFormat::Json,
            &["permissions"],
            &owned,
        )
        .unwrap();
        assert_eq!(
            stripped,
            br#"{"permissions":{"allow":[]},"theme" : "light"}"#
        );
    }

    #[test]
    fn inverse_never_removes_an_identical_nested_json_fragment() {
        let applied = insert(
            br#"{"mcpServers":{}}"#,
            SourceFormat::Json,
            &["mcpServers"],
            &Insert::JsonMember {
                parent: SourcePath::new(["mcpServers"]),
                key: "icm".to_owned(),
                value: serde_json::json!({}),
            },
        )
        .unwrap();
        let owned = applied.owned.unwrap();
        let external = br#"{"mcpServers":{"external":{"icm":{}}}}"#;
        assert!(
            try_remove_owned(external, SourceFormat::Json, &["mcpServers"], &owned,)
                .unwrap()
                .is_none()
        );
        assert!(remove_owned(external, SourceFormat::Json, &["mcpServers"], &owned,).is_err());
    }

    #[test]
    fn inverse_never_removes_a_toml_fragment_from_a_multiline_string() {
        let applied = insert(
            b"[mcp_servers.icm]\n",
            SourceFormat::Toml,
            &[],
            &Insert::TomlScalar {
                table: SourcePath::new(["mcp_servers", "icm"]),
                key: "approval_mode".to_owned(),
                value: toml::Value::String("approve".to_owned()),
            },
        )
        .unwrap();
        let owned = applied.owned.unwrap();
        let external = b"[mcp_servers.icm]\nnotes = \"\"\"\napproval_mode = \"approve\"\n\"\"\"\n";
        assert!(try_remove_owned(external, SourceFormat::Toml, &[], &owned)
            .unwrap()
            .is_none());
        assert!(remove_owned(external, SourceFormat::Toml, &[], &owned).is_err());
    }
}
