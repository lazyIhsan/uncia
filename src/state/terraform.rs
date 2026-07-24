//! Parse the JSON emitted by `terraform show -json` (or the identical
//! `tofu show -json`) into uncia resources.
//!
//! Guard order matters and implements the hard-failure invariant from
//! `docs/ARCHITECTURE.md`: every way an input can be the *wrong document*
//! is rejected with a specific error before "no resources" is ever accepted
//! as a legitimate empty state. "No drift found" must never be produced by
//! silently parsing the wrong file.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::UnciaError;
use crate::types::resource::{Resource, ResourceId, ResourceKind};

/// Top-level keys present in an OpenTofu state file that was encrypted at
/// rest and fed to us raw (i.e. without `tofu show -json` decrypting it).
const ENCRYPTION_MARKERS: &[&str] = &["encrypted_data", "encryption_version", "encryption"];

/// Top-level keys that identify `terraform show -json <planfile>` output,
/// which also carries `format_version` but is a plan, not state.
const PLAN_MARKERS: &[&str] = &["planned_values", "resource_changes"];

/// Parse `terraform show -json` output into the crate's resource model.
///
/// Returns only `mode == "managed"` resources; data sources are declared
/// lookups, not managed infrastructure, and cannot drift in uncia's sense.
pub fn parse(json: &str) -> crate::Result<Vec<Resource>> {
    // Guard 1: must be JSON at all.
    let doc: Value = serde_json::from_str(json)?;

    // Guard 2: encrypted state fed raw. Checked before anything else so the
    // error names the real problem rather than a downstream symptom.
    if ENCRYPTION_MARKERS.iter().any(|k| doc.get(k).is_some()) {
        return Err(UnciaError::EncryptedState);
    }

    // Guard 3: a raw .tfstate file (schema `version: 4`, no `format_version`)
    // rather than `show -json` output.
    if doc.get("format_version").is_none()
        && doc.get("version").is_some()
        && doc.get("resources").is_some()
    {
        return Err(UnciaError::RawStateFile);
    }

    // Guard 4: recognizable and supported format_version.
    let format_version = doc
        .get("format_version")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    if format_version != "1" && !format_version.starts_with("1.") {
        return Err(UnciaError::UnsupportedFormatVersion {
            found: format_version.to_string(),
        });
    }

    // Guard 5: plan output, not state. A plan passes guards 1-4 (it has a 1.x
    // format_version and no `values` key) and would otherwise fall through to
    // the empty-state case below — reporting zero drift on the wrong document.
    for marker in PLAN_MARKERS {
        if doc.get(*marker).is_some() {
            return Err(UnciaError::WrongDocumentKind {
                marker: (*marker).to_string(),
            });
        }
    }

    // Guard 6: only now is a missing `values` a legitimate empty state.
    let show: ShowJson = serde_json::from_value(doc)?;
    let Some(values) = show.values else {
        return Ok(Vec::new());
    };

    let mut resources = Vec::new();
    walk_module(values.root_module, &mut resources);
    Ok(resources)
}

/// Recursively collect managed resources from a module and its children.
fn walk_module(module: RawModule, out: &mut Vec<Resource>) {
    for raw in module.resources {
        if raw.mode != "managed" {
            continue;
        }
        out.push(Resource {
            id: ResourceId(raw.address),
            kind: ResourceKind::from_terraform_type(&raw.r#type),
            attributes: raw.values,
        });
    }
    for child in module.child_modules {
        walk_module(child, out);
    }
}

// Serde mirror of the `terraform show -json` state schema — only the parts
// uncia reads; unknown fields are ignored.

#[derive(Deserialize)]
struct ShowJson {
    #[serde(default)]
    values: Option<StateValues>,
}

#[derive(Deserialize)]
struct StateValues {
    #[serde(default)]
    root_module: RawModule,
}

#[derive(Deserialize, Default)]
struct RawModule {
    #[serde(default)]
    resources: Vec<RawResource>,
    #[serde(default)]
    child_modules: Vec<RawModule>,
}

#[derive(Deserialize)]
struct RawResource {
    address: String,
    mode: String,
    r#type: String,
    #[serde(default)]
    values: Map<String, Value>,
}
