//! Parse a raw `.tfstate` file (schema version 4) into uncia resources.
//!
//! This is the file Terraform actually stores — on disk as `terraform.tfstate`
//! or as the object in an S3/remote backend — and its schema differs from
//! `terraform show -json` output: resources are grouped, each carrying one or
//! more *instances*, and there is no precomputed `address` field.
//!
//! Attribute values themselves are the same provider-schema-shaped maps the
//! show-json path produces, which is what lets both parsers feed one diff
//! engine. `tests/state_equivalence.rs` proves that against real Terraform
//! output rather than assuming it.
//!
//! **Secrets**: unlike `show -json`, a raw state file is the stored object and
//! routinely contains sensitive attribute values in plaintext (the instance's
//! `sensitive_attributes` list names them). uncia reads them only to diff, but
//! anything that later *transmits* a `DriftKind::FieldChanged` payload — an
//! alert sink, a webhook — must redact before sending.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::UnciaError;
use crate::types::resource::{Resource, ResourceId, ResourceKind};

/// The only raw-state schema version uncia understands. Version 3 and older
/// predate Terraform 0.12 and are a genuinely different shape.
const SUPPORTED_VERSION: u64 = 4;

/// Parse a raw `.tfstate` document into the crate's resource model.
///
/// Returns only `mode == "managed"` resources; data sources are declared
/// lookups, not managed infrastructure, and cannot drift in uncia's sense.
pub fn parse(json: &str) -> crate::Result<Vec<Resource>> {
    let raw: RawState = serde_json::from_str(json)?;

    if raw.version != SUPPORTED_VERSION {
        return Err(UnciaError::UnsupportedStateVersion { found: raw.version });
    }

    let mut resources = Vec::new();
    for entry in raw.resources {
        if entry.mode != "managed" {
            continue;
        }
        let RawResource {
            module,
            r#type,
            name,
            instances,
            ..
        } = entry;
        for instance in instances {
            // A deposed object is the leftover of a failed
            // create_before_destroy, not the resource's current object.
            // Diffing it would compare against something already replaced.
            if instance.deposed.is_some() {
                continue;
            }
            resources.push(Resource {
                id: ResourceId(address_of(
                    module.as_deref(),
                    &r#type,
                    &name,
                    instance.index_key.as_ref(),
                )),
                kind: ResourceKind::from_terraform_type(&r#type),
                attributes: instance.attributes,
            });
        }
    }
    Ok(resources)
}

/// Rebuild the Terraform address that `show -json` would have emitted:
/// `{module.}{type}.{name}{[index]}`.
///
/// The `module` field already arrives fully qualified (`module.network`, and
/// nested as `module.network.module.private`), so it prefixes directly. An
/// `index_key` is an integer under `count` and a string under `for_each`;
/// Terraform renders them as `[0]` and `["blue"]` respectively.
fn address_of(module: Option<&str>, r#type: &str, name: &str, index_key: Option<&Value>) -> String {
    let mut address = String::new();
    if let Some(module) = module {
        address.push_str(module);
        address.push('.');
    }
    address.push_str(r#type);
    address.push('.');
    address.push_str(name);
    match index_key {
        Some(Value::Number(n)) => address.push_str(&format!("[{n}]")),
        Some(Value::String(s)) => address.push_str(&format!("[\"{s}\"]")),
        _ => {}
    }
    address
}

// Serde mirror of the raw state schema — only the parts uncia reads; unknown
// fields (lineage, serial, outputs, check_results, ...) are ignored.

#[derive(Deserialize)]
struct RawState {
    version: u64,
    #[serde(default)]
    resources: Vec<RawResource>,
}

#[derive(Deserialize)]
struct RawResource {
    /// Absent for root-module resources.
    #[serde(default)]
    module: Option<String>,
    mode: String,
    r#type: String,
    name: String,
    #[serde(default)]
    instances: Vec<RawInstance>,
}

#[derive(Deserialize)]
struct RawInstance {
    #[serde(default)]
    attributes: Map<String, Value>,
    /// Present under `count` (integer) or `for_each` (string).
    #[serde(default)]
    index_key: Option<Value>,
    /// Present only on deposed objects awaiting cleanup.
    #[serde(default)]
    deposed: Option<String>,
}
