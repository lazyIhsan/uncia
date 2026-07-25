//! Desired-state ingestion: read what the IaC tool thinks should exist.
//!
//! Two document kinds carry declared state, and [`parse`] accepts either:
//!
//! - `terraform show -json` output ([`terraform`]) — the rendered view.
//! - a raw `.tfstate` file ([`tfstate`]) — what Terraform actually stores, on
//!   disk or in a remote backend.
//!
//! Callers should use [`parse`] and let it route; the per-format parsers stay
//! public for explicit use.

pub mod terraform;
pub mod tfstate;

use serde_json::Value;

use crate::error::UnciaError;
use crate::types::resource::Resource;

/// Top-level keys present in an OpenTofu state file that was encrypted at rest
/// and fed to us raw (i.e. without `tofu show -json` decrypting it).
const ENCRYPTION_MARKERS: &[&str] = &["encrypted_data", "encryption_version", "encryption"];

/// Top-level keys that identify `terraform show -json <planfile>` output,
/// which carries a `format_version` but is a plan, not state.
const PLAN_MARKERS: &[&str] = &["planned_values", "resource_changes"];

/// Parse declared state from either supported document kind.
///
/// Wrong-document guards run *before* routing, so every way an input can be
/// the wrong thing is rejected with a specific error before an empty result is
/// ever accepted — the hard-failure invariant from `docs/ARCHITECTURE.md`. An
/// unrecognized document is an error, never a silent zero resources.
pub fn parse(json: &str) -> crate::Result<Vec<Resource>> {
    let doc: Value = serde_json::from_str(json)?;

    // Encrypted state is checked first: an encrypted OpenTofu file also carries
    // `serial`/`lineage` and would otherwise look raw-state-shaped, producing a
    // confusing downstream error instead of naming the real problem.
    if ENCRYPTION_MARKERS.iter().any(|k| doc.get(k).is_some()) {
        return Err(UnciaError::EncryptedState);
    }

    // A plan carries a 1.x format_version and no `values`, so without this it
    // would route to the show-json parser and read as an empty state —
    // reporting zero drift against the wrong document.
    for marker in PLAN_MARKERS {
        if doc.get(*marker).is_some() {
            return Err(UnciaError::WrongDocumentKind {
                marker: (*marker).to_string(),
            });
        }
    }

    if doc.get("format_version").is_some() {
        terraform::parse(json)
    } else if doc.get("version").and_then(Value::as_u64).is_some() && doc.get("resources").is_some()
    {
        tfstate::parse(json)
    } else {
        Err(UnciaError::UnsupportedFormatVersion {
            found: "(none)".to_string(),
        })
    }
}
