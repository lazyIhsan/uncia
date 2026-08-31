//! Diffing: compare desired state against live state to produce drift.
//!
//! Two passes, in order, over the same inputs:
//!
//! - [`behavioral`] — a field's stored value no longer matches what was
//!   declared. Table stakes.
//! - [`semantic`] — the stored values agree, but the resource no longer *means*
//!   what it did. The differentiator; see `docs/SEMANTIC-DRIFT.md`.
//!
//! [`compare`] runs both and owns the disjointness between them. The per-pass
//! entry points stay public for direct testing, mirroring how [`crate::state`]
//! dispatches while its per-format parsers remain reachable.

pub mod behavioral;
pub(crate) mod rules;
pub mod semantic;
pub(crate) mod target_attachments;

use crate::collector::LiveResource;
use crate::types::drift::DriftReport;
use crate::types::resource::Resource;

/// Compare declared state against live observations, running both drift passes.
///
/// Order matters: the semantic pass reads the behavioral results to enforce
/// that the two classes never both fire on the same resource and field.
pub fn compare(declared: &[Resource], live: &[LiveResource]) -> DriftReport {
    let mut report = behavioral::compare(declared, live);
    semantic::compare(declared, live, &mut report);
    report
}
