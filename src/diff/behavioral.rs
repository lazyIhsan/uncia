//! Behavioral diff: field-by-field comparison that reasons about meaning,
//! not just raw value equality.

use crate::types::drift::DriftReport;
use crate::types::resource::Resource;

/// Compare desired vs. live resources field-by-field and report drift.
pub fn compare(_desired: &[Resource], _live: &[Resource]) -> DriftReport {
    // TODO: field-by-field, meaning-aware comparison.
    DriftReport::default()
}
