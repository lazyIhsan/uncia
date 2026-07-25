//! Drift model: what changed, how much it matters, and the collected report.

use serde_json::Value;

use super::resource::ResourceId;

/// How severe a detected drift is.
///
/// The mapping from a drift to a severity is currently a static placeholder;
/// severity policy is an open question in `docs/ARCHITECTURE.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The nature of a detected drift.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DriftKind {
    /// Declared in state with a real cloud ID, but not found live.
    Missing,
    /// A field's live value no longer matches what was declared.
    FieldChanged {
        field: String,
        declared: Value,
        actual: Value,
    },
}

/// A single detected drift against one resource.
#[derive(Debug, Clone)]
pub struct Drift {
    pub resource: ResourceId,
    pub kind: DriftKind,
    pub severity: Severity,
}

/// A declared resource that could not be checked at all.
///
/// Not drift and not proof of health: the resource had no usable cloud ID to
/// join on (partial apply, odd import). Reported separately so "no drift"
/// is never conflated with "couldn't check".
#[derive(Debug, Clone)]
pub struct Unjoinable {
    pub resource: ResourceId,
    pub reason: String,
}

/// The full result of a single run.
#[derive(Debug, Clone, Default)]
pub struct DriftReport {
    pub drifts: Vec<Drift>,
    pub unjoinable: Vec<Unjoinable>,
}
