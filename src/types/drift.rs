//! Drift model: what changed, how much it matters, and the collected report.

use super::resource::ResourceId;

/// How severe a detected drift is.
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
    // TODO: value drift, behavioral drift, missing, unmanaged, ...
}

/// A single detected drift against one resource.
#[derive(Debug, Clone)]
pub struct Drift {
    pub resource: ResourceId,
    pub kind: DriftKind,
    pub severity: Severity,
    // TODO: description / affected fields.
}

/// The full set of drifts found in a single run.
#[derive(Debug, Clone, Default)]
pub struct DriftReport {
    pub drifts: Vec<Drift>,
}
