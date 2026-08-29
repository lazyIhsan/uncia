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
    /// The field's value is unchanged, but what it *means* is not, because
    /// something it references changed. See `docs/SEMANTIC-DRIFT.md`.
    SemanticChanged {
        /// The subject field whose meaning changed. Its stored value is
        /// identical on both sides — that is what makes this semantic drift
        /// rather than behavioral.
        field: String,
        /// The relation that resolved the effective meaning, e.g.
        /// `sg_membership`.
        relation: String,
        declared_effective: Value,
        actual_effective: Value,
        /// Cloud IDs on the path from subject to cause. **Never empty.**
        ///
        /// Not diagnostic — load-bearing. A behavioral finding is self-evident
        /// from its two values, but this one asserts something about a resource
        /// whose fields are provably unchanged, so without the path it is an
        /// unfalsifiable claim. A `SemanticChanged` with an empty `via` is a
        /// bug.
        via: Vec<String>,
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

/// A relation that could not be evaluated.
///
/// The same principle as [`Unjoinable`], one level up: "couldn't resolve" is
/// neither drift nor health, and folding it into either would make "no semantic
/// drift" mean two different things.
#[derive(Debug, Clone)]
pub struct Unresolved {
    /// The affected resource, or `None` when the whole relation is
    /// unresolvable.
    ///
    /// A failed authority check is a property of the state file rather than of
    /// any one resource — a state file declaring no instances is not
    /// authoritative about group membership, full stop — so reporting it
    /// per-resource would print one line per subject where one line is the
    /// truth.
    pub resource: Option<ResourceId>,
    pub relation: String,
    pub reason: String,
}

/// The full result of a single run.
#[derive(Debug, Clone, Default)]
pub struct DriftReport {
    pub drifts: Vec<Drift>,
    pub unjoinable: Vec<Unjoinable>,
    pub unresolved: Vec<Unresolved>,
}
