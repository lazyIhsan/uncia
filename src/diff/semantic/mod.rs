//! Semantic diff: the declared and live values are identical, but the resource
//! no longer *means* what it did, because something it depends on changed.
//!
//! Behavioral drift is a function of one resource — its stored attributes
//! against its live attributes. Semantic drift is a function of a resource
//! *and its neighbourhood*: resolve each side's effective meaning from the
//! state it belongs to, then compare. No amount of field-level comparison finds
//! it, because the information needed is not in the resource. See
//! `docs/SEMANTIC-DRIFT.md`.
//!
//! Both baselines are resolved from fully-read inputs, so this stays
//! deterministic and fully observed — a finding is never "this looks
//! anomalous", always a concrete difference between two computed sets, carrying
//! the path that produced it.
//!
//! The failure mode to design against here is not a missed finding but a
//! *confident wrong* one, so three guards run before anything is reported; see
//! [`compare`].

pub mod graph;
pub mod reachability;
pub mod relations;

use serde_json::{Map, Value};

use crate::collector::LiveResource;
use crate::diff::rules::SiblingRules;
use crate::types::drift::{Drift, DriftKind, DriftReport, Severity, Unresolved};
use crate::types::resource::{Resource, ResourceKind};
use graph::{Graph, Node};

/// One way meaning flows between resource kinds — the unit of extension, as
/// `Collector` is for cloud coverage.
pub trait Relation {
    /// Stable identifier, reported on every finding this relation produces.
    fn name(&self) -> &str;

    /// Kinds the declared side must contain for this relation to be resolvable.
    fn requires(&self) -> &[ResourceKind];

    /// The subject kind and the field whose meaning this relation expands.
    fn subject(&self) -> (ResourceKind, &str);

    /// Expand a subject's stored value into its effective meaning.
    ///
    /// Pure: reads an already-built graph and returns a value, performing no
    /// I/O, so relations are unit-testable against hand-built graphs. `Err`
    /// carries the reason the subject could not be resolved, which becomes an
    /// [`Unresolved`] rather than a finding.
    fn expand(&self, subject: &Node, graph: &Graph) -> Result<Value, String>;

    /// The cloud IDs a subject's stored value points at, reported on every
    /// finding as `via` — the path that makes a semantic claim checkable
    /// against the account without reading this source. Must never be empty
    /// for a subject [`expand`](Relation::expand) resolved successfully; a
    /// relation whose findings would have no path to report should fail
    /// resolution in `expand` instead.
    fn via(&self, subject: &Node) -> Vec<String>;
}

/// Every relation shipped in the open catalog.
fn catalog() -> Vec<Box<dyn Relation>> {
    vec![
        Box::new(relations::SgMembership),
        Box::new(relations::InstanceExposure),
    ]
}

/// Append semantic findings to a report that already holds the behavioral pass.
///
/// Takes the existing report because guard 1 needs it: semantic drift is
/// *defined* as the field being unchanged, so a field the behavioral pass
/// already flagged must not also produce a semantic finding.
pub fn compare(declared: &[Resource], live: &[LiveResource], report: &mut DriftReport) {
    // The declared graph must carry *effective* rules, not raw inline blocks.
    // A group whose rules are declared as sibling resources has empty inline
    // blocks, so a relation reading them straight off the node would compare an
    // empty declared rule set against a real live one and invent drift — the
    // behavioral pass's reconciliation would have merely moved the false
    // positive rather than removed it.
    let siblings = SiblingRules::index(declared);
    let effective: Vec<(&ResourceKind, &str, Map<String, Value>)> = declared
        .iter()
        .filter_map(|r| Some((&r.kind, r.cloud_id()?, effective_attributes(r, &siblings))))
        .collect();
    let declared_graph = graph::build(effective.iter().map(|(k, id, a)| (*k, *id, a)));
    let live_graph = graph::build(
        live.iter()
            .map(|r| (&r.kind, r.cloud_id.as_str(), &r.attributes)),
    );

    for relation in catalog() {
        let (subject_kind, field) = relation.subject();

        // Guard 2 — authority. A state file that declares none of a required
        // kind is not the authority on that relation: comparing a real live set
        // against a vacuous empty one would fire on every subject in the
        // account. Splitting network and compute into separate state files is a
        // common enough layout that this is not hypothetical.
        if let Some(missing) = relation
            .requires()
            .iter()
            .find(|kind| !declared_graph.has_kind(kind))
        {
            report.unresolved.push(Unresolved {
                resource: None,
                relation: relation.name().to_string(),
                reason: format!(
                    "declared state contains no `{}`, so it is not authoritative \
                     for this relation",
                    missing.as_str()
                ),
            });
            continue;
        }

        for resource in declared.iter().filter(|r| r.kind == subject_kind) {
            // No cloud id, or absent live: the behavioral pass already recorded
            // these as Unjoinable / Missing. Nothing semantic to add.
            let Some(cloud_id) = resource.cloud_id() else {
                continue;
            };
            let (Some(declared_node), Some(live_node)) = (
                declared_graph.node(&subject_kind, cloud_id),
                live_graph.node(&subject_kind, cloud_id),
            ) else {
                continue;
            };

            // Guard 1 — disjointness. If the field itself drifted, behavioral
            // owns it. This does not suppress a finding whose *cause* drifted
            // elsewhere: the consequence is the point, and `via` links them.
            if has_field_drift(report, &resource.id.0, field) {
                continue;
            }

            let effective = (
                relation.expand(declared_node, &declared_graph),
                relation.expand(live_node, &live_graph),
            );
            let (declared_effective, actual_effective) = match effective {
                (Ok(d), Ok(a)) => (d, a),
                (Err(reason), _) | (_, Err(reason)) => {
                    report.unresolved.push(Unresolved {
                        resource: Some(resource.id.clone()),
                        relation: relation.name().to_string(),
                        reason,
                    });
                    continue;
                }
            };

            if declared_effective == actual_effective {
                continue;
            }

            let via = relation.via(declared_node);
            if via.is_empty() {
                // A finding whose path cannot be stated is unfalsifiable, and
                // users mute unfalsifiable claims. Refuse to emit one.
                debug_assert!(false, "semantic finding with no via path");
                continue;
            }

            report.drifts.push(Drift {
                resource: resource.id.clone(),
                severity: severity_for(&declared_effective, &actual_effective),
                kind: DriftKind::SemanticChanged {
                    field: field.to_string(),
                    relation: relation.name().to_string(),
                    declared_effective,
                    actual_effective,
                    via,
                },
            });
        }
    }
}

/// A declared resource's attributes with its separately-declared rules folded
/// into the rule lists, so relations see what the group effectively allows.
fn effective_attributes(resource: &Resource, siblings: &SiblingRules) -> Map<String, Value> {
    let mut attributes = resource.attributes.clone();
    if resource.kind != ResourceKind::AwsSecurityGroup {
        return attributes;
    }
    let Some(cloud_id) = resource.cloud_id() else {
        return attributes;
    };
    for direction in ["ingress", "egress"] {
        let extra = siblings.blocks(cloud_id, direction);
        if extra.is_empty() {
            continue;
        }
        let mut rules = attributes
            .get(direction)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        rules.extend(extra);
        attributes.insert(direction.to_string(), Value::Array(rules));
    }
    attributes
}

/// Whether the behavioral pass already reported this exact resource and field.
fn has_field_drift(report: &DriftReport, address: &str, field: &str) -> bool {
    report.drifts.iter().any(|d| {
        d.resource.0 == address
            && matches!(&d.kind, DriftKind::FieldChanged { field: f, .. } if f == field)
    })
}

/// Severity from blast-radius direction: a set that *grew* admits more
/// principals than declared, which is worse than one that shrank.
///
/// This is the first input uncia has to severity policy that needs no new
/// configuration — the direction is derivable from the finding itself. Severity
/// policy overall remains an open question in `docs/ARCHITECTURE.md`.
fn severity_for(declared: &Value, actual: &Value) -> Severity {
    let as_set = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let before = as_set(declared);
    let after = as_set(actual);

    if after.iter().any(|a| !before.contains(a)) {
        Severity::High
    } else {
        Severity::Low
    }
}
