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
use crate::diff::target_attachments::TargetAttachments;
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

    /// The subject kinds and the field whose meaning this relation expands
    /// on each. Usually one kind; a relation whose claim applies uniformly
    /// across several kinds (e.g. "is this resource reachable from the
    /// internet," which asks the same question of an instance, an RDS
    /// instance, a Lambda function, or an ECS service) lists them all here
    /// rather than needing a near-duplicate relation per kind.
    fn subject(&self) -> &[(ResourceKind, &str)];

    /// Expand a subject's stored value into its effective meaning.
    ///
    /// Pure: reads an already-built graph and returns a value, performing no
    /// I/O, so relations are unit-testable against hand-built graphs. `Err`
    /// carries the reason the subject could not be resolved, which becomes an
    /// [`Unresolved`] rather than a finding.
    fn expand(&self, subject: &Node, graph: &Graph) -> Result<Value, String>;

    /// The cloud IDs a subject's stored value points at, reported on every
    /// finding as `via` — the path that makes a semantic claim checkable
    /// against the account without reading this source. `compare` calls this
    /// once per side and unions the results, since a relation's path can
    /// exist on only one side (a chain that's new live, or one that
    /// disappeared) — unlike `SgMembership`/`InstanceExposure`, whose `via`
    /// happens to read identically off either side, `graph` is here so a
    /// relation whose path only exists on one side can still compute it. The
    /// union must never be empty for a subject
    /// [`expand`](Relation::expand) resolved successfully; a relation whose
    /// findings would have no path to report should fail resolution in
    /// `expand` instead.
    fn via(&self, subject: &Node, graph: &Graph) -> Vec<String>;
}

/// Every relation shipped in the open catalog.
fn catalog() -> Vec<Box<dyn Relation>> {
    vec![
        Box::new(relations::SgMembership),
        Box::new(relations::InstanceExposure),
        Box::new(relations::InternetReachability),
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
    let attachments = TargetAttachments::index(declared);
    let effective: Vec<(&ResourceKind, &str, Map<String, Value>)> = declared
        .iter()
        .filter_map(|r| {
            Some((
                &r.kind,
                r.cloud_id()?,
                effective_attributes(r, &siblings, &attachments),
            ))
        })
        .collect();
    let declared_graph = graph::build(effective.iter().map(|(k, id, a)| (*k, *id, a)));
    let live_graph = graph::build(
        live.iter()
            .map(|r| (&r.kind, r.cloud_id.as_str(), &r.attributes)),
    );

    for relation in catalog() {
        // Guard 2 — authority. A state file that declares none of a required
        // kind is not the authority on that relation: comparing a real live set
        // against a vacuous empty one would fire on every subject in the
        // account. Splitting network and compute into separate state files is a
        // common enough layout that this is not hypothetical. Relation-scoped,
        // not per-subject-kind: `requires()` is a property of the relation as
        // a whole.
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

        for (subject_kind, field) in relation.subject() {
            let field = *field;
            for resource in declared.iter().filter(|r| &r.kind == subject_kind) {
                // No cloud id, or absent live: the behavioral pass already
                // recorded these as Unjoinable / Missing. Nothing semantic to
                // add.
                let Some(cloud_id) = resource.cloud_id() else {
                    continue;
                };
                let (Some(declared_node), Some(live_node)) = (
                    declared_graph.node(subject_kind, cloud_id),
                    live_graph.node(subject_kind, cloud_id),
                ) else {
                    continue;
                };

                // Guard 1 — disjointness. If the field itself drifted,
                // behavioral owns it. This does not suppress a finding whose
                // *cause* drifted elsewhere: the consequence is the point, and
                // `via` links them.
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

                let mut via = relation.via(declared_node, &declared_graph);
                via.extend(relation.via(live_node, &live_graph));
                via.sort();
                via.dedup();
                if via.is_empty() {
                    // A finding whose path cannot be stated is unfalsifiable,
                    // and users mute unfalsifiable claims. Refuse to emit one.
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
}

/// A declared resource's attributes with its separately-declared rules or
/// target registrations folded in, so relations see what the resource
/// effectively allows or contains.
fn effective_attributes(
    resource: &Resource,
    siblings: &SiblingRules,
    attachments: &TargetAttachments,
) -> Map<String, Value> {
    let mut attributes = resource.attributes.clone();
    let Some(cloud_id) = resource.cloud_id() else {
        return attributes;
    };

    match resource.kind {
        ResourceKind::AwsSecurityGroup => {
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
        }
        ResourceKind::AwsLbTargetGroup => {
            attributes.insert(
                "targets".to_string(),
                Value::Array(
                    attachments
                        .targets(cloud_id)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        // Both nest their security-group and subnet lists one level inside a
        // single block — `vpc_config { security_group_ids = [...], subnet_ids
        // = [...] }`, `network_configuration { security_groups = [...],
        // subnets = [...] }` — which `terraform show -json` renders as a
        // one-element array, the same shape as `metadata_options` on
        // `aws_instance`. `EDGE_FIELDS` only reads flat top-level fields, so
        // both get copied up to `vpc_security_group_ids`/`subnet_ids` keys
        // matching every other member kind. `AwsDbInstance` needs no arm for
        // `vpc_security_group_ids` — that's already a flat top-level
        // argument on `aws_db_instance` — and none yet for subnets either:
        // `aws_db_instance` has no `subnet_ids` of its own at all, only a
        // `db_subnet_group_name` reference to a separate resource this
        // module doesn't collect yet.
        ResourceKind::AwsLambdaFunction => {
            attributes.insert(
                "vpc_security_group_ids".to_string(),
                nested_block_field(&attributes, "vpc_config", "security_group_ids"),
            );
            attributes.insert(
                "subnet_ids".to_string(),
                nested_block_field(&attributes, "vpc_config", "subnet_ids"),
            );
        }
        ResourceKind::AwsEcsService => {
            attributes.insert(
                "vpc_security_group_ids".to_string(),
                nested_block_field(&attributes, "network_configuration", "security_groups"),
            );
            attributes.insert(
                "subnet_ids".to_string(),
                nested_block_field(&attributes, "network_configuration", "subnets"),
            );
        }
        _ => {}
    }

    attributes
}

/// The value of `field` inside the single-element block `attributes[block]`
/// renders as in `terraform show -json` — `Value::Array([])` when the block
/// or field is absent, matching how a collector normalizes "nothing here"
/// to an empty membership list rather than an error.
fn nested_block_field(attributes: &Map<String, Value>, block: &str, field: &str) -> Value {
    attributes
        .get(block)
        .and_then(Value::as_array)
        .and_then(|blocks| blocks.first())
        .and_then(|b| b.get(field))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::resource::ResourceId;
    use serde_json::json;

    fn resource(kind: ResourceKind, attributes: Value) -> Resource {
        Resource {
            id: ResourceId("under_test".to_string()),
            kind,
            attributes: attributes.as_object().unwrap().clone(),
        }
    }

    #[test]
    fn a_lambda_functions_declared_vpc_config_flattens_subnet_ids_to_the_top_level() {
        let r = resource(
            ResourceKind::AwsLambdaFunction,
            json!({
                "id": "my-function",
                "vpc_config": [{
                    "security_group_ids": ["sg-1111"],
                    "subnet_ids": ["subnet-1111", "subnet-2222"],
                }],
            }),
        );
        let attrs =
            effective_attributes(&r, &SiblingRules::default(), &TargetAttachments::default());
        assert_eq!(attrs["subnet_ids"], json!(["subnet-1111", "subnet-2222"]));
    }

    #[test]
    fn a_lambda_function_with_no_vpc_config_flattens_subnet_ids_to_an_empty_list() {
        let r = resource(
            ResourceKind::AwsLambdaFunction,
            json!({"id": "my-function"}),
        );
        let attrs =
            effective_attributes(&r, &SiblingRules::default(), &TargetAttachments::default());
        assert_eq!(attrs["subnet_ids"], json!([]));
    }

    #[test]
    fn an_ecs_services_declared_network_configuration_flattens_subnets_to_the_top_level() {
        let r = resource(
            ResourceKind::AwsEcsService,
            json!({
                "id": "arn:svc/1",
                "network_configuration": [{
                    "security_groups": ["sg-1111"],
                    "subnets": ["subnet-1111", "subnet-2222"],
                }],
            }),
        );
        let attrs =
            effective_attributes(&r, &SiblingRules::default(), &TargetAttachments::default());
        assert_eq!(attrs["subnet_ids"], json!(["subnet-1111", "subnet-2222"]));
    }

    #[test]
    fn an_ecs_service_with_no_network_configuration_flattens_subnets_to_an_empty_list() {
        let r = resource(ResourceKind::AwsEcsService, json!({"id": "arn:svc/1"}));
        let attrs =
            effective_attributes(&r, &SiblingRules::default(), &TargetAttachments::default());
        assert_eq!(attrs["subnet_ids"], json!([]));
    }

    #[test]
    fn a_db_instance_gets_no_subnet_ids_arm() {
        // aws_db_instance has no subnet_ids of its own to flatten - see the
        // comment on the AwsEcsService/AwsLambdaFunction match arms.
        let r = resource(
            ResourceKind::AwsDbInstance,
            json!({"id": "db-ABCDEF", "vpc_security_group_ids": ["sg-1111"]}),
        );
        let attrs =
            effective_attributes(&r, &SiblingRules::default(), &TargetAttachments::default());
        assert!(!attrs.contains_key("subnet_ids"));
    }
}
