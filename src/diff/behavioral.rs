//! Behavioral diff: field-by-field comparison of declared state against live
//! observations.
//!
//! Joining follows the architecture invariants: declared resources are keyed
//! by Terraform address, live observations by cloud ID, and the two meet
//! *only* here, via `Resource::cloud_id()`. A declared resource with no
//! usable cloud ID is neither skipped nor reported as missing — it lands in
//! `DriftReport::unjoinable` so "no drift" and "couldn't check" stay
//! distinguishable.

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;

use crate::collector::LiveResource;
use crate::types::drift::{Drift, DriftKind, DriftReport, Severity, Unjoinable};
use crate::types::resource::{Resource, ResourceKind};

/// Fields compared for `aws_security_group`.
const SECURITY_GROUP_FIELDS: &[&str] =
    &["name", "description", "vpc_id", "tags", "ingress", "egress"];

/// Fields holding rule lists, compared as exploded atom sets rather than by
/// value equality (rule order and grouping are not meaningful).
const RULE_FIELDS: &[&str] = &["ingress", "egress"];

/// Compare declared resources against live observations and report drift.
pub fn compare(declared: &[Resource], live: &[LiveResource]) -> DriftReport {
    let mut report = DriftReport::default();

    let live_index: HashMap<(&ResourceKind, &str), &LiveResource> = live
        .iter()
        .map(|l| ((&l.kind, l.cloud_id.as_str()), l))
        .collect();

    for resource in declared {
        let fields = fields_for(&resource.kind);
        if fields.is_empty() {
            // Kinds no collector covers yet can't be checked either way.
            continue;
        }

        let Some(cloud_id) = resource.cloud_id() else {
            report.unjoinable.push(Unjoinable {
                resource: resource.id.clone(),
                reason:
                    "no cloud id recorded in state (attributes[\"id\"] missing or not a string)"
                        .to_string(),
            });
            continue;
        };

        let Some(live_resource) = live_index.get(&(&resource.kind, cloud_id)) else {
            report.drifts.push(Drift {
                resource: resource.id.clone(),
                kind: DriftKind::Missing,
                severity: Severity::High,
            });
            continue;
        };

        for field in fields {
            // Terraform records provider default_tags only in `tags_all`;
            // the live side reports every tag, so that's the honest declared
            // counterpart when present.
            let declared_value = if *field == "tags" {
                resource
                    .attributes
                    .get("tags_all")
                    .or_else(|| resource.attributes.get("tags"))
            } else {
                resource.attributes.get(*field)
            }
            .cloned()
            .unwrap_or(Value::Null);
            let actual_value = live_resource
                .attributes
                .get(*field)
                .cloned()
                .unwrap_or(Value::Null);

            let equal = if RULE_FIELDS.contains(field) {
                explode_rules(&declared_value) == explode_rules(&actual_value)
            } else {
                declared_value == actual_value
            };

            if !equal {
                report.drifts.push(Drift {
                    resource: resource.id.clone(),
                    kind: DriftKind::FieldChanged {
                        field: (*field).to_string(),
                        declared: declared_value,
                        actual: actual_value,
                    },
                    severity: Severity::Medium,
                });
            }
        }
    }

    // TODO: unmanaged detection (live resources declared nowhere) is deferred:
    // other state files may legitimately own them. See ARCHITECTURE.md.
    report
}

fn fields_for(kind: &ResourceKind) -> &'static [&'static str] {
    match kind {
        ResourceKind::AwsSecurityGroup => SECURITY_GROUP_FIELDS,
        _ => &[],
    }
}

/// Explode a rule list into a canonical set of atoms, one per
/// (port-range, protocol, source). Insensitive to rule order *and* to how
/// sources are grouped into rules — AWS and Terraform group differently, and
/// neither grouping is meaningful.
///
/// Rule descriptions are deliberately not part of the atom (see module docs
/// in `collector::aws::security_group`).
fn explode_rules(rules: &Value) -> BTreeSet<String> {
    let mut atoms = BTreeSet::new();
    let Some(list) = rules.as_array() else {
        return atoms;
    };
    for rule in list {
        let from = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
        let to = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
        let protocol = rule.get("protocol").and_then(Value::as_str).unwrap_or("-1");
        let base = format!("{protocol}/{from}-{to}");

        for (key, tag) in [
            ("cidr_blocks", "cidr"),
            ("ipv6_cidr_blocks", "cidr6"),
            ("prefix_list_ids", "pl"),
            ("security_groups", "sg"),
        ] {
            if let Some(sources) = rule.get(key).and_then(Value::as_array) {
                for source in sources {
                    if let Some(source) = source.as_str() {
                        atoms.insert(format!("{base}/{tag}:{source}"));
                    }
                }
            }
        }
        if rule.get("self").and_then(Value::as_bool).unwrap_or(false) {
            atoms.insert(format!("{base}/self"));
        }
    }
    atoms
}
