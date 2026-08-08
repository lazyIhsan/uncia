//! The resource graph both semantic passes are built on.
//!
//! Two graphs get built per run — one from declared state, one from live
//! observations — by the *same* [`build`] function. That is deliberate: semantic
//! drift is the shape difference between them, so any asymmetry in how they are
//! constructed would show up as a finding. One function, two call sites, no way
//! for them to diverge.
//!
//! **Nodes are keyed by cloud ID**, per the identifier invariant in
//! `docs/ARCHITECTURE.md`: the Terraform address exists only on the declared
//! side, so the cloud ID is the only key the two graphs share. Terraform
//! addresses re-enter only when a finding is reported.
//!
//! **Edges come from attribute values, not Terraform references.** The live
//! side has no references at all — AWS returns values — so a declared graph
//! built from `configuration` expressions or a raw state file's `dependencies`
//! list would have nothing comparable to diff against. Reading values also
//! means a hardcoded `"sg-0abc"` and `aws_security_group.app.id` produce the
//! same edge, which matches what AWS sees.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value};

use crate::types::resource::ResourceKind;

/// Attribute fields whose string values reference another resource by cloud ID.
///
/// This table is the whole of edge discovery: adding a relation that needs a
/// new edge kind means adding a row here, not touching [`build`].
const EDGE_FIELDS: &[(ResourceKind, &str)] =
    &[(ResourceKind::AwsInstance, "vpc_security_group_ids")];

/// One resource in the graph, as observed on whichever side built it.
#[derive(Debug, Clone)]
pub struct Node {
    pub kind: ResourceKind,
    pub cloud_id: String,
    pub attributes: Map<String, Value>,
}

/// Resources plus the references between them, for one side of the comparison.
#[derive(Debug, Default)]
pub struct Graph {
    nodes: HashMap<(ResourceKind, String), Node>,
    /// target cloud id -> the nodes referencing it. Unordered internally;
    /// [`Graph::referrers`] sorts on the way out so callers see a stable set.
    incoming: HashMap<String, HashSet<(ResourceKind, String)>>,
}

impl Graph {
    /// Look up one node by kind and cloud ID.
    pub fn node(&self, kind: &ResourceKind, cloud_id: &str) -> Option<&Node> {
        self.nodes.get(&(kind.clone(), cloud_id.to_string()))
    }

    /// Cloud IDs of `kind` nodes that reference `target` through an edge field.
    ///
    /// This is the reverse direction of [`EDGE_FIELDS`] — "which instances are
    /// in this security group" is not stored on the group, it is derived from
    /// the instances that name it.
    pub fn referrers(&self, target: &str, kind: &ResourceKind) -> BTreeSet<String> {
        self.incoming
            .get(target)
            .into_iter()
            .flatten()
            .filter(|(k, _)| k == kind)
            .map(|(_, id)| id.clone())
            .collect()
    }

    /// Whether the graph contains any node of this kind.
    ///
    /// Used by the authority check: a side that declares nothing of a kind is
    /// not an authority on relations that depend on it.
    pub fn has_kind(&self, kind: &ResourceKind) -> bool {
        self.nodes.keys().any(|(k, _)| k == kind)
    }
}

/// Build a graph from `(kind, cloud_id, attributes)` triples.
///
/// Both the declared and the live side go through here; see the module docs for
/// why that symmetry matters.
pub fn build<'a>(
    nodes: impl Iterator<Item = (&'a ResourceKind, &'a str, &'a Map<String, Value>)>,
) -> Graph {
    let mut graph = Graph::default();

    for (kind, cloud_id, attributes) in nodes {
        let key = (kind.clone(), cloud_id.to_string());

        for (edge_kind, field) in EDGE_FIELDS {
            if edge_kind != kind {
                continue;
            }
            let targets = attributes
                .get(*field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            for target in targets {
                graph
                    .incoming
                    .entry(target.to_string())
                    .or_default()
                    .insert(key.clone());
            }
        }

        graph.nodes.insert(
            key,
            Node {
                kind: kind.clone(),
                cloud_id: cloud_id.to_string(),
                attributes: attributes.clone(),
            },
        );
    }

    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attrs(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn instance(sgs: Value) -> Map<String, Value> {
        attrs(json!({"instance_type": "t3.micro", "vpc_security_group_ids": sgs}))
    }

    #[test]
    fn membership_is_derived_from_the_referencing_side() {
        // Nothing on the group says who is in it; the edge is discovered from
        // the instances that name it.
        let sg = attrs(json!({"name": "app"}));
        let worker = instance(json!(["sg-app"]));
        let other = instance(json!(["sg-web"]));

        let graph = build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-app", &sg),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
                (&ResourceKind::AwsInstance, "i-other", &other),
            ]
            .into_iter(),
        );

        assert_eq!(
            graph.referrers("sg-app", &ResourceKind::AwsInstance),
            BTreeSet::from(["i-worker".to_string()])
        );
        assert!(
            graph
                .referrers("sg-app", &ResourceKind::AwsSecurityGroup)
                .is_empty(),
            "referrers must filter by kind"
        );
    }

    #[test]
    fn one_resource_can_reference_several_targets() {
        let worker = instance(json!(["sg-app", "sg-web"]));
        let graph = build([(&ResourceKind::AwsInstance, "i-worker", &worker)].into_iter());

        for sg in ["sg-app", "sg-web"] {
            assert_eq!(
                graph.referrers(sg, &ResourceKind::AwsInstance),
                BTreeSet::from(["i-worker".to_string()])
            );
        }
    }

    #[test]
    fn declared_and_live_inputs_build_the_same_shape() {
        // The point of a single `build`: given the same attribute values, the
        // two sides are indistinguishable. Only the values may differ.
        let sg = attrs(json!({"name": "app"}));
        let worker = instance(json!(["sg-app"]));
        let make = || {
            build(
                [
                    (&ResourceKind::AwsSecurityGroup, "sg-app", &sg),
                    (&ResourceKind::AwsInstance, "i-worker", &worker),
                ]
                .into_iter(),
            )
        };

        let declared = make();
        let live = make();
        assert_eq!(
            declared.referrers("sg-app", &ResourceKind::AwsInstance),
            live.referrers("sg-app", &ResourceKind::AwsInstance)
        );
        assert_eq!(
            declared
                .node(&ResourceKind::AwsSecurityGroup, "sg-app")
                .map(|n| &n.attributes),
            live.node(&ResourceKind::AwsSecurityGroup, "sg-app")
                .map(|n| &n.attributes)
        );
    }

    #[test]
    fn nodes_are_keyed_by_cloud_id_and_kind() {
        let sg = attrs(json!({"name": "app"}));
        let graph = build([(&ResourceKind::AwsSecurityGroup, "sg-app", &sg)].into_iter());

        assert!(
            graph
                .node(&ResourceKind::AwsSecurityGroup, "sg-app")
                .is_some()
        );
        assert!(
            graph.node(&ResourceKind::AwsInstance, "sg-app").is_none(),
            "same id under a different kind must not collide"
        );
        assert!(graph.has_kind(&ResourceKind::AwsSecurityGroup));
        assert!(!graph.has_kind(&ResourceKind::AwsInstance));
    }

    #[test]
    fn a_resource_with_no_edge_fields_contributes_no_edges() {
        let bucket = attrs(json!({"vpc_security_group_ids": ["sg-app"]}));
        let graph = build(
            [(
                &ResourceKind::Other("aws_s3_bucket".to_string()),
                "assets",
                &bucket,
            )]
            .into_iter(),
        );

        assert!(
            graph
                .referrers("sg-app", &ResourceKind::AwsInstance)
                .is_empty(),
            "edge fields are per-kind, not global field names"
        );
    }
}
