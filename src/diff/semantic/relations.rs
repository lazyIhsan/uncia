//! The built-in relation catalog.
//!
//! Per `docs/SEMANTIC-DRIFT.md`, the open relation set has to stand on its own
//! rather than function as a teaser for a paid catalog.

use serde_json::Value;

use super::Relation;
use super::graph::{Graph, Node};
use crate::diff::rules::rule_base;
use crate::types::resource::ResourceKind;

/// Security-group membership: a rule that trusts another group effectively
/// trusts whatever is *in* that group, and the group's own attributes say
/// nothing about that.
///
/// This is the relation `docs/ARCHITECTURE.md` uses to motivate semantic drift.
/// A rule reading `allow 443 from sg-app` is byte-identical before and after
/// someone attaches `sg-app` to a new instance, so no field diff can see it;
/// what changed is the set of machines the rule admits.
pub struct SgMembership;

impl Relation for SgMembership {
    fn name(&self) -> &str {
        "sg_membership"
    }

    fn requires(&self) -> &[ResourceKind] {
        // Membership is derived from the instance side, so a state file that
        // declares no instances is not an authority on it.
        &[ResourceKind::AwsInstance]
    }

    fn subject(&self) -> (ResourceKind, &str) {
        (ResourceKind::AwsSecurityGroup, "ingress")
    }

    /// Expand each group-sourced rule into one atom per member instance.
    ///
    /// Only group-sourced atoms are produced. CIDR and prefix-list sources are
    /// literal — they cannot differ between the two sides here, because the
    /// disjointness guard only lets a subject through when its `ingress` value
    /// is already identical — so including them would pad the reported payload
    /// without ever contributing a difference.
    fn expand(&self, subject: &Node, graph: &Graph) -> Result<Value, String> {
        let mut atoms: Vec<String> = Vec::new();

        let rules = subject
            .attributes
            .get("ingress")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();

        for rule in rules {
            let base = rule_base(rule);
            let sources = rule
                .get("security_groups")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);

            for source in sources {
                // A referenced group that isn't in this graph means the group
                // was deleted out from under the rule. Expanding it anyway
                // would report an empty membership as a narrowing finding,
                // pinning the blame on the wrong resource: the real story is
                // that the group is gone, which the diff reports separately.
                if graph
                    .node(&ResourceKind::AwsSecurityGroup, source)
                    .is_none()
                {
                    return Err(format!(
                        "rule references security group `{source}`, which is not present"
                    ));
                }

                for member in graph.referrers(source, &ResourceKind::AwsInstance) {
                    atoms.push(format!("{base}/member:{member}"));
                }
            }
        }

        // Sorted and deduplicated: neither rule order nor how AWS groups
        // sources into permissions is meaningful.
        atoms.sort();
        atoms.dedup();
        Ok(Value::Array(atoms.into_iter().map(Value::String).collect()))
    }
}

/// The cloud IDs a subject's `ingress` rules trust by group reference.
///
/// Reported as a finding's `via` path, which is what makes a semantic claim
/// checkable against the account without reading this source.
pub fn referenced_groups(subject: &Node) -> Vec<String> {
    let mut ids: Vec<String> = subject
        .attributes
        .get("ingress")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| rule.get("security_groups").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::semantic::graph;
    use serde_json::{Map, json};

    fn attrs(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn sg_trusting(source: &str) -> Map<String, Value> {
        attrs(json!({"ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [],
            "security_groups": [source], "self": false,
        }]}))
    }

    fn instance_in(sgs: Value) -> Map<String, Value> {
        attrs(json!({"vpc_security_group_ids": sgs}))
    }

    /// A graph with `sg-web` trusting `sg-app`, plus the given instances.
    fn graph_with(members: &[(&str, Map<String, Value>)]) -> (Map<String, Value>, graph::Graph) {
        let web = sg_trusting("sg-app");
        let app = attrs(json!({"name": "app"}));
        let mut triples: Vec<(&ResourceKind, &str, &Map<String, Value>)> = vec![
            (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
            (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
        ];
        for (id, a) in members {
            triples.push((&ResourceKind::AwsInstance, id, a));
        }
        let g = graph::build(triples.into_iter());
        (web.clone(), g)
    }

    fn subject(attributes: &Map<String, Value>) -> Node {
        Node {
            kind: ResourceKind::AwsSecurityGroup,
            cloud_id: "sg-web".to_string(),
            attributes: attributes.clone(),
        }
    }

    #[test]
    fn membership_expands_to_one_atom_per_member() {
        let worker = instance_in(json!(["sg-app"]));
        let (web, g) = graph_with(&[("i-worker", worker)]);

        let effective = SgMembership.expand(&subject(&web), &g).unwrap();
        assert_eq!(effective, json!(["tcp/443-443/member:i-worker"]));
    }

    #[test]
    fn an_undeclared_member_widens_the_effective_set() {
        // The scenario the whole feature exists for: same rule, more machines.
        let worker = instance_in(json!(["sg-app"]));
        let console = instance_in(json!(["sg-app"]));
        let (web, declared) = graph_with(&[("i-worker", worker.clone())]);
        let (_, live) = graph_with(&[("i-worker", worker), ("i-console", console)]);

        let before = SgMembership.expand(&subject(&web), &declared).unwrap();
        let after = SgMembership.expand(&subject(&web), &live).unwrap();

        assert_ne!(before, after);
        assert_eq!(
            after,
            json!([
                "tcp/443-443/member:i-console",
                "tcp/443-443/member:i-worker"
            ])
        );
    }

    #[test]
    fn an_empty_group_expands_to_nothing_without_erroring() {
        // A group that exists but holds no instances is a real, resolvable
        // state — distinct from a group that is gone.
        let (web, g) = graph_with(&[]);
        assert_eq!(SgMembership.expand(&subject(&web), &g).unwrap(), json!([]));
    }

    #[test]
    fn a_rule_with_no_group_sources_expands_to_nothing() {
        let cidr_only = attrs(json!({"ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": ["0.0.0.0/0"], "security_groups": [], "self": false,
        }]}));
        let g = graph::build(std::iter::empty());

        assert_eq!(
            SgMembership.expand(&subject(&cidr_only), &g).unwrap(),
            json!([]),
            "literal sources carry no membership to expand"
        );
    }

    #[test]
    fn a_missing_referenced_group_is_unresolvable_not_empty() {
        let web = sg_trusting("sg-gone");
        let g = graph::build(std::iter::empty());

        let err = SgMembership.expand(&subject(&web), &g).unwrap_err();
        assert!(err.contains("sg-gone"), "{err}");
    }

    #[test]
    fn expansion_is_insensitive_to_member_discovery_order() {
        let a = instance_in(json!(["sg-app"]));
        let b = instance_in(json!(["sg-app"]));
        let (web, one) = graph_with(&[("i-a", a.clone()), ("i-b", b.clone())]);
        let (_, two) = graph_with(&[("i-b", b), ("i-a", a)]);

        assert_eq!(
            SgMembership.expand(&subject(&web), &one).unwrap(),
            SgMembership.expand(&subject(&web), &two).unwrap()
        );
    }

    #[test]
    fn via_lists_the_groups_a_subject_trusts() {
        let web = sg_trusting("sg-app");
        assert_eq!(referenced_groups(&subject(&web)), vec!["sg-app"]);
    }
}
