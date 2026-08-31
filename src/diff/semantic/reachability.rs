//! Multi-hop reachability: a bounded walk from internet-facing security
//! groups through membership, load-balancer target registration, and
//! group-to-group trust, independent of any single [`super::Relation`].
//!
//! This is deliberately *not* a relation itself — no subject, no `expand`,
//! nothing compared. It is the traversal engine a future relation composes:
//! given a graph, which resources can the public internet actually reach,
//! and through what chain. Phase 1 (target-group collection) got the data
//! into the graph's shape; this is the first thing that actually reads it.
//!
//! **Why the "trusts" edge below is not another `EDGE_FIELDS` row.**
//! `EDGE_FIELDS` indexes flat top-level attribute fields — an instance's
//! `vpc_security_group_ids`, a load balancer's `security_groups`. A rule's
//! `security_groups` source, by contrast, is nested inside the `ingress`
//! array: one security group's rule naming another group as a trusted
//! source. That is a different shape than [`super::graph::build`]
//! deliberately walks, so it gets its own scan here rather than forcing the
//! edge table to understand nested rule objects.
//!
//! **Why a three-tier chain, not just one hop.** `internet → web tier →
//! app tier → database tier` is the ordinary shape of a real VPC, and
//! getting from the web tier to the database tier needs exactly the
//! "trusts" edge above: the database's security group names the app tier's
//! group as an allowed source, not the other way around. A traversal that
//! stopped at one membership hop could reach a load balancer's own targets
//! but never a resource behind a second security boundary — which is most
//! of what "internet to database" is supposed to prove.

use std::collections::{BTreeSet, HashSet, VecDeque};

use serde_json::Value;

use super::graph::{Graph, Node};
use super::relations::MEMBER_KINDS;
use crate::types::resource::ResourceKind;

/// Rule sources that mean "the public internet," not a general CIDR-overlap
/// judgment. Deliberately a literal match — `1.2.3.0/24` being "basically
/// public" is a call this does not make.
const INTERNET_CIDRS: &[&str] = &["0.0.0.0/0", "::/0"];

/// Security groups in `graph` with at least one ingress rule sourced
/// directly from the public internet ([`INTERNET_CIDRS`]).
pub fn internet_facing_groups(graph: &Graph) -> BTreeSet<String> {
    graph
        .nodes_of_kind(&ResourceKind::AwsSecurityGroup)
        .filter(|sg| has_internet_facing_rule(sg))
        .map(|sg| sg.cloud_id.clone())
        .collect()
}

fn has_internet_facing_rule(sg: &Node) -> bool {
    ingress_rules(sg).any(|rule| {
        ["cidr_blocks", "ipv6_cidr_blocks"].iter().any(|key| {
            rule.get(*key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|cidr| INTERNET_CIDRS.contains(&cidr))
        })
    })
}

/// Security groups elsewhere in the graph whose ingress cites `group_id` as
/// a trusted source. The mirror of [`Graph::referrers`] one level up: not
/// who belongs to the group, but who trusts it. See the module docs for why
/// this is a scan rather than an `EDGE_FIELDS` row.
fn groups_trusting(graph: &Graph, group_id: &str) -> BTreeSet<String> {
    graph
        .nodes_of_kind(&ResourceKind::AwsSecurityGroup)
        .filter(|sg| {
            ingress_rules(sg).any(|rule| {
                rule.get("security_groups")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(|source| source == group_id)
            })
        })
        .map(|sg| sg.cloud_id.clone())
        .collect()
}

fn ingress_rules(sg: &Node) -> impl Iterator<Item = &Value> {
    sg.attributes
        .get("ingress")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// The resources one hop reaches from `node`, dispatched by kind. Each kind
/// contributes the one or two edge shapes that apply to it; nothing outside
/// this list continues a chain.
fn neighbors(graph: &Graph, node: &Node) -> Vec<(ResourceKind, String)> {
    match node.kind {
        ResourceKind::AwsSecurityGroup => MEMBER_KINDS
            .iter()
            .flat_map(|kind| {
                graph
                    .referrers(&node.cloud_id, kind)
                    .into_iter()
                    .map(|id| (kind.clone(), id))
            })
            .collect(),

        ResourceKind::AwsInstance => own_groups(node, "vpc_security_group_ids")
            .flat_map(|group_id| groups_trusting(graph, &group_id))
            .map(|id| (ResourceKind::AwsSecurityGroup, id))
            .collect(),

        ResourceKind::AwsLoadBalancer => {
            let trusting = own_groups(node, "security_groups")
                .flat_map(|group_id| groups_trusting(graph, &group_id))
                .map(|id| (ResourceKind::AwsSecurityGroup, id));
            let target_groups = graph
                .referrers(&node.cloud_id, &ResourceKind::AwsLbTargetGroup)
                .into_iter()
                .map(|id| (ResourceKind::AwsLbTargetGroup, id));
            trusting.chain(target_groups).collect()
        }

        ResourceKind::AwsLbTargetGroup => node
            .attributes
            .get("targets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|id| (ResourceKind::AwsInstance, id.to_string()))
            .collect(),

        _ => Vec::new(),
    }
}

/// The cloud IDs a node lists under `field` on itself — its own group
/// memberships, read as a plain attribute rather than a graph edge.
fn own_groups<'a>(node: &'a Node, field: &str) -> impl Iterator<Item = String> + 'a {
    node.attributes
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
}

/// One resource reachable from an entry point, plus the chain that reaches
/// it — the `via` a future relation would report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reached {
    pub kind: ResourceKind,
    pub cloud_id: String,
    /// Cloud IDs from the first hop past the start node through to (and
    /// including) this resource. The start node's own id is not included —
    /// callers already know it, the same convention `Relation::via` uses.
    pub path: Vec<String>,
}

/// Every resource reachable from `start_id` within `max_hops`, however many
/// security-group, load-balancer, or target-group hops away.
///
/// Plain BFS: a visited set keyed the same way [`Graph`]'s own nodes are,
/// so a cycle (two groups trusting each other) terminates instead of
/// looping. Deterministic by construction — [`Graph::referrers`] and
/// [`groups_trusting`] both return sorted `BTreeSet`s and [`MEMBER_KINDS`]
/// is a fixed order, so [`neighbors`] always yields the same order and BFS
/// visits (and reports) resources in the same order every run.
pub fn reachable_from(
    graph: &Graph,
    start_kind: &ResourceKind,
    start_id: &str,
    max_hops: usize,
) -> Vec<Reached> {
    let mut reached = Vec::new();
    let mut visited: HashSet<(ResourceKind, String)> = HashSet::new();
    let mut queue: VecDeque<(ResourceKind, String, Vec<String>)> = VecDeque::new();

    visited.insert((start_kind.clone(), start_id.to_string()));
    queue.push_back((start_kind.clone(), start_id.to_string(), Vec::new()));

    while let Some((kind, id, path)) = queue.pop_front() {
        if path.len() >= max_hops {
            continue;
        }
        let Some(node) = graph.node(&kind, &id) else {
            continue;
        };

        for (next_kind, next_id) in neighbors(graph, node) {
            let key = (next_kind.clone(), next_id.clone());
            if !visited.insert(key) {
                continue;
            }

            let mut next_path = path.clone();
            next_path.push(next_id.clone());

            reached.push(Reached {
                kind: next_kind.clone(),
                cloud_id: next_id.clone(),
                path: next_path.clone(),
            });
            queue.push_back((next_kind, next_id, next_path));
        }
    }

    reached
}

#[cfg(test)]
mod tests {
    use super::super::graph;
    use super::*;
    use serde_json::{Map, json};

    fn attrs(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn sg_with_cidr(cidr: &str) -> Map<String, Value> {
        attrs(json!({"ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": [cidr], "ipv6_cidr_blocks": [],
            "security_groups": [], "self": false,
        }]}))
    }

    fn sg_with_ipv6_cidr(cidr: &str) -> Map<String, Value> {
        attrs(json!({"ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": [], "ipv6_cidr_blocks": [cidr],
            "security_groups": [], "self": false,
        }]}))
    }

    fn sg_trusting(source: &str) -> Map<String, Value> {
        attrs(json!({"ingress": [{
            "from_port": 5432, "to_port": 5432, "protocol": "tcp",
            "cidr_blocks": [], "ipv6_cidr_blocks": [],
            "security_groups": [source], "self": false,
        }]}))
    }

    fn empty_sg() -> Map<String, Value> {
        attrs(json!({"name": "app"}))
    }

    fn instance_in(sgs: &[&str]) -> Map<String, Value> {
        attrs(json!({"vpc_security_group_ids": sgs}))
    }

    fn lb_in(sgs: &[&str]) -> Map<String, Value> {
        attrs(json!({"security_groups": sgs}))
    }

    fn target_group(lb_arn: &str, targets: &[&str]) -> Map<String, Value> {
        attrs(json!({"load_balancer_arns": [lb_arn], "targets": targets}))
    }

    // --- internet_facing_groups ---

    #[test]
    fn finds_a_group_with_an_ipv4_wildcard_rule() {
        let sg = sg_with_cidr("0.0.0.0/0");
        let graph = graph::build([(&ResourceKind::AwsSecurityGroup, "sg-web", &sg)].into_iter());
        assert_eq!(
            internet_facing_groups(&graph),
            BTreeSet::from(["sg-web".to_string()])
        );
    }

    #[test]
    fn finds_a_group_with_an_ipv6_wildcard_rule() {
        let sg = sg_with_ipv6_cidr("::/0");
        let graph = graph::build([(&ResourceKind::AwsSecurityGroup, "sg-web", &sg)].into_iter());
        assert_eq!(
            internet_facing_groups(&graph),
            BTreeSet::from(["sg-web".to_string()])
        );
    }

    #[test]
    fn does_not_flag_a_group_with_only_private_or_group_sourced_rules() {
        let private = sg_with_cidr("10.0.0.0/8");
        let trusting = sg_trusting("sg-app");
        let graph = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-private", &private),
                (&ResourceKind::AwsSecurityGroup, "sg-db", &trusting),
            ]
            .into_iter(),
        );
        assert!(internet_facing_groups(&graph).is_empty());
    }

    // --- reachable_from: membership hop ---

    #[test]
    fn reaches_a_direct_member_of_the_entry_group() {
        let sg = sg_with_cidr("0.0.0.0/0");
        let worker = instance_in(&["sg-web"]);
        let graph = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let reached = reachable_from(&graph, &ResourceKind::AwsSecurityGroup, "sg-web", 10);
        assert_eq!(
            reached,
            vec![Reached {
                kind: ResourceKind::AwsInstance,
                cloud_id: "i-worker".to_string(),
                path: vec!["i-worker".to_string()],
            }]
        );
    }

    // --- reachable_from: registration chain ---

    #[test]
    fn reaches_a_target_group_instance_through_an_alb() {
        let sg = sg_with_cidr("0.0.0.0/0");
        let alb = lb_in(&["sg-web"]);
        let tg = target_group("arn:alb/1", &["i-app"]);
        let app = instance_in(&[]);
        let graph = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
                (&ResourceKind::AwsLbTargetGroup, "arn:tg/1", &tg),
                (&ResourceKind::AwsInstance, "i-app", &app),
            ]
            .into_iter(),
        );

        let reached = reachable_from(&graph, &ResourceKind::AwsSecurityGroup, "sg-web", 10);
        let ids: Vec<&str> = reached.iter().map(|r| r.cloud_id.as_str()).collect();
        assert_eq!(ids, vec!["arn:alb/1", "arn:tg/1", "i-app"], "{reached:?}");

        let app_reached = reached.iter().find(|r| r.cloud_id == "i-app").unwrap();
        assert_eq!(
            app_reached.path,
            vec![
                "arn:alb/1".to_string(),
                "arn:tg/1".to_string(),
                "i-app".to_string()
            ]
        );
    }

    // --- reachable_from: the flagship three-tier chain ---

    #[test]
    fn reaches_a_database_instance_through_a_web_and_app_tier() {
        // internet -> sg-web (entry) -> alb (member) -> tg (registered)
        // -> i-app (registered) -> sg-app (own group) -> sg-db (trusts
        // sg-app) -> i-db (member). Nothing about sg-web or the ALB
        // mentions the database at all; the chain is entirely composed
        // from independent, real edges.
        let sg_web = sg_with_cidr("0.0.0.0/0");
        let alb = lb_in(&["sg-web"]);
        let tg = target_group("arn:alb/1", &["i-app"]);
        let app = instance_in(&["sg-app"]);
        let sg_app = empty_sg();
        let sg_db = sg_trusting("sg-app");
        let db = instance_in(&["sg-db"]);

        let graph = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg_web),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
                (&ResourceKind::AwsLbTargetGroup, "arn:tg/1", &tg),
                (&ResourceKind::AwsInstance, "i-app", &app),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &sg_app),
                (&ResourceKind::AwsSecurityGroup, "sg-db", &sg_db),
                (&ResourceKind::AwsInstance, "i-db", &db),
            ]
            .into_iter(),
        );

        let reached = reachable_from(&graph, &ResourceKind::AwsSecurityGroup, "sg-web", 10);
        let db_reached = reached
            .iter()
            .find(|r| r.cloud_id == "i-db")
            .unwrap_or_else(|| panic!("database instance not reached: {reached:?}"));

        assert_eq!(db_reached.kind, ResourceKind::AwsInstance);
        assert_eq!(
            db_reached.path,
            vec![
                "arn:alb/1".to_string(),
                "arn:tg/1".to_string(),
                "i-app".to_string(),
                "sg-db".to_string(),
                "i-db".to_string(),
            ]
        );
    }

    // --- reachable_from: cycles and depth bound ---

    #[test]
    fn two_groups_trusting_each_other_terminate_without_looping() {
        // i-a (in sg-a) -> sg-b (trusts sg-a) -> i-b (in sg-b) -> sg-a
        // (trusts sg-b) -> i-a again: a genuine cycle in the traversal
        // graph, not just in the two groups' rules. Without the visited
        // set this would loop forever; with it, the second visit to sg-a
        // is skipped and the walk terminates.
        let sg_a = sg_trusting("sg-b");
        let sg_b = sg_trusting("sg-a");
        let i_a = instance_in(&["sg-a"]);
        let i_b = instance_in(&["sg-b"]);
        let graph = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-a", &sg_a),
                (&ResourceKind::AwsSecurityGroup, "sg-b", &sg_b),
                (&ResourceKind::AwsInstance, "i-a", &i_a),
                (&ResourceKind::AwsInstance, "i-b", &i_b),
            ]
            .into_iter(),
        );

        let reached = reachable_from(&graph, &ResourceKind::AwsSecurityGroup, "sg-a", 50);
        let ids: Vec<&str> = reached.iter().map(|r| r.cloud_id.as_str()).collect();
        assert_eq!(ids, vec!["i-a", "sg-b", "i-b"], "{reached:?}");
    }

    #[test]
    fn a_chain_longer_than_max_hops_is_cut_off() {
        let sg = sg_with_cidr("0.0.0.0/0");
        let worker = instance_in(&["sg-web"]);
        let graph = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        // The membership hop is the first hop past the start node; a cap of
        // 0 leaves no room to take it.
        let reached = reachable_from(&graph, &ResourceKind::AwsSecurityGroup, "sg-web", 0);
        assert!(reached.is_empty(), "{reached:?}");
    }
}
