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
//!
//! **Ports travel with the walk, not just resource identity.** Knowing a
//! resource is reachable isn't enough to ask whether a NACL agrees — that
//! needs to know *on which port*. A security-group *membership* edge
//! doesn't change the port: the group's own admitting rule already set it,
//! and every member inherits exactly that. A group-to-group *trust* edge
//! and a target-group *registration* edge are different: each is a new
//! gate with its own rule (or, for a target group, its own `port` field),
//! so the port set is *replaced*, not carried forward. [`PortSpec`] and
//! [`Reached::ports`] are that state; [`neighbors`] is where the
//! inherit-vs-replace decision actually happens, per edge kind.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use serde_json::Value;

use super::graph::{Graph, Node};
use super::relations::MEMBER_KINDS;
use crate::types::resource::ResourceKind;

/// Rule sources that mean "the public internet," not a general CIDR-overlap
/// judgment. Deliberately a literal match — `1.2.3.0/24` being "basically
/// public" is a call this does not make.
const INTERNET_CIDRS: &[&str] = &["0.0.0.0/0", "::/0"];

/// A protocol and port range a resource is reachable on, in the NACL API's
/// own protocol-*number* convention (`"-1"`, `"6"` for tcp, `"17"` for udp,
/// ...) — translated once, at the point a security-group rule is read
/// ([`port_spec_from_rule`]), so nothing downstream (including
/// `nacl::evaluate`) needs to translate security groups' protocol *names*
/// again.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortSpec {
    pub protocol: String,
    pub from: i64,
    pub to: i64,
}

/// One internet-facing rule on a security group: the literal CIDR
/// ([`INTERNET_CIDRS`]) that sources it, and the port it admits. A group
/// can have several — different ports, or the same port opened to both
/// `0.0.0.0/0` and `::/0` — so [`internet_facing_groups`] returns every one,
/// not just whether the group qualifies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryPoint {
    pub source_cidr: String,
    pub port: PortSpec,
}

/// Security groups in `graph` with at least one ingress rule sourced
/// directly from the public internet, and the specific entry point(s) each
/// one offers.
pub fn internet_facing_groups(graph: &Graph) -> BTreeMap<String, Vec<EntryPoint>> {
    graph
        .nodes_of_kind(&ResourceKind::AwsSecurityGroup)
        .filter_map(|sg| {
            let entries: BTreeSet<EntryPoint> = internet_facing_entry_points(sg);
            if entries.is_empty() {
                None
            } else {
                Some((sg.cloud_id.clone(), entries.into_iter().collect()))
            }
        })
        .collect()
}

fn internet_facing_entry_points(sg: &Node) -> BTreeSet<EntryPoint> {
    let mut out = BTreeSet::new();
    for rule in ingress_rules(sg) {
        let port = port_spec_from_rule(rule);
        for key in ["cidr_blocks", "ipv6_cidr_blocks"] {
            let cidrs = rule
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            for cidr in cidrs {
                if INTERNET_CIDRS.contains(&cidr) {
                    out.insert(EntryPoint {
                        source_cidr: cidr.to_string(),
                        port: port.clone(),
                    });
                }
            }
        }
    }
    out
}

/// Security groups elsewhere in the graph whose ingress cites `group_id` as
/// a trusted source, and the port(s) of the specific rule(s) that trust it —
/// not the group's other, unrelated rules. The mirror of [`Graph::referrers`]
/// one level up: not who belongs to the group, but who trusts it. See the
/// module docs for why this is a scan rather than an `EDGE_FIELDS` row.
fn groups_trusting(graph: &Graph, group_id: &str) -> BTreeMap<String, Vec<PortSpec>> {
    let mut out: BTreeMap<String, BTreeSet<PortSpec>> = BTreeMap::new();
    for sg in graph.nodes_of_kind(&ResourceKind::AwsSecurityGroup) {
        for rule in ingress_rules(sg) {
            let sources: Vec<&str> = rule
                .get("security_groups")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if sources.contains(&group_id) {
                out.entry(sg.cloud_id.clone())
                    .or_default()
                    .insert(port_spec_from_rule(rule));
            }
        }
    }
    out.into_iter()
        .map(|(id, ports)| (id, ports.into_iter().collect()))
        .collect()
}

fn ingress_rules(sg: &Node) -> impl Iterator<Item = &Value> {
    sg.attributes
        .get("ingress")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

/// A rule's protocol and port range, protocol translated to the NACL API's
/// number convention. Absent ports normalize to `0`, matching how
/// `collector::aws::security_group` itself represents an all-traffic
/// permission.
fn port_spec_from_rule(rule: &Value) -> PortSpec {
    let from = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
    let to = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
    let protocol = rule.get("protocol").and_then(Value::as_str).unwrap_or("-1");
    PortSpec {
        protocol: protocol_number(protocol),
        from,
        to,
    }
}

/// Security-group rules speak protocol *names* for the four well-known
/// protocols (verified against the SDK's own doc comment on
/// `IpPermission::ip_protocol`) and numbers for everything else; NACL rules
/// speak numbers exclusively. Anything already numeric (including `"-1"`)
/// passes through unchanged.
fn protocol_number(sg_protocol: &str) -> String {
    match sg_protocol {
        "tcp" => "6",
        "udp" => "17",
        "icmp" => "1",
        "icmpv6" => "58",
        other => other,
    }
    .to_string()
}

/// The port a target group forwards to, as a [`PortSpec`]. Defaulted to tcp
/// (`"6"`) — target groups don't declare their own protocol anywhere this
/// codebase collects yet (`collector::aws::target_group` normalizes only
/// `port`), and ALB/NLB target groups are overwhelmingly TCP-based even
/// when the listener speaks HTTP/HTTPS on top. A target group with no port
/// set (some `lambda`-type groups) produces the placeholder `0-0` range,
/// the same absent-numeric-field convention `target_group.rs` itself uses.
fn target_group_ports(node: &Node) -> Vec<PortSpec> {
    let port = node
        .attributes
        .get("port")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    vec![PortSpec {
        protocol: "6".to_string(),
        from: port,
        to: port,
    }]
}

/// The resources one hop reaches from `node`, dispatched by kind, and the
/// port each one is reached on. Each kind contributes the one or two edge
/// shapes that apply to it; nothing outside this list continues a chain.
fn neighbors(
    graph: &Graph,
    node: &Node,
    current_ports: &[PortSpec],
) -> Vec<(ResourceKind, String, Vec<PortSpec>)> {
    match node.kind {
        // Membership: the port doesn't change. The group's own admitting
        // rule already set it, and being "in" the group doesn't add a gate
        // of its own.
        ResourceKind::AwsSecurityGroup => MEMBER_KINDS
            .iter()
            .flat_map(|kind| {
                graph
                    .referrers(&node.cloud_id, kind)
                    .into_iter()
                    .map(|id| (kind.clone(), id, current_ports.to_vec()))
            })
            .collect(),

        // Identical logic for every member kind whose membership lives in a
        // flat `vpc_security_group_ids` field — true of all of `MEMBER_KINDS`
        // except `AwsLoadBalancer`, which uses a different field name and has
        // an extra hop below. Trust: a new rule, a new port set - replaces
        // `current_ports` rather than carrying it forward.
        ResourceKind::AwsInstance
        | ResourceKind::AwsLambdaFunction
        | ResourceKind::AwsDbInstance
        | ResourceKind::AwsEcsService => own_groups(node, "vpc_security_group_ids")
            .flat_map(|group_id| groups_trusting(graph, &group_id))
            .map(|(id, ports)| (ResourceKind::AwsSecurityGroup, id, ports))
            .collect(),

        ResourceKind::AwsLoadBalancer => {
            let trusting = own_groups(node, "security_groups")
                .flat_map(|group_id| groups_trusting(graph, &group_id))
                .map(|(id, ports)| (ResourceKind::AwsSecurityGroup, id, ports));
            // Registration, not membership - but nothing terminates at the
            // target group itself, so which ports it's tagged with here
            // doesn't matter; only the registered-instance hop below reads
            // the target group's own port.
            let target_groups = graph
                .referrers(&node.cloud_id, &ResourceKind::AwsLbTargetGroup)
                .into_iter()
                .map(|id| (ResourceKind::AwsLbTargetGroup, id, current_ports.to_vec()));
            trusting.chain(target_groups).collect()
        }

        // Registration: the target group's own port replaces whatever port
        // reached the ALB - very often a different one (TLS termination,
        // protocol translation).
        ResourceKind::AwsLbTargetGroup => {
            let ports = target_group_ports(node);
            node.attributes
                .get("targets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|id| (ResourceKind::AwsInstance, id.to_string(), ports.clone()))
                .collect()
        }

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
    /// The port(s) this specific resource is reached on — the port context
    /// in effect at the *last* hop into it, not a history of every port
    /// along the way. See the module docs for why only the last hop matters.
    pub ports: Vec<PortSpec>,
}

/// Every resource reachable from `start_id` within `max_hops`, however many
/// security-group, load-balancer, or target-group hops away, starting from
/// `start_ports` (the entry rule's own port(s) — see [`EntryPoint`]).
///
/// Plain BFS: a visited set keyed the same way [`Graph`]'s own nodes are,
/// so a cycle (two groups trusting each other) terminates instead of
/// looping. Deterministic by construction — [`Graph::referrers`] and
/// [`groups_trusting`] both iterate in sorted order and [`MEMBER_KINDS`]
/// is a fixed order, so [`neighbors`] always yields the same order and BFS
/// visits (and reports) resources in the same order every run.
///
/// The visited set means only *one* path (and its port context) is ever
/// reported per resource per call, even when several distinct paths reach
/// it — the same simplification the walk already made before ports existed.
pub fn reachable_from(
    graph: &Graph,
    start_kind: &ResourceKind,
    start_id: &str,
    start_ports: &[PortSpec],
    max_hops: usize,
) -> Vec<Reached> {
    let mut reached = Vec::new();
    let mut visited: HashSet<(ResourceKind, String)> = HashSet::new();
    let mut queue: VecDeque<(ResourceKind, String, Vec<String>, Vec<PortSpec>)> = VecDeque::new();

    visited.insert((start_kind.clone(), start_id.to_string()));
    queue.push_back((
        start_kind.clone(),
        start_id.to_string(),
        Vec::new(),
        start_ports.to_vec(),
    ));

    while let Some((kind, id, path, ports)) = queue.pop_front() {
        if path.len() >= max_hops {
            continue;
        }
        let Some(node) = graph.node(&kind, &id) else {
            continue;
        };

        for (next_kind, next_id, next_ports) in neighbors(graph, node, &ports) {
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
                ports: next_ports.clone(),
            });
            queue.push_back((next_kind, next_id, next_path, next_ports));
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

    fn target_group_with_port(lb_arn: &str, targets: &[&str], port: i64) -> Map<String, Value> {
        attrs(json!({"load_balancer_arns": [lb_arn], "targets": targets, "port": port}))
    }

    /// The `PortSpec` `sg_with_cidr`/`sg_trusting`'s rules produce, for
    /// assertions that check port propagation.
    fn tcp(from: i64, to: i64) -> PortSpec {
        PortSpec {
            protocol: "6".to_string(),
            from,
            to,
        }
    }

    // --- internet_facing_groups ---

    #[test]
    fn finds_a_group_with_an_ipv4_wildcard_rule() {
        let sg = sg_with_cidr("0.0.0.0/0");
        let graph = graph::build([(&ResourceKind::AwsSecurityGroup, "sg-web", &sg)].into_iter());
        let found = internet_facing_groups(&graph);
        assert_eq!(
            found.get("sg-web"),
            Some(&vec![EntryPoint {
                source_cidr: "0.0.0.0/0".to_string(),
                port: tcp(443, 443),
            }])
        );
    }

    #[test]
    fn finds_a_group_with_an_ipv6_wildcard_rule() {
        let sg = sg_with_ipv6_cidr("::/0");
        let graph = graph::build([(&ResourceKind::AwsSecurityGroup, "sg-web", &sg)].into_iter());
        let found = internet_facing_groups(&graph);
        assert_eq!(
            found.get("sg-web"),
            Some(&vec![EntryPoint {
                source_cidr: "::/0".to_string(),
                port: tcp(443, 443),
            }])
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

    #[test]
    fn a_rule_open_to_both_ip_families_is_two_distinct_entry_points() {
        let sg = attrs(json!({"ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": ["::/0"],
            "security_groups": [], "self": false,
        }]}));
        let graph = graph::build([(&ResourceKind::AwsSecurityGroup, "sg-web", &sg)].into_iter());
        let found = internet_facing_groups(&graph);
        assert_eq!(
            found.get("sg-web"),
            Some(&vec![
                EntryPoint {
                    source_cidr: "0.0.0.0/0".to_string(),
                    port: tcp(443, 443),
                },
                EntryPoint {
                    source_cidr: "::/0".to_string(),
                    port: tcp(443, 443),
                },
            ])
        );
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

        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-web",
            &[tcp(443, 443)],
            10,
        );
        assert_eq!(
            reached,
            vec![Reached {
                kind: ResourceKind::AwsInstance,
                cloud_id: "i-worker".to_string(),
                path: vec!["i-worker".to_string()],
                ports: vec![tcp(443, 443)],
            }]
        );
    }

    #[test]
    fn a_membership_hop_inherits_the_entry_ports_unchanged() {
        // The scenario the whole port-threading model exists to get right:
        // the group's own admitting rule (443) is what a member inherits,
        // not some property of "being a member."
        let sg = sg_with_cidr("0.0.0.0/0");
        let worker = instance_in(&["sg-web"]);
        let graph = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-web",
            &[tcp(443, 443)],
            10,
        );
        assert_eq!(reached[0].ports, vec![tcp(443, 443)]);
    }

    // --- reachable_from: registration chain ---

    #[test]
    fn reaches_a_target_group_instance_through_an_alb() {
        let sg = sg_with_cidr("0.0.0.0/0");
        let alb = lb_in(&["sg-web"]);
        let tg = target_group_with_port("arn:alb/1", &["i-app"], 8080);
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

        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-web",
            &[tcp(443, 443)],
            10,
        );
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

    #[test]
    fn a_registered_instance_is_reached_on_the_target_groups_own_port() {
        // The ALB is reached on 443 (TLS termination); the target group
        // forwards to 8080. The registered instance's port must be 8080,
        // not the port that got the internet to the ALB.
        let sg = sg_with_cidr("0.0.0.0/0");
        let alb = lb_in(&["sg-web"]);
        let tg = target_group_with_port("arn:alb/1", &["i-app"], 8080);
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

        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-web",
            &[tcp(443, 443)],
            10,
        );
        let app_reached = reached.iter().find(|r| r.cloud_id == "i-app").unwrap();
        assert_eq!(app_reached.ports, vec![tcp(8080, 8080)]);
    }

    #[test]
    fn a_target_group_with_no_port_set_reaches_its_target_on_the_placeholder_range() {
        let sg = sg_with_cidr("0.0.0.0/0");
        let alb = lb_in(&["sg-web"]);
        let tg = target_group("arn:alb/1", &["i-app"]); // no port field at all
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

        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-web",
            &[tcp(443, 443)],
            10,
        );
        let app_reached = reached.iter().find(|r| r.cloud_id == "i-app").unwrap();
        assert_eq!(app_reached.ports, vec![tcp(0, 0)]);
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

        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-web",
            &[tcp(443, 443)],
            10,
        );
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
        // sg-db trusts sg-app on 5432 (its own rule), not the 443 that got
        // the internet to the ALB, and not the target group's placeholder
        // port either - the trust hop is a fresh gate.
        assert_eq!(db_reached.ports, vec![tcp(5432, 5432)]);
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

        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-a",
            &[tcp(5432, 5432)],
            50,
        );
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
        let reached = reachable_from(
            &graph,
            &ResourceKind::AwsSecurityGroup,
            "sg-web",
            &[tcp(443, 443)],
            0,
        );
        assert!(reached.is_empty(), "{reached:?}");
    }
}
