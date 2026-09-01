//! The built-in relation catalog.
//!
//! Per `docs/SEMANTIC-DRIFT.md`, the open relation set has to stand on its own
//! rather than function as a teaser for a paid catalog.

use std::collections::BTreeSet;

use serde_json::Value;

use super::Relation;
use super::graph::{Graph, Node};
use super::nacl;
use super::reachability;
use crate::diff::rules::{explode_rules, rule_base};
use crate::types::resource::ResourceKind;

/// Members a rule referencing a security group can admit. An ALB's ENI, a
/// VPC-attached Lambda function, an RDS instance, and an `awsvpc`-mode ECS
/// service all carry whatever security groups they name, exactly like an EC2
/// instance carries `vpc_security_group_ids` — all of them are "who is in
/// this group," just discovered through different edge fields.
pub(crate) const MEMBER_KINDS: &[ResourceKind] = &[
    ResourceKind::AwsInstance,
    ResourceKind::AwsLoadBalancer,
    ResourceKind::AwsLambdaFunction,
    ResourceKind::AwsDbInstance,
    ResourceKind::AwsEcsService,
];

/// Security-group membership: a rule that trusts another group effectively
/// trusts whatever is *in* that group, and the group's own attributes say
/// nothing about that. "In" means any of [`MEMBER_KINDS`] that names the
/// group.
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
        //
        // Deliberately does *not* also require `AwsLoadBalancer`: that would
        // make this relation go fully unresolved for every subject in the
        // (very common) case of a stack with no load balancers at all — a
        // regression, not a correctness fix. The residual risk is narrower
        // than it looks: a referenced group that isn't declared at all is
        // already caught below (`Err` when `graph.node` misses), and a false
        // "membership grew" from an undeclared load balancer can only happen
        // when the *group* is declared here but the load balancer using it
        // lives in a different state file — narrower than the instance/network
        // split this guard was built for, since a security group made for one
        // load balancer is typically declared alongside it. Known, narrow,
        // and documented rather than solved with a second relation.
        &[ResourceKind::AwsInstance]
    }

    fn subject(&self) -> &[(ResourceKind, &str)] {
        &[(ResourceKind::AwsSecurityGroup, "ingress")]
    }

    /// Expand each group-sourced rule into one atom per member.
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

                for kind in MEMBER_KINDS {
                    for member in graph.referrers(source, kind) {
                        atoms.push(format!("{base}/member:{member}"));
                    }
                }
            }
        }

        // Sorted and deduplicated: neither rule order nor how AWS groups
        // sources into permissions is meaningful.
        atoms.sort();
        atoms.dedup();
        Ok(Value::Array(atoms.into_iter().map(Value::String).collect()))
    }

    fn via(&self, subject: &Node, _graph: &Graph) -> Vec<String> {
        referenced_groups(subject)
    }
}

/// The cloud IDs a subject's `ingress` rules trust by group reference.
fn referenced_groups(subject: &Node) -> Vec<String> {
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

/// Instance exposure: an instance's effective attack surface is the union of
/// its attached groups' ingress rules, and nothing on the instance itself
/// says what those rules currently are.
///
/// The mirror image of [`SgMembership`]: that relation resolves a group's
/// meaning from the instances that reference it; this one resolves an
/// instance's meaning from the groups it references. Same shape, opposite
/// direction — proving the trait generalizes past the one relation it was
/// designed for.
///
/// A rule added directly to an attached group in the console leaves the
/// instance's own `vpc_security_group_ids` untouched, so no field diff sees
/// it — the instance is more open than declared and nothing said so.
pub struct InstanceExposure;

impl Relation for InstanceExposure {
    fn name(&self) -> &str {
        "instance_exposure"
    }

    fn requires(&self) -> &[ResourceKind] {
        // Exposure is derived from the groups an instance is attached to; a
        // state file that declares no security groups is not an authority on
        // what those groups (declared elsewhere, or not at all) allow.
        &[ResourceKind::AwsSecurityGroup]
    }

    fn subject(&self) -> &[(ResourceKind, &str)] {
        &[(ResourceKind::AwsInstance, "vpc_security_group_ids")]
    }

    /// Union the ingress rules of every attached group into one atom set.
    ///
    /// Deliberately a set, not a multiset: two attached groups granting the
    /// same access contribute one atom, because "is this port reachable" does
    /// not care how many groups agree it is. Reuses `explode_rules`, the same
    /// atomization the behavioral pass uses for a single group's rules, so a
    /// rule the two passes would ever disagree about is a bug in one place,
    /// not two.
    fn expand(&self, subject: &Node, graph: &Graph) -> Result<Value, String> {
        let mut atoms: BTreeSet<String> = BTreeSet::new();

        let group_ids = subject
            .attributes
            .get("vpc_security_group_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);

        for group_id in group_ids {
            let Some(group) = graph.node(&ResourceKind::AwsSecurityGroup, group_id) else {
                // Attached to a group that isn't in this graph: same story as
                // a group trusting one that vanished — the honest report is
                // "the group is gone," made separately, not a confident claim
                // about this instance's exposure shrinking.
                return Err(format!(
                    "attached to security group `{group_id}`, which is not present"
                ));
            };
            let ingress = group.attributes.get("ingress").cloned().unwrap_or_default();
            atoms.extend(explode_rules(&ingress));
        }

        Ok(Value::Array(atoms.into_iter().map(Value::String).collect()))
    }

    fn via(&self, subject: &Node, _graph: &Graph) -> Vec<String> {
        let mut ids: Vec<String> = subject
            .attributes
            .get("vpc_security_group_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

/// How many hops [`InternetReachability`] will follow before giving up.
/// Chosen generously past the 6-hop three-tier chain `reachability`'s own
/// tests exercise (entry group -> ALB -> target group -> app instance ->
/// trusted group -> db instance) — a cutoff for a bounded walk, not a claim
/// about what depth is "normal."
const MAX_HOPS: usize = 12;

/// Internet reachability: whether the public internet can reach a declared
/// instance at all, however many security-group, load-balancer, or trust
/// hops away — and, where a network ACL governs the subject's own subnet,
/// whether the NACL actually lets that specific flow through.
///
/// The transitive generalization of [`InstanceExposure`]: that relation
/// reads only the rules on an instance's *directly* attached groups, so a
/// group's rule trusting another group (`security_groups: [sg-app]`) reads
/// as an opaque `sg:sg-app` atom — it says nothing about whether `sg-app`
/// itself traces back to the internet. This relation answers that question
/// by walking [`reachability::reachable_from`] from every internet-facing
/// group and checking whether the subject instance is among what's found.
///
/// **The NACL gate only ever narrows, and only when the graph being
/// expanded has NACL data for the subject's subnet at all.** A state file
/// that never declares `aws_network_acl`/`aws_default_network_acl` — most
/// accounts never touch NACLs beyond AWS's own wide-open default — has no
/// node to check against, so [`subnet_allows`] returns `None` and the chain
/// passes through exactly as it did before this gate existed. This carries
/// the same known, narrow, accepted-not-solved risk `SgMembership` already
/// documents for `AwsLoadBalancer`: an account with a real, restrictive
/// custom NACL that is *never* declared in Terraform at all could see a
/// declared/live mismatch that isn't genuine drift, because only the live
/// side ever has that NACL's real rules to evaluate. Narrower in practice
/// than it sounds — a team disciplined enough to lock down a custom NACL is
/// disproportionately likely to also manage it as code.
pub struct InternetReachability;

impl InternetReachability {
    /// Every distinct chain (entry group, then each hop, ending at the
    /// subject) from an internet-facing group to `subject` in `graph`,
    /// excluding any the subject's own subnet NACL actually blocks.
    fn chains(subject: &Node, graph: &Graph) -> Vec<Vec<String>> {
        let mut chains = Vec::new();
        for (entry, entry_points) in reachability::internet_facing_groups(graph) {
            for entry_point in &entry_points {
                let reached = reachability::reachable_from(
                    graph,
                    &ResourceKind::AwsSecurityGroup,
                    &entry,
                    std::slice::from_ref(&entry_point.port),
                    MAX_HOPS,
                );
                for r in reached {
                    if r.kind != subject.kind || r.cloud_id != subject.cloud_id {
                        continue;
                    }
                    if subnet_allows(subject, graph, &entry_point.source_cidr, &r.ports)
                        == Some(false)
                    {
                        continue;
                    }
                    let mut chain = vec![entry.clone()];
                    chain.extend(r.path.iter().cloned());
                    chains.push(chain);
                }
            }
        }
        chains
    }
}

/// The subnet(s) `subject` runs in, per its own kind's collected shape.
/// `AwsDbInstance` isn't included: RDS subnet resolution needs its own
/// `aws_db_subnet_group` collector, not yet built (see
/// `collector::aws::rds`'s module docs).
fn subject_subnet_ids(subject: &Node) -> Vec<String> {
    match subject.kind {
        ResourceKind::AwsInstance => subject
            .attributes
            .get("subnet_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| vec![id.to_string()])
            .unwrap_or_default(),
        ResourceKind::AwsLambdaFunction | ResourceKind::AwsEcsService => subject
            .attributes
            .get("subnet_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether `subject`'s own subnet(s) let a flow from `source_cidr` on any of
/// `ports` through, per the ingress rules of whichever `AwsNetworkAcl` node
/// in `graph` covers each subnet.
///
/// `None` means "no NACL data to check" — either the subject's kind doesn't
/// have subnet resolution yet, or `graph` has no `AwsNetworkAcl` node
/// covering any of its subnets at all — and the caller must treat that as
/// "don't filter," never as a denial. `Some(true)`/`Some(false)` means a
/// covering NACL was actually found and evaluated; reachable through *any*
/// one of the subject's subnets is enough, since which subnet a given
/// invocation actually lands in (for a multi-subnet Lambda function or ECS
/// service) isn't something this graph can predict.
fn subnet_allows(
    subject: &Node,
    graph: &Graph,
    source_cidr: &str,
    ports: &[reachability::PortSpec],
) -> Option<bool> {
    let subnet_ids = subject_subnet_ids(subject);
    if subnet_ids.is_empty() {
        return None;
    }

    let mut covered = false;
    for nacl in graph.nodes_of_kind(&ResourceKind::AwsNetworkAcl) {
        let nacl_subnets: Vec<&str> = nacl
            .attributes
            .get("subnet_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !subnet_ids
            .iter()
            .any(|id| nacl_subnets.contains(&id.as_str()))
        {
            continue;
        }
        covered = true;

        let ingress = nacl
            .attributes
            .get("ingress")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for port in ports {
            if nacl::evaluate(&ingress, source_cidr, &port.protocol, port.from, port.to)
                == nacl::Verdict::Allow
            {
                return Some(true);
            }
        }
    }

    if covered { Some(false) } else { None }
}

impl Relation for InternetReachability {
    fn name(&self) -> &str {
        "internet_reachability"
    }

    fn requires(&self) -> &[ResourceKind] {
        // Same reasoning as InstanceExposure: reachability is derived from
        // what groups allow, so a state file declaring none isn't
        // authoritative. Deliberately does not also require
        // AwsLoadBalancer or AwsLbTargetGroupAttachment, for the same
        // "network/compute split across state files" reason SgMembership
        // documents for AwsLoadBalancer — narrower than it looks, known,
        // and accepted rather than solved with more required kinds.
        &[ResourceKind::AwsSecurityGroup]
    }

    fn subject(&self) -> &[(ResourceKind, &str)] {
        // The same field InstanceExposure expands on AwsInstance — this
        // relation reinterprets it transitively (through membership,
        // registration, and trust) rather than reading only the attached
        // groups' own rules — and asks the same question of every other
        // kind that can carry a security group: "is this thing reachable
        // from the internet at all," which is the same claim shape
        // regardless of which kind answers yes. `chains()` reads
        // `subject.kind` rather than assuming `AwsInstance`, so no other
        // code needs to change as this list grows.
        &[
            (ResourceKind::AwsInstance, "vpc_security_group_ids"),
            (ResourceKind::AwsDbInstance, "vpc_security_group_ids"),
            (ResourceKind::AwsLambdaFunction, "vpc_security_group_ids"),
            (ResourceKind::AwsEcsService, "vpc_security_group_ids"),
        ]
    }

    /// One atom per distinct chain, not just per entry/target pair: a
    /// topology change (a different intermediate hop) is meaningful even
    /// when "reachable: yes" doesn't change, the same philosophy
    /// `SgMembership`'s atoms already follow. An instance no chain reaches
    /// expands to an empty set, not an error — unlike a dangling group
    /// reference, "not currently reachable" is a legitimate, resolvable
    /// state.
    fn expand(&self, subject: &Node, graph: &Graph) -> Result<Value, String> {
        let atoms: BTreeSet<String> = Self::chains(subject, graph)
            .into_iter()
            .map(|chain| format!("via:{}", chain.join(">")))
            .collect();
        Ok(Value::Array(atoms.into_iter().map(Value::String).collect()))
    }

    fn via(&self, subject: &Node, graph: &Graph) -> Vec<String> {
        let mut ids: BTreeSet<String> = BTreeSet::new();
        for chain in Self::chains(subject, graph) {
            ids.extend(chain);
        }
        ids.into_iter().collect()
    }
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

    // --- SgMembership: load balancers as members ---

    fn lb_in(sgs: Value) -> Map<String, Value> {
        attrs(json!({"security_groups": sgs}))
    }

    #[test]
    fn a_load_balancer_attached_to_the_trusted_group_is_a_member() {
        let web = sg_trusting("sg-app");
        let app = attrs(json!({"name": "app"}));
        let alb = lb_in(json!(["sg-app"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
            ]
            .into_iter(),
        );

        let effective = SgMembership.expand(&subject(&web), &g).unwrap();
        assert_eq!(effective, json!(["tcp/443-443/member:arn:alb/1"]));
    }

    #[test]
    fn membership_includes_instances_and_load_balancers_together() {
        let web = sg_trusting("sg-app");
        let app = attrs(json!({"name": "app"}));
        let worker = instance_in(json!(["sg-app"]));
        let alb = lb_in(json!(["sg-app"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
            ]
            .into_iter(),
        );

        let effective = SgMembership.expand(&subject(&web), &g).unwrap();
        assert_eq!(
            effective,
            json!([
                "tcp/443-443/member:arn:alb/1",
                "tcp/443-443/member:i-worker"
            ])
        );
    }

    #[test]
    fn a_load_balancer_attaching_to_a_trusted_group_widens_the_effective_set() {
        // The load-balancer-shaped version of the flagship scenario: same
        // rule, an ALB starts carrying the trusted group. Nothing on `web` or
        // `app` moved, so this can only surface through the semantic pass.
        let web = sg_trusting("sg-app");
        let app = attrs(json!({"name": "app"}));
        let alb = lb_in(json!(["sg-app"]));

        let declared = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
            ]
            .into_iter(),
        );
        let live = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
            ]
            .into_iter(),
        );

        let before = SgMembership.expand(&subject(&web), &declared).unwrap();
        let after = SgMembership.expand(&subject(&web), &live).unwrap();

        assert_eq!(before, json!([]));
        assert_eq!(after, json!(["tcp/443-443/member:arn:alb/1"]));
    }

    // --- InstanceExposure ---

    fn sg_with_ingress(rule: Value) -> Map<String, Value> {
        attrs(json!({"ingress": [rule]}))
    }

    fn cidr_rule(from: i64, to: i64, cidr: &str) -> Value {
        json!({
            "from_port": from, "to_port": to, "protocol": "tcp",
            "cidr_blocks": [cidr], "ipv6_cidr_blocks": [], "prefix_list_ids": [],
            "security_groups": [], "self": false,
        })
    }

    fn instance_subject(cloud_id: &str, attributes: &Map<String, Value>) -> Node {
        Node {
            kind: ResourceKind::AwsInstance,
            cloud_id: cloud_id.to_string(),
            attributes: attributes.clone(),
        }
    }

    #[test]
    fn exposure_is_the_union_of_attached_groups_rules() {
        let app = sg_with_ingress(cidr_rule(22, 22, "0.0.0.0/0"));
        let worker = instance_in(json!(["sg-app"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let effective = InstanceExposure
            .expand(&instance_subject("i-worker", &worker), &g)
            .unwrap();
        assert_eq!(effective, json!(["tcp/22-22/cidr:0.0.0.0/0"]));
    }

    #[test]
    fn a_rule_added_to_an_attached_group_widens_exposure() {
        // The scenario this relation exists for: the instance's own
        // `vpc_security_group_ids` never moves, but a group it belongs to
        // gains a rule in the console. No field diff on the instance sees it.
        let worker = instance_in(json!(["sg-app"]));
        let declared_app = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let live_app = attrs(json!({"ingress": [
            cidr_rule(443, 443, "0.0.0.0/0"),
            cidr_rule(22, 22, "0.0.0.0/0"),
        ]}));

        let declared = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-app", &declared_app),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );
        let live = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-app", &live_app),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let before = InstanceExposure
            .expand(&instance_subject("i-worker", &worker), &declared)
            .unwrap();
        let after = InstanceExposure
            .expand(&instance_subject("i-worker", &worker), &live)
            .unwrap();

        assert_ne!(before, after);
        assert_eq!(
            after,
            json!(["tcp/22-22/cidr:0.0.0.0/0", "tcp/443-443/cidr:0.0.0.0/0"])
        );
    }

    #[test]
    fn exposure_unions_rules_from_every_attached_group() {
        let app = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let db = sg_with_ingress(cidr_rule(5432, 5432, "10.0.0.0/8"));
        let worker = instance_in(json!(["sg-app", "sg-db"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
                (&ResourceKind::AwsSecurityGroup, "sg-db", &db),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let effective = InstanceExposure
            .expand(&instance_subject("i-worker", &worker), &g)
            .unwrap();
        assert_eq!(
            effective,
            json!([
                "tcp/443-443/cidr:0.0.0.0/0",
                "tcp/5432-5432/cidr:10.0.0.0/8"
            ])
        );
    }

    #[test]
    fn an_instance_with_no_groups_expands_to_nothing() {
        let worker = instance_in(json!([]));
        let g = graph::build(std::iter::empty());
        assert_eq!(
            InstanceExposure
                .expand(&instance_subject("i-worker", &worker), &g)
                .unwrap(),
            json!([])
        );
    }

    #[test]
    fn a_missing_attached_group_is_unresolvable_not_empty() {
        // Same discipline as SgMembership's missing-referenced-group case: an
        // instance attached to a group that has vanished gets an honest
        // "can't resolve," not a confident claim that its exposure shrank.
        let worker = instance_in(json!(["sg-gone"]));
        let g = graph::build(std::iter::empty());

        let err = InstanceExposure
            .expand(&instance_subject("i-worker", &worker), &g)
            .unwrap_err();
        assert!(err.contains("sg-gone"), "{err}");
    }

    #[test]
    fn via_lists_the_groups_an_instance_is_attached_to() {
        let worker = instance_in(json!(["sg-app", "sg-db"]));
        let g = graph::build(std::iter::empty());
        assert_eq!(
            InstanceExposure.via(&instance_subject("i-worker", &worker), &g),
            vec!["sg-app", "sg-db"]
        );
    }

    // --- InternetReachability ---

    fn tg_in(lb_arn: &str, targets: Value) -> Map<String, Value> {
        attrs(json!({"load_balancer_arns": [lb_arn], "targets": targets}))
    }

    #[test]
    fn an_instance_directly_in_an_internet_facing_group_is_reachable() {
        let web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let worker = instance_in(json!(["sg-web"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let effective = InternetReachability
            .expand(&instance_subject("i-worker", &worker), &g)
            .unwrap();
        assert_eq!(effective, json!(["via:sg-web>i-worker"]));
        assert_eq!(
            InternetReachability.via(&instance_subject("i-worker", &worker), &g),
            vec!["i-worker", "sg-web"]
        );
    }

    #[test]
    fn reaches_a_database_instance_through_a_web_and_app_tier() {
        // internet -> sg-web (entry) -> alb (member) -> tg (registered)
        // -> i-app (registered) -> sg-app (own group) -> sg-db (trusts
        // sg-app) -> i-db (member) — the same chain reachability.rs's own
        // flagship test proves the engine finds, now proven through the
        // actual Relation a user's report reads.
        let sg_web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let alb = lb_in(json!(["sg-web"]));
        let tg = tg_in("arn:alb/1", json!(["i-app"]));
        let app = instance_in(json!(["sg-app"]));
        let sg_app = attrs(json!({"name": "app"}));
        let sg_db = sg_trusting("sg-app");
        let db = instance_in(json!(["sg-db"]));

        let g = graph::build(
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

        let effective = InternetReachability
            .expand(&instance_subject("i-db", &db), &g)
            .unwrap();
        assert_eq!(
            effective,
            json!(["via:sg-web>arn:alb/1>arn:tg/1>i-app>sg-db>i-db"])
        );
    }

    #[test]
    fn a_new_live_target_group_registration_widens_reachability() {
        // Nothing about sg-web, the ALB, or i-app moves — only the live
        // target group's registered targets change. This is the scenario
        // Phase 3 exists to make provable: without declared-side
        // reconciliation, the declared side would have no `targets` at
        // all, so this would (wrongly) fire on every run instead of only
        // this one.
        let sg_web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let alb = lb_in(json!(["sg-web"]));
        let app = instance_in(json!([]));

        let declared_tg = tg_in("arn:alb/1", json!([]));
        let declared = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg_web),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
                (&ResourceKind::AwsLbTargetGroup, "arn:tg/1", &declared_tg),
                (&ResourceKind::AwsInstance, "i-app", &app),
            ]
            .into_iter(),
        );

        let live_tg = tg_in("arn:alb/1", json!(["i-app"]));
        let live = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg_web),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
                (&ResourceKind::AwsLbTargetGroup, "arn:tg/1", &live_tg),
                (&ResourceKind::AwsInstance, "i-app", &app),
            ]
            .into_iter(),
        );

        let before = InternetReachability
            .expand(&instance_subject("i-app", &app), &declared)
            .unwrap();
        let after = InternetReachability
            .expand(&instance_subject("i-app", &app), &live)
            .unwrap();

        assert_eq!(before, json!([]));
        assert_eq!(after, json!(["via:sg-web>arn:alb/1>arn:tg/1>i-app"]));
    }

    #[test]
    fn an_instance_with_no_path_from_the_internet_expands_to_nothing() {
        let web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let isolated = attrs(json!({"name": "isolated"}));
        let worker = instance_in(json!(["sg-isolated"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsSecurityGroup, "sg-isolated", &isolated),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let effective = InternetReachability
            .expand(&instance_subject("i-worker", &worker), &g)
            .unwrap();
        assert_eq!(effective, json!([]));
        assert!(
            InternetReachability
                .via(&instance_subject("i-worker", &worker), &g)
                .is_empty()
        );
    }

    #[test]
    fn a_graph_with_no_internet_facing_group_reports_nothing_reachable() {
        let private = sg_with_ingress(cidr_rule(443, 443, "10.0.0.0/8"));
        let worker = instance_in(json!(["sg-private"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-private", &private),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
            ]
            .into_iter(),
        );

        let effective = InternetReachability
            .expand(&instance_subject("i-worker", &worker), &g)
            .unwrap();
        assert_eq!(effective, json!([]));
    }

    // --- Lambda/RDS/ECS as members and as InternetReachability subjects ---

    fn subject_of(kind: ResourceKind, cloud_id: &str, attributes: &Map<String, Value>) -> Node {
        Node {
            kind,
            cloud_id: cloud_id.to_string(),
            attributes: attributes.clone(),
        }
    }

    #[test]
    fn an_rds_instance_attached_to_the_trusted_group_is_a_member() {
        // Same shape as the load-balancer case: a member kind other than
        // AwsInstance, discovered through MEMBER_KINDS with no other code
        // change.
        let web = sg_trusting("sg-app");
        let app = attrs(json!({"name": "app"}));
        let db = instance_in(json!(["sg-app"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &app),
                (&ResourceKind::AwsDbInstance, "db-ABCDEF", &db),
            ]
            .into_iter(),
        );

        let effective = SgMembership.expand(&subject(&web), &g).unwrap();
        assert_eq!(effective, json!(["tcp/443-443/member:db-ABCDEF"]));
    }

    #[test]
    fn a_database_instance_directly_in_an_internet_facing_group_is_reachable() {
        // Proves AwsDbInstance as a real InternetReachability subject, not
        // just a hop something else passes through.
        let web = sg_with_ingress(cidr_rule(5432, 5432, "0.0.0.0/0"));
        let db = instance_in(json!(["sg-web"]));
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsDbInstance, "db-ABCDEF", &db),
            ]
            .into_iter(),
        );

        let subject = subject_of(ResourceKind::AwsDbInstance, "db-ABCDEF", &db);
        let effective = InternetReachability.expand(&subject, &g).unwrap();
        assert_eq!(effective, json!(["via:sg-web>db-ABCDEF"]));
    }

    #[test]
    fn reaches_an_rds_instance_through_a_web_and_app_tier() {
        // The flagship chain, terminating at a real AwsDbInstance instead of
        // a plain AwsInstance standing in for "the database."
        let sg_web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let alb = lb_in(json!(["sg-web"]));
        let tg = tg_in("arn:alb/1", json!(["i-app"]));
        let app = instance_in(json!(["sg-app"]));
        let sg_app = attrs(json!({"name": "app"}));
        let sg_db = sg_trusting("sg-app");
        let db = instance_in(json!(["sg-db"]));

        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg_web),
                (&ResourceKind::AwsLoadBalancer, "arn:alb/1", &alb),
                (&ResourceKind::AwsLbTargetGroup, "arn:tg/1", &tg),
                (&ResourceKind::AwsInstance, "i-app", &app),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &sg_app),
                (&ResourceKind::AwsSecurityGroup, "sg-db", &sg_db),
                (&ResourceKind::AwsDbInstance, "db-ABCDEF", &db),
            ]
            .into_iter(),
        );

        let subject = subject_of(ResourceKind::AwsDbInstance, "db-ABCDEF", &db);
        let effective = InternetReachability.expand(&subject, &g).unwrap();
        assert_eq!(
            effective,
            json!(["via:sg-web>arn:alb/1>arn:tg/1>i-app>sg-db>db-ABCDEF"])
        );
    }

    // --- InternetReachability: NACL gate ---

    fn instance_in_subnet(sgs: Value, subnet_id: &str) -> Map<String, Value> {
        attrs(json!({"vpc_security_group_ids": sgs, "subnet_id": subnet_id}))
    }

    fn nacl_rule(
        rule_no: i64,
        action: &str,
        protocol: &str,
        cidr: &str,
        from: i64,
        to: i64,
    ) -> Value {
        json!({
            "rule_no": rule_no, "action": action, "protocol": protocol,
            "cidr_block": cidr, "ipv6_cidr_block": "",
            "from_port": from, "to_port": to,
            "icmp_type": 0, "icmp_code": 0,
        })
    }

    fn nacl_with_ingress(subnet_ids: Value, rule: Value) -> Map<String, Value> {
        attrs(json!({"subnet_ids": subnet_ids, "ingress": [rule], "egress": []}))
    }

    #[test]
    fn a_denying_nacl_on_the_subjects_subnet_blocks_an_otherwise_reachable_instance() {
        let web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let worker = instance_in_subnet(json!(["sg-web"]), "subnet-a");
        let nacl = nacl_with_ingress(
            json!(["subnet-a"]),
            nacl_rule(100, "deny", "6", "0.0.0.0/0", 443, 443),
        );
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
                (&ResourceKind::AwsNetworkAcl, "acl-1", &nacl),
            ]
            .into_iter(),
        );

        let subject = instance_subject("i-worker", &worker);
        let effective = InternetReachability.expand(&subject, &g).unwrap();
        assert_eq!(
            effective,
            json!([]),
            "the NACL denies port 443, so no chain survives"
        );
    }

    #[test]
    fn an_allowing_nacl_on_the_subjects_subnet_keeps_the_chain() {
        let web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let worker = instance_in_subnet(json!(["sg-web"]), "subnet-a");
        let nacl = nacl_with_ingress(
            json!(["subnet-a"]),
            nacl_rule(100, "allow", "6", "0.0.0.0/0", 443, 443),
        );
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
                (&ResourceKind::AwsNetworkAcl, "acl-1", &nacl),
            ]
            .into_iter(),
        );

        let subject = instance_subject("i-worker", &worker);
        let effective = InternetReachability.expand(&subject, &g).unwrap();
        assert_eq!(effective, json!(["via:sg-web>i-worker"]));
    }

    #[test]
    fn a_nacl_loosening_outside_terraform_widens_reachability_with_nothing_on_the_sg_changing() {
        // The scenario ARCHITECTURE.md motivates this whole gate for: a
        // security-group rule can be declared correctly and still not
        // matter if a NACL blocks it. Nothing about sg-web or i-worker
        // moves - only the live NACL's rule set does.
        let web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let worker = instance_in_subnet(json!(["sg-web"]), "subnet-a");

        let declared_nacl = nacl_with_ingress(
            json!(["subnet-a"]),
            nacl_rule(100, "deny", "6", "0.0.0.0/0", 443, 443),
        );
        let declared = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
                (&ResourceKind::AwsNetworkAcl, "acl-1", &declared_nacl),
            ]
            .into_iter(),
        );

        let live_nacl = nacl_with_ingress(
            json!(["subnet-a"]),
            nacl_rule(100, "allow", "6", "0.0.0.0/0", 443, 443),
        );
        let live = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsInstance, "i-worker", &worker),
                (&ResourceKind::AwsNetworkAcl, "acl-1", &live_nacl),
            ]
            .into_iter(),
        );

        let subject = instance_subject("i-worker", &worker);
        let before = InternetReachability.expand(&subject, &declared).unwrap();
        let after = InternetReachability.expand(&subject, &live).unwrap();

        assert_eq!(before, json!([]));
        assert_eq!(after, json!(["via:sg-web>i-worker"]));
    }

    #[test]
    fn reachable_through_any_one_of_a_functions_several_subnets() {
        // subnet-a's NACL denies; subnet-b's allows. The function is still
        // reachable, because some invocations land in subnet-b - which
        // subnet a given invocation actually uses isn't something the
        // graph can predict.
        let web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        let function = attrs(json!({
            "vpc_security_group_ids": ["sg-web"],
            "subnet_ids": ["subnet-a", "subnet-b"],
        }));
        let nacl_a = nacl_with_ingress(
            json!(["subnet-a"]),
            nacl_rule(100, "deny", "6", "0.0.0.0/0", 443, 443),
        );
        let nacl_b = nacl_with_ingress(
            json!(["subnet-b"]),
            nacl_rule(100, "allow", "6", "0.0.0.0/0", 443, 443),
        );
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsLambdaFunction, "my-function", &function),
                (&ResourceKind::AwsNetworkAcl, "acl-a", &nacl_a),
                (&ResourceKind::AwsNetworkAcl, "acl-b", &nacl_b),
            ]
            .into_iter(),
        );

        let subject = subject_of(ResourceKind::AwsLambdaFunction, "my-function", &function);
        let effective = InternetReachability.expand(&subject, &g).unwrap();
        assert_eq!(effective, json!(["via:sg-web>my-function"]));
    }

    #[test]
    fn rds_subjects_are_never_nacl_gated_pending_subnet_group_support() {
        // Even a deny-everything NACL has nothing to match against: an
        // AwsDbInstance subject carries no subnet_ids yet (needs its own
        // aws_db_subnet_group collector - see collector::aws::rds).
        let web = sg_with_ingress(cidr_rule(5432, 5432, "0.0.0.0/0"));
        let db = instance_in(json!(["sg-web"]));
        let nacl = nacl_with_ingress(
            json!(["subnet-a"]),
            nacl_rule(100, "deny", "-1", "0.0.0.0/0", 0, 0),
        );
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &web),
                (&ResourceKind::AwsDbInstance, "db-ABCDEF", &db),
                (&ResourceKind::AwsNetworkAcl, "acl-a", &nacl),
            ]
            .into_iter(),
        );

        let subject = subject_of(ResourceKind::AwsDbInstance, "db-ABCDEF", &db);
        let effective = InternetReachability.expand(&subject, &g).unwrap();
        assert_eq!(effective, json!(["via:sg-web>db-ABCDEF"]));
    }

    /// A group trusting `source` on a port distinct from `sg_trusting`'s
    /// (443, the same value the flagship entry rules in this module use) -
    /// so a test can tell "the entry's port leaked through" apart from
    /// "the trust hop's own port was correctly used."
    fn sg_trusting_on(source: &str, port: i64) -> Map<String, Value> {
        attrs(json!({"ingress": [{
            "from_port": port, "to_port": port, "protocol": "tcp",
            "cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [],
            "security_groups": [source], "self": false,
        }]}))
    }

    #[test]
    fn the_nacl_check_at_the_end_of_a_chain_uses_the_final_hops_port_not_the_entrys() {
        // internet enters sg-web on 443; the trust hop into sg-db happens
        // on 5432 (sg-db's own rule). The database's subnet NACL must be
        // checked against 5432, not 443 - a NACL that allows 5432 but
        // would deny 443 proves which one actually got used.
        let sg_web = sg_with_ingress(cidr_rule(443, 443, "0.0.0.0/0"));
        // i-app is a direct member of sg-web (reached at 443) and also
        // carries sg-app, whose trust relationship with sg-db is what
        // matters here - no ALB/target-group hop needed to make the point.
        let app = instance_in(json!(["sg-web", "sg-app"]));
        let sg_app = attrs(json!({"name": "app"}));
        let sg_db = sg_trusting_on("sg-app", 5432);
        let db = instance_in_subnet(json!(["sg-db"]), "subnet-db");

        let nacl = nacl_with_ingress(
            json!(["subnet-db"]),
            nacl_rule(100, "allow", "6", "0.0.0.0/0", 5432, 5432),
        );
        let g = graph::build(
            [
                (&ResourceKind::AwsSecurityGroup, "sg-web", &sg_web),
                (&ResourceKind::AwsInstance, "i-app", &app),
                (&ResourceKind::AwsSecurityGroup, "sg-app", &sg_app),
                (&ResourceKind::AwsSecurityGroup, "sg-db", &sg_db),
                (&ResourceKind::AwsInstance, "i-db", &db),
                (&ResourceKind::AwsNetworkAcl, "acl-db", &nacl),
            ]
            .into_iter(),
        );

        let subject = instance_subject("i-db", &db);
        let effective = InternetReachability.expand(&subject, &g).unwrap();
        assert_eq!(effective, json!(["via:sg-web>i-app>sg-db>i-db"]));
    }
}
