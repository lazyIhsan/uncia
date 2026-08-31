//! Semantic-diff tests: drift where the declared and live values are
//! byte-identical but the meaning is not.
//!
//! These go through `diff::compare` — both passes — rather than the semantic
//! pass alone, because two of the three guards are properties of how the passes
//! interact, and testing the semantic half in isolation would assert something
//! users never experience.
//!
//! Layers 1-3 of the plan in `docs/SEMANTIC-DRIFT.md`. Layer 4, the end-to-end
//! replay of the worked example against real captured bytes, lives in
//! `tests/collector_replay.rs` alongside the collectors it replays through.

use serde_json::{Map, Value, json};

use uncia::diff::compare;
use uncia::{
    Drift, DriftKind, DriftReport, LiveResource, Resource, ResourceId, ResourceKind, Severity,
};

fn attrs(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

/// A security group whose ingress trusts `trusts` on 443.
fn sg_attrs(id: &str, trusts: &[&str]) -> Value {
    json!({
        "id": id, "name": id, "description": "d", "vpc_id": "vpc-1", "tags": {},
        "ingress": [{
            "from_port": 443, "to_port": 443, "protocol": "tcp",
            "cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [],
            "security_groups": trusts, "self": false,
        }],
        "egress": [],
    })
}

fn instance_attrs(id: &str, sgs: &[&str]) -> Value {
    json!({
        "id": id, "instance_type": "t3.micro", "ami": "ami-1", "tags": {},
        "vpc_security_group_ids": sgs, "iam_instance_profile": "",
        "metadata_options": [{
            "http_endpoint": "enabled", "http_tokens": "required",
            "http_put_response_hop_limit": 1, "instance_metadata_tags": "disabled",
        }],
    })
}

fn declared(address: &str, kind: ResourceKind, values: Value) -> Resource {
    Resource {
        id: ResourceId(address.to_string()),
        kind,
        attributes: attrs(values),
    }
}

fn live(cloud_id: &str, kind: ResourceKind, values: Value) -> LiveResource {
    LiveResource {
        cloud_id: cloud_id.to_string(),
        kind,
        attributes: attrs(values),
    }
}

fn declared_sg(address: &str, id: &str, trusts: &[&str]) -> Resource {
    declared(
        address,
        ResourceKind::AwsSecurityGroup,
        sg_attrs(id, trusts),
    )
}

fn live_sg(id: &str, trusts: &[&str]) -> LiveResource {
    live(id, ResourceKind::AwsSecurityGroup, sg_attrs(id, trusts))
}

/// A security group whose ingress allows `port` from `cidr` — a literal
/// rule, not a group reference, for `instance_exposure` scenarios.
fn sg_open_attrs(id: &str, ports: &[i64]) -> Value {
    let ingress: Vec<Value> = ports
        .iter()
        .map(|p| {
            json!({
                "from_port": p, "to_port": p, "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [], "prefix_list_ids": [],
                "security_groups": [], "self": false,
            })
        })
        .collect();
    json!({
        "id": id, "name": id, "description": "d", "vpc_id": "vpc-1", "tags": {},
        "ingress": ingress, "egress": [],
    })
}

fn declared_sg_open(address: &str, id: &str, ports: &[i64]) -> Resource {
    declared(
        address,
        ResourceKind::AwsSecurityGroup,
        sg_open_attrs(id, ports),
    )
}

fn live_sg_open(id: &str, ports: &[i64]) -> LiveResource {
    live(id, ResourceKind::AwsSecurityGroup, sg_open_attrs(id, ports))
}

fn declared_instance(address: &str, id: &str, sgs: &[&str]) -> Resource {
    declared(address, ResourceKind::AwsInstance, instance_attrs(id, sgs))
}

fn live_instance(id: &str, sgs: &[&str]) -> LiveResource {
    live(id, ResourceKind::AwsInstance, instance_attrs(id, sgs))
}

fn live_lb(arn: &str, sgs: &[&str]) -> LiveResource {
    live(
        arn,
        ResourceKind::AwsLoadBalancer,
        json!({"id": arn, "security_groups": sgs}),
    )
}

fn declared_lb(address: &str, arn: &str, sgs: &[&str]) -> Resource {
    declared(
        address,
        ResourceKind::AwsLoadBalancer,
        json!({"id": arn, "security_groups": sgs}),
    )
}

/// A declared `aws_lb_target_group`. No `targets` here — Terraform has no
/// such inline argument; registration is `declared_attachment` below,
/// reconciled in by `diff::target_attachments::TargetAttachments`.
fn declared_tg(address: &str, arn: &str, lb_arn: &str) -> Resource {
    declared(
        address,
        ResourceKind::AwsLbTargetGroup,
        json!({"id": arn, "load_balancer_arns": [lb_arn]}),
    )
}

fn live_tg(arn: &str, lb_arn: &str, targets: &[&str]) -> LiveResource {
    live(
        arn,
        ResourceKind::AwsLbTargetGroup,
        json!({"id": arn, "load_balancer_arns": [lb_arn], "targets": targets}),
    )
}

fn declared_attachment(address: &str, target_group_arn: &str, target_id: &str) -> Resource {
    declared(
        address,
        ResourceKind::AwsLbTargetGroupAttachment,
        json!({"target_group_arn": target_group_arn, "target_id": target_id}),
    )
}

/// The scenario the whole feature exists for, from `docs/ARCHITECTURE.md`:
/// `web` trusts `sg-app` on 443, and someone attaches `sg-app` to an instance
/// that is in no state file. Every field on every declared resource is
/// byte-identical, so the behavioral pass is correct to stay silent.
#[test]
fn an_undeclared_instance_joining_a_trusted_group_is_drift() {
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_instance("i-worker", &["sg-app"]),
        // Launched in the console, attached to the trusted group.
        live_instance("i-console", &["sg-app"]),
    ];

    let report = compare(&declared, &live);

    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
    let drift = &report.drifts[0];
    assert_eq!(drift.resource.0, "aws_security_group.web");
    assert_eq!(
        drift.severity,
        Severity::High,
        "membership grew: more machines can reach 443"
    );

    let DriftKind::SemanticChanged {
        field,
        relation,
        declared_effective,
        actual_effective,
        via,
    } = &drift.kind
    else {
        panic!("expected SemanticChanged, got {:?}", drift.kind);
    };
    assert_eq!(field, "ingress");
    assert_eq!(relation, "sg_membership");
    assert_eq!(via, &["sg-app"], "the path that explains the finding");
    assert_eq!(declared_effective, &json!(["tcp/443-443/member:i-worker"]));
    assert_eq!(
        actual_effective,
        &json!([
            "tcp/443-443/member:i-console",
            "tcp/443-443/member:i-worker"
        ])
    );
}

#[test]
fn matching_membership_is_not_drift() {
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_instance("i-worker", &["sg-app"]),
    ];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
}

// --- Guard 1: disjointness with behavioral drift ---

#[test]
fn a_field_that_drifted_literally_gets_only_the_behavioral_finding() {
    // `web`'s own ingress changed, so this is behavioral drift by definition.
    // Semantic drift *means* the field is unchanged; reporting both on the same
    // resource and field would be reporting the same thing twice.
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg("sg-web", &["sg-other"]),
        live_sg("sg-app", &[]),
        live_sg("sg-other", &[]),
        live_instance("i-worker", &["sg-app"]),
        live_instance("i-console", &["sg-app"]),
    ];

    let report = compare(&declared, &live);

    let on_web: Vec<_> = report
        .drifts
        .iter()
        .filter(|d| d.resource.0 == "aws_security_group.web")
        .collect();
    assert_eq!(on_web.len(), 1, "{on_web:?}");
    assert!(
        matches!(&on_web[0].kind, DriftKind::FieldChanged { field, .. } if field == "ingress"),
        "{:?}",
        on_web[0].kind
    );
}

#[test]
fn a_cause_that_drifted_behaviorally_does_not_suppress_the_consequence() {
    // A declared instance was detached from `sg-app` outside Terraform. That is
    // behavioral drift on the instance *and* a meaning change for `web`, whose
    // own rules never moved. Reporting only the cause would hide the blast
    // radius; the two are linked by `via`, not deduplicated.
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_instance("i-worker", &[]),
    ];

    let report = compare(&declared, &live);

    assert!(
        report.drifts.iter().any(|d| {
            d.resource.0 == "aws_instance.worker"
                && matches!(&d.kind, DriftKind::FieldChanged { field, .. } if field == "vpc_security_group_ids")
        }),
        "the cause: {:?}",
        report.drifts
    );
    assert!(
        report.drifts.iter().any(|d| {
            d.resource.0 == "aws_security_group.web"
                && matches!(d.kind, DriftKind::SemanticChanged { .. })
        }),
        "the consequence: {:?}",
        report.drifts
    );
}

// --- Guard 2: authority ---

#[test]
fn a_state_file_declaring_no_instances_reports_no_membership_drift() {
    // The load-bearing guard. Network and compute in separate state files is a
    // common layout; without this, the network state file would compare a real
    // live membership against a vacuous empty one and fire on every
    // group-sourced rule in the account.
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_instance("i-owned-elsewhere", &["sg-app"]),
        live_instance("i-also-elsewhere", &["sg-app"]),
    ];

    let report = compare(&declared, &live);

    assert!(
        report.drifts.is_empty(),
        "must not fabricate drift from a non-authoritative state file: {:?}",
        report.drifts
    );
    assert_eq!(report.unresolved.len(), 1, "{:?}", report.unresolved);
    let unresolved = &report.unresolved[0];
    assert_eq!(unresolved.relation, "sg_membership");
    assert!(
        unresolved.resource.is_none(),
        "the state file is not authoritative, not any one resource"
    );
    assert!(
        unresolved.reason.contains("aws_instance"),
        "{}",
        unresolved.reason
    );
}

// --- Guard 3: severity from blast-radius direction ---

#[test]
fn a_shrinking_membership_is_low_severity() {
    // Fewer machines can reach the port than declared. Still drift — still
    // worth reporting — but not the alarming direction.
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
        declared_instance("aws_instance.second", "i-second", &["sg-app"]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_instance("i-worker", &["sg-app"]),
        live_instance("i-second", &["sg-app"]),
    ];
    // Both declared instances are live, so nothing drifts.
    assert!(compare(&declared, &live).drifts.is_empty());

    // Now one of them is gone from the account entirely.
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_instance("i-worker", &["sg-app"]),
    ];
    let report = compare(&declared, &live);

    let semantic: Vec<_> = report
        .drifts
        .iter()
        .filter(|d| matches!(d.kind, DriftKind::SemanticChanged { .. }))
        .collect();
    assert_eq!(semantic.len(), 1, "{:?}", report.drifts);
    assert_eq!(semantic[0].severity, Severity::Low);
}

// --- Unresolvable subjects ---

#[test]
fn a_deleted_trusted_group_is_unresolved_not_a_narrowing_finding() {
    // `web` trusts a group that no longer exists. The honest report is "the
    // group is gone" — which the behavioral pass makes on `app` — not a
    // confident claim that `web`'s membership shrank.
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_instance("i-worker", &[]),
    ];

    let report = compare(&declared, &live);

    assert!(
        !report
            .drifts
            .iter()
            .any(|d| matches!(d.kind, DriftKind::SemanticChanged { .. })),
        "{:?}",
        report.drifts
    );
    let unresolved = report
        .unresolved
        .iter()
        .find(|u| {
            u.resource
                .as_ref()
                .is_some_and(|r| r.0 == "aws_security_group.web")
        })
        .expect("expected an Unresolved for web");
    assert_eq!(unresolved.relation, "sg_membership");
    assert!(
        unresolved.reason.contains("sg-app"),
        "{}",
        unresolved.reason
    );
}

#[test]
fn a_subject_missing_from_the_account_is_not_semantically_checked() {
    // Already reported as Missing by the behavioral pass; there is no live
    // resource to resolve a meaning against.
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg("sg-app", &[]),
        live_instance("i-worker", &["sg-app"]),
    ];

    let report = compare(&declared, &live);

    assert!(
        report
            .drifts
            .iter()
            .any(|d| d.resource.0 == "aws_security_group.web"
                && matches!(d.kind, DriftKind::Missing)),
        "{:?}",
        report.drifts
    );
    assert!(
        !report
            .drifts
            .iter()
            .any(|d| matches!(d.kind, DriftKind::SemanticChanged { .. })),
        "{:?}",
        report.drifts
    );
}

#[test]
fn groups_with_no_group_sourced_rules_are_never_reported() {
    // A group whose rules are all literal CIDRs has no membership to resolve,
    // so it must stay silent no matter what the account contains.
    let declared = [
        declared(
            "aws_security_group.web",
            ResourceKind::AwsSecurityGroup,
            json!({
                "id": "sg-web", "name": "web", "description": "d", "vpc_id": "vpc-1",
                "tags": {},
                "ingress": [{
                    "from_port": 443, "to_port": 443, "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
                    "prefix_list_ids": [], "security_groups": [], "self": false,
                }],
                "egress": [],
            }),
        ),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live(
            "sg-web",
            ResourceKind::AwsSecurityGroup,
            json!({
                "id": "sg-web", "name": "web", "description": "d", "vpc_id": "vpc-1",
                "tags": {},
                "ingress": [{
                    "from_port": 443, "to_port": 443, "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
                    "prefix_list_ids": [], "security_groups": [], "self": false,
                }],
                "egress": [],
            }),
        ),
        live_sg("sg-app", &[]),
        live_instance("i-worker", &["sg-app"]),
        live_instance("i-console", &["sg-app"]),
    ];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
}

// --- InstanceExposure: the mirror-image relation ---
//
// Where `sg_membership` resolves a group's meaning from the instances that
// reference it, `instance_exposure` resolves an instance's meaning from the
// groups it references — proving the guards and the trait generalize past
// the one relation they were built for.

/// Unlike the `sg_membership` flagship (where the undeclared party is a
/// live-only instance, so nothing on the group side ever drifts), widening an
/// already-declared group's rules is unavoidably *also* behavioral drift on
/// that group — there is no way to change a declared group's live rules
/// without it. So this is the "a cause that drifted behaviorally does not
/// suppress the consequence" shape from the start, not the single-finding
/// shape: the group's own drift is the cause, and every instance attached to
/// it gets the consequence.
#[test]
fn a_console_rule_on_an_attached_group_reads_as_exposure_drift_on_the_instance() {
    let declared = [
        declared_sg_open("aws_security_group.app", "sg-app", &[443]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg_open("sg-app", &[443, 22]),
        live_instance("i-worker", &["sg-app"]),
    ];

    let report = compare(&declared, &live);

    assert!(
        report.drifts.iter().any(|d| {
            d.resource.0 == "aws_security_group.app"
                && matches!(&d.kind, DriftKind::FieldChanged { field, .. } if field == "ingress")
        }),
        "the cause: {:?}",
        report.drifts
    );

    let consequence = report
        .drifts
        .iter()
        .find(|d| d.resource.0 == "aws_instance.worker")
        .expect("expected an exposure finding on the instance");
    assert_eq!(
        consequence.severity,
        Severity::High,
        "more ports reachable than declared"
    );

    let DriftKind::SemanticChanged {
        field,
        relation,
        declared_effective,
        actual_effective,
        via,
    } = &consequence.kind
    else {
        panic!("expected SemanticChanged, got {:?}", consequence.kind);
    };
    assert_eq!(field, "vpc_security_group_ids");
    assert_eq!(relation, "instance_exposure");
    assert_eq!(via, &["sg-app"], "the path that explains the finding");
    assert_eq!(declared_effective, &json!(["tcp/443-443/cidr:0.0.0.0/0"]));
    assert_eq!(
        actual_effective,
        &json!(["tcp/22-22/cidr:0.0.0.0/0", "tcp/443-443/cidr:0.0.0.0/0"])
    );
}

#[test]
fn matching_exposure_is_not_drift() {
    let declared = [
        declared_sg_open("aws_security_group.app", "sg-app", &[443]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg_open("sg-app", &[443]),
        live_instance("i-worker", &["sg-app"]),
    ];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
}

#[test]
fn an_instances_own_group_list_changing_gets_only_the_behavioral_finding() {
    // `worker`'s own `vpc_security_group_ids` changed, so this is behavioral
    // drift by definition; reporting a semantic finding for the same subject
    // and field would be reporting the same thing twice.
    let declared = [
        declared_sg_open("aws_security_group.app", "sg-app", &[443]),
        declared_sg_open("aws_security_group.extra", "sg-extra", &[22]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg_open("sg-app", &[443]),
        live_sg_open("sg-extra", &[22]),
        live_instance("i-worker", &["sg-app", "sg-extra"]),
    ];

    let report = compare(&declared, &live);

    let on_worker: Vec<_> = report
        .drifts
        .iter()
        .filter(|d| d.resource.0 == "aws_instance.worker")
        .collect();
    assert_eq!(on_worker.len(), 1, "{on_worker:?}");
    assert!(
        matches!(&on_worker[0].kind, DriftKind::FieldChanged { field, .. } if field == "vpc_security_group_ids"),
        "{:?}",
        on_worker[0].kind
    );
}

#[test]
fn a_state_file_declaring_no_security_groups_reports_no_exposure_drift() {
    // The load-bearing guard, mirrored: a state file that declares instances
    // but no security groups is not an authority on what those groups (owned
    // by a different state file, or not declared at all) currently allow.
    let declared = [declared_instance(
        "aws_instance.worker",
        "i-worker",
        &["sg-app"],
    )];
    let live = [
        live_sg_open("sg-app", &[443]),
        live_instance("i-worker", &["sg-app"]),
    ];

    let report = compare(&declared, &live);

    assert!(
        report.drifts.is_empty(),
        "must not fabricate drift from a non-authoritative state file: {:?}",
        report.drifts
    );
    let unresolved = report
        .unresolved
        .iter()
        .find(|u| u.relation == "instance_exposure")
        .expect("expected an unresolved instance_exposure entry");
    assert!(
        unresolved.resource.is_none(),
        "the state file is not authoritative, not any one resource"
    );
    assert!(
        unresolved.reason.contains("aws_security_group"),
        "{}",
        unresolved.reason
    );
}

#[test]
fn an_attached_group_missing_from_declared_state_is_unresolved_not_a_narrowing_finding() {
    // `worker` is attached to a group this state file never declares — a
    // real layout (network and compute split across state files), and the
    // honest report is "can't resolve," not a confident claim that exposure
    // shrank to nothing.
    let declared = [
        declared_sg_open("aws_security_group.other", "sg-other", &[]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [live_instance("i-worker", &["sg-app"])];

    let report = compare(&declared, &live);

    assert!(
        !report
            .drifts
            .iter()
            .any(|d| matches!(d.kind, DriftKind::SemanticChanged { .. })),
        "{:?}",
        report.drifts
    );
    let unresolved = report
        .unresolved
        .iter()
        .find(|u| {
            u.resource
                .as_ref()
                .is_some_and(|r| r.0 == "aws_instance.worker")
        })
        .expect("expected an Unresolved for worker");
    assert_eq!(unresolved.relation, "instance_exposure");
    assert!(
        unresolved.reason.contains("sg-app"),
        "{}",
        unresolved.reason
    );
}

#[test]
fn a_removed_console_rule_is_low_severity_exposure_drift() {
    // Fewer ports reachable than declared. Still drift, still worth
    // reporting, but not the alarming direction.
    let declared = [
        declared_sg_open("aws_security_group.app", "sg-app", &[443, 22]),
        declared_instance("aws_instance.worker", "i-worker", &["sg-app"]),
    ];
    let live = [
        live_sg_open("sg-app", &[443]),
        live_instance("i-worker", &["sg-app"]),
    ];

    let report = compare(&declared, &live);
    let consequence = report
        .drifts
        .iter()
        .find(|d| {
            d.resource.0 == "aws_instance.worker"
                && matches!(d.kind, DriftKind::SemanticChanged { .. })
        })
        .expect("expected an exposure finding");
    assert_eq!(consequence.severity, Severity::Low);
}

// --- sg_membership: load balancers as members ---
//
// A load balancer's ENI carries whatever security groups it names, exactly
// like an EC2 instance carries `vpc_security_group_ids` — `sg_membership`
// discovers both as members of a group they're attached to.

#[test]
fn an_undeclared_load_balancer_joining_a_trusted_group_is_drift() {
    // The load-balancer-shaped version of the original flagship: `web` trusts
    // `sg-app` on 443, and an ALB — a brand-new live-only resource nobody has
    // to declare — starts carrying `sg-app`. Every field on every declared
    // resource is byte-identical, so only the semantic pass can see it. Unlike
    // `instance_exposure`'s worked example, this recovers the clean
    // single-finding shape: nothing declared needs to change for an ALB to
    // start carrying a security group.
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        // `sg_membership`'s authority guard is keyed on `AwsInstance` alone
        // (see `SgMembership::requires`), so at least one declared instance
        // is needed for the relation to resolve at all — unrelated to `sg-app`
        // here, purely to satisfy the guard.
        declared_instance("aws_instance.other", "i-other", &[]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_instance("i-other", &[]),
        // Provisioned outside Terraform, attached to the trusted group.
        live_lb(
            "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/my-alb/1",
            &["sg-app"],
        ),
    ];

    let report = compare(&declared, &live);

    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
    let drift = &report.drifts[0];
    assert_eq!(drift.resource.0, "aws_security_group.web");
    assert_eq!(
        drift.severity,
        Severity::High,
        "membership grew: the ALB can now reach 443"
    );

    let DriftKind::SemanticChanged {
        field,
        relation,
        declared_effective,
        actual_effective,
        via,
    } = &drift.kind
    else {
        panic!("expected SemanticChanged, got {:?}", drift.kind);
    };
    assert_eq!(field, "ingress");
    assert_eq!(relation, "sg_membership");
    assert_eq!(via, &["sg-app"]);
    assert_eq!(declared_effective, &json!([]));
    assert_eq!(
        actual_effective,
        &json!([
            "tcp/443-443/member:arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/my-alb/1"
        ])
    );
}

#[test]
fn matching_load_balancer_membership_is_not_drift() {
    // The ALB is declared too this time (e.g. via `aws_lb` + a
    // `security_groups` argument referencing `sg-app`), so both sides agree.
    let arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/my-alb/1";
    let declared = [
        declared_sg("aws_security_group.web", "sg-web", &["sg-app"]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_lb("aws_lb.app", arn, &["sg-app"]),
        declared_instance("aws_instance.other", "i-other", &[]),
    ];
    let live = [
        live_sg("sg-web", &["sg-app"]),
        live_sg("sg-app", &[]),
        live_lb(arn, &["sg-app"]),
        live_instance("i-other", &[]),
    ];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
}

// --- internet_reachability ---

fn reachability_drift(report: &DriftReport) -> Option<&Drift> {
    report.drifts.iter().find(
        |d| matches!(&d.kind, DriftKind::SemanticChanged { relation, .. } if relation == "internet_reachability"),
    )
}

#[test]
fn a_declared_target_group_attachment_matching_live_registration_is_not_drift() {
    // The steady state this whole phase exists to make possible: a target
    // group's registration is declared via `aws_lb_target_group_attachment`
    // and matches what's live. Before Phase 3's declared-side reconciliation,
    // the declared side could never represent `targets` at all, so this
    // would have false-positived on every run regardless of this test.
    let alb_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/my-alb/1";
    let tg_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/my-targets/1";
    let declared = [
        declared_sg_open("aws_security_group.web", "sg-web", &[443]),
        declared_lb("aws_lb.app", alb_arn, &["sg-web"]),
        declared_tg("aws_lb_target_group.app", tg_arn, alb_arn),
        declared_attachment("aws_lb_target_group_attachment.app", tg_arn, "i-app"),
        declared_instance("aws_instance.app", "i-app", &[]),
    ];
    let live = [
        live_sg_open("sg-web", &[443]),
        live_lb(alb_arn, &["sg-web"]),
        live_tg(tg_arn, alb_arn, &["i-app"]),
        live_instance("i-app", &[]),
    ];

    let report = compare(&declared, &live);
    assert!(reachability_drift(&report).is_none(), "{:?}", report.drifts);
}

#[test]
fn a_target_registered_live_but_never_declared_is_high_severity_drift() {
    // The scenario Phase 3 exists to catch: an instance registered to an
    // ALB's target group outside Terraform. Every field on every declared
    // resource is byte-identical (there's simply no attachment resource at
    // all), so only the semantic pass can see it.
    let alb_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/my-alb/1";
    let tg_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/my-targets/1";
    let declared = [
        declared_sg_open("aws_security_group.web", "sg-web", &[443]),
        declared_lb("aws_lb.app", alb_arn, &["sg-web"]),
        declared_tg("aws_lb_target_group.app", tg_arn, alb_arn),
        // No attachment resource declared.
        declared_instance("aws_instance.app", "i-app", &[]),
    ];
    let live = [
        live_sg_open("sg-web", &[443]),
        live_lb(alb_arn, &["sg-web"]),
        live_tg(tg_arn, alb_arn, &["i-app"]),
        live_instance("i-app", &[]),
    ];

    let report = compare(&declared, &live);

    let drift = reachability_drift(&report).unwrap_or_else(|| {
        panic!(
            "expected an internet_reachability finding: {:?}",
            report.drifts
        )
    });
    assert_eq!(drift.resource.0, "aws_instance.app");
    assert_eq!(
        drift.severity,
        Severity::High,
        "reachability grew: the instance is now reachable from the internet"
    );

    let DriftKind::SemanticChanged {
        field,
        declared_effective,
        actual_effective,
        via,
        ..
    } = &drift.kind
    else {
        panic!("expected SemanticChanged, got {:?}", drift.kind);
    };
    assert_eq!(field, "vpc_security_group_ids");
    assert_eq!(declared_effective, &json!([]));
    assert_eq!(
        actual_effective,
        &json!([format!("via:sg-web>{alb_arn}>{tg_arn}>i-app")])
    );
    assert!(via.contains(&"sg-web".to_string()), "{via:?}");
    assert!(via.contains(&"i-app".to_string()), "{via:?}");
}

#[test]
fn a_declared_attachment_no_longer_registered_live_is_low_severity_drift() {
    // The mirror image: declared via Terraform, deregistered outside it.
    // Still drift, still worth reporting, but the shrinking direction.
    let alb_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/my-alb/1";
    let tg_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/my-targets/1";
    let declared = [
        declared_sg_open("aws_security_group.web", "sg-web", &[443]),
        declared_lb("aws_lb.app", alb_arn, &["sg-web"]),
        declared_tg("aws_lb_target_group.app", tg_arn, alb_arn),
        declared_attachment("aws_lb_target_group_attachment.app", tg_arn, "i-app"),
        declared_instance("aws_instance.app", "i-app", &[]),
    ];
    let live = [
        live_sg_open("sg-web", &[443]),
        live_lb(alb_arn, &["sg-web"]),
        live_tg(tg_arn, alb_arn, &[]),
        live_instance("i-app", &[]),
    ];

    let report = compare(&declared, &live);

    let drift = reachability_drift(&report).unwrap_or_else(|| {
        panic!(
            "expected an internet_reachability finding: {:?}",
            report.drifts
        )
    });
    assert_eq!(drift.severity, Severity::Low);
}

#[test]
fn reachability_through_a_pure_security_group_trust_chain_needs_no_load_balancer() {
    // No load balancer or target group anywhere in this graph: `i-web` picks
    // up `sg-app` outside Terraform, and `sg-db` (declared to trust sg-app
    // already) now admits it — so `i-db`, two hops from the internet-facing
    // group and untouched itself, becomes reachable. Confirms the ALB-
    // specific reconciliation this phase added didn't couple to the
    // trust-hop path the engine already proved in Phase 2.
    let declared = [
        declared_sg_open("aws_security_group.web", "sg-web", &[443]),
        declared_sg("aws_security_group.app", "sg-app", &[]),
        declared_sg("aws_security_group.db", "sg-db", &["sg-app"]),
        declared_instance("aws_instance.web", "i-web", &["sg-web"]),
        declared_instance("aws_instance.db", "i-db", &["sg-db"]),
    ];
    let live = [
        live_sg_open("sg-web", &[443]),
        live_sg("sg-app", &[]),
        live_sg("sg-db", &["sg-app"]),
        // Attached to sg-app in the console; nothing declared changed.
        live_instance("i-web", &["sg-web", "sg-app"]),
        live_instance("i-db", &["sg-db"]),
    ];

    let report = compare(&declared, &live);

    // The cause: i-web's own field really did change.
    assert!(
        report.drifts.iter().any(|d| {
            d.resource.0 == "aws_instance.web"
                && matches!(&d.kind, DriftKind::FieldChanged { field, .. } if field == "vpc_security_group_ids")
        }),
        "the cause: {:?}",
        report.drifts
    );
    // The consequence: i-db, untouched itself, is now reachable.
    let drift = reachability_drift(&report)
        .unwrap_or_else(|| panic!("the consequence: {:?}", report.drifts));
    assert_eq!(drift.resource.0, "aws_instance.db");
    assert_eq!(drift.severity, Severity::High);
}

#[test]
fn a_state_file_declaring_no_security_groups_reports_no_reachability_drift() {
    // The load-bearing guard, mirrored a third time: a state file that
    // declares instances but no security groups is not an authority on
    // whether the internet can reach them.
    let declared = [declared_instance("aws_instance.app", "i-app", &[])];
    let live = [
        live_sg_open("sg-app", &[443]),
        live_instance("i-app", &["sg-app"]),
    ];

    let report = compare(&declared, &live);

    assert!(
        reachability_drift(&report).is_none(),
        "must not fabricate drift from a non-authoritative state file: {:?}",
        report.drifts
    );
    let unresolved = report
        .unresolved
        .iter()
        .find(|u| u.relation == "internet_reachability")
        .expect("expected an unresolved internet_reachability entry");
    assert!(
        unresolved.resource.is_none(),
        "the state file is not authoritative, not any one resource"
    );
    assert!(
        unresolved.reason.contains("aws_security_group"),
        "{}",
        unresolved.reason
    );
}
