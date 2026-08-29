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
use uncia::{DriftKind, LiveResource, Resource, ResourceId, ResourceKind, Severity};

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

fn declared_instance(address: &str, id: &str, sgs: &[&str]) -> Resource {
    declared(address, ResourceKind::AwsInstance, instance_attrs(id, sgs))
}

fn live_instance(id: &str, sgs: &[&str]) -> LiveResource {
    live(id, ResourceKind::AwsInstance, instance_attrs(id, sgs))
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
        live_instance("i-worker", &["sg-app"]),
        live_instance("i-console", &["sg-app"]),
    ];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
}
