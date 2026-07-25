//! Behavioral-diff tests: joining, missing detection, field drift, the
//! unjoinable bucket, and — the load-bearing one — rule-set comparison that
//! ignores ordering and grouping differences between Terraform state and the
//! AWS API's shape.

use serde_json::{Map, Value, json};

use uncia::diff::behavioral::compare;
use uncia::{DriftKind, LiveResource, Resource, ResourceId, ResourceKind};

fn attrs(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn declared_sg(address: &str, values: Value) -> Resource {
    Resource {
        id: ResourceId(address.to_string()),
        kind: ResourceKind::AwsSecurityGroup,
        attributes: attrs(values),
    }
}

fn live_sg(cloud_id: &str, values: Value) -> LiveResource {
    LiveResource {
        cloud_id: cloud_id.to_string(),
        kind: ResourceKind::AwsSecurityGroup,
        attributes: attrs(values),
    }
}

fn rule(from: i64, to: i64, protocol: &str, cidrs: Value) -> Value {
    json!({
        "from_port": from, "to_port": to, "protocol": protocol,
        "cidr_blocks": cidrs, "ipv6_cidr_blocks": [], "prefix_list_ids": [],
        "security_groups": [], "self": false,
    })
}

#[test]
fn identical_resources_produce_no_drift() {
    let declared = [declared_sg(
        "aws_security_group.web",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1",
               "tags": {"Name": "web"},
               "ingress": [rule(443, 443, "tcp", json!(["0.0.0.0/0"]))],
               "egress": []}),
    )];
    let live = [live_sg(
        "sg-1",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1",
               "tags": {"Name": "web"},
               "ingress": [rule(443, 443, "tcp", json!(["0.0.0.0/0"]))],
               "egress": []}),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unjoinable.is_empty());
}

#[test]
fn declared_but_absent_is_missing() {
    let declared = [declared_sg(
        "aws_security_group.gone",
        json!({"id": "sg-gone"}),
    )];

    let report = compare(&declared, &[]);
    assert_eq!(report.drifts.len(), 1);
    assert_eq!(report.drifts[0].resource.0, "aws_security_group.gone");
    assert!(matches!(report.drifts[0].kind, DriftKind::Missing));
}

#[test]
fn changed_field_is_reported_with_both_values() {
    let declared = [declared_sg(
        "aws_security_group.web",
        json!({"id": "sg-1", "name": "web", "description": "web tier", "vpc_id": "vpc-1",
               "tags": {}, "ingress": [], "egress": []}),
    )];
    let live = [live_sg(
        "sg-1",
        json!({"id": "sg-1", "name": "web", "description": "edited in console", "vpc_id": "vpc-1",
               "tags": {}, "ingress": [], "egress": []}),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1);
    assert!(matches!(
        &report.drifts[0].kind,
        DriftKind::FieldChanged { field, declared, actual }
            if field == "description" && declared == "web tier" && actual == "edited in console"
    ));
}

#[test]
fn rule_order_and_grouping_differences_are_not_drift() {
    // Declared: two Terraform blocks, one cidr each.
    let declared = [declared_sg(
        "aws_security_group.web",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1", "tags": {},
               "ingress": [
                   rule(443, 443, "tcp", json!(["10.0.0.0/8"])),
                   rule(443, 443, "tcp", json!(["192.168.0.0/16"])),
               ],
               "egress": []}),
    )];
    // Live: AWS groups both cidrs under one permission, in reverse order.
    let live = [live_sg(
        "sg-1",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1", "tags": {},
               "ingress": [
                   rule(443, 443, "tcp", json!(["192.168.0.0/16", "10.0.0.0/8"])),
               ],
               "egress": []}),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn extra_live_rule_is_drift() {
    let declared = [declared_sg(
        "aws_security_group.web",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1", "tags": {},
               "ingress": [rule(443, 443, "tcp", json!(["10.0.0.0/8"]))],
               "egress": []}),
    )];
    // Someone opened SSH to the world in the console.
    let live = [live_sg(
        "sg-1",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1", "tags": {},
               "ingress": [
                   rule(443, 443, "tcp", json!(["10.0.0.0/8"])),
                   rule(22, 22, "tcp", json!(["0.0.0.0/0"])),
               ],
               "egress": []}),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1);
    assert!(matches!(
        &report.drifts[0].kind,
        DriftKind::FieldChanged { field, .. } if field == "ingress"
    ));
}

#[test]
fn missing_cloud_id_is_unjoinable_not_missing() {
    let declared = [declared_sg(
        "aws_security_group.unappl",
        json!({"name": "unappl"}),
    )];

    let report = compare(&declared, &[]);
    assert!(report.drifts.is_empty(), "must not fabricate Missing drift");
    assert_eq!(report.unjoinable.len(), 1);
    assert_eq!(report.unjoinable[0].resource.0, "aws_security_group.unappl");
}

#[test]
fn uncovered_kinds_are_skipped_entirely() {
    let declared = [Resource {
        id: ResourceId("aws_s3_bucket.assets".to_string()),
        kind: ResourceKind::Other("aws_s3_bucket".to_string()),
        attributes: attrs(json!({"id": "assets-bucket"})),
    }];

    let report = compare(&declared, &[]);
    assert!(report.drifts.is_empty());
    assert!(report.unjoinable.is_empty());
}

#[test]
fn tags_all_is_preferred_over_tags_when_present() {
    // Provider default_tags live only in tags_all; live side reports all tags.
    let declared = [declared_sg(
        "aws_security_group.web",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1",
               "tags": {"Name": "web"},
               "tags_all": {"Name": "web", "Env": "prod"},
               "ingress": [], "egress": []}),
    )];
    let live = [live_sg(
        "sg-1",
        json!({"id": "sg-1", "name": "web", "description": "d", "vpc_id": "vpc-1",
               "tags": {"Name": "web", "Env": "prod"},
               "ingress": [], "egress": []}),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

// --- EC2 instances ---

fn declared_instance(address: &str, values: Value) -> Resource {
    Resource {
        id: ResourceId(address.to_string()),
        kind: ResourceKind::AwsInstance,
        attributes: attrs(values),
    }
}

fn live_instance(cloud_id: &str, values: Value) -> LiveResource {
    LiveResource {
        cloud_id: cloud_id.to_string(),
        kind: ResourceKind::AwsInstance,
        attributes: attrs(values),
    }
}

fn instance_meta(http_tokens: &str) -> Value {
    json!([{
        "http_endpoint": "enabled",
        "http_tokens": http_tokens,
        "http_put_response_hop_limit": 1,
        "instance_metadata_tags": "disabled",
    }])
}

fn base_instance(id: &str, instance_type: &str, sgs: Value, http_tokens: &str) -> Value {
    json!({
        "id": id, "instance_type": instance_type, "ami": "ami-1",
        "tags": {"Name": "web"}, "vpc_security_group_ids": sgs,
        "iam_instance_profile": "app-role", "metadata_options": instance_meta(http_tokens),
    })
}

#[test]
fn instance_type_change_is_drift() {
    let declared = [declared_instance(
        "aws_instance.web",
        base_instance("i-1", "t3.medium", json!(["sg-a"]), "required"),
    )];
    let live = [live_instance(
        "i-1",
        base_instance("i-1", "t3.large", json!(["sg-a"]), "required"),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1);
    assert!(matches!(
        &report.drifts[0].kind,
        DriftKind::FieldChanged { field, declared, actual }
            if field == "instance_type" && declared == "t3.medium" && actual == "t3.large"
    ));
}

#[test]
fn security_group_id_order_is_not_drift() {
    let declared = [declared_instance(
        "aws_instance.web",
        base_instance("i-1", "t3.medium", json!(["sg-a", "sg-b"]), "required"),
    )];
    let live = [live_instance(
        "i-1",
        base_instance("i-1", "t3.medium", json!(["sg-b", "sg-a"]), "required"),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn changed_security_group_attachment_is_drift() {
    let declared = [declared_instance(
        "aws_instance.web",
        base_instance("i-1", "t3.medium", json!(["sg-a"]), "required"),
    )];
    // An SG was swapped out from under Terraform.
    let live = [live_instance(
        "i-1",
        base_instance("i-1", "t3.medium", json!(["sg-b"]), "required"),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1);
    assert!(matches!(
        &report.drifts[0].kind,
        DriftKind::FieldChanged { field, .. } if field == "vpc_security_group_ids"
    ));
}

#[test]
fn imdsv2_downgrade_is_drift() {
    // http_tokens required -> optional re-opens IMDSv1: a posture change.
    let declared = [declared_instance(
        "aws_instance.web",
        base_instance("i-1", "t3.medium", json!(["sg-a"]), "required"),
    )];
    let live = [live_instance(
        "i-1",
        base_instance("i-1", "t3.medium", json!(["sg-a"]), "optional"),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1);
    assert!(matches!(
        &report.drifts[0].kind,
        DriftKind::FieldChanged { field, .. } if field == "metadata_options"
    ));
}

#[test]
fn extra_metadata_key_in_state_is_not_drift() {
    // A newer provider adds http_protocol_ipv6 to the block; the live side
    // (which uncia builds) doesn't emit it. It must not read as drift.
    let mut declared_meta = instance_meta("required");
    declared_meta[0]
        .as_object_mut()
        .unwrap()
        .insert("http_protocol_ipv6".to_string(), json!("disabled"));

    let declared = [declared_instance(
        "aws_instance.web",
        json!({"id": "i-1", "instance_type": "t3.medium", "ami": "ami-1",
               "tags": {"Name": "web"}, "vpc_security_group_ids": ["sg-a"],
               "iam_instance_profile": "app-role", "metadata_options": declared_meta}),
    )];
    let live = [live_instance(
        "i-1",
        base_instance("i-1", "t3.medium", json!(["sg-a"]), "required"),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn declared_instance_absent_from_live_is_missing() {
    let declared = [declared_instance(
        "aws_instance.gone",
        base_instance("i-gone", "t3.medium", json!(["sg-a"]), "required"),
    )];

    let report = compare(&declared, &[]);
    assert_eq!(report.drifts.len(), 1);
    assert!(matches!(report.drifts[0].kind, DriftKind::Missing));
}
