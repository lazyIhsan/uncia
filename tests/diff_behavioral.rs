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
