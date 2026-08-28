//! Rules declared as *separate* resources rather than inline blocks.
//!
//! `aws_security_group` carries its rules two mutually exclusive ways: inline
//! `ingress`/`egress` blocks, or separate rule resources. With the separate
//! form the group's inline blocks are empty in state while the rules live as
//! their own resources — so a diff that only reads the inline blocks compares
//! an empty declared set against the live group's real rules and reports every
//! rule as drift.
//!
//! The live side needs no reconciling: AWS reports a group's rules *on the
//! group*, however Terraform declared them. This is a declared-side concern
//! only.

use serde_json::{Map, Value, json};

use uncia::diff::behavioral::compare;
use uncia::{DriftKind, LiveResource, Resource, ResourceId, ResourceKind};

fn attrs(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn declared(address: &str, kind: ResourceKind, values: Value) -> Resource {
    Resource {
        id: ResourceId(address.to_string()),
        kind,
        attributes: attrs(values),
    }
}

/// A group with no inline rules at all — what state looks like when the rules
/// are declared as sibling resources.
fn declared_bare_group(address: &str, id: &str) -> Resource {
    declared(
        address,
        ResourceKind::AwsSecurityGroup,
        json!({
            "id": id, "name": "web", "description": "d", "vpc_id": "vpc-1",
            "tags": {}, "ingress": [], "egress": [],
        }),
    )
}

/// A live group carrying `rules` on its ingress, as AWS always reports them.
fn live_group_with_ingress(id: &str, rules: Value) -> LiveResource {
    LiveResource {
        cloud_id: id.to_string(),
        kind: ResourceKind::AwsSecurityGroup,
        attributes: attrs(json!({
            "id": id, "name": "web", "description": "d", "vpc_id": "vpc-1",
            "tags": {}, "ingress": rules, "egress": [],
        })),
    }
}

/// The shape the collector emits for one live rule.
fn live_rule(
    from: i64,
    to: i64,
    protocol: &str,
    cidrs: Value,
    sgs: Value,
    self_ref: bool,
) -> Value {
    json!({
        "from_port": from, "to_port": to, "protocol": protocol,
        "cidr_blocks": cidrs, "ipv6_cidr_blocks": [], "prefix_list_ids": [],
        "security_groups": sgs, "self": self_ref,
    })
}

/// The modern separate form: `aws_vpc_security_group_ingress_rule`.
/// Note `ip_protocol` (not `protocol`) and the singular `cidr_ipv4`.
fn modern_ingress_rule(address: &str, sg: &str, values: Value) -> Resource {
    let mut v = attrs(values);
    v.insert("security_group_id".into(), json!(sg));
    declared(
        address,
        ResourceKind::AwsVpcSecurityGroupIngressRule,
        Value::Object(v),
    )
}

// --- The regression this suite exists for ---

#[test]
fn a_rule_declared_as_a_separate_resource_is_not_drift() {
    // Every rule here is declared; none of it drifted. Before reconciliation
    // this reported the whole rule set as drift, because the group's own
    // inline blocks are empty.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.https",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(
            443,
            443,
            "tcp",
            json!(["0.0.0.0/0"]),
            json!([]),
            false
        )]),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn a_separately_declared_rule_missing_from_the_account_is_still_drift() {
    // The fix must not swallow the true positive it resembles.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.https",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}),
        ),
    ];
    let live = [live_group_with_ingress("sg-web", json!([]))];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
    assert!(matches!(
        &report.drifts[0].kind,
        DriftKind::FieldChanged { field, .. } if field == "ingress"
    ));
}

#[test]
fn a_live_rule_declared_nowhere_is_still_drift() {
    // Someone opened SSH in the console; no rule resource declares it.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.https",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([
            live_rule(443, 443, "tcp", json!(["0.0.0.0/0"]), json!([]), false),
            live_rule(22, 22, "tcp", json!(["0.0.0.0/0"]), json!([]), false),
        ]),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
}

#[test]
fn a_group_with_no_rules_declared_anywhere_still_reports_live_rules() {
    // No sibling rules exist, so the state genuinely claims the group is
    // empty. That is drift, and reconciliation must not hide it.
    let declared = [declared_bare_group("aws_security_group.web", "sg-web")];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(
            22,
            22,
            "tcp",
            json!(["0.0.0.0/0"]),
            json!([]),
            false
        )]),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
}

// --- The self-reference trap ---

#[test]
fn a_modern_self_reference_matches_the_collectors_self_flag() {
    // The modern form has no `self` field: a self-reference is
    // `referenced_security_group_id` pointing at the group's own id. The
    // collector turns AWS's equivalent into `self: true` and drops it from
    // `security_groups`, so without folding these together every
    // self-referencing rule reads as drift.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.internal",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 0, "to_port": 0,
                   "ip_protocol": "-1", "referenced_security_group_id": "sg-web"}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(0, 0, "-1", json!([]), json!([]), true)]),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn a_modern_rule_referencing_another_group_is_not_a_self_reference() {
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.from_app",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "referenced_security_group_id": "sg-app"}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(
            443,
            443,
            "tcp",
            json!([]),
            json!(["sg-app"]),
            false
        )]),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

// --- The legacy separate form ---

#[test]
fn the_legacy_rule_resource_routes_by_its_type_field() {
    // `aws_security_group_rule` carries direction in `type`, so an egress rule
    // must not be counted toward ingress.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        declared(
            "aws_security_group_rule.out",
            ResourceKind::AwsSecurityGroupRule,
            json!({"id": "sgrule-1", "security_group_id": "sg-web", "type": "egress",
                   "from_port": 0, "to_port": 0, "protocol": "-1",
                   "cidr_blocks": ["0.0.0.0/0"]}),
        ),
    ];
    let live = [LiveResource {
        cloud_id: "sg-web".to_string(),
        kind: ResourceKind::AwsSecurityGroup,
        attributes: attrs(json!({
            "id": "sg-web", "name": "web", "description": "d", "vpc_id": "vpc-1",
            "tags": {}, "ingress": [],
            "egress": [live_rule(0, 0, "-1", json!(["0.0.0.0/0"]), json!([]), false)],
        })),
    }];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn a_legacy_egress_rule_does_not_satisfy_an_ingress_rule() {
    // Same rule body, wrong direction: must still be drift on both fields.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        declared(
            "aws_security_group_rule.out",
            ResourceKind::AwsSecurityGroupRule,
            json!({"id": "sgrule-1", "security_group_id": "sg-web", "type": "egress",
                   "from_port": 443, "to_port": 443, "protocol": "tcp",
                   "cidr_blocks": ["10.0.0.0/8"]}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(
            443,
            443,
            "tcp",
            json!(["10.0.0.0/8"]),
            json!([]),
            false
        )]),
    )];

    let report = compare(&declared, &live);
    // ingress: declared nothing, live has a rule. egress: declared a rule,
    // live has none. Both drift.
    assert_eq!(report.drifts.len(), 2, "{:?}", report.drifts);
}

#[test]
fn legacy_and_modern_forms_agree_on_the_same_logical_rule() {
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(
            443,
            443,
            "tcp",
            json!(["10.0.0.0/8"]),
            json!([]),
            false
        )]),
    )];

    let legacy = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        declared(
            "aws_security_group_rule.https",
            ResourceKind::AwsSecurityGroupRule,
            json!({"id": "sgrule-1", "security_group_id": "sg-web", "type": "ingress",
                   "from_port": 443, "to_port": 443, "protocol": "tcp",
                   "cidr_blocks": ["10.0.0.0/8"]}),
        ),
    ];
    let modern = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.https",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "cidr_ipv4": "10.0.0.0/8"}),
        ),
    ];

    assert!(compare(&legacy, &live).drifts.is_empty());
    assert!(compare(&modern, &live).drifts.is_empty());
}

// --- Inline and sibling rules together ---

#[test]
fn inline_blocks_and_sibling_rules_are_unioned() {
    let declared = [
        declared(
            "aws_security_group.web",
            ResourceKind::AwsSecurityGroup,
            json!({
                "id": "sg-web", "name": "web", "description": "d", "vpc_id": "vpc-1",
                "tags": {},
                "ingress": [live_rule(443, 443, "tcp", json!(["10.0.0.0/8"]), json!([]), false)],
                "egress": [],
            }),
        ),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.ssh",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 22, "to_port": 22,
                   "ip_protocol": "tcp", "cidr_ipv4": "10.0.0.0/8"}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([
            live_rule(443, 443, "tcp", json!(["10.0.0.0/8"]), json!([]), false),
            live_rule(22, 22, "tcp", json!(["10.0.0.0/8"]), json!([]), false),
        ]),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn sibling_rules_target_only_their_own_group() {
    // A rule naming a different group must not silence drift on this one.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.elsewhere",
            "sg-other",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(
            443,
            443,
            "tcp",
            json!(["0.0.0.0/0"]),
            json!([]),
            false
        )]),
    )];

    let report = compare(&declared, &live);
    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
}

#[test]
fn a_rule_resource_is_never_itself_a_comparison_subject() {
    // No collector returns rule resources, so they must be skipped entirely —
    // not reported as Missing, and not landed in `unjoinable`.
    let declared = [modern_ingress_rule(
        "aws_vpc_security_group_ingress_rule.https",
        "sg-web",
        json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
               "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}),
    )];

    let report = compare(&declared, &[]);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unjoinable.is_empty(), "{:?}", report.unjoinable);
}

#[test]
fn a_sibling_rule_contributes_before_it_has_been_applied() {
    // No `id` yet: unapplied, but it is still declared intent, and intent is
    // what the declared side is supposed to represent.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.https",
            "sg-web",
            json!({"from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}),
        ),
    ];
    let live = [live_group_with_ingress(
        "sg-web",
        json!([live_rule(
            443,
            443,
            "tcp",
            json!(["0.0.0.0/0"]),
            json!([]),
            false
        )]),
    )];

    let report = compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

// --- Interaction with the semantic pass ---

#[test]
fn a_sibling_declared_trust_rule_does_not_become_a_semantic_false_positive() {
    // Reconciliation silences the behavioral finding for this group, which
    // removes the disjointness guard that was incidentally suppressing the
    // semantic pass. If the semantic pass still reads only the group's inline
    // blocks it will see an empty declared membership against a real live one
    // and invent drift — trading one false positive for another.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.from_app",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "referenced_security_group_id": "sg-app"}),
        ),
        declared_bare_group("aws_security_group.app", "sg-app"),
        declared(
            "aws_instance.worker",
            ResourceKind::AwsInstance,
            json!({"id": "i-worker", "instance_type": "t3.micro", "ami": "ami-1",
                   "tags": {}, "vpc_security_group_ids": ["sg-app"],
                   "iam_instance_profile": "",
                   "metadata_options": [{"http_endpoint": "enabled",
                       "http_tokens": "required", "http_put_response_hop_limit": 1,
                       "instance_metadata_tags": "disabled"}]}),
        ),
    ];
    let live = [
        live_group_with_ingress(
            "sg-web",
            json!([live_rule(
                443,
                443,
                "tcp",
                json!([]),
                json!(["sg-app"]),
                false
            )]),
        ),
        live_group_with_ingress("sg-app", json!([])),
        LiveResource {
            cloud_id: "i-worker".to_string(),
            kind: ResourceKind::AwsInstance,
            attributes: attrs(json!({"id": "i-worker", "instance_type": "t3.micro",
                "ami": "ami-1", "tags": {}, "vpc_security_group_ids": ["sg-app"],
                "iam_instance_profile": "",
                "metadata_options": [{"http_endpoint": "enabled",
                    "http_tokens": "required", "http_put_response_hop_limit": 1,
                    "instance_metadata_tags": "disabled"}]})),
        },
    ];

    // Nothing drifted: the rule is declared, and sg-app's membership matches.
    let report = uncia::diff::compare(&declared, &live);
    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
}

#[test]
fn semantic_drift_is_still_detected_through_a_sibling_declared_rule() {
    // The other half of the previous test: silencing the false positive must
    // not blind the semantic pass. The trust rule is declared as a sibling
    // resource and is byte-identical, but an undeclared instance joined the
    // group it trusts — which is exactly the finding uncia exists to make.
    let declared = [
        declared_bare_group("aws_security_group.web", "sg-web"),
        modern_ingress_rule(
            "aws_vpc_security_group_ingress_rule.from_app",
            "sg-web",
            json!({"id": "sgr-1", "from_port": 443, "to_port": 443,
                   "ip_protocol": "tcp", "referenced_security_group_id": "sg-app"}),
        ),
        declared_bare_group("aws_security_group.app", "sg-app"),
        declared(
            "aws_instance.worker",
            ResourceKind::AwsInstance,
            json!({"id": "i-worker", "instance_type": "t3.micro", "ami": "ami-1",
                   "tags": {}, "vpc_security_group_ids": ["sg-app"],
                   "iam_instance_profile": "",
                   "metadata_options": [{"http_endpoint": "enabled",
                       "http_tokens": "required", "http_put_response_hop_limit": 1,
                       "instance_metadata_tags": "disabled"}]}),
        ),
    ];
    let instance = |id: &str| LiveResource {
        cloud_id: id.to_string(),
        kind: ResourceKind::AwsInstance,
        attributes: attrs(json!({"id": id, "instance_type": "t3.micro",
            "ami": "ami-1", "tags": {}, "vpc_security_group_ids": ["sg-app"],
            "iam_instance_profile": "",
            "metadata_options": [{"http_endpoint": "enabled",
                "http_tokens": "required", "http_put_response_hop_limit": 1,
                "instance_metadata_tags": "disabled"}]})),
    };
    let live = [
        live_group_with_ingress(
            "sg-web",
            json!([live_rule(
                443,
                443,
                "tcp",
                json!([]),
                json!(["sg-app"]),
                false
            )]),
        ),
        live_group_with_ingress("sg-app", json!([])),
        instance("i-worker"),
        instance("i-console"),
    ];

    let report = uncia::diff::compare(&declared, &live);

    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
    assert_eq!(report.drifts[0].resource.0, "aws_security_group.web");
    let DriftKind::SemanticChanged {
        via,
        actual_effective,
        ..
    } = &report.drifts[0].kind
    else {
        panic!("expected SemanticChanged, got {:?}", report.drifts[0].kind);
    };
    assert_eq!(via, &["sg-app"], "the path must survive reconciliation");
    assert_eq!(
        actual_effective,
        &json!([
            "tcp/443-443/member:i-console",
            "tcp/443-443/member:i-worker"
        ])
    );
}
