//! Replay-harness tests: recorded AWS responses fed back through the *real*
//! SDK, so the collectors are exercised end to end offline.
//!
//! Why this exists: the collectors' unit tests build `SecurityGroup` /
//! `Instance` values with SDK builders, which skips XML deserialization
//! entirely. If AWS's wire format differed from what the collector assumes,
//! no unit test would notice. Here the bytes go through the same
//! deserialization path a live call uses.
//!
//! **Two recordings captured from real accounts, one still a seed:**
//!
//! - `aws-two-resources.json` — one security group, an empty account (no EC2
//!   instances).
//! - `aws-sg-membership.json` — three security groups including a
//!   cross-group trust (not just the self-reference the first recording
//!   proved), and two real running instances, both members of the trusted
//!   group. This also grounds the `sg_membership` semantic-drift worked
//!   example end to end — see `docs/SEMANTIC-DRIFT.md`.
//! - `aws-lb-membership-seed.json` — hand-written, not yet captured from a
//!   real account with an ALB/NLB provisioned; `seed_`-prefixed tests assert
//!   against it.
//!
//! See `docs/TESTING.md` for the capture workflow and current status.

use std::collections::HashMap;

use aws_sdk_ec2::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
use aws_smithy_types::body::SdkBody;
use serde::Deserialize;

use uncia::collector::aws::{ec2, load_balancer, security_group};
use uncia::types::drift::DriftKind;
use uncia::{LiveResource, ResourceKind};

#[derive(Deserialize)]
struct Recording {
    responses: Vec<RecordedResponse>,
}

#[derive(Deserialize)]
struct RecordedResponse {
    operation: String,
    status: u16,
    body: String,
}

/// Select every recorded response belonging to the requested operations,
/// preserving file order, and shape each into a replay event against `uri`.
///
/// A paginated capture contributes several responses under one operation
/// name and must replay them all, in sequence. Shared between services —
/// only the client `Config` type differs, since each generated SDK crate has
/// its own.
fn replay_events(recording: &Recording, operations: &[&str], uri: &str) -> Vec<ReplayEvent> {
    let mut by_operation: HashMap<&str, Vec<&RecordedResponse>> = HashMap::new();
    for response in &recording.responses {
        by_operation
            .entry(response.operation.as_str())
            .or_default()
            .push(response);
    }

    operations
        .iter()
        .flat_map(|op| {
            by_operation
                .get(op)
                .unwrap_or_else(|| panic!("recording has no response for {op}"))
                .clone()
        })
        .map(|recorded| {
            ReplayEvent::new(
                http::Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(SdkBody::empty())
                    .unwrap(),
                http::Response::builder()
                    .status(recorded.status)
                    .body(SdkBody::from(recorded.body.clone()))
                    .unwrap(),
            )
        })
        .collect()
}

/// Build an EC2 client that replays the named recording instead of calling AWS.
fn replay_client(recording: &Recording, operations: &[&str]) -> aws_sdk_ec2::Client {
    let events = replay_events(
        recording,
        operations,
        "https://ec2.us-east-1.amazonaws.com/",
    );
    let config = aws_sdk_ec2::Config::builder()
        .http_client(StaticReplayClient::new(events))
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new("replay", "replay", None, None, "replay"))
        .behavior_version(BehaviorVersion::latest())
        .build();
    aws_sdk_ec2::Client::from_conf(config)
}

/// Build an ELBv2 client that replays the named recording instead of calling AWS.
fn replay_elbv2_client(
    recording: &Recording,
    operations: &[&str],
) -> aws_sdk_elasticloadbalancingv2::Client {
    let events = replay_events(
        recording,
        operations,
        "https://elasticloadbalancing.us-east-1.amazonaws.com/",
    );
    let config = aws_sdk_elasticloadbalancingv2::Config::builder()
        .http_client(StaticReplayClient::new(events))
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new("replay", "replay", None, None, "replay"))
        .behavior_version(BehaviorVersion::latest())
        .build();
    aws_sdk_elasticloadbalancingv2::Client::from_conf(config)
}

/// Captured from a real AWS account — ground truth.
fn captured() -> Recording {
    serde_json::from_str(include_str!("recordings/aws-two-resources.json")).unwrap()
}

/// Captured from a second real account — a security-group trust relationship
/// plus two real running instances.
fn sg_membership() -> Recording {
    serde_json::from_str(include_str!("recordings/aws-sg-membership.json")).unwrap()
}

/// Hand-written `DescribeLoadBalancers` response — a guess, not ground truth.
/// See `docs/TESTING.md`.
fn lb_membership_seed() -> Recording {
    serde_json::from_str(include_str!("recordings/aws-lb-membership-seed.json")).unwrap()
}

async fn collect_captured() -> Vec<LiveResource> {
    let rec = captured();
    let mut live = security_group::fetch(&replay_client(&rec, &["DescribeSecurityGroups"]))
        .await
        .unwrap();
    live.extend(
        ec2::fetch(&replay_client(&rec, &["DescribeInstances"]))
            .await
            .unwrap(),
    );
    live
}

async fn collect_sg_membership() -> Vec<LiveResource> {
    let rec = sg_membership();
    let mut live = security_group::fetch(&replay_client(&rec, &["DescribeSecurityGroups"]))
        .await
        .unwrap();
    live.extend(
        ec2::fetch(&replay_client(&rec, &["DescribeInstances"]))
            .await
            .unwrap(),
    );
    live
}

// --- Ground truth: captured from a real account ---

#[tokio::test]
async fn captured_security_group_survives_the_wire() {
    let rec = captured();
    let live = security_group::fetch(&replay_client(&rec, &["DescribeSecurityGroups"]))
        .await
        .unwrap();

    assert_eq!(live.len(), 1);
    let sg = &live[0];
    assert_eq!(sg.cloud_id, "sg-00000000000000001");
    assert_eq!(sg.kind, ResourceKind::AwsSecurityGroup);
    assert_eq!(sg.attributes["name"], "default");
    assert_eq!(sg.attributes["description"], "default VPC security group");
    assert_eq!(sg.attributes["vpc_id"], "vpc-00000000000000002");

    // An empty <value/> element becomes an empty string, not a missing key.
    assert_eq!(sg.attributes["tags"]["test-ec2-collector"], "");

    // The payoff. A default VPC security group allows all traffic from itself,
    // which AWS models as a UserIdGroupPair whose groupId is the group's own
    // id. The collector turns that into `self: true` and drops the group from
    // `security_groups`, matching how Terraform represents it — written blind
    // against the API docs, and only now confirmed against real bytes.
    let ingress = &sg.attributes["ingress"][0];
    assert_eq!(
        ingress["self"], true,
        "self-reference not detected: {ingress}"
    );
    assert_eq!(ingress["security_groups"], serde_json::json!([]));

    // All-traffic rules omit the ports entirely on the wire; they normalize to
    // 0 to match Terraform. Also confirmed against real bytes here.
    assert_eq!(ingress["protocol"], "-1");
    assert_eq!(ingress["from_port"], 0);
    assert_eq!(ingress["to_port"], 0);

    let egress = &sg.attributes["egress"][0];
    assert_eq!(egress["protocol"], "-1");
    assert_eq!(egress["cidr_blocks"][0], "0.0.0.0/0");
    assert_eq!(egress["self"], false);
}

#[tokio::test]
async fn captured_empty_account_yields_no_instances() {
    // The captured account has no EC2 instances, so AWS returns an empty
    // <reservationSet/>. That must parse as zero resources rather than an
    // error — the "account is genuinely empty" case, distinct from a failed
    // read.
    let live = ec2::fetch(&replay_client(&captured(), &["DescribeInstances"]))
        .await
        .unwrap();
    assert!(live.is_empty(), "{live:?}");
}

#[tokio::test]
async fn captured_account_matching_state_reports_no_drift() {
    // The full pipeline against real recorded bytes: state that matches the
    // account produces silence. This is the smoke test that used to require
    // live credentials.
    let declared = uncia::state::parse(include_str!("fixtures/replay_state_clean.json")).unwrap();
    let report = uncia::diff::behavioral::compare(&declared, &collect_captured().await);

    assert!(report.drifts.is_empty(), "{:?}", report.drifts);
    assert!(report.unjoinable.is_empty(), "{:?}", report.unjoinable);
}

#[tokio::test]
async fn console_edits_show_up_as_drift() {
    // Same recorded live state, but the declared state says something else —
    // i.e. someone changed prod outside Terraform. Mutating the *declared*
    // side is equivalent to mutating live and keeps the recording fixed.
    let mut state: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/replay_state_clean.json")).unwrap();
    {
        let sg = &mut state["values"]["root_module"]["resources"][0]["values"];
        sg["description"] = serde_json::json!("edited in console");
        // Drop the self-referencing rule: live still has it, so it reads as an
        // undeclared rule.
        sg["ingress"] = serde_json::json!([]);
    }

    let declared = uncia::state::parse(&state.to_string()).unwrap();
    let report = uncia::diff::behavioral::compare(&declared, &collect_captured().await);

    let fields: Vec<&str> = report
        .drifts
        .iter()
        .filter_map(|d| match &d.kind {
            DriftKind::FieldChanged { field, .. } => Some(field.as_str()),
            _ => None,
        })
        .collect();

    assert!(fields.contains(&"description"), "got: {fields:?}");
    assert!(fields.contains(&"ingress"), "got: {fields:?}");
    assert_eq!(report.drifts.len(), 2, "{:?}", report.drifts);
}

#[tokio::test]
async fn declared_instance_absent_from_account_is_missing() {
    // A genuinely real scenario for this recording: state declares an instance,
    // the account has none, so it must surface as Missing rather than being
    // quietly ignored.
    let declared =
        uncia::state::parse(include_str!("fixtures/replay_state_declares_instance.json")).unwrap();
    let report = uncia::diff::behavioral::compare(&declared, &collect_captured().await);

    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
    assert!(matches!(report.drifts[0].kind, DriftKind::Missing));
    assert_eq!(report.drifts[0].resource.0, "aws_instance.gone");
}

// --- Ground truth: captured from a second real account (sg-membership) ---

#[tokio::test]
async fn captured_sg_membership_security_groups_survive_the_wire() {
    // The first captured recording only proved the self-reference case (a
    // group trusting itself). This one has a group trusting a *different*
    // group — a cross-group `UserIdGroupPair` — which is the shape the
    // `sg_membership` semantic-drift relation actually depends on.
    let rec = sg_membership();
    let live = security_group::fetch(&replay_client(&rec, &["DescribeSecurityGroups"]))
        .await
        .unwrap();

    assert_eq!(live.len(), 3);
    let web = live
        .iter()
        .find(|sg| sg.attributes["name"] == "uncia-capture-web")
        .expect("web group present");
    let app = live
        .iter()
        .find(|sg| sg.attributes["name"] == "uncia-capture-app")
        .expect("app group present");

    let ingress = &web.attributes["ingress"][0];
    assert_eq!(ingress["protocol"], "tcp");
    assert_eq!(ingress["from_port"], 443);
    assert_eq!(ingress["to_port"], 443);
    assert_eq!(ingress["self"], false);
    assert_eq!(
        ingress["security_groups"],
        serde_json::json!([app.cloud_id])
    );
}

#[tokio::test]
async fn captured_sg_membership_instances_survive_the_wire() {
    let rec = sg_membership();
    let live = ec2::fetch(&replay_client(&rec, &["DescribeInstances"]))
        .await
        .unwrap();

    assert_eq!(live.len(), 2);
    for instance in &live {
        assert_eq!(instance.kind, ResourceKind::AwsInstance);
        assert_eq!(instance.attributes["instance_type"], "t3.micro");
        assert_eq!(
            instance.attributes["metadata_options"][0]["http_tokens"], "required",
            "IMDSv2 required, confirmed against real bytes"
        );
    }

    let app_group = security_group::fetch(&replay_client(&rec, &["DescribeSecurityGroups"]))
        .await
        .unwrap()
        .into_iter()
        .find(|sg| sg.attributes["name"] == "uncia-capture-app")
        .unwrap()
        .cloud_id;
    assert!(
        live.iter()
            .all(|i| i.attributes["vpc_security_group_ids"] == serde_json::json!([app_group])),
        "both instances are members of the trusted group: {live:?}"
    );
}

#[tokio::test]
async fn captured_undeclared_instance_joining_a_trusted_group_is_semantic_drift() {
    // The worked example from `docs/ARCHITECTURE.md` and `docs/SEMANTIC-DRIFT.md`,
    // replayed end to end against real captured bytes rather than hand-built
    // resources: `web` trusts `app` on 443, and the account has two real
    // instances in `app` while state only declares one. Every field on every
    // declared resource is byte-identical, so this can only surface through
    // the semantic pass.
    let declared =
        uncia::state::parse(include_str!("fixtures/replay_state_sg_membership.json")).unwrap();
    let report = uncia::diff::compare(&declared, &collect_sg_membership().await);

    assert_eq!(report.drifts.len(), 1, "{:?}", report.drifts);
    let drift = &report.drifts[0];
    assert_eq!(drift.resource.0, "aws_security_group.web");

    let DriftKind::SemanticChanged {
        field, relation, ..
    } = &drift.kind
    else {
        panic!("expected SemanticChanged, got {:?}", drift.kind);
    };
    assert_eq!(field, "ingress");
    assert_eq!(relation, "sg_membership");
}

// --- Seed data: hand-written, NOT ground truth ---
//
// Carries the `seed_` prefix so a reader can tell at a glance it asserts
// against invented bytes — same discipline `docs/TESTING.md` established for
// the (now-retired) instance seed. Exercises the deserialization path and
// locks a regression baseline, but a disagreement between this and real AWS
// would mean the seed is wrong, not the collector. Replace by running
// `cargo run --example capture_recording` against an account with a real
// ALB/NLB provisioned.

#[tokio::test]
async fn seed_load_balancer_survives_the_wire() {
    let rec = lb_membership_seed();
    let live = load_balancer::fetch(&replay_elbv2_client(&rec, &["DescribeLoadBalancers"]))
        .await
        .unwrap();

    assert_eq!(live.len(), 2);

    let alb = live
        .iter()
        .find(|lb| lb.cloud_id.contains("uncia-seed-alb"))
        .expect("ALB present");
    assert_eq!(alb.kind, ResourceKind::AwsLoadBalancer);
    assert_eq!(alb.attributes["id"], alb.cloud_id.as_str());
    assert_eq!(
        alb.attributes["security_groups"],
        serde_json::json!(["sg-00000000000000001"])
    );

    // The NLB in the same account carries none — the common real-world shape,
    // confirmed to deserialize as an empty list rather than erroring.
    let nlb = live
        .iter()
        .find(|lb| lb.cloud_id.contains("uncia-seed-nlb"))
        .expect("NLB present");
    assert_eq!(nlb.attributes["security_groups"], serde_json::json!([]));
}
