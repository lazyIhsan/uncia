//! Replay-harness tests: recorded AWS responses fed back through the *real*
//! SDK, so the collectors are exercised end to end offline.
//!
//! Why this exists: the collectors' unit tests build `SecurityGroup` /
//! `Instance` values with SDK builders, which skips XML deserialization
//! entirely. If AWS's wire format differed from what the collector assumes,
//! no unit test would notice. Here the bytes go through the same
//! deserialization path a live call uses.
//!
//! **Two recordings, two different levels of confidence** — the distinction
//! matters and is deliberately visible in the test names:
//!
//! - `aws-two-resources.json` is **captured** from a real account. Tests over
//!   it are ground truth.
//! - `aws-instance-seed.json` is **hand-written**, because the captured
//!   account has no EC2 instances. Tests over it prove the deserialization
//!   path works but cannot prove AWS emits those bytes.
//!
//! See `docs/TESTING.md` for the capture workflow and current status.

use std::collections::HashMap;

use aws_sdk_ec2::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
use aws_smithy_types::body::SdkBody;
use serde::Deserialize;

use uncia::collector::aws::{ec2, security_group};
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

/// Build an EC2 client that replays the named recording instead of calling AWS.
///
/// Selects every response belonging to the requested operations, preserving
/// file order — a paginated capture contributes several responses under one
/// operation name and must replay them all, in sequence.
fn replay_client(recording: &Recording, operations: &[&str]) -> aws_sdk_ec2::Client {
    let mut by_operation: HashMap<&str, Vec<&RecordedResponse>> = HashMap::new();
    for response in &recording.responses {
        by_operation
            .entry(response.operation.as_str())
            .or_default()
            .push(response);
    }

    let events: Vec<ReplayEvent> = operations
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
                    .uri("https://ec2.us-east-1.amazonaws.com/")
                    .body(SdkBody::empty())
                    .unwrap(),
                http::Response::builder()
                    .status(recorded.status)
                    .body(SdkBody::from(recorded.body.clone()))
                    .unwrap(),
            )
        })
        .collect();

    let config = aws_sdk_ec2::Config::builder()
        .http_client(StaticReplayClient::new(events))
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new("replay", "replay", None, None, "replay"))
        .behavior_version(BehaviorVersion::latest())
        .build();
    aws_sdk_ec2::Client::from_conf(config)
}

/// Captured from a real AWS account — ground truth.
fn captured() -> Recording {
    serde_json::from_str(include_str!("recordings/aws-two-resources.json")).unwrap()
}

/// Hand-written instance response — a guess, not ground truth.
fn instance_seed() -> Recording {
    serde_json::from_str(include_str!("recordings/aws-instance-seed.json")).unwrap()
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

// --- Seed data: hand-written, NOT ground truth ---
//
// These carry the `seed_` prefix so a reader can tell at a glance that they
// assert against invented bytes. They still catch regressions in the
// deserialization path, but a disagreement between them and real AWS would
// mean the seed is wrong, not the collector.

#[tokio::test]
async fn seed_instance_survives_the_wire() {
    let rec = instance_seed();
    let live = ec2::fetch(&replay_client(&rec, &["DescribeInstances"]))
        .await
        .unwrap();

    assert_eq!(live.len(), 1);
    let instance = &live[0];
    assert_eq!(instance.cloud_id, "i-00000000000000001");
    assert_eq!(instance.kind, ResourceKind::AwsInstance);
    assert_eq!(instance.attributes["instance_type"], "t3.medium");
    assert_eq!(instance.attributes["ami"], "ami-00000000000000001");
    assert_eq!(
        instance.attributes["vpc_security_group_ids"],
        serde_json::json!(["sg-00000000000000001"])
    );

    // The two normalizations most likely to break on a wire-format change.
    assert_eq!(
        instance.attributes["iam_instance_profile"], "app-role",
        "instance-profile ARN should be reduced to the bare name"
    );
    assert_eq!(
        instance.attributes["metadata_options"][0]["http_tokens"],
        "required"
    );
    assert_eq!(
        instance.attributes["metadata_options"][0]["http_put_response_hop_limit"],
        2
    );
}
