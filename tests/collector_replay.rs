//! Replay-harness tests: recorded AWS responses fed back through the *real*
//! SDK, so the collectors are exercised end to end offline.
//!
//! Why this exists: the collectors' unit tests build `SecurityGroup` /
//! `Instance` values with SDK builders, which skips XML deserialization
//! entirely. If AWS's wire format differed from what the collector assumes,
//! no unit test would notice. Here the bytes go through the same
//! deserialization path a live call uses.
//!
//! Recordings live in `tests/recordings/`. They are meant to be *captured*
//! from a real account (`cargo run --example capture_recording`) and then
//! replayed forever; see `docs/TESTING.md` for the workflow and the current
//! status of each recording.

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

fn recording() -> Recording {
    serde_json::from_str(include_str!("recordings/aws-two-resources.json")).unwrap()
}

/// Collect both kinds from the recording, as `AwsCollector::fetch` would.
async fn collect_all() -> Vec<LiveResource> {
    let rec = recording();
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

#[tokio::test]
async fn security_group_survives_the_wire() {
    let rec = recording();
    let live = security_group::fetch(&replay_client(&rec, &["DescribeSecurityGroups"]))
        .await
        .unwrap();

    assert_eq!(live.len(), 1);
    let sg = &live[0];
    assert_eq!(sg.cloud_id, "sg-00000000000000001");
    assert_eq!(sg.kind, ResourceKind::AwsSecurityGroup);
    assert_eq!(sg.attributes["name"], "web");
    assert_eq!(sg.attributes["vpc_id"], "vpc-00000000000000001");
    assert_eq!(sg.attributes["tags"]["Name"], "web");

    // Rule normalization, straight off the wire rather than from a builder.
    let ingress = &sg.attributes["ingress"][0];
    assert_eq!(ingress["from_port"], 443);
    assert_eq!(ingress["protocol"], "tcp");
    assert_eq!(ingress["cidr_blocks"][0], "0.0.0.0/0");

    // All-traffic egress: AWS omits the ports entirely, so this asserts the
    // absent-port -> 0 normalization against real response shape.
    let egress = &sg.attributes["egress"][0];
    assert_eq!(egress["protocol"], "-1");
    assert_eq!(egress["from_port"], 0);
    assert_eq!(egress["to_port"], 0);
}

#[tokio::test]
async fn instance_survives_the_wire() {
    let rec = recording();
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

#[tokio::test]
async fn clean_account_reports_no_drift() {
    // The full pipeline: recorded AWS bytes -> collectors -> diff, against a
    // state file that matches. This is the smoke test that previously required
    // a real account.
    let declared = uncia::state::parse(include_str!("fixtures/replay_state_clean.json")).unwrap();
    let report = uncia::diff::behavioral::compare(&declared, &collect_all().await);

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
        let resources = state["values"]["root_module"]["resources"]
            .as_array_mut()
            .unwrap();
        // SG: declared without the 443 rule -> live has an extra rule.
        resources[0]["values"]["ingress"] = serde_json::json!([]);
        // Instance: declared bigger, and with IMDSv1 still allowed.
        resources[1]["values"]["instance_type"] = serde_json::json!("t3.large");
        resources[1]["values"]["metadata_options"][0]["http_tokens"] =
            serde_json::json!("optional");
    }

    let declared = uncia::state::parse(&state.to_string()).unwrap();
    let report = uncia::diff::behavioral::compare(&declared, &collect_all().await);

    let fields: Vec<&str> = report
        .drifts
        .iter()
        .filter_map(|d| match &d.kind {
            DriftKind::FieldChanged { field, .. } => Some(field.as_str()),
            _ => None,
        })
        .collect();

    assert!(fields.contains(&"ingress"), "got: {fields:?}");
    assert!(fields.contains(&"instance_type"), "got: {fields:?}");
    assert!(fields.contains(&"metadata_options"), "got: {fields:?}");
    assert_eq!(report.drifts.len(), 3, "{:?}", report.drifts);
}

#[tokio::test]
async fn terminated_instance_reads_as_missing() {
    // Live returns nothing (the box is gone); state still declares it.
    let declared = uncia::state::parse(include_str!("fixtures/replay_state_clean.json")).unwrap();
    let sg_only = security_group::fetch(&replay_client(&recording(), &["DescribeSecurityGroups"]))
        .await
        .unwrap();

    let report = uncia::diff::behavioral::compare(&declared, &sg_only);

    assert_eq!(report.drifts.len(), 1);
    assert!(matches!(report.drifts[0].kind, DriftKind::Missing));
    assert_eq!(report.drifts[0].resource.0, "aws_instance.web");
}
