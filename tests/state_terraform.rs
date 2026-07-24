//! Golden tests for the `terraform show -json` state parser.
//!
//! The bad-input tests assert the *specific* error variant: per the
//! architecture invariants, each way an input can be wrong must fail loudly
//! with an error naming the actual problem — never a generic failure, and
//! never a silent empty parse.

use uncia::state::terraform::parse;
use uncia::{ResourceKind, UnciaError};

#[test]
fn parses_root_module_resources() {
    let resources = parse(include_str!("fixtures/simple.json")).unwrap();

    // The data-mode resource is filtered out; the three managed ones remain.
    let addresses: Vec<&str> = resources.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(
        addresses,
        [
            "aws_security_group.web",
            "aws_instance.web",
            "aws_s3_bucket.assets"
        ]
    );

    let sg = &resources[0];
    assert_eq!(sg.kind, ResourceKind::AwsSecurityGroup);
    assert_eq!(sg.cloud_id(), Some("sg-0123456789abcdef0"));
    // Attributes pass through untouched, nested structures included.
    assert_eq!(sg.attributes["vpc_id"], "vpc-0aa11bb22cc33dd44");
    assert_eq!(sg.attributes["ingress"][0]["from_port"], 443);

    let instance = &resources[1];
    assert_eq!(instance.kind, ResourceKind::AwsInstance);
    assert_eq!(instance.cloud_id(), Some("i-0abc123def4567890"));
    assert_eq!(instance.attributes["instance_type"], "t3.medium");

    // Unknown types are carried through as Other, not dropped.
    let bucket = &resources[2];
    assert_eq!(
        bucket.kind,
        ResourceKind::Other("aws_s3_bucket".to_string())
    );
    assert_eq!(bucket.kind.as_str(), "aws_s3_bucket");
}

#[test]
fn walks_child_modules_recursively() {
    let resources = parse(include_str!("fixtures/child_modules.json")).unwrap();

    let addresses: Vec<&str> = resources.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(
        addresses,
        [
            "aws_security_group.edge",
            "module.network.aws_security_group.internal",
            "module.network.module.private.aws_instance.db"
        ]
    );
}

#[test]
fn empty_state_is_legitimately_empty() {
    let resources = parse(include_str!("fixtures/empty_state.json")).unwrap();
    assert!(resources.is_empty());
}

#[test]
fn rejects_non_json() {
    let err = parse("this is not json").unwrap_err();
    assert!(matches!(err, UnciaError::StateJson(_)), "got: {err:?}");
}

#[test]
fn rejects_encrypted_state() {
    let err = parse(include_str!("fixtures/encrypted_tofu.json")).unwrap_err();
    assert!(matches!(err, UnciaError::EncryptedState), "got: {err:?}");
}

#[test]
fn rejects_raw_tfstate_file() {
    let err = parse(include_str!("fixtures/raw_tfstate.json")).unwrap_err();
    assert!(matches!(err, UnciaError::RawStateFile), "got: {err:?}");
}

#[test]
fn rejects_unsupported_format_version() {
    let err = parse(include_str!("fixtures/bad_version.json")).unwrap_err();
    assert!(
        matches!(&err, UnciaError::UnsupportedFormatVersion { found } if found == "2.0"),
        "got: {err:?}"
    );
}

#[test]
fn rejects_plan_output_rather_than_reporting_empty() {
    // A plan document has a 1.x format_version and no `values` key: without
    // the plan guard it would fall through to the empty-state case and
    // report zero resources — indistinguishable from "no drift".
    let err = parse(include_str!("fixtures/plan_output.json")).unwrap_err();
    assert!(
        matches!(&err, UnciaError::WrongDocumentKind { marker } if marker == "planned_values"),
        "got: {err:?}"
    );
}
