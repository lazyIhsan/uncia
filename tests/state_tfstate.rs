//! Tests for the raw `.tfstate` (schema v4) parser.

use uncia::state::tfstate::parse;
use uncia::{ResourceKind, UnciaError};

#[test]
fn parses_root_and_module_resources() {
    let resources = parse(include_str!("fixtures/raw_tfstate.json")).unwrap();

    let addresses: Vec<&str> = resources.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(
        addresses,
        [
            "aws_security_group.web",
            "aws_instance.web",
            "module.network.aws_instance.db",
        ]
    );

    let sg = &resources[0];
    assert_eq!(sg.kind, ResourceKind::AwsSecurityGroup);
    assert_eq!(sg.cloud_id(), Some("sg-0123456789abcdef0"));
    // Attributes pass through untouched, nested structures included.
    assert_eq!(sg.attributes["ingress"][0]["from_port"], 443);

    assert_eq!(resources[1].kind, ResourceKind::AwsInstance);
    assert_eq!(resources[1].cloud_id(), Some("i-0abc123def4567890"));
}

#[test]
fn reconstructs_count_and_for_each_addresses() {
    let resources = parse(include_str!("fixtures/raw_indexed.json")).unwrap();

    let addresses: Vec<&str> = resources.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(
        addresses,
        [
            "aws_instance.counted[0]",
            "aws_instance.counted[1]",
            "aws_instance.keyed[\"blue\"]",
        ]
    );
}

#[test]
fn skips_data_sources_and_deposed_instances() {
    let resources = parse(include_str!("fixtures/raw_deposed.json")).unwrap();

    // The data source is dropped; only the current (non-deposed) object of the
    // managed resource survives.
    let addresses: Vec<&str> = resources.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(addresses, ["aws_instance.web"]);
    assert_eq!(resources[0].cloud_id(), Some("i-current000000000"));
}

#[test]
fn rejects_unsupported_schema_version() {
    let err = parse(include_str!("fixtures/raw_version3.json")).unwrap_err();
    assert!(
        matches!(&err, UnciaError::UnsupportedStateVersion { found } if *found == 3),
        "got: {err:?}"
    );
}

#[test]
fn empty_resources_list_is_empty() {
    let resources = parse(r#"{"version": 4, "resources": []}"#).unwrap();
    assert!(resources.is_empty());
}
