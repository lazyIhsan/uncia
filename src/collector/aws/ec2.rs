//! AWS EC2 instance collection.
//!
//! Fetches instances via `DescribeInstances` and normalizes each into the
//! attribute names and shapes Terraform state uses for `aws_instance`, so the
//! diff compares like against like.
//!
//! Compared (the security-focused v1 field set): `instance_type`, `ami`,
//! `tags`, `vpc_security_group_ids`, `iam_instance_profile`, and
//! `metadata_options` (IMDSv2). Volatile fields — `public_ip`, `private_ip`,
//! public/private DNS, `instance_state`, `arn` — are never emitted for
//! comparison: they change on stop/start and would drown the signal.
//!
//! Normalization pitfalls handled here:
//! - Terminated / shutting-down instances are skipped (return `None`). Such an
//!   instance is effectively gone, so the declared resource fails to join and
//!   is correctly reported as `Missing` rather than matched to a dead box.
//!   Stopped instances are kept — their config is intact.
//! - `iam_instance_profile`: the API returns an ARN
//!   (`arn:aws:iam::123:instance-profile/NAME`) but Terraform state stores the
//!   bare NAME; the trailing segment is extracted. An unset profile is emitted
//!   as `""` to match Terraform's representation of an empty optional string.
//!   (An instance profile with an IAM *path* is an unhandled edge — the bare
//!   name still wins.)
//! - `metadata_options` is emitted as Terraform's canonical one-element block.
//!   The diff compares only the keys uncia understands, so provider-version
//!   additions (e.g. `http_protocol_ipv6`) in state don't read as false drift.

use aws_sdk_ec2::error::DisplayErrorContext;
use aws_sdk_ec2::types::Instance;
use serde_json::{Map, Value, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// Fetch and normalize all non-terminated instances visible to the client.
pub async fn fetch(client: &aws_sdk_ec2::Client) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();
    let mut pages = client.describe_instances().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!("DescribeInstances: {}", DisplayErrorContext(&e)))
        })?;
        for reservation in page.reservations() {
            for instance in reservation.instances() {
                if let Some(live) = normalize(instance) {
                    out.push(live);
                }
            }
        }
    }
    Ok(out)
}

/// Normalize one API-shaped instance into Terraform-state-shaped attributes.
/// Returns `None` for a terminated/shutting-down instance (treated as gone) or
/// one with no id.
fn normalize(instance: &Instance) -> Option<LiveResource> {
    let state = instance.state().and_then(|s| s.name()).map(|n| n.as_str());
    if matches!(state, Some("terminated") | Some("shutting-down")) {
        return None;
    }

    let instance_id = instance.instance_id()?.to_string();

    let tags: Map<String, Value> = instance
        .tags()
        .iter()
        .filter_map(|t| Some((t.key()?.to_string(), json!(t.value().unwrap_or_default()))))
        .collect();

    let security_group_ids: Vec<&str> = instance
        .security_groups()
        .iter()
        .filter_map(|g| g.group_id())
        .collect();

    let iam_instance_profile = instance
        .iam_instance_profile()
        .and_then(|p| p.arn())
        .map(profile_name_from_arn)
        .unwrap_or("");

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(instance_id));
    attributes.insert(
        "instance_type".into(),
        json!(
            instance
                .instance_type()
                .map(|t| t.as_str())
                .unwrap_or_default()
        ),
    );
    attributes.insert("ami".into(), json!(instance.image_id().unwrap_or_default()));
    attributes.insert("tags".into(), Value::Object(tags));
    attributes.insert("vpc_security_group_ids".into(), json!(security_group_ids));
    attributes.insert("iam_instance_profile".into(), json!(iam_instance_profile));
    attributes.insert("metadata_options".into(), metadata_options(instance));

    Some(LiveResource {
        cloud_id: instance_id,
        kind: ResourceKind::AwsInstance,
        attributes,
    })
}

/// The bare instance-profile name from its ARN
/// (`arn:aws:iam::123:instance-profile/NAME` -> `NAME`).
fn profile_name_from_arn(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

/// Terraform models `metadata_options` as a one-element block; match that shape.
fn metadata_options(instance: &Instance) -> Value {
    let Some(mo) = instance.metadata_options() else {
        return json!([]);
    };
    json!([{
        "http_endpoint": mo.http_endpoint().map(|e| e.as_str()).unwrap_or_default(),
        "http_tokens": mo.http_tokens().map(|t| t.as_str()).unwrap_or_default(),
        "http_put_response_hop_limit": mo.http_put_response_hop_limit().unwrap_or(0),
        "instance_metadata_tags": mo
            .instance_metadata_tags()
            .map(|t| t.as_str())
            .unwrap_or_default(),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ec2::types::{
        GroupIdentifier, HttpTokensState, IamInstanceProfile, InstanceMetadataEndpointState,
        InstanceMetadataOptionsResponse, InstanceMetadataTagsState, InstanceState,
        InstanceStateName, InstanceType, Tag,
    };

    fn running_instance() -> Instance {
        Instance::builder()
            .instance_id("i-0abc123def4567890")
            .instance_type(InstanceType::T3Medium)
            .image_id("ami-0aabbccdd11223344")
            .state(
                InstanceState::builder()
                    .name(InstanceStateName::Running)
                    .build(),
            )
            .tags(Tag::builder().key("Name").value("web").build())
            .security_groups(GroupIdentifier::builder().group_id("sg-1111").build())
            .security_groups(GroupIdentifier::builder().group_id("sg-2222").build())
            .iam_instance_profile(
                IamInstanceProfile::builder()
                    .arn("arn:aws:iam::123456789012:instance-profile/app-role")
                    .build(),
            )
            .metadata_options(
                InstanceMetadataOptionsResponse::builder()
                    .http_endpoint(InstanceMetadataEndpointState::Enabled)
                    .http_tokens(HttpTokensState::Required)
                    .http_put_response_hop_limit(2)
                    .instance_metadata_tags(InstanceMetadataTagsState::Disabled)
                    .build(),
            )
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let live = normalize(&running_instance()).unwrap();

        assert_eq!(live.cloud_id, "i-0abc123def4567890");
        assert_eq!(live.kind, ResourceKind::AwsInstance);
        assert_eq!(live.attributes["instance_type"], "t3.medium");
        assert_eq!(live.attributes["ami"], "ami-0aabbccdd11223344");
        assert_eq!(live.attributes["tags"]["Name"], "web");
        assert_eq!(
            live.attributes["vpc_security_group_ids"],
            json!(["sg-1111", "sg-2222"])
        );
        // ARN normalized down to the bare profile name.
        assert_eq!(live.attributes["iam_instance_profile"], "app-role");

        let meta = &live.attributes["metadata_options"][0];
        assert_eq!(meta["http_tokens"], "required");
        assert_eq!(meta["http_put_response_hop_limit"], 2);
        assert_eq!(meta["http_endpoint"], "enabled");
    }

    #[test]
    fn terminated_instance_is_not_collected() {
        let terminated = Instance::builder()
            .instance_id("i-deadbeef00000000")
            .state(
                InstanceState::builder()
                    .name(InstanceStateName::Terminated)
                    .build(),
            )
            .build();
        assert!(normalize(&terminated).is_none());
    }

    #[test]
    fn instance_without_profile_emits_empty_string() {
        let bare = Instance::builder()
            .instance_id("i-noprofile0000000")
            .instance_type(InstanceType::T3Micro)
            .image_id("ami-1")
            .state(
                InstanceState::builder()
                    .name(InstanceStateName::Stopped)
                    .build(),
            )
            .build();
        let live = normalize(&bare).unwrap();
        assert_eq!(live.attributes["iam_instance_profile"], "");
        // A stopped instance is still collected.
        assert_eq!(live.cloud_id, "i-noprofile0000000");
    }
}
