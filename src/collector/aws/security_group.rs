//! AWS security group collection.
//!
//! Fetches security groups via `DescribeSecurityGroups` and normalizes each
//! into the attribute names and shapes Terraform state uses for
//! `aws_security_group`, so the diff compares like against like.
//!
//! Normalization pitfalls handled here:
//! - protocol `"-1"` means "all"; Terraform stores it as the literal `"-1"`.
//! - `from_port`/`to_port` are absent on all-traffic permissions; Terraform
//!   stores them as `0`.
//! - AWS models a self-reference as a `UserIdGroupPair` whose group id equals
//!   the group's own id; Terraform models it as `self = true` and excludes
//!   the group from `security_groups`.
//! - AWS may group many sources under one permission where Terraform splits
//!   them into several blocks (and vice versa); the diff compares rules as
//!   exploded atoms, so grouping differences never register as drift.
//!
//! Not yet detected: per-rule description drift (AWS carries descriptions
//! per source range, Terraform per block; reconciling them is deferred).
//!
//! Known gap — inline rules only. `aws_security_group` can carry its rules
//! two mutually exclusive ways: **inline** `ingress`/`egress` blocks on the
//! group (what the diff compares against), or **separate** rule resources
//! (`aws_security_group_rule`, or the newer
//! `aws_vpc_security_group_ingress_rule` / `_egress_rule`). With the separate
//! form the group's own inline `ingress`/`egress` are empty in state while the
//! rules live as their own resources, so the diff would compare live rules
//! against an empty declared set and report every rule as drift. Those
//! separate rule resources are also `ResourceKind::Other` today, so they are
//! not collected or checked. Detecting drift for separately-declared rules is
//! deferred; see `docs/ARCHITECTURE.md` non-goals.

use aws_sdk_ec2::error::DisplayErrorContext;
use aws_sdk_ec2::types::{IpPermission, SecurityGroup};
use serde_json::{Map, Value, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// Fetch and normalize all security groups visible to the client.
pub async fn fetch(client: &aws_sdk_ec2::Client) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();
    let mut pages = client.describe_security_groups().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!(
                "DescribeSecurityGroups: {}",
                DisplayErrorContext(&e)
            ))
        })?;
        for sg in page.security_groups() {
            if let Some(live) = normalize(sg) {
                out.push(live);
            }
        }
    }
    Ok(out)
}

/// Normalize one API-shaped security group into Terraform-state-shaped
/// attributes. Returns `None` for a group with no id (never observed in
/// practice, but the API models it as optional).
fn normalize(sg: &SecurityGroup) -> Option<LiveResource> {
    let group_id = sg.group_id()?.to_string();

    let tags: Map<String, Value> = sg
        .tags()
        .iter()
        .filter_map(|t| Some((t.key()?.to_string(), json!(t.value().unwrap_or_default()))))
        .collect();

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(group_id));
    attributes.insert("name".into(), json!(sg.group_name().unwrap_or_default()));
    attributes.insert(
        "description".into(),
        json!(sg.description().unwrap_or_default()),
    );
    attributes.insert("vpc_id".into(), json!(sg.vpc_id().unwrap_or_default()));
    attributes.insert("owner_id".into(), json!(sg.owner_id().unwrap_or_default()));
    attributes.insert("tags".into(), Value::Object(tags));
    attributes.insert(
        "ingress".into(),
        rules_to_value(sg.ip_permissions(), &group_id),
    );
    attributes.insert(
        "egress".into(),
        rules_to_value(sg.ip_permissions_egress(), &group_id),
    );

    Some(LiveResource {
        cloud_id: group_id,
        kind: ResourceKind::AwsSecurityGroup,
        attributes,
    })
}

fn rules_to_value(permissions: &[IpPermission], own_group_id: &str) -> Value {
    Value::Array(
        permissions
            .iter()
            .map(|p| {
                let mut security_groups = Vec::new();
                let mut self_reference = false;
                for pair in p.user_id_group_pairs() {
                    if let Some(gid) = pair.group_id() {
                        if gid == own_group_id {
                            self_reference = true;
                        } else {
                            security_groups.push(gid.to_string());
                        }
                    }
                }
                json!({
                    "from_port": p.from_port().unwrap_or(0),
                    "to_port": p.to_port().unwrap_or(0),
                    "protocol": p.ip_protocol().unwrap_or("-1"),
                    "cidr_blocks": p.ip_ranges().iter()
                        .filter_map(|r| r.cidr_ip()).collect::<Vec<_>>(),
                    "ipv6_cidr_blocks": p.ipv6_ranges().iter()
                        .filter_map(|r| r.cidr_ipv6()).collect::<Vec<_>>(),
                    "prefix_list_ids": p.prefix_list_ids().iter()
                        .filter_map(|r| r.prefix_list_id()).collect::<Vec<_>>(),
                    "security_groups": security_groups,
                    "self": self_reference,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ec2::types::{IpRange, Tag, UserIdGroupPair};

    fn sample_group() -> SecurityGroup {
        SecurityGroup::builder()
            .group_id("sg-0123456789abcdef0")
            .group_name("web")
            .description("web tier")
            .vpc_id("vpc-0aa11bb22cc33dd44")
            .owner_id("123456789012")
            .tags(Tag::builder().key("Name").value("web").build())
            .ip_permissions(
                IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(443)
                    .to_port(443)
                    .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
                    .user_id_group_pairs(
                        UserIdGroupPair::builder()
                            .group_id("sg-0123456789abcdef0")
                            .build(),
                    )
                    .user_id_group_pairs(
                        UserIdGroupPair::builder()
                            .group_id("sg-other0000000000")
                            .build(),
                    )
                    .build(),
            )
            .ip_permissions_egress(
                IpPermission::builder()
                    .ip_protocol("-1")
                    .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
                    .build(),
            )
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let live = normalize(&sample_group()).unwrap();

        assert_eq!(live.cloud_id, "sg-0123456789abcdef0");
        assert_eq!(live.kind, ResourceKind::AwsSecurityGroup);
        assert_eq!(live.attributes["id"], "sg-0123456789abcdef0");
        assert_eq!(live.attributes["name"], "web");
        assert_eq!(live.attributes["vpc_id"], "vpc-0aa11bb22cc33dd44");
        assert_eq!(live.attributes["tags"]["Name"], "web");

        let ingress = &live.attributes["ingress"][0];
        assert_eq!(ingress["from_port"], 443);
        assert_eq!(ingress["protocol"], "tcp");
        assert_eq!(ingress["cidr_blocks"][0], "0.0.0.0/0");
        // Own-group pair becomes self=true and is excluded from the list.
        assert_eq!(ingress["self"], true);
        assert_eq!(ingress["security_groups"], json!(["sg-other0000000000"]));

        // All-traffic egress: absent ports normalize to 0, protocol "-1".
        let egress = &live.attributes["egress"][0];
        assert_eq!(egress["from_port"], 0);
        assert_eq!(egress["to_port"], 0);
        assert_eq!(egress["protocol"], "-1");
    }
}
