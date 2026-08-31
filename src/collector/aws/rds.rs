//! AWS RDS instance collection.
//!
//! Fetches DB instances via `DescribeDBInstances` and normalizes each into
//! the attribute names Terraform state uses for `aws_db_instance`.
//!
//! **The join key is not the identifier or the ARN.** Terraform's
//! `aws_db_instance.id` is `DbiResourceId` — an immutable AWS-internal id,
//! not `DBInstanceIdentifier` (the human-chosen name) and not the ARN.
//! Keying on either of those would silently break the join between declared
//! and live state for every RDS instance, so `dbi_resource_id` is read
//! directly rather than assumed.
//!
//! **Deliberately minimal**, same discipline as `load_balancer.rs`: only
//! `id` and `vpc_security_group_ids` are normalized. Full behavioral
//! tracking of an instance's other attributes (engine, instance class,
//! storage, ...) is unhandled; `diff::behavioral` skips any kind with no
//! `FIELDS` entry, so this is silent by design.
//!
//! **Every VPC security group membership is included regardless of
//! `status`** (`active`, `adding`, `removing`, ...). Membership is a trust
//! question, not a liveness one — the same reasoning Phase 1's target-group
//! collector applies to target health.

use aws_sdk_rds::error::DisplayErrorContext;
use aws_sdk_rds::types::DbInstance;
use serde_json::{Map, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// Fetch and normalize all RDS DB instances visible to the client.
pub async fn fetch(client: &aws_sdk_rds::Client) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();
    let mut pages = client.describe_db_instances().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!("DescribeDBInstances: {}", DisplayErrorContext(&e)))
        })?;
        for instance in page.db_instances() {
            if let Some(live) = normalize(instance) {
                out.push(live);
            }
        }
    }
    Ok(out)
}

/// Normalize one API-shaped DB instance into Terraform-state-shaped
/// attributes. Returns `None` for an instance with no `DbiResourceId`
/// (never observed in practice, but the API models it as optional).
fn normalize(instance: &DbInstance) -> Option<LiveResource> {
    let resource_id = instance.dbi_resource_id()?.to_string();

    let security_group_ids: Vec<&str> = instance
        .vpc_security_groups()
        .iter()
        .filter_map(|membership| membership.vpc_security_group_id())
        .collect();

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(resource_id));
    attributes.insert("vpc_security_group_ids".into(), json!(security_group_ids));

    Some(LiveResource {
        cloud_id: resource_id,
        kind: ResourceKind::AwsDbInstance,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_rds::types::VpcSecurityGroupMembership;

    fn with_memberships() -> DbInstance {
        DbInstance::builder()
            .db_instance_identifier("my-db")
            .dbi_resource_id("db-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            .vpc_security_groups(
                VpcSecurityGroupMembership::builder()
                    .vpc_security_group_id("sg-1111")
                    .status("active")
                    .build(),
            )
            .vpc_security_groups(
                VpcSecurityGroupMembership::builder()
                    .vpc_security_group_id("sg-2222")
                    .status("adding")
                    .build(),
            )
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let live = normalize(&with_memberships()).unwrap();

        assert_eq!(live.cloud_id, "db-ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(live.kind, ResourceKind::AwsDbInstance);
        assert_eq!(live.attributes["id"], "db-ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(
            live.attributes["vpc_security_group_ids"],
            json!(["sg-1111", "sg-2222"]),
            "every membership survives regardless of status"
        );
    }

    #[test]
    fn an_instance_with_no_memberships_normalizes_to_an_empty_list() {
        let instance = DbInstance::builder().dbi_resource_id("db-EMPTY").build();

        let live = normalize(&instance).unwrap();
        assert_eq!(live.attributes["vpc_security_group_ids"], json!([]));
    }

    #[test]
    fn an_instance_with_no_resource_id_is_not_collected() {
        let bare = DbInstance::builder()
            .db_instance_identifier("no-resource-id")
            .build();
        assert!(normalize(&bare).is_none());
    }
}
