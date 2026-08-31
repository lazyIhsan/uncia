//! AWS ECS service collection.
//!
//! Fetches services via `ListClusters` → `ListServices` → `DescribeServices`
//! and normalizes each into the attribute names Terraform state uses for
//! `aws_ecs_service`.
//!
//! **Why the subject is the service, not the task.** A running `Task`
//! carries no security groups at all — `DescribeTasks`' `attachments[].details`
//! has the ENI id, MAC address, subnet id, and private IP, never a security
//! group. Security groups for `awsvpc`-mode tasks live on the *service* that
//! runs them, in `network_configuration.awsvpc_configuration.security_groups`
//! — every task under that service inherits it. So there is nothing a
//! task-shaped collector could report that the service doesn't already say,
//! and the service is also what `aws_ecs_service` in Terraform actually
//! declares this on.
//!
//! **The three-level walk is not a choice.** Services are enumerated per
//! cluster (`ListServices` takes a `cluster`, with no cross-cluster listing
//! operation), and `DescribeServices` accepts at most 10 service ARNs per
//! call — a hard API limit, not a design decision — so the ARNs `ListServices`
//! returns are chunked before the batch describe.
//!
//! **Deliberately minimal**, same discipline as `load_balancer.rs`: only
//! `id` (the service ARN) and `vpc_security_group_ids` are normalized. Full
//! behavioral tracking of a service's other attributes (task definition,
//! desired count, deployment config, ...) is unhandled; `diff::behavioral`
//! skips any kind with no `FIELDS` entry, so this is silent by design.
//!
//! Services not running in `awsvpc` mode (EC2 launch type with bridge/host
//! networking, or services with no `network_configuration` at all) don't
//! carry a per-service security-group list — that normalizes to an empty
//! membership list, not a skipped service.

use aws_sdk_ecs::error::DisplayErrorContext;
use aws_sdk_ecs::types::Service;
use serde_json::{Map, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// `DescribeServices` accepts at most this many service ARNs per call.
const DESCRIBE_SERVICES_BATCH_SIZE: usize = 10;

/// Fetch and normalize all ECS services visible to the client, across every
/// cluster.
pub async fn fetch(client: &aws_sdk_ecs::Client) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();

    let mut cluster_pages = client.list_clusters().into_paginator().send();
    while let Some(page) = cluster_pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!("ListClusters: {}", DisplayErrorContext(&e)))
        })?;
        for cluster_arn in page.cluster_arns() {
            out.extend(fetch_cluster_services(client, cluster_arn).await?);
        }
    }

    Ok(out)
}

/// Every service in one cluster, fully described.
async fn fetch_cluster_services(
    client: &aws_sdk_ecs::Client,
    cluster_arn: &str,
) -> crate::Result<Vec<LiveResource>> {
    let mut service_arns = Vec::new();
    let mut service_pages = client
        .list_services()
        .cluster(cluster_arn)
        .into_paginator()
        .send();
    while let Some(page) = service_pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!("ListServices: {}", DisplayErrorContext(&e)))
        })?;
        service_arns.extend(page.service_arns().iter().cloned());
    }

    let mut out = Vec::new();
    for batch in service_arns.chunks(DESCRIBE_SERVICES_BATCH_SIZE) {
        let output = client
            .describe_services()
            .cluster(cluster_arn)
            .set_services(Some(batch.to_vec()))
            .send()
            .await
            .map_err(|e| {
                UnciaError::Collector(format!("DescribeServices: {}", DisplayErrorContext(&e)))
            })?;
        out.extend(output.services().iter().filter_map(normalize));
    }

    Ok(out)
}

/// Normalize one API-shaped service into Terraform-state-shaped attributes.
/// Returns `None` for a service with no ARN (never observed in practice, but
/// the API models it as optional).
fn normalize(service: &Service) -> Option<LiveResource> {
    let arn = service.service_arn()?.to_string();

    let security_group_ids: Vec<&str> = service
        .network_configuration()
        .and_then(|nc| nc.awsvpc_configuration())
        .map(|vpc_config| {
            vpc_config
                .security_groups()
                .iter()
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_default();

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(arn));
    attributes.insert("vpc_security_group_ids".into(), json!(security_group_ids));

    Some(LiveResource {
        cloud_id: arn,
        kind: ResourceKind::AwsEcsService,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ecs::types::{AwsVpcConfiguration, NetworkConfiguration};

    fn awsvpc_service() -> Service {
        Service::builder()
            .service_arn("arn:aws:ecs:us-east-1:123456789012:service/my-cluster/my-service")
            .service_name("my-service")
            .network_configuration(
                NetworkConfiguration::builder()
                    .awsvpc_configuration(
                        AwsVpcConfiguration::builder()
                            .security_groups("sg-1111")
                            .security_groups("sg-2222")
                            .subnets("subnet-1111")
                            .build()
                            .unwrap(),
                    )
                    .build(),
            )
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let live = normalize(&awsvpc_service()).unwrap();

        assert_eq!(
            live.cloud_id,
            "arn:aws:ecs:us-east-1:123456789012:service/my-cluster/my-service"
        );
        assert_eq!(live.kind, ResourceKind::AwsEcsService);
        assert_eq!(live.attributes["id"], live.cloud_id.as_str());
        assert_eq!(
            live.attributes["vpc_security_group_ids"],
            json!(["sg-1111", "sg-2222"])
        );
    }

    #[test]
    fn a_service_with_no_network_configuration_normalizes_to_an_empty_list() {
        // EC2 launch type with bridge/host networking, or no awsvpc config
        // at all.
        let service = Service::builder()
            .service_arn("arn:aws:ecs:us-east-1:123456789012:service/my-cluster/bridge-service")
            .build();

        let live = normalize(&service).unwrap();
        assert_eq!(live.attributes["vpc_security_group_ids"], json!([]));
    }

    #[test]
    fn a_service_with_no_arn_is_not_collected() {
        let bare = Service::builder().service_name("no-arn").build();
        assert!(normalize(&bare).is_none());
    }
}
