//! AWS load balancer collection.
//!
//! Fetches ALBs, NLBs, and GWLBs via `DescribeLoadBalancers` and normalizes
//! each into the attribute names Terraform state uses for `aws_lb`.
//!
//! **Deliberately minimal.** The only thing this collector exists to support
//! today is `sg_membership` discovering a load balancer as a member of a
//! security group it's attached to — an ALB's ENI carries whatever security
//! groups the load balancer names, exactly like an EC2 instance carries
//! `vpc_security_group_ids`. So only `id` (the ARN) and `security_groups` are
//! normalized; full behavioral tracking of a load balancer's other attributes
//! (idle timeout, scheme, subnets, ...) is unhandled — `diff::behavioral`
//! skips any kind with no `FIELDS` entry, so this is silent by design, not an
//! oversight, until that tracking is built as its own feature.
//!
//! Network and Gateway Load Balancers commonly report an empty
//! `security_groups` list (NLBs only gained optional security-group support
//! in 2023, and GWLBs never had it) — nothing here special-cases that; an
//! empty list just contributes no membership edges, same as an ALB with none
//! attached.

use aws_sdk_elasticloadbalancingv2::error::DisplayErrorContext;
use aws_sdk_elasticloadbalancingv2::types::LoadBalancer;
use serde_json::{Map, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// Fetch and normalize all load balancers visible to the client.
pub async fn fetch(
    client: &aws_sdk_elasticloadbalancingv2::Client,
) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();
    let mut pages = client.describe_load_balancers().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!(
                "DescribeLoadBalancers: {}",
                DisplayErrorContext(&e)
            ))
        })?;
        for lb in page.load_balancers() {
            if let Some(live) = normalize(lb) {
                out.push(live);
            }
        }
    }
    Ok(out)
}

/// Normalize one API-shaped load balancer into Terraform-state-shaped
/// attributes. Returns `None` for a load balancer with no ARN (never observed
/// in practice, but the API models it as optional).
fn normalize(lb: &LoadBalancer) -> Option<LiveResource> {
    let arn = lb.load_balancer_arn()?.to_string();

    let security_groups: Vec<&str> = lb.security_groups().iter().map(String::as_str).collect();

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(arn));
    attributes.insert("security_groups".into(), json!(security_groups));

    Some(LiveResource {
        cloud_id: arn,
        kind: ResourceKind::AwsLoadBalancer,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_elasticloadbalancingv2::types::LoadBalancerTypeEnum;

    fn alb() -> LoadBalancer {
        LoadBalancer::builder()
            .load_balancer_arn(
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188",
            )
            .load_balancer_name("my-alb")
            .r#type(LoadBalancerTypeEnum::Application)
            .security_groups("sg-1111")
            .security_groups("sg-2222")
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let live = normalize(&alb()).unwrap();

        assert_eq!(
            live.cloud_id,
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188"
        );
        assert_eq!(live.kind, ResourceKind::AwsLoadBalancer);
        assert_eq!(live.attributes["id"], live.cloud_id.as_str());
        assert_eq!(
            live.attributes["security_groups"],
            json!(["sg-1111", "sg-2222"])
        );
    }

    #[test]
    fn a_load_balancer_with_no_security_groups_normalizes_to_an_empty_list() {
        // The common NLB/GWLB shape: no special-casing, just nothing to
        // contribute as a membership edge.
        let nlb = LoadBalancer::builder()
            .load_balancer_arn(
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/1234567890abcdef",
            )
            .r#type(LoadBalancerTypeEnum::Network)
            .build();

        let live = normalize(&nlb).unwrap();
        assert_eq!(live.attributes["security_groups"], json!([]));
    }

    #[test]
    fn a_load_balancer_with_no_arn_is_not_collected() {
        let bare = LoadBalancer::builder().load_balancer_name("no-arn").build();
        assert!(normalize(&bare).is_none());
    }
}
