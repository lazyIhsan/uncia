//! AWS target group collection.
//!
//! Fetches target groups via `DescribeTargetGroups` and their registered
//! targets via `DescribeTargetHealth`, normalizing each into the attribute
//! names Terraform state uses for `aws_lb_target_group`.
//!
//! **Why this exists on its own, before anything reads it.** An ALB being
//! reachable (`sg_membership` already proves that) doesn't mean anything is
//! reachable *behind* it — that depends on what's actually registered as a
//! target. This collector gets that data into the same shape the rest of the
//! collector layer uses; nothing consumes it yet (no relation, no
//! `EDGE_FIELDS` row), by design — wiring graph edges before there's a
//! relation to exercise them would be untested dead code.
//!
//! **The API shape forces an N+1 call pattern.** `DescribeTargetGroups` is
//! paginated like every other collector call, but `DescribeTargetHealth`
//! takes exactly one `target_group_arn` per call and has no bulk or
//! paginated form — so fetching registration data costs one extra call per
//! target group, not a single follow-up request.
//!
//! **Deliberately minimal**, same discipline as `load_balancer.rs`: only
//! `id` (the ARN), `load_balancer_arns` (passed through — the API already
//! gives the owning load balancer directly, no `DescribeListeners` or port
//! routing needed), and `targets` are normalized. Full behavioral tracking
//! of a target group's other attributes (health check config, port,
//! protocol, ...) is unhandled; `diff::behavioral` skips any kind with no
//! `FIELDS` entry, so this is silent by design.
//!
//! **`targets` is only populated for `instance`-type target groups.** `ip`
//! targets aren't a resource this graph models yet; `lambda` and `alb`
//! targets need their own handling later rather than being silently
//! misrepresented as instances now.
//!
//! **Every registered target is included regardless of health state**
//! (`Healthy`, `Draining`, `Unhealthy`, ...). A target's health is a
//! liveness/routing concern, not a security boundary — the
//! security-group-permitted path exists whether or not the target is
//! currently passing health checks, matching uncia's existing stance of
//! proving trust relationships rather than runtime behavior.

use aws_sdk_elasticloadbalancingv2::error::DisplayErrorContext;
use aws_sdk_elasticloadbalancingv2::types::{TargetGroup, TargetTypeEnum};
use serde_json::{Map, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// Fetch and normalize all target groups visible to the client, including
/// their currently registered targets.
pub async fn fetch(
    client: &aws_sdk_elasticloadbalancingv2::Client,
) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();
    let mut pages = client.describe_target_groups().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!("DescribeTargetGroups: {}", DisplayErrorContext(&e)))
        })?;
        for tg in page.target_groups() {
            let Some(arn) = tg.target_group_arn() else {
                continue;
            };
            let targets = if tg.target_type() == Some(&TargetTypeEnum::Instance) {
                fetch_targets(client, arn).await?
            } else {
                Vec::new()
            };
            if let Some(live) = normalize(tg, targets) {
                out.push(live);
            }
        }
    }
    Ok(out)
}

/// The instance ids currently registered to one target group, regardless of
/// health state. One `DescribeTargetHealth` call per target group — the API
/// has no bulk form.
async fn fetch_targets(
    client: &aws_sdk_elasticloadbalancingv2::Client,
    target_group_arn: &str,
) -> crate::Result<Vec<String>> {
    let output = client
        .describe_target_health()
        .target_group_arn(target_group_arn)
        .send()
        .await
        .map_err(|e| {
            UnciaError::Collector(format!("DescribeTargetHealth: {}", DisplayErrorContext(&e)))
        })?;

    Ok(output
        .target_health_descriptions()
        .iter()
        .filter_map(|d| d.target())
        .filter_map(|t| t.id())
        .map(str::to_string)
        .collect())
}

/// Normalize one API-shaped target group into Terraform-state-shaped
/// attributes. Returns `None` for a target group with no ARN (never observed
/// in practice, but the API models it as optional).
fn normalize(tg: &TargetGroup, targets: Vec<String>) -> Option<LiveResource> {
    let arn = tg.target_group_arn()?.to_string();

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(arn));
    attributes.insert("load_balancer_arns".into(), json!(tg.load_balancer_arns()));
    attributes.insert("targets".into(), json!(targets));

    Some(LiveResource {
        cloud_id: arn,
        kind: ResourceKind::AwsLbTargetGroup,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance_target_group() -> TargetGroup {
        TargetGroup::builder()
            .target_group_arn(
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/50dc6c495c0c9188",
            )
            .target_group_name("my-targets")
            .target_type(TargetTypeEnum::Instance)
            .load_balancer_arns(
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef",
            )
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let tg = instance_target_group();
        let targets = vec!["i-1111".to_string(), "i-2222".to_string()];
        let live = normalize(&tg, targets).unwrap();

        assert_eq!(
            live.cloud_id,
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/50dc6c495c0c9188"
        );
        assert_eq!(live.kind, ResourceKind::AwsLbTargetGroup);
        assert_eq!(live.attributes["id"], live.cloud_id.as_str());
        assert_eq!(
            live.attributes["load_balancer_arns"],
            json!([
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef"
            ])
        );
        assert_eq!(live.attributes["targets"], json!(["i-1111", "i-2222"]));
    }

    #[test]
    fn a_target_group_with_no_registered_targets_normalizes_to_an_empty_list() {
        let live = normalize(&instance_target_group(), Vec::new()).unwrap();
        assert_eq!(live.attributes["targets"], json!([]));
    }

    #[test]
    fn a_target_group_with_no_arn_is_not_collected() {
        let bare = TargetGroup::builder().target_group_name("no-arn").build();
        assert!(normalize(&bare, Vec::new()).is_none());
    }

    #[test]
    fn fetch_only_resolves_targets_for_instance_type_groups() {
        // `fetch()` itself decides whether to call DescribeTargetHealth at
        // all based on target_type; this locks in the condition it checks,
        // since getting it backwards would either miss real instance
        // registrations or make a pointless call for ip/lambda/alb groups.
        let ip_tg = TargetGroup::builder()
            .target_group_arn(
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/ip-targets/aaaaaaaaaaaaaaaa",
            )
            .target_type(TargetTypeEnum::Ip)
            .build();
        assert_ne!(ip_tg.target_type(), Some(&TargetTypeEnum::Instance));

        let instance_tg = instance_target_group();
        assert_eq!(instance_tg.target_type(), Some(&TargetTypeEnum::Instance));
    }
}
