//! AWS collector implementation.

pub mod ec2;
pub mod load_balancer;
pub mod security_group;
pub mod target_group;

use async_trait::async_trait;
use aws_config::BehaviorVersion;

use super::{Collector, LiveResource};

/// Collects live resource state from AWS via the standard SDK credential and
/// region chain (env vars, shared config/credentials files, IMDS).
///
/// One client per AWS service — EC2 and ELBv2 are separate generated SDK
/// crates with separate client types, so there is no single client to share
/// across `ec2`/`security_group` and `load_balancer`.
pub struct AwsCollector {
    ec2: aws_sdk_ec2::Client,
    elbv2: aws_sdk_elasticloadbalancingv2::Client,
}

impl AwsCollector {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        Self {
            ec2: aws_sdk_ec2::Client::new(&config),
            elbv2: aws_sdk_elasticloadbalancingv2::Client::new(&config),
        }
    }
}

#[async_trait]
impl Collector for AwsCollector {
    fn name(&self) -> &str {
        "aws"
    }

    async fn fetch(&self) -> crate::Result<Vec<LiveResource>> {
        let mut out = security_group::fetch(&self.ec2).await?;
        out.extend(ec2::fetch(&self.ec2).await?);
        out.extend(load_balancer::fetch(&self.elbv2).await?);
        out.extend(target_group::fetch(&self.elbv2).await?);
        Ok(out)
    }
}
