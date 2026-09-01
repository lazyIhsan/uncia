//! AWS collector implementation.

pub mod ec2;
pub mod ecs;
pub mod lambda;
pub mod load_balancer;
pub mod network_acl;
pub mod rds;
pub mod security_group;
pub mod target_group;

use async_trait::async_trait;
use aws_config::BehaviorVersion;

use super::{Collector, LiveResource};

/// Collects live resource state from AWS via the standard SDK credential and
/// region chain (env vars, shared config/credentials files, IMDS).
///
/// One client per AWS service — each is a separate generated SDK crate with
/// its own client type, so there is no single client to share across
/// collectors.
pub struct AwsCollector {
    ec2: aws_sdk_ec2::Client,
    elbv2: aws_sdk_elasticloadbalancingv2::Client,
    lambda: aws_sdk_lambda::Client,
    rds: aws_sdk_rds::Client,
    ecs: aws_sdk_ecs::Client,
}

impl AwsCollector {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        Self {
            ec2: aws_sdk_ec2::Client::new(&config),
            elbv2: aws_sdk_elasticloadbalancingv2::Client::new(&config),
            lambda: aws_sdk_lambda::Client::new(&config),
            rds: aws_sdk_rds::Client::new(&config),
            ecs: aws_sdk_ecs::Client::new(&config),
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
        out.extend(lambda::fetch(&self.lambda).await?);
        out.extend(rds::fetch(&self.rds).await?);
        out.extend(ecs::fetch(&self.ecs).await?);
        out.extend(network_acl::fetch(&self.ec2).await?);
        Ok(out)
    }
}
