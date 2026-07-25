//! AWS collector implementation.

pub mod ec2;
pub mod security_group;

use async_trait::async_trait;
use aws_config::BehaviorVersion;

use super::{Collector, LiveResource};

/// Collects live resource state from AWS via the standard SDK credential and
/// region chain (env vars, shared config/credentials files, IMDS).
pub struct AwsCollector {
    client: aws_sdk_ec2::Client,
}

impl AwsCollector {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        Self {
            client: aws_sdk_ec2::Client::new(&config),
        }
    }
}

#[async_trait]
impl Collector for AwsCollector {
    fn name(&self) -> &str {
        "aws"
    }

    async fn fetch(&self) -> crate::Result<Vec<LiveResource>> {
        // Security groups only for now; ec2 instances are the next kind.
        security_group::fetch(&self.client).await
    }
}
