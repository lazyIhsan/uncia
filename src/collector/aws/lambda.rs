//! AWS Lambda function collection.
//!
//! Fetches functions via `ListFunctions` and normalizes each into the
//! attribute names Terraform state uses for `aws_lambda_function`.
//!
//! **Deliberately minimal**, same discipline as `load_balancer.rs`: a
//! VPC-attached Lambda function's ENI carries whatever security groups its
//! `vpc_config` names, exactly like an instance carries
//! `vpc_security_group_ids` — so only `id` (the function name) and
//! `vpc_security_group_ids` are normalized. Full behavioral tracking of a
//! function's other attributes (runtime, handler, memory, ...) is
//! unhandled; `diff::behavioral` skips any kind with no `FIELDS` entry, so
//! this is silent by design.
//!
//! Most functions aren't VPC-attached at all, so `vpc_config` is commonly
//! absent — that normalizes to an empty membership list, not a skipped
//! function; a function gaining VPC config (and a trusted security group
//! along with it) outside Terraform is itself real drift to catch.

use aws_sdk_lambda::error::DisplayErrorContext;
use aws_sdk_lambda::types::FunctionConfiguration;
use serde_json::{Map, json};

use crate::collector::LiveResource;
use crate::error::UnciaError;
use crate::types::resource::ResourceKind;

/// Fetch and normalize all Lambda functions visible to the client.
pub async fn fetch(client: &aws_sdk_lambda::Client) -> crate::Result<Vec<LiveResource>> {
    let mut out = Vec::new();
    let mut pages = client.list_functions().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(|e| {
            UnciaError::Collector(format!("ListFunctions: {}", DisplayErrorContext(&e)))
        })?;
        for function in page.functions() {
            if let Some(live) = normalize(function) {
                out.push(live);
            }
        }
    }
    Ok(out)
}

/// Normalize one API-shaped function into Terraform-state-shaped attributes.
/// Returns `None` for a function with no name (never observed in practice,
/// but the API models it as optional).
fn normalize(function: &FunctionConfiguration) -> Option<LiveResource> {
    let name = function.function_name()?.to_string();

    let security_group_ids: Vec<&str> = function
        .vpc_config()
        .map(|vpc_config| {
            vpc_config
                .security_group_ids()
                .iter()
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_default();

    let mut attributes = Map::new();
    attributes.insert("id".into(), json!(name));
    attributes.insert("vpc_security_group_ids".into(), json!(security_group_ids));

    Some(LiveResource {
        cloud_id: name,
        kind: ResourceKind::AwsLambdaFunction,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_lambda::types::VpcConfigResponse;

    fn vpc_attached() -> FunctionConfiguration {
        FunctionConfiguration::builder()
            .function_name("my-function")
            .vpc_config(
                VpcConfigResponse::builder()
                    .security_group_ids("sg-1111")
                    .security_group_ids("sg-2222")
                    .build(),
            )
            .build()
    }

    #[test]
    fn normalizes_to_terraform_shape() {
        let live = normalize(&vpc_attached()).unwrap();

        assert_eq!(live.cloud_id, "my-function");
        assert_eq!(live.kind, ResourceKind::AwsLambdaFunction);
        assert_eq!(live.attributes["id"], "my-function");
        assert_eq!(
            live.attributes["vpc_security_group_ids"],
            json!(["sg-1111", "sg-2222"])
        );
    }

    #[test]
    fn a_function_with_no_vpc_config_normalizes_to_an_empty_list() {
        // The common case: most functions aren't VPC-attached at all.
        let function = FunctionConfiguration::builder()
            .function_name("no-vpc-function")
            .build();

        let live = normalize(&function).unwrap();
        assert_eq!(live.attributes["vpc_security_group_ids"], json!([]));
    }

    #[test]
    fn a_function_with_no_name_is_not_collected() {
        let bare = FunctionConfiguration::builder().build();
        assert!(normalize(&bare).is_none());
    }
}
