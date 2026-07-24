//! Parse the JSON emitted by `terraform show -json` into uncia resources.

use crate::types::resource::Resource;

/// Parse `terraform show -json` output into the crate's resource model.
pub fn parse(_json: &str) -> crate::Result<Vec<Resource>> {
    // TODO: deserialize the terraform state JSON and map into `Resource`s.
    Ok(Vec::new())
}
