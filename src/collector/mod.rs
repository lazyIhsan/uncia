//! Collectors: the key extension seam.
//!
//! A [`Collector`] fetches the *actual* state of resources from a live
//! backend (e.g. AWS) so it can be compared against declared state. New cloud
//! or platform support is added by implementing this trait.
//!
//! Collectors return [`LiveResource`]s keyed by **cloud ID**, never by
//! Terraform address — a collector talking to a cloud API cannot know
//! Terraform addresses, and pretending otherwise would conflate the two
//! identifiers the architecture keeps apart. Only the diff joins declared
//! resources to live observations, via `Resource::cloud_id()`.
//!
//! Collectors are strictly read-only: they fetch live state and never mutate
//! cloud resources or Terraform state.

pub mod aws;

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::types::resource::ResourceKind;

/// A live observation of one resource, as reported by a backend's API.
#[derive(Debug, Clone)]
pub struct LiveResource {
    /// The cloud-assigned identifier (e.g. `sg-0def456`).
    pub cloud_id: String,
    pub kind: ResourceKind,
    /// Attributes normalized to the same names/shapes Terraform state uses
    /// for this kind, so the diff compares like against like.
    pub attributes: Map<String, Value>,
}

/// Fetches live resource state from a backend.
#[async_trait]
pub trait Collector {
    /// Human-readable collector name (e.g. `"aws"`).
    fn name(&self) -> &str;

    /// Fetch the current live state of all resources this collector covers.
    async fn fetch(&self) -> crate::Result<Vec<LiveResource>>;
}
