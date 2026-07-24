//! Collectors: the key extension seam.
//!
//! A [`Collector`] fetches the *actual* state of resources from a live
//! backend (e.g. AWS) so it can be compared against declared state. New cloud
//! or platform support is added by implementing this trait.

pub mod aws;

use crate::types::resource::Resource;

/// Fetches live resource state from a backend.
pub trait Collector {
    /// Human-readable collector name (e.g. `"aws"`).
    fn name(&self) -> &str;

    /// Fetch the current live state of all resources this collector manages.
    fn fetch(&self) -> crate::Result<Vec<Resource>>;
}
