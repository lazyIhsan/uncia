//! # uncia
//!
//! Drift detection for IaC that goes beyond value diffs — catches
//! infrastructure that looks unchanged but no longer means what it used to.
//!
//! This is the public API surface for the crate. It contains **re-exports only**;
//! all behaviour lives in the submodules below.

pub mod collector;
pub mod config;
pub mod diff;
pub mod error;
pub mod state;
pub mod store;
pub mod tui;
pub mod types;

pub use collector::{Collector, LiveResource};
pub use config::Config;
pub use error::{Result, UnciaError};
pub use types::drift::{Drift, DriftKind, DriftReport, Severity};
pub use types::resource::{Resource, ResourceId, ResourceKind};
