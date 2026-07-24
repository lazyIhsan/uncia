//! Crate-wide error type and `Result` alias.

use std::fmt;

/// The top-level error type for uncia.
#[derive(Debug)]
#[non_exhaustive]
pub enum UnciaError {
    // TODO: enumerate concrete failure modes (config, state parsing,
    // provider, store, ...) as the implementation lands.
}

impl fmt::Display for UnciaError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

impl std::error::Error for UnciaError {}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, UnciaError>;
