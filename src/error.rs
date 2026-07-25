//! Crate-wide error type and `Result` alias.

use thiserror::Error;

/// The top-level error type for uncia.
///
/// State-input failures are deliberately specific: per the invariants in
/// `docs/ARCHITECTURE.md`, unreadable or wrong-kind input must fail loudly
/// with a message naming what went wrong, never degrade to an empty or
/// partial parse.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UnciaError {
    #[error("failed to read input: {0}")]
    Io(#[from] std::io::Error),

    #[error("state input is not valid JSON: {0}")]
    StateJson(#[from] serde_json::Error),

    #[error(
        "state input is encrypted and uncia holds no decryption keys; \
         run `tofu show -json` so the state is decrypted before parsing"
    )]
    EncryptedState,

    #[error("unsupported .tfstate schema version `{found}`; expected 4")]
    UnsupportedStateVersion { found: u64 },

    #[error(
        "state input is a plan, not state (found `{marker}`); run \
         `terraform show -json` without a plan file argument"
    )]
    WrongDocumentKind { marker: String },

    #[error("unsupported state format_version `{found}`; expected 1.x")]
    UnsupportedFormatVersion { found: String },

    #[error("collector error: {0}")]
    Collector(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, UnciaError>;
