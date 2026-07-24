//! Configuration: CLI flag resolution (config-file layering comes later).

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to `terraform show -json` output; `-` means stdin.
    pub state_path: String,
}

impl Config {
    /// Resolve configuration from CLI arguments.
    ///
    /// A config file layer (defaults < file < flags) is planned; for now the
    /// flags are the whole story.
    pub fn resolve(state_path: String) -> crate::Result<Self> {
        Ok(Self { state_path })
    }
}
