//! Configuration: config-file loading merged with CLI flag resolution.

/// Resolved runtime configuration.
///
/// Built by layering CLI flags on top of any config file, on top of defaults.
#[derive(Debug, Default, Clone)]
pub struct Config {
    // TODO: config fields (state source, provider selection, store path, ...).
}

impl Config {
    /// Resolve configuration from defaults, config file, and CLI flags.
    pub fn resolve() -> crate::Result<Self> {
        // TODO: load config file + overlay CLI flags.
        Ok(Self::default())
    }
}
