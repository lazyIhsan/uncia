//! SQLite-backed drift history persistence.

use crate::types::drift::DriftReport;

/// A handle to the on-disk drift history store.
#[derive(Debug)]
pub struct SqliteStore {
    // TODO: connection / pool handle.
}

impl SqliteStore {
    /// Open (creating if needed) the store at the given path.
    pub fn open(_path: &str) -> crate::Result<Self> {
        // TODO: open connection and run migrations.
        Ok(Self {})
    }

    /// Persist a drift report from a single run.
    pub fn record(&self, _report: &DriftReport) -> crate::Result<()> {
        // TODO: insert report rows.
        Ok(())
    }
}
