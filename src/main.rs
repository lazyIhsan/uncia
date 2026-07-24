//! Thin CLI binary for uncia.
//!
//! This entry point stays deliberately small: it parses arguments, resolves
//! configuration, and delegates all real work into the library crate.

use uncia::Result;

fn main() -> Result<()> {
    // TODO: parse CLI flags, resolve config, dispatch into the library.
    Ok(())
}
