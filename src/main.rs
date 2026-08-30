//! Thin CLI binary for uncia.
//!
//! This entry point stays deliberately small: it parses arguments, resolves
//! configuration, and delegates all real work into the library crate.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use uncia::collector::Collector;
use uncia::collector::aws::AwsCollector;
use uncia::types::drift::{DriftKind, DriftReport};
use uncia::{Config, Result};

#[derive(Parser)]
#[command(name = "uncia", version, about = "Drift detection for IaC")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check declared state against live infrastructure and report drift.
    Check {
        /// Path to `terraform show -json` output (`-` for stdin).
        #[arg(long)]
        state: String,
    },
    /// Check declared state, then browse the report interactively.
    Tui {
        /// Path to `terraform show -json` output (`-` for stdin).
        #[arg(long)]
        state: String,
    },
}

/// Exit codes follow `terraform plan -detailed-exitcode` conventions:
/// 0 = no drift, 1 = error, 2 = drift found. `tui` always exits 0 on a clean
/// quit — it's for a human at a keyboard, not a CI gate, so it doesn't
/// encode drift presence in its exit code the way `check` does.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Check { state } => match check(state).await {
            Ok(report) => {
                print_report(&report);
                if report.drifts.is_empty() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Command::Tui { state } => match check(state.clone()).await {
            // `tui::run` is a blocking, synchronous event loop (crossterm's
            // event::read() blocks the calling thread). Nothing else is
            // running concurrently by this point, so calling it directly
            // from the async main is simplest — no spawn_blocking needed.
            Ok(report) => match uncia::tui::run(state, report) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(1)
                }
            },
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
    }
}

async fn check(state_path: String) -> Result<DriftReport> {
    let config = Config::resolve(state_path)?;

    let state_json = if config.state_path == "-" {
        std::io::read_to_string(std::io::stdin())?
    } else {
        std::fs::read_to_string(&config.state_path)?
    };
    let declared = uncia::state::parse(&state_json)?;

    let collector = AwsCollector::new().await;
    let live = collector.fetch().await?;

    Ok(uncia::diff::compare(&declared, &live))
}

fn print_report(report: &DriftReport) {
    for unjoinable in &report.unjoinable {
        eprintln!(
            "warning: cannot check {}: {}",
            unjoinable.resource.0, unjoinable.reason
        );
    }
    for unresolved in &report.unresolved {
        let subject = match &unresolved.resource {
            Some(id) => id.0.as_str(),
            None => "(all subjects)",
        };
        eprintln!(
            "warning: cannot resolve `{}` for {}: {}",
            unresolved.relation, subject, unresolved.reason
        );
    }
    for drift in &report.drifts {
        match &drift.kind {
            DriftKind::Missing => println!(
                "[{:?}] {}: declared in state but not found live",
                drift.severity, drift.resource.0
            ),
            DriftKind::FieldChanged {
                field,
                declared,
                actual,
            } => println!(
                "[{:?}] {}: `{}` drifted\n    declared: {}\n    actual:   {}",
                drift.severity, drift.resource.0, field, declared, actual
            ),
            // The `via` path is printed because it is what makes the claim
            // checkable against the account without reading uncia's source.
            DriftKind::SemanticChanged {
                field,
                relation,
                declared_effective,
                actual_effective,
                via,
            } => println!(
                "[{:?}] {}: `{}` unchanged but its meaning drifted ({})\n    \
                 via:      {}\n    declared: {}\n    actual:   {}",
                drift.severity,
                drift.resource.0,
                field,
                relation,
                via.join(", "),
                declared_effective,
                actual_effective
            ),
            _ => println!(
                "[{:?}] {}: drift detected",
                drift.severity, drift.resource.0
            ),
        }
    }
    if report.drifts.is_empty() {
        // "No drift" must never absorb "couldn't check": both buckets are
        // counted so silence is only ever reported when it was earned.
        let unchecked = report.unjoinable.len() + report.unresolved.len();
        println!(
            "no drift detected{}",
            if unchecked == 0 {
                String::new()
            } else {
                format!(" ({unchecked} check(s) could not be completed)")
            }
        );
    } else {
        println!("{} drift(s) detected", report.drifts.len());
    }
}
