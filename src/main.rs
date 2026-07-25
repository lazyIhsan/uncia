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
}

/// Exit codes follow `terraform plan -detailed-exitcode` conventions:
/// 0 = no drift, 1 = error, 2 = drift found.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Check { state } = cli.command;

    match check(state).await {
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
    }
}

async fn check(state_path: String) -> Result<DriftReport> {
    let config = Config::resolve(state_path)?;

    let state_json = if config.state_path == "-" {
        std::io::read_to_string(std::io::stdin())?
    } else {
        std::fs::read_to_string(&config.state_path)?
    };
    let declared = uncia::state::terraform::parse(&state_json)?;

    let collector = AwsCollector::new().await;
    let live = collector.fetch().await?;

    Ok(uncia::diff::behavioral::compare(&declared, &live))
}

fn print_report(report: &DriftReport) {
    for unjoinable in &report.unjoinable {
        eprintln!(
            "warning: cannot check {}: {}",
            unjoinable.resource.0, unjoinable.reason
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
            _ => println!(
                "[{:?}] {}: drift detected",
                drift.severity, drift.resource.0
            ),
        }
    }
    if report.drifts.is_empty() {
        println!(
            "no drift detected{}",
            if report.unjoinable.is_empty() {
                String::new()
            } else {
                format!(
                    " ({} resource(s) could not be checked)",
                    report.unjoinable.len()
                )
            }
        );
    } else {
        println!("{} drift(s) detected", report.drifts.len());
    }
}
