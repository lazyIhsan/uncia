//! Smoke tests for TUI rendering: build an `App` against a small hand-built
//! `DriftReport` (mirroring `tests/diff_semantic.rs`'s fixture style) and
//! assert the rendered buffer contains the expected text.
//!
//! Not pixel-perfect snapshot testing — just enough to catch a gross
//! rendering regression (a resource address that stops showing up, a tab
//! label that vanishes, a reason string that gets dropped).

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use serde_json::json;

use uncia::tui::app::{App, Tab};
use uncia::tui::views;
use uncia::types::drift::{Drift, DriftKind, DriftReport, Severity, Unjoinable, Unresolved};
use uncia::types::resource::ResourceId;

fn sample_report() -> DriftReport {
    DriftReport {
        drifts: vec![
            Drift {
                resource: ResourceId("aws_security_group.existing".to_string()),
                kind: DriftKind::FieldChanged {
                    field: "tags".to_string(),
                    declared: json!({}),
                    actual: json!({"test-ec2-collector": ""}),
                },
                severity: Severity::Medium,
            },
            Drift {
                resource: ResourceId("aws_security_group.web".to_string()),
                kind: DriftKind::SemanticChanged {
                    field: "ingress".to_string(),
                    relation: "sg_membership".to_string(),
                    declared_effective: json!(["tcp/443-443/member:i-worker"]),
                    actual_effective: json!([
                        "tcp/443-443/member:i-console",
                        "tcp/443-443/member:i-worker"
                    ]),
                    via: vec!["sg-app".to_string()],
                },
                severity: Severity::High,
            },
            Drift {
                resource: ResourceId("aws_instance.legacy_worker".to_string()),
                kind: DriftKind::Missing,
                severity: Severity::Critical,
            },
        ],
        unresolved: vec![Unresolved {
            resource: None,
            relation: "sg_membership".to_string(),
            reason: "declared state contains no `aws_instance`".to_string(),
        }],
        unjoinable: vec![Unjoinable {
            resource: ResourceId("aws_security_group.imported".to_string()),
            reason: "no cloud id recorded in state".to_string(),
        }],
    }
}

fn app() -> App {
    App::new("state.json".to_string(), sample_report())
}

/// Flatten the rendered buffer into one string (one line per row, so
/// assertions can check substrings without text accidentally running
/// together across a row boundary).
fn render(app: &mut App) -> String {
    let width = 110;
    let backend = TestBackend::new(width, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| views::draw(frame, app)).unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(width as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn drifts_tab_shows_resources_badges_and_severity_counts() {
    let mut app = app();
    let screen = render(&mut app);

    assert!(screen.contains("uncia"));
    assert!(screen.contains("state.json"));
    assert!(screen.contains("Drifts"));
    assert!(screen.contains("Unresolved"));
    assert!(screen.contains("Unjoinable"));

    // The badge distinction is the loudest signal in the list.
    assert!(screen.contains("FIELD"), "{screen}");
    assert!(screen.contains("SEM"), "{screen}");
    assert!(screen.contains("MISS"), "{screen}");

    assert!(screen.contains("aws_security_group.existing"), "{screen}");
    assert!(screen.contains("Critical 1"), "{screen}");
    assert!(screen.contains("High 1"), "{screen}");
    assert!(screen.contains("Medium 1"), "{screen}");

    // The first drift is selected by default, so its detail shows.
    assert!(screen.contains("declared"), "{screen}");
}

#[test]
fn selecting_the_semantic_drift_shows_its_via_chain_in_detail() {
    let mut app = app();
    app.drift_list.select(Some(1)); // aws_security_group.web, SemanticChanged
    let screen = render(&mut app);

    assert!(screen.contains("aws_security_group.web"), "{screen}");
    assert!(screen.contains("sg_membership"), "{screen}");
    assert!(screen.contains("sg-app"), "{screen}");
    assert!(screen.contains("i-console"), "{screen}");
}

#[test]
fn unresolved_tab_shows_the_relation_and_reason() {
    let mut app = app();
    app.tab = Tab::Unresolved;
    let screen = render(&mut app);

    assert!(screen.contains("sg_membership"), "{screen}");
    assert!(screen.contains("declared state contains no"), "{screen}");
}

#[test]
fn unjoinable_tab_shows_the_resource_and_reason() {
    let mut app = app();
    app.tab = Tab::Unjoinable;
    let screen = render(&mut app);

    assert!(screen.contains("aws_security_group.imported"), "{screen}");
    assert!(screen.contains("no cloud id recorded"), "{screen}");
}

#[test]
fn an_empty_report_renders_without_panicking() {
    let mut app = App::new("state.json".to_string(), DriftReport::default());
    let screen = render(&mut app);
    assert!(screen.contains("no drift detected"), "{screen}");
}
