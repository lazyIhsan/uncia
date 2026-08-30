//! Rendering for each TUI screen.
//!
//! Colors here mirror the palette worked out in the HTML mockup (glacier
//! cyan accent, a violet tag reserved for semantic drift, warm severity
//! colors against a cool ground) — translated to what a fixed-width
//! character grid can actually draw: no rounded badges, no gradients, no
//! hover. A severity "stripe" becomes a colored `\u{2588}` block prefixing a
//! list row; a badge becomes a bracket-free colored tag, since ratatui has no
//! per-item list border to hang a stripe on.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use serde_json::Value;

use super::app::{App, Tab};
use crate::types::drift::{Drift, DriftKind, Severity};

mod palette {
    use ratatui::style::Color;

    pub const TEXT: Color = Color::Rgb(219, 228, 236);
    pub const TEXT_DIM: Color = Color::Rgb(131, 148, 168);
    pub const TEXT_FAINT: Color = Color::Rgb(82, 97, 118);
    pub const ACCENT: Color = Color::Rgb(94, 203, 216);
    pub const SEMANTIC: Color = Color::Rgb(199, 146, 234);
    pub const CRITICAL: Color = Color::Rgb(239, 83, 80);
    pub const HIGH: Color = Color::Rgb(242, 153, 74);
    pub const MEDIUM: Color = Color::Rgb(232, 197, 71);
    pub const LOW: Color = Color::Rgb(110, 168, 216);
    pub const INFO: Color = Color::Rgb(124, 139, 160);
    pub const DIFF_ADD: Color = Color::Rgb(126, 231, 135);
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [title_area, tabs_area, status_area, body_area, footer_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_title(frame, title_area, app);
    draw_tabs(frame, tabs_area, app);
    draw_status(frame, status_area, app);
    match app.tab {
        Tab::Drifts => draw_drifts(frame, body_area, app),
        Tab::Unresolved => draw_unresolved(frame, body_area, app),
        Tab::Unjoinable => draw_unjoinable(frame, body_area, app),
    }
    draw_footer(frame, footer_area, app);
}

fn draw_title(frame: &mut Frame, area: Rect, app: &App) {
    let line = Line::from(vec![
        Span::styled("uncia", Style::default().fg(palette::ACCENT).bold()),
        Span::styled("  ·  ", Style::default().fg(palette::TEXT_FAINT)),
        Span::styled(
            app.state_path.as_str(),
            Style::default().fg(palette::TEXT_DIM),
        ),
    ]);
    frame.render_widget(line, area);
}

fn draw_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let labels = [Tab::Drifts, Tab::Unresolved, Tab::Unjoinable].map(|tab| {
        let count = match tab {
            Tab::Drifts => app.report.drifts.len(),
            Tab::Unresolved => app.report.unresolved.len(),
            Tab::Unjoinable => app.report.unjoinable.len(),
        };
        format!(" {} ({count}) ", tab.label())
    });
    let tabs = ratatui::widgets::Tabs::new(labels)
        .select(tab_index(app.tab))
        .style(Style::default().fg(palette::TEXT_FAINT))
        .highlight_style(
            Style::default()
                .fg(palette::TEXT)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
        )
        .divider("");
    frame.render_widget(tabs, area);
}

fn tab_index(tab: Tab) -> usize {
    match tab {
        Tab::Drifts => 0,
        Tab::Unresolved => 1,
        Tab::Unjoinable => 2,
    }
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    let mut counts = [0usize; 5];
    for drift in &app.report.drifts {
        counts[severity_index(drift.severity)] += 1;
    }
    let sev_order = [
        (Severity::Critical, "Critical"),
        (Severity::High, "High"),
        (Severity::Medium, "Medium"),
        (Severity::Low, "Low"),
        (Severity::Info, "Info"),
    ];
    let mut spans = Vec::new();
    for (sev, label) in sev_order {
        let n = counts[severity_index(sev)];
        if n == 0 {
            continue;
        }
        if !spans.is_empty() {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled("● ", Style::default().fg(severity_color(sev))));
        spans.push(Span::styled(
            format!("{label} {n}"),
            Style::default().fg(palette::TEXT_DIM),
        ));
    }
    if spans.is_empty() {
        spans.push(Span::styled(
            "no drift detected",
            Style::default().fg(palette::TEXT_FAINT),
        ));
    }
    let incomplete = app.report.unresolved.len() + app.report.unjoinable.len();
    if incomplete > 0 {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("{incomplete} check(s) incomplete"),
            Style::default().fg(palette::TEXT_FAINT),
        ));
    }
    frame.render_widget(Line::from(spans), area);
}

fn severity_index(sev: Severity) -> usize {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Critical => palette::CRITICAL,
        Severity::High => palette::HIGH,
        Severity::Medium => palette::MEDIUM,
        Severity::Low => palette::LOW,
        Severity::Info => palette::INFO,
    }
}

/// The badge text and color for a drift's kind — the loudest signal in the
/// list, ahead of severity, since behavioral-vs-semantic is what uncia is
/// actually for.
fn badge_for(kind: &DriftKind) -> (&'static str, Color) {
    match kind {
        DriftKind::Missing => ("MISS", palette::CRITICAL),
        DriftKind::FieldChanged { .. } => ("FIELD", palette::LOW),
        DriftKind::SemanticChanged { .. } => ("SEM", palette::SEMANTIC),
    }
}

fn summary_for(kind: &DriftKind) -> String {
    match kind {
        DriftKind::Missing => "declared, not found live".to_string(),
        DriftKind::FieldChanged { field, .. } => format!("{field} drifted"),
        DriftKind::SemanticChanged {
            field,
            relation,
            via,
            ..
        } => {
            format!("{field} unchanged · {relation} · via {}", via.join(", "))
        }
    }
}

fn draw_drifts(frame: &mut Frame, area: Rect, app: &mut App) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Fill(1)]).areas(area);

    let items: Vec<ListItem> = app
        .report
        .drifts
        .iter()
        .map(|drift| {
            let (badge, badge_color) = badge_for(&drift.kind);
            let stripe = Span::styled("▌ ", Style::default().fg(severity_color(drift.severity)));
            let top = Line::from(vec![
                stripe,
                Span::styled(
                    format!("{badge:<5}"),
                    Style::default().fg(badge_color).bold(),
                ),
                Span::raw(" "),
                Span::styled(
                    drift.resource.0.as_str(),
                    Style::default().fg(palette::TEXT),
                ),
            ]);
            let bottom = Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    summary_for(&drift.kind),
                    Style::default().fg(palette::TEXT_FAINT),
                ),
            ]);
            ListItem::new(vec![top, bottom])
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::new()
                .borders(Borders::RIGHT)
                .border_style(Style::default().fg(palette::TEXT_FAINT)),
        )
        .highlight_style(Style::default().bg(Color::Rgb(23, 29, 38)));
    frame.render_stateful_widget(list, list_area, &mut app.drift_list);

    draw_drift_detail(frame, detail_area, app.selected_drift());
}

fn draw_drift_detail(frame: &mut Frame, area: Rect, drift: Option<&Drift>) {
    let Some(drift) = drift else {
        frame.render_widget(
            Paragraph::new("no drift selected").style(Style::default().fg(palette::TEXT_FAINT)),
            area,
        );
        return;
    };

    let mut lines = vec![
        Line::from(Span::styled(
            drift.resource.0.as_str(),
            Style::default()
                .fg(palette::TEXT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    match &drift.kind {
        DriftKind::Missing => {
            lines.push(field_label("note"));
            lines.push(Line::from(Span::styled(
                "declared in state with a cloud id, but not found live",
                Style::default().fg(palette::TEXT_DIM),
            )));
        }
        DriftKind::FieldChanged {
            field,
            declared,
            actual,
        } => {
            lines.push(Line::from(vec![
                Span::styled("field  ", Style::default().fg(palette::TEXT_FAINT)),
                Span::styled(field.as_str(), Style::default().fg(palette::TEXT)),
            ]));
            lines.push(Line::from(""));
            lines.push(field_label("declared"));
            lines.push(code_line(&format_value(declared), palette::TEXT_DIM));
            lines.push(Line::from(""));
            lines.push(field_label("actual"));
            lines.push(code_line(&format_value(actual), palette::TEXT));
        }
        DriftKind::SemanticChanged {
            field,
            relation,
            declared_effective,
            actual_effective,
            via,
        } => {
            lines.push(Line::from(vec![
                Span::styled("field     ", Style::default().fg(palette::TEXT_FAINT)),
                Span::styled(field.as_str(), Style::default().fg(palette::TEXT)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("relation  ", Style::default().fg(palette::TEXT_FAINT)),
                Span::styled(relation.as_str(), Style::default().fg(palette::TEXT)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("via  ", Style::default().fg(palette::TEXT_FAINT)),
                Span::styled(via.join(", "), Style::default().fg(palette::SEMANTIC)),
            ]));
            lines.push(Line::from(""));
            lines.push(field_label("declared_effective"));
            lines.push(code_line(
                &format_value(declared_effective),
                palette::TEXT_DIM,
            ));
            lines.push(Line::from(""));
            lines.push(field_label("actual_effective"));
            lines.push(effective_diff_line(declared_effective, actual_effective));
        }
    }

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::new()
                .borders(Borders::NONE)
                .padding(ratatui::widgets::Padding::horizontal(2)),
        ),
        area,
    );
}

fn field_label(label: &str) -> Line<'static> {
    Line::from(Span::styled(
        label.to_uppercase(),
        Style::default()
            .fg(palette::TEXT_FAINT)
            .add_modifier(Modifier::BOLD),
    ))
}

fn code_line(text: &str, color: Color) -> Line<'static> {
    Line::from(Span::styled(text.to_string(), Style::default().fg(color)))
}

fn format_value(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| v.to_string())
}

/// Renders `actual_effective` as a bracketed list, coloring entries that
/// aren't in `declared_effective` — the widened members that are the whole
/// point of a semantic finding — the same way the mockup's diff highlight did.
fn effective_diff_line(declared: &Value, actual: &Value) -> Line<'static> {
    let declared_items: Vec<&str> = declared
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let actual_items: Vec<&Value> = actual
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();

    if actual_items.is_empty() {
        return Line::from(Span::styled("[]", Style::default().fg(palette::TEXT_DIM)));
    }

    let mut spans = vec![Span::styled("[", Style::default().fg(palette::TEXT_DIM))];
    for (i, item) in actual_items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(", ", Style::default().fg(palette::TEXT_DIM)));
        }
        let s = item.as_str().unwrap_or_default();
        let is_new = !declared_items.contains(&s);
        let color = if is_new {
            palette::DIFF_ADD
        } else {
            palette::TEXT
        };
        spans.push(Span::styled(format!("\"{s}\""), Style::default().fg(color)));
    }
    spans.push(Span::styled("]", Style::default().fg(palette::TEXT_DIM)));
    Line::from(spans)
}

fn draw_unresolved(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .report
        .unresolved
        .iter()
        .map(|u| {
            let subject = u
                .resource
                .as_ref()
                .map(|r| r.0.as_str())
                .unwrap_or("(all subjects)");
            let top = Line::from(vec![
                Span::styled(subject, Style::default().fg(palette::TEXT).bold()),
                Span::raw("  "),
                Span::styled(u.relation.as_str(), Style::default().fg(palette::INFO)),
            ]);
            let bottom = Line::from(Span::styled(
                u.reason.as_str(),
                Style::default().fg(palette::TEXT_DIM),
            ));
            ListItem::new(vec![top, bottom, Line::from("")])
        })
        .collect();
    flat_list(frame, area, items, "nothing unresolved");
}

fn draw_unjoinable(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .report
        .unjoinable
        .iter()
        .map(|u| {
            let top = Line::from(Span::styled(
                u.resource.0.as_str(),
                Style::default().fg(palette::TEXT).bold(),
            ));
            let bottom = Line::from(Span::styled(
                u.reason.as_str(),
                Style::default().fg(palette::TEXT_DIM),
            ));
            ListItem::new(vec![top, bottom, Line::from("")])
        })
        .collect();
    flat_list(frame, area, items, "nothing unjoinable");
}

fn flat_list(frame: &mut Frame, area: Rect, items: Vec<ListItem>, empty_label: &str) {
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(empty_label).style(Style::default().fg(palette::TEXT_FAINT)),
            area,
        );
        return;
    }
    frame.render_widget(List::new(items), area);
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![key_hint("Tab/Shift+Tab", "switch view")];
    if app.tab == Tab::Drifts {
        spans.push(Span::raw("   "));
        spans.push(key_hint("↑/↓", "select"));
    }
    spans.push(Span::raw("   "));
    spans.push(key_hint("q", "quit"));
    frame.render_widget(Line::from(spans), area);
}

fn key_hint(key: &str, action: &str) -> Span<'static> {
    Span::styled(
        format!("{key} {action}"),
        Style::default().fg(palette::TEXT_FAINT),
    )
}
