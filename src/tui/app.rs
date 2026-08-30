//! TUI application state and key handling.
//!
//! Pure logic, no rendering — kept separate from `views.rs` so the behavior
//! (tab cycling, selection movement) is testable without a terminal backend.

use crossterm::event::KeyCode;
use ratatui::widgets::ListState;

use crate::types::drift::{Drift, DriftReport};

/// Which screen is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Drifts,
    Unresolved,
    Unjoinable,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Drifts, Tab::Unresolved, Tab::Unjoinable];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Drifts => "Drifts",
            Tab::Unresolved => "Unresolved",
            Tab::Unjoinable => "Unjoinable",
        }
    }

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|t| *t == self)
            .expect("Tab::ALL covers every variant")
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn previous(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Interactive state for browsing one `DriftReport`.
pub struct App {
    pub state_path: String,
    pub report: DriftReport,
    pub tab: Tab,
    pub drift_list: ListState,
    pub should_quit: bool,
}

impl App {
    pub fn new(state_path: String, report: DriftReport) -> Self {
        let mut drift_list = ListState::default();
        if !report.drifts.is_empty() {
            drift_list.select(Some(0));
        }
        Self {
            state_path,
            report,
            tab: Tab::Drifts,
            drift_list,
            should_quit: false,
        }
    }

    pub fn on_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::BackTab => self.tab = self.tab.previous(),
            KeyCode::Down | KeyCode::Char('j') if self.tab == Tab::Drifts => {
                self.drift_list.select_next();
                self.clamp_drift_selection();
            }
            KeyCode::Up | KeyCode::Char('k') if self.tab == Tab::Drifts => {
                self.drift_list.select_previous();
                self.clamp_drift_selection();
            }
            _ => {}
        }
    }

    /// `ListState::select_next`/`select_previous` only get clamped to the
    /// real item count when rendered against a `List` widget — this app
    /// reads the selection from key events too (to drive the detail pane),
    /// not only from rendering, so it clamps explicitly rather than relying
    /// on render order.
    fn clamp_drift_selection(&mut self) {
        let len = self.report.drifts.len();
        if len == 0 {
            self.drift_list.select(None);
            return;
        }
        if let Some(i) = self.drift_list.selected() {
            self.drift_list.select(Some(i.min(len - 1)));
        }
    }

    pub fn selected_drift(&self) -> Option<&Drift> {
        self.drift_list
            .selected()
            .and_then(|i| self.report.drifts.get(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::drift::Severity;
    use crate::types::resource::ResourceId;

    fn drift(address: &str) -> Drift {
        Drift {
            resource: ResourceId(address.to_string()),
            kind: crate::types::drift::DriftKind::Missing,
            severity: Severity::Critical,
        }
    }

    fn app_with(n: usize) -> App {
        let report = DriftReport {
            drifts: (0..n).map(|i| drift(&format!("r{i}"))).collect(),
            ..Default::default()
        };
        App::new("state.json".to_string(), report)
    }

    #[test]
    fn tab_cycles_forward_and_wraps() {
        let mut app = app_with(1);
        assert_eq!(app.tab, Tab::Drifts);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.tab, Tab::Unresolved);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.tab, Tab::Unjoinable);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.tab, Tab::Drifts, "wraps back to the first tab");
    }

    #[test]
    fn tab_cycles_backward_and_wraps() {
        let mut app = app_with(1);
        app.on_key(KeyCode::BackTab);
        assert_eq!(
            app.tab,
            Tab::Unjoinable,
            "wraps to the last tab going backward"
        );
    }

    #[test]
    fn quit_keys_set_should_quit() {
        let mut app = app_with(1);
        assert!(!app.should_quit);
        app.on_key(KeyCode::Char('q'));
        assert!(app.should_quit);

        let mut app = app_with(1);
        app.on_key(KeyCode::Esc);
        assert!(app.should_quit);
    }

    #[test]
    fn selection_starts_at_the_first_drift() {
        let app = app_with(3);
        assert_eq!(app.drift_list.selected(), Some(0));
        assert_eq!(app.selected_drift().unwrap().resource.0, "r0");
    }

    #[test]
    fn selection_clamps_at_the_last_drift() {
        let mut app = app_with(2);
        app.on_key(KeyCode::Down);
        assert_eq!(app.selected_drift().unwrap().resource.0, "r1");
        app.on_key(KeyCode::Down);
        assert_eq!(
            app.selected_drift().unwrap().resource.0,
            "r1",
            "stays on the last item rather than going out of bounds"
        );
    }

    #[test]
    fn selection_clamps_at_the_first_drift() {
        let mut app = app_with(2);
        app.on_key(KeyCode::Up);
        assert_eq!(
            app.selected_drift().unwrap().resource.0,
            "r0",
            "stays on the first item rather than going negative"
        );
    }

    #[test]
    fn an_empty_drift_list_has_no_selection() {
        let mut app = app_with(0);
        assert_eq!(app.drift_list.selected(), None);
        assert!(app.selected_drift().is_none());
        app.on_key(KeyCode::Down);
        assert_eq!(app.drift_list.selected(), None, "no drifts to select");
    }

    #[test]
    fn arrow_keys_are_ignored_outside_the_drifts_tab() {
        let mut app = app_with(3);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.tab, Tab::Unresolved);
        app.on_key(KeyCode::Down);
        assert_eq!(
            app.drift_list.selected(),
            Some(0),
            "selection is scoped to the Drifts tab"
        );
    }
}
