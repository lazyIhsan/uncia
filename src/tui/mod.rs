//! Terminal UI for exploring drift interactively.
//!
//! Phase A: browse one fresh [`DriftReport`] — `Drifts` (list + detail),
//! `Unresolved`, `Unjoinable`. No history yet; that needs `src/store` to
//! actually persist runs, which is a separate piece of work (see
//! `docs/ARCHITECTURE.md`'s open question on store granularity).

pub mod app;
pub mod views;

use crossterm::event::{self, Event, KeyEventKind};

use crate::types::drift::DriftReport;
use app::App;

/// Launch the interactive TUI over one drift report. Blocks until the user
/// quits, then restores the terminal — including on error, so a failure
/// mid-render never leaves the caller's terminal in raw mode.
pub fn run(state_path: String, report: DriftReport) -> crate::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new(state_path, report);

    let result = event_loop(&mut terminal, &mut app);

    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> crate::Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| views::draw(frame, app))?;
        if let Event::Key(key) = event::read()? {
            // crossterm can report both press and release on platforms that
            // distinguish them (e.g. Windows) — only press should act, or
            // every keystroke would fire its handler twice.
            if key.kind == KeyEventKind::Press {
                app.on_key(key.code);
            }
        }
    }
    Ok(())
}
