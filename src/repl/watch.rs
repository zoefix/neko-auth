//! The full-screen live view.
//!
//! Codes are recomputed only when their time step rolls over, so a vault with
//! a hundred accounts still costs one AEAD open per account per period rather
//! than four per second.

use std::collections::HashMap;
use std::io::Stdout;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{execute, ExecutableCommand};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};

use crate::app::App;
use crate::i18n;
use crate::otp::{self, OtpKind};
use crate::vault::Account;

const TICK: Duration = Duration::from_millis(250);

/// Restores the terminal on every exit path, panics included.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Terminal<CrosstermBackend<Stdout>>> {
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        Ok(Terminal::new(CrosstermBackend::new(stdout))?)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Without this, a panic inside the alternate screen leaves the user's
        // terminal in raw mode with no echo — effectively broken until reset.
        let _ = disable_raw_mode();
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
    }
}

struct Cached {
    code: String,
    /// Unix time at which this code stops being valid.
    expires_at: u64,
}

pub fn run(app: &mut App, pattern: Option<&str>) -> Result<()> {
    let mut filter = pattern.unwrap_or("").to_string();
    let mut editing_filter = false;
    let mut state = TableState::default();
    let mut codes: HashMap<[u8; 16], Cached> = HashMap::new();
    let mut status = String::new();

    let _guard = TerminalGuard;
    let mut terminal = TerminalGuard::enter()?;

    loop {
        // The idle watchdog can erase the keys while this view is open.
        if !app.vault.is_unlocked() {
            break;
        }

        let accounts: Vec<Account> = app
            .vault
            .list()?
            .into_iter()
            .filter(|a| a.matches(&filter))
            .collect();

        if state.selected().is_none() && !accounts.is_empty() {
            state.select(Some(0));
        }
        if let Some(i) = state.selected() {
            if i >= accounts.len() {
                state.select(accounts.is_empty().then_some(0).map(|_| 0));
            }
        }

        let now = otp::now();
        let rows = build_rows(app, &accounts, &mut codes, now)?;

        terminal.draw(|frame| draw(frame, &rows, &mut state, &filter, editing_filter, &status))?;

        if !event::poll(TICK)? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if editing_filter {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => editing_filter = false,
                KeyCode::Backspace => {
                    filter.pop();
                }
                KeyCode::Char(c) => filter.push(c),
                _ => {}
            }
            continue;
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => break,
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
            (KeyCode::Char('/'), _) => {
                editing_filter = true;
                status.clear();
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                move_selection(&mut state, accounts.len(), 1)
            }
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                move_selection(&mut state, accounts.len(), -1)
            }
            (KeyCode::Char('c'), _) => {
                status = copy_selected(app, &accounts, &state, &codes);
            }
            _ => {}
        }
    }

    // The guard restores the terminal as it drops.
    drop(terminal);
    Ok(())
}

struct DisplayRow {
    issuer: String,
    label: String,
    code: String,
    remaining: Option<(u32, u32)>,
}

fn build_rows(
    app: &App,
    accounts: &[Account],
    codes: &mut HashMap<[u8; 16], Cached>,
    now: u64,
) -> Result<Vec<DisplayRow>> {
    let mut rows = Vec::with_capacity(accounts.len());

    for account in accounts {
        let stale = codes
            .get(&account.uuid)
            .is_none_or(|cached| now >= cached.expires_at);

        if stale {
            let secret = app.vault.secret_of(account)?;
            let code = otp::generate(&secret, &account.params, now)?;
            // The seed is dropped here rather than cached: the session keeps
            // names in memory for search, never secrets.
            drop(secret);

            let expires_at = match account.params.kind {
                OtpKind::Totp { period } => now + u64::from(otp::seconds_remaining(now, period)),
                // A counter-based code does not expire on its own.
                OtpKind::Hotp { .. } => u64::MAX,
            };
            codes.insert(
                account.uuid,
                Cached {
                    code: code.as_str().to_string(),
                    expires_at,
                },
            );
        }

        let remaining = match account.params.kind {
            OtpKind::Totp { period } => Some((otp::seconds_remaining(now, period), period)),
            OtpKind::Hotp { .. } => None,
        };

        rows.push(DisplayRow {
            issuer: account.issuer.clone().unwrap_or_else(|| "-".into()),
            label: account.label.clone(),
            code: codes[&account.uuid].code.clone(),
            remaining,
        });
    }

    codes.retain(|uuid, _| accounts.iter().any(|a| a.uuid == *uuid));
    Ok(rows)
}

fn draw(
    frame: &mut Frame,
    rows: &[DisplayRow],
    state: &mut TableState,
    filter: &str,
    editing_filter: bool,
    status: &str,
) {
    let layout = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .split(frame.area());

    let header_text = if editing_filter {
        format!("{}▏", i18n::watch_filter(filter))
    } else if filter.is_empty() {
        i18n::watch_title()
    } else {
        format!("neko-auth · {}", i18n::watch_filter(filter))
    };
    frame.render_widget(
        Paragraph::new(header_text)
            .style(Style::new().bold())
            .block(Block::default().borders(Borders::ALL)),
        layout[0],
    );

    let table_rows: Vec<Row> = rows
        .iter()
        .map(|row| {
            let (bar, seconds) = match row.remaining {
                Some((remaining, period)) => {
                    (bar_text(remaining, period, 12), format!("{remaining:>2}s"))
                }
                None => (i18n::watch_counter_label(), String::new()),
            };
            let urgency = match row.remaining {
                Some((remaining, _)) if remaining <= 5 => Color::Yellow,
                Some(_) => Color::Green,
                None => Color::Cyan,
            };
            Row::new(vec![
                Cell::from(row.issuer.clone()),
                Cell::from(row.label.clone()),
                Cell::from(row.code.clone()).style(Style::new().fg(Color::Cyan).bold()),
                Cell::from(bar).style(Style::new().fg(urgency)),
                Cell::from(seconds).style(Style::new().dim()),
            ])
        })
        .collect();

    let table = Table::new(
        table_rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Length(12),
            Constraint::Length(13),
            Constraint::Length(4),
        ],
    )
    .header(
        Row::new([
            i18n::column_issuer(),
            i18n::column_account(),
            i18n::column_code(),
            String::new(),
            String::new(),
        ])
        .style(Style::new().bold().dim()),
    )
    .row_highlight_style(Style::new().reversed())
    .highlight_symbol("› ")
    .block(Block::default().borders(Borders::ALL));

    frame.render_stateful_widget(table, layout[1], state);

    let footer = if status.is_empty() {
        i18n::watch_keys()
    } else {
        status.to_string()
    };
    frame.render_widget(Paragraph::new(footer).style(Style::new().dim()), layout[2]);
}

fn bar_text(remaining: u32, period: u32, width: usize) -> String {
    if period == 0 {
        return " ".repeat(width);
    }
    let filled = (remaining as usize * width)
        .div_ceil(period as usize)
        .min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn move_selection(state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        return;
    }
    let current = state.selected().unwrap_or(0) as isize;
    let next = (current + delta).rem_euclid(len as isize);
    state.select(Some(next as usize));
}

#[cfg(feature = "clipboard")]
fn copy_selected(
    app: &App,
    accounts: &[Account],
    state: &TableState,
    codes: &HashMap<[u8; 16], Cached>,
) -> String {
    let Some(account) = state.selected().and_then(|i| accounts.get(i)) else {
        return String::new();
    };
    let Some(cached) = codes.get(&account.uuid) else {
        return String::new();
    };
    let plain = cached.code.clone();
    match crate::clipboard::copy_transient(&plain, app.config.clipboard_timeout(), false) {
        Ok(()) => match app.config.clipboard_timeout() {
            Some(t) => i18n::copied_named(&account.display(), t.as_secs()),
            None => i18n::copied(),
        },
        Err(e) => i18n::copy_failed(&e.to_string()),
    }
}

#[cfg(not(feature = "clipboard"))]
fn copy_selected(
    _app: &App,
    _accounts: &[Account],
    _state: &TableState,
    _codes: &HashMap<[u8; 16], Cached>,
) -> String {
    i18n::no_clipboard_support()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_wraps_at_both_ends() {
        let mut state = TableState::default();
        state.select(Some(0));
        move_selection(&mut state, 3, -1);
        assert_eq!(state.selected(), Some(2));
        move_selection(&mut state, 3, 1);
        assert_eq!(state.selected(), Some(0));
    }

    #[test]
    fn selection_is_a_no_op_on_an_empty_list() {
        let mut state = TableState::default();
        move_selection(&mut state, 0, 1);
        assert_eq!(state.selected(), None);
    }

    #[test]
    fn the_view_renders_codes_countdowns_and_the_key_hints() {
        use ratatui::backend::TestBackend;

        let rows = vec![
            DisplayRow {
                issuer: "GitHub".into(),
                label: "zoe@example.com".into(),
                code: "123 456".into(),
                remaining: Some((22, 30)),
            },
            DisplayRow {
                issuer: "Bank".into(),
                label: "acct".into(),
                code: "999 000".into(),
                remaining: None,
            },
        ];

        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        let mut state = TableState::default();
        state.select(Some(0));
        terminal
            .draw(|frame| draw(frame, &rows, &mut state, "", false, ""))
            .unwrap();

        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();

        assert!(rendered.contains("123 456"), "the code is missing");
        assert!(rendered.contains("zoe@example.com"));
        assert!(rendered.contains(&i18n::Language::English.column_issuer()));
        assert!(rendered.contains("22s"));
        assert!(rendered.contains('█'), "the countdown bar is missing");
        // A counter-based account has no countdown, and must say so rather
        // than showing a full or empty bar.
        assert!(rendered.contains(&i18n::Language::English.watch_counter_label()));
        assert!(rendered.contains("q quit"), "the key hints are missing");
    }

    #[test]
    fn the_filter_prompt_replaces_the_title_while_typing() {
        use ratatui::backend::TestBackend;

        let mut terminal = Terminal::new(TestBackend::new(60, 8)).unwrap();
        let mut state = TableState::default();
        terminal
            .draw(|frame| draw(frame, &[], &mut state, "git", true, ""))
            .unwrap();

        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(rendered.contains("filter: git"));
    }

    #[test]
    fn the_bar_tracks_the_remaining_fraction() {
        assert_eq!(bar_text(30, 30, 10), "██████████");
        assert_eq!(bar_text(15, 30, 10), "█████░░░░░");
        assert_eq!(bar_text(0, 30, 10), "░░░░░░░░░░");
    }
}
