//! Terminal output: colour, tables, and the countdown bar.

use std::io::IsTerminal;
use std::sync::OnceLock;

use crossterm::style::Stylize;

/// Colour is disabled when output is redirected, and by `NO_COLOR`.
pub fn colored() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

macro_rules! paint {
    ($name:ident, $style:ident) => {
        pub fn $name(text: &str) -> String {
            if colored() {
                text.$style().to_string()
            } else {
                text.to_string()
            }
        }
    };
}

paint!(dim, dark_grey);
paint!(bold, bold);
paint!(green, green);
paint!(yellow, yellow);
paint!(red, red);
paint!(cyan, cyan);

pub fn heading(text: &str) -> String {
    if colored() {
        text.bold().underlined().to_string()
    } else {
        text.to_string()
    }
}

pub fn warn(message: &str) {
    eprintln!("{} {message}", yellow(&crate::i18n::label_warning()));
}

pub fn error(message: &str) {
    eprintln!("{} {message}", red(&crate::i18n::label_error()));
}

pub fn note(message: &str) {
    println!("{}", dim(message));
}

pub fn success(message: &str) {
    println!("{} {message}", green("✓"));
}

/// A filled/empty bar showing how much of the current time step remains.
pub fn countdown_bar(remaining: u32, period: u32, width: usize) -> String {
    if period == 0 {
        return " ".repeat(width);
    }
    let filled = (remaining as usize * width)
        .div_ceil(period as usize)
        .min(width);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));
    // Amber in the last five seconds: the point at which it is worth waiting
    // for the next code rather than racing this one into a login form.
    if remaining <= 5 {
        yellow(&bar)
    } else {
        green(&bar)
    }
}

/// The number of terminal cells a string occupies.
pub fn width(text: &str) -> usize {
    display_width(text)
}

/// Renders rows under headers, padding each column to its widest cell.
pub fn table<H: AsRef<str>>(headers: &[H], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let columns = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| display_width(h.as_ref())).collect();
    for row in rows {
        for (i, cell) in row.iter().take(columns).enumerate() {
            widths[i] = widths[i].max(display_width(cell));
        }
    }

    let mut out = String::new();
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(h.as_ref(), widths[i]))
        .collect();
    out.push_str(&heading(header_line.join("  ").trim_end()));
    out.push('\n');

    for row in rows {
        let line: Vec<String> = row
            .iter()
            .take(columns)
            .enumerate()
            .map(|(i, c)| pad(c, widths[i]))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

fn pad(text: &str, width: usize) -> String {
    let len = display_width(text);
    format!("{text}{}", " ".repeat(width.saturating_sub(len)))
}

/// Character count, ignoring ANSI escapes. Good enough for the Latin and CJK
/// text that appears in issuer names; full grapheme handling would need a
/// dependency that is not worth it here.
fn display_width(text: &str) -> usize {
    let mut width = 0;
    let mut in_escape = false;
    for c in text.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
            continue;
        }
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        // CJK and emoji occupy two cells in a terminal.
        width += if matches!(c as u32, 0x1100..=0x115F | 0x2E80..=0xA4CF | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF | 0xFE30..=0xFE6F | 0xFF00..=0xFF60 | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1F64F | 0x1F900..=0x1F9FF | 0x20000..=0x3FFFD)
        {
            2
        } else {
            1
        };
    }
    width
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bar_empties_as_the_step_expires() {
        assert_eq!(strip(&countdown_bar(30, 30, 10)), "██████████");
        assert_eq!(strip(&countdown_bar(15, 30, 10)), "█████░░░░░");
        assert_eq!(strip(&countdown_bar(0, 30, 10)), "░░░░░░░░░░");
        // A partial step still shows at least one block, so "about to expire"
        // never looks the same as "expired".
        assert_eq!(strip(&countdown_bar(1, 30, 10)), "█░░░░░░░░░");
    }

    #[test]
    fn columns_line_up_regardless_of_cell_width() {
        let out = table(
            &["Issuer", "Account"],
            &[
                vec!["GitHub".into(), "zoe@example.com".into()],
                vec!["A".into(), "b".into()],
            ],
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].starts_with("GitHub  zoe@example.com"));
        assert!(lines[2].starts_with("A       b"));
    }

    #[test]
    fn wide_characters_are_measured_as_two_cells() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("公司"), 4);
        assert_eq!(display_width("\x1b[32mgreen\x1b[0m"), 5);
    }

    fn strip(s: &str) -> String {
        let mut out = String::new();
        let mut in_escape = false;
        for c in s.chars() {
            if in_escape {
                in_escape = c != 'm';
            } else if c == '\x1b' {
                in_escape = true;
            } else {
                out.push(c);
            }
        }
        out
    }
}
