//! Reading a master password without echoing it, and process-level hardening.
//!
//! Built on `crossterm`, which the watch view already requires, rather than on
//! a dedicated password crate. The code that reads the master password should
//! be code that has actually been read, and this way there is no extra
//! dependency on the most sensitive input path in the program.

use std::io::{IsTerminal, Write};

use anyhow::{bail, Context, Result};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{normalize_email, Credentials};
use crate::i18n;

/// Refuse absurdly long input rather than growing a buffer we cannot erase.
const MAX_PASSWORD_LEN: usize = 1024;
pub const MIN_PASSWORD_LEN: usize = 8;

/// The user pressed Ctrl-C or Escape at a prompt.
#[derive(Debug)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&i18n::cancelled())
    }
}

impl std::error::Error for Cancelled {}

/// Restores cooked mode however the scope is left, including by a panic.
struct RawModeGuard(bool);

impl RawModeGuard {
    fn enter() -> Result<Self> {
        let was_raw = terminal::is_raw_mode_enabled().unwrap_or(false);
        if !was_raw {
            terminal::enable_raw_mode().with_context(i18n::err_raw_mode)?;
        }
        Ok(RawModeGuard(was_raw))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if !self.0 {
            let _ = terminal::disable_raw_mode();
        }
    }
}

/// Reads a password with echo disabled.
///
/// Nothing is printed as the user types, matching `sudo` and `ssh`: even a
/// masking character publishes the password's length to anyone watching the
/// screen.
pub fn prompt_password(prompt: &str) -> Result<SecretString> {
    // A pipe or a here-doc is a legitimate way to drive this in a script, and
    // silently blocking on terminal events would just hang.
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .with_context(i18n::err_read_password_stdin)?;
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        line.zeroize();
        return Ok(SecretString::from(trimmed));
    }

    print!("{prompt}");
    std::io::stdout().flush()?;

    let _guard = RawModeGuard::enter()?;
    let mut buffer = String::with_capacity(MAX_PASSWORD_LEN);

    let result = loop {
        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        // Windows reports key releases as well; acting on both would double
        // every character.
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match (key.code, key.modifiers) {
            (KeyCode::Enter, _) => break Ok(()),
            (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                break Err(anyhow::Error::new(Cancelled))
            }
            (KeyCode::Char('u'), KeyModifiers::CONTROL) => buffer.zeroize(),
            (KeyCode::Backspace, _) => {
                buffer.pop();
            }
            // Input beyond the cap falls through to the catch-all and is
            // simply ignored, rather than growing a buffer we cannot erase.
            (KeyCode::Char(c), m)
                if !m.contains(KeyModifiers::CONTROL) && buffer.len() < MAX_PASSWORD_LEN =>
            {
                buffer.push(c)
            }
            _ => {}
        }
    };

    drop(_guard);
    println!();
    result?;

    Ok(SecretString::from(std::mem::take(&mut buffer)))
}

/// Reads a new password twice and checks the two match.
pub fn prompt_new_password(prompt: &str) -> Result<SecretString> {
    let first = prompt_password(prompt)?;
    if first.expose_secret().chars().count() < MIN_PASSWORD_LEN {
        bail!("{}", i18n::password_too_short(MIN_PASSWORD_LEN));
    }
    let second = prompt_password(&i18n::init_confirm_password())?;
    if first.expose_secret() != second.expose_secret() {
        bail!("{}", i18n::password_mismatch());
    }
    Ok(first)
}

/// Reads the email, echoing it as it is typed unless `hidden` is set.
///
/// Echoing is the default, and the reasoning is worth stating because it looks
/// like the less careful choice. What protects the vault is that the address is
/// **not in the file** — that holds whether or not it appears on screen.
/// Hiding it defends only against someone reading over your shoulder, which is
/// outside the threat model, and it costs something real: with both halves
/// invisible, a mistyped address is undetectable at the moment you make it and
/// indistinguishable from a wrong password ever after. Set `hide_email` if you
/// want the old behaviour.
pub fn prompt_email(hidden: bool) -> Result<Zeroizing<String>> {
    if hidden {
        let entered = prompt_password(&i18n::prompt_email_hidden())?;
        return Ok(Zeroizing::new(entered.expose_secret().to_string()));
    }
    let mut line = prompt_line(&i18n::prompt_email())?;
    let email = Zeroizing::new(std::mem::take(&mut line));
    line.zeroize();
    Ok(email)
}

/// Reads both halves of the unlock secret.
pub fn prompt_credentials(hide_email: bool) -> Result<Credentials> {
    let email = prompt_email(hide_email)?;
    let password = prompt_password(&i18n::prompt_master_password())?;
    Ok(Credentials::new(&email, password))
}

/// Reads new credentials.
///
/// The address is confirmed only when it is hidden; when it is visible on
/// screen, asking for it twice adds a prompt without adding a check the user
/// cannot already make with their eyes.
pub fn prompt_new_credentials(hide_email: bool) -> Result<Credentials> {
    let email = prompt_email(hide_email)?;
    if normalize_email(&email).is_empty() {
        bail!("{}", i18n::email_is_empty());
    }
    if hide_email {
        // Only reachable with `hide_email`, where the value cannot be checked
        // by eye and a single mistype would create an unopenable vault.
        let confirm = prompt_password(&i18n::prompt_email_confirm())?;
        let confirm = Zeroizing::new(confirm.expose_secret().to_string());
        if normalize_email(&email) != normalize_email(&confirm) {
            bail!("{}", i18n::email_mismatch());
        }
    }

    let password = prompt_new_password(&i18n::init_choose_password())?;
    Ok(Credentials::new(&email, password))
}

/// Reads a visible line of input.
pub fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        return Err(anyhow::Error::new(Cancelled));
    }
    Ok(line.trim().to_string())
}

/// A y/N confirmation, defaulting to no.
pub fn confirm(question: &str) -> Result<bool> {
    let answer = prompt_line(&format!("{question} {} ", i18n::yes_no_hint()))?;
    Ok(matches!(answer.to_lowercase().as_str(), "y" | "yes"))
}

/// Requires the user to type an exact word. Used where a mistake is
/// irreversible or exposes secrets, and a reflexive `y` should not be enough.
pub fn confirm_typed(question: &str, expected: &str) -> Result<bool> {
    if !question.is_empty() {
        println!("{question}");
    }
    let answer = prompt_line(&i18n::type_to_continue(expected))?;
    Ok(answer == expected)
}

/// Process-level hardening, applied before anything sensitive is in memory.
pub fn harden_process() {
    #[cfg(unix)]
    {
        // A core dump writes the entire address space, keys included, to a file
        // that typically is not owner-only.
        use rustix::process::{setrlimit, Resource, Rlimit};
        let _ = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        );

        // SQLite creates its -wal and -shm files using the process umask rather
        // than the mode of the database, so this is what keeps them private.
        rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));
    }
}

/// Replaces the panic message with a fixed one.
///
/// The default hook prints the panic payload and, with `RUST_BACKTRACE`, the
/// stack. Either can carry a decrypted value that happened to be in a
/// formatted string. `RUST_BACKTRACE` still works for debugging; the point is
/// that the quiet default does not leak.
pub fn install_panic_hook() {
    let backtrace_requested = std::env::var_os("RUST_BACKTRACE").is_some();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        // A panic on the alternate screen would otherwise leave the user
        // staring at a blank one with their shell hidden behind it.
        use crossterm::ExecutableCommand;
        let _ = std::io::stdout().execute(terminal::LeaveAlternateScreen);
        if backtrace_requested {
            default_hook(info);
        } else {
            eprintln!("{}", i18n::internal_error());
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_its_own_error_type() {
        let err: anyhow::Error = anyhow::Error::new(Cancelled);
        assert!(err.downcast_ref::<Cancelled>().is_some());
        assert_eq!(err.to_string(), "cancelled");
    }

    #[test]
    fn secret_strings_do_not_print_themselves() {
        let s = SecretString::from("hunter2".to_string());
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(s.expose_secret(), "hunter2");
    }
}
