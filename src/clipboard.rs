//! Copying a code to the system clipboard, and taking it back out again.
//!
//! The clipboard is a downgrade in security whichever way it is used: every
//! process running as this user can read it. What it buys is that the code is
//! not retyped by hand, and what this module adds is that it does not sit there
//! for the rest of the session.
//!
//! One platform difference drives the design. On X11 and Wayland the clipboard
//! contents belong to the *process that set them* and vanish when it exits, so
//! a CLI that copies and immediately returns leaves the user with nothing to
//! paste. The owning handle therefore has to stay alive, either on a background
//! thread inside the REPL or by keeping a one-shot invocation running.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::i18n;

/// Copies `text`, then erases it after `timeout`.
///
/// With `block`, the caller waits for the timeout — which is what a one-shot
/// `neko-auth get -c` must do, both to clear the code afterwards and to keep
/// owning the selection on Linux. Otherwise the wait happens on a background
/// thread and the clipboard handle moves onto it.
pub fn copy_transient(text: &str, timeout: Option<Duration>, block: bool) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().with_context(i18n::err_clipboard_unavailable)?;
    clipboard
        .set_text(text.to_string())
        .with_context(i18n::err_clipboard_write)?;

    let Some(timeout) = timeout else {
        // Clearing is disabled, but the handle must still outlive this call on
        // Linux or the paste buffer empties as soon as we return.
        if block {
            std::mem::forget(clipboard);
        }
        return Ok(());
    };

    let expected = text.to_string();
    if block {
        std::thread::sleep(timeout);
        clear_if_unchanged(&mut clipboard, &expected);
    } else {
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            clear_if_unchanged(&mut clipboard, &expected);
        });
    }
    Ok(())
}

/// Erases the clipboard only if it still holds what we put there.
///
/// Without this check, copying something else during the countdown would have
/// it silently wiped a few seconds later.
fn clear_if_unchanged(clipboard: &mut arboard::Clipboard, expected: &str) {
    match clipboard.get_text() {
        Ok(current) if current == expected => {
            let _ = clipboard.clear();
        }
        _ => {}
    }
}
