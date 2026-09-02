//! The interactive session.
//!
//! History is held in memory and never written to disk. A TOTP manager's
//! command history is itself sensitive — `show coinbase` says which services
//! the user has accounts with — and it has no business outliving the session.

pub mod watch;

use std::path::PathBuf;

use anyhow::Result;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::history::MemHistory;
use rustyline::{CompletionType, Config, Context, Editor};
use rustyline::{Helper, Highlighter, Hinter, Validator};

use crate::app::App;
use crate::i18n::{self, Language};
use crate::secrets::Cancelled;
use crate::ui;

/// Command names, in the order `help` lists them.
const COMMAND_NAMES: &[&str] = &[
    "ls", "get", "watch", "add", "import", "rm", "rename", "show", "reveal", "export", "restore",
    "passwd", "doctor", "config", "lang", "lock", "update", "help", "exit",
];

/// Name and description, resolved in the active language.
fn commands() -> Vec<(&'static str, String)> {
    COMMAND_NAMES
        .iter()
        .map(|name| {
            let description = match *name {
                "ls" => i18n::cmd_ls(),
                "get" => i18n::cmd_get(),
                "watch" => i18n::cmd_watch(),
                "add" => i18n::cmd_add(),
                "import" => i18n::cmd_import(),
                "rm" => i18n::cmd_rm(),
                "rename" => i18n::cmd_rename(),
                "show" => i18n::cmd_show(),
                "reveal" => i18n::cmd_reveal(),
                "export" => i18n::cmd_export(),
                "restore" => i18n::cmd_restore(),
                "passwd" => i18n::cmd_passwd(),
                "doctor" => i18n::cmd_doctor(),
                "config" => i18n::cmd_config(),
                "lang" => i18n::cmd_lang(),
                "lock" => i18n::cmd_lock(),
                "update" => i18n::cmd_update(),
                "help" => i18n::cmd_help(),
                _ => i18n::cmd_exit(),
            };
            (*name, description)
        })
        .collect()
}

/// Commands whose first argument is an account name.
const TAKES_ACCOUNT: &[&str] = &["get", "rm", "remove", "rename", "show", "reveal", "watch"];

/// Languages offered by `lang`, for completion.
const LANGUAGE_CODES: &[&str] = &["auto", "en", "zh-Hans", "zh-Hant", "ja"];

pub fn run(mut app: App) -> Result<()> {
    banner(&app);

    let config = Config::builder()
        .completion_type(CompletionType::List)
        // Nothing is recorded automatically; entries are added by hand below,
        // and only for commands that cannot carry a secret.
        .auto_add_history(false)
        .build();

    let mut editor: Editor<NekoHelper, MemHistory> =
        Editor::with_history(config, MemHistory::new())?;
    editor.set_helper(Some(NekoHelper {
        accounts: Vec::new(),
    }));

    loop {
        // Refresh completions, and notice if the idle watchdog has locked us.
        if let Some(helper) = editor.helper_mut() {
            helper.accounts = if app.vault.is_unlocked() {
                app.vault
                    .list()
                    .map(|list| list.into_iter().map(|a| a.display()).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
        }

        let prompt = if app.vault.is_unlocked() {
            format!("{} ", ui::cyan("neko-auth ›"))
        } else {
            format!(
                "{} ",
                ui::yellow(&format!("neko-auth {} ›", i18n::prompt_locked_suffix()))
            )
        };

        match editor.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let words = tokenize(line);
                if words.is_empty() {
                    continue;
                }

                // Only commands that cannot carry a secret are remembered, and
                // only in memory. `import uri otpauth://...` is excluded.
                if is_safe_to_remember(&words) {
                    let _ = editor.add_history_entry(line);
                }

                match dispatch(&mut app, &words) {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Exit) => break,
                    Err(e) if e.downcast_ref::<Cancelled>().is_some() => ui::note("cancelled"),
                    Err(e) => ui::error(&format!("{e:#}")),
                }
            }
            // Ctrl-C abandons the current line, as in a shell.
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                ui::error(&e.to_string());
                break;
            }
        }
    }

    app.vault.close();
    println!("{}", ui::dim(&i18n::locked_goodbye()));
    Ok(())
}

enum Flow {
    Continue,
    Exit,
}

fn dispatch(app: &mut App, words: &[String]) -> Result<Flow> {
    // A leading slash is accepted because that is the habit other agent CLIs
    // build, and rejecting `/help` teaches nothing.
    let command = words[0].strip_prefix('/').unwrap_or(&words[0]);
    let args: Vec<&str> = words[1..].iter().map(String::as_str).collect();

    match command {
        "help" | "?" => print_help(),
        "exit" | "quit" => return Ok(Flow::Exit),
        "lock" => {
            app.vault.lock();
            ui::success(&i18n::keys_erased());
        }
        "lang" | "language" => match args.first().copied() {
            None => show_languages(),
            Some(value) => app.set_config("language", value)?,
        },
        "ls" | "list" => app.list(args.first().copied())?,
        "get" => {
            let name = require(&args, "get <account>")?;
            let copy = args.contains(&"-c") || args.contains(&"--copy");
            app.get(name, copy, false)?;
        }
        "watch" => {
            app.ensure_unlocked()?;
            watch::run(app, args.first().copied())?;
        }
        "add" => app.add()?,
        "import" => match args.first().copied() {
            Some("uri") => app.import_uri(args.get(1).copied())?,
            Some("qr") => {
                let paths: Vec<PathBuf> = args[1..].iter().map(PathBuf::from).collect();
                app.import_qr(&paths)?;
            }
            Some("file") => {
                let path = require(&args[1..], "import file <path>")?;
                app.import_file(Path::new(path))?;
            }
            _ => anyhow::bail!(
                "usage: import uri [<uri>] | import qr <image>... | import file <path>"
            ),
        },
        "rm" | "remove" | "delete" => app.remove(require(&args, "rm <account>")?)?,
        "rename" => app.rename(require(&args, "rename <account>")?)?,
        "show" => app.show(require(&args, "show <account>")?)?,
        "reveal" => app.reveal(require(&args, "reveal <account>")?)?,
        "export" => match args.first().copied() {
            Some("encrypted") => {
                let path = require(&args[1..], "export encrypted <path>")?;
                let same = args.contains(&"--same-password");
                app.export_encrypted(Path::new(path), same)?;
            }
            Some("plain") | Some("plaintext") => {
                let path = require(&args[1..], "export plain <path>")?;
                app.export_plain(Path::new(path))?;
            }
            _ => anyhow::bail!("{}", i18n::export_usage()),
        },
        "restore" => app.restore(Path::new(require(&args, "restore <path>")?))?,
        "passwd" | "password" => app.change_password()?,
        "doctor" => app.doctor()?,
        "config" => match (args.first().copied(), args.get(1).copied()) {
            (None, _) => app.show_config()?,
            (Some(key), None) => {
                let value = app
                    .config
                    .entries()
                    .into_iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| v);
                match value {
                    Some(v) => println!("{}", i18n::setting_saved(key, &v)),
                    None => anyhow::bail!("{}", i18n::unknown_setting(key)),
                }
            }
            (Some(key), Some(value)) => app.set_config(key, value)?,
        },
        #[cfg(feature = "update")]
        "update" => crate::update::run(&app.config, args.contains(&"--check"))?,
        other => {
            anyhow::bail!("{}", i18n::unknown_command(other))
        }
    }
    Ok(Flow::Continue)
}

use std::path::Path;

fn require<'a>(args: &[&'a str], form: &str) -> Result<&'a str> {
    args.first()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::usage(form)))
}

/// Lists the available languages, each written in its own script.
fn show_languages() {
    let active = i18n::current();
    println!("{}", ui::heading(&i18n::cmd_lang()));
    for language in Language::ALL {
        let marker = if language == active { "›" } else { " " };
        println!(
            "  {marker} {:<8} {}",
            language.code(),
            if language == active {
                ui::bold(language.endonym())
            } else {
                language.endonym().to_string()
            }
        );
    }
    // What `auto` would pick right now, not the configured value: the point of
    // the line is to say what following the system locale would give you.
    let detected = Language::from_environment().unwrap_or_default();
    println!(
        "    {:<8} {}",
        "auto",
        ui::dim(&format!("→ {}", detected.endonym()))
    );
    println!();
    println!("{}", ui::dim(&i18n::usage("lang <code>")));
}

/// A command line is remembered only if no argument could be a secret.
fn is_safe_to_remember(words: &[String]) -> bool {
    !matches!(words[0].as_str(), "import") || words.len() <= 2
}

fn banner(app: &App) {
    println!(
        "{} {}",
        ui::bold("neko-auth"),
        ui::dim(env!("CARGO_PKG_VERSION"))
    );
    println!(
        "{}",
        ui::dim(&i18n::banner_vault(&app.vault.path().display().to_string()))
    );
    if let Some(timeout) = app.config.idle_timeout() {
        println!("{}", ui::dim(&i18n::banner_autolock(timeout.as_secs())));
    }
    println!("{}", ui::dim(&i18n::banner_hint()));
    println!();
}

fn print_help() {
    println!("{}", ui::heading(&i18n::help_heading()));
    for (name, description) in commands() {
        // Padded by hand rather than with `{:<9}`: the format width counts
        // bytes, and three of the four languages render these as CJK.
        let padding = " ".repeat(9usize.saturating_sub(name.len()));
        println!("  {}{padding} {}", ui::bold(name), ui::dim(&description));
    }
    println!();
    println!("  {}", ui::dim(&i18n::help_copy_hint()));
    println!("  {}", ui::dim(&i18n::help_qr_hint()));
}

/// Splits a line into words, honouring double quotes so account names with
/// spaces work.
fn tokenize(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_word = false;

    for c in line.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                has_word = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_word {
                    words.push(std::mem::take(&mut current));
                    has_word = false;
                }
            }
            c => {
                current.push(c);
                has_word = true;
            }
        }
    }
    if has_word {
        words.push(current);
    }
    words
}

#[derive(Helper, Highlighter, Hinter, Validator)]
struct NekoHelper {
    accounts: Vec<String>,
}

impl Completer for NekoHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let start = line[..pos]
            .rfind(char::is_whitespace)
            .map(|i| i + 1)
            .unwrap_or(0);
        let word = &line[start..pos];
        let first = line[..start].split_whitespace().next().unwrap_or("");

        let candidates: Vec<&str> = if start == 0 {
            COMMAND_NAMES.to_vec()
        } else if first == "import" && line[..start].split_whitespace().count() == 1 {
            vec!["uri", "qr", "file"]
        } else if first == "export" && line[..start].split_whitespace().count() == 1 {
            vec!["encrypted", "plain"]
        } else if matches!(first, "lang" | "language") {
            LANGUAGE_CODES.to_vec()
        } else if TAKES_ACCOUNT.contains(&first) {
            self.accounts.iter().map(String::as_str).collect()
        } else {
            Vec::new()
        };

        let lowered = word.to_lowercase();
        let pairs = candidates
            .into_iter()
            .filter(|c| c.to_lowercase().starts_with(&lowered))
            .map(|c| Pair {
                display: c.to_string(),
                // Quote anything containing a space, so the completion can be
                // re-parsed by tokenize().
                replacement: if c.contains(' ') {
                    format!("\"{c}\"")
                } else {
                    c.to_string()
                },
            })
            .collect();
        Ok((start, pairs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_arguments_stay_together() {
        assert_eq!(tokenize("get github"), ["get", "github"]);
        assert_eq!(tokenize(r#"get "ACME Co (bob)""#), ["get", "ACME Co (bob)"]);
        assert_eq!(tokenize("   ls   "), ["ls"]);
        assert_eq!(tokenize(""), Vec::<String>::new());
        assert_eq!(tokenize(r#"rename "" x"#), ["rename", "", "x"]);
    }

    #[test]
    fn a_uri_argument_is_never_remembered() {
        // `import uri otpauth://...?secret=...` must not reach the history,
        // even the in-memory one.
        assert!(!is_safe_to_remember(&[
            "import".into(),
            "uri".into(),
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()
        ]));
        assert!(is_safe_to_remember(&["import".into(), "uri".into()]));
        assert!(is_safe_to_remember(&["ls".into()]));
        assert!(is_safe_to_remember(&["get".into(), "github".into()]));
    }

    #[test]
    fn completion_offers_commands_then_account_names() {
        let helper = NekoHelper {
            accounts: vec!["GitHub (zoe)".into(), "AWS (root)".into()],
        };
        let ctx_history = MemHistory::new();
        let ctx = Context::new(&ctx_history);

        let (start, pairs) = helper.complete("re", 2, &ctx).unwrap();
        assert_eq!(start, 0);
        let names: Vec<&str> = pairs.iter().map(|p| p.display.as_str()).collect();
        assert!(names.contains(&"rename"));
        assert!(names.contains(&"reveal"));

        let (start, pairs) = helper.complete("get git", 7, &ctx).unwrap();
        assert_eq!(start, 4);
        assert_eq!(pairs.len(), 1);
        // A name with spaces comes back quoted so tokenize() sees one word.
        assert_eq!(pairs[0].replacement, "\"GitHub (zoe)\"");
    }
}
