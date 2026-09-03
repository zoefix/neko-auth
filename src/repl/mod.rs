//! The interactive session.
//!
//! History is held in memory and never written to disk. A TOTP manager's
//! command history is itself sensitive — `show coinbase` says which services
//! the user has accounts with — and it has no business outliving the session.

pub mod watch;

use std::path::PathBuf;

use anyhow::Result;
use std::io::IsTerminal;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::MemHistory;
use rustyline::{CompletionType, Config, Context, Editor};
use rustyline::{Helper, Validator};

use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;

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
    // Everything the session prints — issuer names, account names, codes —
    // goes on the terminal's alternate screen, so `exit` takes it with it.
    // Otherwise the account list stays in the scrollback of a terminal anyone
    // can scroll back through, which is exactly the metadata the in-memory
    // history was there to keep out of reach.
    let private_screen = PrivateScreen::enter(&app.config);

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
        locked: false,
    }));

    loop {
        // Refresh completions, and notice if the idle watchdog has locked us.
        let unlocked = app.vault.is_unlocked();
        if let Some(helper) = editor.helper_mut() {
            helper.locked = !unlocked;
            helper.accounts = if unlocked {
                app.vault
                    .list()
                    .map(|list| list.into_iter().map(|a| a.display()).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
        }

        let prompt = prompt_for(!unlocked);

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
    // Dropped before the closing line, so that line lands on the terminal the
    // user is left looking at rather than on the screen being discarded.
    drop(private_screen);
    println!("{}", ui::dim(&i18n::locked_goodbye()));
    Ok(())
}

/// Runs the session on the terminal's alternate screen, restoring whatever was
/// there when it drops.
///
/// Deliberately not a screen-clear on exit: `\x1b[3J` would erase the whole
/// scrollback, including everything the user had before neko-auth started.
/// The alternate screen only ever hides what this program itself drew.
struct PrivateScreen {
    active: bool,
}

impl PrivateScreen {
    fn enter(config: &crate::config::Config) -> Self {
        // Nothing to hide when output is a pipe or a file, and switching
        // screens would only inject escape sequences into it.
        let wanted = !config.keep_scrollback && std::io::stdout().is_terminal();
        let active = wanted && std::io::stdout().execute(EnterAlternateScreen).is_ok();
        PrivateScreen { active }
    }
}

impl Drop for PrivateScreen {
    fn drop(&mut self) {
        if self.active {
            let _ = std::io::stdout().execute(LeaveAlternateScreen);
        }
    }
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
        // A bare `/` is the same question as `help`.
        "help" | "?" | "" => print_help(),
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
            // The session already owns the alternate screen.
            watch::run(app, args.first().copied(), false)?;
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

#[derive(Helper, Validator)]
struct NekoHelper {
    accounts: Vec<String>,
    locked: bool,
}

/// The prompt string handed to `readline()`.
///
/// Deliberately plain. rustyline measures the prompt to work out where the
/// cursor goes, and its Windows backend counts ANSI escapes as visible columns
/// while its Unix backend skips them — so a pre-coloured prompt puts the cursor
/// about fifteen columns too far right on Windows and looks fine everywhere
/// else. Colour is applied in `highlight_prompt`, which rustyline excludes from
/// the measurement.
fn prompt_for(locked: bool) -> String {
    if locked {
        format!("neko-auth {} › ", i18n::prompt_locked_suffix())
    } else {
        "neko-auth › ".to_string()
    }
}

impl Highlighter for NekoHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> std::borrow::Cow<'b, str> {
        if !ui::colored() {
            return std::borrow::Cow::Borrowed(prompt);
        }
        let painted = if self.locked {
            ui::yellow(prompt)
        } else {
            ui::cyan(prompt)
        };
        std::borrow::Cow::Owned(painted)
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        if ui::colored() {
            std::borrow::Cow::Owned(ui::dim(hint))
        } else {
            std::borrow::Cow::Borrowed(hint)
        }
    }
}

/// Shows the command list the moment `/` is typed.
///
/// A hint rather than a completion popup: rustyline's list completion only
/// prints candidates on a *second* Tab, so no single keypress can produce the
/// list through that route. A hint is recomputed after every keystroke and
/// drawn straight after the cursor, which is what makes `/` feel like it opens
/// a menu — and it narrows as more is typed.
impl Hinter for NekoHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        // Only while typing at the end of the line, or the hint would appear
        // in the middle of what is being edited.
        if pos != line.len() {
            return None;
        }
        let typed = line.strip_prefix('/')?;
        // Once there is an argument, the command is settled and the list is
        // just noise.
        if typed.contains(char::is_whitespace) {
            return None;
        }

        let matching: Vec<&str> = COMMAND_NAMES
            .iter()
            .copied()
            .filter(|name| name.starts_with(typed))
            .collect();

        match matching.as_slice() {
            [] => None,
            // A single match completes itself rather than repeating what is
            // already on screen.
            [only] => (*only != typed).then(|| only[typed.len()..].to_string()),
            names => Some(format!("   {}", names.join(" "))),
        }
    }
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

    /// Redirected output must not be given screen-switching escapes.
    ///
    /// `cargo test` captures stdout, so this exercises exactly the non-terminal
    /// path: piping `ls` into a file should produce the listing and nothing
    /// else.
    #[test]
    fn a_pipe_is_left_alone() {
        let config = crate::config::Config::default();
        assert!(!config.keep_scrollback, "the private screen is the default");
        let screen = PrivateScreen::enter(&config);
        assert!(
            !screen.active,
            "stdout is not a terminal here, so no screen switch may happen"
        );
    }

    #[test]
    fn the_private_screen_can_be_turned_off() {
        let mut config = crate::config::Config::default();
        config.set("keep_scrollback", "true").unwrap();
        assert!(config.keep_scrollback);
        assert!(!PrivateScreen::enter(&config).active);
    }

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

    /// The prompt reaches rustyline uncoloured.
    ///
    /// rustyline's Windows backend measures escape sequences as visible
    /// columns, so a coloured prompt here would leave the cursor stranded to
    /// the right of where the user is typing — and would look perfectly fine
    /// on Linux and macOS, which is how it shipped the first time.
    #[test]
    fn the_prompt_carries_no_escape_sequences() {
        for locked in [false, true] {
            let prompt = prompt_for(locked);
            assert!(
                !prompt.contains('\x1b'),
                "locked={locked}: prompt is pre-coloured: {prompt:?}"
            );
            assert!(prompt.starts_with("neko-auth "));
            assert!(prompt.ends_with("› "));
        }
        // The locked prompt says so, in whatever language is active.
        assert!(prompt_for(true).len() > prompt_for(false).len());
    }

    #[test]
    fn the_highlighter_is_what_adds_the_colour() {
        let plain = prompt_for(false);
        let helper = NekoHelper {
            accounts: Vec::new(),
            locked: false,
        };
        let painted = helper.highlight_prompt(&plain, true);

        if ui::colored() {
            assert!(painted.contains('\x1b'), "colour should be applied here");
            assert!(painted.contains("neko-auth"));
        } else {
            // With colour off the prompt passes through untouched, so nothing
            // has to be stripped later.
            assert_eq!(painted, plain);
        }
    }

    fn hint_for(line: &str) -> Option<String> {
        let helper = NekoHelper {
            accounts: Vec::new(),
            locked: false,
        };
        let history = MemHistory::new();
        helper.hint(line, line.len(), &Context::new(&history))
    }

    #[test]
    fn a_slash_lists_the_commands_immediately() {
        let hint = hint_for("/").expect("`/` on its own should list everything");
        for name in COMMAND_NAMES {
            assert!(
                hint.contains(name),
                "`{name}` missing from the list: {hint}"
            );
        }
    }

    #[test]
    fn the_list_narrows_as_more_is_typed() {
        assert_eq!(
            hint_for("/re")
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>(),
            ["rename", "reveal", "restore"]
        );
        assert_eq!(
            hint_for("/ex")
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>(),
            ["export", "exit"]
        );
        // Down to one, the hint completes the word instead of echoing it back.
        assert_eq!(hint_for("/doc").as_deref(), Some("tor"));
        // And says nothing once the word is whole.
        assert_eq!(hint_for("/doctor"), None);
        // Nothing matches: no hint rather than an empty one.
        assert_eq!(hint_for("/zzz"), None);
    }

    #[test]
    fn the_hint_stays_out_of_the_way_the_rest_of_the_time() {
        // No slash: the user is typing a bare command, which Tab handles.
        assert_eq!(hint_for("ls"), None);
        // Past the command word, the list would just be noise.
        assert_eq!(hint_for("/get github"), None);
        assert_eq!(hint_for("/import qr a.png"), None);

        // Mid-line editing must not sprout a hint after the cursor.
        let helper = NekoHelper {
            accounts: Vec::new(),
            locked: false,
        };
        let history = MemHistory::new();
        assert_eq!(helper.hint("/re", 1, &Context::new(&history)), None);
    }

    #[test]
    fn a_bare_slash_is_accepted_as_help() {
        // `/` alone tokenises to one word that strips to nothing, and the
        // dispatcher treats that as `help` rather than an unknown command.
        let words = tokenize("/");
        assert_eq!(words, ["/"]);
        assert_eq!(words[0].strip_prefix('/'), Some(""));
    }

    #[test]
    fn completion_offers_commands_then_account_names() {
        let helper = NekoHelper {
            accounts: vec!["GitHub (zoe)".into(), "AWS (root)".into()],
            locked: false,
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
