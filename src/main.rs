//! neko-auth — a fully offline TOTP authenticator.

use std::process::ExitCode;

use anyhow::Result;

use neko_auth::app::App;
use neko_auth::cli::{self, Command, ExportTarget, ImportSource};
use neko_auth::config::Config;
use neko_auth::crypto::KdfParams;
use neko_auth::i18n::{self, Language};
use neko_auth::secrets::{self, Cancelled};
use neko_auth::vault::Vault;
use neko_auth::{paths, repl, ui};

fn main() -> ExitCode {
    // Before anything sensitive can reach memory: no core dumps, a private
    // umask for the files SQLite will create, and a panic hook that does not
    // print the payload.
    secrets::harden_process();
    secrets::install_panic_hook();

    // Held for the whole run: the Windows console decodes output with its own
    // code page, and on a Chinese or Japanese system that is not UTF-8, so the
    // translated interface would arrive as mojibake. Restored on the way out.
    let _console = ui::use_utf8_console();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.downcast_ref::<Cancelled>().is_some() => {
            eprintln!();
            ExitCode::from(130) // the conventional code for an interrupted command
        }
        Err(e) => {
            ui::error(&format!("{e:#}"));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let config_path = paths::config_path()?;

    // Settle the language before clap can print help or an error, and before
    // any message is produced. The locale environment is the starting point so
    // that even a broken config file reports its own failure in the right
    // language.
    i18n::set_current(Language::from_environment().unwrap_or_default());
    let flag = cli::language_override(std::env::args());
    let config = Config::load(&config_path)?;
    i18n::set_current(match flag.as_deref() {
        Some(value) => i18n::resolve(value),
        None => config.language(),
    });

    let cli = cli::parse_localized();
    let vault_path = paths::vault_path(cli.vault.as_deref())?;

    // `init` is the one command that runs without an existing vault.
    if let Some(Command::Init { kdf_profile }) = &cli.command {
        let kdf = match kdf_profile {
            Some(name) => KdfParams::by_name(name)
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::unknown_kdf_profile(name)))?,
            None => config.kdf()?,
        };
        let mut updated = config.clone();
        if let Some(name) = kdf_profile {
            updated.kdf_profile = name.clone();
        }
        if let Some(value) = &flag {
            updated.language = value.clone();
        }
        let vault = App::init(&vault_path, updated, kdf)?;
        vault.close();
        return Ok(());
    }

    if !vault_path.exists() {
        anyhow::bail!("{}", i18n::no_vault_here(&vault_path.display().to_string()));
    }
    if let Some(message) = paths::permission_warning(&vault_path) {
        ui::warn(&message);
    }

    let mut vault = Vault::open(&vault_path, config.idle_timeout())?;
    if !vault.wal_active {
        ui::warn(&i18n::wal_warning_startup());
    }

    App::unlock_interactively(&mut vault, config.hide_email)?;
    let mut app = App {
        vault,
        config,
        config_path,
    };

    let result = match cli.command {
        None => return repl::run(app),
        Some(command) => dispatch(&mut app, command),
    };

    app.vault.close();
    result
}

fn dispatch(app: &mut App, command: Command) -> Result<()> {
    match command {
        // Handled before the vault is opened.
        Command::Init { .. } => unreachable!(),

        Command::Ls { pattern } => app.list(pattern.as_deref()),
        // `block: true` for one-shot use: the process has to stay alive to
        // clear the clipboard afterwards, and on X11 and Wayland it has to
        // stay alive for the paste to work at all.
        Command::Get { name, copy } => app.get(&name, copy, true),
        Command::Watch { pattern } => repl::watch::run(app, pattern.as_deref()),
        Command::Add => app.add(),
        Command::Import { source } => match source {
            ImportSource::Uri { uri } => app.import_uri(uri.as_deref()),
            ImportSource::Qr { paths } => app.import_qr(&paths),
            ImportSource::File { path } => app.import_file(&path),
        },
        Command::Rm { name } => app.remove(&name),
        Command::Rename { name } => app.rename(&name),
        Command::Show { name } => app.show(&name),
        Command::Reveal { name } => app.reveal(&name),
        Command::Export { target } => match target {
            ExportTarget::Encrypted {
                path,
                same_password,
            } => app.export_encrypted(&path, same_password),
            ExportTarget::Plain { path } => app.export_plain(&path),
        },
        Command::Restore { path } => app.restore(&path),
        Command::ChangePassword => app.change_password(),
        Command::Doctor => app.doctor(),
        Command::Config { key, value } => match (key, value) {
            (None, _) => app.show_config(),
            (Some(key), None) => {
                let found = app
                    .config
                    .entries()
                    .into_iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| v);
                match found {
                    Some(v) => {
                        println!("{}", i18n::setting_saved(&key, &v));
                        Ok(())
                    }
                    None => anyhow::bail!("{}", i18n::unknown_setting(&key)),
                }
            }
            (Some(key), Some(value)) => app.set_config(&key, &value),
        },
        #[cfg(feature = "update")]
        Command::Update { check } => neko_auth::update::run(&app.config, check),
    }
}
