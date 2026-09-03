//! Command-line parsing for one-shot invocations.
//!
//! Running `neko-auth` with no subcommand opens the interactive session
//! instead. Every one-shot form still asks for the master password.

use std::path::PathBuf;

use clap::{Arg, ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::i18n;

#[derive(Parser, Debug)]
#[command(
    name = "neko-auth",
    version,
    about = "A fully offline TOTP authenticator with an encrypted vault",
    long_about = "neko-auth keeps two-factor secrets in a local, encrypted SQLite vault.\n\
                  Nothing leaves the machine: there is no HTTP client, no TLS, and \
                  no DNS resolver in the build.\n\n\
                  Run with no arguments to open the interactive session."
)]
pub struct Cli {
    /// Vault file to use (default: the per-user data directory).
    #[arg(long, global = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Interface language: auto, en, zh-Hans, zh-Hant, ja.
    #[arg(long, global = true, value_name = "LANG")]
    pub lang: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new vault.
    Init {
        /// Key-derivation cost: interactive, moderate, or paranoid.
        #[arg(long, value_name = "PROFILE")]
        kdf_profile: Option<String>,
    },
    /// List accounts, without generating codes.
    #[command(alias = "list")]
    Ls {
        /// Only show accounts matching this text.
        pattern: Option<String>,
    },
    /// Print the current code for one account.
    Get {
        /// Any part of the issuer or account name.
        name: String,
        /// Also copy the code to the clipboard.
        #[arg(short, long)]
        copy: bool,
    },
    /// Full-screen live view of every code.
    Watch {
        /// Only show accounts matching this text.
        pattern: Option<String>,
    },
    /// Add one account, entering the secret at a hidden prompt.
    Add,
    /// Import accounts from a URI, a QR image, or a file.
    Import {
        #[command(subcommand)]
        source: ImportSource,
    },
    /// Delete an account.
    #[command(alias = "remove")]
    Rm { name: String },
    /// Change an account's issuer or label.
    Rename { name: String },
    /// Show one account's settings, without its secret.
    Show { name: String },
    /// Print an account's shared secret. Asks for confirmation.
    Reveal { name: String },
    /// Write a backup or an export.
    Export {
        #[command(subcommand)]
        target: ExportTarget,
    },
    /// Import accounts from an encrypted backup.
    Restore { path: PathBuf },
    /// Change the email and master password.
    #[command(alias = "passwd")]
    ChangePassword,
    /// Check the vault for damage.
    Doctor,
    /// Retired in 0.1.3; kept only to explain itself.
    ///
    /// Hidden, so it is absent from help and from completion, but still
    /// recognised: `neko-auth update` was the documented way to upgrade up to
    /// 0.1.2, and answering it with "unrecognized subcommand" would look like
    /// a broken install rather than a deliberate removal.
    #[command(hide = true, alias = "upgrade")]
    Update,
    /// Show or change settings.
    Config {
        /// Setting to change. Omit to list everything.
        key: Option<String>,
        /// New value. Omit to show just this setting.
        value: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ImportSource {
    /// A single otpauth:// URI. Omit it to be prompted with the echo off.
    Uri { uri: Option<String> },
    /// One or more images containing QR codes.
    ///
    /// A Google Authenticator export split across several codes must be given
    /// all at once, or as repeated imports before anything is stored.
    Qr { paths: Vec<PathBuf> },
    /// A text file of otpauth:// or otpauth-migration:// URIs, one per line.
    File { path: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum ExportTarget {
    /// An encrypted .nekobak archive.
    Encrypted {
        path: PathBuf,
        /// Protect the backup with the current master password instead of a
        /// new one.
        #[arg(long)]
        same_password: bool,
    },
    /// Unencrypted otpauth:// URIs. Requires a typed confirmation.
    Plain { path: PathBuf },
}

/// Builds the command with every description replaced by its translation.
///
/// clap's derive attributes only accept literals, so the English text in this
/// file is the source of truth and the active language is applied here, once,
/// before anything is rendered.
pub fn localized_command() -> clap::Command {
    let mut command = Cli::command()
        .about(i18n::cli_about())
        .long_about(i18n::cli_long_about())
        .mut_arg("vault", |arg| arg.help(i18n::arg_vault()))
        .mut_arg("lang", |arg| arg.help(i18n::arg_lang()));

    let subcommands: Vec<(&str, String)> = vec![
        ("init", i18n::cmd_init()),
        ("ls", i18n::cmd_ls()),
        ("get", i18n::cmd_get()),
        ("watch", i18n::cmd_watch()),
        ("add", i18n::cmd_add()),
        ("import", i18n::cmd_import()),
        ("rm", i18n::cmd_rm()),
        ("rename", i18n::cmd_rename()),
        ("show", i18n::cmd_show()),
        ("reveal", i18n::cmd_reveal()),
        ("export", i18n::cmd_export()),
        ("restore", i18n::cmd_restore()),
        ("change-password", i18n::cmd_passwd()),
        ("doctor", i18n::cmd_doctor()),
        ("config", i18n::cmd_config()),
    ];
    for (name, about) in subcommands {
        command = command.mut_subcommand(name, |sub| sub.about(about));
    }

    command = command
        .mut_subcommand("init", |sub| {
            sub.mut_arg("kdf_profile", |arg| arg.help(i18n::arg_kdf_profile()))
        })
        .mut_subcommand("ls", |sub| {
            sub.mut_arg("pattern", |arg| arg.help(i18n::arg_pattern()))
        })
        .mut_subcommand("watch", |sub| {
            sub.mut_arg("pattern", |arg| arg.help(i18n::arg_pattern()))
        })
        .mut_subcommand("get", |sub| {
            sub.mut_arg("name", |arg| arg.help(i18n::arg_name()))
                .mut_arg("copy", |arg| arg.help(i18n::arg_copy()))
        })
        .mut_subcommand("import", |sub| {
            sub.mut_subcommand("uri", |c| {
                c.about(i18n::sub_import_uri())
                    .mut_arg("uri", |arg| arg.help(i18n::arg_uri()))
            })
            .mut_subcommand("qr", |c| {
                c.about(i18n::sub_import_qr())
                    .mut_arg("paths", |arg| arg.help(i18n::arg_qr_paths()))
            })
            .mut_subcommand("file", |c| {
                c.about(i18n::sub_import_file())
                    .mut_arg("path", |arg| arg.help(i18n::arg_import_file()))
            })
        })
        .mut_subcommand("export", |sub| {
            sub.mut_subcommand("encrypted", |c| {
                c.about(i18n::sub_export_encrypted())
                    .mut_arg("same_password", |arg| arg.help(i18n::arg_same_password()))
            })
            .mut_subcommand("plain", |c| c.about(i18n::sub_export_plain()))
        })
        .mut_subcommand("config", |sub| {
            sub.mut_arg("key", |arg| arg.help(i18n::arg_config_key()))
                .mut_arg("value", |arg| arg.help(i18n::arg_config_value()))
        });

    apply_help_template(&mut command, true);
    command
}

/// Replaces clap's English section headings and built-in flag descriptions.
///
/// Two templates rather than `{all-args}`: the automatic form emits the
/// headings itself, and a leaf subcommand has no `Commands:` section to head.
///
/// `--help` and `--version` are declared here instead of relabelled, because
/// clap injects its own versions only while building, long after `mut_arg`
/// could reach them.
fn apply_help_template(command: &mut clap::Command, is_root: bool) {
    // Each section is added only when it has content, or the heading would be
    // left hanging over nothing. `{all-args}` would handle that automatically
    // but supplies its own English headings, which is the thing being replaced.
    let mut template = format!("{{about-with-newline}}\n{} {{usage}}\n", i18n::help_usage());
    if command.get_positionals().next().is_some() {
        template.push_str(&format!("\n{}\n{{positionals}}\n", i18n::help_arguments()));
    }
    if command.has_subcommands() {
        template.push_str(&format!("\n{}\n{{subcommands}}\n", i18n::help_commands()));
    }
    template.push_str(&format!("\n{}\n{{options}}", i18n::help_options()));

    let mut built = command
        .clone()
        .help_template(template)
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help(i18n::arg_help()),
        );

    // A derive doc comment with a second paragraph becomes clap's long_about,
    // which `--help` prefers over about and which the translation above does
    // not touch. The root keeps its own longer text; every subcommand shows
    // its translated one-liner in both forms.
    if !is_root {
        if let Some(about) = command.get_about().cloned() {
            built = built.long_about(about);
        }
    }

    if is_root {
        built = built.disable_version_flag(true).arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help(i18n::arg_version()),
        );
    }
    *command = built;

    let names: Vec<String> = command
        .get_subcommands()
        .map(|sub| sub.get_name().to_string())
        .collect();
    for name in names {
        *command = command.clone().mut_subcommand(&name, |mut sub| {
            apply_help_template(&mut sub, false);
            sub
        });
    }
}

/// Parses the command line, rendering help and errors in the active language.
pub fn parse_localized() -> Cli {
    let matches = localized_command().get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

/// Finds `--lang` before clap runs.
///
/// The language has to be settled before clap can render `--help` or an
/// argument error, and clap cannot tell us the value until after it has had a
/// chance to do both.
pub fn language_override<I, S>(args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref();
        if let Some(value) = arg.strip_prefix("--lang=") {
            return Some(value.to_string());
        }
        if arg == "--lang" {
            return args.next().map(|next| next.as_ref().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_language_flag_is_found_in_either_form() {
        assert_eq!(
            language_override(["neko-auth", "--lang", "ja", "ls"]),
            Some("ja".to_string())
        );
        assert_eq!(
            language_override(["neko-auth", "--lang=zh-Hant"]),
            Some("zh-Hant".to_string())
        );
        assert_eq!(language_override(["neko-auth", "ls"]), None);
        // A trailing --lang with no value is left for clap to complain about.
        assert_eq!(language_override(["neko-auth", "--lang"]), None);
    }

    #[test]
    fn the_command_tree_is_valid_after_translation() {
        // mut_subcommand and mut_arg silently do nothing when a name is wrong,
        // so this asserts the structure clap actually built.
        localized_command().debug_assert();
    }
}
