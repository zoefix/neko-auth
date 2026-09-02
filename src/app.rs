//! Command implementations, shared by the one-shot CLI and the REPL.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use secrecy::SecretString;

use crate::config::Config;
use crate::crypto::KdfParams;
use crate::i18n;
use crate::otp::uri::OtpAuth;
use crate::otp::{self, OtpKind, OtpParams};
use crate::secrets;
use crate::ui;
use crate::vault::{Account, Vault, VaultIntegrityWarning};

pub struct App {
    pub vault: Vault,
    pub config: Config,
    pub config_path: PathBuf,
}

impl App {
    /// Creates a vault and takes the user through choosing a master password.
    pub fn init(vault_path: &Path, config: Config, kdf: KdfParams) -> Result<Vault> {
        if vault_path.exists() {
            bail!(
                "{}",
                i18n::init_already_exists(&vault_path.display().to_string())
            );
        }

        println!("{}", ui::heading(&i18n::init_heading()));
        println!("  {}", vault_path.display());
        println!();
        // The emphasised word is a separate entry rather than markup inside the
        // sentence, so each language can put the emphasis where it belongs.
        let only = i18n::init_only_word();
        println!(
            "{}",
            i18n::init_only_protection().replacen(&only, &ui::bold(&only), 1)
        );
        println!("{}", ui::yellow(&i18n::init_no_recovery()));
        println!();
        println!("{}", i18n::init_email_note());
        println!("{}", ui::yellow(&i18n::init_email_warning()));
        println!();
        println!(
            "{}",
            ui::dim(&i18n::init_kdf_note(
                kdf.memory_bytes() / (1024 * 1024),
                kdf.t_cost()
            ))
        );
        println!();

        let credentials = secrets::prompt_new_credentials(config.hide_email)?;
        let vault = Vault::create(vault_path, &credentials, kdf)?;

        if !vault.wal_active {
            ui::warn(&i18n::wal_warning_init());
        }

        config.save(&crate::paths::config_path()?)?;
        ui::success(&i18n::init_done());

        // Show the address back, normalised, exactly as it will have to be
        // typed. It is not stored anywhere, so this is the only moment the
        // user can see what the vault will actually expect.
        println!();
        println!(
            "  {} {}",
            i18n::field_email(),
            ui::bold(credentials.email())
        );
        println!("{}", ui::yellow(&i18n::init_remember_email()));
        Ok(vault)
    }

    /// Prompts for the master password until the vault opens.
    ///
    /// Used both at startup and whenever the idle timer has erased the keys
    /// mid-session.
    pub fn unlock_interactively(vault: &mut Vault, hide_email: bool) -> Result<()> {
        loop {
            let credentials = secrets::prompt_credentials(hide_email)?;
            match vault.unlock(&credentials) {
                Ok(()) => return Ok(()),
                Err(e) if e.downcast_ref::<VaultIntegrityWarning>().is_some() => {
                    // The password was right; the vault opened. This is a
                    // warning about the file's contents, not a failed unlock.
                    ui::warn(&e.to_string());
                    return Ok(());
                }
                Err(e) => {
                    ui::error(&e.to_string());
                    if !secrets::confirm(&i18n::try_again())? {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Re-prompts if the vault has been locked since the last command, whether
    /// by the idle watchdog or by the user.
    pub fn ensure_unlocked(&mut self) -> Result<()> {
        if self.vault.is_unlocked() {
            self.vault.touch();
            return Ok(());
        }
        ui::note(&i18n::vault_is_locked());
        let hide_email = self.config.hide_email;
        Self::unlock_interactively(&mut self.vault, hide_email)?;
        Ok(())
    }

    // -- lookup -------------------------------------------------------------

    /// Finds the one account matching `needle`, or explains the ambiguity.
    pub fn resolve(&self, needle: &str) -> Result<Account> {
        let accounts = self.vault.list()?;
        let matches: Vec<Account> = accounts.into_iter().filter(|a| a.matches(needle)).collect();

        match matches.len() {
            0 => bail!("{}", i18n::no_account_matches(needle)),
            1 => Ok(matches.into_iter().next().unwrap()),
            _ => {
                // An exact, case-insensitive hit on the full display name wins
                // over the substring matches it is a prefix of.
                if let Some(exact) = matches
                    .iter()
                    .find(|a| a.display().eq_ignore_ascii_case(needle))
                {
                    return Ok(exact.clone());
                }
                let names: Vec<String> = matches
                    .iter()
                    .map(|a| format!("  {}", a.display()))
                    .collect();
                bail!(
                    "{}",
                    i18n::ambiguous_name(needle, matches.len(), &names.join("\n"))
                )
            }
        }
    }

    // -- commands -----------------------------------------------------------

    pub fn list(&mut self, pattern: Option<&str>) -> Result<()> {
        self.ensure_unlocked()?;
        let needle = pattern.unwrap_or("");
        let accounts: Vec<Account> = self
            .vault
            .list()?
            .into_iter()
            .filter(|a| a.matches(needle))
            .collect();

        if accounts.is_empty() {
            ui::note(&if needle.is_empty() {
                i18n::no_accounts_yet()
            } else {
                i18n::no_accounts_match()
            });
            return Ok(());
        }

        let now = otp::now();
        let mut unreadable = 0usize;
        let rows: Vec<Vec<String>> = accounts
            .iter()
            .map(|account| {
                let code = match self.code_for(account, now) {
                    Some(code) => ui::cyan(&code),
                    None => {
                        unreadable += 1;
                        ui::red(&"?".repeat(account.params.digits as usize))
                    }
                };
                vec![
                    account
                        .issuer
                        .clone()
                        .unwrap_or_else(|| ui::dim(&i18n::none_placeholder())),
                    account.label.clone(),
                    code,
                ]
            })
            .collect();

        print!(
            "{}",
            ui::table(
                &[
                    &i18n::column_issuer(),
                    &i18n::column_account(),
                    &i18n::column_code(),
                ],
                &rows
            )
        );

        // The countdown goes in the footer rather than a fourth column, and
        // only when every account shown shares one period — with mixed periods
        // a single number would be wrong for some of the rows.
        let mut periods = accounts.iter().filter_map(|a| match a.params.kind {
            OtpKind::Totp { period } => Some(period),
            OtpKind::Hotp { .. } => None,
        });
        let shared = periods.next().filter(|first| periods.all(|p| p == *first));

        let count = i18n::account_count(accounts.len());
        match shared {
            Some(period) => println!(
                "{}",
                ui::dim(&format!(
                    "{count} · {}",
                    i18n::refreshes_in(otp::seconds_remaining(now, period))
                ))
            ),
            None => println!("{}", ui::dim(&count)),
        }

        if unreadable > 0 {
            ui::warn(&i18n::some_codes_unreadable());
        }
        Ok(())
    }

    /// The current code for one account, or `None` if its secret will not
    /// decrypt.
    ///
    /// Listing must survive a damaged row: naming the one bad account while
    /// every other code still works is the whole practical payoff of
    /// encrypting field by field, and it would be thrown away by letting one
    /// failure abort the listing.
    ///
    /// Counter-based accounts are shown without advancing the counter. Listing
    /// is not using a code, and silently consuming one on every `ls` would
    /// desynchronise the account from the server.
    fn code_for(&self, account: &Account, now: u64) -> Option<String> {
        let secret = self.vault.secret_of(account).ok()?;
        let code = otp::generate(&secret, &account.params, now).ok()?;
        Some(if self.config.group_digits {
            code.grouped()
        } else {
            code.as_str().to_string()
        })
    }

    pub fn get(&mut self, needle: &str, copy: bool, block: bool) -> Result<()> {
        self.ensure_unlocked()?;
        let account = self.resolve(needle)?;
        let secret = self.vault.secret_of(&account)?;
        let code = otp::generate(&secret, &account.params, otp::now())?;
        drop(secret);

        let shown = if self.config.group_digits {
            code.grouped()
        } else {
            code.as_str().to_string()
        };

        println!("{}", ui::bold(&account.display()));
        match account.params.kind {
            OtpKind::Totp { period } => {
                let remaining = otp::seconds_remaining(otp::now(), period);
                println!(
                    "  {}   {} {}",
                    ui::cyan(&shown),
                    ui::countdown_bar(remaining, period, 12),
                    ui::dim(&i18n::seconds_left(remaining))
                );
            }
            OtpKind::Hotp { counter } => {
                println!(
                    "  {}   {}",
                    ui::cyan(&shown),
                    ui::dim(&format!("counter {counter}"))
                );
                let next = self.vault.bump_counter(&account)?;
                ui::note(&format!("counter advanced to {next}"));
            }
        }

        if copy {
            self.copy_code(code.as_str(), block)?;
        }
        Ok(())
    }

    #[cfg(feature = "clipboard")]
    fn copy_code(&self, code: &str, block: bool) -> Result<()> {
        let timeout = self.config.clipboard_timeout();
        crate::clipboard::copy_transient(code, timeout, block)?;
        match timeout {
            Some(t) if block => ui::note(&i18n::copied_cleared_after(t.as_secs())),
            Some(t) => ui::note(&i18n::copied_clears_in(t.as_secs())),
            None => ui::note(&i18n::copied()),
        }
        Ok(())
    }

    #[cfg(not(feature = "clipboard"))]
    fn copy_code(&self, _code: &str, _block: bool) -> Result<()> {
        bail!("{}", i18n::no_clipboard_support())
    }

    /// Adds one account, prompting for whatever was not supplied.
    ///
    /// The secret is read with echo off and never accepted as a command-line
    /// argument: `argv` is visible to other processes through `ps`, and a
    /// non-interactive invocation would also leave it in the shell history.
    pub fn add(&mut self) -> Result<()> {
        self.ensure_unlocked()?;

        println!("{}", i18n::add_intro());
        let input = secrets::prompt_password(&i18n::prompt_secret_or_uri())?;
        let entry = self.build_entry(&input)?;

        self.store(std::slice::from_ref(&entry))
    }

    fn build_entry(&self, input: &SecretString) -> Result<OtpAuth> {
        use secrecy::ExposeSecret;
        let text = input.expose_secret().trim();
        if text.is_empty() {
            bail!("{}", i18n::nothing_entered());
        }

        if text.to_ascii_lowercase().starts_with("otpauth://") {
            return OtpAuth::parse(text).map_err(Into::into);
        }

        // A plain Base32 secret. Plenty of sites offer only this, with no QR
        // code, so the rest of the parameters are asked for with the standard
        // defaults pre-filled.
        let secret = crate::otp::uri::decode_base32(text).with_context(i18n::not_uri_or_base32)?;

        let issuer = secrets::prompt_line(&i18n::prompt_issuer_example())?;
        let label = secrets::prompt_line(&i18n::prompt_account_example())?;
        let digits = prompt_number(&i18n::prompt_digits(), 6)?;
        let period = prompt_number(&i18n::prompt_period(), 30)?;
        let algorithm_text = secrets::prompt_line(&i18n::prompt_algorithm())?;
        let algorithm = if algorithm_text.is_empty() {
            otp::Algorithm::Sha1
        } else {
            otp::Algorithm::parse(&algorithm_text)
                .with_context(|| i18n::unknown_algorithm(&algorithm_text))?
        };

        let params = OtpParams {
            algorithm,
            digits,
            kind: OtpKind::Totp { period },
        };
        params.validate()?;

        Ok(OtpAuth {
            issuer: (!issuer.is_empty()).then_some(issuer),
            account: label,
            secret: zeroize::Zeroizing::new(secret),
            params,
        })
    }

    pub fn import_uri(&mut self, uri: Option<&str>) -> Result<()> {
        self.ensure_unlocked()?;
        let text = match uri {
            Some(u) => u.to_string(),
            None => {
                use secrecy::ExposeSecret;
                secrets::prompt_password(&i18n::prompt_uri())?
                    .expose_secret()
                    .to_string()
            }
        };
        let entries = crate::import::collect(&[text])?;
        self.store(&entries)
    }

    #[cfg(feature = "qr")]
    pub fn import_qr(&mut self, paths: &[PathBuf]) -> Result<()> {
        self.ensure_unlocked()?;
        if paths.is_empty() {
            bail!("{}", i18n::give_an_image());
        }
        let decoded = crate::import::qr::decode_files(paths)?;
        ui::note(&i18n::read_qr_codes(decoded.len(), paths.len()));
        let entries = crate::import::collect(&decoded)?;
        self.store(&entries)
    }

    #[cfg(not(feature = "qr"))]
    pub fn import_qr(&mut self, _paths: &[PathBuf]) -> Result<()> {
        bail!("{}", i18n::no_qr_support())
    }

    pub fn import_file(&mut self, path: &Path) -> Result<()> {
        self.ensure_unlocked()?;
        let entries = crate::import::collect(&crate::import::read_file(path)?)?;
        self.store(&entries)
    }

    /// Stores parsed entries, skipping duplicates unless the user insists.
    fn store(&mut self, entries: &[OtpAuth]) -> Result<()> {
        if entries.is_empty() {
            bail!("{}", i18n::nothing_to_import());
        }

        let existing = self.vault.list()?;
        let mut added = 0;
        for entry in entries {
            let duplicate = existing.iter().any(|a| {
                a.issuer.as_deref().unwrap_or("") == entry.issuer.as_deref().unwrap_or("")
                    && a.label == entry.account
            });
            let name = format_name(entry);

            if duplicate {
                ui::warn(&i18n::already_in_vault(&name));
                if !secrets::confirm(&i18n::add_anyway())? {
                    continue;
                }
            }

            self.vault.add(entry, None)?;
            println!("  {} {name}", ui::green("+"));
            added += 1;
        }

        if added == 0 {
            ui::note(&i18n::nothing_added());
        } else {
            ui::success(&i18n::added_accounts(added));
            ui::note(&i18n::back_up_reminder());
        }
        Ok(())
    }

    pub fn remove(&mut self, needle: &str) -> Result<()> {
        self.ensure_unlocked()?;
        let account = self.resolve(needle)?;
        println!("{}", i18n::about_to_delete(&ui::bold(&account.display())));
        ui::warn(&i18n::delete_lockout_warning());
        if !secrets::confirm(&i18n::delete_confirm())? {
            ui::note(&i18n::cancelled());
            return Ok(());
        }
        self.vault.delete(&account)?;
        ui::success(&i18n::deleted(&account.display()));
        Ok(())
    }

    pub fn rename(&mut self, needle: &str) -> Result<()> {
        self.ensure_unlocked()?;
        let account = self.resolve(needle)?;
        println!(
            "Renaming {}. Leave a field empty to keep it.",
            ui::bold(&account.display())
        );

        let issuer_input = secrets::prompt_line(&format!(
            "Issuer [{}]: ",
            account.issuer.as_deref().unwrap_or("-")
        ))?;
        let label_input = secrets::prompt_line(&format!("Account [{}]: ", account.label))?;

        let issuer = if issuer_input.is_empty() {
            account.issuer.clone()
        } else {
            Some(issuer_input)
        };
        let label = if label_input.is_empty() {
            account.label.clone()
        } else {
            label_input
        };

        self.vault.rename(&account, issuer, label)?;
        ui::success(&i18n::renamed());
        Ok(())
    }

    pub fn show(&mut self, needle: &str) -> Result<()> {
        self.ensure_unlocked()?;
        let account = self.resolve(needle)?;
        println!("{}", ui::heading(&account.display()));
        let dash = i18n::none_placeholder();
        let rows = vec![
            vec![
                i18n::field_issuer(),
                account.issuer.clone().unwrap_or_else(|| dash.clone()),
            ],
            vec![i18n::field_account(), account.label.clone()],
            vec![i18n::field_type(), describe_params(&account.params)],
            vec![i18n::field_created(), format_time(account.created_at)],
            vec![i18n::field_updated(), format_time(account.updated_at)],
            vec![
                i18n::field_notes(),
                account.notes.clone().unwrap_or_else(|| dash.clone()),
            ],
        ];
        print!(
            "{}",
            ui::table(&[&i18n::column_field(), &i18n::column_value()], &rows)
        );
        ui::note(&i18n::secret_not_shown());
        Ok(())
    }

    /// Prints the account's `otpauth://` URI, secret included.
    pub fn reveal(&mut self, needle: &str) -> Result<()> {
        self.ensure_unlocked()?;
        let account = self.resolve(needle)?;

        ui::warn(&i18n::reveal_warning(&account.display()));
        // The word typed to confirm stays "REVEAL" in every language: it is a
        // fixed token, and a translated one would be a new way to mistype an
        // irreversible action.
        if !secrets::confirm_typed("", "REVEAL")? {
            ui::note(&i18n::cancelled());
            return Ok(());
        }

        let secret = self.vault.secret_of(&account)?;
        let entry = OtpAuth {
            issuer: account.issuer.clone(),
            account: account.label.clone(),
            secret,
            params: account.params,
        };
        println!("{}", entry.to_uri().as_str());
        Ok(())
    }

    pub fn export_encrypted(&mut self, path: &Path, reuse_password: bool) -> Result<()> {
        self.ensure_unlocked()?;
        let entries = self.vault.export_entries()?;
        if entries.is_empty() {
            bail!("{}", i18n::vault_is_empty());
        }

        let password = if reuse_password {
            ui::note(&i18n::backup_uses_master_password());
            // Confirms with the same pair that unlocks the vault; the backup
            // is then keyed on exactly what the user already has to know.
            let credentials = secrets::prompt_credentials(self.config.hide_email)?;
            crate::export::password_from_credentials(&credentials)
        } else {
            println!("{}", i18n::choose_backup_password());
            secrets::prompt_new_password(&i18n::prompt_backup_password())?
        };

        crate::export::write_encrypted(path, &entries, &password, self.config.kdf()?)?;
        ui::success(&i18n::wrote_to(
            &i18n::account_count(entries.len()),
            &path.display().to_string(),
        ));
        ui::note(&i18n::keep_backup_elsewhere());
        Ok(())
    }

    pub fn export_plain(&mut self, path: &Path) -> Result<()> {
        self.ensure_unlocked()?;
        let entries = self.vault.export_entries()?;
        if entries.is_empty() {
            bail!("{}", i18n::vault_is_empty());
        }

        ui::warn(&i18n::plaintext_export_warning(
            &i18n::secret_count(entries.len()),
            &path.display().to_string(),
        ));
        // The word typed to confirm stays "YES" in every language: it is a
        // fixed token, and translating it would add a new way to mistype an
        // irreversible action.
        if !secrets::confirm_typed(&i18n::plaintext_export_purpose(), "YES")? {
            ui::note(&i18n::cancelled());
            return Ok(());
        }

        crate::export::write_plaintext(path, &entries)?;
        ui::success(&i18n::wrote_to(
            &i18n::account_count(entries.len()),
            &path.display().to_string(),
        ));
        ui::warn(&i18n::delete_export_now());
        Ok(())
    }

    pub fn restore(&mut self, path: &Path) -> Result<()> {
        self.ensure_unlocked()?;
        let password = secrets::prompt_password(&i18n::prompt_backup_password())?;
        let entries = crate::export::read_encrypted(path, &password)?;
        ui::note(&i18n::accounts_in_file(
            &i18n::account_count(entries.len()),
            &path.display().to_string(),
        ));
        self.store(&entries)
    }

    pub fn change_password(&mut self) -> Result<()> {
        self.ensure_unlocked()?;

        // Re-authenticate: an unattended unlocked terminal should not be enough
        // to lock the owner out of their own vault.
        println!("{}", ui::bold(&i18n::prompt_current_credentials()));
        let current = secrets::prompt_credentials(self.config.hide_email)?;
        let mut probe = crate::vault::Vault::open(self.vault.path(), None)?;
        probe
            .unlock(&current)
            .or_else(|e| {
                if e.downcast_ref::<VaultIntegrityWarning>().is_some() {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .with_context(i18n::current_password_wrong)?;
        drop(probe);

        println!("{}", ui::bold(&i18n::prompt_new_credentials()));
        let new = secrets::prompt_new_credentials(self.config.hide_email)?;
        self.vault.change_password(&new, self.config.kdf()?)?;
        ui::success(&i18n::credentials_changed());
        ui::note(&i18n::backups_keep_own_password());
        Ok(())
    }

    pub fn doctor(&mut self) -> Result<()> {
        self.ensure_unlocked()?;
        let report = self.vault.doctor()?;

        println!("{}", ui::heading(&i18n::doctor_heading()));

        // Labels are padded as a group rather than to a fixed width: they are
        // several cells wider in Japanese than in English, and a hard-coded
        // column would leave the values ragged in three of the four languages.
        let rows: Vec<(String, String)> = vec![
            (i18n::doctor_file(), self.vault.path().display().to_string()),
            (i18n::doctor_accounts(), report.accounts.to_string()),
            (
                i18n::doctor_sqlite(),
                if report.sqlite_integrity == "ok" {
                    ui::green(&i18n::status_ok())
                } else {
                    ui::red(&report.sqlite_integrity)
                },
            ),
            (
                i18n::doctor_signature(),
                if report.mac_ok {
                    ui::green(&i18n::status_ok())
                } else {
                    ui::red(&i18n::status_mismatch())
                },
            ),
            (
                i18n::doctor_wal(),
                if report.wal_active {
                    ui::green(&i18n::status_active())
                } else {
                    ui::yellow(&i18n::status_unavailable())
                },
            ),
        ];
        let width = rows
            .iter()
            .map(|(label, _)| ui::width(label))
            .max()
            .unwrap_or(0);
        for (label, value) in &rows {
            let padding = " ".repeat(width.saturating_sub(ui::width(label)));
            println!("  {label}{padding}  {value}");
        }

        if !report.mac_ok {
            ui::warn(&i18n::doctor_mac_warning());
        }
        if !report.wal_active {
            ui::warn(&i18n::wal_warning());
        }
        if let Some(message) = &report.permission_warning {
            ui::warn(message);
        }
        if report.damaged.is_empty() {
            if report.is_healthy() {
                ui::success(&i18n::all_accounts_decrypt());
            }
        } else {
            ui::error(&i18n::accounts_failed_to_decrypt(&i18n::account_count(
                report.damaged.len(),
            )));
            for name in &report.damaged {
                println!("    {}", ui::red(name));
            }
            ui::note(&i18n::restore_damaged_from_backup());
        }
        Ok(())
    }

    pub fn show_config(&self) -> Result<()> {
        println!(
            "{}",
            ui::heading(&format!("{}", self.config_path.display()))
        );
        let rows: Vec<Vec<String>> = self
            .config
            .entries()
            .into_iter()
            .map(|(k, v)| vec![k.to_string(), v])
            .collect();
        print!(
            "{}",
            ui::table(&[&i18n::column_setting(), &i18n::column_value()], &rows)
        );
        Ok(())
    }

    pub fn set_config(&mut self, key: &str, value: &str) -> Result<()> {
        self.config.set(key, value)?;
        self.config.save(&self.config_path)?;
        ui::success(&i18n::setting_saved(key, value));
        if key == "idle_lock_seconds" || key == "kdf_profile" {
            ui::note(&i18n::takes_effect_next_start());
        }
        Ok(())
    }
}

fn prompt_number(label: &str, default: u32) -> Result<u32> {
    let text = secrets::prompt_line(&format!("{label} [{default}]: "))?;
    if text.is_empty() {
        return Ok(default);
    }
    text.parse().with_context(|| i18n::not_a_number(&text))
}

fn format_name(entry: &OtpAuth) -> String {
    match &entry.issuer {
        Some(issuer) if entry.account.is_empty() => issuer.clone(),
        Some(issuer) => format!("{issuer} ({})", entry.account),
        None => entry.account.clone(),
    }
}

pub fn describe_params(params: &OtpParams) -> String {
    match params.kind {
        OtpKind::Totp { period } => format!(
            "TOTP {}d/{}s/{}",
            params.digits,
            period,
            params.algorithm.as_str()
        ),
        OtpKind::Hotp { counter } => format!(
            "HOTP {}d/{}/#{counter}",
            params.digits,
            params.algorithm.as_str()
        ),
    }
}

fn format_time(unix: u64) -> String {
    if unix == 0 {
        return i18n::none_placeholder();
    }
    // Enough for a "when did I set this up" glance without pulling in a date
    // library for a single format string.
    let days = unix / 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let seconds = unix % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        seconds / 3600,
        (seconds % 3600) / 60
    )
}

/// Howard Hinnant's days-to-calendar algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_described_compactly() {
        assert_eq!(describe_params(&OtpParams::default()), "TOTP 6d/30s/SHA1");
        assert_eq!(
            describe_params(&OtpParams {
                algorithm: otp::Algorithm::Sha256,
                digits: 8,
                kind: OtpKind::Hotp { counter: 7 },
            }),
            "HOTP 8d/SHA256/#7"
        );
    }

    #[test]
    fn timestamps_render_as_utc_dates() {
        assert_eq!(format_time(0), "-");
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(format_time(946_684_800), "2000-01-01 00:00 UTC");
    }
}
