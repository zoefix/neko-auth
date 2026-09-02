//! User settings, read from `config.toml`.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::i18n::{self, Language};

/// Where `update` looks for releases.
///
/// Overridable at build time (`NEKO_AUTH_REPO=owner/repo cargo build`) and at
/// run time through the config file, so a fork does not have to patch source.
pub const DEFAULT_UPDATE_REPO: &str = match option_env!("NEKO_AUTH_REPO") {
    Some(repo) => repo,
    None => "zoefix/neko-auth",
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Seconds of inactivity before the keys are erased from memory. 0 disables.
    pub idle_lock_seconds: u64,
    /// Seconds before a copied code is wiped from the clipboard. 0 disables.
    pub clipboard_clear_seconds: u64,
    /// `interactive`, `moderate`, or `paranoid`.
    pub kdf_profile: String,
    /// `owner/repo` to check for updates. Only ever contacted by `update`.
    pub update_repo: String,
    /// Group codes as `123 456` when printing.
    pub group_digits: bool,
    /// `auto`, `en`, `zh-Hans`, `zh-Hant`, or `ja`.
    pub language: String,
    /// Hide the email as it is typed, the way the password always is.
    ///
    /// Off by default: the address is never written to the vault either way,
    /// so hiding it guards only against someone reading your screen, and it
    /// makes a typo impossible to notice.
    pub hide_email: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            idle_lock_seconds: 300,
            clipboard_clear_seconds: 15,
            kdf_profile: "moderate".to_string(),
            update_repo: DEFAULT_UPDATE_REPO.to_string(),
            group_digits: true,
            // Follows the locale environment, which is what someone who never
            // opens this file will get.
            language: "auto".to_string(),
            hide_email: false,
        }
    }
}

impl Config {
    /// Loads the config, falling back to defaults when the file is absent.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| crate::i18n::err_cannot_read(&path.display().to_string()))?;
        toml::from_str(&text).with_context(|| i18n::err_config_invalid(&path.display().to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            crate::paths::ensure_private_dir(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)
            .with_context(|| i18n::err_cannot_write(&path.display().to_string()))?;
        crate::paths::restrict_file(path)?;
        Ok(())
    }

    pub fn idle_timeout(&self) -> Option<Duration> {
        (self.idle_lock_seconds > 0).then(|| Duration::from_secs(self.idle_lock_seconds))
    }

    pub fn clipboard_timeout(&self) -> Option<Duration> {
        (self.clipboard_clear_seconds > 0)
            .then(|| Duration::from_secs(self.clipboard_clear_seconds))
    }

    pub fn language(&self) -> Language {
        i18n::resolve(&self.language)
    }

    pub fn kdf(&self) -> Result<crate::crypto::KdfParams> {
        crate::crypto::KdfParams::by_name(&self.kdf_profile).with_context(|| {
            format!(
                "unknown kdf_profile `{}` (expected interactive, moderate, or paranoid)",
                self.kdf_profile
            )
        })
    }

    /// Applies a `key = value` edit from the `config` command.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "idle_lock_seconds" => self.idle_lock_seconds = value.parse()?,
            "clipboard_clear_seconds" => self.clipboard_clear_seconds = value.parse()?,
            "kdf_profile" => {
                crate::crypto::KdfParams::by_name(value)
                    .with_context(|| i18n::unknown_kdf_profile(value))?;
                self.kdf_profile = value.to_string();
            }
            "language" => {
                let language = parse_language_setting(value)?;
                self.language = value.trim().to_string();
                // Applied immediately, so the confirmation that follows is
                // already in the language just chosen.
                i18n::set_current(language);
            }
            "update_repo" => self.update_repo = value.to_string(),
            "group_digits" => self.group_digits = value.parse()?,
            "hide_email" => self.hide_email = value.parse()?,
            other => anyhow::bail!("{}", i18n::unknown_setting(other)),
        }
        Ok(())
    }

    pub fn entries(&self) -> Vec<(&'static str, String)> {
        vec![
            ("idle_lock_seconds", self.idle_lock_seconds.to_string()),
            (
                "clipboard_clear_seconds",
                self.clipboard_clear_seconds.to_string(),
            ),
            ("kdf_profile", self.kdf_profile.clone()),
            ("update_repo", self.update_repo.clone()),
            ("group_digits", self.group_digits.to_string()),
            ("language", self.language.clone()),
            ("hide_email", self.hide_email.to_string()),
        ]
    }
}

/// Accepts `auto` alongside the language tags.
pub fn parse_language_setting(value: &str) -> Result<Language> {
    if value.trim().eq_ignore_ascii_case("auto") {
        return Ok(Language::from_environment().unwrap_or_default());
    }
    Language::parse(value).with_context(|| {
        let known = Language::ALL
            .iter()
            .map(|l| l.code())
            .collect::<Vec<_>>()
            .join(", ");
        i18n::unknown_language(value, &known)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = Config::default();
        original.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.idle_lock_seconds, original.idle_lock_seconds);
        assert_eq!(loaded.kdf_profile, original.kdf_profile);
    }

    #[test]
    fn a_missing_file_yields_defaults() {
        let cfg = Config::load(Path::new("/nonexistent/neko/config.toml")).unwrap();
        assert_eq!(cfg.idle_lock_seconds, 300);
    }

    #[test]
    fn a_typo_in_a_setting_name_is_reported_rather_than_ignored() {
        // deny_unknown_fields: silently ignoring `idle_lock_second` would leave
        // the user believing they had changed a security setting.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "idle_lock_second = 60\n").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn zero_disables_the_timeouts() {
        let mut cfg = Config::default();
        cfg.set("idle_lock_seconds", "0").unwrap();
        cfg.set("clipboard_clear_seconds", "0").unwrap();
        assert!(cfg.idle_timeout().is_none());
        assert!(cfg.clipboard_timeout().is_none());
    }

    #[test]
    fn invalid_settings_are_refused() {
        let mut cfg = Config::default();
        assert!(cfg.set("kdf_profile", "ludicrous").is_err());
        assert!(cfg.set("idle_lock_seconds", "soon").is_err());
        assert!(cfg.set("nonexistent", "1").is_err());
        assert_eq!(cfg.kdf_profile, "moderate");
    }

    #[test]
    fn the_language_setting_accepts_tags_and_auto() {
        assert_eq!(
            parse_language_setting("zh-Hant").unwrap(),
            Language::TraditionalChinese
        );
        assert_eq!(parse_language_setting("ja").unwrap(), Language::Japanese);
        // `auto` resolves against the environment and must never fail.
        assert!(parse_language_setting("auto").is_ok());
        assert!(parse_language_setting("klingon").is_err());
    }

    #[test]
    fn the_default_config_follows_the_locale() {
        assert_eq!(Config::default().language, "auto");
    }
}
