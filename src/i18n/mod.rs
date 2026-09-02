//! Translations.
//!
//! Messages live in [`messages`] as one entry per string with all four
//! languages side by side, so a translation is reviewed in context rather than
//! by hunting through parallel files. The macro requires every language for
//! every message, which makes a missing translation a compile error rather
//! than a string that silently falls back to English.

mod messages;

use std::sync::atomic::{AtomicU8, Ordering};

pub use messages::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    English,
    /// 简体中文
    SimplifiedChinese,
    /// 繁體中文（台灣）
    TraditionalChinese,
    /// 日本語
    Japanese,
}

impl Language {
    pub const ALL: [Language; 4] = [
        Language::English,
        Language::SimplifiedChinese,
        Language::TraditionalChinese,
        Language::Japanese,
    ];

    /// The value written to the config file.
    pub fn code(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::SimplifiedChinese => "zh-Hans",
            Language::TraditionalChinese => "zh-Hant",
            Language::Japanese => "ja",
        }
    }

    /// The language's name in itself, which is how a language menu should read.
    pub fn endonym(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::SimplifiedChinese => "简体中文",
            Language::TraditionalChinese => "繁體中文",
            Language::Japanese => "日本語",
        }
    }

    /// Accepts the config values, the common IETF tags, and POSIX locale names
    /// such as `zh_TW.UTF-8`, so that a value copied from `$LANG` works.
    pub fn parse(value: &str) -> Option<Language> {
        let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
        let tag = normalized.split('.').next().unwrap_or("");

        if tag.starts_with("ja") {
            return Some(Language::Japanese);
        }
        if tag.starts_with("en") {
            return Some(Language::English);
        }
        if tag.starts_with("zh") {
            // Script beats region, then the regions that use traditional
            // characters. Everything else Chinese defaults to simplified.
            let traditional = tag.contains("hant")
                || tag.contains("-tw")
                || tag.contains("-hk")
                || tag.contains("-mo");
            return Some(if traditional {
                Language::TraditionalChinese
            } else {
                Language::SimplifiedChinese
            });
        }
        None
    }

    /// Reads the POSIX locale environment, in the order those variables
    /// override one another.
    pub fn from_environment() -> Option<Language> {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .filter(|value| !value.is_empty() && value != "C" && value != "POSIX")
            .find_map(|value| Language::parse(&value))
    }
}

/// The active language, as an index into [`Language::ALL`].
///
/// A process-wide value rather than a parameter threaded through every call:
/// it is set once during startup, before any output, and never changes
/// afterwards. Message functions also exist as methods on [`Language`], so
/// tests can exercise a translation without touching this.
static ACTIVE: AtomicU8 = AtomicU8::new(0);

pub fn current() -> Language {
    Language::ALL[usize::from(ACTIVE.load(Ordering::Relaxed)) % Language::ALL.len()]
}

pub fn set_current(language: Language) {
    let index = Language::ALL
        .iter()
        .position(|candidate| *candidate == language)
        .unwrap_or(0);
    ACTIVE.store(index as u8, Ordering::Relaxed);
}

/// Resolves a configured setting into a language.
///
/// `auto` follows the locale environment, which is what someone who never
/// opens the config file will get.
pub fn resolve(setting: &str) -> Language {
    if setting.trim().eq_ignore_ascii_case("auto") {
        return Language::from_environment().unwrap_or_default();
    }
    Language::parse(setting).unwrap_or_default()
}

/// Declares one message per entry, in every language.
///
/// ```ignore
/// fn added_account(name: &str) =>
///     en: "added {name}",
///     zh_hans: "已添加 {name}",
///     zh_hant: "已新增 {name}",
///     ja: "{name} を追加しました";
/// ```
///
/// Each arm generates a method on [`Language`] and a free function that reads
/// the active language, so call sites stay short while tests stay explicit.
#[macro_export]
macro_rules! messages {
    ($(
        $(#[$meta:meta])*
        fn $name:ident $(( $($arg:ident : $ty:ty),* $(,)? ))? =>
            en: $en:literal,
            zh_hans: $hans:literal,
            zh_hant: $hant:literal,
            ja: $ja:literal;
    )*) => {
        impl $crate::i18n::Language {
            $(
                $(#[$meta])*
                pub fn $name(self $(, $($arg: $ty),*)?) -> String {
                    match self {
                        $crate::i18n::Language::English => format!($en),
                        $crate::i18n::Language::SimplifiedChinese => format!($hans),
                        $crate::i18n::Language::TraditionalChinese => format!($hant),
                        $crate::i18n::Language::Japanese => format!($ja),
                    }
                }
            )*
        }

        $(
            $(#[$meta])*
            #[inline]
            pub fn $name($($($arg: $ty),*)?) -> String {
                $crate::i18n::current().$name($($($arg),*)?)
            }
        )*
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_names_map_to_languages() {
        assert_eq!(Language::parse("en"), Some(Language::English));
        assert_eq!(Language::parse("en_US.UTF-8"), Some(Language::English));
        assert_eq!(Language::parse("ja"), Some(Language::Japanese));
        assert_eq!(Language::parse("ja_JP.UTF-8"), Some(Language::Japanese));
        assert_eq!(
            Language::parse("zh-Hans"),
            Some(Language::SimplifiedChinese)
        );
        assert_eq!(
            Language::parse("zh_CN.UTF-8"),
            Some(Language::SimplifiedChinese)
        );
        assert_eq!(Language::parse("zh"), Some(Language::SimplifiedChinese));
        assert_eq!(Language::parse("fr_FR.UTF-8"), None);
    }

    #[test]
    fn the_traditional_regions_are_distinguished_from_the_mainland() {
        // Getting this wrong shows a Taiwanese user simplified characters,
        // which is the single most visible way to get Chinese localisation
        // wrong.
        for tag in ["zh-Hant", "zh_TW.UTF-8", "zh-HK", "zh_MO", "zh-Hant-TW"] {
            assert_eq!(
                Language::parse(tag),
                Some(Language::TraditionalChinese),
                "{tag} should be traditional"
            );
        }
        for tag in ["zh-Hans", "zh_CN", "zh-SG", "zh"] {
            assert_eq!(
                Language::parse(tag),
                Some(Language::SimplifiedChinese),
                "{tag} should be simplified"
            );
        }
    }

    #[test]
    fn an_unknown_setting_falls_back_to_english_rather_than_failing() {
        assert_eq!(resolve("klingon"), Language::English);
        assert_eq!(resolve("zh-Hant"), Language::TraditionalChinese);
    }

    #[test]
    fn codes_round_trip_through_parsing() {
        for language in Language::ALL {
            assert_eq!(Language::parse(language.code()), Some(language));
        }
    }

    #[test]
    fn every_language_names_itself_in_its_own_script() {
        assert_eq!(Language::SimplifiedChinese.endonym(), "简体中文");
        assert_eq!(Language::TraditionalChinese.endonym(), "繁體中文");
        assert_eq!(Language::Japanese.endonym(), "日本語");
    }

    #[test]
    fn the_default_is_english_and_indexing_is_consistent() {
        // Deliberately does not call set_current: the language is process-wide,
        // and flipping it here would be visible to every other test.
        assert_eq!(current(), Language::English);
        for (index, language) in Language::ALL.iter().enumerate() {
            assert_eq!(Language::ALL[index], *language);
        }
    }
}
