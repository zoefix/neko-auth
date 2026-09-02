//! `otpauth://` URI parsing and generation (Key Uri Format).
//!
//! Shape: `otpauth://TYPE/LABEL?PARAMETERS`, where `LABEL` is
//! `[issuer:]account` and everything is percent-encoded.
//!
//! Percent coding is done here rather than pulled from a crate, so that the
//! exact set of characters we escape on output is visible and testable.

use data_encoding::BASE32_NOPAD;

use crate::i18n;
use zeroize::Zeroizing;

use super::{Algorithm, OtpKind, OtpParams, MAX_DIGITS, MAX_PERIOD, MIN_DIGITS};

#[derive(Debug)]
pub enum UriError {
    NotOtpauth,
    UnknownType(String),
    MissingSecret,
    BadSecret,
    UnknownAlgorithm(String),
    NotANumber { param: &'static str, value: String },
    Digits(u32),
    Period(u32),
    MissingCounter,
    BadEncoding,
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            UriError::NotOtpauth => i18n::err_not_otpauth(),
            UriError::UnknownType(value) => i18n::err_unknown_otp_type(value),
            UriError::MissingSecret => i18n::err_no_secret_param(),
            UriError::BadSecret => i18n::err_bad_base32(),
            UriError::UnknownAlgorithm(name) => i18n::unknown_algorithm(name),
            UriError::NotANumber { param, value } => i18n::err_param_not_number(param, value),
            UriError::Digits(got) => i18n::err_digits_range(MIN_DIGITS, MAX_DIGITS, *got),
            UriError::Period(got) => i18n::err_period_range(MAX_PERIOD, *got),
            UriError::MissingCounter => i18n::err_hotp_needs_counter(),
            UriError::BadEncoding => i18n::err_bad_encoding(),
        })
    }
}

impl std::error::Error for UriError {}

/// One account, as described by an `otpauth://` URI.
pub struct OtpAuth {
    pub issuer: Option<String>,
    pub account: String,
    pub secret: Zeroizing<Vec<u8>>,
    pub params: OtpParams,
}

// Never derived: a derived Debug prints the shared secret.
impl std::fmt::Debug for OtpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpAuth")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .field("params", &self.params)
            .finish()
    }
}

impl OtpAuth {
    pub fn parse(uri: &str) -> Result<Self, UriError> {
        let uri = uri.trim();
        let rest = strip_scheme(uri).ok_or(UriError::NotOtpauth)?;

        // TYPE is everything up to the first '/'; LABEL runs to the query.
        let (kind_str, after_type) = match rest.split_once('/') {
            Some((k, r)) => (k, r),
            None => (rest, ""),
        };
        let (label_raw, query) = match after_type.split_once('?') {
            Some((l, q)) => (l, q),
            None => (after_type, ""),
        };

        let is_hotp = match kind_str.to_ascii_lowercase().as_str() {
            "totp" => false,
            "hotp" => true,
            other => return Err(UriError::UnknownType(other.to_string())),
        };

        let (label_issuer, account) = split_label(label_raw)?;

        let mut secret_b32: Option<String> = None;
        let mut query_issuer: Option<String> = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits: u32 = 6;
        let mut period: u32 = 30;
        let mut counter: Option<u64> = None;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value)?;
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret_b32 = Some(value),
                "issuer" => {
                    if !value.is_empty() {
                        query_issuer = Some(value)
                    }
                }
                "algorithm" => {
                    algorithm = Algorithm::parse(&value).ok_or(UriError::UnknownAlgorithm(value))?
                }
                "digits" => {
                    digits = value.parse().map_err(|_| UriError::NotANumber {
                        param: "digits",
                        value,
                    })?
                }
                "period" => {
                    period = value.parse().map_err(|_| UriError::NotANumber {
                        param: "period",
                        value,
                    })?
                }
                "counter" => {
                    counter = Some(value.parse().map_err(|_| UriError::NotANumber {
                        param: "counter",
                        value,
                    })?)
                }
                // Unknown parameters are ignored rather than rejected: issuers
                // add their own, and refusing an otherwise-valid account over
                // one is worse than dropping it.
                _ => {}
            }
        }

        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(UriError::Digits(digits));
        }
        if !is_hotp && (period == 0 || period > MAX_PERIOD) {
            return Err(UriError::Period(period));
        }

        let secret = decode_base32(&secret_b32.ok_or(UriError::MissingSecret)?)?;

        let kind = if is_hotp {
            OtpKind::Hotp {
                counter: counter.ok_or(UriError::MissingCounter)?,
            }
        } else {
            OtpKind::Totp { period }
        };

        Ok(OtpAuth {
            // The issuer= parameter wins over the label prefix. They disagree
            // in the wild, and the Key Uri Format designates the parameter as
            // authoritative.
            issuer: query_issuer.or(label_issuer),
            account,
            secret: Zeroizing::new(secret),
            params: OtpParams {
                algorithm,
                digits,
                kind,
            },
        })
    }

    /// Renders back to an `otpauth://` URI.
    ///
    /// The result contains the shared secret, so it is returned in a buffer
    /// that erases itself.
    pub fn to_uri(&self) -> Zeroizing<String> {
        let mut s = String::with_capacity(128);
        s.push_str("otpauth://");
        s.push_str(self.params.kind.type_str());
        s.push('/');

        if let Some(issuer) = &self.issuer {
            s.push_str(&percent_encode(issuer));
            // A literal colon, while any colon *inside* the issuer or account
            // is escaped to %3A. That asymmetry is what makes the separator
            // unambiguous on the way back in.
            s.push(':');
        }
        s.push_str(&percent_encode(&self.account));

        s.push_str("?secret=");
        s.push_str(&BASE32_NOPAD.encode(&self.secret));

        if let Some(issuer) = &self.issuer {
            s.push_str("&issuer=");
            s.push_str(&percent_encode(issuer));
        }
        s.push_str("&algorithm=");
        s.push_str(self.params.algorithm.as_str());
        s.push_str("&digits=");
        s.push_str(&self.params.digits.to_string());
        match self.params.kind {
            OtpKind::Totp { period } => {
                s.push_str("&period=");
                s.push_str(&period.to_string());
            }
            OtpKind::Hotp { counter } => {
                s.push_str("&counter=");
                s.push_str(&counter.to_string());
            }
        }
        Zeroizing::new(s)
    }
}

fn strip_scheme(uri: &str) -> Option<&str> {
    const SCHEME: &str = "otpauth://";
    if uri.len() >= SCHEME.len() && uri[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        Some(&uri[SCHEME.len()..])
    } else {
        None
    }
}

/// Splits a still-encoded label into `(issuer, account)`.
///
/// Splitting must happen *before* percent-decoding. An issuer such as
/// `Corp%3A%20EU` decodes to `Corp: EU`, and splitting the decoded form would
/// cut the name in half and move its tail into the account.
///
/// The Key Uri Format allows the separator to be written either literally or
/// as `%3A`. A literal colon takes precedence, because that is what we emit
/// while escaping every colon inside a name; only when there is no literal
/// colon do we fall back to `%3A`, which is what some exporters produce.
fn split_label(raw: &str) -> Result<(Option<String>, String), UriError> {
    let cut = raw.find(':').map(|i| (i, 1)).or_else(|| {
        raw.char_indices().find_map(|(i, _)| {
            let end = i + 3;
            (raw.len() >= end && raw[i..end].eq_ignore_ascii_case("%3A")).then_some((i, 3))
        })
    });

    match cut {
        Some((at, sep_len)) if at > 0 => {
            let issuer = percent_decode(&raw[..at])?;
            let account = percent_decode(&raw[at + sep_len..])?;
            Ok((
                Some(issuer.trim().to_string()),
                account.trim_start().to_string(),
            ))
        }
        // A leading separator means an empty issuer; treat the whole thing as
        // the account name rather than inventing an empty issuer.
        _ => Ok((None, percent_decode(raw)?.trim().to_string())),
    }
}

/// Base32 as it actually appears in the wild: unpadded or padded, upper or
/// lower case, and broken into space- or dash-separated groups for readability.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, UriError> {
    let normalized: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err(UriError::BadSecret);
    }
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| UriError::BadSecret)
}

pub(super) fn percent_decode(s: &str) -> Result<String, UriError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_value(bytes[i + 1]);
            let lo = hex_value(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| UriError::BadEncoding)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Escapes everything outside the RFC 3986 unreserved set. Deliberately
/// conservative: escaping too much is always safe, escaping too little is not.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_google_uri() {
        let a = OtpAuth::parse(
            "otpauth://totp/GitHub:zoe%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .unwrap();
        assert_eq!(a.issuer.as_deref(), Some("GitHub"));
        assert_eq!(a.account, "zoe@example.com");
        assert_eq!(a.params.digits, 6);
        assert_eq!(a.params.kind, OtpKind::Totp { period: 30 });
        assert_eq!(a.params.algorithm, Algorithm::Sha1);
    }

    #[test]
    fn the_issuer_parameter_overrides_the_label_prefix() {
        // These disagree in real exports; the parameter is authoritative.
        let a = OtpAuth::parse("otpauth://totp/OldName:me?secret=JBSWY3DPEHPK3PXP&issuer=RealName")
            .unwrap();
        assert_eq!(a.issuer.as_deref(), Some("RealName"));
        assert_eq!(a.account, "me");
    }

    #[test]
    fn label_prefix_is_used_when_no_parameter_is_present() {
        let a = OtpAuth::parse("otpauth://totp/ACME%20Co:john?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(a.account, "john");
    }

    #[test]
    fn space_after_the_label_separator_is_dropped() {
        let a = OtpAuth::parse("otpauth://totp/ACME:%20john?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.account, "john");
    }

    #[test]
    fn honours_non_default_parameters() {
        let a = OtpAuth::parse(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(a.params.algorithm, Algorithm::Sha256);
        assert_eq!(a.params.digits, 8);
        assert_eq!(a.params.kind, OtpKind::Totp { period: 60 });
    }

    #[test]
    fn hotp_requires_a_counter() {
        assert!(OtpAuth::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        let a = OtpAuth::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=7").unwrap();
        assert_eq!(a.params.kind, OtpKind::Hotp { counter: 7 });
    }

    #[test]
    fn scheme_and_type_are_case_insensitive() {
        assert!(OtpAuth::parse("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP").is_ok());
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(OtpAuth::parse("https://example.com").is_err());
        assert!(OtpAuth::parse("otpauth://totp/x").is_err()); // no secret
        assert!(OtpAuth::parse("otpauth://xotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(OtpAuth::parse("otpauth://totp/x?secret=1111111").is_err()); // 1,8 not base32
        assert!(OtpAuth::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99").is_err());
        assert!(OtpAuth::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
    }

    #[test]
    fn unknown_parameters_are_ignored() {
        // Issuers add their own; refusing the account over one would be worse.
        let a = OtpAuth::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&image=https%3A%2F%2Fa.b")
            .unwrap();
        assert_eq!(a.account, "x");
    }

    #[test]
    fn base32_is_accepted_in_the_shapes_users_actually_paste() {
        let canonical = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decode_base32("jbswy3dpehpk3pxp").unwrap(), canonical);
        assert_eq!(decode_base32("JBSW Y3DP EHPK 3PXP").unwrap(), canonical);
        assert_eq!(decode_base32("JBSW-Y3DP-EHPK-3PXP").unwrap(), canonical);
        assert_eq!(decode_base32("JBSWY3DPEHPK3PXP====").unwrap(), canonical);
        assert_eq!(canonical, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn round_trips_through_generation() {
        let original = "otpauth://totp/GitHub:zoe%40example.com?secret=JBSWY3DPEHPK3PXP\
                        &issuer=GitHub&algorithm=SHA256&digits=8&period=60";
        let a = OtpAuth::parse(original).unwrap();
        let b = OtpAuth::parse(&a.to_uri()).unwrap();

        assert_eq!(a.issuer, b.issuer);
        assert_eq!(a.account, b.account);
        assert_eq!(a.secret.to_vec(), b.secret.to_vec());
        assert_eq!(a.params, b.params);
    }

    #[test]
    fn round_trips_names_containing_separators() {
        // A colon or a slash inside an account name must survive encoding, or
        // the reparse silently splits the label in the wrong place.
        let a = OtpAuth {
            issuer: Some("Corp: EU/West".into()),
            account: "a:b/c?d&e".into(),
            secret: Zeroizing::new(b"secretbytes".to_vec()),
            params: OtpParams::default(),
        };
        let b = OtpAuth::parse(&a.to_uri()).unwrap();
        assert_eq!(b.issuer.as_deref(), Some("Corp: EU/West"));
        assert_eq!(b.account, "a:b/c?d&e");
    }
}
