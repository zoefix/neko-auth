//! HOTP (RFC 4226) and TOTP (RFC 6238).
//!
//! Hand-written rather than pulled from a crate. This is the one computation
//! the whole program exists to perform, it is about thirty lines on top of
//! `hmac`, and it is the last place where an unaudited dependency belongs.
//! Correctness is pinned by the official test vectors at the bottom of this
//! file.

pub mod migration;
pub mod uri;

use hmac::{Hmac, Mac};

use crate::i18n;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// The HMAC hash underlying the code.
///
/// SHA-1 is kept, and is the default, because essentially every real
/// `otpauth://` URI in the wild uses it. The SHA-1 collision attacks do not
/// apply to HMAC-SHA1, which relies on PRF properties rather than collision
/// resistance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Some(Algorithm::Sha1),
            "SHA256" => Some(Algorithm::Sha256),
            "SHA512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

/// Time-based, or counter-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp {
        period: u32,
    },
    /// `otpauth://hotp/` URIs are rare but real, and a counter that is not
    /// persisted after each use silently desynchronises from the server.
    Hotp {
        counter: u64,
    },
}

impl Default for OtpKind {
    fn default() -> Self {
        OtpKind::Totp { period: 30 }
    }
}

impl OtpKind {
    pub fn type_str(&self) -> &'static str {
        match self {
            OtpKind::Totp { .. } => "totp",
            OtpKind::Hotp { .. } => "hotp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtpParams {
    pub algorithm: Algorithm,
    pub digits: u32,
    pub kind: OtpKind,
}

impl Default for OtpParams {
    fn default() -> Self {
        OtpParams {
            algorithm: Algorithm::default(),
            digits: 6,
            kind: OtpKind::default(),
        }
    }
}

pub const MIN_DIGITS: u32 = 4;
pub const MAX_DIGITS: u32 = 10;
pub const MAX_PERIOD: u32 = 3600;

/// Display is hand-written rather than derived so the text can be translated;
/// the variants themselves stay plain data.
#[derive(Debug)]
pub enum OtpError {
    Digits(u32),
    Period(u32),
    EmptySecret,
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            OtpError::Digits(got) => i18n::err_digits_range(MIN_DIGITS, MAX_DIGITS, *got),
            OtpError::Period(got) => i18n::err_period_range(MAX_PERIOD, *got),
            OtpError::EmptySecret => i18n::err_empty_secret(),
        })
    }
}

impl std::error::Error for OtpError {}

impl OtpParams {
    pub fn validate(&self) -> Result<(), OtpError> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&self.digits) {
            return Err(OtpError::Digits(self.digits));
        }
        if let OtpKind::Totp { period } = self.kind {
            if period == 0 || period > MAX_PERIOD {
                return Err(OtpError::Period(period));
            }
        }
        Ok(())
    }
}

/// A generated one-time code, kept as digits so leading zeros survive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code(String);

impl Code {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `123 456` — grouped for reading off a screen and typing by hand.
    pub fn grouped(&self) -> String {
        let s = &self.0;
        let mid = s.len().div_ceil(2);
        format!("{} {}", &s[..mid], &s[mid..])
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC 4226 HOTP.
pub fn hotp(
    secret: &[u8],
    counter: u64,
    algorithm: Algorithm,
    digits: u32,
) -> Result<Code, OtpError> {
    if secret.is_empty() {
        return Err(OtpError::EmptySecret);
    }
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(OtpError::Digits(digits));
    }

    let mac = hmac_digest(algorithm, secret, &counter.to_be_bytes());

    // Dynamic truncation (RFC 4226 §5.3). The offset comes from the low nibble
    // of the *last* byte, which is byte 19 for SHA-1 but 31 or 63 for the
    // wider hashes; indexing a fixed 19 is a classic SHA-256/512 bug.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let binary = u64::from(mac[offset] & 0x7f) << 24
        | u64::from(mac[offset + 1]) << 16
        | u64::from(mac[offset + 2]) << 8
        | u64::from(mac[offset + 3]);

    let modulus = 10u64.pow(digits);
    Ok(Code(format!(
        "{:0width$}",
        binary % modulus,
        width = digits as usize
    )))
}

/// RFC 6238 TOTP. `unix_time` is seconds since the epoch; T0 is 0.
pub fn totp(
    secret: &[u8],
    unix_time: u64,
    period: u32,
    algorithm: Algorithm,
    digits: u32,
) -> Result<Code, OtpError> {
    if period == 0 || period > MAX_PERIOD {
        return Err(OtpError::Period(period));
    }
    hotp(secret, unix_time / u64::from(period), algorithm, digits)
}

/// Generates the code for `params` at `unix_time`.
pub fn generate(secret: &[u8], params: &OtpParams, unix_time: u64) -> Result<Code, OtpError> {
    match params.kind {
        OtpKind::Totp { period } => {
            totp(secret, unix_time, period, params.algorithm, params.digits)
        }
        OtpKind::Hotp { counter } => hotp(secret, counter, params.algorithm, params.digits),
    }
}

/// Seconds until the current time step ends.
pub fn seconds_remaining(unix_time: u64, period: u32) -> u32 {
    if period == 0 {
        return 0;
    }
    period - (unix_time % u64::from(period)) as u32
}

/// Seconds since the epoch, or 0 if the clock is set before 1970.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hmac_digest(algorithm: Algorithm, key: &[u8], msg: &[u8; 8]) -> Zeroizing<Vec<u8>> {
    macro_rules! run {
        ($hash:ty) => {{
            // `new_from_slice` only rejects lengths for fixed-key MACs; HMAC
            // accepts a key of any length, so this cannot fail.
            let mut mac = <Hmac<$hash>>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(msg);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }};
    }

    match algorithm {
        Algorithm::Sha1 => run!(Sha1),
        Algorithm::Sha256 => run!(Sha256),
        Algorithm::Sha512 => run!(Sha512),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D.
    #[test]
    fn rfc4226_hotp_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(secret, counter as u64, Algorithm::Sha1, 6).unwrap();
            assert_eq!(got.as_str(), *want, "counter {counter}");
        }
    }

    /// RFC 6238 Appendix B. Each algorithm uses a differently-sized seed;
    /// reusing the 20-byte SHA-1 seed for all three is the standard mistake
    /// and produces vectors that look plausible but are wrong.
    #[test]
    fn rfc6238_totp_vectors() {
        let sha1_seed = b"12345678901234567890".as_slice();
        let sha256_seed = b"12345678901234567890123456789012".as_slice();
        let sha512_seed =
            b"1234567890123456789012345678901234567890123456789012345678901234".as_slice();

        let cases: &[(u64, Algorithm, &str)] = &[
            (59, Algorithm::Sha1, "94287082"),
            (59, Algorithm::Sha256, "46119246"),
            (59, Algorithm::Sha512, "90693936"),
            (1111111109, Algorithm::Sha1, "07081804"),
            (1111111109, Algorithm::Sha256, "68084774"),
            (1111111109, Algorithm::Sha512, "25091201"),
            (1111111111, Algorithm::Sha1, "14050471"),
            (1111111111, Algorithm::Sha256, "67062674"),
            (1111111111, Algorithm::Sha512, "99943326"),
            (1234567890, Algorithm::Sha1, "89005924"),
            (1234567890, Algorithm::Sha256, "91819424"),
            (1234567890, Algorithm::Sha512, "93441116"),
            (2000000000, Algorithm::Sha1, "69279037"),
            (2000000000, Algorithm::Sha256, "90698825"),
            (2000000000, Algorithm::Sha512, "38618901"),
            (20000000000, Algorithm::Sha1, "65353130"),
            (20000000000, Algorithm::Sha256, "77737706"),
            (20000000000, Algorithm::Sha512, "47863826"),
        ];

        for (time, algorithm, want) in cases {
            let seed = match algorithm {
                Algorithm::Sha1 => sha1_seed,
                Algorithm::Sha256 => sha256_seed,
                Algorithm::Sha512 => sha512_seed,
            };
            let got = totp(seed, *time, 30, *algorithm, 8).unwrap();
            assert_eq!(got.as_str(), *want, "t={time} {:?}", algorithm);
        }
    }

    #[test]
    fn leading_zeros_are_preserved() {
        // "07081804" truncated to 6 digits is "081804"; dropping the leading
        // zero would produce a code the server rejects.
        let code = totp(b"12345678901234567890", 1111111109, 30, Algorithm::Sha1, 8).unwrap();
        assert_eq!(code.as_str(), "07081804");
        assert_eq!(code.as_str().len(), 8);
    }

    #[test]
    fn countdown_wraps_at_the_period_boundary() {
        assert_eq!(seconds_remaining(0, 30), 30);
        assert_eq!(seconds_remaining(1, 30), 29);
        assert_eq!(seconds_remaining(29, 30), 1);
        assert_eq!(seconds_remaining(30, 30), 30);
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        assert!(hotp(b"", 0, Algorithm::Sha1, 6).is_err());
        assert!(hotp(b"seed", 0, Algorithm::Sha1, 3).is_err());
        assert!(hotp(b"seed", 0, Algorithm::Sha1, 11).is_err());
        assert!(totp(b"seed", 0, 0, Algorithm::Sha1, 6).is_err());
    }

    #[test]
    fn grouping_splits_evenly() {
        assert_eq!(Code("123456".into()).grouped(), "123 456");
        assert_eq!(Code("12345678".into()).grouped(), "1234 5678");
    }
}
