//! The encrypted `ct_params` blob.
//!
//! OTP parameters, timestamps and notes all live inside one sealed blob rather
//! than in plaintext columns. Plaintext `created_at` and `updated_at` would be
//! a behavioural profile — when each second factor was enrolled and when it was
//! last touched — and a plaintext `algorithm = SHA512, digits = 8` fingerprints
//! the specific services in use.
//!
//! The encoding is hand-written and fixed-width rather than JSON: it is
//! deterministic, it keeps `serde` out of the path that handles secrets, and it
//! cannot grow an accidental `Serialize` on a struct that holds a seed.

use crate::i18n;
use crate::otp::{Algorithm, OtpKind, OtpParams};

const CODEC_VERSION: u8 = 1;

#[derive(Debug)]
pub enum RecordError {
    Truncated,
    Version(u8),
    BadEnum(BadField),
    BadUtf8,
}

/// Which field of a record failed to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadField {
    Algorithm,
    OtpType,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            RecordError::Truncated => i18n::err_record_truncated(),
            RecordError::Version(version) => i18n::err_record_version(*version),
            RecordError::BadEnum(field) => {
                let name = match field {
                    BadField::Algorithm => i18n::err_field_algorithm(),
                    BadField::OtpType => i18n::err_field_otp_type(),
                };
                i18n::err_record_enum(&name)
            }
            RecordError::BadUtf8 => i18n::err_record_utf8(),
        })
    }
}

impl std::error::Error for RecordError {}

/// Everything about an account except its name and its secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordParams {
    pub params: OtpParams,
    pub created_at: u64,
    pub updated_at: u64,
    pub notes: Option<String>,
}

impl RecordParams {
    pub fn encode(&self) -> Vec<u8> {
        let notes = self.notes.as_deref().unwrap_or("").as_bytes();
        let mut out = Vec::with_capacity(36 + notes.len());

        out.push(CODEC_VERSION);
        out.push(match self.params.algorithm {
            Algorithm::Sha1 => 0,
            Algorithm::Sha256 => 1,
            Algorithm::Sha512 => 2,
        });
        let (kind_code, period, counter) = match self.params.kind {
            OtpKind::Totp { period } => (0u8, period, 0u64),
            OtpKind::Hotp { counter } => (1u8, 0u32, counter),
        };
        out.push(kind_code);
        out.push(self.params.digits as u8);
        out.extend_from_slice(&period.to_le_bytes());
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&self.updated_at.to_le_bytes());
        out.extend_from_slice(&(notes.len() as u32).to_le_bytes());
        out.extend_from_slice(notes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut c = Cursor { buf: bytes, pos: 0 };

        let version = c.u8()?;
        if version != CODEC_VERSION {
            return Err(RecordError::Version(version));
        }

        let algorithm = match c.u8()? {
            0 => Algorithm::Sha1,
            1 => Algorithm::Sha256,
            2 => Algorithm::Sha512,
            _ => return Err(RecordError::BadEnum(BadField::Algorithm)),
        };
        let kind_code = c.u8()?;
        let digits = u32::from(c.u8()?);
        let period = c.u32()?;
        let counter = c.u64()?;
        let created_at = c.u64()?;
        let updated_at = c.u64()?;
        let notes_len = c.u32()? as usize;
        let notes_bytes = c.take(notes_len)?;

        let kind = match kind_code {
            0 => OtpKind::Totp { period },
            1 => OtpKind::Hotp { counter },
            _ => return Err(RecordError::BadEnum(BadField::OtpType)),
        };

        Ok(RecordParams {
            params: OtpParams {
                algorithm,
                digits,
                kind,
            },
            created_at,
            updated_at,
            notes: (!notes_bytes.is_empty())
                .then(|| String::from_utf8(notes_bytes.to_vec()))
                .transpose()
                .map_err(|_| RecordError::BadUtf8)?,
        })
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RecordError> {
        let end = self.pos.checked_add(n).ok_or(RecordError::Truncated)?;
        if end > self.buf.len() {
            return Err(RecordError::Truncated);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, RecordError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, RecordError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RecordError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: OtpKind, notes: Option<&str>) -> RecordParams {
        RecordParams {
            params: OtpParams {
                algorithm: Algorithm::Sha512,
                digits: 8,
                kind,
            },
            created_at: 1_700_000_000,
            updated_at: 1_800_000_000,
            notes: notes.map(str::to_string),
        }
    }

    #[test]
    fn round_trips_every_variant() {
        for record in [
            sample(OtpKind::Totp { period: 60 }, None),
            sample(
                OtpKind::Hotp { counter: 12345 },
                Some("recovery codes in the safe"),
            ),
            sample(OtpKind::Totp { period: 30 }, Some("多字节备注")),
        ] {
            assert_eq!(RecordParams::decode(&record.encode()).unwrap(), record);
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        // The blob is hashed into the vault MAC, so two encodings of the same
        // value must be byte-identical. This is exactly the property JSON does
        // not provide, and the reason it is not used here.
        let r = sample(OtpKind::Totp { period: 30 }, Some("note"));
        assert_eq!(r.encode(), r.encode());
    }

    #[test]
    fn truncated_or_corrupt_records_error_rather_than_panic() {
        let good = sample(OtpKind::Totp { period: 30 }, Some("x")).encode();
        for n in 0..good.len() {
            assert!(
                RecordParams::decode(&good[..n]).is_err(),
                "length {n} should not decode"
            );
        }
        let mut bad_version = good.clone();
        bad_version[0] = 99;
        assert!(matches!(
            RecordParams::decode(&bad_version),
            Err(RecordError::Version(99))
        ));

        let mut bad_algorithm = good.clone();
        bad_algorithm[1] = 42;
        assert!(matches!(
            RecordParams::decode(&bad_algorithm),
            Err(RecordError::BadEnum(_))
        ));

        // A notes length longer than the buffer must not be trusted.
        let mut huge = good.clone();
        let at = huge.len() - 1 - 4;
        huge[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            RecordParams::decode(&huge),
            Err(RecordError::Truncated)
        ));
    }
}
