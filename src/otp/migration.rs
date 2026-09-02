//! Google Authenticator's "export accounts" payload.
//!
//! The exporter encodes accounts as `otpauth-migration://offline?data=<base64>`
//! where the payload is this protobuf message:
//!
//! ```text
//! message MigrationPayload {
//!   message OtpParameters {
//!     bytes  secret    = 1;   // raw bytes, NOT base32
//!     string name      = 2;
//!     string issuer    = 3;
//!     enum   algorithm = 4;   // 1=SHA1 2=SHA256 3=SHA512 4=MD5
//!     enum   digits    = 5;   // 1=six 2=eight
//!     enum   type      = 6;   // 1=HOTP 2=TOTP
//!     int64  counter   = 7;
//!   }
//!   repeated OtpParameters otp_parameters = 1;
//!   int32 version    = 2;
//!   int32 batch_size = 3;
//!   int32 batch_index = 4;
//!   int32 batch_id   = 5;
//! }
//! ```
//!
//! The schema is fixed and tiny, so the wire format is decoded by hand here
//! rather than through `prost`, which would put `protoc` in the build path and
//! undercut the "clone and `cargo build` anywhere" goal.
//!
//! With more than a handful of accounts, Google splits the export across
//! several QR codes. Partial imports are the main hazard: an importer that
//! silently accepts one code out of three leaves the user believing they have
//! migrated when most of their accounts are missing.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::uri::OtpAuth;
use super::{Algorithm, OtpKind, OtpParams};
use crate::i18n;

#[derive(Debug)]
pub enum MigrationError {
    NotMigration,
    MissingData,
    BadBase64,
    Malformed,
    Md5 { name: String },
    EmptySecret { name: String },
    UnknownAlgorithm { code: u64, name: String },
    UnknownDigits { code: u64, name: String },
    MixedBatches,
    IncompleteBatch { missing: Vec<i32>, total: i32 },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            MigrationError::NotMigration => i18n::err_not_migration(),
            MigrationError::MissingData => i18n::err_no_data_param(),
            MigrationError::BadBase64 => i18n::err_bad_base64(),
            MigrationError::Malformed => i18n::err_migration_malformed(),
            MigrationError::Md5 { name } => i18n::err_md5(name),
            MigrationError::EmptySecret { name } => i18n::err_account_empty_secret(name),
            MigrationError::UnknownAlgorithm { code, name } => {
                i18n::err_unknown_algorithm_code(*code, name)
            }
            MigrationError::UnknownDigits { code, name } => {
                i18n::err_unknown_digits_code(*code, name)
            }
            MigrationError::MixedBatches => i18n::err_mixed_batches(),
            // The list of missing parts is joined with each language's own
            // conjunction, so this lives in the i18n layer.
            MigrationError::IncompleteBatch { missing, total } => {
                i18n::incomplete_batch(missing, *total)
            }
        })
    }
}

impl std::error::Error for MigrationError {}

/// One decoded QR code from an export.
pub struct MigrationPayload {
    pub accounts: Vec<OtpAuth>,
    pub batch_size: i32,
    pub batch_index: i32,
    pub batch_id: i32,
}

impl std::fmt::Debug for MigrationPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationPayload")
            .field("accounts", &self.accounts.len())
            .field("batch_size", &self.batch_size)
            .field("batch_index", &self.batch_index)
            .field("batch_id", &self.batch_id)
            .finish()
    }
}

/// Parses one `otpauth-migration://` URI.
pub fn parse(uri: &str) -> Result<MigrationPayload, MigrationError> {
    let uri = uri.trim();
    const SCHEME: &str = "otpauth-migration://";
    if uri.len() < SCHEME.len() || !uri[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        return Err(MigrationError::NotMigration);
    }

    let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut data: Option<String> = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.eq_ignore_ascii_case("data") {
            data = Some(super::uri::percent_decode(value).map_err(|_| MigrationError::BadBase64)?);
        }
    }

    decode_payload(&decode_base64(&data.ok_or(MigrationError::MissingData)?)?)
}

/// Accepts the base64 shapes that survive a trip through a QR code and a
/// clipboard: standard or URL-safe alphabet, padded or not.
fn decode_base64(input: &str) -> Result<Vec<u8>, MigrationError> {
    use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let trimmed = cleaned.trim_end_matches('=');
    for codec in [&BASE64, &BASE64URL] {
        if let Ok(bytes) = codec.decode(cleaned.as_bytes()) {
            return Ok(bytes);
        }
    }
    for codec in [&BASE64_NOPAD, &BASE64URL_NOPAD] {
        if let Ok(bytes) = codec.decode(trimmed.as_bytes()) {
            return Ok(bytes);
        }
    }
    Err(MigrationError::BadBase64)
}

fn decode_payload(bytes: &[u8]) -> Result<MigrationPayload, MigrationError> {
    let mut accounts = Vec::new();
    let mut batch_size = 1i32;
    let mut batch_index = 0i32;
    let mut batch_id = 0i32;

    let mut r = Reader::new(bytes);
    while let Some((field, wire)) = r.tag()? {
        match (field, wire) {
            (1, WIRE_LEN) => accounts.push(decode_account(r.bytes()?)?),
            (3, WIRE_VARINT) => batch_size = r.varint()? as i32,
            (4, WIRE_VARINT) => batch_index = r.varint()? as i32,
            (5, WIRE_VARINT) => batch_id = r.varint()? as i32,
            // Field 2 is `version`, which we do not act on. Unknown fields are
            // skipped so a newer exporter does not break the import.
            _ => r.skip(wire)?,
        }
    }

    Ok(MigrationPayload {
        accounts,
        batch_size: batch_size.max(1),
        batch_index,
        batch_id,
    })
}

fn decode_account(bytes: &[u8]) -> Result<OtpAuth, MigrationError> {
    let mut secret: Vec<u8> = Vec::new();
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm_code = 0u64;
    let mut digits_code = 0u64;
    let mut type_code = 0u64;
    let mut counter = 0u64;

    let mut r = Reader::new(bytes);
    while let Some((field, wire)) = r.tag()? {
        match (field, wire) {
            (1, WIRE_LEN) => secret = r.bytes()?.to_vec(),
            (2, WIRE_LEN) => name = r.string()?,
            (3, WIRE_LEN) => issuer = r.string()?,
            (4, WIRE_VARINT) => algorithm_code = r.varint()?,
            (5, WIRE_VARINT) => digits_code = r.varint()?,
            (6, WIRE_VARINT) => type_code = r.varint()?,
            (7, WIRE_VARINT) => counter = r.varint()?,
            _ => r.skip(wire)?,
        }
    }

    let display = if name.is_empty() {
        "<unnamed>".to_string()
    } else {
        name.clone()
    };

    if secret.is_empty() {
        return Err(MigrationError::EmptySecret { name: display });
    }

    // Protobuf omits fields that equal their zero value, so an absent
    // algorithm or digit count means "unspecified" and takes the Key Uri
    // Format default rather than being an error.
    let algorithm = match algorithm_code {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        4 => return Err(MigrationError::Md5 { name: display }),
        code => {
            return Err(MigrationError::UnknownAlgorithm {
                code,
                name: display,
            })
        }
    };

    let digits = match digits_code {
        0 | 1 => 6,
        2 => 8,
        code => {
            return Err(MigrationError::UnknownDigits {
                code,
                name: display,
            })
        }
    };

    // 1 = HOTP, 2 = TOTP. An unspecified type is treated as TOTP: it is what
    // the overwhelming majority of entries are, and a wrong guess is visible
    // immediately when the code is compared against the phone.
    let kind = if type_code == 1 {
        OtpKind::Hotp { counter }
    } else {
        OtpKind::Totp { period: 30 }
    };

    Ok(OtpAuth {
        issuer: (!issuer.is_empty()).then_some(issuer),
        account: name,
        // The `secret` field carries raw key bytes, not base32 text. Treating
        // it as a base32 string is the classic mistake here and yields codes
        // that are wrong in a way that looks like a clock-skew problem.
        secret: Zeroizing::new(secret),
        params: OtpParams {
            algorithm,
            digits,
            kind,
        },
    })
}

/// Collects the QR codes of one export and refuses to hand back a partial set.
#[derive(Default)]
pub struct BatchCollector {
    batch_id: Option<i32>,
    batch_size: i32,
    parts: BTreeMap<i32, Vec<OtpAuth>>,
}

impl BatchCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, payload: MigrationPayload) -> Result<(), MigrationError> {
        match self.batch_id {
            // Mixing two exports would produce a plausible-looking but
            // arbitrary subset, so reject rather than merge.
            Some(id) if id != payload.batch_id => return Err(MigrationError::MixedBatches),
            Some(_) => {}
            None => {
                self.batch_id = Some(payload.batch_id);
                self.batch_size = payload.batch_size;
            }
        }
        self.parts.insert(payload.batch_index, payload.accounts);
        Ok(())
    }

    /// Which 1-based part numbers have not been scanned yet.
    pub fn missing(&self) -> Vec<i32> {
        (0..self.batch_size)
            .filter(|i| !self.parts.contains_key(i))
            .map(|i| i + 1)
            .collect()
    }

    pub fn total_parts(&self) -> i32 {
        self.batch_size
    }

    pub fn is_complete(&self) -> bool {
        self.batch_id.is_some() && self.missing().is_empty()
    }

    /// Returns the accounts, or reports exactly which parts are still needed.
    pub fn finish(self) -> Result<Vec<OtpAuth>, MigrationError> {
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(MigrationError::IncompleteBatch {
                missing,
                total: self.batch_size,
            });
        }
        Ok(self.parts.into_values().flatten().collect())
    }
}

// ---------------------------------------------------------------------------
// Minimal protobuf wire-format reader
// ---------------------------------------------------------------------------

const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_I32: u8 = 5;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Returns `(field_number, wire_type)`, or `None` at the end of the buffer.
    fn tag(&mut self) -> Result<Option<(u32, u8)>, MigrationError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return Err(MigrationError::Malformed);
        }
        Ok(Some((field, wire)))
    }

    fn varint(&mut self) -> Result<u64, MigrationError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = *self.buf.get(self.pos).ok_or(MigrationError::Malformed)?;
            self.pos += 1;
            // A varint is at most ten bytes; refusing longer ones stops a
            // crafted payload from shifting past 64 bits.
            if shift >= 64 {
                return Err(MigrationError::Malformed);
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], MigrationError> {
        let len = self.varint()? as usize;
        let end = self.pos.checked_add(len).ok_or(MigrationError::Malformed)?;
        if end > self.buf.len() {
            return Err(MigrationError::Malformed);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn string(&mut self) -> Result<String, MigrationError> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| MigrationError::Malformed)
    }

    fn skip(&mut self, wire: u8) -> Result<(), MigrationError> {
        match wire {
            WIRE_VARINT => {
                self.varint()?;
            }
            WIRE_I64 => self.advance(8)?,
            WIRE_LEN => {
                self.bytes()?;
            }
            WIRE_I32 => self.advance(4)?,
            _ => return Err(MigrationError::Malformed),
        }
        Ok(())
    }

    fn advance(&mut self, n: usize) -> Result<(), MigrationError> {
        let end = self.pos.checked_add(n).ok_or(MigrationError::Malformed)?;
        if end > self.buf.len() {
            return Err(MigrationError::Malformed);
        }
        self.pos = end;
        Ok(())
    }
}

/// Re-exported so callers can accept a bare base32 secret in the same code
/// path that handles URIs.
pub use super::uri::decode_base32 as base32;

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64;

    // --- a minimal protobuf writer, so the tests build real payloads ---

    fn varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn tag(out: &mut Vec<u8>, field: u32, wire: u8) {
        varint(out, u64::from(field) << 3 | u64::from(wire));
    }

    fn len_field(out: &mut Vec<u8>, field: u32, data: &[u8]) {
        tag(out, field, WIRE_LEN);
        varint(out, data.len() as u64);
        out.extend_from_slice(data);
    }

    fn varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
        tag(out, field, WIRE_VARINT);
        varint(out, v);
    }

    struct Acct<'a> {
        secret: &'a [u8],
        name: &'a str,
        issuer: &'a str,
        algorithm: u64,
        digits: u64,
        otp_type: u64,
        counter: u64,
    }

    impl Default for Acct<'_> {
        fn default() -> Self {
            Acct {
                secret: b"12345678901234567890",
                name: "me@example.com",
                issuer: "Example",
                algorithm: 1,
                digits: 1,
                otp_type: 2,
                counter: 0,
            }
        }
    }

    fn encode_account(a: &Acct) -> Vec<u8> {
        let mut b = Vec::new();
        len_field(&mut b, 1, a.secret);
        len_field(&mut b, 2, a.name.as_bytes());
        len_field(&mut b, 3, a.issuer.as_bytes());
        varint_field(&mut b, 4, a.algorithm);
        varint_field(&mut b, 5, a.digits);
        varint_field(&mut b, 6, a.otp_type);
        if a.counter != 0 {
            varint_field(&mut b, 7, a.counter);
        }
        b
    }

    fn encode_payload(accounts: &[Acct], size: i32, index: i32, id: i32) -> String {
        let mut b = Vec::new();
        for a in accounts {
            len_field(&mut b, 1, &encode_account(a));
        }
        varint_field(&mut b, 2, 1); // version
        varint_field(&mut b, 3, size as u64);
        varint_field(&mut b, 4, index as u64);
        varint_field(&mut b, 5, id as u64);
        format!(
            "otpauth-migration://offline?data={}",
            BASE64
                .encode(&b)
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        )
    }

    // --- tests ---

    #[test]
    fn parses_a_single_account_export() {
        let uri = encode_payload(&[Acct::default()], 1, 0, 42);
        let payload = parse(&uri).unwrap();

        assert_eq!(payload.accounts.len(), 1);
        assert_eq!(payload.batch_size, 1);
        let a = &payload.accounts[0];
        assert_eq!(a.issuer.as_deref(), Some("Example"));
        assert_eq!(a.account, "me@example.com");
        assert_eq!(a.params.algorithm, Algorithm::Sha1);
        assert_eq!(a.params.digits, 6);
        assert_eq!(a.params.kind, OtpKind::Totp { period: 30 });
    }

    #[test]
    fn the_secret_is_raw_bytes_not_base32_text() {
        // The seed below is the RFC 6238 test seed. If it were mistakenly
        // treated as base32 text the codes would silently be wrong, so pin it
        // against the RFC vector directly.
        let uri = encode_payload(&[Acct::default()], 1, 0, 1);
        let a = &parse(&uri).unwrap().accounts[0];
        assert_eq!(a.secret.as_slice(), b"12345678901234567890");

        let code = crate::otp::totp(&a.secret, 59, 30, Algorithm::Sha1, 8).unwrap();
        assert_eq!(code.as_str(), "94287082");
    }

    #[test]
    fn decodes_sha256_eight_digit_and_hotp_entries() {
        let uri = encode_payload(
            &[
                Acct {
                    algorithm: 2,
                    digits: 2,
                    ..Default::default()
                },
                Acct {
                    otp_type: 1,
                    counter: 9,
                    name: "counter-based",
                    ..Default::default()
                },
            ],
            1,
            0,
            1,
        );
        let accounts = parse(&uri).unwrap().accounts;
        assert_eq!(accounts[0].params.algorithm, Algorithm::Sha256);
        assert_eq!(accounts[0].params.digits, 8);
        assert_eq!(accounts[1].params.kind, OtpKind::Hotp { counter: 9 });
    }

    #[test]
    fn multi_part_export_must_be_scanned_completely() {
        let one = parse(&encode_payload(&[Acct::default()], 3, 0, 77)).unwrap();
        let three = parse(&encode_payload(
            &[Acct {
                name: "c",
                ..Default::default()
            }],
            3,
            2,
            77,
        ))
        .unwrap();

        let mut c = BatchCollector::new();
        c.add(one).unwrap();
        c.add(three).unwrap();

        // Part 2 of 3 is missing: the import must say so rather than quietly
        // returning the two parts it has.
        assert!(!c.is_complete());
        assert_eq!(c.missing(), vec![2]);
        assert!(matches!(
            c.finish(),
            Err(MigrationError::IncompleteBatch { .. })
        ));
    }

    #[test]
    fn a_complete_multi_part_export_is_reassembled_in_order() {
        let mut c = BatchCollector::new();
        for (index, name) in ["first", "second", "third"].iter().enumerate() {
            let payload = parse(&encode_payload(
                &[Acct {
                    name,
                    ..Default::default()
                }],
                3,
                index as i32,
                5,
            ))
            .unwrap();
            c.add(payload).unwrap();
        }
        assert!(c.is_complete());
        let names: Vec<_> = c.finish().unwrap().into_iter().map(|a| a.account).collect();
        assert_eq!(names, ["first", "second", "third"]);
    }

    #[test]
    fn parts_may_be_scanned_out_of_order() {
        let mut c = BatchCollector::new();
        for index in [2, 0, 1] {
            let payload = parse(&encode_payload(
                &[Acct {
                    name: "x",
                    ..Default::default()
                }],
                3,
                index,
                5,
            ))
            .unwrap();
            c.add(payload).unwrap();
        }
        assert!(c.is_complete());
    }

    #[test]
    fn qr_codes_from_two_different_exports_are_refused() {
        let mut c = BatchCollector::new();
        c.add(parse(&encode_payload(&[Acct::default()], 2, 0, 1)).unwrap())
            .unwrap();
        assert!(matches!(
            c.add(parse(&encode_payload(&[Acct::default()], 2, 1, 2)).unwrap()),
            Err(MigrationError::MixedBatches)
        ));
    }

    #[test]
    fn md5_accounts_are_reported_by_name() {
        let uri = encode_payload(
            &[Acct {
                algorithm: 4,
                name: "legacy",
                ..Default::default()
            }],
            1,
            0,
            1,
        );
        assert!(matches!(parse(&uri), Err(MigrationError::Md5 { name }) if name == "legacy"));
    }

    #[test]
    fn unknown_fields_from_a_newer_exporter_are_skipped() {
        let mut acct = encode_account(&Acct::default());
        varint_field(&mut acct, 99, 12345); // a field we have never seen
        len_field(&mut acct, 98, b"future");

        let mut body = Vec::new();
        len_field(&mut body, 1, &acct);
        varint_field(&mut body, 3, 1);

        let uri = format!(
            "otpauth-migration://offline?data={}",
            BASE64
                .encode(&body)
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        );
        assert_eq!(parse(&uri).unwrap().accounts.len(), 1);
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        assert!(matches!(
            parse("otpauth://totp/x"),
            Err(MigrationError::NotMigration)
        ));
        assert!(matches!(
            parse("otpauth-migration://offline"),
            Err(MigrationError::MissingData)
        ));
        assert!(parse("otpauth-migration://offline?data=!!!!").is_err());
        // Truncated length-delimited field: must error, not index out of bounds.
        assert!(matches!(
            decode_payload(&[0x0a, 0x7f]),
            Err(MigrationError::Malformed)
        ));
        // A varint that never terminates.
        assert!(decode_payload(&[0x08, 0xff, 0xff, 0xff]).is_err());
    }
}
