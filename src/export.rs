//! Backup and export.
//!
//! Two formats, for two different jobs.
//!
//! `.nekobak` is an encrypted, self-describing archive. It is deliberately not
//! a copy of the SQLite file: a backup should outlive the schema that produced
//! it, and ideally the program too. The layout below is small enough to
//! re-implement from this comment in about fifty lines, which is the point.
//!
//! ```text
//! offset  size  field
//!      0     8  magic  "NEKOBAK1"
//!      8     1  format version (1)
//!      9     1  kdf algorithm  (0 = argon2id)
//!     10     4  m_cost, KiB, little-endian
//!     14     4  t_cost
//!     18     4  p_cost
//!     22    32  salt
//!     54     n  XChaCha20-Poly1305 blob: [1-byte version][24-byte nonce][ct||tag]
//! ```
//!
//! The key comes straight from Argon2id over the backup password and the salt
//! above; there is no wrapped inner key, because a backup file never needs its
//! password changed in place. The header is bound into the AEAD's associated
//! data, so editing the cost parameters to make cracking cheap breaks the file
//! instead.
//!
//! The plaintext export is a list of `otpauth://` URIs. Refusing to provide one
//! would be lock-in — these are the user's own seeds, and they must be able to
//! leave — but it is guarded by a typed confirmation, written owner-only, and
//! announced loudly.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::crypto::{self, Aad, KdfParams, SALT_LEN};
use crate::i18n;
use crate::otp::uri::OtpAuth;
use crate::otp::{Algorithm, OtpKind, OtpParams};

const MAGIC: &[u8; 8] = b"NEKOBAK1";
const BACKUP_VERSION: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + SALT_LEN;

/// Serialises accounts into an encrypted archive at `path`.
pub fn write_encrypted(
    path: &Path,
    entries: &[OtpAuth],
    password: &SecretString,
    kdf: KdfParams,
) -> Result<()> {
    let salt = crypto::random_bytes::<SALT_LEN>()?;
    let key = crypto::derive_backup_key(password, &salt, kdf)?;

    let header = header_bytes(&kdf, &salt);
    let aad = Aad::backup(&header);
    let body = encode_entries(entries);
    let sealed = crypto::seal_backup(&key, &aad, &body).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut out = Vec::with_capacity(header.len() + sealed.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&sealed);
    write_private(path, &out)
}

/// Reads an encrypted archive back.
pub fn read_encrypted(path: &Path, password: &SecretString) -> Result<Vec<OtpAuth>> {
    let bytes =
        std::fs::read(path).with_context(|| i18n::err_cannot_read(&path.display().to_string()))?;
    if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
        bail!("{}", i18n::not_a_backup(&path.display().to_string()));
    }
    if bytes[8] != BACKUP_VERSION {
        bail!(
            "{}",
            i18n::err_backup_format(
                &path.display().to_string(),
                u64::from(bytes[8]),
                u64::from(BACKUP_VERSION)
            )
        );
    }
    if bytes[9] != 0 {
        bail!(
            "{} uses an unsupported key-derivation algorithm",
            path.display()
        );
    }

    let m_cost = u32::from_le_bytes(bytes[10..14].try_into().unwrap());
    let t_cost = u32::from_le_bytes(bytes[14..18].try_into().unwrap());
    let p_cost = u32::from_le_bytes(bytes[18..22].try_into().unwrap());
    // Bounded exactly as the vault header is: these came off disk, and argon2
    // will try to allocate whatever it is given.
    let kdf = KdfParams::new(m_cost, t_cost, p_cost).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::err_backup_params(&path.display().to_string(), &e.to_string())
        )
    })?;

    let salt: [u8; SALT_LEN] = bytes[22..22 + SALT_LEN].try_into().unwrap();
    let key = crypto::derive_backup_key(password, &salt, kdf)?;
    let aad = Aad::backup(&bytes[..HEADER_LEN]);

    let plain = crypto::open_backup(&key, &aad, &bytes[HEADER_LEN..])
        .map_err(|_| anyhow::anyhow!("{}", i18n::wrong_backup_password()))?;
    decode_entries(&plain)
}

/// Writes the accounts as `otpauth://` URIs, one per line.
pub fn write_plaintext(path: &Path, entries: &[OtpAuth]) -> Result<()> {
    let mut text = Zeroizing::new(String::new());
    // Kept in English regardless of the interface language: this file is
    // meant to be read by whoever finds it, including a future stranger.
    text.push_str("# neko-auth plaintext export. Every line below is a live secret.\n");
    text.push_str("# Delete this file as soon as you have imported it elsewhere.\n");
    for entry in entries {
        text.push_str(&entry.to_uri());
        text.push('\n');
    }
    write_private(path, text.as_bytes())
}

/// Writes owner-only, atomically.
///
/// The temporary file is created in the destination directory so the rename is
/// within one filesystem, and `tempfile` creates it 0600 from the start — there
/// is deliberately no create-then-chmod, which would leave a window in which
/// the secrets are world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }

    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| i18n::err_cannot_create_temp(&dir.display().to_string()))?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| {
        anyhow::anyhow!(
            "{}: {}",
            i18n::err_cannot_write(&path.display().to_string()),
            e.error
        )
    })?;

    // Without fsync on the directory the rename itself may not survive a power
    // cut, which is the step nearly every implementation omits.
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }

    crate::paths::restrict_file(path)?;
    Ok(())
}

fn header_bytes(kdf: &KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(BACKUP_VERSION);
    header.push(0); // argon2id
    header.extend_from_slice(&kdf.m_cost().to_le_bytes());
    header.extend_from_slice(&kdf.t_cost().to_le_bytes());
    header.extend_from_slice(&kdf.p_cost().to_le_bytes());
    header.extend_from_slice(salt);
    header
}

// --- body codec: length-prefixed, deterministic, no serde ---

fn encode_entries(entries: &[OtpAuth]) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(128 * entries.len());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        push_bytes(&mut out, entry.issuer.as_deref().unwrap_or("").as_bytes());
        push_bytes(&mut out, entry.account.as_bytes());
        push_bytes(&mut out, &entry.secret);
        out.push(match entry.params.algorithm {
            Algorithm::Sha1 => 0,
            Algorithm::Sha256 => 1,
            Algorithm::Sha512 => 2,
        });
        out.push(entry.params.digits as u8);
        match entry.params.kind {
            OtpKind::Totp { period } => {
                out.push(0);
                out.extend_from_slice(&period.to_le_bytes());
                out.extend_from_slice(&0u64.to_le_bytes());
            }
            OtpKind::Hotp { counter } => {
                out.push(1);
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&counter.to_le_bytes());
            }
        }
    }
    Zeroizing::new(out)
}

fn decode_entries(bytes: &[u8]) -> Result<Vec<OtpAuth>> {
    let mut c = Cursor { buf: bytes, pos: 0 };
    let count = c.u32()? as usize;
    let mut entries = Vec::with_capacity(count.min(4096));

    for _ in 0..count {
        let issuer = c.string()?;
        let account = c.string()?;
        let secret = c.blob()?.to_vec();
        let algorithm = match c.u8()? {
            0 => Algorithm::Sha1,
            1 => Algorithm::Sha256,
            2 => Algorithm::Sha512,
            _ => bail!("{}", i18n::err_backup_unknown_algorithm()),
        };
        let digits = u32::from(c.u8()?);
        let kind_code = c.u8()?;
        let period = c.u32()?;
        let counter = c.u64()?;
        let kind = match kind_code {
            0 => OtpKind::Totp { period },
            1 => OtpKind::Hotp { counter },
            _ => bail!("{}", i18n::err_backup_unknown_type()),
        };

        entries.push(OtpAuth {
            issuer: (!issuer.is_empty()).then_some(issuer),
            account,
            secret: Zeroizing::new(secret),
            params: OtpParams {
                algorithm,
                digits,
                kind,
            },
        });
    }
    Ok(entries)
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .with_context(i18n::backup_truncated)?;
        if end > self.buf.len() {
            bail!("{}", i18n::backup_truncated());
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.blob()?.to_vec()).with_context(i18n::err_backup_utf8)
    }
}

/// Flattens the unlock pair into a single backup password.
///
/// A `.nekobak` archive is a standalone file with its own password; it does not
/// carry the vault's identity split. `--same-password` therefore means "keyed
/// on the same pair you type to unlock", flattened through the same
/// length-prefixed encoding so it stays unambiguous.
pub fn password_from_credentials(credentials: &crate::crypto::Credentials) -> SecretString {
    SecretString::from(credentials.backup_password_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_kdf() -> KdfParams {
        KdfParams::new(32, 1, 4).unwrap()
    }

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    fn entries() -> Vec<OtpAuth> {
        vec![
            OtpAuth {
                issuer: Some("GitHub".into()),
                account: "zoe@example.com".into(),
                secret: Zeroizing::new(b"12345678901234567890".to_vec()),
                params: OtpParams::default(),
            },
            OtpAuth {
                issuer: None,
                account: "counter-based".into(),
                secret: Zeroizing::new(vec![0xAB; 32]),
                params: OtpParams {
                    algorithm: Algorithm::Sha512,
                    digits: 8,
                    kind: OtpKind::Hotp { counter: 41 },
                },
            },
        ]
    }

    #[test]
    fn an_archive_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.nekobak");
        write_encrypted(&path, &entries(), &pw("backup-pass"), fast_kdf()).unwrap();

        let restored = read_encrypted(&path, &pw("backup-pass")).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(restored[0].secret.as_slice(), b"12345678901234567890");
        assert_eq!(restored[1].params.kind, OtpKind::Hotp { counter: 41 });
        assert_eq!(restored[1].params.algorithm, Algorithm::Sha512);
        assert!(restored[1].issuer.is_none());
    }

    #[test]
    fn the_archive_is_not_readable_with_the_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.nekobak");
        write_encrypted(&path, &entries(), &pw("right"), fast_kdf()).unwrap();
        assert!(read_encrypted(&path, &pw("wrong")).is_err());
    }

    #[test]
    fn no_secret_appears_in_the_archive_in_the_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.nekobak");
        write_encrypted(&path, &entries(), &pw("backup-pass"), fast_kdf()).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(raw.windows(20).all(|w| w != b"12345678901234567890"));
        assert!(raw.windows(6).all(|w| w != b"GitHub"));
    }

    #[test]
    fn flipping_any_header_byte_makes_the_archive_unreadable() {
        // The cost parameters and salt feed the KDF, so editing them yields a
        // different key; the magic, version and algorithm bytes are validated
        // outright; and the AAD binding covers all of it regardless. The
        // property that matters is the union: no single-byte edit produces a
        // readable file with weaker settings.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.nekobak");
        write_encrypted(
            &path,
            &entries(),
            &pw("backup-pass"),
            KdfParams::new(64, 2, 4).unwrap(),
        )
        .unwrap();
        let original = std::fs::read(&path).unwrap();

        for i in 0..HEADER_LEN {
            let mut raw = original.clone();
            raw[i] ^= 0x01;
            std::fs::write(&path, &raw).unwrap();
            assert!(
                read_encrypted(&path, &pw("backup-pass")).is_err(),
                "header byte {i} could be edited without detection"
            );
        }
    }

    #[test]
    fn a_truncated_archive_is_reported_not_panicked_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.nekobak");
        write_encrypted(&path, &entries(), &pw("p"), fast_kdf()).unwrap();

        let raw = std::fs::read(&path).unwrap();
        for cut in [0, 10, HEADER_LEN, HEADER_LEN + 5, raw.len() - 1] {
            std::fs::write(&path, &raw[..cut]).unwrap();
            assert!(read_encrypted(&path, &pw("p")).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn the_plaintext_export_round_trips_and_is_labelled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.txt");
        write_plaintext(&path, &entries()).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# neko-auth plaintext export"));

        let back = crate::import::collect(&crate::import::read_file(&path).unwrap()).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].secret.as_slice(), b"12345678901234567890");
    }

    #[cfg(unix)]
    #[test]
    fn exports_are_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();

        let archive = dir.path().join("backup.nekobak");
        write_encrypted(&archive, &entries(), &pw("p"), fast_kdf()).unwrap();

        let plain = dir.path().join("secrets.txt");
        write_plaintext(&plain, &entries()).unwrap();

        for path in [archive, plain] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} is mode {mode:04o}", path.display());
        }
    }
}
