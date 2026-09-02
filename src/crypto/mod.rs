//! The only place in neko-auth that touches cryptographic primitives.
//!
//! Key hierarchy:
//!
//! ```text
//! master password --Argon2id(salt, m/t/p)--> KEK
//!                                             |
//!                                             +--HKDF("dek-wrap")--> unwraps DEK
//!                                                                     |
//!                                          +--HKDF("field")-----------+
//!                                          |    per-field encryption
//!                                          +--HKDF("meta")
//!                                               vault integrity MAC
//! ```
//!
//! The two-layer design exists for correctness, not speed: changing the master
//! password re-wraps 32 bytes in a single transaction, which is atomic.
//! Re-encrypting an entire vault is not, and a half-completed password rotation
//! is a data-loss event.

pub mod aad;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use aad::{Aad, Column, Table};

/// On-disk blob format. Bumping this requires a migration path.
///
/// Version 2 derives the key from an email address *and* a password; a
/// version 1 vault used the password alone and cannot be opened by this build.
pub const FORMAT_VERSION: u8 = 2;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Plaintext is padded up to a multiple of this before sealing, so ciphertext
/// length reveals only a bucket. Unpadded, "the issuer is 6 characters" already
/// narrows the candidates to a handful of well-known services.
const PAD_BUCKET: usize = 32;

#[derive(Debug)]
pub enum CryptoError {
    /// Wrong password, or the ciphertext (or its AAD binding) was tampered
    /// with. These are deliberately indistinguishable: the tag check cannot
    /// tell us which, and guessing for the user would be a lie.
    Authentication,
    Malformed,
    UnsupportedFormat(u8),
    TooLarge(usize),
    KdfParams(KdfParamProblem),
    KdfFailed,
    Rng,
}

/// Which cost parameter was out of range. An enum rather than a message, so
/// the text can be translated at the point of display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParamProblem {
    MemoryTooLarge,
    TimeOutOfRange,
    LanesOutOfRange,
    MemoryTooSmall,
    RejectedByArgon2,
}

impl core::fmt::Display for KdfParamProblem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&match self {
            KdfParamProblem::MemoryTooLarge => crate::i18n::err_kdf_m_cost(),
            KdfParamProblem::TimeOutOfRange => crate::i18n::err_kdf_t_cost(),
            KdfParamProblem::LanesOutOfRange => crate::i18n::err_kdf_p_cost(),
            KdfParamProblem::MemoryTooSmall => crate::i18n::err_kdf_m_too_small(),
            KdfParamProblem::RejectedByArgon2 => crate::i18n::err_kdf_rejected(),
        })
    }
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&match self {
            CryptoError::Authentication => crate::i18n::err_authentication(),
            CryptoError::Malformed => crate::i18n::err_ciphertext_malformed(),
            CryptoError::UnsupportedFormat(version) => {
                crate::i18n::err_unsupported_format(*version)
            }
            CryptoError::TooLarge(bytes) => crate::i18n::err_too_large(*bytes),
            CryptoError::KdfParams(problem) => {
                crate::i18n::err_invalid_kdf_params(&problem.to_string())
            }
            CryptoError::KdfFailed => crate::i18n::err_kdf_failed(),
            CryptoError::Rng => crate::i18n::err_rng(),
        })
    }
}

impl std::error::Error for CryptoError {}

// Note: no CryptoError variant carries key material, plaintext, or any part of
// a password. `unwrap()` on a Result<_, CryptoError> prints the Debug of the
// error, and that output must always be safe to put in a terminal or a log.

/// Declares a 32-byte key newtype that erases itself on drop and refuses to
/// print itself.
macro_rules! secret_key {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Zeroize, ZeroizeOnDrop, Clone)]
        pub struct $name([u8; KEY_LEN]);

        impl $name {
            fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }
        }

        // Hand-written, never derived: a derived Debug would put the key in
        // any panic message or stray `dbg!` that ever touches this value.
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_key! {
    /// Key-encryption key. Derived from the master password; only ever used to
    /// wrap and unwrap the DEK.
    Kek
}

secret_key! {
    /// Data-encryption key. Random at vault creation, stored wrapped.
    Dek
}

secret_key! {
    /// Derived from the DEK. Encrypts account fields.
    FieldKey
}

secret_key! {
    /// Derived from the DEK. Authenticates the vault as a whole.
    MetaKey
}

secret_key! {
    /// Encrypts a standalone `.nekobak` archive.
    ///
    /// A distinct type from [`Kek`] on purpose: a backup is derived straight
    /// from its own password with no wrapped inner key, and the two must not
    /// be interchangeable at a call site.
    BackupKey
}

impl MetaKey {
    /// Exposed because the vault MAC is computed outside this module.
    pub fn raw(&self) -> &[u8; KEY_LEN] {
        self.as_bytes()
    }
}

/// Fills `N` bytes from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Argon2id cost parameters, as stored in the vault.
///
/// These are part of the hash function, so they must be persisted and read
/// back. Deriving `p_cost` from the local core count at unlock time would make
/// a vault unopenable on a machine with a different number of cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_cost: u32, // KiB
    t_cost: u32,
    p_cost: u32,
}

/// Upper bounds enforced on parameters read back from the vault file.
///
/// `argon2::Params` performs no upper-bound check at all — `MAX_M_COST` is
/// `u32::MAX`, and the crate's own source says it therefore skips the check.
/// So a one-byte edit of `kdf_m_cost` in the database is an out-of-memory
/// denial of service unless we clamp here.
const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024; // 2 GiB
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;

impl KdfParams {
    /// Fast, for low-memory machines. 64 MiB.
    pub const INTERACTIVE: KdfParams = KdfParams {
        m_cost: 64 * 1024,
        t_cost: 3,
        p_cost: 4,
    };
    /// Default. 256 MiB.
    pub const MODERATE: KdfParams = KdfParams {
        m_cost: 256 * 1024,
        t_cost: 3,
        p_cost: 4,
    };
    /// 1 GiB. Slow to unlock, correspondingly expensive to attack.
    pub const PARANOID: KdfParams = KdfParams {
        m_cost: 1024 * 1024,
        t_cost: 4,
        p_cost: 4,
    };

    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self, CryptoError> {
        if m_cost > MAX_M_COST_KIB {
            return Err(CryptoError::KdfParams(KdfParamProblem::MemoryTooLarge));
        }
        if t_cost == 0 || t_cost > MAX_T_COST {
            return Err(CryptoError::KdfParams(KdfParamProblem::TimeOutOfRange));
        }
        if p_cost == 0 || p_cost > MAX_P_COST {
            return Err(CryptoError::KdfParams(KdfParamProblem::LanesOutOfRange));
        }
        // Argon2 itself requires at least 8 blocks per lane.
        if m_cost < 8 * p_cost {
            return Err(CryptoError::KdfParams(KdfParamProblem::MemoryTooSmall));
        }
        Ok(KdfParams {
            m_cost,
            t_cost,
            p_cost,
        })
    }

    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "interactive" => Some(Self::INTERACTIVE),
            "moderate" => Some(Self::MODERATE),
            "paranoid" => Some(Self::PARANOID),
            _ => None,
        }
    }

    pub fn algorithm_id(&self) -> &'static str {
        "argon2id"
    }
    pub fn m_cost(&self) -> u32 {
        self.m_cost
    }
    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }
    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }

    /// Approximate peak working-set size of a derivation with these settings.
    pub fn memory_bytes(&self) -> u64 {
        u64::from(self.m_cost) * 1024
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::MODERATE
    }
}

/// The two secrets that together unlock a vault.
///
/// Neither is stored anywhere: the email is a second thing to know, not a
/// second thing to look up. An attacker holding the vault file has to guess
/// both, and the file gives away neither.
pub struct Credentials {
    email: Zeroizing<String>,
    password: SecretString,
}

// Never derived: this holds both halves of the unlock secret.
impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

impl Credentials {
    pub fn new(email: &str, password: SecretString) -> Self {
        Credentials {
            email: Zeroizing::new(normalize_email(email)),
            password,
        }
    }

    /// The bytes fed to Argon2id.
    ///
    /// Each part is length-prefixed rather than simply concatenated. Plain
    /// concatenation is ambiguous in exactly the way that matters here:
    /// `("a@b.com", "xyz")` and `("a@b.co", "mxyz")` join to the same string
    /// and would derive the same key, so two different credential pairs would
    /// open the same vault.
    fn key_material(&self) -> Zeroizing<Vec<u8>> {
        const DOMAIN: &[u8] = b"neko-auth/identity/v1";
        let email = self.email.as_bytes();
        let password = self.password.expose_secret().as_bytes();

        // Sized exactly, so the buffer never reallocates: Zeroize cannot reach
        // memory a Vec has already abandoned.
        let mut out = Vec::with_capacity(12 + DOMAIN.len() + email.len() + password.len());
        for part in [DOMAIN, email, password] {
            out.extend_from_slice(&(part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
        Zeroizing::new(out)
    }

    /// The normalised email, for display at a confirmation prompt.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The pair rendered as one string, for the standalone backup format.
    ///
    /// Uses the same length-prefixed encoding as the key material, so two
    /// different pairs can never flatten to the same backup password.
    pub fn backup_password_string(&self) -> String {
        let material = self.key_material();
        // Hex rather than raw bytes: the backup password travels as a string,
        // and the material contains arbitrary bytes from the password.
        material.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Trims and lowercases an email address.
///
/// Without this, a vault created as `Zoe@Example.com` will not open when the
/// same person types `zoe@example.com`, and the failure is indistinguishable
/// from a wrong password. RFC 5321 does make the local part case-sensitive,
/// but no mail provider in practice treats it that way, and an unopenable
/// vault is a far worse outcome than the theoretical mismatch.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Derives the key for a standalone backup archive.
///
/// Straight from the password, with no DEK indirection: a backup file never
/// needs its password changed in place, so the extra layer would buy nothing.
pub fn derive_backup_key(
    password: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<BackupKey, CryptoError> {
    let mut out = BackupKey([0u8; KEY_LEN]);
    derive_into(
        password.expose_secret().as_bytes(),
        salt,
        params,
        &mut out.0,
    )?;
    Ok(out)
}

/// Seals a backup body. Unlike a field, it is not padded: the archive is one
/// large blob, bucketing would hide nothing, and the padding header caps a
/// value at 64 KiB.
pub fn seal_backup(key: &BackupKey, aad: &Aad, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    seal_raw(key.as_bytes(), aad, plaintext)
}

pub fn open_backup(
    key: &BackupKey,
    aad: &Aad,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_raw(key.as_bytes(), aad, blob)
}

/// Derives the key-encryption key from the master password.
///
/// Allocates and owns the Argon2 working memory so it can be erased. The
/// convenience `hash_password_into` allocates internally and drops the buffer
/// without zeroizing, which would leave hundreds of megabytes of
/// password-derived state in the allocator's free list.
pub fn derive_kek(
    credentials: &Credentials,
    salt: &[u8],
    params: KdfParams,
) -> Result<Kek, CryptoError> {
    let mut out = Kek([0u8; KEY_LEN]);
    derive_into(&credentials.key_material(), salt, params, &mut out.0)?;
    Ok(out)
}

fn derive_into(
    secret: &[u8],
    salt: &[u8],
    params: KdfParams,
    out: &mut [u8; KEY_LEN],
) -> Result<(), CryptoError> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::KdfParams(KdfParamProblem::RejectedByArgon2))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut blocks: Zeroizing<Vec<Block>> =
        Zeroizing::new(vec![Block::default(); argon.params().block_count()]);

    argon
        .hash_password_into_with_memory(secret, salt, out, blocks.as_mut_slice())
        .map_err(|_| CryptoError::KdfFailed)?;

    Ok(())
}

/// Subkeys derived from the DEK.
///
/// HKDF costs nothing and buys domain separation: a mistake in how one key is
/// used cannot bleed into another.
pub struct VaultKeys {
    dek: Dek,
    field: FieldKey,
    meta: MetaKey,
}

impl core::fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VaultKeys(<redacted>)")
    }
}

impl VaultKeys {
    pub fn from_dek(dek: Dek) -> Self {
        let field = FieldKey(expand(dek.as_bytes(), b"neko-auth/v1/field"));
        let meta = MetaKey(expand(dek.as_bytes(), b"neko-auth/v1/meta"));
        VaultKeys { dek, field, meta }
    }

    /// Generates a brand-new random DEK and its subkeys.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self::from_dek(Dek(random_bytes::<KEY_LEN>()?)))
    }

    pub fn field_key(&self) -> &FieldKey {
        &self.field
    }
    pub fn meta_key(&self) -> &MetaKey {
        &self.meta
    }
    pub(crate) fn dek(&self) -> &Dek {
        &self.dek
    }
}

fn expand(ikm: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; KEY_LEN];
    // Only fails for absurd output lengths; 32 bytes cannot fail.
    hk.expand(info, &mut okm)
        .expect("HKDF output length is valid");
    okm
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

/// Seals `plaintext` under the field key, padded so its length is bucketed.
pub fn seal_field(key: &FieldKey, aad: &Aad, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let padded = pad(plaintext)?;
    seal_raw(key.as_bytes(), aad, &padded)
}

/// Opens a field ciphertext and strips the padding.
pub fn open_field(
    key: &FieldKey,
    aad: &Aad,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let padded = open_raw(key.as_bytes(), aad, blob)?;
    unpad(&padded)
}

/// Wraps the DEK under the KEK. No padding: the plaintext is always 32 bytes.
pub fn wrap_dek(kek: &Kek, aad: &Aad, keys: &VaultKeys) -> Result<Vec<u8>, CryptoError> {
    seal_raw(kek.as_bytes(), aad, keys.dek().as_bytes())
}

/// Unwraps the DEK, which is also how the master password is verified.
///
/// A wrong password yields a wrong KEK, which fails the Poly1305 tag. The cost
/// of a guess is therefore exactly one Argon2id evaluation — there is no
/// cheaper oracle anywhere in the vault, because there is no separate verifier.
pub fn unwrap_dek(kek: &Kek, aad: &Aad, blob: &[u8]) -> Result<VaultKeys, CryptoError> {
    let plain = open_raw(kek.as_bytes(), aad, blob)?;
    if plain.len() != KEY_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut dek = Dek([0u8; KEY_LEN]);
    dek.0.copy_from_slice(&plain);
    Ok(VaultKeys::from_dek(dek))
}

/// Blob layout: `[u8 format_version][24-byte nonce][ciphertext || 16-byte tag]`
///
/// The format version byte is also inside the AAD, so flipping it on disk
/// cannot steer a future version into a weaker legacy code path.
fn seal_raw(key: &[u8; KEY_LEN], aad: &Aad, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());

    // A fresh random 192-bit nonce every time, never derived from a row id or
    // a timestamp. This is the reason for choosing XChaCha20 over AES-GCM: at
    // 192 bits, random nonces are unconditionally safe, so restoring an old
    // backup and writing again cannot reuse one. GCM's 96-bit nonce would push
    // us toward a counter, and a reused GCM nonce leaks the authentication key.
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Authentication)?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_raw(
    key: &[u8; KEY_LEN],
    aad: &Aad,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < 1 + NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Malformed);
    }
    if blob[0] != FORMAT_VERSION {
        return Err(CryptoError::UnsupportedFormat(blob[0]));
    }

    let nonce = XNonce::from_slice(&blob[1..1 + NONCE_LEN]);
    let ciphertext = &blob[1 + NONCE_LEN..];

    let cipher = XChaCha20Poly1305::new(key.into());
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Authentication)?;

    Ok(Zeroizing::new(plain))
}

// ---------------------------------------------------------------------------
// Length hiding
// ---------------------------------------------------------------------------

/// `[u16 real length][content][zero padding to a multiple of PAD_BUCKET]`
fn pad(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if plaintext.len() > u16::MAX as usize {
        return Err(CryptoError::TooLarge(plaintext.len()));
    }
    let total = (2 + plaintext.len()).next_multiple_of(PAD_BUCKET);
    // Pre-allocated to its final size: a Vec that grows leaves the old buffer
    // behind, and Zeroize cannot reach memory the Vec has already abandoned.
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(plaintext.len() as u16).to_le_bytes());
    buf.extend_from_slice(plaintext);
    buf.resize(total, 0);
    Ok(Zeroizing::new(buf))
}

fn unpad(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if padded.len() < 2 {
        return Err(CryptoError::Malformed);
    }
    let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if 2 + len > padded.len() {
        return Err(CryptoError::Malformed);
    }
    // The AEAD tag already guarantees integrity, so a non-zero pad can only
    // mean an encoder bug on our side. Catch it here rather than shipping
    // subtly wrong bytes to a caller.
    if padded[2 + len..].iter().any(|&b| b != 0) {
        return Err(CryptoError::Malformed);
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&padded[2..2 + len]);
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: u32 = 1;

    fn keys() -> VaultKeys {
        VaultKeys::generate().unwrap()
    }

    fn pair(email: &str, password: &str) -> Credentials {
        Credentials::new(email, SecretString::from(password.to_string()))
    }

    fn field_aad(uuid: &[u8; 16], column: Column) -> Aad {
        Aad::field(FORMAT_VERSION, SCHEMA, Table::Accounts, column, uuid, 0)
    }

    #[test]
    fn seal_open_round_trip() {
        let k = keys();
        let aad = field_aad(&[1; 16], Column::Secret);
        for msg in [b"".as_slice(), b"hello", &[0xAB; 300]] {
            let blob = seal_field(k.field_key(), &aad, msg).unwrap();
            let out = open_field(k.field_key(), &aad, &blob).unwrap();
            assert_eq!(out.as_slice(), msg);
        }
    }

    #[test]
    fn padding_bucketizes_length() {
        let k = keys();
        let aad = field_aad(&[1; 16], Column::Issuer);
        // Two issuers of different length within the same bucket must produce
        // identical ciphertext lengths, or the length itself identifies them.
        let a = seal_field(k.field_key(), &aad, b"Google").unwrap();
        let b = seal_field(k.field_key(), &aad, b"GitHub").unwrap();
        let c = seal_field(k.field_key(), &aad, b"a").unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
    }

    #[test]
    fn flipping_any_ciphertext_byte_is_rejected() {
        let k = keys();
        let aad = field_aad(&[1; 16], Column::Secret);
        let blob = seal_field(k.field_key(), &aad, b"JBSWY3DPEHPK3PXP").unwrap();

        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            assert!(
                open_field(k.field_key(), &aad, &bad).is_err(),
                "byte {i} was mutable without detection"
            );
        }
    }

    #[test]
    fn a_secret_cannot_be_moved_to_another_account() {
        // The core claim of the AAD design. An attacker with write access to
        // the vault file copies account A's sealed secret onto account B's row,
        // so that reading "B" would print A's code. It must not decrypt.
        let k = keys();
        let a_uuid = [0xAA; 16];
        let b_uuid = [0xBB; 16];

        let blob = seal_field(
            k.field_key(),
            &field_aad(&a_uuid, Column::Secret),
            b"account-a-seed",
        )
        .unwrap();

        assert!(open_field(k.field_key(), &field_aad(&b_uuid, Column::Secret), &blob).is_err());
    }

    #[test]
    fn a_secret_cannot_be_moved_into_a_displayed_column() {
        // Relocating ct_secret into ct_label would print the seed on screen.
        let k = keys();
        let uuid = [0xCC; 16];
        let blob = seal_field(k.field_key(), &field_aad(&uuid, Column::Secret), b"seed").unwrap();
        assert!(open_field(k.field_key(), &field_aad(&uuid, Column::Label), &blob).is_err());
    }

    #[test]
    fn wrong_password_fails_to_unwrap_the_dek() {
        let salt = [3u8; SALT_LEN];
        let params = KdfParams::INTERACTIVE;
        let aad = Aad::dek_wrap(FORMAT_VERSION, SCHEMA, &params, &salt, 0);

        let right = derive_kek(&pair("zoe@example.com", "correct horse"), &salt, params).unwrap();
        let wrong = derive_kek(&pair("zoe@example.com", "correct horsf"), &salt, params).unwrap();

        let keys = VaultKeys::generate().unwrap();
        let wrapped = wrap_dek(&right, &aad, &keys).unwrap();

        assert!(unwrap_dek(&right, &aad, &wrapped).is_ok());
        assert!(matches!(
            unwrap_dek(&wrong, &aad, &wrapped),
            Err(CryptoError::Authentication)
        ));
    }

    #[test]
    fn unwrapping_recovers_the_same_subkeys() {
        let salt = [4u8; SALT_LEN];
        let params = KdfParams::INTERACTIVE;
        let aad = Aad::dek_wrap(FORMAT_VERSION, SCHEMA, &params, &salt, 0);
        let kek = derive_kek(&pair("zoe@example.com", "pw"), &salt, params).unwrap();

        let original = VaultKeys::generate().unwrap();
        let wrapped = wrap_dek(&kek, &aad, &original).unwrap();
        let reopened = unwrap_dek(&kek, &aad, &wrapped).unwrap();

        // Data sealed before a lock must open after the next unlock.
        let aad_f = field_aad(&[9; 16], Column::Params);
        let blob = seal_field(original.field_key(), &aad_f, b"payload").unwrap();
        assert_eq!(
            open_field(reopened.field_key(), &aad_f, &blob)
                .unwrap()
                .as_slice(),
            b"payload"
        );
        assert_eq!(original.meta_key().raw(), reopened.meta_key().raw());
    }

    #[test]
    fn weakening_stored_kdf_parameters_breaks_the_unwrap() {
        // An attacker edits kdf_m_cost down so that brute-forcing is cheap.
        // Because the parameters are inside the wrap's AAD, the edit is
        // self-defeating: no password can open the vault any more.
        let salt = [5u8; SALT_LEN];
        let real = KdfParams::INTERACTIVE;
        let weakened = KdfParams::new(8 * 4, 1, 4).unwrap();

        let kek = derive_kek(&pair("zoe@example.com", "pw"), &salt, real).unwrap();
        let keys = VaultKeys::generate().unwrap();
        let wrapped = wrap_dek(
            &kek,
            &Aad::dek_wrap(FORMAT_VERSION, SCHEMA, &real, &salt, 0),
            &keys,
        )
        .unwrap();

        let forged = Aad::dek_wrap(FORMAT_VERSION, SCHEMA, &weakened, &salt, 0);
        assert!(unwrap_dek(&kek, &forged, &wrapped).is_err());
    }

    #[test]
    fn a_rearranged_pair_does_not_derive_the_same_key() {
        // The property that makes length-prefixing necessary. Concatenated
        // naively, "a@b.com" + "xyz" and "a@b.co" + "mxyz" are the same
        // string, so one pair would open a vault created with the other.
        let salt = [1u8; SALT_LEN];
        let params = KdfParams::INTERACTIVE;
        let a = derive_kek(&pair("a@b.com", "xyz"), &salt, params).unwrap();
        let b = derive_kek(&pair("a@b.co", "mxyz"), &salt, params).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn both_halves_affect_the_key() {
        let salt = [2u8; SALT_LEN];
        let params = KdfParams::INTERACTIVE;
        let base = derive_kek(&pair("zoe@example.com", "hunter2"), &salt, params).unwrap();

        let other_email = derive_kek(&pair("zoe@example.org", "hunter2"), &salt, params).unwrap();
        let other_password =
            derive_kek(&pair("zoe@example.com", "hunter3"), &salt, params).unwrap();

        assert_ne!(base.as_bytes(), other_email.as_bytes());
        assert_ne!(base.as_bytes(), other_password.as_bytes());
    }

    #[test]
    fn the_email_is_matched_case_and_whitespace_insensitively() {
        // Otherwise a vault created as "Zoe@Example.com " never opens when the
        // same person types "zoe@example.com", and the failure is
        // indistinguishable from a forgotten password.
        let salt = [3u8; SALT_LEN];
        let params = KdfParams::INTERACTIVE;
        let canonical = derive_kek(&pair("zoe@example.com", "pw"), &salt, params).unwrap();
        for variant in ["Zoe@Example.com", "  zoe@example.com  ", "ZOE@EXAMPLE.COM"] {
            let derived = derive_kek(&pair(variant, "pw"), &salt, params).unwrap();
            assert_eq!(canonical.as_bytes(), derived.as_bytes(), "{variant}");
        }
    }

    #[test]
    fn credentials_never_print_themselves() {
        let credentials = pair("zoe@example.com", "hunter2");
        let rendered = format!("{credentials:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("zoe@example.com"));
    }

    #[test]
    fn out_of_range_kdf_parameters_are_rejected_not_allocated() {
        // argon2 does not bound m_cost, so a tampered vault claiming 4 TiB
        // would be an out-of-memory abort if we passed it through.
        assert!(KdfParams::new(u32::MAX, 3, 4).is_err());
        assert!(KdfParams::new(64 * 1024, 0, 4).is_err());
        assert!(KdfParams::new(64 * 1024, 1000, 4).is_err());
        assert!(KdfParams::new(64 * 1024, 3, 0).is_err());
        assert!(KdfParams::new(64 * 1024, 3, 99).is_err());
        assert!(KdfParams::new(8, 3, 4).is_err());
    }

    #[test]
    fn dek_generation_is_bound() {
        let k = keys();
        let uuid = [7u8; 16];
        let gen0 = Aad::field(
            FORMAT_VERSION,
            SCHEMA,
            Table::Accounts,
            Column::Secret,
            &uuid,
            0,
        );
        let gen1 = Aad::field(
            FORMAT_VERSION,
            SCHEMA,
            Table::Accounts,
            Column::Secret,
            &uuid,
            1,
        );
        let blob = seal_field(k.field_key(), &gen0, b"x").unwrap();
        assert!(open_field(k.field_key(), &gen1, &blob).is_err());
    }
}
