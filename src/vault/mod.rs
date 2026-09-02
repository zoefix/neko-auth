//! The vault: unlocking, the in-memory session, and every read and write.

pub mod record;
pub mod schema;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{
    self, Aad, Column, Credentials, KdfParams, MetaKey, Table, VaultKeys, FORMAT_VERSION, SALT_LEN,
};
use crate::i18n;
use crate::otp::uri::OtpAuth;
use crate::otp::{now, OtpKind, OtpParams};
use record::RecordParams;
use schema::{VaultMeta, SCHEMA_VERSION};

/// One account's metadata. Deliberately does **not** carry the shared secret:
/// the session caches names so search is instant, and re-reads and re-decrypts
/// the seed for each code, discarding it immediately afterwards.
#[derive(Debug, Clone)]
pub struct Account {
    pub uuid: [u8; 16],
    pub issuer: Option<String>,
    pub label: String,
    pub params: OtpParams,
    pub created_at: u64,
    pub updated_at: u64,
    pub notes: Option<String>,
}

impl Account {
    /// How the account is shown and referred to on the command line.
    pub fn display(&self) -> String {
        match (&self.issuer, self.label.is_empty()) {
            (Some(issuer), true) => issuer.clone(),
            (Some(issuer), false) => format!("{issuer} ({})", self.label),
            (None, _) => self.label.clone(),
        }
    }

    /// Case-insensitive substring match over issuer, label, and both combined.
    pub fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        let needle = needle.to_lowercase();
        self.display().to_lowercase().contains(&needle)
            || self.label.to_lowercase().contains(&needle)
            || self
                .issuer
                .as_deref()
                .is_some_and(|i| i.to_lowercase().contains(&needle))
    }

    fn sort_key(&self) -> (String, String) {
        (
            self.issuer.clone().unwrap_or_default().to_lowercase(),
            self.label.to_lowercase(),
        )
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Live key material, plus the idle clock that erases it.
pub struct Session {
    keys: Option<VaultKeys>,
    last_activity: Instant,
    idle_timeout: Option<Duration>,
}

pub type SharedSession = Arc<Mutex<Session>>;

impl Session {
    fn new(idle_timeout: Option<Duration>) -> SharedSession {
        Arc::new(Mutex::new(Session {
            keys: None,
            last_activity: Instant::now(),
            idle_timeout,
        }))
    }

    pub fn is_unlocked(&self) -> bool {
        self.keys.is_some()
    }

    /// Drops the keys. `VaultKeys` erases itself on drop.
    pub fn lock(&mut self) {
        self.keys = None;
    }

    fn expired(&self) -> bool {
        self.keys.is_some()
            && self
                .idle_timeout
                .is_some_and(|t| self.last_activity.elapsed() >= t)
    }
}

/// Starts the idle watchdog. It holds only a weak reference, so it stops on its
/// own once the vault is dropped.
///
/// Locking happens here rather than by interrupting the prompt: `readline` has
/// no timeout, and a blocking read cannot be cancelled portably. Erasing the
/// keys on a timer and reporting "locked" at the next command achieves the same
/// thing without fighting the terminal.
fn spawn_idle_watchdog(session: &SharedSession) {
    let weak: Weak<Mutex<Session>> = Arc::downgrade(session);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let Some(shared) = weak.upgrade() else { return };
        let mut guard = shared.lock().unwrap_or_else(|e| e.into_inner());
        if guard.expired() {
            guard.lock();
        }
    });
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

pub struct Vault {
    conn: Connection,
    meta: VaultMeta,
    path: PathBuf,
    session: SharedSession,
    /// False when the filesystem refused write-ahead logging, which is the
    /// signature of a vault sitting in a cloud-sync or network folder.
    pub wal_active: bool,
}

// Hand-written, never derived: the session reachable from here holds live key
// material, and a derived Debug would print it into any panic message.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("unlocked", &self.is_unlocked())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl Vault {
    /// Creates a new vault. Fails if one already exists at `path`.
    pub fn create(path: &Path, credentials: &Credentials, kdf: KdfParams) -> Result<Self> {
        if path.exists() {
            bail!("{}", i18n::init_already_exists(&path.display().to_string()));
        }
        if let Some(parent) = path.parent() {
            crate::paths::ensure_private_dir(parent)?;
        }

        let conn = schema::open(path)?;
        let wal_active = schema::enable_wal(&conn)?;
        schema::create_schema(&conn)?;

        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let kek = crypto::derive_kek(credentials, &salt, kdf)?;
        let keys = VaultKeys::generate()?;
        let wrap_aad = Aad::dek_wrap(FORMAT_VERSION, SCHEMA_VERSION, &kdf, &salt, 0);
        let wrapped_dek = crypto::wrap_dek(&kek, &wrap_aad, &keys)?;

        let mut meta = VaultMeta {
            format_version: FORMAT_VERSION,
            schema_version: SCHEMA_VERSION,
            kdf,
            salt: salt.to_vec(),
            dek_generation: 0,
            wrapped_dek,
            vault_serial: 1,
            vault_mac: vec![0; 32],
        };
        meta.vault_mac = compute_mac(keys.meta_key(), &meta, &[])?;
        meta.insert(&conn)?;

        restrict_all(path);

        let session = Session::new(None);
        session.lock().unwrap_or_else(|e| e.into_inner()).keys = Some(keys);
        spawn_idle_watchdog(&session);

        Ok(Vault {
            conn,
            meta,
            path: path.to_path_buf(),
            session,
            wal_active,
        })
    }

    /// Opens an existing vault. The returned vault is locked.
    pub fn open(path: &Path, idle_timeout: Option<Duration>) -> Result<Self> {
        if !path.exists() {
            bail!("{}", i18n::no_vault_here(&path.display().to_string()));
        }
        let conn = schema::open(path)?;
        if !schema::is_initialized(&conn)? {
            bail!("{}", i18n::not_a_vault(&path.display().to_string()));
        }
        schema::validate_schema(&conn)?;
        let wal_active = schema::enable_wal(&conn)?;
        let meta = VaultMeta::load(&conn)?;

        let session = Session::new(idle_timeout);
        spawn_idle_watchdog(&session);

        Ok(Vault {
            conn,
            meta,
            path: path.to_path_buf(),
            session,
            wal_active,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn session(&self) -> &SharedSession {
        &self.session
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.meta.kdf
    }

    pub fn is_unlocked(&self) -> bool {
        self.session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_unlocked()
    }

    pub fn lock(&self) {
        self.session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lock();
    }

    /// Records activity, so the idle watchdog measures real idleness.
    pub fn touch(&self) {
        self.session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_activity = Instant::now();
    }

    /// Verifies the credentials by unwrapping the DEK.
    ///
    /// There is no separate verifier anywhere in the vault. Wrong credentials
    /// produce a wrong KEK, which fails the AEAD tag, so the cost of a guess is
    /// exactly one Argon2id evaluation. Storing any cheaper check — a hash of
    /// the password or of the email, say — would make the whole KDF decorative,
    /// and a stored email hash would hand away half the secret outright.
    pub fn unlock(&mut self, credentials: &Credentials) -> Result<()> {
        let kek = crypto::derive_kek(credentials, &self.meta.salt, self.meta.kdf)?;
        let aad = Aad::dek_wrap(
            FORMAT_VERSION,
            SCHEMA_VERSION,
            &self.meta.kdf,
            &self.meta.salt,
            self.meta.dek_generation,
        );
        let keys = crypto::unwrap_dek(&kek, &aad, &self.meta.wrapped_dek).map_err(|_| {
            // One message for both causes. The tag check genuinely cannot tell
            // them apart, and guessing on the user's behalf would be a lie.
            anyhow!("{}", i18n::unlock_failed_pair())
        })?;

        let expected = compute_mac(keys.meta_key(), &self.meta, &self.row_digests(&self.conn)?)?;
        let mac_ok = expected.as_slice() == self.meta.vault_mac.as_slice();

        let mut guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        guard.keys = Some(keys);
        guard.last_activity = Instant::now();
        drop(guard);

        if !mac_ok {
            // Not fatal: individual accounts still decrypt, and refusing to
            // open would strand the user. But this is how row deletion and
            // file rollback surface, so it must be loud.
            bail!(VaultIntegrityWarning);
        }
        Ok(())
    }

    // -- reads --------------------------------------------------------------

    /// Decrypts every account's metadata. Secrets are not touched.
    pub fn list(&self) -> Result<Vec<Account>> {
        let guard = self.keys()?;
        let keys = guard.keys.as_ref().expect("checked by keys()");

        let mut stmt = self
            .conn
            .prepare("SELECT uuid, dek_generation, ct_issuer, ct_label, ct_params FROM accounts")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;

        let mut accounts = Vec::new();
        for row in rows {
            let (uuid_bytes, generation, ct_issuer, ct_label, ct_params) = row?;
            let uuid = to_uuid(&uuid_bytes)?;
            let generation = u32::try_from(generation).unwrap_or(u32::MAX);

            let issuer = decrypt_text(keys, &uuid, generation, Column::Issuer, &ct_issuer)?;
            let label = decrypt_text(keys, &uuid, generation, Column::Label, &ct_label)?;
            let params_blob = crypto::open_field(
                keys.field_key(),
                &field_aad(&uuid, generation, Column::Params),
                &ct_params,
            )
            .map_err(|_| corrupt(&label))?;
            let rp = RecordParams::decode(&params_blob).map_err(|e| anyhow!("{e}"))?;

            accounts.push(Account {
                uuid,
                issuer: (!issuer.is_empty()).then_some(issuer),
                label,
                params: rp.params,
                created_at: rp.created_at,
                updated_at: rp.updated_at,
                notes: rp.notes,
            });
        }

        // Sorted here rather than in SQL: an order-preserving plaintext column
        // would leak the alphabetical ordering of issuer names, which combined
        // with a guess at the likely set of services is a strong inference
        // channel. At vault sizes, sorting in memory is free.
        accounts.sort_by_key(Account::sort_key);
        Ok(accounts)
    }

    /// Decrypts one account's seed. The caller must let the result drop
    /// promptly; it erases itself.
    pub fn secret_of(&self, account: &Account) -> Result<Zeroizing<Vec<u8>>> {
        let guard = self.keys()?;
        let keys = guard.keys.as_ref().expect("checked by keys()");

        let (generation, ct_secret): (i64, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT dek_generation, ct_secret FROM accounts WHERE uuid = ?1",
                [&account.uuid[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .with_context(|| i18n::no_such_account_named(&account.display()))?;

        crypto::open_field(
            keys.field_key(),
            &field_aad(
                &account.uuid,
                u32::try_from(generation).unwrap_or(u32::MAX),
                Column::Secret,
            ),
            &ct_secret,
        )
        .map_err(|_| corrupt(&account.display()))
    }

    /// Decrypts every account, secrets included.
    ///
    /// This is the one operation that holds every seed in memory at once,
    /// which is unavoidable for a backup. The buffers erase themselves on
    /// drop, so the caller should not keep the result around.
    pub fn export_entries(&self) -> Result<Vec<OtpAuth>> {
        let accounts = self.list()?;
        let mut entries = Vec::with_capacity(accounts.len());
        for account in &accounts {
            entries.push(OtpAuth {
                issuer: account.issuer.clone(),
                account: account.label.clone(),
                secret: self.secret_of(account)?,
                params: account.params,
            });
        }
        Ok(entries)
    }

    // -- writes -------------------------------------------------------------

    /// Stores a new account. Returns its id.
    pub fn add(&mut self, entry: &OtpAuth, notes: Option<String>) -> Result<[u8; 16]> {
        entry.params.validate().map_err(|e| anyhow!("{e}"))?;

        let uuid = crypto::random_bytes::<16>()?;
        let timestamp = now();
        let generation = self.meta.dek_generation;
        let issuer = entry.issuer.clone().unwrap_or_default();
        let record = RecordParams {
            params: entry.params,
            created_at: timestamp,
            updated_at: timestamp,
            notes,
        };

        self.write(|tx, keys| {
            let ct_issuer = seal(keys, &uuid, generation, Column::Issuer, issuer.as_bytes())?;
            let ct_label = seal(keys, &uuid, generation, Column::Label, entry.account.as_bytes())?;
            let ct_secret = seal(keys, &uuid, generation, Column::Secret, &entry.secret)?;
            let ct_params = seal(keys, &uuid, generation, Column::Params, &record.encode())?;

            tx.execute(
                "INSERT INTO accounts (uuid, dek_generation, ct_issuer, ct_label, ct_secret, ct_params)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![&uuid[..], generation as i64, ct_issuer, ct_label, ct_secret, ct_params],
            )?;
            Ok(())
        })?;

        Ok(uuid)
    }

    pub fn delete(&mut self, account: &Account) -> Result<()> {
        let uuid = account.uuid;
        self.write(|tx, _| {
            let n = tx.execute("DELETE FROM accounts WHERE uuid = ?1", [&uuid[..]])?;
            if n == 0 {
                bail!("{}", i18n::no_such_account());
            }
            Ok(())
        })
    }

    /// Renames an account, and optionally replaces its notes.
    pub fn rename(
        &mut self,
        account: &Account,
        issuer: Option<String>,
        label: String,
    ) -> Result<()> {
        let uuid = account.uuid;
        let generation = self.meta.dek_generation;
        let record = RecordParams {
            params: account.params,
            created_at: account.created_at,
            updated_at: now(),
            notes: account.notes.clone(),
        };
        let issuer_text = issuer.unwrap_or_default();

        self.write(|tx, keys| {
            let ct_issuer = seal(keys, &uuid, generation, Column::Issuer, issuer_text.as_bytes())?;
            let ct_label = seal(keys, &uuid, generation, Column::Label, label.as_bytes())?;
            let ct_params = seal(keys, &uuid, generation, Column::Params, &record.encode())?;
            tx.execute(
                "UPDATE accounts SET ct_issuer = ?1, ct_label = ?2, ct_params = ?3, dek_generation = ?4
                 WHERE uuid = ?5",
                rusqlite::params![ct_issuer, ct_label, ct_params, generation as i64, &uuid[..]],
            )?;
            Ok(())
        })
    }

    /// Advances an HOTP counter. Must be persisted immediately after use, or
    /// the counter silently desynchronises from the server.
    pub fn bump_counter(&mut self, account: &Account) -> Result<u64> {
        let OtpKind::Hotp { counter } = account.params.kind else {
            bail!("{}", i18n::not_time_based(&account.display()));
        };
        let next = counter.saturating_add(1);
        let uuid = account.uuid;
        let generation = self.meta.dek_generation;
        let record = RecordParams {
            params: OtpParams {
                kind: OtpKind::Hotp { counter: next },
                ..account.params
            },
            created_at: account.created_at,
            updated_at: now(),
            notes: account.notes.clone(),
        };

        self.write(|tx, keys| {
            let ct_params = seal(keys, &uuid, generation, Column::Params, &record.encode())?;
            tx.execute(
                "UPDATE accounts SET ct_params = ?1 WHERE uuid = ?2",
                rusqlite::params![ct_params, &uuid[..]],
            )?;
            Ok(())
        })?;
        Ok(next)
    }

    /// Re-wraps the DEK under a key derived from the new credentials.
    ///
    /// Only the 32-byte wrapped key changes, in a single transaction. Nothing
    /// else in the vault is rewritten, so a password change cannot be left
    /// half-applied.
    pub fn change_password(&mut self, new_credentials: &Credentials, kdf: KdfParams) -> Result<()> {
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let kek = crypto::derive_kek(new_credentials, &salt, kdf)?;
        let generation = self.meta.dek_generation;
        let aad = Aad::dek_wrap(FORMAT_VERSION, SCHEMA_VERSION, &kdf, &salt, generation);

        let guard = self.keys()?;
        let keys = guard.keys.as_ref().expect("checked by keys()");
        let wrapped = crypto::wrap_dek(&kek, &aad, keys)?;
        drop(guard);

        let mut next = self.meta.clone();
        next.kdf = kdf;
        next.salt = salt.to_vec();
        next.wrapped_dek = wrapped;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        next.vault_serial = self.meta.vault_serial + 1;
        {
            let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
            let keys = guard
                .keys
                .as_ref()
                .ok_or_else(|| anyhow!("{}", i18n::locked_error()))?;
            next.vault_mac = compute_mac(keys.meta_key(), &next, &row_digests_of(&tx)?)?;
        }
        next.update(&tx)?;
        tx.commit()?;

        self.meta = next;
        Ok(())
    }

    /// Runs a mutation, then advances the serial and rewrites the integrity MAC
    /// inside the same transaction, so data and its metadata commit together.
    fn write<T>(
        &mut self,
        body: impl FnOnce(&rusqlite::Transaction<'_>, &VaultKeys) -> Result<T>,
    ) -> Result<T> {
        let Vault {
            conn,
            meta,
            session,
            ..
        } = self;
        let guard = session.lock().unwrap_or_else(|e| e.into_inner());
        let keys = guard
            .keys
            .as_ref()
            .ok_or_else(|| anyhow!("{}", i18n::locked_error()))?;

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let out = body(&tx, keys)?;

        let mut next = meta.clone();
        next.vault_serial = meta.vault_serial + 1;
        next.vault_mac = compute_mac(keys.meta_key(), &next, &row_digests_of(&tx)?)?;
        next.update(&tx)?;
        tx.commit()?;

        *meta = next;
        drop(guard);
        restrict_all(&self.path);
        Ok(out)
    }

    fn keys(&self) -> Result<MutexGuard<'_, Session>> {
        let guard = self.session.lock().unwrap_or_else(|e| e.into_inner());
        if guard.keys.is_none() {
            bail!("{}", i18n::locked_error());
        }
        Ok(guard)
    }

    fn row_digests(&self, conn: &Connection) -> Result<Vec<RowDigest>> {
        row_digests_of(conn)
    }

    /// Folds the WAL back in and tightens permissions. Called on clean exit.
    pub fn close(&self) {
        let _ = schema::checkpoint(&self.conn);
        restrict_all(&self.path);
    }

    // -- diagnostics --------------------------------------------------------

    /// Structural check, integrity check, and a per-account decryption probe.
    ///
    /// Per-row encryption is what makes this possible: a damaged row is named
    /// and every other account keeps working. With whole-file encryption, one
    /// bad page can make the entire vault unopenable.
    pub fn doctor(&self) -> Result<DoctorReport> {
        let integrity: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;

        let guard = self.keys()?;
        let keys = guard.keys.as_ref().expect("checked by keys()");

        let expected = compute_mac(keys.meta_key(), &self.meta, &self.row_digests(&self.conn)?)?;
        let mac_ok = expected.as_slice() == self.meta.vault_mac.as_slice();

        let mut stmt = self
            .conn
            .prepare("SELECT uuid, dek_generation, ct_issuer, ct_label, ct_secret FROM accounts")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;

        let mut total = 0usize;
        let mut damaged = Vec::new();
        for row in rows {
            let (uuid_bytes, generation, ct_issuer, ct_label, ct_secret) = row?;
            total += 1;
            let Ok(uuid) = to_uuid(&uuid_bytes) else {
                damaged.push("<unreadable id>".to_string());
                continue;
            };
            let generation = u32::try_from(generation).unwrap_or(u32::MAX);

            // Named exactly as `ls` names it, so the report can be matched
            // against the listing without guesswork. Whichever half still
            // decrypts is used; if neither does, the raw id is all we have.
            let issuer = decrypt_text(keys, &uuid, generation, Column::Issuer, &ct_issuer).ok();
            let label = decrypt_text(keys, &uuid, generation, Column::Label, &ct_label).ok();
            let name = match (issuer.filter(|i| !i.is_empty()), label) {
                (Some(issuer), Some(label)) if label.is_empty() => issuer,
                (Some(issuer), Some(label)) => format!("{issuer} ({label})"),
                (Some(issuer), None) => issuer,
                (None, Some(label)) => label,
                (None, None) => hex(&uuid),
            };

            if crypto::open_field(
                keys.field_key(),
                &field_aad(&uuid, generation, Column::Secret),
                &ct_secret,
            )
            .is_err()
            {
                damaged.push(name);
            }
        }

        Ok(DoctorReport {
            sqlite_integrity: integrity,
            mac_ok,
            accounts: total,
            damaged,
            wal_active: self.wal_active,
            permission_warning: crate::paths::permission_warning(&self.path),
        })
    }
}

#[derive(Debug)]
pub struct DoctorReport {
    pub sqlite_integrity: String,
    pub mac_ok: bool,
    pub accounts: usize,
    pub damaged: Vec<String>,
    pub wal_active: bool,
    pub permission_warning: Option<String>,
}

impl DoctorReport {
    pub fn is_healthy(&self) -> bool {
        self.sqlite_integrity == "ok" && self.mac_ok && self.damaged.is_empty()
    }
}

/// Raised when the vault-wide MAC does not match. Its own type so callers can
/// present it as a warning rather than a failed unlock.
#[derive(Debug)]
pub struct VaultIntegrityWarning;

impl std::fmt::Display for VaultIntegrityWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&i18n::integrity_warning())
    }
}

impl std::error::Error for VaultIntegrityWarning {}

// ---------------------------------------------------------------------------
// Integrity MAC
// ---------------------------------------------------------------------------

type RowDigest = ([u8; 16], [u8; 32]);

/// Per-row AAD binds a ciphertext to its row, but says nothing about *which*
/// rows should exist. This MAC covers the whole set plus a monotonic serial, so
/// a deleted row, an inserted row, or an older file spliced back in is caught.
///
/// It does not catch a rollback to a genuinely older *complete* state — that
/// would need state kept outside the file — and the README says so.
fn compute_mac(key: &MetaKey, meta: &VaultMeta, rows: &[RowDigest]) -> Result<Vec<u8>> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.raw()).expect("HMAC accepts any key length");

    // Length-prefixed, for the same reason as the AAD encoding: plain
    // concatenation would let an attacker shift a boundary without changing
    // the input.
    let mut part = |bytes: &[u8]| {
        mac.update(&(bytes.len() as u32).to_le_bytes());
        mac.update(bytes);
    };

    part(b"neko-auth/vault-mac/v1");
    part(&[meta.format_version]);
    part(&meta.schema_version.to_le_bytes());
    part(meta.kdf.algorithm_id().as_bytes());
    part(&meta.kdf.m_cost().to_le_bytes());
    part(&meta.kdf.t_cost().to_le_bytes());
    part(&meta.kdf.p_cost().to_le_bytes());
    part(&meta.salt);
    part(&meta.dek_generation.to_le_bytes());
    part(&meta.vault_serial.to_le_bytes());
    part(&(rows.len() as u32).to_le_bytes());

    let mut sorted: Vec<&RowDigest> = rows.iter().collect();
    sorted.sort_by_key(|(uuid, _)| *uuid);
    for (uuid, digest) in sorted {
        part(uuid);
        part(digest);
    }

    Ok(mac.finalize().into_bytes().to_vec())
}

fn row_digests_of(conn: &Connection) -> Result<Vec<RowDigest>> {
    let mut stmt = conn.prepare(
        "SELECT uuid, dek_generation, ct_issuer, ct_label, ct_secret, ct_params FROM accounts",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, Vec<u8>>(5)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (uuid_bytes, generation, issuer, label, secret, params) = row?;
        let uuid = to_uuid(&uuid_bytes)?;
        let mut h = Sha256::new();
        for field in [
            &generation.to_le_bytes()[..],
            &issuer,
            &label,
            &secret,
            &params,
        ] {
            h.update((field.len() as u32).to_le_bytes());
            h.update(field);
        }
        out.push((uuid, h.finalize().into()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn field_aad(uuid: &[u8; 16], generation: u32, column: Column) -> Aad {
    Aad::field(
        FORMAT_VERSION,
        SCHEMA_VERSION,
        Table::Accounts,
        column,
        uuid,
        generation,
    )
}

fn seal(
    keys: &VaultKeys,
    uuid: &[u8; 16],
    generation: u32,
    column: Column,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    crypto::seal_field(
        keys.field_key(),
        &field_aad(uuid, generation, column),
        plaintext,
    )
    .map_err(|e| anyhow!("{e}"))
}

fn decrypt_text(
    keys: &VaultKeys,
    uuid: &[u8; 16],
    generation: u32,
    column: Column,
    blob: &[u8],
) -> Result<String> {
    let bytes = crypto::open_field(keys.field_key(), &field_aad(uuid, generation, column), blob)
        .map_err(|_| corrupt(&hex(uuid)))?;
    String::from_utf8(bytes.to_vec()).with_context(i18n::err_account_name_utf8)
}

fn corrupt(what: &str) -> anyhow::Error {
    anyhow!("{}", i18n::account_integrity_failed(what))
}

fn to_uuid(bytes: &[u8]) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{}", i18n::err_malformed_account_id(bytes.len())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Restricts the database and the sidecars SQLite creates beside it.
///
/// SQLite creates `-wal` and `-shm` using the process umask rather than the
/// main file's mode, so they need tightening separately even after `umask`
/// has been set.
fn restrict_all(path: &Path) {
    let _ = crate::paths::restrict_file(path);
    for sidecar in crate::paths::sidecar_paths(path) {
        let _ = crate::paths::restrict_file(&sidecar);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Algorithm, OtpKind};
    use secrecy::SecretString;

    /// Deliberately far below any real setting: these tests exercise the vault
    /// logic, not the KDF, and 256 MiB per unlock would make them unusable.
    fn fast_kdf() -> KdfParams {
        KdfParams::new(32, 1, 4).unwrap()
    }

    fn creds(email: &str, password: &str) -> Credentials {
        Credentials::new(email, SecretString::from(password.to_string()))
    }

    /// The fixture's credentials.
    fn zoe() -> Credentials {
        creds("zoe@example.com", "hunter2")
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> (Self, Vault) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.db");
            let vault = Vault::create(&path, &zoe(), fast_kdf()).unwrap();
            (Fixture { _dir: dir, path }, vault)
        }

        fn reopen(&self, credentials: &Credentials) -> Result<Vault> {
            let mut v = Vault::open(&self.path, None)?;
            v.unlock(credentials)?;
            Ok(v)
        }
    }

    fn entry(issuer: &str, account: &str) -> OtpAuth {
        OtpAuth {
            issuer: Some(issuer.to_string()),
            account: account.to_string(),
            secret: Zeroizing::new(b"12345678901234567890".to_vec()),
            params: OtpParams::default(),
        }
    }

    #[test]
    fn accounts_survive_a_lock_and_unlock_cycle() {
        let (fx, mut vault) = Fixture::new();
        vault
            .add(&entry("GitHub", "zoe@example.com"), None)
            .unwrap();
        vault.add(&entry("AWS", "root"), None).unwrap();
        vault.close();
        drop(vault);

        let reopened = fx.reopen(&zoe()).unwrap();
        let accounts = reopened.list().unwrap();
        assert_eq!(accounts.len(), 2);
        // Sorted by issuer, case-insensitively, in memory.
        assert_eq!(accounts[0].issuer.as_deref(), Some("AWS"));
        assert_eq!(accounts[1].label, "zoe@example.com");

        // The seed survives, and produces the RFC 6238 vector for this seed.
        let secret = reopened.secret_of(&accounts[1]).unwrap();
        let code = crate::otp::totp(&secret, 59, 30, Algorithm::Sha1, 8).unwrap();
        assert_eq!(code.as_str(), "94287082");
    }

    #[test]
    fn the_wrong_password_is_refused() {
        let (fx, vault) = Fixture::new();
        drop(vault);

        let err = fx
            .reopen(&creds("zoe@example.com", "hunter3"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong"), "{err}");

        // The message must not hint at which half was wrong, nor echo either.
        assert!(!err.contains("hunter"));
        assert!(!err.contains("zoe@example.com"));
    }

    #[test]
    fn a_locked_vault_refuses_reads() {
        let (_fx, mut vault) = Fixture::new();
        vault.add(&entry("GitHub", "me"), None).unwrap();

        vault.lock();
        assert!(!vault.is_unlocked());
        assert!(vault.list().unwrap_err().to_string().contains("locked"));
        assert!(vault.add(&entry("AWS", "root"), None).is_err());

        vault.unlock(&zoe()).unwrap();
        assert_eq!(vault.list().unwrap().len(), 1);
    }

    #[test]
    fn changing_the_password_retires_the_old_one_and_keeps_the_data() {
        let (fx, mut vault) = Fixture::new();
        vault.add(&entry("GitHub", "me"), None).unwrap();
        vault
            .change_password(&creds("zoe@example.com", "new-passphrase"), fast_kdf())
            .unwrap();
        vault.close();
        drop(vault);

        assert!(fx.reopen(&zoe()).is_err());

        let reopened = fx
            .reopen(&creds("zoe@example.com", "new-passphrase"))
            .unwrap();
        let accounts = reopened.list().unwrap();
        assert_eq!(accounts.len(), 1);
        // The data key is unchanged, so previously sealed rows still open.
        assert_eq!(
            reopened.secret_of(&accounts[0]).unwrap().as_slice(),
            b"12345678901234567890"
        );
    }

    #[test]
    fn deleting_a_row_behind_our_back_is_detected() {
        // Per-row AAD cannot notice a missing row: the remaining rows are all
        // individually valid. The vault-wide MAC is what catches it.
        let (fx, mut vault) = Fixture::new();
        vault.add(&entry("GitHub", "me"), None).unwrap();
        vault.add(&entry("AWS", "root"), None).unwrap();
        vault.close();
        drop(vault);

        let conn = rusqlite::Connection::open(&fx.path).unwrap();
        // `accounts` is WITHOUT ROWID, so delete by the primary key.
        conn.execute(
            "DELETE FROM accounts WHERE uuid = (SELECT uuid FROM accounts LIMIT 1)",
            [],
        )
        .unwrap();
        drop(conn);

        let mut vault = Vault::open(&fx.path, None).unwrap();
        let err = vault.unlock(&zoe()).unwrap_err();
        assert!(
            err.downcast_ref::<VaultIntegrityWarning>().is_some(),
            "{err}"
        );

        // The warning must not lock the user out of what remains.
        assert!(vault.is_unlocked());
        assert_eq!(vault.list().unwrap().len(), 1);
        assert!(!vault.doctor().unwrap().mac_ok);
    }

    #[test]
    fn rolling_the_file_back_to_an_earlier_state_is_detected() {
        let (fx, mut vault) = Fixture::new();
        vault.add(&entry("GitHub", "me"), None).unwrap();
        vault.close();
        let old_serial = vault.meta.vault_serial;
        let old_mac = vault.meta.vault_mac.clone();

        vault.add(&entry("AWS", "root"), None).unwrap();
        vault.close();
        drop(vault);

        // Splice the earlier header back in, keeping the newer rows.
        let conn = rusqlite::Connection::open(&fx.path).unwrap();
        conn.execute(
            "UPDATE vault_meta SET vault_serial = ?1, vault_mac = ?2",
            rusqlite::params![old_serial as i64, old_mac],
        )
        .unwrap();
        drop(conn);

        let mut vault = Vault::open(&fx.path, None).unwrap();
        assert!(vault
            .unlock(&zoe())
            .unwrap_err()
            .downcast_ref::<VaultIntegrityWarning>()
            .is_some());
    }

    #[test]
    fn swapping_ciphertext_between_two_accounts_is_caught_per_row() {
        // The scenario the AAD exists for: reading "AWS" must never print the
        // code belonging to "GitHub".
        let (fx, mut vault) = Fixture::new();
        let mut github = entry("GitHub", "me");
        github.secret = Zeroizing::new(b"github-seed-bytes".to_vec());
        let mut aws = entry("AWS", "root");
        aws.secret = Zeroizing::new(b"aws-seed-bytes!!!".to_vec());
        vault.add(&github, None).unwrap();
        vault.add(&aws, None).unwrap();
        vault.close();
        drop(vault);

        let conn = rusqlite::Connection::open(&fx.path).unwrap();
        let stolen: Vec<u8> = conn
            .query_row("SELECT ct_secret FROM accounts LIMIT 1", [], |r| r.get(0))
            .unwrap();
        conn.execute(
            "UPDATE accounts SET ct_secret = ?1 WHERE uuid != (SELECT uuid FROM accounts LIMIT 1)",
            [&stolen],
        )
        .unwrap();
        drop(conn);

        let mut vault = Vault::open(&fx.path, None).unwrap();
        let _ = vault.unlock(&zoe());
        let accounts = vault.list().unwrap();

        // Exactly one account now carries a secret that does not belong to it,
        // and it must refuse to decrypt rather than produce a wrong code.
        let failures = accounts
            .iter()
            .filter(|a| vault.secret_of(a).is_err())
            .count();
        assert_eq!(failures, 1);

        let report = vault.doctor().unwrap();
        assert_eq!(report.damaged.len(), 1);
        assert!(!report.is_healthy());
    }

    #[test]
    fn hotp_counters_advance_and_persist() {
        let (fx, mut vault) = Fixture::new();
        let mut e = entry("Bank", "acct");
        e.params.kind = OtpKind::Hotp { counter: 0 };
        vault.add(&e, None).unwrap();

        let account = vault.list().unwrap().remove(0);
        assert_eq!(vault.bump_counter(&account).unwrap(), 1);
        vault.close();
        drop(vault);

        let reopened = fx.reopen(&zoe()).unwrap();
        assert_eq!(
            reopened.list().unwrap()[0].params.kind,
            OtpKind::Hotp { counter: 1 }
        );
    }

    #[test]
    fn renaming_preserves_the_secret_and_the_creation_time() {
        let (_fx, mut vault) = Fixture::new();
        vault.add(&entry("Old", "name"), None).unwrap();
        let before = vault.list().unwrap().remove(0);

        vault
            .rename(&before, Some("New".into()), "handle".into())
            .unwrap();

        let after = vault.list().unwrap().remove(0);
        assert_eq!(after.issuer.as_deref(), Some("New"));
        assert_eq!(after.label, "handle");
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(
            vault.secret_of(&after).unwrap().as_slice(),
            b"12345678901234567890"
        );
    }

    #[test]
    fn deletion_removes_the_account_and_keeps_the_vault_valid() {
        let (fx, mut vault) = Fixture::new();
        vault.add(&entry("GitHub", "me"), None).unwrap();
        vault.add(&entry("AWS", "root"), None).unwrap();
        let victim = vault.list().unwrap().remove(0);
        vault.delete(&victim).unwrap();
        vault.close();
        drop(vault);

        // Our own delete rewrites the MAC, so reopening must be clean.
        let vault = fx.reopen(&zoe()).unwrap();
        assert_eq!(vault.list().unwrap().len(), 1);
        assert!(vault.doctor().unwrap().is_healthy());
    }

    #[test]
    fn matching_finds_accounts_by_issuer_or_label() {
        let a = Account {
            uuid: [0; 16],
            issuer: Some("GitHub".into()),
            label: "zoe@example.com".into(),
            params: OtpParams::default(),
            created_at: 0,
            updated_at: 0,
            notes: None,
        };
        assert!(a.matches("github"));
        assert!(a.matches("GITHUB"));
        assert!(a.matches("zoe"));
        assert!(a.matches("example.com"));
        assert!(a.matches(""));
        assert!(!a.matches("gitlab"));
    }

    #[test]
    fn the_idle_watchdog_erases_the_keys() {
        let (_fx, vault) = Fixture::new();
        {
            let mut guard = vault.session.lock().unwrap();
            guard.idle_timeout = Some(Duration::from_millis(1));
            guard.last_activity = Instant::now() - Duration::from_secs(60);
        }
        // The watchdog ticks once a second.
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!vault.is_unlocked());
        assert!(vault.list().unwrap_err().to_string().contains("locked"));
    }

    #[cfg(unix)]
    #[test]
    fn the_vault_and_its_sidecars_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (fx, mut vault) = Fixture::new();
        vault.add(&entry("GitHub", "me"), None).unwrap();

        let mut checked = 0;
        for path in std::iter::once(fx.path.clone()).chain(crate::paths::sidecar_paths(&fx.path)) {
            if path.exists() {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} is mode {mode:04o}", path.display());
                checked += 1;
            }
        }
        assert!(checked >= 1);
    }
}
