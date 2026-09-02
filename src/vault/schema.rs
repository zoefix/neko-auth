//! Database layout, connection hardening, and the vault header.
//!
//! The `.db` file is treated as untrusted input throughout. It is the one thing
//! an attacker with disk access can edit, SQLite has had CVEs reachable from a
//! malicious database file, and every number read out of it feeds something
//! that allocates.

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{config::DbConfig, Connection};

use crate::crypto::{KdfParams, FORMAT_VERSION, SALT_LEN};
use crate::i18n;

pub const SCHEMA_VERSION: u32 = 1;

const DDL: &str = r#"
CREATE TABLE vault_meta (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  format_version INTEGER NOT NULL,
  schema_version INTEGER NOT NULL,
  kdf_algorithm  TEXT    NOT NULL,
  kdf_m_cost     INTEGER NOT NULL,
  kdf_t_cost     INTEGER NOT NULL,
  kdf_p_cost     INTEGER NOT NULL,
  kdf_salt       BLOB    NOT NULL,
  dek_generation INTEGER NOT NULL,
  wrapped_dek    BLOB    NOT NULL,
  vault_serial   INTEGER NOT NULL,
  vault_mac      BLOB    NOT NULL
);

CREATE TABLE accounts (
  uuid           BLOB PRIMARY KEY,
  dek_generation INTEGER NOT NULL,
  ct_issuer      BLOB NOT NULL,
  ct_label       BLOB NOT NULL,
  ct_secret      BLOB NOT NULL,
  ct_params      BLOB NOT NULL
) WITHOUT ROWID;
"#;

/// Every object the schema is allowed to contain.
const EXPECTED_OBJECTS: &[(&str, &str)] = &[("table", "vault_meta"), ("table", "accounts")];

/// Opens a connection and applies the hardening pragmas.
pub fn open(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| i18n::err_cannot_open(&path.display().to_string()))?;
    configure(&conn)?;
    Ok(conn)
}

pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    configure(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<()> {
    // Defensive mode blocks direct writes to schema tables and other
    // footguns that a hostile database file could otherwise reach.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;

    conn.execute_batch(
        "PRAGMA trusted_schema = OFF;   -- no views or triggers from a tampered file
         PRAGMA cell_size_check = ON;
         PRAGMA synchronous = FULL;     -- NORMAL can lose the last commits on power loss
         PRAGMA temp_store = MEMORY;    -- temp b-trees must never reach /tmp
         PRAGMA secure_delete = ON;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    Ok(())
}

/// Switches on write-ahead logging, reporting whether it took effect.
///
/// WAL needs shared memory and silently does not engage on a network
/// filesystem — which is exactly where someone puts a vault inside a
/// cloud-sync folder, and where a live SQLite file gets corrupted.
pub fn enable_wal(conn: &Connection) -> Result<bool> {
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    Ok(mode.eq_ignore_ascii_case("wal"))
}

/// Folds the write-ahead log back into the main file so the steady state on
/// disk is a single file. Copying a vault that still has a `-wal` beside it
/// yields a stale or torn backup.
pub fn checkpoint(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(())
}

pub fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(DDL)?;
    Ok(())
}

pub fn is_initialized(conn: &Connection) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'vault_meta'",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Rejects a database whose schema is not exactly what we created.
pub fn validate_schema(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let found: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    for (kind, name) in &found {
        if !EXPECTED_OBJECTS.iter().any(|(k, n)| k == kind && n == name) {
            bail!("{}", i18n::err_unexpected_db_object(kind, name));
        }
    }
    for (kind, name) in EXPECTED_OBJECTS {
        if !found.iter().any(|(k, n)| k == kind && n == name) {
            bail!("{}", i18n::err_missing_db_object(name, kind));
        }
    }
    Ok(())
}

/// The vault header: everything needed to turn a password into the DEK.
#[derive(Debug, Clone)]
pub struct VaultMeta {
    pub format_version: u8,
    pub schema_version: u32,
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    pub dek_generation: u32,
    pub wrapped_dek: Vec<u8>,
    pub vault_serial: u64,
    pub vault_mac: Vec<u8>,
}

/// The header row as SQLite hands it back, before any of it is trusted.
type RawHeader = (
    i64,
    i64,
    String,
    i64,
    i64,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
);

impl VaultMeta {
    pub fn load(conn: &Connection) -> Result<Self> {
        let (fmt, schema, algo, m, t, p, salt, generation, wrapped, serial, mac): RawHeader = conn
            .query_row(
                "SELECT format_version, schema_version, kdf_algorithm, kdf_m_cost, kdf_t_cost,
                        kdf_p_cost, kdf_salt, dek_generation, wrapped_dek, vault_serial, vault_mac
                 FROM vault_meta WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                    ))
                },
            )
            .with_context(i18n::err_header_unreadable)?;

        if fmt != i64::from(FORMAT_VERSION) {
            // Format 1 keyed the vault on a password alone. Naming that is far
            // more useful than "unsupported version", because the remedy is
            // different: there is no upgrade path, the accounts have to be
            // exported from the older build and imported here.
            if fmt == 1 {
                bail!("{}", i18n::err_vault_v1(&path_hint(conn)));
            }
            bail!(
                "{}",
                i18n::err_format_version(fmt as u64, u64::from(FORMAT_VERSION))
            );
        }
        if schema != i64::from(SCHEMA_VERSION) {
            bail!(
                "{}",
                i18n::err_schema_version(schema as u64, u64::from(SCHEMA_VERSION))
            );
        }
        if algo != "argon2id" {
            bail!("{}", i18n::err_unsupported_kdf(&algo));
        }

        // Every number below came off disk, so it is attacker-controlled if the
        // file was tampered with. `KdfParams::new` bounds them; without that,
        // an edited m_cost of u32::MAX is an out-of-memory abort, because
        // argon2 itself performs no upper-bound check.
        let kdf = KdfParams::new(clamp_u32(m)?, clamp_u32(t)?, clamp_u32(p)?)
            .map_err(|e| anyhow!("{}", i18n::err_header_kdf(&e.to_string())))?;

        if salt.len() != SALT_LEN {
            bail!(
                "the vault header has a {}-byte salt; expected {SALT_LEN}",
                salt.len()
            );
        }

        Ok(VaultMeta {
            format_version: FORMAT_VERSION,
            schema_version: SCHEMA_VERSION,
            kdf,
            salt,
            dek_generation: clamp_u32(generation)?,
            wrapped_dek: wrapped,
            vault_serial: serial.max(0) as u64,
            vault_mac: mac,
        })
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO vault_meta
               (id, format_version, schema_version, kdf_algorithm, kdf_m_cost, kdf_t_cost,
                kdf_p_cost, kdf_salt, dek_generation, wrapped_dek, vault_serial, vault_mac)
             VALUES (1, ?1, ?2, 'argon2id', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                self.format_version as i64,
                self.schema_version as i64,
                self.kdf.m_cost() as i64,
                self.kdf.t_cost() as i64,
                self.kdf.p_cost() as i64,
                self.salt,
                self.dek_generation as i64,
                self.wrapped_dek,
                self.vault_serial as i64,
                self.vault_mac,
            ],
        )?;
        Ok(())
    }

    /// Rewrites the header. Used by password change and by every mutation that
    /// advances the serial.
    pub fn update(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "UPDATE vault_meta SET kdf_m_cost = ?1, kdf_t_cost = ?2, kdf_p_cost = ?3,
                    kdf_salt = ?4, dek_generation = ?5, wrapped_dek = ?6,
                    vault_serial = ?7, vault_mac = ?8
             WHERE id = 1",
            rusqlite::params![
                self.kdf.m_cost() as i64,
                self.kdf.t_cost() as i64,
                self.kdf.p_cost() as i64,
                self.salt,
                self.dek_generation as i64,
                self.wrapped_dek,
                self.vault_serial as i64,
                self.vault_mac,
            ],
        )?;
        Ok(())
    }
}

/// The database file's own path, for an error that has no other way to name it.
fn path_hint(conn: &Connection) -> String {
    conn.path().unwrap_or_default().to_string()
}

fn clamp_u32(v: i64) -> Result<u32> {
    u32::try_from(v).map_err(|_| anyhow!("{}", i18n::err_header_out_of_range(v)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        let conn = open_in_memory().unwrap();
        create_schema(&conn).unwrap();
        conn
    }

    fn meta() -> VaultMeta {
        VaultMeta {
            format_version: FORMAT_VERSION,
            schema_version: SCHEMA_VERSION,
            kdf: KdfParams::INTERACTIVE,
            salt: vec![7; SALT_LEN],
            dek_generation: 0,
            wrapped_dek: vec![0; 73],
            vault_serial: 1,
            vault_mac: vec![0; 32],
        }
    }

    #[test]
    fn header_round_trips() {
        let conn = fresh();
        meta().insert(&conn).unwrap();
        let loaded = VaultMeta::load(&conn).unwrap();
        assert_eq!(loaded.kdf, KdfParams::INTERACTIVE);
        assert_eq!(loaded.salt.len(), SALT_LEN);
        assert_eq!(loaded.vault_serial, 1);
    }

    #[test]
    fn a_tampered_m_cost_is_rejected_rather_than_allocated() {
        // The whole point of clamping: 4 TiB of Argon2 memory is a one-byte
        // edit away, and argon2 will happily try to allocate it.
        let conn = fresh();
        meta().insert(&conn).unwrap();
        conn.execute(
            "UPDATE vault_meta SET kdf_m_cost = ?1",
            [i64::from(u32::MAX)],
        )
        .unwrap();

        let err = VaultMeta::load(&conn).unwrap_err().to_string();
        assert!(err.contains("KDF parameters"), "unexpected error: {err}");
    }

    #[test]
    fn a_truncated_salt_is_rejected() {
        let conn = fresh();
        meta().insert(&conn).unwrap();
        conn.execute("UPDATE vault_meta SET kdf_salt = ?1", [vec![1u8; 4]])
            .unwrap();
        assert!(VaultMeta::load(&conn)
            .unwrap_err()
            .to_string()
            .contains("salt"));
    }

    #[test]
    fn only_one_header_row_can_exist() {
        let conn = fresh();
        meta().insert(&conn).unwrap();
        assert!(meta().insert(&conn).is_err());
    }

    #[test]
    fn the_expected_schema_validates() {
        assert!(validate_schema(&fresh()).is_ok());
    }

    #[test]
    fn an_injected_view_is_refused() {
        // A hostile file could define a view or trigger that runs on read.
        let conn = fresh();
        conn.execute_batch("CREATE VIEW sneaky AS SELECT * FROM accounts;")
            .unwrap();
        let err = validate_schema(&conn).unwrap_err().to_string();
        assert!(err.contains("unexpected database object"), "{err}");
    }

    #[test]
    fn a_missing_table_is_refused() {
        let conn = open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE vault_meta (id INTEGER PRIMARY KEY);")
            .unwrap();
        assert!(validate_schema(&conn)
            .unwrap_err()
            .to_string()
            .contains("missing"));
    }

    #[test]
    fn hardening_pragmas_are_actually_in_effect() {
        let conn = open_in_memory().unwrap();
        let secure_delete: i64 = conn
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!(secure_delete, 1);
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 2, "synchronous should be FULL");
        assert!(conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE).unwrap());
    }
}
