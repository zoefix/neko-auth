//! Canonical associated-data encoding.
//!
//! Every ciphertext in the vault is bound to *where it lives*: which table,
//! which column, which row, under which DEK generation. Without that binding,
//! an attacker with write access to the vault file could copy the `ct_secret`
//! blob from one account onto another account's row. The Poly1305 tag would
//! still verify, and neko-auth would print account A's code while labelling it
//! account B. Displaying codes is this program's entire job, so a swapped
//! secret is directly exploitable.
//!
//! Two rules make the encoding safe:
//!
//! * Every component is length-prefixed. Naive concatenation is ambiguous:
//!   `("ab", "c")` and `("a", "bc")` produce identical bytes, which would let
//!   an attacker shift a boundary without changing the AAD.
//! * [`Aad`] cannot be constructed from raw bytes, only through the
//!   constructors below. "Forgot to pass the AAD" is not expressible.

use crate::crypto::KdfParams;

/// Domain separator. Present so that a blob from some other program that
/// happens to use the same primitives can never authenticate here.
const DOMAIN: &[u8] = b"neko-auth";

/// Which table a ciphertext lives in.
///
/// An enum rather than a `&str`: a typo in a string literal would silently
/// change the AAD, and the resulting failure would look like data corruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    VaultMeta,
    Accounts,
}

impl Table {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Table::VaultMeta => b"vault_meta",
            Table::Accounts => b"accounts",
        }
    }
}

/// Which column a ciphertext lives in.
///
/// Binding this stops an attacker from relocating the `secret` blob into the
/// `label` column, where it would be printed to the screen in plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    Issuer,
    Label,
    Secret,
    Params,
}

impl Column {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Column::Issuer => b"ct_issuer",
            Column::Label => b"ct_label",
            Column::Secret => b"ct_secret",
            Column::Params => b"ct_params",
        }
    }
}

/// Authenticated associated data. Opaque by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad(Vec<u8>);

impl Aad {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// AAD for a per-account field.
    ///
    /// `row_uuid` must be the account's random 16-byte id, never the SQLite
    /// rowid: without `AUTOINCREMENT`, rowids are reused after a delete, so an
    /// attacker could delete a row, let its id be reissued to a new account,
    /// and splice the old ciphertext back in — and it would verify.
    pub fn field(
        format_version: u8,
        schema_version: u32,
        table: Table,
        column: Column,
        row_uuid: &[u8; 16],
        dek_generation: u32,
    ) -> Self {
        let mut w = Writer::new();
        w.part(DOMAIN);
        w.part(&[format_version]);
        w.part(&schema_version.to_le_bytes());
        w.part(table.as_bytes());
        w.part(column.as_bytes());
        w.part(row_uuid);
        w.part(&dek_generation.to_le_bytes());
        Aad(w.finish())
    }

    /// AAD for the wrapped data-encryption key.
    ///
    /// The KDF parameters and salt are included deliberately. An attacker who
    /// edits `kdf_m_cost` down to 8 KiB to make brute-forcing cheap will find
    /// that the unwrap fails authentication, because only the original
    /// parameters reconstruct a valid AAD. The parameters are therefore
    /// authenticated by the wrap itself, with no extra storage.
    pub fn dek_wrap(
        format_version: u8,
        schema_version: u32,
        kdf: &KdfParams,
        salt: &[u8],
        dek_generation: u32,
    ) -> Self {
        let mut w = Writer::new();
        w.part(DOMAIN);
        w.part(b"dek-wrap");
        w.part(&[format_version]);
        w.part(&schema_version.to_le_bytes());
        w.part(kdf.algorithm_id().as_bytes());
        w.part(&kdf.m_cost().to_le_bytes());
        w.part(&kdf.t_cost().to_le_bytes());
        w.part(&kdf.p_cost().to_le_bytes());
        w.part(salt);
        w.part(&dek_generation.to_le_bytes());
        Aad(w.finish())
    }
}

impl Aad {
    /// AAD for a `.nekobak` archive body: the archive's own header.
    ///
    /// Binding the whole header means editing the stored cost parameters to
    /// make the file cheaper to attack simply makes it unreadable instead.
    pub fn backup(header: &[u8]) -> Self {
        let mut w = Writer::new();
        w.part(DOMAIN);
        w.part(b"backup");
        w.part(header);
        Aad(w.finish())
    }
}

/// Length-prefixed byte-string concatenation.
struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Writer(Vec::with_capacity(128))
    }

    fn part(&mut self, bytes: &[u8]) {
        // A u32 length is plenty: every component here is a fixed-size id or a
        // short constant. Nothing user-controlled reaches this encoder.
        debug_assert!(bytes.len() <= u32::MAX as usize);
        self.0
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.0.extend_from_slice(bytes);
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn length_prefixing_removes_boundary_ambiguity() {
        // The classic failure: with naive concatenation, moving a character
        // across a component boundary leaves the AAD unchanged. It must not.
        let mut a = Writer::new();
        a.part(b"ab");
        a.part(b"c");
        let mut b = Writer::new();
        b.part(b"a");
        b.part(b"bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn aad_differs_across_every_bound_component() {
        let base = Aad::field(1, 1, Table::Accounts, Column::Secret, &uuid(1), 0);

        // Different row: blocks copying a secret between accounts.
        assert_ne!(
            base,
            Aad::field(1, 1, Table::Accounts, Column::Secret, &uuid(2), 0)
        );
        // Different column: blocks moving a secret into a displayed field.
        assert_ne!(
            base,
            Aad::field(1, 1, Table::Accounts, Column::Label, &uuid(1), 0)
        );
        // Different table.
        assert_ne!(
            base,
            Aad::field(1, 1, Table::VaultMeta, Column::Secret, &uuid(1), 0)
        );
        // Different DEK generation: stale rows are detectable after rotation.
        assert_ne!(
            base,
            Aad::field(1, 1, Table::Accounts, Column::Secret, &uuid(1), 1)
        );
        // Different format version: blocks forcing a downgrade.
        assert_ne!(
            base,
            Aad::field(2, 1, Table::Accounts, Column::Secret, &uuid(1), 0)
        );
        // Different schema version.
        assert_ne!(
            base,
            Aad::field(1, 2, Table::Accounts, Column::Secret, &uuid(1), 0)
        );
    }

    #[test]
    fn dek_wrap_aad_covers_kdf_parameters() {
        let salt = [7u8; 32];
        let a = KdfParams::new(65536, 3, 4).unwrap();
        let b = KdfParams::new(32, 3, 4).unwrap();
        // Weakening m_cost must invalidate the wrap rather than being accepted.
        assert_ne!(
            Aad::dek_wrap(1, 1, &a, &salt, 0),
            Aad::dek_wrap(1, 1, &b, &salt, 0)
        );
    }
}
