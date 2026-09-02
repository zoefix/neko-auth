//! Where the vault lives, and the file permissions it must have.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub const APP_DIR: &str = "neko-auth";
pub const VAULT_FILE: &str = "vault.db";
pub const CONFIG_FILE: &str = "config.toml";

/// Environment overrides. `NEKO_AUTH_VAULT` names a database file directly;
/// `NEKO_AUTH_HOME` names a directory holding both the vault and the config,
/// which is also how the test suite keeps runs isolated from a real vault.
pub const ENV_VAULT: &str = "NEKO_AUTH_VAULT";
pub const ENV_HOME: &str = "NEKO_AUTH_HOME";

/// Resolves the vault path: explicit flag, then environment, then platform
/// default.
pub fn vault_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = std::env::var_os(ENV_VAULT) {
        return Ok(PathBuf::from(p));
    }
    Ok(data_dir()?.join(VAULT_FILE))
}

pub fn config_path() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os(ENV_HOME) {
        return Ok(PathBuf::from(home).join(CONFIG_FILE));
    }
    let dir = dirs::config_dir().with_context(crate::i18n::err_no_config_dir)?;
    Ok(dir.join(APP_DIR).join(CONFIG_FILE))
}

/// The per-user data directory.
///
/// On Windows this is `%LOCALAPPDATA%`, not `%APPDATA%`: the roaming profile is
/// synchronised to a domain server on login, and a vault has no business
/// travelling across a network by default.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os(ENV_HOME) {
        return Ok(PathBuf::from(home));
    }
    let dir = dirs::data_local_dir().with_context(crate::i18n::err_no_data_dir)?;
    Ok(dir.join(APP_DIR))
}

/// Creates the directory if needed, owner-only.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| crate::i18n::err_cannot_create(&dir.display().to_string()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dir)?.permissions();
        if perms.mode() & 0o077 != 0 {
            perms.set_mode(0o700);
            std::fs::set_permissions(dir, perms)
                .with_context(|| crate::i18n::err_cannot_restrict(&dir.display().to_string()))?;
        }
    }
    Ok(())
}

/// Restricts a file to its owner. A no-op on Windows, where the containing
/// `%LOCALAPPDATA%` directory's ACL already limits access to the user, SYSTEM
/// and Administrators. Hand-rolled DACL manipulation is deliberately avoided:
/// it is easy to get wrong, and buys nothing against a local administrator.
pub fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let mut perms = std::fs::metadata(path)?.permissions();
            if perms.mode() & 0o777 != 0o600 {
                perms.set_mode(0o600);
                std::fs::set_permissions(path, perms).with_context(|| {
                    format!("cannot restrict permissions on {}", path.display())
                })?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Reports a vault file readable by anyone but its owner.
///
/// This catches the realistic case of a vault restored from a tarball or a
/// backup that lost its mode bits. It warns rather than refusing: the data is
/// encrypted, and locking a user out of their own 2FA over a permission bit
/// would be worse than the leak of knowing how many accounts they have.
pub fn permission_warning(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(crate::i18n::permissions_too_open(
                &path.display().to_string(),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    None
}

/// SQLite creates `-wal` and `-shm` beside the database using the process
/// umask rather than the main file's mode, so they need restricting too.
pub fn sidecar_paths(db: &Path) -> Vec<PathBuf> {
    let name = db
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let parent = db.parent().unwrap_or(Path::new("."));
    ["-wal", "-shm", "-journal"]
        .iter()
        .map(|suffix| parent.join(format!("{name}{suffix}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecars_sit_beside_the_database() {
        let db = Path::new("/tmp/x/vault.db");
        let names: Vec<String> = sidecar_paths(db)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["vault.db-wal", "vault.db-shm", "vault.db-journal"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_vault_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vault.db");
        std::fs::write(&file, b"x").unwrap();

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(permission_warning(&file).is_some());

        restrict_file(&file).unwrap();
        assert!(permission_warning(&file).is_none());
    }
}
