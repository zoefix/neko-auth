//! Checking for and installing a new release.
//!
//! This is the only code in neko-auth that opens a socket, and it runs only
//! when the user types `update`. There is no background check, no version ping
//! at startup, and no telemetry: a tool whose selling point is that it stays on
//! your machine should not quietly tell a server how often you use it.
//!
//! An update replaces the running binary, so the download is verified twice
//! over. A SHA-256 checksum alone would only prove the file arrived intact
//! from whoever served it; the Ed25519 signature over the checksum file is
//! what proves the release came from the holder of the signing key, and it is
//! the check that still holds if the GitHub account is compromised.

use std::io::Read;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::i18n;
use crate::ui;

/// Ed25519 public key for release signing, as 64 hex characters.
///
/// Set at build time with `NEKO_AUTH_UPDATE_PUBKEY=<hex> cargo build`. Until a
/// real key is configured, `update` will report new versions but refuse to
/// install one, because an unverifiable download of a binary that holds your
/// TOTP seeds is not something to fall back to silently.
const SIGNING_KEY_HEX: &str = match option_env!("NEKO_AUTH_UPDATE_PUBKEY") {
    Some(hex) => hex,
    None => "",
};

/// Refuse absurd downloads rather than letting a hostile server exhaust memory.
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;
const TIMEOUT_SECS: u64 = 30;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

pub fn run(config: &Config, check_only: bool) -> Result<()> {
    let repo = config.update_repo().trim();
    if repo.is_empty() || repo.starts_with("OWNER/") {
        bail!("{}", i18n::update_no_repo());
    }

    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .with_context(i18n::err_bad_own_version)?;

    ui::note(&i18n::update_contacting(repo));
    let release = fetch_latest(repo)?;

    let latest = semver::Version::parse(release.tag_name.trim_start_matches('v'))
        .with_context(|| i18n::err_release_tag_not_a_version(&release.tag_name))?;

    if latest <= current {
        ui::success(&i18n::update_up_to_date(&current.to_string()));
        return Ok(());
    }

    println!(
        "{} {} → {}",
        ui::bold(&i18n::update_available()),
        current,
        ui::green(&latest.to_string())
    );
    if !release.html_url.is_empty() {
        ui::note(&release.html_url);
    }

    if check_only {
        ui::note(&i18n::update_run_to_install());
        return Ok(());
    }

    let key = signing_key().with_context(i18n::update_no_signing_key)?;

    let wanted = asset_name();
    let archive = find_asset(&release, &wanted)?;
    let sums = find_asset(&release, "SHA256SUMS")?;
    let signature = find_asset(&release, "SHA256SUMS.sig")?;

    ui::note(&i18n::update_downloading());
    let archive_bytes = download(&archive.browser_download_url)?;
    let sums_bytes = download(&sums.browser_download_url)?;
    let signature_bytes = download(&signature.browser_download_url)?;

    // Signature first: the checksum file is untrusted input until it is
    // verified, and only then is the checksum inside it worth comparing.
    verify_signature(&key, &sums_bytes, &signature_bytes)?;
    verify_checksum(&sums_bytes, &wanted, &archive_bytes)?;
    ui::success(&i18n::update_verified());

    let staged = extract_binary(&archive_bytes)?;
    self_replace::self_replace(&staged).with_context(i18n::err_cannot_replace_exe)?;
    let _ = std::fs::remove_file(&staged);

    ui::success(&i18n::update_done(&latest.to_string()));
    ui::note(&i18n::update_vault_untouched());
    Ok(())
}

fn fetch_latest(repo: &str) -> Result<Release> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(TIMEOUT_SECS))
        .timeout_read(std::time::Duration::from_secs(TIMEOUT_SECS))
        .build();

    let response = agent
        .get(&url)
        .set(
            "User-Agent",
            concat!("neko-auth/", env!("CARGO_PKG_VERSION")),
        )
        .set("Accept", "application/vnd.github+json")
        .call()
        .with_context(|| i18n::err_cannot_reach(&url))?;

    response
        .into_json()
        .with_context(i18n::err_github_bad_response)
}

fn download(url: &str) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(TIMEOUT_SECS))
        .timeout_read(std::time::Duration::from_secs(TIMEOUT_SECS * 10))
        .build();

    let response = agent
        .get(url)
        .set(
            "User-Agent",
            concat!("neko-auth/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .with_context(|| i18n::err_cannot_download(url))?;

    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_DOWNLOAD + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DOWNLOAD {
        bail!("{url} is larger than the {MAX_DOWNLOAD} byte limit");
    }
    Ok(bytes)
}

fn signing_key() -> Result<VerifyingKey> {
    if SIGNING_KEY_HEX.is_empty() {
        bail!("no signing key");
    }
    let bytes = decode_hex(SIGNING_KEY_HEX).with_context(i18n::err_signing_key_malformed)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{}", i18n::err_signing_key_malformed()))?;
    VerifyingKey::from_bytes(&array).with_context(i18n::err_signing_key_malformed)
}

fn verify_signature(key: &VerifyingKey, message: &[u8], signature_file: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(signature_file)
        .with_context(i18n::err_signature_file_bad)?
        .trim();
    let bytes = decode_hex(text).with_context(i18n::err_signature_file_bad)?;
    let array: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{}", i18n::err_signature_wrong_length()))?;

    key.verify(message, &Signature::from_bytes(&array))
        .with_context(i18n::update_signature_bad)
}

/// Matches the archive against its line in a `sha256sum`-format file.
fn verify_checksum(sums: &[u8], asset: &str, archive: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(sums).with_context(i18n::err_checksums_not_text)?;
    let expected = text
        .lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(_, name)| name.trim().trim_start_matches('*') == asset)
        .map(|(digest, _)| digest.to_ascii_lowercase())
        .ok_or_else(|| anyhow!("{}", i18n::update_no_checksum_entry(asset)))?;

    let actual = hex(&Sha256::digest(archive));
    if actual != expected {
        bail!("{}", i18n::update_checksum_bad(asset));
    }
    Ok(())
}

/// Unpacks the archive to a temporary file next to the running executable, so
/// the replacement is a rename within one filesystem.
fn extract_binary(archive: &[u8]) -> Result<std::path::PathBuf> {
    let binary_name = if cfg!(windows) {
        "neko-auth.exe"
    } else {
        "neko-auth"
    };
    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder);

    let current = std::env::current_exe().with_context(i18n::err_cannot_locate_exe)?;
    let dir = current.parent().unwrap_or(std::path::Path::new("."));

    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.file_name().and_then(|n| n.to_str()) != Some(binary_name) {
            continue;
        }

        let staged = dir.join(format!("{binary_name}.new"));
        let mut file = std::fs::File::create(&staged)
            .with_context(|| i18n::err_cannot_write(&staged.display().to_string()))?;
        std::io::copy(&mut entry, &mut file)?;
        file.sync_all()?;
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        }
        return Ok(staged);
    }

    bail!("{}", i18n::update_archive_missing_binary(binary_name))
}

/// The release asset for this platform.
fn asset_name() -> String {
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        (os, arch) => return format!("neko-auth-{arch}-{os}.tar.gz"),
    };
    format!("neko-auth-{target}.tar.gz")
}

fn find_asset<'a>(release: &'a Release, name: &str) -> Result<&'a Asset> {
    release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| anyhow!("{}", i18n::update_missing_asset(name)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        bail!("odd number of hex digits");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("not a hex digit"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_are_matched_by_asset_name() {
        let archive = b"release bytes";
        let digest = hex(&Sha256::digest(archive));
        let sums = format!(
            "0000000000000000000000000000000000000000000000000000000000000000  other.tar.gz\n\
             {digest}  neko-auth-x86_64-apple-darwin.tar.gz\n"
        );

        assert!(verify_checksum(
            sums.as_bytes(),
            "neko-auth-x86_64-apple-darwin.tar.gz",
            archive
        )
        .is_ok());

        // A different asset's digest must not satisfy ours.
        assert!(verify_checksum(sums.as_bytes(), "other.tar.gz", archive).is_err());
        // Nor may a missing entry pass silently.
        assert!(verify_checksum(sums.as_bytes(), "absent.tar.gz", archive).is_err());
        // Nor a modified archive.
        assert!(verify_checksum(
            sums.as_bytes(),
            "neko-auth-x86_64-apple-darwin.tar.gz",
            b"tampered"
        )
        .is_err());
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        use ed25519_dalek::{Signer, SigningKey};

        let real = SigningKey::from_bytes(&[7u8; 32]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let message = b"abc123  neko-auth-x86_64-apple-darwin.tar.gz\n";

        let good = hex(&real.sign(message).to_bytes());
        assert!(verify_signature(&real.verifying_key(), message, good.as_bytes()).is_ok());

        // The scenario signing exists for: someone who can serve files but does
        // not hold the release key.
        let forged = hex(&attacker.sign(message).to_bytes());
        assert!(verify_signature(&real.verifying_key(), message, forged.as_bytes()).is_err());

        // And a checksum file edited after signing.
        assert!(verify_signature(&real.verifying_key(), b"tampered", good.as_bytes()).is_err());
    }

    #[test]
    fn an_unconfigured_build_refuses_to_install() {
        // Better to send the user to the release page than to install a binary
        // holding their TOTP seeds without being able to verify it.
        if SIGNING_KEY_HEX.is_empty() {
            assert!(signing_key().is_err());
        }
    }

    #[test]
    fn the_asset_name_matches_the_release_workflow() {
        let name = asset_name();
        assert!(name.starts_with("neko-auth-"), "{name}");
        assert!(name.ends_with(".tar.gz"), "{name}");
    }

    #[test]
    fn hex_decoding_rejects_malformed_input() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }
}
