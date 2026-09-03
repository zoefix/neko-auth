//! End-to-end tests that drive the real binary.
//!
//! `NEKO_AUTH_HOME` points every run at a temporary directory, so a test can
//! never reach a real vault.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::TempDir;

const EMAIL: &str = "zoe@example.com";
const PASSWORD: &str = "correct-horse-battery";

/// What `init` reads: email twice, then password twice.
fn setup_input() -> String {
    format!("{EMAIL}\n{PASSWORD}\n{PASSWORD}\n")
}

/// What every unlock reads: email, then password.
fn unlock_input() -> String {
    format!("{EMAIL}\n{PASSWORD}\n")
}
/// Base32 of the RFC 6238 test seed `12345678901234567890`.
const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn neko(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("neko-auth").expect("binary is built");
    cmd.env("NEKO_AUTH_HOME", home)
        .env("NO_COLOR", "1")
        // These assertions are written against the English text, so the
        // language is pinned rather than inherited from whoever is running
        // the suite.
        .env("LANG", "en_US.UTF-8")
        .env_remove("LC_ALL")
        .env_remove("LC_MESSAGES");
    cmd
}

/// A vault with one known account in it.
fn vault_with_one_account() -> TempDir {
    let dir = tempfile::tempdir().unwrap();

    neko(dir.path())
        .args(["init", "--kdf-profile", "interactive"])
        .write_stdin(setup_input())
        .assert()
        .success();

    neko(dir.path())
        .args([
            "import",
            "uri",
            &format!("otpauth://totp/GitHub:zoe%40example.com?secret={SEED_B32}&issuer=GitHub"),
        ])
        .write_stdin(unlock_input())
        .assert()
        .success();

    dir
}

#[test]
fn a_vault_is_created_populated_listed_and_emptied() {
    let dir = vault_with_one_account();

    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("GitHub").and(contains("zoe@example.com")));

    // Six digits in one run, with no space to strip out after copying.
    neko(dir.path())
        .args(["get", "github"])
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(
            predicates::str::is_match(r"\b\d{6}\b")
                .unwrap()
                .and(predicates::str::is_match(r"\d{3} \d{3}").unwrap().not()),
        );

    neko(dir.path())
        .args(["rm", "github"])
        .write_stdin(format!("{}y\n", unlock_input()))
        .assert()
        .success()
        .stdout(contains("deleted"));

    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("no accounts yet"));
}

#[test]
fn the_wrong_password_fails_without_saying_which_part_was_wrong() {
    let dir = vault_with_one_account();

    neko(dir.path())
        .arg("ls")
        .write_stdin(format!("{EMAIL}\nnot-the-password\nn\n"))
        .assert()
        .failure()
        .stderr(
            contains("wrong email or password")
                .and(contains("not-the-password").not())
                .and(contains(EMAIL).not()),
        );
}

#[test]
fn deleting_asks_first_and_a_refusal_keeps_the_account() {
    let dir = vault_with_one_account();

    neko(dir.path())
        .args(["rm", "github"])
        .write_stdin(format!("{}n\n", unlock_input()))
        .assert()
        .success()
        .stdout(contains("cancelled"));

    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("GitHub"));
}

#[test]
fn a_backup_restores_into_a_fresh_vault_unchanged() {
    let source = vault_with_one_account();
    let backup = source.path().join("vault.nekobak");

    neko(source.path())
        .args(["export", "encrypted", backup.to_str().unwrap()])
        .write_stdin(format!(
            "{}backup-password\nbackup-password\n",
            unlock_input()
        ))
        .assert()
        .success()
        .stdout(contains("wrote 1 account"));

    let destination = tempfile::tempdir().unwrap();
    neko(destination.path())
        .args(["init", "--kdf-profile", "interactive"])
        .write_stdin("other@example.com\nother-vault-password\nother-vault-password\n")
        .assert()
        .success();

    neko(destination.path())
        .args(["restore", backup.to_str().unwrap()])
        .write_stdin("other@example.com\nother-vault-password\nbackup-password\n")
        .assert()
        .success()
        .stdout(contains("added 1 account"));

    neko(destination.path())
        .args(["show", "github"])
        .write_stdin("other@example.com\nother-vault-password\n")
        .assert()
        .success()
        .stdout(contains("zoe@example.com").and(contains("TOTP 6d/30s/SHA1")));
}

#[test]
fn a_backup_will_not_open_with_the_wrong_password() {
    let dir = vault_with_one_account();
    let backup = dir.path().join("vault.nekobak");

    neko(dir.path())
        .args(["export", "encrypted", backup.to_str().unwrap()])
        .write_stdin(format!(
            "{}backup-password\nbackup-password\n",
            unlock_input()
        ))
        .assert()
        .success();

    neko(dir.path())
        .args(["restore", backup.to_str().unwrap()])
        .write_stdin(format!("{}wrong-backup-password\n", unlock_input()))
        .assert()
        .failure()
        .stderr(contains("wrong backup password"));
}

#[test]
fn a_plaintext_export_requires_the_word_to_be_typed() {
    let dir = vault_with_one_account();
    let out = dir.path().join("plain.txt");

    // A bare "y" is not enough for an operation that writes live secrets.
    neko(dir.path())
        .args(["export", "plain", out.to_str().unwrap()])
        .write_stdin(format!("{}y\n", unlock_input()))
        .assert()
        .success()
        .stdout(contains("cancelled"));
    assert!(!out.exists());

    neko(dir.path())
        .args(["export", "plain", out.to_str().unwrap()])
        .write_stdin(format!("{}YES\n", unlock_input()))
        .assert()
        .success();
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("otpauth://totp/"));
}

#[test]
fn a_multi_part_google_export_is_refused_until_every_part_is_present() {
    let dir = vault_with_one_account();
    let parts = google_export_parts();

    let partial = dir.path().join("partial.txt");
    std::fs::write(&partial, format!("{}\n", parts[0])).unwrap();
    neko(dir.path())
        .args(["import", "file", partial.to_str().unwrap()])
        .write_stdin(unlock_input())
        .assert()
        .failure()
        .stderr(contains("still missing").and(contains("parts 2 and 3")));

    let complete = dir.path().join("complete.txt");
    std::fs::write(&complete, parts.join("\n")).unwrap();
    neko(dir.path())
        .args(["import", "file", complete.to_str().unwrap()])
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("added 3 account"));
}

#[test]
fn doctor_reports_a_healthy_vault() {
    let dir = vault_with_one_account();
    neko(dir.path())
        .arg("doctor")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("every account decrypts correctly"));
}

#[test]
fn doctor_names_an_account_whose_ciphertext_was_altered() {
    let dir = vault_with_one_account();

    // Corrupt one byte of the stored secret, as a damaged disk or a meddling
    // process would.
    let db = dir.path().join("vault.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let mut secret: Vec<u8> = conn
        .query_row("SELECT ct_secret FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let last = secret.len() - 1;
    secret[last] ^= 0xFF;
    conn.execute("UPDATE accounts SET ct_secret = ?1", [&secret])
        .unwrap();
    drop(conn);

    neko(dir.path())
        .arg("doctor")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("GitHub"))
        .stderr(contains("failed to decrypt"));
}

#[test]
fn an_ambiguous_name_lists_the_candidates_instead_of_guessing() {
    let dir = vault_with_one_account();
    neko(dir.path())
        .args([
            "import",
            "uri",
            &format!("otpauth://totp/GitLab:zoe%40example.com?secret={SEED_B32}&issuer=GitLab"),
        ])
        .write_stdin(unlock_input())
        .assert()
        .success();

    neko(dir.path())
        .args(["get", "example.com"])
        .write_stdin(unlock_input())
        .assert()
        .failure()
        .stderr(
            contains("matches 2 accounts")
                .and(contains("GitHub"))
                .and(contains("GitLab")),
        );
}

#[test]
fn running_without_a_vault_says_how_to_make_one() {
    let dir = tempfile::tempdir().unwrap();
    neko(dir.path())
        .arg("ls")
        .assert()
        .failure()
        .stderr(contains("neko-auth init"));
}

#[test]
fn the_master_password_has_a_minimum_length() {
    let dir = tempfile::tempdir().unwrap();
    neko(dir.path())
        .args(["init", "--kdf-profile", "interactive"])
        .write_stdin(format!("{EMAIL}\nshort\nshort\n"))
        .assert()
        .failure()
        .stderr(contains("at least"));
}

#[test]
fn a_mistyped_confirmation_does_not_create_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    neko(dir.path())
        .args(["init", "--kdf-profile", "interactive"])
        .write_stdin(format!(
            "{EMAIL}\n{EMAIL}\nfirst-password\nsecond-password\n"
        ))
        .assert()
        .failure()
        .stderr(contains("did not match"));
    assert!(!dir.path().join("vault.db").exists());
}

#[cfg(unix)]
#[test]
fn every_file_the_tool_writes_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = vault_with_one_account();
    let backup = dir.path().join("vault.nekobak");
    neko(dir.path())
        .args(["export", "encrypted", backup.to_str().unwrap()])
        .write_stdin(format!(
            "{}backup-password\nbackup-password\n",
            unlock_input()
        ))
        .assert()
        .success();

    let mut checked = 0;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} is mode {mode:04o}", path.display());
        checked += 1;
    }
    // The vault, its write-ahead sidecars, the config, and the backup.
    assert!(checked >= 3, "only checked {checked} files");
}

/// Three parts of one synthetic Google Authenticator export.
fn google_export_parts() -> Vec<String> {
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }
    fn len_field(field: u32, data: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from(field) << 3 | 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }
    fn varint_field(field: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(field) << 3);
        out.extend(varint(value));
        out
    }

    (0..3)
        .map(|index| {
            let mut account = len_field(1, b"12345678901234567890");
            account.extend(len_field(2, format!("user{index}@example.com").as_bytes()));
            account.extend(len_field(3, format!("Service{index}").as_bytes()));
            account.extend(varint_field(4, 1));
            account.extend(varint_field(5, 1));
            account.extend(varint_field(6, 2));

            let mut body = len_field(1, &account);
            body.extend(varint_field(2, 1));
            body.extend(varint_field(3, 3));
            body.extend(varint_field(4, index));
            body.extend(varint_field(5, 31337));

            let encoded = data_encoding::BASE64
                .encode(&body)
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D");
            format!("otpauth-migration://offline?data={encoded}")
        })
        .collect()
}

#[test]
fn the_interface_language_follows_the_locale_and_the_flag() {
    let dir = vault_with_one_account();

    // The flag wins over everything.
    neko(dir.path())
        .args(["--lang", "ja", "ls"])
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("アカウント"));

    neko(dir.path())
        .args(["--lang", "zh-Hant", "ls"])
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("發行方").and(contains("帳號")));

    // Simplified and traditional must not be the same output.
    neko(dir.path())
        .args(["--lang", "zh-Hans", "ls"])
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("发行方").and(contains("帳號").not()));

    // With no flag, the locale environment decides. LC_ALL and LC_MESSAGES
    // have to be cleared as well: POSIX has them override LANG, CI runners set
    // them, and the program is right to follow that order.
    Command::cargo_bin("neko-auth")
        .unwrap()
        .env("NEKO_AUTH_HOME", dir.path())
        .env("NO_COLOR", "1")
        .env("LANG", "ja_JP.UTF-8")
        .env_remove("LC_ALL")
        .env_remove("LC_MESSAGES")
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("アカウント"));
}

#[test]
fn the_language_setting_persists_across_runs() {
    let dir = vault_with_one_account();

    neko(dir.path())
        .args(["config", "language", "ja"])
        .write_stdin(unlock_input())
        .assert()
        .success();

    // No flag this time: the saved setting must override the English locale
    // the helper pins.
    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("アカウント"));
}

#[test]
fn errors_are_translated_too() {
    let dir = vault_with_one_account();

    neko(dir.path())
        .args(["--lang", "zh-Hans", "ls"])
        .write_stdin(format!("{EMAIL}\nnot-the-password\nn\n"))
        .assert()
        .failure()
        .stderr(contains("邮箱或密码错误"));

    neko(dir.path())
        .args(["--lang", "ja", "get", "nonexistent-account"])
        .write_stdin(unlock_input())
        .assert()
        .failure()
        .stderr(contains("一致するアカウントはありません"));
}

#[test]
fn the_help_text_is_translated() {
    let dir = tempfile::tempdir().unwrap();

    // The description, the subcommand list, and clap's own section headings.
    neko(dir.path())
        .args(["--lang", "zh-Hant", "--help"])
        .assert()
        .success()
        .stdout(
            contains("保險庫")
                .and(contains("列出帳號"))
                .and(contains("用法："))
                .and(contains("指令：")),
        );

    neko(dir.path())
        .args(["--lang", "ja", "--help"])
        .assert()
        .success()
        .stdout(contains("保管庫").and(contains("使い方:")));

    // A leaf subcommand has no Commands section, so its template differs.
    neko(dir.path())
        .args(["--lang", "ja", "get", "--help"])
        .assert()
        .success()
        .stdout(contains("オプション:").and(contains("コマンド:").not()));
}

#[test]
fn the_email_is_a_second_secret_not_a_label() {
    let dir = vault_with_one_account();

    // The right password with the wrong email must not open the vault.
    neko(dir.path())
        .arg("ls")
        .write_stdin(format!("someone@else.com\n{PASSWORD}\n"))
        .assert()
        .failure()
        .stderr(contains("wrong email or password"));

    // And the vault file must not contain the email in any form: storing it,
    // or even a hash of it, would hand an attacker half the secret.
    let raw = std::fs::read(dir.path().join("vault.db")).unwrap();
    let needle = EMAIL.as_bytes();
    assert!(
        !raw.windows(needle.len()).any(|window| window == needle),
        "the email appears in the vault file"
    );
}

#[test]
fn init_shows_the_address_the_vault_will_expect() {
    // It is never stored, so this is the only chance to see what was captured;
    // without it a typo is silent and the vault is unopenable forever.
    let dir = tempfile::tempdir().unwrap();
    neko(dir.path())
        .args(["init", "--kdf-profile", "interactive"])
        .write_stdin(setup_input())
        .assert()
        .success()
        .stdout(contains(EMAIL).and(contains("Write that address down")));
}

#[test]
fn a_mistyped_email_is_caught_when_the_address_is_hidden() {
    // With `hide_email` the address cannot be checked by eye, so it is asked
    // for twice instead.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.toml"), "hide_email = true\n").unwrap();

    neko(dir.path())
        .args(["init", "--kdf-profile", "interactive"])
        .write_stdin("zoe@example.com\nzoe@exmaple.com\n")
        .assert()
        .failure()
        .stderr(contains("did not match"));
    assert!(!dir.path().join("vault.db").exists());
}

#[test]
fn a_hidden_email_vault_still_opens() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.toml"), "hide_email = true\n").unwrap();

    neko(dir.path())
        .args(["init", "--kdf-profile", "interactive"])
        .write_stdin(format!("{EMAIL}\n{EMAIL}\n{PASSWORD}\n{PASSWORD}\n"))
        .assert()
        .success();

    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("no accounts yet"));
}

#[test]
fn the_email_is_matched_case_insensitively() {
    let dir = vault_with_one_account();

    // A vault created with a lowercase address opens from a capitalised one;
    // the alternative is an unopenable vault after an autocorrect.
    neko(dir.path())
        .arg("ls")
        .write_stdin(format!("  Zoe@Example.COM  \n{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("GitHub"));
}

#[test]
fn changing_the_credentials_retires_the_old_pair() {
    let dir = vault_with_one_account();

    neko(dir.path())
        .arg("change-password")
        // Unlock, then re-authenticate, then the new pair twice over: an
        // unattended unlocked terminal must not be enough to change these.
        .write_stdin(format!(
            "{}{}new@example.com\nnew-passphrase\nnew-passphrase\n",
            unlock_input(),
            unlock_input()
        ))
        .assert()
        .success();

    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .failure();

    neko(dir.path())
        .arg("ls")
        .write_stdin("new@example.com\nnew-passphrase\n")
        .assert()
        .success()
        .stdout(contains("GitHub"));
}

#[test]
fn listing_shows_live_codes_rather_than_parameters() {
    let dir = vault_with_one_account();

    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        // A grouped six-digit code, a shared countdown, and no trace of the
        // parameter column it replaced.
        .stdout(
            predicates::str::is_match(r"\b\d{6}\b")
                .unwrap()
                .and(predicates::str::is_match(r"\d{3} \d{3}").unwrap().not())
                .and(contains("refreshes in"))
                .and(contains("TOTP 6d/30s/SHA1").not()),
        );

    // `show` is where the parameters live now.
    neko(dir.path())
        .args(["show", "github"])
        .write_stdin(unlock_input())
        .assert()
        .success()
        .stdout(contains("TOTP 6d/30s/SHA1"));
}

#[test]
fn one_damaged_account_does_not_take_out_the_whole_listing() {
    // Generating codes means `ls` now decrypts every secret, so a single bad
    // row could abort the command. Per-row encryption exists precisely so that
    // it does not.
    let dir = vault_with_one_account();
    neko(dir.path())
        .args([
            "import",
            "uri",
            &format!("otpauth://totp/AWS:root?secret={SEED_B32}&issuer=AWS"),
        ])
        .write_stdin(unlock_input())
        .assert()
        .success();

    let conn = rusqlite::Connection::open(dir.path().join("vault.db")).unwrap();
    let uuid: Vec<u8> = conn
        .query_row("SELECT uuid FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let mut secret: Vec<u8> = conn
        .query_row(
            "SELECT ct_secret FROM accounts WHERE uuid = ?1",
            [&uuid],
            |r| r.get(0),
        )
        .unwrap();
    let last = secret.len() - 1;
    secret[last] ^= 0xFF;
    conn.execute(
        "UPDATE accounts SET ct_secret = ?1 WHERE uuid = ?2",
        rusqlite::params![secret, uuid],
    )
    .unwrap();
    drop(conn);

    neko(dir.path())
        .arg("ls")
        .write_stdin(unlock_input())
        .assert()
        .success()
        // Both accounts are still listed, the intact one still has a code, and
        // the damaged one is marked rather than silently blank.
        .stdout(
            contains("AWS")
                .and(contains("GitHub"))
                .and(contains("??????"))
                .and(predicates::str::is_match(r"\b\d{6}\b").unwrap()),
        )
        .stderr(contains("doctor"));
}

#[test]
fn every_listing_command_is_translated_not_just_some() {
    // Three separate rounds of this work left `show` and `doctor` printing
    // English column headers while everything around them was translated,
    // because a silently-failed source edit looks exactly like a successful
    // one. This asserts the output, not the source.
    let dir = vault_with_one_account();

    for (args, expected, must_not_contain) in [
        (
            vec!["ls"],
            vec!["発行元", "アカウント", "コード"],
            vec!["ISSUER", "TYPE"],
        ),
        (
            vec!["show", "github"],
            vec!["項目", "値", "発行元", "作成日時"],
            vec!["FIELD", "VALUE", "issuer", "created"],
        ),
        (
            vec!["doctor"],
            vec!["保管庫の状態", "アカウント数", "整合性", "正常"],
            vec!["Vault health", "accounts", "sqlite integrity", "MISMATCH"],
        ),
    ] {
        let mut cmd = neko(dir.path());
        cmd.arg("--lang").arg("ja");
        for arg in &args {
            cmd.arg(arg);
        }
        let output = cmd.write_stdin(unlock_input()).assert().success();
        let rendered = String::from_utf8_lossy(&output.get_output().stdout).into_owned();

        for needle in expected {
            assert!(
                rendered.contains(needle),
                "{args:?}: missing `{needle}`\n{rendered}"
            );
        }
        for needle in must_not_contain {
            assert!(
                !rendered.contains(needle),
                "{args:?}: untranslated `{needle}` survived\n{rendered}"
            );
        }
    }
}
