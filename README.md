<div align="center">

# Neko Auth

---

Two-factor codes that never leave your machine. A command-line authenticator
with an encrypted local vault, unlocked by an email and a password that are
stored nowhere.

[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md)

![Version](https://img.shields.io/badge/VERSION-v0.1.3-8A2BE2?style=for-the-badge&labelColor=444)
![Platform](https://img.shields.io/badge/PLATFORM-MACOS%20%7C%20LINUX%20%7C%20WINDOWS-00B5E2?style=for-the-badge&labelColor=444)
![Rust](https://img.shields.io/badge/RUST-1.82%2B-000000?style=for-the-badge&labelColor=444)
![Licence](https://img.shields.io/badge/LICENCE-MIT-F5A623?style=for-the-badge&labelColor=444)

</div>

## What this is

Two-factor secrets go into a local, encrypted SQLite vault. Nothing is synced,
nothing is uploaded, and there is no account to sign in to. There is no
network code in the program at all — no update check, no telemetry, and no HTTP
client anywhere in its dependency tree.

Even if your laptop is stolen or the SQLite database file is copied, the contents remain inaccessible without your email and password—everything is protected by your password.

```
$ neko-auth
Email: zoe@example.com
Master password:

neko-auth 0.1.3
vault: ~/.local/share/neko-auth/vault.db
auto-locks after 300s idle
press / to list commands, `exit` to leave

neko-auth › get github
GitHub (zoe@example.com)
  123456   █████████░░░ 22s
```

---

## Install

**macOS, Linux, WSL:**

```bash
curl -fsSL https://raw.githubusercontent.com/zoefix/neko-auth/main/install.sh | sh
```

**Windows PowerShell:**

```powershell
irm https://raw.githubusercontent.com/zoefix/neko-auth/main/install.ps1 | iex
```

**Windows CMD:**

```
curl -fsSL https://raw.githubusercontent.com/zoefix/neko-auth/main/install.cmd -o install.cmd && install.cmd
```

The installer downloads the release build for your machine, checks it against
the published checksums, puts it on your PATH, and stops. It creates no vault
and asks for nothing. Open a new terminal, then:

```bash
neko-auth init
```

Piping a script into a shell runs whatever that URL serves, so read it first if
you would rather — [install.sh](install.sh) is about a hundred lines.
`NEKO_AUTH_INSTALL_DIR` changes where the binary goes and `NEKO_AUTH_NO_PATH=1`
leaves your shell startup files alone.

### From source

```bash
cargo install --git https://github.com/zoefix/neko-auth
```

The result is one static binary with no runtime dependencies; SQLite is
compiled in. To build without the QR-image decoder (which pulls in the `image`
crate, a large parsing surface):

```bash
cargo build --release --no-default-features
```

---

## Getting started

```bash
neko-auth init            # create the vault and choose a master password
neko-auth                 # open the interactive session
```

### Moving off Google Authenticator

1. In the app: **⋮ → Transfer accounts → Export accounts**, pick the accounts,
   and let it show the QR code(s).
2. Screenshot each code. **Large account lists are split across several codes**
   — screenshot all of them.
3. Import them all at once:

```bash
neko-auth import qr part1.png part2.png part3.png
```

A partial import is refused. If you hand it two of three codes it will say so
and store nothing, rather than leaving you believing you have migrated while
most accounts are still only on the phone.

Export codes are dense — version 20 and up — and the decoder's binarisation is
sensitive to how many pixels each module covers, so a screenshot that a phone
reads instantly can fail at its native resolution. Each image is therefore
retried at several scales before it is given up on. If one still will not read,
crop the screenshot down to the code itself and try again.

4. **Verify before you delete anything from your phone.** Compare a few codes
   side by side:

```bash
neko-auth watch
```

Only once the codes match should you consider removing the phone app — and
even then, keeping a second factor on a second device is usually wiser than
having exactly one copy.

### Other ways in

```bash
neko-auth import uri            # paste an otpauth:// URI at a hidden prompt
neko-auth import file list.txt  # a file of otpauth:// or migration URIs
neko-auth add                   # type a Base32 secret from a "can't scan?" link
```

Secrets are never accepted as command-line arguments. `argv` is visible to
every process on the machine through `ps`, and a non-interactive invocation
would also leave the secret in your shell history.

---

## Commands

Everything works both inside the session and as a one-shot command.

| | |
|---|---|
| `ls [pattern]` | list accounts with their current codes |
| `get <name> [-c]` | print one code; `-c` copies it to the clipboard |
| `watch [pattern]` | full-screen live view with countdowns |
| `add` | add an account at a hidden prompt |
| `import uri｜qr｜file` | import from a URI, QR images, or a text file |
| `rm <name>` | delete an account, after confirmation |
| `rename <name>` | change an account's issuer or label |
| `show <name>` | settings for one account, without its secret |
| `reveal <name>` | print the shared secret; requires typing `REVEAL` |
| `export encrypted <path>` | write an encrypted `.nekobak` backup |
| `export plain <path>` | write plaintext `otpauth://` URIs; requires typing `YES` |
| `restore <path>` | import from an encrypted backup |
| `passwd` | change the email and master password |
| `doctor` | check the vault for damage |
| `config [key] [value]` | show or change settings |
| `lang [code]` | show or switch the interface language |
| `lock` | erase the keys from memory now |

Typing `/` lists the commands straight away, and narrows as you keep typing — `/re`
leaves `rename reveal restore`. A leading `/` is accepted on every command, so
`/help` works as well as `help`.

The session runs on the terminal's alternate screen, so `exit` takes its output
with it — the account list does not stay in the scrollback of a terminal anyone
can later scroll back through. `config keep_scrollback true` turns that off.

Tab completes commands and account names, and history is kept **in memory
only**. `show coinbase` is itself sensitive — it says which services
you have accounts with — and has no business outliving the session.

### Backups

```bash
neko-auth export encrypted ~/vault.nekobak
```

`.nekobak` is a self-contained, versioned, encrypted archive, deliberately not
a copy of the SQLite file: a backup should outlive the schema that produced it,
and ideally the program too. Its byte layout is documented at the top of
[`src/export.rs`](src/export.rs) in enough detail to re-implement in about
fifty lines.

`export plain` writes your secrets as ordinary `otpauth://` URIs. It exists
because they are **your** secrets and you must be able to leave — but it asks
you to type `YES`, writes the file `0600`, and tells you to delete it
afterwards.

### Leaving

`export plain` produces URIs any other authenticator will accept. There is no
lock-in here.

---

## The email

The vault key is derived from the email address **and** the password, not from
the password alone:

```
Argon2id( "neko-auth/identity/v1" ‖ len(email) ‖ email ‖ len(password) ‖ password , salt )
```

Every part is length-prefixed. Plain concatenation would be ambiguous in a way
that matters: `("a@b.com", "xyz")` and `("a@b.co", "mxyz")` join to the same
string, so one pair would open a vault created with the other.

The address is **not stored anywhere** — that is the whole point of it. Storing
it, or even a hash of it, would hand half the secret to anyone who copies the
file, and it would be no better than the 32-byte random salt already there.

**The address is echoed as you type it; the password is not.** That asymmetry
is deliberate. What protects the vault is that the address is not *in the
file*, and that holds whether or not it appears on screen. Hiding it would
defend only against someone reading over your shoulder — outside the threat
model above — while costing something real: with both halves invisible, a
mistyped address cannot be noticed when you make it and is indistinguishable
from a wrong password ever after. `neko-auth init` also prints the normalised
address back once it is done, because that is the only moment you will ever see
what the vault actually expects.

If you would rather have it hidden, `config hide_email true` restores that, and
the address is then confirmed twice at setup instead of being checked by eye.

Consequences worth knowing before you commit to it:

- A wrong address and a wrong password give the same message. That is not
  coyness: the authentication tag genuinely cannot tell which half was wrong.
- The address is trimmed and lowercased before use, so `Zoe@Example.com` and
  `zoe@example.com` are the same. RFC 5321 does make the local part
  case-sensitive; no mail provider treats it that way, and an unopenable vault
  is a far worse outcome than the theoretical mismatch.
- **Write down which address you used**, with your backup. It is a secret, so
  keep it where you would keep the password — but it is a secret you are much
  more likely to misremember than one you chose deliberately.

A `.nekobak` backup keeps its own single password by default, since it is a
standalone file. `export encrypted --same-password` keys it on the same
email-and-password pair you unlock with.

---

## Language

neko-auth speaks English, 简体中文, 繁體中文 and 日本語. It follows your locale
by default, so on a system set to Japanese it starts in Japanese with no
configuration.

```bash
neko-auth --lang zh-Hant          # just this run
neko-auth config language ja      # remembered
```

or from inside the session:

```
neko-auth › lang
neko-auth › lang zh-Hans
```

Accepted values are `auto` (follow `$LC_ALL`, `$LC_MESSAGES` or `$LANG`), `en`,
`zh-Hans`, `zh-Hant` and `ja`. POSIX locale names work too, so `--lang
zh_TW.UTF-8` does what you would expect.

Traditional Chinese is written in Taiwanese usage (檔案, 設定, 網路, 金鑰)
rather than converted character by character from the simplified text, which is
the usual way this kind of localisation reads wrong.

Two things stay in English on purpose:

- The words you type to confirm a destructive action — `YES` and `REVEAL`.
  They are fixed tokens; a translated one is just another way to mistype
  something irreversible.
- clap's own argument-parsing errors ("unexpected argument", and similar).
  Everything neko-auth writes is translated, including `--help`, but the
  library's internal strings are not reachable from outside it.

Adding a language means adding one arm to each entry in
[`src/i18n/messages.rs`](src/i18n/messages.rs). The macro requires every
language for every message, so a missing translation is a compile error rather
than a string that silently falls back to English.

---

## How it works

### Key hierarchy

```
email + password ─Argon2id(salt, m/t/p)──▶ KEK
                                            │
                                            └─ unwraps ─▶ DEK (random, stored wrapped)
                                                           │
                                          ┌────────────────┴────────────────┐
                                     field key                          meta key
                                per-field encryption              vault-wide signature
```

The two layers exist for correctness, not speed. Changing the credentials
re-wraps 32 bytes in one transaction, which is atomic. Re-encrypting an entire
vault is not, and a half-completed change is a data-loss event.

**Verification is the DEK unwrap and nothing else.** Wrong credentials give a
wrong KEK, which fails the AEAD tag. There is deliberately no stored password
hash to check against, and no stored email hash either: the first is the
classic mistake in this kind of tool — a check billions of times cheaper than
the Argon2id it is meant to protect — and the second would give away half of a
secret that is otherwise nowhere on disk.

There is also deliberately **no failed-attempt counter and no self-destruct**.
An attacker copies the file and works on it offline, where no counter of ours
runs. All such a feature can do is give you a way to destroy your own second
factors by accident.

### Encryption

- **Argon2id**, 256 MiB / 3 passes / 4 lanes by default (`--kdf-profile
  interactive` for 64 MiB, `paranoid` for 1 GiB). The parameters are stored in
  the vault, because they are part of the hash function — a vault created on
  one machine has to open on another. They are bounds-checked on the way back
  in: `argon2` performs no upper-bound check of its own, so a one-byte edit of
  the stored `m_cost` would otherwise be an out-of-memory abort.
- **XChaCha20-Poly1305** for every field. The 192-bit nonce is what makes
  random nonces unconditionally safe. AES-GCM's 96-bit nonce pushes you toward
  a counter, and a counter in a database you can restore from backup is a trap:
  restore last month's copy, add two accounts, and you have reused one. A
  reused GCM nonce leaks the authentication key.
- **Every ciphertext is bound to its location** — table, column, row id, key
  generation, format version, each length-prefixed — as the AEAD's associated
  data. Without it, someone with write access to the file could copy one
  account's encrypted secret onto another's row, and neko-auth would print
  account A's code while labelling it account B. Displaying codes is this
  program's whole job, so a swapped secret is directly exploitable.
- **The KDF parameters are authenticated by the key wrap.** Editing `m_cost`
  down to make cracking cheap does not weaken the vault; it makes it
  unopenable.
- **A vault-wide HMAC** over the row set and a monotonic serial catches deleted
  rows, inserted rows, and old files with new rows spliced in. Per-row binding
  cannot see any of those, because each surviving row is individually valid.

### What is stored in the clear

Two columns: a random 16-byte account id and a key-generation counter. Plus,
unavoidably, the number of rows.

Timestamps are inside the encrypted blob rather than in columns, because
plaintext `created_at`/`updated_at` is a behavioural profile — when you set up
each second factor, and when you last touched it. Sorting happens in memory;
an order-preserving column would leak the alphabetical ordering of your issuer
names.

### Process hygiene

At startup, before anything sensitive exists: core dumps disabled, `umask`
set to `0077` (SQLite creates its `-wal` and `-shm` files with the process
umask, not the database's mode), and a panic hook that prints a fixed message
instead of a payload that might contain a decrypted value.

The release profile deliberately does **not** set `panic = "abort"`. It sounds
safer and is backwards here: aborting skips unwinding, which skips `Drop`,
which skips every zeroization.

---

## Storage

| | |
|---|---|
| Linux | `$XDG_DATA_HOME/neko-auth/` (default `~/.local/share/neko-auth/`) |
| macOS | `~/Library/Application Support/neko-auth/` |
| Windows | `%LOCALAPPDATA%\neko-auth\` |

`%LOCALAPPDATA%` rather than `%APPDATA%` on purpose: the roaming profile is
copied to a domain server at login, and a vault should not travel across a
network by default.

Override with `--vault <path>` or `NEKO_AUTH_VAULT`; `NEKO_AUTH_HOME` moves the
whole directory.

On Unix the vault, its sidecars and every export are `0600`, and a
group- or world-readable vault produces a warning at startup — which is how a
restore from a badly-made tarball gets noticed. On Windows there is no mode
bit; `%LOCALAPPDATA%`'s default ACL already restricts access to you, SYSTEM and
Administrators, and hand-rolled DACL code would add risk without adding
protection against a local administrator.

**Do not put the vault in Dropbox, iCloud Drive or OneDrive.** A live SQLite
file plus a sync client is a corruption factory. neko-auth warns when the
write-ahead log will not engage, which is the usual symptom. Keep the vault on
local disk and use `export encrypted` for backups.

---

## Upgrading

Re-run the install command for your platform. It replaces the binary and does
not touch the vault.

macOS, Linux, WSL:

```bash
curl -fsSL https://raw.githubusercontent.com/zoefix/neko-auth/main/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/zoefix/neko-auth/main/install.ps1 | iex
```

There is no `update` command, and no way to add one at runtime: the binary
contains no HTTP client, so there is nothing in it that could fetch a
replacement. Upgrading is a separate program you run deliberately.

That is the trade, stated plainly. You give up one-command upgrades. In return,
the process holding your TOTP secrets has no code in it that can reach another
machine — which means a bug in it cannot be turned into one that phones home,
and you do not have to trust a self-replacing binary to overwrite itself
correctly. A `cargo tree` on this project turns up no HTTP client, no TLS
stack, no DNS resolver, and no async runtime, and a test in the suite fails if
one ever appears.

If you would rather check the shipped binary than the source, `nm -u` on the
macOS build lists 200 imported symbols, of which the only socket-related ones
are `socketpair`, `send` and `recv`. Those come from crossterm, which polls
the terminal for key events using an unnamed `AF_UNIX` socket pair as a
self-pipe — one byte written to wake the reader, one read to drain it. A pair
like that has no address and cannot be connected to; it is local IPC between
two file descriptors in one process.

`neko-auth update` still answers, rather than reporting an unknown command, but
only to say the above and point you back here.

The installer verifies a download twice: an Ed25519 signature over the checksum
file, then the SHA-256 of the archive against that file. A checksum alone would
only prove the bytes arrived intact from whoever served them; the signature is
the check that still holds if the GitHub account is compromised. The public key
is built into the install script rather than downloaded next to the signature,
because a key fetched from the same place as the signature proves nothing.
Releases are not signed yet — until they are, the installer verifies the
checksum and tells you the signature was skipped.

---

## Recovering from damage

```bash
neko-auth doctor
```

Runs SQLite's integrity check, verifies the vault signature, and then tries to
decrypt every account, **naming the ones that fail while the rest keep
working**. That last part is the practical payoff of encrypting field by field
rather than encrypting the whole file: with whole-file encryption, one bad page
in the wrong place can make the entire vault unopenable.

---

## Development

```bash
cargo test                       # unit and integration tests
cargo test --no-default-features # the minimal build
cargo clippy --all-targets
```

The TOTP implementation is checked against the official RFC 4226 and RFC 6238
test vectors, including the SHA-256 and SHA-512 cases, which use differently
sized seeds — reusing the 20-byte SHA-1 seed for all three is the standard
mistake, and it produces vectors that look plausible and are wrong.

The security-critical claims have tests that state them directly: flipping any
byte of a ciphertext is rejected; a secret moved to another account's row will
not decrypt; a secret moved into a displayed column will not decrypt; weakening
the stored KDF parameters breaks the key wrap; a deleted row is caught by the
vault signature; every file the tool writes is `0600`; and a rearranged
email-and-password pair does not derive the same key.

The translations are tested too: that arguments interpolate in every language,
that counted phrases inflect in English and not in the others, and that the
traditional Chinese entries use Taiwanese rather than mainland vocabulary.

## Licence

MIT. See [LICENSE](LICENSE).
