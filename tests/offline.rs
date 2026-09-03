//! Guards for the one property the whole design rests on: this program does
//! not talk to the network.
//!
//! Up to 0.1.2 that was a claim with an exception (`update` fetched releases
//! over HTTPS). The exception is gone, which turns the claim into something
//! worth enforcing mechanically — a single careless dependency is all it takes
//! to put an HTTP stack back into a binary that holds TOTP secrets.

use std::path::Path;

/// Crates that exist to move bytes over a network, or to secure bytes that are
/// about to be. Matched against the resolved lockfile, so a transitive
/// dependency counts the same as a direct one.
///
/// Not exhaustive, and cannot be: it is a tripwire for the realistic
/// regression — someone adds a convenient crate and does not notice that it
/// dragged in a whole TLS stack.
const NETWORK_CRATES: &[&str] = &[
    // HTTP clients and servers
    "reqwest",
    "ureq",
    "hyper",
    "hyper-util",
    "isahc",
    "surf",
    "attohttpc",
    "curl",
    "curl-sys",
    "http",
    "http-body",
    "h2",
    "h3",
    "actix-web",
    "axum",
    "tiny_http",
    "rouille",
    "warp",
    "tide",
    // TLS
    "rustls",
    "native-tls",
    "openssl",
    "openssl-sys",
    "schannel",
    "security-framework",
    "boring",
    "tokio-rustls",
    "webpki",
    "rustls-webpki",
    "webpki-roots",
    "rustls-native-certs",
    "ring",
    // async runtimes whose reason for existing is I/O
    "tokio",
    "async-std",
    "smol",
    // sockets, DNS, addressing
    "socket2",
    "trust-dns-resolver",
    "hickory-resolver",
    "dns-lookup",
    "tungstenite",
    "tokio-tungstenite",
    "quinn",
    "url",
    // self-replacement: the mechanism a fetched binary would need
    "self-replace",
    "self_update",
];

/// The crates from `lock` that are on the list above.
///
/// Split out from the assertion so the matching itself can be tested against a
/// known-bad input. Cargo rewrites `Cargo.lock` whenever it disagrees with
/// `Cargo.toml`, so a network crate cannot simply be spliced into the real
/// file to check that this fires.
fn network_crates_in(lock: &str) -> Vec<&str> {
    locked_crates(lock)
        .into_iter()
        .filter(|name| NETWORK_CRATES.contains(name))
        .collect()
}

fn lockfile() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Every crate in the resolved dependency graph, in lockfile order.
fn locked_crates(lock: &str) -> Vec<&str> {
    lock.lines()
        .filter_map(|line| line.strip_prefix("name = "))
        .map(|name| name.trim().trim_matches('"'))
        .collect()
}

#[test]
fn no_network_crate_is_in_the_dependency_tree() {
    let lock = lockfile();
    let found = network_crates_in(&lock);

    assert!(
        found.is_empty(),
        "these crates put networking back into a program that promises never to \
         use it: {found:?}\n\
         If one of them is genuinely needed for something offline, run \
         `cargo tree -i <crate>` to see who asked for it, and only then take it \
         off the list in this test — with a comment saying why."
    );
}

#[test]
fn the_lockfile_was_actually_read() {
    // Guards the test above against passing because the parse produced nothing:
    // an empty list of crates trivially contains no network crates.
    let lock = lockfile();
    let crates = locked_crates(&lock);
    assert!(
        crates.len() > 50,
        "only parsed {} crates out of Cargo.lock, so the denylist above proves \
         nothing — has the lockfile format changed?",
        crates.len()
    );
    assert!(crates.contains(&"neko-auth"));
    // mio and signal-hook-mio are in the tree and stay there: crossterm uses
    // mio to poll the terminal for key events, not to open sockets.
    assert!(crates.contains(&"crossterm"));
}

#[test]
fn a_network_crate_would_be_caught() {
    // Without this, the test above could pass because the matching is broken
    // rather than because the tree is clean.
    let lock = concat!(
        "[[package]]\nname = \"neko-auth\"\nversion = \"0.1.3\"\n\n",
        "[[package]]\nname = \"reqwest\"\nversion = \"0.12.0\"\n\n",
        "[[package]]\nname = \"rustls\"\nversion = \"0.23.0\"\n",
    );
    let mut found = network_crates_in(lock);
    found.sort_unstable();
    assert_eq!(found, ["reqwest", "rustls"]);
}
