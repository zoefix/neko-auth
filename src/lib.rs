//! neko-auth: a fully offline TOTP vault.
//!
//! # Threat model
//!
//! neko-auth protects the vault **at rest**: a stolen laptop, a copied backup,
//! a `.db` file lifted off a disk, with neko-auth not running. That is the
//! threat model, and it is the whole threat model.
//!
//! It does *not* defend against malware or any other process running as the
//! same user; such a process can read this one's memory directly. It does not
//! defend against a root or kernel-level attacker, against secrets reaching
//! swap before they can be erased, or against a system crash reporter.
//!
//! Nothing here can reach another machine: no HTTP client, no TLS, and no DNS
//! resolver in the dependency tree, and so no update check and no telemetry.
//! Upgrading is the installer's job, a separate program the user runs
//! deliberately.
//!
//! The binary does import `socketpair`, by way of crossterm's terminal-event
//! polling, which uses an unnamed `AF_UNIX` pair to wake its own reader. It
//! has no address and cannot leave the process.

pub mod app;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod export;
pub mod i18n;
pub mod import;
pub mod otp;
pub mod paths;
pub mod repl;
pub mod secrets;
pub mod ui;
pub mod vault;

#[cfg(feature = "clipboard")]
pub mod clipboard;
