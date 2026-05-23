//! Verification core for `wsc` — WASM-module parsing and classic Ed25519
//! signature verification, carved out so it builds for
//! `wasm32-unknown-unknown` with no network, TLS, or X.509 dependencies.
//!
//! # Why this crate exists
//!
//! The full `wsc` crate pulls in `rustls`/`ureq`/`rcgen`/`x509-parser` for
//! the keyless/Sigstore/provisioning machinery. Those transitively require
//! `ring`, which does not build for `wasm32-unknown-unknown` via plain
//! cargo. The classic verification path — `PublicKey::verify`,
//! `PublicKey::verify_multi`, the WASM module parser, the signature-section
//! parser — needs none of that. Splitting it into this crate lets MC/DC
//! coverage tools (e.g. `pulseengine/witness`) instrument the verification
//! code directly with plain cargo, without dragging in TLS.
//!
//! # Public API
//!
//! The shape is identical to what `wsc` exposed before the carve: items are
//! re-exported at the crate root for convenience, and the moved modules
//! (`signature`, `wasm_module`, `split`) are still available at their old
//! paths. `wsc` re-exports this crate's items so existing callers see no
//! change.

#![allow(clippy::vec_init_then_push)]
#![forbid(unsafe_code)]

mod error;
mod split;

/// Secure file operations with restrictive permissions (Unix 0600).
///
/// Provides utilities for reading and writing sensitive files such as
/// private keys. Lives here so the verification core's `KeyPair::from_file`
/// / `to_file` methods have what they need without crossing crate
/// boundaries (which the orphan rule would have made awkward).
pub mod secure_file;

pub mod signature;
pub mod wasm_module;

pub use error::CoreError;
pub use signature::*;
pub use wasm_module::*;
// `split` only adds inherent `impl Module { … }` methods (no free items to
// glob-import); declaring the module is enough to register the impls.

// Wire-format constants shared across the verification core. Public so the
// outer `wsc` crate and downstream tooling can reference them — they are
// part of the signed module's on-disk format and must stay stable.
pub const SIGNATURE_WASM_DOMAIN: &str = "wasmsig";
pub const SIGNATURE_VERSION: u8 = 0x01;
pub const SIGNATURE_WASM_MODULE_CONTENT_TYPE: u8 = 0x01;
pub const SIGNATURE_HASH_FUNCTION: u8 = 0x01;
