//! Witness MC/DC harness for `wsc-verify-core` — Phase 1.
//!
//! This crate compiles to a `wasm32-unknown-unknown` cdylib that the
//! [`pulseengine/witness`](https://github.com/pulseengine/witness) tool
//! instruments to reconstruct **Modified Condition / Decision Coverage**
//! truth tables for the verification core.
//!
//! # Phase 1 — toolchain end-to-end
//!
//! The scenario here drives `wasm_module::varint::get32` — sigil's LEB128
//! decoder, the only sigil-core hot loop whose conditions a witness truth
//! table can render cleanly. Five symbolic input bytes flip the
//! continuation bit at each varint position; witness reports MC/DC over the
//! decoder's loop.
//!
//! Phase 2 (#128) adds scenarios over `PublicKey::verify_multi` with
//! crafted signed-module fixtures.

#![allow(clippy::missing_safety_doc)]

use wsc_verify_core::wasm_module::varint;

/// Decode the LEB128 varint encoded in `[b0, b1, b2, b3, b4]`.
///
/// Returns the decoded `u32` on success, or `0xFFFFFFFF` on a decode error.
/// Witness instruments the branches inside `varint::get32`; each call to
/// this export flips the continuation bit at exactly one position, giving
/// the truth-table rows MC/DC needs to prove each condition independently.
#[unsafe(no_mangle)]
pub extern "C" fn decode_varint_5(b0: u8, b1: u8, b2: u8, b3: u8, b4: u8) -> u32 {
    let bytes = [b0, b1, b2, b3, b4];
    let mut slice = &bytes[..];
    varint::get32(&mut slice).unwrap_or(0xFFFFFFFF)
}
