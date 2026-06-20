//! Witness MC/DC harness for `wsc-verify-core` — Phases 1 + 2.
//!
//! This crate compiles to a `wasm32-wasip1` cdylib that the
//! [`pulseengine/witness`](https://github.com/pulseengine/witness) tool
//! instruments to reconstruct **Modified Condition / Decision Coverage**
//! truth tables for the verification core.
//!
//! # Phase 1 — varint decoder (`varint::get32`)
//!
//! `decode_varint_5` drives sigil's LEB128 decoder. Five symbolic input
//! bytes flip the continuation bit at each varint position; witness
//! reports MC/DC over the decoder's loop.
//!
//! # Phase 2 — WASM module parser (`Module::init_from_reader`)
//!
//! `try_parse_wasm` drives `Module::init_from_reader` on an 8-byte
//! symbolic input. The WASM module format requires the magic bytes
//! `[0x00, 0x61, 0x73, 0x6D]` followed by the version `[0x01, 0, 0, 0]`;
//! flipping any one of those bytes hits a different parser-decision branch.
//! This covers more of `wsc-verify-core`'s surface than Phase 1, while
//! staying small enough that the truth tables remain legible. Phase 3
//! (#128) will add scenarios over `PublicKey::verify_multi` with crafted
//! signed-module fixtures.

#![allow(clippy::missing_safety_doc)]

use wsc_verify_core::wasm_module::{Module, varint};

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

/// Try to parse the 8-byte WASM module header `[b0..b7]` via
/// `Module::init_from_reader`.
///
/// Returns `0` on parse success, a nonzero discriminant on parse error
/// (the specific value is informational; witness measures the branch
/// coverage, not the return value). Each invocation flips one or more
/// of the 8 header bytes — scenarios that flip exactly one byte at a
/// time give MC/DC rows for the magic / version field decisions inside
/// the parser.
#[unsafe(no_mangle)]
pub extern "C" fn try_parse_wasm(
    b0: u8,
    b1: u8,
    b2: u8,
    b3: u8,
    b4: u8,
    b5: u8,
    b6: u8,
    b7: u8,
) -> u32 {
    let bytes = [b0, b1, b2, b3, b4, b5, b6, b7];
    let mut slice = &bytes[..];
    match Module::init_from_reader(&mut slice) {
        Ok(_stream) => 0,
        Err(_) => 1,
    }
}
