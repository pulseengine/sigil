//! Fuzz target for DSSE envelope JSON parsing.
//!
//! `wsc::dsse::DsseEnvelope` is a central attestation parser: it accepts
//! untrusted JSON whose `signatures` field is an unbounded `Vec<DsseSignature>`,
//! and the envelope is consumed by every downstream verifier.
//!
//! Security concerns this target exercises:
//! - JSON denial-of-service (deeply nested structures, oversize signatures).
//! - serde_json error handling on malformed input.
//! - Round-trip stability: parse → serialize → parse must yield equal
//!   structural data, otherwise an attacker may craft an envelope whose
//!   re-serialized form differs from the bytes that were actually verified.
//!
//! Oracle: not just "doesn't crash" — also a structural round-trip equality
//! check on any successfully parsed envelope.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::dsse::DsseEnvelope;

fuzz_target!(|data: &[u8]| {
    // Treat input as candidate UTF-8 JSON. Skip non-UTF-8 inputs early so
    // the deserializer is not asked to do work on bytes that can never be
    // valid JSON (serde_json would reject them anyway, but this keeps
    // corpus mutations focused on JSON-shaped inputs).
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    let envelope = match DsseEnvelope::from_json(s) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Round-trip oracle: serialize back to JSON, parse again, and assert
    // that the two parsed envelopes are structurally identical. A divergence
    // here would indicate a serde quirk an attacker could exploit (e.g. a
    // field that survives the first parse but is dropped on the second).
    let json = envelope
        .to_json()
        .expect("serialization of a successfully parsed envelope must succeed");

    let envelope2 = DsseEnvelope::from_json(&json)
        .expect("re-parse of self-serialized envelope must succeed");

    assert_eq!(envelope.payload, envelope2.payload);
    assert_eq!(envelope.payload_type, envelope2.payload_type);
    assert_eq!(envelope.signatures.len(), envelope2.signatures.len());
    for (a, b) in envelope.signatures.iter().zip(envelope2.signatures.iter()) {
        assert_eq!(a.keyid, b.keyid);
        assert_eq!(a.sig, b.sig);
    }
});
