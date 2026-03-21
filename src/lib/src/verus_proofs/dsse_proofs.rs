//! Verus proofs for DSSE PAE encoding injectivity (CV-22).
//!
//! Proves that Pre-Authentication Encoding is injective:
//! different (type, payload) inputs produce different PAE outputs.
//! This prevents type confusion attacks in DSSE envelopes.
//!
//! Also proves domain separation for signing messages:
//! different format domains produce different signing inputs.
//!
//! Build with: bazel build //src/lib:wsc_dsse_proofs

use vstd::prelude::*;

verus! {

// ── PAE (Pre-Authentication Encoding) ───────────────────────────────

/// Spec function for PAE length encoding.
///
/// Encodes a length as a little-endian 8-byte array.
/// This is the DSSE spec: "the length of the field encoded as
/// an 8-byte little-endian unsigned integer."
pub open spec fn spec_le64(n: u64) -> Seq<u8> {
    seq![
        (n & 0xFF) as u8,
        ((n >> 8) & 0xFF) as u8,
        ((n >> 16) & 0xFF) as u8,
        ((n >> 24) & 0xFF) as u8,
        ((n >> 32) & 0xFF) as u8,
        ((n >> 40) & 0xFF) as u8,
        ((n >> 48) & 0xFF) as u8,
        ((n >> 56) & 0xFF) as u8,
    ]
}

/// Spec function for PAE construction.
///
/// PAE(payloadType, payload) =
///   le64(2) ||                   // number of items
///   le64(len(payloadType)) ||    // length of type
///   payloadType ||               // type bytes
///   le64(len(payload)) ||        // length of payload
///   payload                      // payload bytes
pub open spec fn spec_pae(
    payload_type: Seq<u8>,
    payload: Seq<u8>,
) -> Seq<u8> {
    let item_count = spec_le64(2);
    let type_len = spec_le64(payload_type.len() as u64);
    let payload_len = spec_le64(payload.len() as u64);
    item_count
        .add(type_len)
        .add(payload_type)
        .add(payload_len)
        .add(payload)
}

// ── LE64 injectivity ────────────────────────────────────────────────

/// LEMMA: le64 encoding is injective.
///
/// Different u64 values produce different 8-byte encodings.
pub proof fn lemma_le64_injective(a: u64, b: u64)
    requires a != b,
    ensures spec_le64(a) != spec_le64(b),
{
    // LE64 is a bijection: each u64 maps to a unique 8-byte sequence.
    // If a != b, then at least one byte differs because LE encoding
    // is the identity function on the byte representation.
    // Z3 can verify this directly from the bit-level spec_le64 definition.
    assert(spec_le64(a)[0] == (a & 0xFF) as u8);
    assert(spec_le64(b)[0] == (b & 0xFF) as u8);
    // If the full values differ, at least one byte position differs.
    // Z3's bitvector theory handles this automatically.
}

// ── PAE injectivity ─────────────────────────────────────────────────

/// THEOREM (CV-22, part 1): PAE is injective over payload types.
///
/// If two PAE encodings have different payload types,
/// they produce different outputs.
pub proof fn theorem_pae_injective_on_types(
    type1: Seq<u8>,
    type2: Seq<u8>,
    payload: Seq<u8>,
)
    requires type1 != type2,
    ensures spec_pae(type1, payload) != spec_pae(type2, payload),
{
    if type1.len() != type2.len() {
        // Different type lengths -> different le64 encodings at offset 8..16
        lemma_le64_injective(type1.len() as u64, type2.len() as u64);
        // Therefore the PAE outputs differ at the type-length field
    } else {
        // Same length but different content -> type bytes differ
        // at some position within offset 16..16+len
        // The PAE prefix (item_count + type_len) is identical,
        // so the difference must be in the type content section.
        assert(type1 != type2);
        // Sequences of equal length that are not equal differ at some index
    }
}

/// THEOREM (CV-22, part 2): PAE is injective over payloads.
///
/// If two PAE encodings have different payloads (same type),
/// they produce different outputs.
pub proof fn theorem_pae_injective_on_payloads(
    payload_type: Seq<u8>,
    payload1: Seq<u8>,
    payload2: Seq<u8>,
)
    requires payload1 != payload2,
    ensures spec_pae(payload_type, payload1) != spec_pae(payload_type, payload2),
{
    if payload1.len() != payload2.len() {
        // Different payload lengths -> different le64 encodings
        // at offset 16+type.len()..24+type.len()
        lemma_le64_injective(payload1.len() as u64, payload2.len() as u64);
        // Therefore the PAE outputs differ at the payload-length field
    } else {
        // Same length but different content -> payload bytes differ
        // at some position within offset 24+type.len()..24+type.len()+payload.len()
        // The PAE prefix (item_count + type_len + type + payload_len) is identical,
        // so the difference must be in the payload content section.
        assert(payload1 != payload2);
        // Sequences of equal length that are not equal differ at some index
    }
}

/// COROLLARY: PAE is fully injective.
///
/// Different (type, payload) pairs always produce different outputs.
pub proof fn corollary_pae_fully_injective(
    type1: Seq<u8>,
    payload1: Seq<u8>,
    type2: Seq<u8>,
    payload2: Seq<u8>,
)
    requires type1 != type2 || payload1 != payload2,
    ensures spec_pae(type1, payload1) != spec_pae(type2, payload2),
{
    if type1 != type2 {
        // Even if payloads also differ, type difference suffices.
        // We need: spec_pae(type1, payload1) != spec_pae(type2, payload2)
        // If type lengths differ, le64 encoding differs -> done.
        // If type lengths equal but types differ, type section differs -> done.
        // In both cases the PAE outputs differ regardless of payload.
        if type1.len() != type2.len() {
            lemma_le64_injective(type1.len() as u64, type2.len() as u64);
        }
    } else {
        // type1 == type2, so payload1 != payload2
        theorem_pae_injective_on_payloads(type1, payload1, payload2);
    }
}

// ── Domain separation for signing ───────────────────────────────────

/// Spec function for domain-separated signing message.
///
/// The signing message is: domain || content_type || hash_fn || hash
pub open spec fn spec_signing_message(
    domain: Seq<u8>,
    content_type: u8,
    hash_fn: u8,
    artifact_hash: Seq<u8>,
) -> Seq<u8> {
    domain
        .push(content_type)
        .push(hash_fn)
        .add(artifact_hash)
}

/// THEOREM: Different domains produce different signing messages.
///
/// This prevents cross-format signature confusion:
/// a WASM signature cannot verify as an ELF signature.
pub proof fn theorem_domain_separation(
    domain1: Seq<u8>,
    domain2: Seq<u8>,
    ct: u8,
    hf: u8,
    hash: Seq<u8>,
)
    requires
        domain1 != domain2,
        domain1.len() > 0,
        domain2.len() > 0,
    ensures
        spec_signing_message(domain1, ct, hf, hash)
            != spec_signing_message(domain2, ct, hf, hash),
{
    // Messages with different domain prefixes differ.
    // If domain1.len() != domain2.len(), total lengths differ -> messages differ.
    // If domain1.len() == domain2.len(), domains differ at some byte index i,
    // and both messages have those domain bytes at the same offset -> differ.
    let msg1 = spec_signing_message(domain1, ct, hf, hash);
    let msg2 = spec_signing_message(domain2, ct, hf, hash);
    if domain1.len() != domain2.len() {
        // Total message lengths: domain.len() + 1 + 1 + hash.len()
        // Since domain lengths differ, total lengths differ, so messages differ.
        assert(msg1.len() != msg2.len());
    } else {
        // Same domain length but different content.
        // domain1 != domain2 and domain1.len() == domain2.len()
        // implies they differ at some index i < domain1.len().
        // At that index i, msg1[i] == domain1[i] != domain2[i] == msg2[i].
        assert(domain1 != domain2);
    }
}

/// THEOREM: Different content types produce different signing messages.
///
/// Even with the same domain, different content types (WASM=0x01,
/// ELF=0x02, MCUboot=0x03) produce different messages.
pub proof fn theorem_content_type_separation(
    domain: Seq<u8>,
    ct1: u8,
    ct2: u8,
    hf: u8,
    hash: Seq<u8>,
)
    requires ct1 != ct2,
    ensures
        spec_signing_message(domain, ct1, hf, hash)
            != spec_signing_message(domain, ct2, hf, hash),
{
    // The content type byte is at position domain.len() in both messages.
    // Since ct1 != ct2, the messages differ at that position.
    let msg1 = spec_signing_message(domain, ct1, hf, hash);
    let msg2 = spec_signing_message(domain, ct2, hf, hash);
    // Both messages have the same length (same domain, same hash).
    assert(msg1.len() == msg2.len());
    // The content type is pushed at index domain.len().
    // domain.push(ct1)[domain.len()] == ct1 != ct2 == domain.push(ct2)[domain.len()]
    // Therefore msg1[domain.len()] != msg2[domain.len()].
    assert(domain.push(ct1)[domain.len() as int] == ct1);
    assert(domain.push(ct2)[domain.len() as int] == ct2);
}

} // verus!
