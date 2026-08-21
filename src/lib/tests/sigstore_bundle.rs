//! Integration tests for `KeylessSignature::from_sigstore_bundle` (REQ-27,
//! issue #260): ingesting an existing cosign / Sigstore bundle into a
//! `KeylessSignature` the offline verifiers accept.
//!
//! Fixtures are real bundles committed under
//! `tests/fixtures/sigstore_bundles/` and loaded with `include_str!`.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use wsc::WSError;
use wsc::container::SigstoreBundle;
use wsc::keyless::KeylessSignature;

const LEGACY_BUNDLE: &str =
    include_str!("fixtures/sigstore_bundles/legacy_rekorbundle_keyless.json");
const V03_LOCALKEY_BUNDLE: &str =
    include_str!("fixtures/sigstore_bundles/protobuf_v0.3_localkey.json");

/// The artifact SHA-256 recorded in the legacy fixture's hashedrekord body.
const LEGACY_MODULE_HASH_HEX: &str =
    "0f2e7d92ff7e1581d2a966db8dcdfc05054cdeb5395aec56561122e11b8a697f";

/// Test 1 — Legacy positive: the real legacy `rekorBundle` fixture ingests,
/// and every extracted field matches what the bundle actually carries.
#[test]
fn from_sigstore_bundle_legacy_positive() {
    let sig = KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE)
        .expect("legacy rekorBundle fixture must ingest");

    assert_eq!(
        sig.module_hash,
        hex::decode(LEGACY_MODULE_HASH_HEX).unwrap(),
        "module_hash must equal the hashedrekord body's data.hash.value"
    );

    assert!(!sig.cert_chain.is_empty(), "cert chain must be non-empty");
    assert!(
        sig.cert_chain[0].starts_with("-----BEGIN CERTIFICATE-----"),
        "leaf cert must be PEM text, got: {:?}",
        &sig.cert_chain[0][..sig.cert_chain[0].len().min(40)]
    );

    assert!(!sig.signature.is_empty(), "signature must be non-empty");

    assert_eq!(sig.rekor_entry.log_index, 2544945534);
    assert!(
        sig.rekor_entry.log_id.starts_with("c0d23d6a"),
        "log_id was: {}",
        sig.rekor_entry.log_id
    );
    assert!(
        !sig.rekor_entry.signed_entry_timestamp.is_empty(),
        "SET must be carried over"
    );
    // integrated_time is normalised to RFC3339 (Unix 1787295161).
    assert_eq!(sig.rekor_entry.integrated_time, "2026-08-21T06:52:41Z");
}

/// Test 1b — the strongest "the offline verifiers accept" proof that needs
/// neither network nor trust roots: `verify_rekor_body_binds_to_bundle`
/// decodes the ingested body and checks the artifact hash, signature bytes,
/// and leaf-cert DER all bind to the bundle. It must return `Ok`.
///
/// Non-vacuity: this is the positive partner of `..._negative_control` below.
/// If the digest, signature, or leaf cert were extracted inconsistently, this
/// call would return `Err`.
#[test]
fn from_sigstore_bundle_legacy_body_binding_accepts() {
    let sig = KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE)
        .expect("legacy fixture must ingest");
    sig.verify_rekor_body_binds_to_bundle()
        .expect("ingested legacy bundle must pass offline Rekor-body binding");
}

/// Test 2 — Legacy negative control (faithful-extraction proof): flip one hex
/// char of the `hash.value` inside the base64 body, re-embed, re-ingest, and
/// assert the extracted `module_hash` DIFFERS from the untampered one. Proves
/// the digest is read faithfully from the body, not fabricated/hardcoded.
///
/// Non-vacuity: a SUT that hardcoded `module_hash` (e.g. `vec![0u8;32]`) or
/// recomputed it from a fixed source would yield the SAME value for both
/// inputs and this `assert_ne!` would fail.
#[test]
fn from_sigstore_bundle_legacy_negative_control_faithful_digest() {
    let genuine = KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE)
        .expect("genuine legacy fixture must ingest");

    // Decode the top-level bundle, reach into rekorBundle.Payload.body,
    // decode it, flip the first hex char of the artifact hash, re-encode.
    let mut bundle: serde_json::Value = serde_json::from_str(LEGACY_BUNDLE).unwrap();
    let body_b64 = bundle["rekorBundle"]["Payload"]["body"].as_str().unwrap();
    let body_bytes = BASE64.decode(body_b64).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let orig = body["spec"]["data"]["hash"]["value"].as_str().unwrap();
    let mut chars: Vec<char> = orig.chars().collect();
    // Flip the first hex digit deterministically to a different hex digit.
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    let mutated: String = chars.into_iter().collect();
    assert_ne!(orig, mutated, "mutation must actually change the hash");
    body["spec"]["data"]["hash"]["value"] = serde_json::json!(mutated);

    let new_body_b64 = BASE64.encode(serde_json::to_vec(&body).unwrap());
    bundle["rekorBundle"]["Payload"]["body"] = serde_json::json!(new_body_b64);
    let tampered_json = serde_json::to_string(&bundle).unwrap();

    let tampered = KeylessSignature::from_sigstore_bundle(&tampered_json)
        .expect("tampered-but-well-formed bundle still ingests");

    assert_ne!(
        genuine.module_hash, tampered.module_hash,
        "corruption of the body hash must be propagated into module_hash"
    );
    assert_eq!(
        genuine.module_hash,
        hex::decode(LEGACY_MODULE_HASH_HEX).unwrap()
    );
}

/// Test 3 — v0.3 envelope + cert-requirement: the real
/// `protobuf_v0.3_localkey.json` bundle is detected as v0.3, its envelope is
/// parsed, and because it carries a raw public key (not a Fulcio cert) it is
/// rejected with the specific cert-requirement error.
///
/// Non-vacuity: the cert check runs BEFORE the messageSignature/digest
/// decode, so this error cannot be an incidental decode failure. If the SUT's
/// `publicKey` branch returned `Ok`/empty-chain, or was deleted so control
/// fell to the generic "no certificate in verificationMaterial" error, the
/// `contains("raw public key")` assertion below would fail — so the test
/// pins that the specific cert-requirement message fires.
#[test]
fn from_sigstore_bundle_v03_rejects_raw_public_key() {
    let err = KeylessSignature::from_sigstore_bundle(V03_LOCALKEY_BUNDLE)
        .expect_err("v0.3 local-key bundle must be rejected");

    match err {
        WSError::KeylessFormatError(msg) => {
            assert!(
                msg.contains("raw public key")
                    && msg.contains("requires a certificate"),
                "expected the raw-public-key cert-requirement error, got: {msg}"
            );
        }
        other => panic!("expected KeylessFormatError, got: {other:?}"),
    }
}

/// Test 4 — Round-trip fidelity: ingest the legacy fixture, re-emit it as a
/// v0.3 `SigstoreBundle`, JSON round-trip it, and prove the signature,
/// module_hash, cert chain, and rekor fields all survive.
///
/// Intentionally-transformed fields are asserted in their re-emitted form and
/// documented inline; nothing is silently dropped.
#[test]
fn from_sigstore_bundle_legacy_round_trip_fidelity() {
    let sig = KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE)
        .expect("legacy fixture must ingest");

    let bundle = SigstoreBundle::from_keyless_signature(&sig);
    let json = bundle.to_json().expect("bundle to_json");
    let bundle2 = SigstoreBundle::from_json(&json).expect("bundle from_json");

    // signature: preserved as base64 of the exact bytes.
    assert_eq!(
        BASE64.decode(&bundle2.message_signature.signature).unwrap(),
        sig.signature,
        "signature bytes must survive the round-trip"
    );

    // module_hash: emitted as lowercase hex by from_keyless_signature.
    assert_eq!(
        bundle2.message_signature.message_digest.digest,
        hex::encode(&sig.module_hash),
        "module_hash must survive as hex digest"
    );

    // cert chain: preserved as base64(DER). Re-derive the DER of the ingested
    // leaf PEM (strip headers, base64-decode) and compare byte-for-byte.
    let certs = &bundle2.verification_material.x509_certificate_chain.certificates;
    assert_eq!(
        certs.len(),
        sig.cert_chain.len(),
        "cert chain length must survive"
    );
    let leaf_der_from_bundle = BASE64.decode(&certs[0].raw_bytes).unwrap();
    let leaf_der_from_sig = pem_body_der(&sig.cert_chain[0]);
    assert_eq!(
        leaf_der_from_bundle, leaf_der_from_sig,
        "leaf certificate DER must survive"
    );

    // rekor fields.
    let tlog = &bundle2.verification_material.tlog_entries[0];
    assert_eq!(tlog.log_index, sig.rekor_entry.log_index.to_string());
    assert_eq!(tlog.log_id.key_id, sig.rekor_entry.log_id);
    assert_eq!(
        tlog.canonicalized_body.as_deref(),
        Some(sig.rekor_entry.body.as_str()),
        "canonicalized body (base64 rekord) must survive"
    );
    assert_eq!(
        tlog.signed_entry_timestamp.as_deref(),
        Some(sig.rekor_entry.signed_entry_timestamp.as_str()),
        "SET must survive"
    );
    // integrated_time: KeylessSignature holds RFC3339; the bundle re-emits it
    // as Unix seconds — the same instant, matching the legacy fixture value.
    assert_eq!(
        tlog.integrated_time, "1787295161",
        "integrated_time must round-trip to the fixture's Unix seconds"
    );

    // Documented intentionally-dropped fields (offline verification does not
    // need them and the legacy bundle never carried them):
    //  - rekor_entry.uuid  (legacy omits it; stays empty)
    //  - rekor_entry.inclusion_proof (legacy carries only the SET)
    assert!(sig.rekor_entry.uuid.is_empty());
    assert!(sig.rekor_entry.inclusion_proof.is_empty());
}

/// Test 5 — Unrecognised shape: an object with neither `rekorBundle` nor a
/// v0.3 marker yields the specific unrecognised-format error.
#[test]
fn from_sigstore_bundle_unrecognized_format() {
    let err = KeylessSignature::from_sigstore_bundle("{}")
        .expect_err("empty object must be rejected");
    match err {
        WSError::KeylessFormatError(msg) => {
            assert!(
                msg.contains("unrecognized Sigstore bundle format"),
                "got: {msg}"
            );
        }
        other => panic!("expected KeylessFormatError, got: {other:?}"),
    }
}

/// Strip PEM armor and decode the base64 body to DER bytes (test helper,
/// mirrors the crate's internal `pem_to_der`).
fn pem_body_der(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----BEGIN") && !l.starts_with("-----END") && !l.is_empty())
        .collect();
    BASE64.decode(&b64).expect("valid base64 in PEM body")
}

/// Test 6 — `verify_cert_chain` (offline: embedded Fulcio trust roots, no
/// network) accepts the ingested legacy bundle. This is the leg that depends
/// on `integrated_time` being RFC3339: `verify_cert_chain` parses that field
/// with `parse_from_rfc3339` and checks the leaf cert's validity window
/// against it. The fixture cert's window is 2026-08-21T06:52:40Z ..
/// 07:02:40Z and integrated_time is 06:52:41Z (inside the window), so this
/// returns `Ok`. A bare Unix-seconds string here would make the parse fail
/// and this test would catch the regression.
#[test]
fn from_sigstore_bundle_legacy_verify_cert_chain_accepts() {
    let sig = KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE)
        .expect("legacy fixture must ingest");
    sig.verify_cert_chain()
        .expect("ingested legacy leaf cert must chain to embedded Fulcio roots at integrated_time");
}
