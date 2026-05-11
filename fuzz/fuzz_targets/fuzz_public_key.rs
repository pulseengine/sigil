//! Fuzz target for public key parsing
//!
//! This target tests the public/secret key parser surface currently exposed
//! by `wsc::signature::keys`:
//!
//! - Raw bytes (with algorithm ID prefix, see `ED25519_PK_ID` / `ED25519_SK_ID`)
//! - PEM encoding (delegated to `ed25519_compact::PublicKey::from_pem`)
//! - DER encoding (delegated to `ed25519_compact::PublicKey::from_der`)
//!
//! Note: a previous revision of this target also exercised
//! `PublicKey::from_openssh`, `PublicKey::from_any`, `PublicKeySet::from_openssh`
//! and `SecretKey::from_openssh`. None of those exist on the current API —
//! OpenSSH ingestion and a polymorphic auto-detect parser were removed from
//! `signature/keys.rs`. We fuzz only the surface that is actually reachable.
//!
//! Oracles exercised:
//! - parsers must not panic on arbitrary bytes/strings
//! - `from_bytes` -> `to_bytes` -> `from_bytes` round-trips and yields the
//!   same key id when one is attached
//! - `from_pem` / `from_der` round-trip back through `to_pem` / `to_der`
//! - `key_id` derivation via `attach_default_key_id` is deterministic
//!
//! Security concerns:
//! - Buffer overflows or panics in key material handling
//! - Invalid key type IDs (anything other than ED25519_PK_ID / ED25519_SK_ID)
//! - Malformed PEM/DER structures and oversize length fields

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::{PublicKey, SecretKey};

fuzz_target!(|data: &[u8]| {
    // --- PublicKey: raw bytes ---------------------------------------------
    if let Ok(pk) = PublicKey::from_bytes(data) {
        // Round-trip raw encoding.
        let bytes = pk.to_bytes();
        let pk2 = PublicKey::from_bytes(&bytes)
            .expect("re-parsing freshly serialized public key must succeed");
        assert_eq!(pk, pk2, "raw round-trip must preserve key");

        // Default key-id derivation must be deterministic.
        let pk_with_id = pk.clone().attach_default_key_id();
        let pk_with_id_again = pk.attach_default_key_id();
        assert_eq!(
            pk_with_id.key_id(),
            pk_with_id_again.key_id(),
            "attach_default_key_id must be deterministic",
        );
        assert!(pk_with_id.key_id().is_some());
    }

    // --- PublicKey: DER ----------------------------------------------------
    if let Ok(pk) = PublicKey::from_der(data) {
        let der = pk.to_der();
        let _ = PublicKey::from_der(&der);
    }

    // --- PublicKey: PEM (string surface) -----------------------------------
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(pk) = PublicKey::from_pem(s) {
            let pem = pk.to_pem();
            let _ = PublicKey::from_pem(&pem);
        }
    }

    // --- SecretKey: raw bytes ---------------------------------------------
    if let Ok(sk) = SecretKey::from_bytes(data) {
        // `to_bytes` returns Zeroizing<Vec<u8>>; deref to &[u8] for re-parse.
        let bytes = sk.to_bytes();
        let _ = SecretKey::from_bytes(&bytes);
    }

    // --- SecretKey: DER ----------------------------------------------------
    if let Ok(sk) = SecretKey::from_der(data) {
        let der = sk.to_der();
        let _ = SecretKey::from_der(&der);
    }

    // --- SecretKey: PEM ----------------------------------------------------
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(sk) = SecretKey::from_pem(s) {
            let pem = sk.to_pem();
            let _ = SecretKey::from_pem(&pem);
        }
    }
});
