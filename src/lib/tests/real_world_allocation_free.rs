//! Real-world allocation-free verification tests
//!
//! This tests actual wsc hot paths to determine which operations
//! are allocation-free. Run with:
//!
//! ```bash
//! cargo test --features allocation-guard --test real_world_allocation_free -- --test-threads=1 --nocapture
//! ```

#![cfg(feature = "allocation-guard")]

use std::io::Cursor;
use wsc::allocator::{
    PhaseLockedAllocator, get_stats, lock_allocations, reset_stats, unlock_allocations,
};
use wsc::{KeyPair, Module, PublicKey};

// Use the phase-locked allocator for these tests
#[global_allocator]
static ALLOCATOR: PhaseLockedAllocator = PhaseLockedAllocator::new();

/// Helper to create a test WASM module
fn create_minimal_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "test") (result i32)
                i32.const 42
            )
        )
        "#,
    )
    .expect("Failed to parse WAT")
}

#[test]
fn test_signature_verification_real() {
    unlock_allocations();
    reset_stats();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  Real-World Test: WASM Signature Verification");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // ========== INIT PHASE ==========
    eprintln!("📦 INIT PHASE: Creating signed WASM module...");

    let wasm = create_minimal_wasm();
    let kp = KeyPair::generate();

    // Sign the module
    let module = Module::deserialize(&mut Cursor::new(&wasm)).expect("Failed to parse module");
    let signed = kp.sk.sign(module, None).expect("Failed to sign");

    // Serialize signed module
    let mut signed_bytes = Vec::new();
    signed
        .serialize(&mut signed_bytes)
        .expect("Failed to serialize");

    // Keep public key for verification
    let pk = kp.pk;

    // Clone for use in hot path
    let module_data = signed_bytes.clone();

    let init_stats = get_stats();
    eprintln!(
        "   Init allocated: {} bytes in {} allocations",
        init_stats.total_bytes, init_stats.total_allocations
    );

    // ========== LOCK PHASE ==========
    eprintln!("\n🔒 LOCK PHASE: Locking allocations...");
    lock_allocations();

    // ========== HOT PATH ==========
    eprintln!("🚀 HOT PATH: Verifying signature (allocation-free?)...");

    let mut reader = Cursor::new(&module_data);
    let result = pk.verify(&mut reader, None);

    let hot_stats = get_stats();

    if hot_stats.locked_attempts == 0 {
        eprintln!("✅ ALLOCATION-FREE! Signature verification succeeded without allocations");
        assert!(result.is_ok(), "Verification should succeed");
    } else {
        eprintln!(
            "❌ ALLOCATES: {} allocation attempts in hot path",
            hot_stats.locked_attempts
        );
        eprintln!("   This is expected - signature verification currently allocates");
        // Don't assert - we're discovering what allocates
    }

    unlock_allocations();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

#[test]
fn test_module_parsing_real() {
    unlock_allocations();
    reset_stats();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  Real-World Test: WASM Module Parsing");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // ========== INIT PHASE ==========
    eprintln!("📦 INIT PHASE: Creating test module...");

    let wasm = create_minimal_wasm();
    let wasm_clone = wasm.clone();

    let init_stats = get_stats();
    eprintln!(
        "   Init allocated: {} bytes in {} allocations",
        init_stats.total_bytes, init_stats.total_allocations
    );

    // ========== LOCK PHASE ==========
    eprintln!("\n🔒 LOCK PHASE: Locking allocations...");
    lock_allocations();

    // ========== HOT PATH ==========
    eprintln!("🚀 HOT PATH: Parsing WASM module (allocation-free?)...");

    let mut reader = Cursor::new(&wasm_clone);
    let result = Module::deserialize(&mut reader);

    let hot_stats = get_stats();

    if hot_stats.locked_attempts == 0 {
        eprintln!("✅ ALLOCATION-FREE! Module parsing succeeded without allocations");
        assert!(result.is_ok(), "Parsing should succeed");
    } else {
        eprintln!(
            "❌ ALLOCATES: {} allocation attempts in hot path",
            hot_stats.locked_attempts
        );
        eprintln!("   Module parsing requires allocations (Vec for sections, etc.)");
    }

    unlock_allocations();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

#[test]
#[cfg(feature = "keyless")]
fn test_rekor_set_verification_real() {
    use wsc::keyless::RekorKeyring;

    unlock_allocations();
    reset_stats();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  Real-World Test: Rekor SET Verification");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // ========== INIT PHASE ==========
    eprintln!("📦 INIT PHASE: Loading Rekor keyring...");

    let keyring = RekorKeyring::from_embedded_trust_root().expect("Failed to load Rekor keys");

    // Note: We'd need real test data here to actually test SET verification
    // For now, just test that the keyring loads

    let init_stats = get_stats();
    eprintln!(
        "   Init allocated: {} bytes in {} allocations",
        init_stats.total_bytes, init_stats.total_allocations
    );
    eprintln!("   Loaded {} Rekor keys", keyring.keys.len());

    // ========== LOCK PHASE ==========
    eprintln!("\n🔒 LOCK PHASE: Locking allocations...");
    lock_allocations();

    // ========== HOT PATH ==========
    eprintln!("🚀 HOT PATH: Accessing pre-loaded keys (allocation-free?)...");

    // Just verify we can read the keyring without allocating
    let key_count = keyring.keys.len();
    assert!(key_count > 0, "Should have at least one key");

    let hot_stats = get_stats();

    if hot_stats.locked_attempts == 0 {
        eprintln!("✅ ALLOCATION-FREE! Keyring access succeeded without allocations");
    } else {
        eprintln!(
            "❌ ALLOCATES: {} allocation attempts in hot path",
            hot_stats.locked_attempts
        );
    }

    unlock_allocations();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

#[test]
fn test_ed25519_signature_verification_raw() {
    use ed25519_compact::{PublicKey as Ed25519PublicKey, Signature};

    unlock_allocations();
    reset_stats();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  Real-World Test: Raw Ed25519 Verification");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // ========== INIT PHASE ==========
    eprintln!("📦 INIT PHASE: Creating Ed25519 signature...");

    let keypair = ed25519_compact::KeyPair::generate();
    let message = b"test message for signing";
    let signature = keypair.sk.sign(message, None);

    // Extract components for hot path
    let pk = keypair.pk;
    let sig = signature;
    let msg = message;

    let init_stats = get_stats();
    eprintln!(
        "   Init allocated: {} bytes in {} allocations",
        init_stats.total_bytes, init_stats.total_allocations
    );

    // ========== LOCK PHASE ==========
    eprintln!("\n🔒 LOCK PHASE: Locking allocations...");
    lock_allocations();

    // ========== HOT PATH ==========
    eprintln!("🚀 HOT PATH: Verifying Ed25519 signature (allocation-free?)...");

    let result = pk.verify(msg, &sig);

    let hot_stats = get_stats();

    if hot_stats.locked_attempts == 0 {
        eprintln!("✅ ALLOCATION-FREE! Ed25519 verification succeeded without allocations");
        assert!(result.is_ok(), "Verification should succeed");
    } else {
        eprintln!(
            "❌ ALLOCATES: {} allocation attempts in hot path",
            hot_stats.locked_attempts
        );
    }

    unlock_allocations();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

#[test]
fn test_sha256_hashing_real() {
    use sha2::{Digest, Sha256};

    unlock_allocations();
    reset_stats();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  Real-World Test: SHA-256 Hashing");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // ========== INIT PHASE ==========
    eprintln!("📦 INIT PHASE: Preparing data...");

    let data = vec![0u8; 4096];

    let init_stats = get_stats();
    eprintln!(
        "   Init allocated: {} bytes in {} allocations",
        init_stats.total_bytes, init_stats.total_allocations
    );

    // ========== LOCK PHASE ==========
    eprintln!("\n🔒 LOCK PHASE: Locking allocations...");
    lock_allocations();

    // ========== HOT PATH ==========
    eprintln!("🚀 HOT PATH: Computing SHA-256 (allocation-free?)...");

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let _hash = hasher.finalize();

    let hot_stats = get_stats();

    if hot_stats.locked_attempts == 0 {
        eprintln!("✅ ALLOCATION-FREE! SHA-256 hashing succeeded without allocations");
    } else {
        eprintln!(
            "❌ ALLOCATES: {} allocation attempts in hot path",
            hot_stats.locked_attempts
        );
    }

    unlock_allocations();

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

#[test]
fn test_summary() {
    eprintln!("\n");
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  Allocation-Free Analysis Summary                        ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!("║                                                          ║");
    eprintln!("║  Run all tests above to see which operations are        ║");
    eprintln!("║  allocation-free in wsc's hot paths.                     ║");
    eprintln!("║                                                          ║");
    eprintln!("║  Expected results:                                       ║");
    eprintln!("║  ✅ SHA-256 hashing (allocation-free)                    ║");
    eprintln!("║  ✅ Ed25519 signature verification (allocation-free)     ║");
    eprintln!("║  ❌ WASM module parsing (allocates for Vec<Section>)     ║");
    eprintln!("║  ❌ Signature verification (allocates during parsing)    ║");
    eprintln!("║  ✅ Pre-loaded keyring access (allocation-free)          ║");
    eprintln!("║                                                          ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!("\n");
}
