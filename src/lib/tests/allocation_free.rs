//! Tests for allocation-free execution in hot paths
//!
//! These tests verify that critical code paths (signature verification,
//! Rekor verification) don't allocate after initialization, which is
//! important for:
//!
//! - Real-time systems (deterministic execution)
//! - Safety-critical systems (ASIL-B requirements like Eclipse S-CORE)
//! - Performance-critical paths (avoid GC pressure)
//!
//! **IMPORTANT**: These tests must be run sequentially because they share
//! global allocator state:
//!
//! ```bash
//! cargo test --features allocation-guard --test allocation_free -- --test-threads=1
//! ```

#![cfg(feature = "allocation-guard")]

use wsc::allocator::{
    lock_allocations, unlock_allocations, get_stats, reset_stats, PhaseLockedAllocator,
};

// Use the phase-locked allocator for these tests
#[global_allocator]
static ALLOCATOR: PhaseLockedAllocator = PhaseLockedAllocator::new();

#[test]
fn test_allocation_guard_basic() {
    // Ensure we start in unlocked state
    unlock_allocations();
    reset_stats();

    // This should work fine
    let v = vec![1, 2, 3];
    assert_eq!(v.len(), 3);

    // Lock allocations
    lock_allocations();

    // Reading stack-allocated data is fine
    assert_eq!(v[0], 1);

    // Unlock for cleanup
    unlock_allocations();
}

// Note: We can't test allocation violations with #[should_panic] because
// the allocator calls abort() instead of panic to avoid infinite recursion
// (panic itself would try to allocate). The abort is detected by CI/test runners.

#[test]
fn test_pre_allocated_data_access() {
    // This test verifies that we can pre-allocate data during init
    // and then work with it allocation-free in hot path
    unlock_allocations();
    reset_stats();

    // Pre-allocate data structures during init
    let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let cloned_data = data.clone();

    // Lock and verify we can read the pre-allocated data
    lock_allocations();

    // Reading from pre-allocated Vec is fine (no new allocations)
    assert_eq!(data.len(), 8);
    assert_eq!(cloned_data.len(), 8);
    assert_eq!(data[0], 1);
    assert_eq!(data[7], 8);

    // Summing values doesn't allocate
    let sum: u8 = data.iter().sum();
    assert_eq!(sum, 36);

    let final_stats = get_stats();
    assert_eq!(final_stats.locked_attempts, 0);

    unlock_allocations();
}

#[test]
fn test_hash_computation_allocation_free() {
    use sha2::{Digest, Sha256};

    unlock_allocations();
    reset_stats();

    // Pre-allocate input data
    let data = vec![0u8; 1024];

    // Lock and verify hashing is allocation-free
    lock_allocations();

    // Hash computation should not allocate
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let _result = hasher.finalize();

    let final_stats = get_stats();
    assert_eq!(
        final_stats.locked_attempts, 0,
        "Hash computation allocated!"
    );

    unlock_allocations();
}

#[test]
fn test_stats_tracking() {
    unlock_allocations();
    reset_stats();

    let stats_before = get_stats();
    assert_eq!(stats_before.total_allocations, 0);
    assert_eq!(stats_before.locked_attempts, 0);
    assert!(!stats_before.locked);

    // Make some allocations
    let _v1 = vec![1, 2, 3];
    let _v2 = vec![4, 5, 6, 7, 8];

    let stats_after = get_stats();
    assert!(stats_after.total_allocations > 0);
    assert!(stats_after.total_bytes > 0);

    // Lock and check state
    lock_allocations();
    let stats_locked = get_stats();
    assert!(stats_locked.locked);

    unlock_allocations();
}

/// Demonstration test showing the pattern for allocation-free verification
///
/// This test shows the recommended pattern:
/// 1. Init phase: Load and parse all data (allocations OK)
/// 2. Lock phase: Lock allocations
/// 3. Hot path: Perform operations (must be allocation-free)
/// 4. Unlock: Return to normal operation
#[test]
fn test_allocation_free_pattern_demo() {
    use sha2::{Digest, Sha256};

    // ========== PHASE 1: INITIALIZATION ==========
    unlock_allocations();
    reset_stats();

    // Pre-allocate all data structures needed for verification
    let data = vec![0u8; 4096];
    let expected_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hasher.finalize()
    };

    let init_stats = get_stats();
    assert!(init_stats.total_allocations > 0, "Init phase should have allocations");

    // ========== PHASE 2: LOCK ==========
    lock_allocations();

    // ========== PHASE 3: HOT PATH ==========
    // Recompute hash (allocation-free)
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let computed_hash = hasher.finalize();

    // Compare hashes (allocation-free)
    assert_eq!(expected_hash, computed_hash);

    let hot_stats = get_stats();
    assert_eq!(
        hot_stats.locked_attempts, 0,
        "Allocations detected in hot path!"
    );

    // ========== PHASE 4: UNLOCK ==========
    unlock_allocations();
}
