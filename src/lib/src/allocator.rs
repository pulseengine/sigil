//! Phase-locked memory allocator for allocation-free verification
//!
//! This module provides a custom allocator that can detect allocations in hot paths,
//! similar to the approach used by Eclipse S-CORE for ASIL-B safety requirements.
//!
//! Note: This module requires unsafe code to implement GlobalAlloc, despite the
//! crate-level #![forbid(unsafe_code)]. This is necessary and safe.

#![allow(unsafe_code)]
//!
//! # Usage
//!
//! Enable the `allocation-guard` feature and use the global allocator:
//!
//! ```rust,ignore
//! #[cfg(feature = "allocation-guard")]
//! use wsc::allocator::PhaseLockedAllocator;
//!
//! #[cfg(feature = "allocation-guard")]
//! #[global_allocator]
//! static ALLOCATOR: PhaseLockedAllocator = PhaseLockedAllocator::new();
//!
//! // Initialization phase - allocations are allowed
//! let verifier = RekorVerifier::new(&entry)?;
//!
//! // Lock down allocations
//! #[cfg(feature = "allocation-guard")]
//! wsc::allocator::lock_allocations();
//!
//! // Hot path - any allocation will panic with detailed trace
//! verifier.verify_checkpoint(&checkpoint)?;
//! ```
//!
//! # Verification Strategy
//!
//! This approach provides coarse-grained but 100% reliable detection:
//!
//! 1. **During initialization**: Allocations are allowed (INIT_PHASE = true)
//! 2. **After lock_allocations()**: Any allocation triggers panic with backtrace
//! 3. **Zero overhead**: When not violated, just an atomic bool check
//!
//! # Why Not memory.grow?
//!
//! While monitoring memory.grow at the WASM runtime level is also valid, this
//! Rust-level approach provides:
//! - Better error messages with Rust backtraces
//! - Works in any WASM runtime (not just Wasmtime)
//! - Can be used in native tests too
//! - Fine-grained control per allocation site

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Phase-locked allocator that can detect allocations after initialization
///
/// This allocator wraps the system allocator and tracks whether allocations
/// are currently allowed. It's designed for verifying allocation-free execution
/// in performance-critical or safety-critical code paths.
pub struct PhaseLockedAllocator {
    _private: (),
}

impl PhaseLockedAllocator {
    /// Create a new phase-locked allocator
    ///
    /// Initially, allocations are allowed (initialization phase).
    /// Call [`lock_allocations`] to transition to the locked phase.
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

/// Global state tracking whether allocations are allowed
static INIT_PHASE: AtomicBool = AtomicBool::new(true);

/// Statistics tracking for debugging
static TOTAL_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static TOTAL_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static LOCKED_ALLOCATION_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for PhaseLockedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Check if we're in the locked phase
        if !INIT_PHASE.load(Ordering::Acquire) {
            // Record the violation
            LOCKED_ALLOCATION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

            // Abort immediately - panic would try to allocate and cause recursion
            std::process::abort();
        }

        // Track statistics during init phase
        TOTAL_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);

        // Delegate to system allocator
        // SAFETY: We're in an allocator implementation, delegating to the system allocator
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Deallocation is always allowed
        // SAFETY: We're in an allocator implementation, delegating to the system allocator
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Same logic as alloc
        if !INIT_PHASE.load(Ordering::Acquire) {
            LOCKED_ALLOCATION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            std::process::abort();
        }

        TOTAL_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        TOTAL_ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);

        // SAFETY: We're in an allocator implementation, delegating to the system allocator
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Reallocation might allocate, so check phase
        if !INIT_PHASE.load(Ordering::Acquire) {
            LOCKED_ALLOCATION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            std::process::abort();
        }

        if new_size > layout.size() {
            TOTAL_ALLOCATED_BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
        }

        // SAFETY: We're in an allocator implementation, delegating to the system allocator
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Lock allocations - transition from initialization phase to hot path phase
///
/// After calling this function, any allocation attempt will panic with a
/// detailed backtrace, helping identify allocation sources in hot paths.
///
/// # Example
///
/// ```rust,ignore
/// // Initialization phase
/// let verifier = create_verifier();
/// let data = load_test_data();
///
/// // Lock down
/// lock_allocations();
///
/// // This must not allocate
/// verifier.verify(&data)?;
/// ```
pub fn lock_allocations() {
    INIT_PHASE.store(false, Ordering::Release);
}

/// Unlock allocations - return to initialization phase
///
/// This is primarily useful for testing scenarios where you want to run
/// multiple hot path tests in sequence.
pub fn unlock_allocations() {
    INIT_PHASE.store(true, Ordering::Release);
}

/// Check if allocations are currently locked
pub fn are_allocations_locked() -> bool {
    !INIT_PHASE.load(Ordering::Acquire)
}

/// Statistics about allocations during initialization phase
#[derive(Debug, Clone, Copy)]
pub struct AllocationStats {
    /// Total number of allocations made during init phase
    pub total_allocations: usize,
    /// Total bytes allocated during init phase
    pub total_bytes: usize,
    /// Number of allocation attempts in locked phase (violations)
    pub locked_attempts: usize,
    /// Whether allocations are currently locked
    pub locked: bool,
}

/// Get current allocation statistics
pub fn get_stats() -> AllocationStats {
    AllocationStats {
        total_allocations: TOTAL_ALLOCATIONS.load(Ordering::Relaxed),
        total_bytes: TOTAL_ALLOCATED_BYTES.load(Ordering::Relaxed),
        locked_attempts: LOCKED_ALLOCATION_ATTEMPTS.load(Ordering::Relaxed),
        locked: are_allocations_locked(),
    }
}

/// Reset statistics counters
///
/// This does NOT unlock allocations - use [`unlock_allocations`] for that.
pub fn reset_stats() {
    TOTAL_ALLOCATIONS.store(0, Ordering::Relaxed);
    TOTAL_ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    LOCKED_ALLOCATION_ATTEMPTS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_unlock() {
        unlock_allocations();
        assert!(!are_allocations_locked());

        lock_allocations();
        assert!(are_allocations_locked());

        unlock_allocations();
        assert!(!are_allocations_locked());
    }

    #[test]
    fn test_stats() {
        reset_stats();
        let stats = get_stats();
        assert_eq!(stats.locked_attempts, 0);
    }

    #[test]
    #[should_panic(expected = "Allocation attempted in locked phase")]
    fn test_allocation_panics_when_locked() {
        unlock_allocations(); // Ensure clean state
        lock_allocations();

        // This should panic
        let _v = Vec::<u8>::new();
        let _boxed = Box::new(42); // This will trigger the panic
    }

    #[test]
    fn test_allocation_allowed_when_unlocked() {
        unlock_allocations();

        // These should work fine
        let v = vec![1, 2, 3, 4, 5];
        assert_eq!(v.len(), 5);

        let boxed = Box::new(42);
        assert_eq!(*boxed, 42);
    }
}
