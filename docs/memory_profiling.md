# Memory Profiling Guide for wsc

## Overview

This guide covers memory profiling options for the wsc project across different platforms.

## Phase-Locked Allocator (Allocation-Free Verification)

**NEW**: wsc includes a built-in phase-locked allocator for verifying that critical code paths are allocation-free, similar to Eclipse S-CORE's approach for ASIL-B safety requirements.

### When to Use

Use allocation-free verification for:
- **Safety-critical systems** (e.g., automotive ECUs with ASIL-B requirements)
- **Real-time systems** (deterministic execution required)
- **Performance hotpaths** (minimize GC pressure and latency)

### Quick Start

Enable the `allocation-guard` feature and use the allocator in tests:

```rust
#[cfg(feature = "allocation-guard")]
use wsc::allocator::{PhaseLockedAllocator, lock_allocations, unlock_allocations};

#[cfg(feature = "allocation-guard")]
#[global_allocator]
static ALLOCATOR: PhaseLockedAllocator = PhaseLockedAllocator::new();

#[test]
fn test_rekor_verify_allocation_free() {
    unlock_allocations(); // Ensure clean state

    // INIT PHASE: Load and parse data (allocations OK)
    let entry = load_test_entry();
    let verifier = RekorVerifier::new(&entry).unwrap();

    // LOCK: Transition to hot path
    lock_allocations();

    // HOT PATH: Must not allocate (will abort if violated)
    verifier.verify_inclusion_proof().unwrap();

    // CLEANUP
    unlock_allocations();
}
```

Run with:
```bash
cargo test --features allocation-guard -- --test-threads=1
```

### How It Works

1. **Init Phase**: Allocations are allowed - load data, parse modules, create verifiers
2. **Lock Phase**: Call `lock_allocations()` to forbid all future allocations
3. **Hot Path**: Any allocation attempt immediately calls `std::process::abort()`
4. **Unlock Phase**: Call `unlock_allocations()` to return to normal operation

**Why `abort()` instead of `panic!()`?**
Panicking itself allocates memory (for the panic message and backtrace), which would create infinite recursion. Aborting ensures the violation is immediately detected.

### Implementation Details

The allocator works by wrapping the system allocator and checking an atomic bool before each allocation:

```rust
unsafe impl GlobalAlloc for PhaseLockedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !INIT_PHASE.load(Ordering::Acquire) {
            // Record violation and abort
            LOCKED_ALLOCATION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            std::process::abort();
        }
        unsafe { System.alloc(layout) }
    }
    // ... dealloc, alloc_zeroed, realloc
}
```

**Performance**: Zero overhead when not violated (just one atomic load per allocation).

### Statistics API

Track allocation patterns during initialization:

```rust
use wsc::allocator::{get_stats, reset_stats};

reset_stats();

// ... initialization code ...

let stats = get_stats();
println!("Init allocated: {} bytes in {} calls",
    stats.total_bytes,
    stats.total_allocations);

lock_allocations();

// ... hot path ...

let hot_stats = get_stats();
assert_eq!(hot_stats.locked_attempts, 0, "Hot path allocated!");
```

### Comparison with Other Approaches

| Approach | Platform | Overhead | Detection |
|----------|----------|----------|-----------|
| **Phase-Locked Allocator** | All | Atomic load | 100% (immediate abort) |
| ByteHound | Linux | High | 100% (post-analysis) |
| dhat-rs | All | Medium | 100% (post-analysis) |
| Monitoring `memory.grow` (WASM) | WASM only | Low | Coarse (page-level) |

### Limitations

- **Tests must run sequentially**: Use `--test-threads=1` since allocator state is global
- **Abort on violation**: No stack trace (prevents recursion), but violation is 100% detected
- **Not for profiling**: Use ByteHound or dhat-rs for allocation profiling/analysis

### See Also

- API documentation: [`src/lib/src/allocator.rs`](../src/lib/src/allocator.rs)
- Test examples: [`src/lib/tests/allocation_free.rs`](../src/lib/tests/allocation_free.rs)
- Eclipse S-CORE FEO: Similar approach for automotive safety

## ByteHound (Linux Only - Recommended for CI)

**ByteHound** is the most comprehensive memory profiler for Rust, but only works on Linux.

### Running in GitHub Actions CI

We have a dedicated **Memory Analysis** workflow that automatically runs on pull requests:

**Triggers**:
- Any PR targeting `main` that modifies Rust code
- Manual workflow dispatch (Actions tab → "Memory Analysis" → "Run workflow")

**What it does**:
1. **Phase-Locked Allocator** (fast, < 1 min): Verifies which operations are allocation-free
2. **ByteHound Profiling** (detailed, ~5 min): Generates comprehensive allocation reports

**After the workflow completes**:
1. Check the **workflow summary** for quick results (✅/❌ for each operation)
2. Download the `bytehound-profiles` artifact (30-day retention)
3. Download the `allocation-guard-log` artifact for detailed test output

**Viewing ByteHound results locally**:
```bash
# Download and extract artifact
unzip bytehound-profiles.zip

# Install ByteHound (Linux only, v0.11.0)
wget https://github.com/koute/bytehound/releases/download/0.11.0/bytehound-x86_64-unknown-linux-gnu.tgz
tar xzf bytehound-x86_64-unknown-linux-gnu.tgz
mv bytehound libbytehound.so ~/.cargo/bin/

# Start the web viewer
bytehound server memory-profiling_*.dat

# Open in browser
open http://localhost:8080
```

**What to look for in ByteHound UI**:
- **Allocations Tab**: All allocations sorted by size/count
- **Flame Graph**: Visual call stacks showing allocation sources
- **Timeline**: Allocation patterns over time
- **Leaked Memory**: Filter for memory not freed (potential leaks)

### Running via Docker (macOS/Windows)

```bash
# Build Docker image with ByteHound
docker build -f Dockerfile.bytehound -t wsc-bytehound .

# Run tests with profiling
docker run --rm -v $(pwd)/profiles:/workspace/profiles wsc-bytehound

# Copy profiling data out
docker cp <container_id>:/workspace/memory-profiling_*.dat ./profiles/

# View results (requires ByteHound installed locally on Linux or in Docker)
docker run --rm -p 8080:8080 -v $(pwd)/profiles:/data wsc-bytehound \
  bytehound server /data/memory-profiling_*.dat
```

Then open http://localhost:8080

## dhat-rs (Cross-Platform Alternative)

**dhat-rs** works on all platforms including macOS. It's less powerful than ByteHound but requires minimal changes.

### Installation

Add to `Cargo.toml`:

```toml
[dev-dependencies]
dhat = "0.3"
```

### Usage in Tests

Create a test file `tests/memory_profile.rs`:

```rust
#[cfg(test)]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn profile_keyless_signing() {
    let _profiler = dhat::Profiler::new_heap();

    // Your test code here
    // Example: Test keyless signing flow

    // Profile data written to dhat-heap.json on drop
}
```

Run the test:

```bash
cargo test --test memory_profile

# View results
dh_view.html dhat-heap.json
```

### Integration Example

Add to existing tests in `src/lib/src/signature/keyless/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(feature = "dhat-heap", global_allocator)]
    fn test_with_profiling() {
        #[cfg(feature = "dhat-heap")]
        let _profiler = dhat::Profiler::new_heap();

        // Your test code
    }
}
```

## Instruments (macOS Native)

**Instruments** is Apple's profiling tool and works great on macOS.

### Installation

```bash
cargo install cargo-instruments
```

### Usage

```bash
# Profile a specific test
cargo instruments --release --test keyless_integration \
  --template Allocations -- --nocapture

# Profile the CLI
cargo instruments --release --bin wsc \
  --template Allocations -- sign --keyless test.wasm
```

### Available Templates

- `Allocations` - Memory allocations
- `Leaks` - Memory leaks
- `Time Profiler` - CPU profiling
- `System Trace` - System-level profiling

Results open automatically in Instruments.app

## Recommendations by Use Case

### Development (macOS)

**Best:** Use Instruments via `cargo-instruments`
- Native macOS tool
- Great visualization
- Easy to use
- No code changes needed

```bash
cargo install cargo-instruments
cargo instruments --template Allocations --bin wsc
```

### CI/CD (Linux)

**Best:** Use ByteHound in GitHub Actions
- Most comprehensive profiling
- Automated on PRs
- Artifacts for later analysis

### Cross-Platform (All OSes)

**Best:** Use dhat-rs
- Works everywhere
- Good for regression testing
- Integrates with tests
- Lightweight

```toml
[dev-dependencies]
dhat = "0.3"
```

## Example: Finding Memory Leaks

### Using ByteHound (Linux/Docker)

```bash
# Run with profiling
LD_PRELOAD=/path/to/libbytehound.so cargo test

# Analyze
bytehound server memory-profiling_*.dat

# Look for:
# - Leaked allocations (not freed before exit)
# - Large allocations
# - Allocation hotspots
```

### Using dhat-rs (macOS/All)

```rust
#[test]
fn check_for_leaks() {
    let _profiler = dhat::Profiler::new_heap();

    // Test code that might leak
    for _ in 0..1000 {
        keyless_sign_operation();
    }

    // dhat will report allocations on drop
}
```

### Using Instruments (macOS)

```bash
# Profile for leaks
cargo instruments --template Leaks --bin wsc -- sign test.wasm

# Instruments will show:
# - Leaked memory blocks
# - Stack traces of leaks
# - Memory graph
```

## Continuous Integration Setup

### GitHub Actions

The `.github/workflows/memory-profile.yml` workflow:
- Runs on PRs that modify Rust code
- Builds and runs tests with ByteHound
- Uploads profiling data as artifacts
- Provides instructions in summary

### Local Docker Setup

```bash
# Build once
docker build -f Dockerfile.bytehound -t wsc-bytehound .

# Run profiling
./scripts/profile-memory.sh

# View results
./scripts/view-profile.sh
```

## Common Profiling Scenarios

### 1. Profile Rekor Verification

```rust
#[test]
fn profile_rekor_verification() {
    let _profiler = dhat::Profiler::new_heap();

    // Load entry
    let entry = load_test_entry();

    // Profile verification
    for _ in 0..100 {
        verify_checkpoint(&entry).unwrap();
    }
}
```

### 2. Profile WASM Signature Operations

```bash
cargo instruments --template Allocations -- \
  cargo test test_signature_verification --release
```

### 3. Find Allocation Hotspots

```bash
# With ByteHound (Linux)
LD_PRELOAD=./libbytehound.so cargo bench

# With Instruments (macOS)
cargo instruments --template Allocations -- cargo bench
```

## Interpreting Results

### ByteHound UI

- **Allocations Tab**: See all allocations, sorted by size/count
- **Flame Graph**: Visual representation of allocation call stacks
- **Leaked Memory**: Filter for memory not freed
- **Timeline**: See allocation patterns over time

### dhat-rs Output

```
dhat: Total:     1,024 bytes in 10 blocks
dhat: At t-gmax: 512 bytes in 5 blocks
dhat: Leaked:    0 bytes in 0 blocks
```

- `Total`: All allocations during run
- `At t-gmax`: Peak memory usage
- `Leaked`: Memory not freed

### Instruments

- Red bars: Memory leaks
- Allocation list: Sorted by size
- Call trees: Where allocations happen
- Generations: Object lifecycle

## Best Practices

1. **Profile in Release Mode**: `cargo test --release` gives realistic results
2. **Use Consistent Workloads**: Same operations for comparison
3. **Profile Multiple Times**: Results can vary
4. **Focus on Hot Paths**: Profile critical code paths (keyless signing, verification)
5. **Track Over Time**: Compare before/after changes

## Further Reading

- [ByteHound Documentation](https://github.com/koute/bytehound)
- [dhat-rs Documentation](https://docs.rs/dhat/)
- [Rust Performance Book - Profiling](https://nnethercote.github.io/perf-book/profiling.html)
- [cargo-instruments](https://github.com/cmyr/cargo-instruments)
