# CI Memory Analysis Guide

## Overview

The **Memory Analysis** workflow provides automated memory profiling and allocation-free verification for every pull request that modifies Rust code.

## Workflow Components

The workflow consists of three parallel jobs:

### 1. 🔒 Allocation-Free Verification
**Duration**: < 1 minute
**Purpose**: Fast verification of which operations are allocation-free

Tests real wsc operations:
- ✅ SHA-256 hashing
- ✅ Ed25519 signature verification
- ❌ WASM module parsing
- ❌ WASM signature verification
- ✅ Pre-loaded keyring access

**Output**:
- Workflow summary with ✅/❌ results
- `allocation-guard-log` artifact (7-day retention)

### 2. 📊 ByteHound Profiling
**Duration**: ~5 minutes
**Purpose**: Detailed allocation analysis with flame graphs

Generates comprehensive profiling data showing:
- All allocation call stacks
- Memory usage timeline
- Potential leaks
- Allocation hotspots

**Output**:
- `bytehound-profiles` artifact (30-day retention)
- `bytehound-test-logs` artifact (7-day retention)

### 3. 📋 Summary
**Duration**: < 10 seconds
**Purpose**: Combined report of both analyses

Shows the status of both jobs and provides guidance on next steps.

## Triggering the Workflow

### Automatic Triggers
The workflow runs automatically on pull requests when these files change:
- `src/**/*.rs` (any Rust source file)
- `Cargo.toml` (dependencies)
- `Cargo.lock` (dependency versions)
- `.github/workflows/memory-profile.yml` (the workflow itself)

### Manual Trigger
You can also run the workflow manually:
1. Go to the **Actions** tab
2. Select **Memory Analysis** workflow
3. Click **Run workflow**
4. Choose the branch
5. Click **Run workflow** button

## Reading the Results

### Quick Check (Workflow Summary)

Each job produces a summary visible in the GitHub Actions UI:

**Allocation-Free Verification Summary**:
```
🔒 Allocation-Free Verification

Testing which operations are allocation-free...

Results:
✅ ALLOCATION-FREE! SHA-256 hashing succeeded without allocations
✅ ALLOCATION-FREE! Ed25519 verification succeeded without allocations
❌ ALLOCATES: Module parsing requires allocations
❌ ALLOCATES: Signature verification requires allocations
✅ ALLOCATION-FREE! Keyring access succeeded without allocations
```

**ByteHound Profile Summary**:
```
📊 ByteHound Memory Profile

✅ Memory profiling data collected successfully

Profile Files:
- memory-profiling_wsc-1234567890.dat (2.3M)

How to Analyze:
1. Download the bytehound-profiles artifact
2. Install ByteHound locally
3. Run: bytehound server memory-profiling_*.dat
4. Open http://localhost:8080
```

### Detailed Analysis (Artifacts)

Download artifacts from the workflow run:

```bash
# From GitHub Actions UI: Download artifact ZIP
# Then extract and analyze

# Option 1: View allocation test log
unzip allocation-guard-log.zip
cat allocation_test.log

# Option 2: Analyze ByteHound profiles (Linux only)
unzip bytehound-profiles.zip
bytehound server memory-profiling_*.dat
# Open http://localhost:8080
```

## Interpreting ByteHound Results

### Flame Graph View

Shows allocation call stacks visually:
- **Width**: Proportional to number of allocations
- **Height**: Call stack depth
- **Color**: Different functions

**Example reading**:
```
test::run_test (1000 allocs)
└── Module::deserialize (950 allocs)
    └── Vec::push (950 allocs)  ← This is the allocation hotspot!
```

### Allocations Tab

Lists all allocations sorted by:
- **By size**: Find memory hogs
- **By count**: Find allocation hotspots
- **By backtrace**: Group by call stack

**What to look for**:
- Unexpected allocations in hot paths
- Large allocations (> 1MB)
- Frequent small allocations (indicate buffering issues)

### Timeline View

Shows allocation patterns over time:
- **Spikes**: Burst allocations (initialization, parsing)
- **Flat regions**: Steady-state operation
- **Growing trend**: Potential leak

**Good pattern**:
```
Memory
  │   ▲ Init phase (many allocations)
  │  ╱│
  │ ╱ │
  │╱  └─────────────── Hot path (flat, no allocations)
  └────────────────────────────────> Time
```

**Bad pattern** (leak):
```
Memory
  │                    ╱
  │                  ╱
  │                ╱
  │              ╱
  │            ╱   ← Memory keeps growing (leak!)
  └────────────────────────────────> Time
```

### Leaked Memory Tab

Shows allocations that were never freed:
- **Expected leaks**: Static/lazy_static data (OK)
- **Unexpected leaks**: Forgotten deallocations (bug!)

**Filter tips**:
- Exclude test setup code (focus on hot paths)
- Look for patterns (same stack multiple times)
- Check if leak is proportional to input size

## CI Performance Optimization

The workflow uses aggressive caching to speed up builds:

**Cached**:
- ✅ ByteHound binary (downloaded once per version)
- ✅ Cargo registry (shared across runs)
- ✅ Cargo git index (shared across runs)
- ✅ Target directory (separate cache per job)

**Typical run times**:
- **First run**: ~10 minutes (cold cache)
- **Subsequent runs**: ~3-4 minutes (warm cache)
- **No code changes**: ~1-2 minutes (fully cached)

## Troubleshooting

### Workflow Fails with "No profiling data generated"

**Cause**: ByteHound failed to attach or tests crashed

**Fix**:
1. Check `bytehound-test-logs` artifact for errors
2. Verify `LD_PRELOAD` is set correctly
3. Check if tests pass without ByteHound:
   ```bash
   cargo test --release -- --test-threads=1
   ```

### Allocation-Free Tests Fail (SIGABRT)

**Cause**: Operation allocated in hot path (expected for some tests)

**This is normal** for tests that document which operations allocate:
- ❌ Module parsing (expected)
- ❌ Signature verification (expected)

**Action needed only if**:
- Previously allocation-free operation now allocates (regression)
- Check the logs to see which operation changed

### ByteHound Viewer Won't Start

**Cause**: ByteHound only works on Linux

**Options**:
1. Use a Linux VM or container
2. Use Docker:
   ```bash
   docker run --rm -p 8080:8080 -v $(pwd):/data \
     koute/bytehound bytehound server /data/memory-profiling_*.dat
   ```
3. Use GitHub Codespaces (Linux environment)

### Profile Files Too Large

**Cause**: Long-running tests generate large profiles

**Fix**:
1. Reduce test duration
2. Profile specific tests only:
   ```bash
   cargo test --release specific_test -- --test-threads=1
   ```
3. Increase artifact retention (max 30 days)

## Best Practices

### For PR Authors

1. **Check the summary** before requesting review
2. **Download artifacts** if allocation patterns changed
3. **Document** why new allocations are necessary
4. **Compare** with main branch (look for regressions)

### For Reviewers

1. **Verify** no allocation regressions in hot paths
2. **Check** flame graphs for new allocation hotspots
3. **Ensure** documentation updated if allocations added
4. **Request changes** if unexpected allocations introduced

### For Maintainers

1. **Monitor** profile sizes over time
2. **Archive** important profiles for comparison
3. **Update** ByteHound version periodically
4. **Tune** cache settings as repo grows

## Advanced Usage

### Profile Specific Tests Only

Edit workflow to target specific tests:

```yaml
- name: Run tests with ByteHound profiling
  env:
    MEMORY_PROFILER_LOG: warn
    LD_PRELOAD: ${{ env.HOME }}/.cargo/bin/libbytehound.so
  run: |
    # Profile only Rekor verification tests
    cargo test --release rekor -- --test-threads=1 --nocapture
```

### Compare Profiles Across Commits

```bash
# Download profiles from two workflow runs
unzip bytehound-profiles-pr-123.zip -d pr-123
unzip bytehound-profiles-main.zip -d main

# Compare allocation counts
bytehound diff main/memory-profiling_*.dat pr-123/memory-profiling_*.dat
```

### Export Data for Analysis

ByteHound can export to JSON for custom analysis:

```bash
bytehound export memory-profiling_*.dat > allocations.json
python analyze_allocations.py allocations.json
```

## Related Documentation

- [Memory Profiling Guide](memory_profiling.md) - Local profiling setup
- [Allocation-Free Findings](allocation_free_findings.md) - Analysis results
- [Phase-Locked Allocator API](../src/lib/src/allocator.rs) - Allocator implementation
- [Real-World Tests](../src/lib/tests/real_world_allocation_free.rs) - Test suite

## Questions?

If you have questions about the memory analysis results:
1. Check `docs/allocation_free_findings.md` for interpretation guide
2. Review ByteHound UI documentation at https://github.com/koute/bytehound
3. Open an issue with the workflow run link and artifact
