# Allocation-Free Verification Findings

## Summary

We tested wsc's critical code paths to determine which operations can run allocation-free after initialization. This is important for:
- **Real-time systems** (deterministic execution)
- **Safety-critical systems** (ASIL-B automotive requirements)
- **Performance hotpaths** (zero GC pressure)

## Test Results

| Operation | Allocation-Free? | Notes |
|-----------|------------------|-------|
| **SHA-256 hashing** | ✅ Yes | Zero allocations, ~4KB input tested |
| **Ed25519 signature verification** | ✅ Yes | Raw cryptographic operation allocation-free |
| **Pre-loaded keyring access** | ✅ Yes | Reading from pre-initialized HashMap |
| **WASM module parsing** | ❌ No | Requires `Vec<Section>` allocations |
| **WASM signature verification** | ❌ No | Must parse module (see above) |
| **Rekor SET verification** | 🟡 Partial | Crypto is free, parsing isn't |
| **Merkle inclusion proof** | 🟡 Partial | Hash operations free, Vec allocations aren't |

## Detailed Analysis

### ✅ **SHA-256 Hashing** (Allocation-Free)

```rust
// INIT
let data = vec![0u8; 4096];

// HOT PATH - NO ALLOCATIONS
let mut hasher = Sha256::new();
hasher.update(&data);
let hash = hasher.finalize();
```

**Why allocation-free?**
- Hasher state is stack-allocated (fixed-size buffer)
- Hash output is fixed 32 bytes (returned by value)
- No dynamic data structures needed

**Test result**: ✅ 0 allocation attempts

---

### ✅ **Ed25519 Signature Verification** (Allocation-Free)

```rust
// INIT
let keypair = ed25519_compact::KeyPair::generate();
let message = b"test message";
let signature = keypair.sk.sign(message, None);
let pk = keypair.pk;

// HOT PATH - NO ALLOCATIONS
let result = pk.verify(message, &signature);
```

**Why allocation-free?**
- All ed25519-compact operations use stack-allocated arrays
- Public key: 32 bytes
- Signature: 64 bytes
- No heap allocations in verification math

**Test result**: ✅ 0 allocation attempts

**Implication**: Once you have a parsed public key, verifying Ed25519 signatures is allocation-free!

---

### ❌ **WASM Module Parsing** (Allocates)

```rust
// HOT PATH - ALLOCATES
let mut reader = Cursor::new(&wasm_bytes);
let module = Module::deserialize(&mut reader); // ❌ Allocates
```

**Why it allocates?**
```rust
pub struct Module {
    pub header: Header,
    pub sections: Vec<Section>,  // ❌ Dynamic allocation
}
```

Each section is dynamically sized:
- Custom sections have `Vec<u8>` payload
- Code sections have `Vec<Function>`
- Data sections have `Vec<DataSegment>`

**Test result**: ❌ Aborted (allocations detected)

**Fix would require**: Pre-allocating fixed-size buffers or arena allocator

---

### ❌ **WASM Signature Verification** (Allocates)

```rust
// HOT PATH - ALLOCATES
let mut reader = Cursor::new(&signed_module);
let result = pk.verify(&mut reader, None); // ❌ Allocates during parsing
```

**Why it allocates?**
`PublicKey::verify()` internally calls:
1. `Module::iterate()` - parses sections ❌
2. Finds signature header custom section
3. Reads signature data
4. ✅ Ed25519 verification (allocation-free)
5. Hashes module sections ✅ (allocation-free)

**Root cause**: Steps 1-3 require parsing WASM sections dynamically

**Test result**: ❌ Aborted (allocations detected)

---

### 🟡 **Rekor SET Verification** (Partially Allocation-Free)

The crypto operations ARE allocation-free:

```rust
// ✅ Allocation-free parts
let signature = Signature::from_der(&signature_bytes).unwrap();
let set_bytes = build_set_canonical_json(&entry); // ❌ Allocates JSON string
let hash = Sha256::digest(&set_bytes); // ✅ Allocation-free
verifying_key.verify(&hash, &signature); // ✅ Allocation-free
```

**Breakdown**:
- ❌ `serde_json` serialization allocates `String`
- ✅ SHA-256 hashing is allocation-free
- ✅ ECDSA P-256 verification is allocation-free

**Workaround**: Pre-serialize SET during init phase

---

### 🟡 **Merkle Inclusion Proof** (Partially Allocation-Free)

```rust
pub fn verify_merkle_proof(
    leaf_hash: &[u8],
    log_index: u64,
    tree_size: u64,
    hashes: &[Vec<u8>],  // ❌ Vec of Vecs
    root_hash: &[u8],
) -> Result<(), WSError>
```

**Allocation sources**:
- `hashes: &[Vec<u8>]` - pre-allocated in init ✅
- Hash concatenation: `let combined = [left, right].concat()` ❌

**Fix**: Use fixed-size buffer:
```rust
let mut combined = [0u8; 64]; // 32 + 32
combined[..32].copy_from_slice(left);
combined[32..].copy_from_slice(right);
let hash = Sha256::digest(&combined); // ✅ Allocation-free
```

---

## Allocation-Free Strategy for wsc

### Current State (What's Free Today)

```rust
// ✅ These operations are allocation-free:
1. SHA-256 hashing
2. Ed25519 signature verification (raw)
3. ECDSA P-256 verification (raw crypto)
4. Reading from pre-loaded data structures
```

### Path to Allocation-Free Verification

#### Option 1: Pre-Parse Everything (Recommended)

```rust
// INIT PHASE: Parse once, allocate all data structures
struct VerificationContext {
    module_hash: [u8; 32],           // ✅ Fixed size
    signature: ed25519_compact::Signature,  // ✅ 64 bytes
    public_key: ed25519_compact::PublicKey, // ✅ 32 bytes
    // NO MODULE STRUCTURE - just the hash!
}

// HOT PATH: Verify using pre-parsed data
fn verify_hot_path(ctx: &VerificationContext) -> Result<(), WSError> {
    // ✅ Allocation-free: just crypto operations
    ctx.public_key.verify(&ctx.module_hash, &ctx.signature)?;
    Ok(())
}
```

**Trade-off**: Lose ability to verify specific sections (all-or-nothing)

#### Option 2: Arena Allocator for Parsing

```rust
use bumpalo::Bump;

// INIT: Pre-allocate arena (e.g., 1MB)
let arena = Bump::with_capacity(1024 * 1024);

// HOT PATH: Parse into arena (fast bump allocation)
let module = parse_module_in_arena(&arena, wasm_bytes)?;

// After verification: arena.reset() resets everything
```

**Trade-off**: Still allocates (but predictably, into fixed buffer)

#### Option 3: Streaming Verification (No Parsing)

```rust
// HOT PATH: Stream through WASM sections, verify on-the-fly
fn verify_streaming(
    reader: &mut impl Read,
    pk: &PublicKey,
    signature: &Signature,
) -> Result<(), WSError> {
    let mut hasher = Sha256::new();

    // Read WASM sections, hash as we go
    while let Some(section) = read_next_section_zero_copy(reader)? {
        hasher.update(section); // ✅ No allocation
    }

    let hash = hasher.finalize(); // ✅ No allocation
    pk.verify(&hash, signature)?; // ✅ No allocation
    Ok(())
}
```

**Trade-off**: Complex implementation, need zero-copy section reading

---

## Recommendations for Production Use

### For Real-Time/Safety-Critical Systems

**Use Option 1 (Pre-Parse)**:
```rust
// Initialization (allocations OK)
let ctx = parse_and_validate_module(&wasm_bytes)?;

// Hot path (allocation-free)
loop {
    // Real-time event
    verify_hot_path(&ctx)?; // ✅ Allocation-free
    execute_verified_code();
}
```

**Rationale**:
- Initialization happens once (outside real-time loop)
- Hot path is 100% allocation-free
- Predictable, deterministic execution

### For WebAssembly Component Model

**Monitor `memory.grow` at runtime**:
```rust
// In Wasmtime
store.limiter(|_| {
    MemoryLimiter::new()
        .memory_size(initial_pages * 65536) // Fixed size
});

// After init:
store.limiter_mut().lock_memory_growth(); // Prevent any growth
```

**Rationale**:
- Coarse-grained but effective
- Zero overhead (trap on grow)
- Works for any WASM code (not just Rust)

### For General Use (Development)

**Use all three approaches**:
1. **Phase-locked allocator** (this implementation) - Development testing
2. **ByteHound** (CI/Linux) - Detailed diagnostics when violations occur
3. **memory.grow hooks** (Production WASM) - Runtime safety

---

## Comparison: Approaches for Different Contexts

| Context | Best Approach | Why |
|---------|---------------|-----|
| **Automotive ECU (QNX)** | ByteHound + Pre-Parse | Certification + Real-time performance |
| **WASM Component** | `memory.grow` hooks | Runtime enforcement |
| **Rust Native** | Phase-Locked Allocator | Development iteration |
| **CI Pipeline** | ByteHound | Detailed reports + Artifacts |
| **Edge Runtime** | Pre-Parse + Monitoring | Defense in depth |

---

## Next Steps

### Immediate (What We Have Now)

✅ Phase-locked allocator implemented
✅ Test suite showing what's allocation-free
✅ Documentation of current state

### Short-Term Improvements

1. **Pre-parsing API**: Add `VerificationContext` struct that pre-parses modules
2. **Streaming verification**: Implement zero-copy section reading
3. **CI integration**: Add ByteHound to GitHub Actions

### Long-Term (Production Hardening)

1. **Arena allocator**: For predictable parsing performance
2. **WASM runtime hooks**: Memory growth monitoring in Wasmtime
3. **Fuzzing**: Test allocator with malformed inputs
4. **Certification**: Prepare artifacts for ASIL-B audit

---

## Conclusion

**What we learned**:
- ✅ Cryptographic primitives (hashing, signing) are allocation-free
- ❌ WASM parsing currently requires dynamic allocation
- 🟡 With pre-parsing, verification CAN be allocation-free

**Bottom line**: You CAN achieve allocation-free verification in wsc, but it requires restructuring the API to separate parsing (init phase) from verification (hot path).

The phase-locked allocator we built is the perfect tool to:
1. **Measure** which operations allocate (done ✅)
2. **Enforce** allocation-free requirements (works ✅)
3. **Guide** refactoring to eliminate allocations (roadmap above)

For your immediate use case ("ensure we don't go off board in hot path"), I recommend:
- **Development**: Use the phase-locked allocator
- **Production**: Add `memory.grow` monitoring in Wasmtime
- **Future**: Implement pre-parsing API for true allocation-free verification
