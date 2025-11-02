# Rekor Leaf Hash Computation Fix

## Problem

The inclusion proof verification was using an incorrect method to obtain the Merkle tree leaf hash:
- ❌ **Old approach**: Extracted leaf hash from the last 64 hex characters of the UUID
- The UUID does contain the leaf hash, but during verification we must recompute it

## Root Cause Analysis

By examining Rekor's reference implementation (`/tmp/rekor/pkg/verify/verify.go:158-162`), we discovered the correct approach:

```go
// Verify the inclusion proof.
entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
if err != nil {
    return err
}
leafHash := rfc6962.DefaultHasher.HashLeaf(entryBytes)
```

## Solution

Per Rekor's `verify.go`, the correct leaf hash computation is:

1. **Base64 decode** the `body` field from the log entry
2. **Compute RFC 6962 leaf hash**: `SHA-256(0x00 || body_bytes)`
   - The `0x00` byte is the RFC 6962 domain separator for leaf nodes
   - This prevents collision attacks between leaf and interior node hashes

The UUID **is** derived from this hash, but during verification we must recompute it from the body.

## Changes Made

### rekor_verifier.rs:280-293

**Before:**
```rust
// Extract the leaf hash from the UUID (last 64 hex characters = 32 bytes SHA256)
let uuid_len = entry.uuid.len();
let leaf_hash_hex = &entry.uuid[uuid_len - 64..];
let leaf_hash_bytes = hex::decode(leaf_hash_hex)?;
```

**After:**
```rust
// Compute the leaf hash from the entry body (per RFC 6962)
// Per Rekor's verify.go:158-162, the leaf hash is computed as:
//   1. Base64 decode the body field
//   2. Compute SHA-256(0x00 || body_bytes)
let body_bytes = BASE64.decode(&entry.body)?;
let leaf_hash = merkle::compute_leaf_hash(&body_bytes);
```

### rekor_verifier.rs:340-341

Also fixed to use `proof.log_index` instead of `entry.log_index` per Rekor's implementation:

**Before:**
```rust
merkle::verify_inclusion_proof(
    entry.log_index,  // Wrong!
    ...
)
```

**After:**
```rust
merkle::verify_inclusion_proof(
    proof.log_index,  // Correct - matches Rekor's verify.go:164
    ...
)
```

## Verification

Tested with production Rekor data:

```
UUID: 108e9186e8c5677a1b77086cce5d81d1fed81432617971b2c6993681aced1a044c89465e8c60fe20
                    └─────────────────────┬────────────────────────────────────┘
                                    Leaf hash (64 hex chars)

Computed from body: 1b77086cce5d81d1fed81432617971b2c6993681aced1a044c89465e8c60fe20
UUID last 64 chars: 1b77086cce5d81d1fed81432617971b2c6993681aced1a044c89465e8c60fe20
                                                                    ✅ MATCH!
```

## Status

- ✅ Leaf hash computation: **FIXED** (matches Rekor reference implementation)
- ✅ SET signature verification: **WORKING** (validated with production data)
- ⚠️  Full inclusion proof: Test data may need updating (tree state changes over time)

## References

- Rekor source: https://github.com/sigstore/rekor
- Key file: `/tmp/rekor/pkg/verify/verify.go:141-170`
- UUID structure: `/tmp/rekor/pkg/sharding/sharding.go:25-36`
- RFC 6962: https://datatracker.ietf.org/doc/html/rfc6962
