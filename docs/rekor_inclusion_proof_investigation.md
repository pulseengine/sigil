# Rekor Inclusion Proof Investigation

## Status: In Progress

### ✅ Completed

1. **SET Signature Verification** - WORKING
   - Fixed by using `DigestVerifier::verify_digest()` instead of `Verifier::verify()`
   - Verifies successfully with production Rekor data

2. **RFC 6962 Merkle Algorithm** - VALIDATED
   - 9/9 Google Certificate Transparency test vectors pass
   - Algorithm implementation is correct

3. **Diagnostic Logging** - COMPREHENSIVE
   - 30-step Merkle tree traversal with all intermediate hashes
   - Leaf hash computation details
   - Clear error messages showing computed vs expected roots

### ⚠️ Current Issue: Inclusion Proof Root Hash Mismatch

**Symptoms:**
- Expected root: `e3b5321b90b449daee48501348db322f4377dab370402916cff55086941f57cc`
- Computed root: `4aafd66a0359989b6bc9a5c8f1cd2eef6a165eb93c3a23cdfbcfd0c819ca7dcd`
- Entry log_index: 538771042
- Tree size: 538772043
- 30 proof hashes provided

**Test Entry Details:**
```
UUID: 108e9186e8c5677a1b77086cce5d81d1fed81432617971b2c6993681aced1a044c89465e8c60fe20
├─ First 16 chars (8 bytes):  108e9186e8c5677a
└─ Last 64 chars (32 bytes):  1b77086cce5d81d1fed81432617971b2c6993681aced1a044c89465e8c60fe20
```

### Hypotheses Tested

| Hypothesis | Approach | Result |
|-----------|----------|--------|
| **Last 64 chars** | Extract last 64 hex chars of UUID (32 bytes) | ❌ Root mismatch |
| **Full UUID** | Use all 80 hex chars / first 64 chars | ❌ Root mismatch |
| **RFC 6962 prefix** | Apply SHA256(0x00 \\| uuid_bytes) | ❌ Root mismatch |
| **proof.logIndex** | Use proof.logIndex (416866780) instead of entry.logIndex | ❌ Root mismatch |
| **Decoded body** | Compute from base64-decoded body | ❌ Root mismatch |

### Key Observations

1. **Checkpoint Verification**
   - Checkpoint contains base64 root: `47UyG5C0SdruSFATSNsyL0N32rNwQCkWz/VQhpQfV8w=`
   - Decodes to: `e3b5321b...` (matches expected root ✅)
   - Confirms our expected root is correct

2. **UUID Structure Mystery**
   - UUID is 80 hex characters (40 bytes)
   - Standard SHA256 is 32 bytes (64 hex chars)
   - First 16 chars may be tree ID, shard ID, or timestamp

3. **Log Index Discrepancy**
   - Entry log_index: 538771042 (used in verification)
   - Proof log_index: 416866780 (different - unclear purpose)
   - Difference: 121,904,262 (no obvious pattern)

4. **Merkle Tree Behavior**
   - Algorithm correctly traverses 30 levels
   - Properly determines left/right child at each step
   - Uses correct RFC 6962 node hashing (0x01 \\| left \\| right)
   - But starts with wrong leaf hash

### Diagnostic Output Example

```
🔍 Inclusion Proof Debug Info:
   Log Index: 538771042
   Tree size: 538772043
   UUID: 108e9186...
   Leaf hash (from UUID): 1b77086cce5d81d1...
   Number of proof hashes: 30
   Expected root hash: e3b5321b90b449daee48501348db322f4377dab370402916cff55086941f57cc

⏳ Computing Merkle root from leaf...
   Starting with leaf hash: 1b77086cce5d81d1...
   Leaf index: 538771042, Tree size: 538772043

   Step 1: LEFT child
     Left:   1b77086cce5d81d1...
     Right:  3cf783511a4100e2...
     Result: c2cc11aa859b59cf...

   [... 28 more steps ...]

   Step 30: LEFT child
     Left:   60825864a14c077e...
     Right:  719f009900e8a014...
     Result: 4aafd66a0359989b...

   Final computed root: 4aafd66a0359989b6bc9a5c8f1cd2eef6a165eb93c3a23cdfbcfd0c819ca7dcd
```

### Next Steps

1. **Examine Rekor Go Implementation**
   - Check how Rekor generates UUIDs
   - Verify exact leaf hash computation
   - Understand inclusion proof structure

2. **Check sigstore-rs Implementation**
   - See if they've solved this
   - Compare with our approach

3. **Test with Different Entries**
   - Fetch multiple entries from different tree positions
   - See if pattern emerges

4. **Contact Sigstore Community**
   - If implementation details aren't clear from code
   - Ask about UUID structure and leaf hash extraction

### References

- [Rekor OpenAPI Spec](https://github.com/sigstore/rekor/blob/main/openapi.yaml)
- [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962.html)
- [RFC 8785: JSON Canonicalization](https://www.rfc-editor.org/rfc/rfc8785.html)
- [Sigstore Documentation](https://docs.sigstore.dev/)

### Test Data Location

- Fresh production entry: `src/lib/src/signature/keyless/rekor_verifier.rs.test_data/recent_entry_*.json`
- Test script: `scripts/fetch_recent_rekor_entry.sh`
- Documentation: `docs/rekor_testing.md`

### CI Verification

The comprehensive diagnostic logging is now in the codebase. When CI runs, you'll see:
- Complete 30-step Merkle traversal
- All intermediate hashes
- Left/right child decisions
- Final computed vs expected root

This will help identify if the behavior differs across environments or if we need to adjust our approach.
