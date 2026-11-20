//! RFC 6962 Merkle Tree Inclusion Proof Verification
//!
//! This module implements cryptographic verification of Merkle tree inclusion proofs
//! according to RFC 6962 (Certificate Transparency). Rekor uses RFC 6962-style Merkle
//! trees via the Trillian transparency log infrastructure.
//!
//! # Security Model
//!
//! Merkle tree inclusion proofs provide cryptographic evidence that a specific entry
//! exists in a transparency log at a given tree size. The proof consists of:
//! - A sequence of sibling hashes along the path from leaf to root
//! - The leaf index in the tree
//! - The tree size at verification time
//! - The expected root hash
//!
//! # RFC 6962 Hash Computation
//!
//! **Leaf Hash**: `SHA-256(0x00 || leaf_data)`
//! - The `0x00` byte is the domain separator for leaf nodes
//! - Prevents second-preimage attacks
//!
//! **Interior Node Hash**: `SHA-256(0x01 || left_child || right_child)`
//! - The `0x01` byte is the domain separator for interior nodes
//! - left_child and right_child are 32-byte SHA-256 hashes
//!
//! # Implementation
//!
//! This is a from-scratch implementation based on RFC 6962 specification.
//! It does NOT use external merkle tree libraries to ensure:
//! - Full audit trail of every line of code
//! - No dependency on unaudited crypto libraries
//! - Clear security review path

use crate::error::WSError;
use sha2::{Digest, Sha256};

/// RFC 6962 domain separator for leaf nodes
const LEAF_PREFIX: u8 = 0x00;

/// RFC 6962 domain separator for interior nodes
const NODE_PREFIX: u8 = 0x01;

/// Compute RFC 6962 leaf hash
///
/// # Arguments
/// * `data` - The leaf data bytes
///
/// # Returns
/// 32-byte SHA-256 hash with leaf domain separator
///
/// # Security
/// The 0x00 prefix ensures leaf hashes cannot collide with interior node hashes.
/// This prevents second-preimage attacks where an attacker tries to find a different
/// tree structure that produces the same root hash.
pub fn compute_leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute RFC 6962 interior node hash
///
/// # Arguments
/// * `left` - Left child hash (32 bytes)
/// * `right` - Right child hash (32 bytes)
///
/// # Returns
/// 32-byte SHA-256 hash of the combined children
///
/// # Security
/// The 0x01 prefix ensures interior node hashes cannot collide with leaf hashes.
pub fn compute_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Verify a Merkle tree inclusion proof according to RFC 6962
///
/// # Arguments
/// * `leaf_index` - Index of the leaf in the tree (0-based)
/// * `tree_size` - Total number of leaves in the tree
/// * `leaf_hash` - Hash of the leaf data (32 bytes)
/// * `proof_hashes` - Audit path hashes, ordered leaf to root (RFC 6962 PATH)
/// * `expected_root` - Expected Merkle tree root hash (32 bytes)
///
/// # Returns
/// `Ok(())` if the proof is valid, `Err(WSError)` otherwise
///
/// # Algorithm
///
/// RFC 6962 §2.1.1 defines PATH(m, D[n]) recursively from the root down:
/// split at k, the largest power of two below n, recurse into the half
/// that holds m, and append the other half's root. The audit path is
/// therefore ordered leaf to root, and its last hash is the sibling at the
/// root's split.
///
/// 1. Descend from the root exactly as PATH does, recording at each level
///    whether leaf m lies in the right subtree. The number of levels is
///    the required proof length.
/// 2. Reject a proof of any other length.
/// 3. Hash upward from the leaf: proof hash j pairs with the decision made
///    j levels above the leaf, i.e. the decisions in reverse order.
/// 4. Compare the result with the expected root.
///
/// The walk before sigil#137's fix applied the top-down decisions in
/// top-down order to the leaf-to-root hashes. That agrees with RFC 6962
/// only when the decision sequence reads the same both ways (e.g. leaf 0
/// of a perfect tree), so real Rekor proofs failed.
///
/// # Security
/// - Validates that leaf exists in tree of specified size
/// - Cryptographically binds leaf to root via hash chain
/// - Rejects proofs with extra or missing hashes
pub fn verify_inclusion_proof(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8; 32],
    proof_hashes: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), WSError> {
    if tree_size == 0 {
        return Err(WSError::RekorError("Tree size cannot be zero".to_string()));
    }
    if leaf_index >= tree_size {
        return Err(WSError::RekorError(format!(
            "Leaf index {} is out of range for tree size {}",
            leaf_index, tree_size
        )));
    }

    // Step 1: root-to-leaf descent. Bit `d` of `right_turns` is set when,
    // at depth `d` below the root, the leaf lies in the right subtree.
    // A u64 tree has depth at most 64.
    let mut right_turns: u64 = 0;
    let mut depth: usize = 0;
    let mut index = leaf_index;
    let mut size = tree_size;
    while size > 1 {
        let k = largest_power_of_two_less_than(size);
        if index >= k {
            right_turns |= 1u64 << depth;
            index -= k;
            size -= k;
        } else {
            size = k;
        }
        depth += 1;
    }

    // Step 2: the proof length is fixed by (leaf_index, tree_size).
    if proof_hashes.len() != depth {
        return Err(WSError::RekorError(format!(
            "Inclusion proof has {} hashes; leaf {} of a tree of size {} needs {}",
            proof_hashes.len(),
            leaf_index,
            tree_size,
            depth
        )));
    }

    // Step 3: leaf-to-root hashing. proof_hashes[0] is the leaf's sibling,
    // which belongs to the deepest decision (depth - 1).
    let mut current_hash = *leaf_hash;
    for (j, sibling) in proof_hashes.iter().enumerate() {
        let is_right = (right_turns >> (depth - 1 - j)) & 1 == 1;
        current_hash = if is_right {
            compute_node_hash(sibling, &current_hash)
        } else {
            compute_node_hash(&current_hash, sibling)
        };
    }

    // Step 4.
    if &current_hash != expected_root {
        return Err(WSError::RekorError(format!(
            "Computed root hash does not match expected root. Computed: {}, Expected: {}",
            hex::encode(current_hash),
            hex::encode(expected_root)
        )));
    }

    Ok(())
}

/// Find the largest power of 2 less than n
///
/// Used in Merkle tree calculations to determine subtree sizes.
/// For example: n=7 returns 4, n=5 returns 4, n=8 returns 4, n=9 returns 8
fn largest_power_of_two_less_than(n: u64) -> u64 {
    if n <= 1 {
        return n;
    }

    // Highest set bit of n-1: the largest power of two strictly below n.
    // Closed form instead of a doubling loop: `power * 2` overflowed for
    // n > 2^63 (panic with overflow-checks, an endless loop without).
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Reference RFC 6962 §2.1 Merkle tree, written straight from the
/// recursive definitions of MTH and PATH. Tests use it as the oracle for
/// `verify_inclusion_proof`; it shares only the two hash primitives.
#[cfg(test)]
pub(crate) mod reference {
    use super::compute_node_hash;

    /// k: the largest power of two smaller than n (n > 1).
    fn split(n: usize) -> usize {
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        k
    }

    /// MTH over leaf hashes (n >= 1).
    pub(crate) fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => panic!("MTH of an empty list is not needed here"),
            1 => leaves[0],
            n => {
                let k = split(n);
                compute_node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    /// PATH(m, D[n]): the audit path for leaf m, ordered leaf to root.
    pub(crate) fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let n = leaves.len();
        if n == 1 {
            return Vec::new();
        }
        let k = split(n);
        if m < k {
            let mut p = path(m, &leaves[..k]);
            p.push(mth(&leaves[k..]));
            p
        } else {
            let mut p = path(m - k, &leaves[k..]);
            p.push(mth(&leaves[..k]));
            p
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| compute_leaf_hash(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    /// The reference tree reproduces the Google CT root vectors, so it is
    /// an oracle independent of `verify_inclusion_proof`.
    // rivet: verifies REQ-40
    #[test]
    fn test_reference_tree_matches_ct_root_vectors() {
        let inputs: Vec<&[u8]> = vec![
            &[],
            &[0x00],
            &[0x10],
            &[0x20, 0x21],
            &[0x30, 0x31],
            &[0x40, 0x41, 0x42, 0x43],
            &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            &[
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
                0x6e, 0x6f,
            ],
        ];
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let leaves: Vec<[u8; 32]> = inputs.iter().map(|d| compute_leaf_hash(d)).collect();
        for n in 1..=8 {
            assert_eq!(
                hex::encode(reference::mth(&leaves[..n])),
                roots[n - 1],
                "n={n}"
            );
        }
    }

    /// Every leaf of every tree size up to 40 verifies with its RFC 6962
    /// audit path. The pre-fix walk split the tree top-down but consumed
    /// the leaf-to-root path bottom-up, so it failed e.g. leaf 1 of 8.
    // rivet: verifies REQ-40
    #[test]
    fn test_inclusion_every_index_matches_rfc6962_reference() {
        for n in 1..=40usize {
            let leaves = synthetic_leaves(n);
            let root = reference::mth(&leaves);
            for m in 0..n {
                let p = reference::path(m, &leaves);
                verify_inclusion_proof(m as u64, n as u64, &leaves[m], &p, &root)
                    .unwrap_or_else(|e| panic!("leaf {m} of {n}: {e}"));
            }
        }
    }

    /// Planted controls on a valid path: a flipped sibling, an extra or a
    /// missing sibling, a different index, or a different leaf must fail.
    // rivet: verifies REQ-40
    #[test]
    fn test_inclusion_rejects_tampered_paths() {
        for (n, m) in [(2usize, 1usize), (7, 3), (8, 1), (13, 12), (33, 17)] {
            let leaves = synthetic_leaves(n);
            let root = reference::mth(&leaves);
            let p = reference::path(m, &leaves);
            let (mi, ni) = (m as u64, n as u64);
            assert!(verify_inclusion_proof(mi, ni, &leaves[m], &p, &root).is_ok());
            for i in 0..p.len() {
                let mut bad = p.clone();
                bad[i][0] ^= 1;
                assert!(verify_inclusion_proof(mi, ni, &leaves[m], &bad, &root).is_err());
            }
            let mut longer = p.clone();
            longer.push([0u8; 32]);
            assert!(verify_inclusion_proof(mi, ni, &leaves[m], &longer, &root).is_err());
            let shorter = &p[..p.len() - 1];
            assert!(verify_inclusion_proof(mi, ni, &leaves[m], shorter, &root).is_err());
            let other = (m + 1) % n;
            assert!(verify_inclusion_proof(other as u64, ni, &leaves[m], &p, &root).is_err());
            assert!(verify_inclusion_proof(mi, ni, &leaves[other], &p, &root).is_err());
        }
    }

    #[test]
    fn test_leaf_hash_computation() {
        // Test that leaf hash includes the 0x00 prefix
        let data = b"test data";
        let hash = compute_leaf_hash(data);

        // Manually compute expected hash
        let mut expected = Sha256::new();
        expected.update([0x00]);
        expected.update(data);
        let expected_hash: [u8; 32] = expected.finalize().into();

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_node_hash_computation() {
        // Test that node hash includes the 0x01 prefix
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash = compute_node_hash(&left, &right);

        // Manually compute expected hash
        let mut expected = Sha256::new();
        expected.update([0x01]);
        expected.update(left);
        expected.update(right);
        let expected_hash: [u8; 32] = expected.finalize().into();

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_single_leaf_tree() {
        // Tree with just one leaf
        let leaf_hash = [0x42u8; 32];
        let result = verify_inclusion_proof(0, 1, &leaf_hash, &[], &leaf_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_leaf_tree_wrong_root() {
        let leaf_hash = [0x42u8; 32];
        let wrong_root = [0x43u8; 32];
        let result = verify_inclusion_proof(0, 1, &leaf_hash, &[], &wrong_root);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_leaf_index() {
        let leaf_hash = [0x42u8; 32];
        let result = verify_inclusion_proof(
            5, // Invalid index for tree size 3
            3,
            &leaf_hash,
            &[],
            &leaf_hash,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_largest_power_of_two() {
        assert_eq!(largest_power_of_two_less_than(1), 1);
        assert_eq!(largest_power_of_two_less_than(2), 1);
        assert_eq!(largest_power_of_two_less_than(3), 2);
        assert_eq!(largest_power_of_two_less_than(4), 2);
        assert_eq!(largest_power_of_two_less_than(5), 4);
        assert_eq!(largest_power_of_two_less_than(7), 4);
        assert_eq!(largest_power_of_two_less_than(8), 4);
        assert_eq!(largest_power_of_two_less_than(9), 8);
        assert_eq!(largest_power_of_two_less_than(15), 8);
        assert_eq!(largest_power_of_two_less_than(16), 8);
        assert_eq!(largest_power_of_two_less_than(17), 16);
        // n > 2^63: the old doubling loop overflowed `power * 2` here.
        assert_eq!(largest_power_of_two_less_than((1 << 63) + 1), 1 << 63);
        assert_eq!(largest_power_of_two_less_than(u64::MAX), 1 << 63);
        assert_eq!(largest_power_of_two_less_than(1 << 63), 1 << 62);
    }

    #[test]
    fn test_huge_tree_size_returns_error_not_panic() {
        // tree_size > 2^63 comes from unsigned bundle input; it must yield an
        // error, not an overflow panic or an endless loop.
        let r = verify_inclusion_proof(0, (1u64 << 63) + 1, &[0u8; 32], &[[0u8; 32]], &[0u8; 32]);
        assert!(r.is_err());
        let r = verify_inclusion_proof(
            u64::MAX - 1,
            u64::MAX,
            &[0u8; 32],
            &[[0u8; 32]; 64],
            &[0u8; 32],
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_two_leaf_tree() {
        // Build a simple 2-leaf tree manually
        // Leaf 0: hash(0x00 || "leaf0")
        // Leaf 1: hash(0x00 || "leaf1")
        // Root: hash(0x01 || leaf0_hash || leaf1_hash)

        let leaf0_data = b"leaf0";
        let leaf1_data = b"leaf1";

        let leaf0_hash = compute_leaf_hash(leaf0_data);
        let leaf1_hash = compute_leaf_hash(leaf1_data);

        let root = compute_node_hash(&leaf0_hash, &leaf1_hash);

        // Verify leaf 0's inclusion (proof is leaf 1's hash)
        let result = verify_inclusion_proof(0, 2, &leaf0_hash, &[leaf1_hash], &root);
        assert!(result.is_ok(), "Failed to verify leaf 0");

        // Verify leaf 1's inclusion (proof is leaf 0's hash)
        let result = verify_inclusion_proof(1, 2, &leaf1_hash, &[leaf0_hash], &root);
        assert!(result.is_ok(), "Failed to verify leaf 1");
    }

    /// Test vectors from Google's certificate-transparency repository
    /// Source: https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc
    ///
    /// These are the official test vectors used by Certificate Transparency implementations.
    /// Validating against these ensures our RFC 6962 implementation is correct.
    #[test]
    fn test_google_ct_test_vectors() {
        // Test vector data from kInputs
        let inputs: Vec<&[u8]> = vec![
            &[],                                               // 0: empty
            &[0x00],                                           // 1: single byte
            &[0x10],                                           // 2: single byte
            &[0x20, 0x21],                                     // 3: 2 bytes
            &[0x30, 0x31],                                     // 4: 2 bytes
            &[0x40, 0x41, 0x42, 0x43],                         // 5: 4 bytes
            &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57], // 6: 8 bytes
            &[
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, // 7: 16 bytes
                0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
            ],
        ];

        // Expected root hashes for trees of size 1-8 (from kSHA256Roots)
        let expected_roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", // 1 leaf
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", // 2 leaves
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", // 3 leaves
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", // 4 leaves
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", // 5 leaves
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", // 6 leaves
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", // 7 leaves
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", // 8 leaves
        ];

        // Test 1: Validate single-leaf tree
        let leaf0_hash = compute_leaf_hash(inputs[0]);
        let expected_root0 = hex::decode(expected_roots[0]).unwrap();
        assert_eq!(
            &leaf0_hash[..],
            &expected_root0[..],
            "Single-leaf root mismatch"
        );

        // Test 2: Validate two-leaf tree
        let leaf0_hash = compute_leaf_hash(inputs[0]);
        let leaf1_hash = compute_leaf_hash(inputs[1]);
        let computed_root = compute_node_hash(&leaf0_hash, &leaf1_hash);
        let expected_root1 = hex::decode(expected_roots[1]).unwrap();
        assert_eq!(
            &computed_root[..],
            &expected_root1[..],
            "Two-leaf root mismatch"
        );

        // Test 3: Build 3-leaf tree and verify structure
        // Tree structure:
        //       root
        //      /    \
        //   h01      leaf2
        //   / \
        // l0  l1
        let leaf0_hash = compute_leaf_hash(inputs[0]);
        let leaf1_hash = compute_leaf_hash(inputs[1]);
        let leaf2_hash = compute_leaf_hash(inputs[2]);
        let h01 = compute_node_hash(&leaf0_hash, &leaf1_hash);
        let root3 = compute_node_hash(&h01, &leaf2_hash);
        let expected_root2 = hex::decode(expected_roots[2]).unwrap();
        assert_eq!(&root3[..], &expected_root2[..], "Three-leaf root mismatch");

        // Test 4: Verify inclusion proof for leaf 0 in 3-leaf tree
        // Proof path: need leaf1_hash and leaf2_hash
        let proof = vec![leaf1_hash, leaf2_hash];
        let result = verify_inclusion_proof(0, 3, &leaf0_hash, &proof, &root3);
        assert!(
            result.is_ok(),
            "Failed to verify leaf 0 in 3-leaf tree: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_empty_leaf_hash() {
        // From Google CT test vectors: A leaf containing empty data
        // This is SHA-256(0x00 || "") which equals the first root in the test vectors
        // Expected: 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
        let empty_leaf_hash = compute_leaf_hash(&[]);
        let expected =
            hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
                .unwrap();

        assert_eq!(
            &empty_leaf_hash[..],
            &expected[..],
            "Empty leaf hash mismatch. Expected SHA-256(0x00 || '')"
        );
    }
}

// ============================================================================
// Kani proof harnesses for Merkle tree operations
// ============================================================================
//
// AUDIT C-7 (partial closure): the `Kani merkle` matrix entry remains
// masked (continue-on-error). proof_largest_power_of_two_* run cleanly,
// but the three SHA-256-touching harnesses (proof_leaf_node_domain_separation,
// proof_leaf_hash_deterministic, proof_node_hash_deterministic) do not pass
// at --default-unwind 4 — see per-harness doc-comments below for diagnosis.
#[cfg(kani)]
mod proofs_arith {
    use super::*;

    /// Prove: largest_power_of_two_less_than never panics and returns correct values.
    ///
    /// For any n > 1, the result must be:
    /// 1. A power of 2
    /// 2. Less than n
    /// 3. The LARGEST such power (i.e., result * 2 >= n)
    #[kani::proof]
    #[kani::unwind(65)]
    fn proof_largest_power_of_two_properties() {
        let n: u64 = kani::any();
        kani::assume(n > 1);

        let result = largest_power_of_two_less_than(n);

        // Must be a power of 2
        assert!(
            result.is_power_of_two(),
            "Result {} is not a power of 2",
            result
        );
        // Must be less than n
        assert!(result < n, "Result {} is not less than n={}", result, n);
        // Must be the largest such power (next power would be >= n)
        assert!(
            result as u128 * 2 >= n as u128,
            "Result {} is not the largest power < n={}",
            result,
            n
        );
    }

    /// Prove: largest_power_of_two_less_than handles edge cases.
    #[kani::proof]
    fn proof_largest_power_of_two_edge_cases() {
        // n=0 returns 0
        assert_eq!(largest_power_of_two_less_than(0), 0);
        // n=1 returns 1
        assert_eq!(largest_power_of_two_less_than(1), 1);
        // n=2 returns 1
        assert_eq!(largest_power_of_two_less_than(2), 1);
        // n=3 returns 2
        assert_eq!(largest_power_of_two_less_than(3), 2);
    }
}

// The SHA-256 harnesses live in their own module so CI can run them apart
// from the arithmetic ones above. They used to share one `mod proofs` and
// therefore one `cargo kani` invocation; under sha2 0.11 these three
// exhaust the runner, and the two VERIFIED arithmetic proofs lost their
// evidence with them. Split here, the arithmetic module runs UNMASKED in
// formal-verification.yml (`merkle-arith`) and this one stays masked and
// memory-capped (`merkle-sha256`). Module paths, not function names, are
// what the vacuous-oracle gate can resolve, which is why the split is in
// the code rather than only in the CI matrix.
#[cfg(kani)]
mod proofs_sha256 {
    use super::*;

    /// Prove: compute_leaf_hash produces different output than compute_node_hash
    /// for the same input data.
    ///
    /// This is the domain separation property: leaf hash uses 0x00 prefix,
    /// node hash uses 0x01 prefix, so they cannot collide.
    ///
    /// AUDIT C-7 (partial closure) — currently masked in CI.
    /// This harness is unprovable with Kani as written:
    ///   1. Verifying assert_ne! on two SHA-256 outputs requires reasoning
    ///      about SHA-256 collision-resistance — a cryptographic assumption,
    ///      not a computational property bounded model checking can discharge.
    ///   2. Even setting that aside, the sha2 crate's compression loop runs
    ///      64 rounds; --default-unwind 4 cannot unroll it, so the harness
    ///      hits an unwinding-assertion failure before reaching the assert.
    /// To make this prov-able the leaf/node domain-separation property should
    /// be moved to a tool that can model SHA-256 as an uninterpreted function
    /// (e.g. Verus or Lean axiomatisation). Until then, the prefix-byte check
    /// in #[cfg(test)] (test_node_hash_computation) is the operational guard.
    #[kani::proof]
    fn proof_leaf_node_domain_separation() {
        // For a 64-byte input that could be interpreted as either a leaf or
        // two 32-byte children concatenated
        let mut data = [0u8; 64];
        data[0] = kani::any();
        data[1] = kani::any();

        let leaf_hash = compute_leaf_hash(&data);

        let left: [u8; 32] = data[0..32].try_into().unwrap();
        let right: [u8; 32] = data[32..64].try_into().unwrap();
        let node_hash = compute_node_hash(&left, &right);

        // Leaf hash and node hash must differ (domain separation)
        assert_ne!(
            leaf_hash, node_hash,
            "Leaf hash and node hash collided — domain separation broken"
        );
    }

    /// Prove: compute_leaf_hash is deterministic.
    ///
    /// AUDIT C-7 (partial closure) — currently masked in CI.
    /// Determinism is trivial for any pure Rust function, but Kani still
    /// has to fully symbolically execute the SHA-256 compression on both
    /// calls. That loop is 64 rounds, so --default-unwind 4 produces an
    /// unwinding-assertion failure long before the assert_eq is reached.
    /// A per-harness #[kani::unwind(65)] is necessary; even then Kani's
    /// SMT backend may time out within the 60-minute job budget.
    #[kani::proof]
    fn proof_leaf_hash_deterministic() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let data = [b0, b1];

        let hash1 = compute_leaf_hash(&data);
        let hash2 = compute_leaf_hash(&data);
        assert_eq!(hash1, hash2);
    }

    /// Prove: compute_node_hash is deterministic.
    ///
    /// AUDIT C-7 (partial closure) — currently masked in CI.
    /// Same blocker as proof_leaf_hash_deterministic: SHA-256's 64-round
    /// compression loop is too deep for --default-unwind 4 and a per-harness
    /// #[kani::unwind(65)] may still hit SMT timeout because inputs are two
    /// fully-symbolic 32-byte arrays.
    #[kani::proof]
    fn proof_node_hash_deterministic() {
        let l: [u8; 32] = [kani::any(); 32];
        let r: [u8; 32] = [kani::any(); 32];

        let hash1 = compute_node_hash(&l, &r);
        let hash2 = compute_node_hash(&l, &r);
        assert_eq!(hash1, hash2);
    }
}
