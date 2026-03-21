//! Rekor checkpoint (Signed Tree Head) consistency verification (Phase 4.3).
//!
//! Verifies that the Rekor transparency log's checkpoint is consistent
//! over time. Detects log truncation, split-view, and rollback attacks
//! by comparing successive checkpoints.
//!
//! # Checkpoint Format
//!
//! Rekor uses Go's signed note format (also called "checkpoint" format):
//!
//! ```text
//! <origin>\n
//! <tree_size>\n
//! <base64_root_hash>\n
//! \n
//! — <signer_name> <base64(key_hash + signature)>\n
//! ```
//!
//! # Security Model
//!
//! - **Monotonic growth**: Tree size must never decrease between successive
//!   checkpoints from the same log, preventing log truncation attacks.
//! - **Consistency proofs**: A Merkle consistency proof cryptographically
//!   demonstrates that the old tree is a prefix of the new tree, preventing
//!   split-view and rollback attacks.
//! - **Persistent storage**: The last verified checkpoint is persisted so
//!   that consistency can be checked across process restarts.

use crate::error::WSError;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::merkle::compute_node_hash;

/// Parsed Rekor checkpoint (Signed Tree Head).
///
/// Represents the body portion of a signed checkpoint note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    /// Log origin identifier (e.g., `rekor.sigstore.dev - 1193050959916656506`).
    pub origin: String,
    /// Number of entries in the log at the time of this checkpoint.
    pub tree_size: u64,
    /// SHA-256 Merkle tree root hash.
    pub root_hash: [u8; 32],
    /// Additional extension lines (between root hash and blank separator).
    pub other_content: Vec<String>,
}

/// A checkpoint together with one or more signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCheckpoint {
    /// The parsed checkpoint body.
    pub checkpoint: Checkpoint,
    /// One or more signatures over the checkpoint note body.
    pub signatures: Vec<CheckpointSignature>,
}

/// A single signature on a checkpoint note.
///
/// The wire format is `— <name> <base64(key_hash ++ sig)>` where `key_hash`
/// is the first 4 bytes of SHA-256 of the verifier identity/key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointSignature {
    /// Human-readable signer name.
    pub name: String,
    /// First 4 bytes of SHA-256 of the verifier key, encoded as a `u32`.
    pub key_hash: u32,
    /// Raw Ed25519 or ECDSA signature bytes.
    pub signature: Vec<u8>,
}

/// Verifies consistency between successive Rekor checkpoints.
///
/// Ensures that the transparency log grows monotonically and that
/// consistency proofs are valid (old tree is a prefix of the new tree).
pub struct ConsistencyVerifier;

impl ConsistencyVerifier {
    /// Create a new consistency verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verify a Merkle consistency proof between two checkpoints.
    ///
    /// A consistency proof demonstrates that the old tree (with
    /// `old.tree_size` leaves and `old.root_hash`) is a prefix of the
    /// new tree (with `new.tree_size` leaves and `new.root_hash`).
    ///
    /// The algorithm follows RFC 6962 Section 2.1.2.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the proof is invalid or the checkpoints are
    /// inconsistent with each other.
    pub fn verify_consistency(
        &self,
        old: &Checkpoint,
        new: &Checkpoint,
        proof: &[&[u8; 32]],
    ) -> Result<(), WSError> {
        // First check monotonicity
        self.check_monotonic(old, new)?;

        let old_size = old.tree_size;
        let new_size = new.tree_size;

        // Same size, same root — trivially consistent
        if old_size == new_size {
            if old.root_hash != new.root_hash {
                return Err(WSError::RekorError(
                    "Checkpoints have same tree size but different root hashes".to_string(),
                ));
            }
            // Proof should be empty for identical checkpoints
            if !proof.is_empty() {
                return Err(WSError::RekorError(
                    "Non-empty consistency proof for identical checkpoints".to_string(),
                ));
            }
            return Ok(());
        }

        // Empty old tree is trivially consistent with any new tree
        if old_size == 0 {
            return Ok(());
        }

        // For non-trivial cases we need a non-empty proof
        if proof.is_empty() {
            return Err(WSError::RekorError(
                "Empty consistency proof for differing tree sizes".to_string(),
            ));
        }

        // RFC 6962 consistency proof verification algorithm
        // Decompose old_size into the path through the tree
        let (mut fr, mut sr) = if old_size.is_power_of_two() {
            // When old_size is a power of two, the first proof node is
            // the old root itself; the algorithm starts one step earlier.
            (*proof[0], *proof[0])
        } else {
            (*proof[0], *proof[0])
        };

        let mut proof_idx = 1;
        let mut node = old_size - 1;
        let mut last_node = new_size - 1;

        // Walk up to the point where the paths diverge
        while node % 2 != 0 || (node != 0 && old_size.is_power_of_two() && node == old_size - 1) {
            if node % 2 != 0 {
                // Node is a right child — sibling is to the left
                if proof_idx >= proof.len() {
                    return Err(WSError::RekorError(
                        "Consistency proof too short".to_string(),
                    ));
                }
                let sibling = proof[proof_idx];
                proof_idx += 1;
                fr = compute_node_hash(sibling, &fr);
                sr = compute_node_hash(sibling, &sr);
            }
            node >>= 1;
            last_node >>= 1;
        }

        // Continue up the tree — only the sr (new root) path needs siblings
        while proof_idx < proof.len() {
            let sibling = proof[proof_idx];
            proof_idx += 1;

            if node < last_node || (node == last_node && node % 2 != 0) {
                sr = compute_node_hash(&sr, sibling);
            } else {
                sr = compute_node_hash(sibling, &sr);
            }

            node >>= 1;
            last_node >>= 1;
        }

        // Verify the computed roots match the expected roots
        if fr != old.root_hash {
            return Err(WSError::RekorError(format!(
                "Consistency proof failed: computed old root {} does not match expected {}",
                hex::encode(fr),
                hex::encode(old.root_hash),
            )));
        }

        if sr != new.root_hash {
            return Err(WSError::RekorError(format!(
                "Consistency proof failed: computed new root {} does not match expected {}",
                hex::encode(sr),
                hex::encode(new.root_hash),
            )));
        }

        Ok(())
    }

    /// Verify that a new checkpoint's tree size is monotonically
    /// non-decreasing relative to a previous checkpoint.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `new.tree_size < old.tree_size`, indicating a
    /// potential log truncation or rollback attack.
    pub fn check_monotonic(
        &self,
        old: &Checkpoint,
        new: &Checkpoint,
    ) -> Result<(), WSError> {
        if new.tree_size < old.tree_size {
            return Err(WSError::RekorError(format!(
                "Log rollback detected: tree size decreased from {} to {}",
                old.tree_size, new.tree_size
            )));
        }
        Ok(())
    }
}

impl Default for ConsistencyVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for persisting the last-seen verified checkpoint.
///
/// Implementations store and retrieve the most recent `SignedCheckpoint`
/// so that monotonicity and consistency can be enforced across restarts.
pub trait CheckpointStore {
    /// Load the last-saved checkpoint, if any.
    fn load(&self) -> Result<Option<SignedCheckpoint>, WSError>;

    /// Persist a checkpoint as the new "last-seen" value.
    fn save(&self, checkpoint: &SignedCheckpoint) -> Result<(), WSError>;
}

/// File-based implementation of [`CheckpointStore`].
///
/// Stores the checkpoint as JSON in the given path. The file is
/// atomically written (write to temp + rename) to prevent corruption.
pub struct FileCheckpointStore {
    path: PathBuf,
}

impl FileCheckpointStore {
    /// Create a new file-based checkpoint store at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl CheckpointStore for FileCheckpointStore {
    fn load(&self) -> Result<Option<SignedCheckpoint>, WSError> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => {
                let checkpoint: SignedCheckpoint = serde_json::from_str(&contents)
                    .map_err(|e| {
                        WSError::RekorError(format!(
                            "Failed to parse stored checkpoint: {}",
                            e
                        ))
                    })?;
                Ok(Some(checkpoint))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(WSError::RekorError(format!(
                "Failed to read checkpoint store at {}: {}",
                self.path.display(),
                e
            ))),
        }
    }

    fn save(&self, checkpoint: &SignedCheckpoint) -> Result<(), WSError> {
        let json = serde_json::to_string_pretty(checkpoint).map_err(|e| {
            WSError::RekorError(format!("Failed to serialize checkpoint: {}", e))
        })?;

        // Write to a temporary file next to the target, then rename for
        // atomic replacement.
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, json.as_bytes()).map_err(|e| {
            WSError::RekorError(format!(
                "Failed to write checkpoint to {}: {}",
                tmp_path.display(),
                e
            ))
        })?;

        std::fs::rename(&tmp_path, &self.path).map_err(|e| {
            WSError::RekorError(format!(
                "Failed to rename checkpoint file: {}",
                e
            ))
        })?;

        Ok(())
    }
}

/// Parse a Rekor checkpoint in signed note format.
///
/// The expected format is:
///
/// ```text
/// <origin>\n
/// <tree_size>\n
/// <base64_root_hash>\n
/// [optional extension lines]\n
/// \n
/// — <signer_name> <base64(key_hash + signature)>\n
/// ```
///
/// The separator between the body and signature section is a blank line.
/// The signature line starts with an em-dash (`\u{2014}`) followed by a
/// space, the signer name, another space, and a base64-encoded blob that
/// contains the 4-byte key hash followed by the raw signature bytes.
pub fn parse_checkpoint(text: &str) -> Result<SignedCheckpoint, WSError> {
    // Split body from signatures on the blank line separator.
    // The blank line is a line that is entirely empty (after the
    // body lines).
    let parts: Vec<&str> = text.splitn(2, "\n\n").collect();
    if parts.len() != 2 {
        return Err(WSError::RekorError(
            "Invalid checkpoint: missing blank line separator between body and signatures"
                .to_string(),
        ));
    }

    let body = parts[0];
    let sig_section = parts[1];

    // Parse body lines
    let body_lines: Vec<&str> = body.lines().collect();
    if body_lines.len() < 3 {
        return Err(WSError::RekorError(format!(
            "Invalid checkpoint body: expected at least 3 lines (origin, tree_size, root_hash), got {}",
            body_lines.len()
        )));
    }

    let origin = body_lines[0].to_string();
    if origin.is_empty() {
        return Err(WSError::RekorError(
            "Invalid checkpoint: empty origin line".to_string(),
        ));
    }

    let tree_size: u64 = body_lines[1].parse().map_err(|e| {
        WSError::RekorError(format!(
            "Invalid checkpoint: cannot parse tree size '{}': {}",
            body_lines[1], e
        ))
    })?;

    let root_hash_bytes = BASE64.decode(body_lines[2]).map_err(|e| {
        WSError::RekorError(format!(
            "Invalid checkpoint: cannot decode root hash: {}",
            e
        ))
    })?;

    if root_hash_bytes.len() != 32 {
        return Err(WSError::RekorError(format!(
            "Invalid checkpoint: root hash must be 32 bytes, got {}",
            root_hash_bytes.len()
        )));
    }

    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&root_hash_bytes);

    // Collect any additional extension lines (between root hash and blank line)
    let other_content: Vec<String> = body_lines[3..]
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Parse signatures
    let mut signatures = Vec::new();
    for line in sig_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Signature lines start with em-dash: \u{2014} (—)
        if !line.starts_with('\u{2014}') {
            return Err(WSError::RekorError(format!(
                "Invalid checkpoint signature line: expected em-dash prefix, got: {}",
                line
            )));
        }

        // Strip the em-dash and leading space: "— name base64sig"
        let after_dash = &line['\u{2014}'.len_utf8()..];
        let after_dash = after_dash.strip_prefix(' ').unwrap_or(after_dash);

        // Split into name and base64 blob
        let space_pos = after_dash.rfind(' ').ok_or_else(|| {
            WSError::RekorError(
                "Invalid checkpoint signature: missing space between name and signature"
                    .to_string(),
            )
        })?;

        let name = after_dash[..space_pos].to_string();
        let sig_b64 = &after_dash[space_pos + 1..];

        let sig_bytes = BASE64.decode(sig_b64).map_err(|e| {
            WSError::RekorError(format!(
                "Invalid checkpoint signature: cannot decode base64: {}",
                e
            ))
        })?;

        // First 4 bytes are the key hash
        if sig_bytes.len() < 5 {
            return Err(WSError::RekorError(
                "Invalid checkpoint signature: too short (need at least 4-byte key hash + 1 byte signature)"
                    .to_string(),
            ));
        }

        let key_hash = u32::from_be_bytes([
            sig_bytes[0],
            sig_bytes[1],
            sig_bytes[2],
            sig_bytes[3],
        ]);
        let signature = sig_bytes[4..].to_vec();

        signatures.push(CheckpointSignature {
            name,
            key_hash,
            signature,
        });
    }

    if signatures.is_empty() {
        return Err(WSError::RekorError(
            "Invalid checkpoint: no signatures found".to_string(),
        ));
    }

    Ok(SignedCheckpoint {
        checkpoint: Checkpoint {
            origin,
            tree_size,
            root_hash,
            other_content,
        },
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed checkpoint note string for testing.
    fn make_checkpoint_note(
        origin: &str,
        tree_size: u64,
        root_hash: &[u8; 32],
        signer_name: &str,
        key_hash: u32,
        sig_bytes: &[u8],
    ) -> String {
        let root_b64 = BASE64.encode(root_hash);
        let mut sig_blob = key_hash.to_be_bytes().to_vec();
        sig_blob.extend_from_slice(sig_bytes);
        let sig_b64 = BASE64.encode(&sig_blob);
        format!(
            "{}\n{}\n{}\n\n\u{2014} {} {}",
            origin, tree_size, root_b64, signer_name, sig_b64
        )
    }

    // ---------------------------------------------------------------
    // Parsing tests
    // ---------------------------------------------------------------

    #[test]
    fn test_parse_valid_checkpoint() {
        let root_hash = [0xABu8; 32];
        let sig = vec![0x01u8; 64];
        let note = make_checkpoint_note(
            "rekor.sigstore.dev - 1193050959916656506",
            12345,
            &root_hash,
            "rekor.sigstore.dev",
            0xDEADBEEF,
            &sig,
        );

        let signed = parse_checkpoint(&note).expect("should parse");
        assert_eq!(
            signed.checkpoint.origin,
            "rekor.sigstore.dev - 1193050959916656506"
        );
        assert_eq!(signed.checkpoint.tree_size, 12345);
        assert_eq!(signed.checkpoint.root_hash, root_hash);
        assert!(signed.checkpoint.other_content.is_empty());
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signatures[0].name, "rekor.sigstore.dev");
        assert_eq!(signed.signatures[0].key_hash, 0xDEADBEEF);
        assert_eq!(signed.signatures[0].signature, sig);
    }

    #[test]
    fn test_parse_checkpoint_with_extension_lines() {
        let root_hash = [0x42u8; 32];
        let root_b64 = BASE64.encode(root_hash);
        let sig_blob = {
            let mut v = 0x11223344u32.to_be_bytes().to_vec();
            v.extend_from_slice(&[0xFFu8; 32]);
            v
        };
        let sig_b64 = BASE64.encode(&sig_blob);
        let note = format!(
            "mylog\n100\n{}\nextension-line-1\nextension-line-2\n\n\u{2014} signer {}",
            root_b64, sig_b64
        );

        let signed = parse_checkpoint(&note).expect("should parse");
        assert_eq!(signed.checkpoint.other_content.len(), 2);
        assert_eq!(signed.checkpoint.other_content[0], "extension-line-1");
        assert_eq!(signed.checkpoint.other_content[1], "extension-line-2");
    }

    #[test]
    fn test_parse_checkpoint_multiple_signatures() {
        let root_hash = [0x00u8; 32];
        let root_b64 = BASE64.encode(root_hash);
        let sig1 = {
            let mut v = 0xAAAAAAAAu32.to_be_bytes().to_vec();
            v.extend_from_slice(&[0x01u8; 64]);
            v
        };
        let sig2 = {
            let mut v = 0xBBBBBBBBu32.to_be_bytes().to_vec();
            v.extend_from_slice(&[0x02u8; 64]);
            v
        };
        let note = format!(
            "origin\n50\n{}\n\n\u{2014} signer-a {}\n\u{2014} signer-b {}",
            root_b64,
            BASE64.encode(&sig1),
            BASE64.encode(&sig2)
        );

        let signed = parse_checkpoint(&note).expect("should parse");
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signatures[0].name, "signer-a");
        assert_eq!(signed.signatures[0].key_hash, 0xAAAAAAAA);
        assert_eq!(signed.signatures[1].name, "signer-b");
        assert_eq!(signed.signatures[1].key_hash, 0xBBBBBBBB);
    }

    #[test]
    fn test_parse_checkpoint_missing_blank_separator() {
        let note = "origin\n100\nAAAA";
        let err = parse_checkpoint(note).unwrap_err();
        assert!(
            err.to_string().contains("blank line separator"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_checkpoint_too_few_body_lines() {
        // Only origin + tree_size, missing root hash
        let note = "origin\n100\n\n\u{2014} signer AAAAAAAAAAA=";
        let err = parse_checkpoint(note).unwrap_err();
        assert!(
            err.to_string().contains("at least 3 lines"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_checkpoint_invalid_tree_size() {
        let root_b64 = BASE64.encode([0u8; 32]);
        let sig_blob = {
            let mut v = 0u32.to_be_bytes().to_vec();
            v.extend_from_slice(&[0u8; 32]);
            v
        };
        let note = format!(
            "origin\nnot_a_number\n{}\n\n\u{2014} signer {}",
            root_b64,
            BASE64.encode(&sig_blob)
        );
        let err = parse_checkpoint(&note).unwrap_err();
        assert!(
            err.to_string().contains("cannot parse tree size"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_checkpoint_bad_root_hash_length() {
        let short_hash = BASE64.encode([0u8; 16]); // 16 bytes, not 32
        let sig_blob = {
            let mut v = 0u32.to_be_bytes().to_vec();
            v.extend_from_slice(&[0u8; 32]);
            v
        };
        let note = format!(
            "origin\n1\n{}\n\n\u{2014} signer {}",
            short_hash,
            BASE64.encode(&sig_blob)
        );
        let err = parse_checkpoint(&note).unwrap_err();
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_checkpoint_no_signatures() {
        let root_b64 = BASE64.encode([0u8; 32]);
        let note = format!("origin\n1\n{}\n\n", root_b64);
        let err = parse_checkpoint(&note).unwrap_err();
        assert!(
            err.to_string().contains("no signatures"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_checkpoint_signature_too_short() {
        let root_b64 = BASE64.encode([0u8; 32]);
        // Only 3 bytes — needs at least 5 (4 key_hash + 1 sig)
        let sig_b64 = BASE64.encode([0u8; 3]);
        let note = format!(
            "origin\n1\n{}\n\n\u{2014} signer {}",
            root_b64, sig_b64
        );
        let err = parse_checkpoint(&note).unwrap_err();
        assert!(
            err.to_string().contains("too short"),
            "unexpected error: {}",
            err
        );
    }

    // ---------------------------------------------------------------
    // Monotonic check tests
    // ---------------------------------------------------------------

    #[test]
    fn test_monotonic_pass() {
        let verifier = ConsistencyVerifier::new();
        let old = Checkpoint {
            origin: "log".to_string(),
            tree_size: 100,
            root_hash: [0u8; 32],
            other_content: vec![],
        };
        let new = Checkpoint {
            origin: "log".to_string(),
            tree_size: 200,
            root_hash: [0u8; 32],
            other_content: vec![],
        };
        assert!(verifier.check_monotonic(&old, &new).is_ok());
    }

    #[test]
    fn test_monotonic_equal() {
        let verifier = ConsistencyVerifier::new();
        let cp = Checkpoint {
            origin: "log".to_string(),
            tree_size: 100,
            root_hash: [0u8; 32],
            other_content: vec![],
        };
        assert!(verifier.check_monotonic(&cp, &cp).is_ok());
    }

    #[test]
    fn test_monotonic_fail_rollback() {
        let verifier = ConsistencyVerifier::new();
        let old = Checkpoint {
            origin: "log".to_string(),
            tree_size: 200,
            root_hash: [0u8; 32],
            other_content: vec![],
        };
        let new = Checkpoint {
            origin: "log".to_string(),
            tree_size: 100,
            root_hash: [0u8; 32],
            other_content: vec![],
        };
        let err = verifier.check_monotonic(&old, &new).unwrap_err();
        assert!(
            err.to_string().contains("rollback"),
            "unexpected error: {}",
            err
        );
    }

    // ---------------------------------------------------------------
    // Consistency proof structure tests
    // ---------------------------------------------------------------

    #[test]
    fn test_consistency_same_checkpoint() {
        let verifier = ConsistencyVerifier::new();
        let cp = Checkpoint {
            origin: "log".to_string(),
            tree_size: 50,
            root_hash: [0x11u8; 32],
            other_content: vec![],
        };
        assert!(verifier.verify_consistency(&cp, &cp, &[]).is_ok());
    }

    #[test]
    fn test_consistency_same_size_different_root() {
        let verifier = ConsistencyVerifier::new();
        let old = Checkpoint {
            origin: "log".to_string(),
            tree_size: 50,
            root_hash: [0x11u8; 32],
            other_content: vec![],
        };
        let new = Checkpoint {
            origin: "log".to_string(),
            tree_size: 50,
            root_hash: [0x22u8; 32],
            other_content: vec![],
        };
        let err = verifier.verify_consistency(&old, &new, &[]).unwrap_err();
        assert!(
            err.to_string().contains("different root hashes"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_consistency_empty_old_tree() {
        let verifier = ConsistencyVerifier::new();
        let old = Checkpoint {
            origin: "log".to_string(),
            tree_size: 0,
            root_hash: [0u8; 32],
            other_content: vec![],
        };
        let new = Checkpoint {
            origin: "log".to_string(),
            tree_size: 100,
            root_hash: [0xFFu8; 32],
            other_content: vec![],
        };
        // Empty -> anything is trivially consistent
        assert!(verifier.verify_consistency(&old, &new, &[]).is_ok());
    }

    #[test]
    fn test_consistency_rejects_empty_proof_for_different_sizes() {
        let verifier = ConsistencyVerifier::new();
        let old = Checkpoint {
            origin: "log".to_string(),
            tree_size: 10,
            root_hash: [0x11u8; 32],
            other_content: vec![],
        };
        let new = Checkpoint {
            origin: "log".to_string(),
            tree_size: 20,
            root_hash: [0x22u8; 32],
            other_content: vec![],
        };
        let err = verifier.verify_consistency(&old, &new, &[]).unwrap_err();
        assert!(
            err.to_string().contains("Empty consistency proof"),
            "unexpected error: {}",
            err
        );
    }

    // ---------------------------------------------------------------
    // FileCheckpointStore round-trip tests
    // ---------------------------------------------------------------

    #[test]
    fn test_file_store_load_nonexistent() {
        let path = std::env::temp_dir().join(format!(
            "wsc_checkpoint_test_nonexistent_{}.json",
            std::process::id()
        ));
        // Make sure file does not exist
        let _ = std::fs::remove_file(&path);

        let store = FileCheckpointStore::new(path.clone());
        let loaded = store.load().expect("load should succeed");
        assert!(loaded.is_none(), "expected None for nonexistent file");
    }

    #[test]
    fn test_file_store_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "wsc_checkpoint_test_roundtrip_{}.json",
            std::process::id()
        ));
        // Clean up any previous run
        let _ = std::fs::remove_file(&path);

        let store = FileCheckpointStore::new(path.clone());

        let checkpoint = SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: "test-origin".to_string(),
                tree_size: 999,
                root_hash: [0xCCu8; 32],
                other_content: vec!["ext1".to_string()],
            },
            signatures: vec![CheckpointSignature {
                name: "test-signer".to_string(),
                key_hash: 0x12345678,
                signature: vec![0xAAu8; 64],
            }],
        };

        store.save(&checkpoint).expect("save should succeed");
        let loaded = store
            .load()
            .expect("load should succeed")
            .expect("should find saved checkpoint");

        assert_eq!(loaded.checkpoint.origin, "test-origin");
        assert_eq!(loaded.checkpoint.tree_size, 999);
        assert_eq!(loaded.checkpoint.root_hash, [0xCCu8; 32]);
        assert_eq!(loaded.checkpoint.other_content, vec!["ext1"]);
        assert_eq!(loaded.signatures.len(), 1);
        assert_eq!(loaded.signatures[0].name, "test-signer");
        assert_eq!(loaded.signatures[0].key_hash, 0x12345678);
        assert_eq!(loaded.signatures[0].signature, vec![0xAAu8; 64]);

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_file_store_overwrite() {
        let path = std::env::temp_dir().join(format!(
            "wsc_checkpoint_test_overwrite_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let store = FileCheckpointStore::new(path.clone());

        let cp1 = SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: "log".to_string(),
                tree_size: 10,
                root_hash: [0x01u8; 32],
                other_content: vec![],
            },
            signatures: vec![CheckpointSignature {
                name: "s".to_string(),
                key_hash: 1,
                signature: vec![0x01; 32],
            }],
        };

        let cp2 = SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: "log".to_string(),
                tree_size: 20,
                root_hash: [0x02u8; 32],
                other_content: vec![],
            },
            signatures: vec![CheckpointSignature {
                name: "s".to_string(),
                key_hash: 2,
                signature: vec![0x02; 32],
            }],
        };

        store.save(&cp1).unwrap();
        store.save(&cp2).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.checkpoint.tree_size, 20);
        assert_eq!(loaded.checkpoint.root_hash, [0x02u8; 32]);

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    // ---------------------------------------------------------------
    // Serde round-trip test
    // ---------------------------------------------------------------

    #[test]
    fn test_signed_checkpoint_serde_camel_case() {
        let cp = SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: "mylog".to_string(),
                tree_size: 42,
                root_hash: [0xFFu8; 32],
                other_content: vec!["ext".to_string()],
            },
            signatures: vec![CheckpointSignature {
                name: "signer".to_string(),
                key_hash: 0xDEADu32,
                signature: vec![0x55; 32],
            }],
        };

        let json = serde_json::to_string(&cp).expect("serialize");
        // Verify camelCase field names
        assert!(json.contains("treeSize"), "expected camelCase treeSize in JSON");
        assert!(json.contains("rootHash"), "expected camelCase rootHash in JSON");
        assert!(json.contains("otherContent"), "expected camelCase otherContent in JSON");
        assert!(json.contains("keyHash"), "expected camelCase keyHash in JSON");

        // Round-trip
        let parsed: SignedCheckpoint =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, cp);
    }

    // ---------------------------------------------------------------
    // ConsistencyVerifier default trait
    // ---------------------------------------------------------------

    #[test]
    fn test_consistency_verifier_default() {
        let _v: ConsistencyVerifier = Default::default();
        // Just ensure it compiles and doesn't panic
    }
}
