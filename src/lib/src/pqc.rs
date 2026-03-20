//! Post-quantum cryptography support (FEAT-1, REQ-7).
//!
//! Provides trait-based abstraction for post-quantum signature schemes
//! alongside classical Ed25519. Initial target: SLH-DSA (FIPS 205,
//! formerly SPHINCS+) for stateless hash-based signatures.
//!
//! # Design
//!
//! SLH-DSA is chosen over ML-DSA (FIPS 204, Dilithium) for sigil because:
//! - Stateless: no state management needed (critical for embedded/air-gapped)
//! - Hash-based: security relies only on hash function properties
//! - Conservative: no lattice assumptions that may weaken
//!
//! # Parameter Sets
//!
//! SLH-DSA defines parameter sets trading signature size vs security:
//!
//! | Parameter Set      | Security | Sig Size | PK Size |
//! |--------------------|----------|----------|---------|
//! | SLH-DSA-SHA2-128s  | Level 1  | 7,856 B  | 32 B    |
//! | SLH-DSA-SHA2-128f  | Level 1  | 17,088 B | 32 B    |
//! | SLH-DSA-SHA2-192s  | Level 3  | 16,224 B | 48 B    |
//! | SLH-DSA-SHA2-256s  | Level 5  | 29,792 B | 64 B    |
//!
//! For embedded targets with constrained flash, `-128s` (small) is
//! preferred. For CI/cloud signing where bandwidth is cheap, `-128f`
//! (fast) is preferred.
//!
//! # Hybrid Signing
//!
//! sigil supports hybrid signing: Ed25519 + SLH-DSA in parallel.
//! Both signatures are embedded; verification requires both to pass.
//! This provides defense-in-depth during the PQC transition period.

use serde::{Deserialize, Serialize};

/// Supported post-quantum signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcAlgorithm {
    /// SLH-DSA-SHA2-128s (FIPS 205) — small signatures, Level 1
    #[serde(rename = "SLH-DSA-SHA2-128s")]
    SlhDsaSha2_128s,

    /// SLH-DSA-SHA2-128f (FIPS 205) — fast signing, Level 1
    #[serde(rename = "SLH-DSA-SHA2-128f")]
    SlhDsaSha2_128f,

    /// SLH-DSA-SHA2-192s (FIPS 205) — Level 3
    #[serde(rename = "SLH-DSA-SHA2-192s")]
    SlhDsaSha2_192s,

    /// SLH-DSA-SHA2-256s (FIPS 205) — Level 5
    #[serde(rename = "SLH-DSA-SHA2-256s")]
    SlhDsaSha2_256s,
}

impl PqcAlgorithm {
    /// NIST security level (1, 3, or 5).
    pub fn security_level(&self) -> u8 {
        match self {
            Self::SlhDsaSha2_128s | Self::SlhDsaSha2_128f => 1,
            Self::SlhDsaSha2_192s => 3,
            Self::SlhDsaSha2_256s => 5,
        }
    }

    /// Maximum signature size in bytes.
    pub fn max_signature_size(&self) -> usize {
        match self {
            Self::SlhDsaSha2_128s => 7_856,
            Self::SlhDsaSha2_128f => 17_088,
            Self::SlhDsaSha2_192s => 16_224,
            Self::SlhDsaSha2_256s => 29_792,
        }
    }

    /// Public key size in bytes.
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::SlhDsaSha2_128s | Self::SlhDsaSha2_128f => 32,
            Self::SlhDsaSha2_192s => 48,
            Self::SlhDsaSha2_256s => 64,
        }
    }

    /// Secret key size in bytes.
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::SlhDsaSha2_128s | Self::SlhDsaSha2_128f => 64,
            Self::SlhDsaSha2_192s => 96,
            Self::SlhDsaSha2_256s => 128,
        }
    }

    /// Algorithm identifier string for signature metadata.
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            Self::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            Self::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            Self::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            Self::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        }
    }

    /// Whether this is a "small" (optimized for size) parameter set.
    pub fn is_small(&self) -> bool {
        matches!(
            self,
            Self::SlhDsaSha2_128s | Self::SlhDsaSha2_192s | Self::SlhDsaSha2_256s
        )
    }

    /// Recommended parameter set for embedded targets (small flash).
    pub fn recommended_embedded() -> Self {
        Self::SlhDsaSha2_128s
    }

    /// Recommended parameter set for CI/cloud signing.
    pub fn recommended_cloud() -> Self {
        Self::SlhDsaSha2_128f
    }
}

/// Hybrid signature combining classical and post-quantum algorithms.
///
/// During the PQC transition period, both signatures are required.
/// Verification fails if either signature is invalid.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridSignature {
    /// Classical Ed25519 signature (64 bytes)
    pub classical: Vec<u8>,

    /// Post-quantum signature (algorithm-dependent size)
    pub post_quantum: Vec<u8>,

    /// Which PQC algorithm was used
    pub pqc_algorithm: PqcAlgorithm,

    /// The signed message hash (SHA-256, for binding)
    pub message_hash: Vec<u8>,
}

/// Configuration for PQC signing operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PqcConfig {
    /// Which SLH-DSA parameter set to use
    pub algorithm: PqcAlgorithm,

    /// Whether to produce hybrid (Ed25519 + PQC) signatures
    #[serde(default = "default_hybrid")]
    pub hybrid: bool,

    /// Domain separation string for PQC signatures
    #[serde(default = "default_pqc_domain")]
    pub domain: String,
}

fn default_hybrid() -> bool {
    true
}

fn default_pqc_domain() -> String {
    "wsc-pqc-v1".to_string()
}

impl Default for PqcConfig {
    fn default() -> Self {
        Self {
            algorithm: PqcAlgorithm::recommended_embedded(),
            hybrid: true,
            domain: default_pqc_domain(),
        }
    }
}

/// Status of PQC implementation readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcStatus {
    /// Parameter sets defined, no signing implementation yet
    ParametersOnly,
    /// Signing implemented but not yet audited
    Experimental,
    /// Audited and ready for production use
    Production,
}

/// Get the current PQC implementation status.
pub fn implementation_status() -> PqcStatus {
    // SLH-DSA implementation is pending a stable pure-Rust no_std crate.
    // Candidates: slh-dsa (RustCrypto), pqcrypto-sphincsplus
    PqcStatus::ParametersOnly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        let alg = PqcAlgorithm::SlhDsaSha2_128s;
        assert_eq!(alg.security_level(), 1);
        assert_eq!(alg.max_signature_size(), 7_856);
        assert_eq!(alg.public_key_size(), 32);
        assert_eq!(alg.secret_key_size(), 64);
        assert_eq!(alg.algorithm_id(), "SLH-DSA-SHA2-128s");
        assert!(alg.is_small());
    }

    #[test]
    fn test_algorithm_sizes_consistent() {
        for alg in [
            PqcAlgorithm::SlhDsaSha2_128s,
            PqcAlgorithm::SlhDsaSha2_128f,
            PqcAlgorithm::SlhDsaSha2_192s,
            PqcAlgorithm::SlhDsaSha2_256s,
        ] {
            assert!(alg.max_signature_size() > 0);
            assert!(alg.public_key_size() > 0);
            assert!(alg.secret_key_size() > 0);
            assert_eq!(alg.secret_key_size(), alg.public_key_size() * 2);
        }
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(PqcAlgorithm::SlhDsaSha2_128s.security_level(), 1);
        assert_eq!(PqcAlgorithm::SlhDsaSha2_128f.security_level(), 1);
        assert_eq!(PqcAlgorithm::SlhDsaSha2_192s.security_level(), 3);
        assert_eq!(PqcAlgorithm::SlhDsaSha2_256s.security_level(), 5);
    }

    #[test]
    fn test_recommendations() {
        let embedded = PqcAlgorithm::recommended_embedded();
        assert!(embedded.is_small());
        assert!(embedded.max_signature_size() < 10_000); // Small sigs for flash

        let cloud = PqcAlgorithm::recommended_cloud();
        assert!(!cloud.is_small()); // Fast, larger sigs OK
    }

    #[test]
    fn test_algorithm_serialization() {
        let alg = PqcAlgorithm::SlhDsaSha2_128s;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"SLH-DSA-SHA2-128s\"");

        let parsed: PqcAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, alg);
    }

    #[test]
    fn test_hybrid_signature_serialization() {
        let sig = HybridSignature {
            classical: vec![0u8; 64],
            post_quantum: vec![0u8; 100],
            pqc_algorithm: PqcAlgorithm::SlhDsaSha2_128s,
            message_hash: vec![0u8; 32],
        };

        let json = serde_json::to_string_pretty(&sig).unwrap();
        assert!(json.contains("pqcAlgorithm"));
        assert!(json.contains("SLH-DSA-SHA2-128s"));

        let parsed: HybridSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pqc_algorithm, PqcAlgorithm::SlhDsaSha2_128s);
    }

    #[test]
    fn test_pqc_config_default() {
        let config = PqcConfig::default();
        assert!(config.hybrid);
        assert_eq!(config.algorithm, PqcAlgorithm::SlhDsaSha2_128s);
        assert_eq!(config.domain, "wsc-pqc-v1");
    }

    #[test]
    fn test_implementation_status() {
        assert_eq!(implementation_status(), PqcStatus::ParametersOnly);
    }

    #[test]
    fn test_all_algorithm_ids_unique() {
        let ids: Vec<&str> = [
            PqcAlgorithm::SlhDsaSha2_128s,
            PqcAlgorithm::SlhDsaSha2_128f,
            PqcAlgorithm::SlhDsaSha2_192s,
            PqcAlgorithm::SlhDsaSha2_256s,
        ]
        .iter()
        .map(|a| a.algorithm_id())
        .collect();

        // All IDs are unique
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len());
    }
}
