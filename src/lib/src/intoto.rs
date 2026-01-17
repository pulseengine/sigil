//! in-toto Statement v1.0 implementation
//!
//! Implements the in-toto attestation framework Statement layer.
//! See: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
//!
//! The Statement is the middle layer of the attestation framework:
//! - Envelope (DSSE) → Statement (this) → Predicate (SLSA, etc.)
//!
//! # Example
//!
//! ```ignore
//! use wsc::intoto::{Statement, Subject, DigestSet};
//! use wsc::slsa::Provenance;
//!
//! let statement = Statement::new(
//!     vec![Subject {
//!         name: "artifact.wasm".to_string(),
//!         digest: DigestSet::sha256("abc123..."),
//!     }],
//!     Provenance { ... },
//! );
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::WSError;

/// in-toto Statement type identifier (v1)
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";

/// in-toto Statement v1.0
///
/// The Statement binds a predicate to one or more subjects (artifacts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement<P> {
    /// Statement type (always "https://in-toto.io/Statement/v1")
    #[serde(rename = "_type")]
    pub type_: String,

    /// Subjects (artifacts) this statement applies to
    pub subject: Vec<Subject>,

    /// Predicate type URI
    #[serde(rename = "predicateType")]
    pub predicate_type: String,

    /// The predicate (e.g., SLSA provenance, VSA, etc.)
    pub predicate: P,
}

impl<P: Serialize> Statement<P> {
    /// Create a new in-toto Statement
    pub fn new(subject: Vec<Subject>, predicate_type: &str, predicate: P) -> Self {
        Self {
            type_: STATEMENT_TYPE_V1.to_string(),
            subject,
            predicate_type: predicate_type.to_string(),
            predicate,
        }
    }

    /// Serialize to JSON bytes (for DSSE payload)
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, WSError> {
        serde_json::to_vec(self).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize statement: {}", e))
        })
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, WSError> {
        serde_json::to_string(self).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize statement: {}", e))
        })
    }

    /// Serialize to pretty JSON string
    pub fn to_json_pretty(&self) -> Result<String, WSError> {
        serde_json::to_string_pretty(self).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize statement: {}", e))
        })
    }
}

impl<P: for<'de> Deserialize<'de>> Statement<P> {
    /// Deserialize from JSON bytes
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, WSError> {
        serde_json::from_slice(bytes).map_err(|e| {
            WSError::InternalError(format!("Failed to parse statement: {}", e))
        })
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, WSError> {
        serde_json::from_str(json).map_err(|e| {
            WSError::InternalError(format!("Failed to parse statement: {}", e))
        })
    }
}

/// Subject of an in-toto statement
///
/// Represents an artifact (file, module, etc.) that the statement applies to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// Name or identifier of the subject
    pub name: String,

    /// Cryptographic digests of the subject
    pub digest: DigestSet,
}

impl Subject {
    /// Create a new subject with SHA256 digest
    pub fn new(name: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            digest: DigestSet::sha256(sha256),
        }
    }

    /// Create a subject with multiple digest algorithms
    pub fn with_digests(name: impl Into<String>, digest: DigestSet) -> Self {
        Self {
            name: name.into(),
            digest,
        }
    }

    /// Create a subject from raw bytes (computes SHA256)
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(bytes);
        Self::new(name, hex::encode(hash))
    }
}

/// Set of cryptographic digests for a subject
///
/// Keys are algorithm names (e.g., "sha256", "sha512"),
/// values are hex-encoded digest strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DigestSet(HashMap<String, String>);

impl DigestSet {
    /// Create a new empty digest set
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Create a digest set with a SHA256 hash
    pub fn sha256(hash: impl Into<String>) -> Self {
        let mut set = Self::new();
        set.0.insert("sha256".to_string(), hash.into());
        set
    }

    /// Create a digest set with a SHA512 hash
    pub fn sha512(hash: impl Into<String>) -> Self {
        let mut set = Self::new();
        set.0.insert("sha512".to_string(), hash.into());
        set
    }

    /// Add a digest
    pub fn insert(&mut self, algorithm: impl Into<String>, hash: impl Into<String>) {
        self.0.insert(algorithm.into(), hash.into());
    }

    /// Get a digest by algorithm
    pub fn get(&self, algorithm: &str) -> Option<&str> {
        self.0.get(algorithm).map(|s| s.as_str())
    }

    /// Get SHA256 digest
    pub fn sha256_value(&self) -> Option<&str> {
        self.get("sha256")
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of digests
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over digests
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

/// Resource descriptor (used in SLSA and other predicates)
///
/// Describes an artifact with optional metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDescriptor {
    /// URI identifying the resource
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Cryptographic digests
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub digest: HashMap<String, String>,

    /// Name of the resource
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Download location (may differ from URI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_location: Option<String>,

    /// Media type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Base64-encoded content (for small resources)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Arbitrary annotations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

impl ResourceDescriptor {
    /// Create a new resource descriptor with URI and digest
    pub fn new(uri: impl Into<String>, sha256: impl Into<String>) -> Self {
        let mut digest = HashMap::new();
        digest.insert("sha256".to_string(), sha256.into());

        Self {
            uri: Some(uri.into()),
            digest,
            name: None,
            download_location: None,
            media_type: None,
            content: None,
            annotations: None,
        }
    }

    /// Create from name and SHA256 (no URI)
    pub fn from_name(name: impl Into<String>, sha256: impl Into<String>) -> Self {
        let mut digest = HashMap::new();
        digest.insert("sha256".to_string(), sha256.into());

        Self {
            uri: None,
            digest,
            name: Some(name.into()),
            download_location: None,
            media_type: None,
            content: None,
            annotations: None,
        }
    }

    /// Create from raw bytes (computes SHA256)
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(bytes);
        Self::from_name(name, hex::encode(hash))
    }

    /// Set media type
    pub fn with_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.media_type = Some(media_type.into());
        self
    }

    /// Add annotation
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value.into());
        self
    }
}

/// Common predicate types
pub mod predicate_types {
    /// SLSA Provenance v1.0
    pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

    /// SLSA Provenance v0.2 (legacy)
    pub const SLSA_PROVENANCE_V02: &str = "https://slsa.dev/provenance/v0.2";

    /// SLSA Verification Summary
    pub const SLSA_VSA_V1: &str = "https://slsa.dev/verification_summary/v1";

    /// WSC Transformation attestation
    pub const WSC_TRANSFORMATION_V1: &str = "https://wsc.dev/transformation/v1";

    /// WSC Composition attestation
    pub const WSC_COMPOSITION_V1: &str = "https://wsc.dev/composition/v1";

    /// SPDX SBOM
    pub const SPDX: &str = "https://spdx.dev/Document";

    /// CycloneDX SBOM
    pub const CYCLONEDX: &str = "https://cyclonedx.org/bom";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_subject_creation() {
        let subject = Subject::new("artifact.wasm", "abc123");

        assert_eq!(subject.name, "artifact.wasm");
        assert_eq!(subject.digest.sha256_value(), Some("abc123"));
    }

    #[test]
    fn test_subject_from_bytes() {
        let subject = Subject::from_bytes("test.wasm", b"hello world");

        assert_eq!(subject.name, "test.wasm");
        assert!(subject.digest.sha256_value().is_some());
        // SHA256 of "hello world"
        assert_eq!(
            subject.digest.sha256_value().unwrap(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_digest_set() {
        let mut digests = DigestSet::new();
        digests.insert("sha256", "abc");
        digests.insert("sha512", "def");

        assert_eq!(digests.len(), 2);
        assert_eq!(digests.get("sha256"), Some("abc"));
        assert_eq!(digests.get("sha512"), Some("def"));
        assert_eq!(digests.get("md5"), None);
    }

    #[test]
    fn test_statement_serialization() {
        let statement = Statement::new(
            vec![Subject::new("module.wasm", "deadbeef")],
            predicate_types::WSC_TRANSFORMATION_V1,
            json!({
                "transformationType": "optimization",
                "tool": {"name": "test", "version": "1.0"}
            }),
        );

        let json = statement.to_json().unwrap();
        assert!(json.contains("https://in-toto.io/Statement/v1"));
        assert!(json.contains("module.wasm"));
        assert!(json.contains("deadbeef"));
        assert!(json.contains("wsc.dev/transformation"));
    }

    #[test]
    fn test_statement_roundtrip() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct TestPredicate {
            value: String,
        }

        let original = Statement::new(
            vec![Subject::new("test.bin", "123456")],
            "https://example.com/predicate/v1",
            TestPredicate { value: "test".to_string() },
        );

        let json = original.to_json().unwrap();
        let parsed: Statement<TestPredicate> = Statement::from_json(&json).unwrap();

        assert_eq!(parsed.type_, STATEMENT_TYPE_V1);
        assert_eq!(parsed.subject.len(), 1);
        assert_eq!(parsed.subject[0].name, "test.bin");
        assert_eq!(parsed.predicate.value, "test");
    }

    #[test]
    fn test_resource_descriptor() {
        let resource = ResourceDescriptor::new("https://example.com/file", "abc123")
            .with_media_type("application/wasm")
            .with_annotation("source", "github");

        assert_eq!(resource.uri, Some("https://example.com/file".to_string()));
        assert_eq!(resource.digest.get("sha256"), Some(&"abc123".to_string()));
        assert_eq!(resource.media_type, Some("application/wasm".to_string()));
        assert_eq!(
            resource.annotations.as_ref().unwrap().get("source"),
            Some(&"github".to_string())
        );
    }

    #[test]
    fn test_resource_descriptor_from_bytes() {
        let resource = ResourceDescriptor::from_bytes("module.wasm", b"test content");

        assert_eq!(resource.name, Some("module.wasm".to_string()));
        assert!(resource.digest.contains_key("sha256"));
    }
}
