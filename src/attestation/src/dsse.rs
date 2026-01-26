//! Dead Simple Signing Envelope (DSSE) implementation
//!
//! DSSE is a standard envelope format for signing arbitrary payloads,
//! used by in-toto and SLSA for attestation signatures.
//!
//! Specification: <https://github.com/secure-systems-lab/dsse>
//!
//! # Example
//!
//! ```rust
//! use wsc_attestation::dsse::*;
//!
//! // Create a DSSE envelope
//! let envelope = DsseEnvelope::new(
//!     b"payload data",
//!     "application/vnd.in-toto+json",
//! );
//!
//! // Sign the envelope (in real usage, use actual signing)
//! // let signed = envelope.sign(&signer, Some("key-id"))?;
//! ```

use serde::{Deserialize, Serialize};

/// DSSE payload type for in-toto statements
pub const PAYLOAD_TYPE_INTOTO: &str = "application/vnd.in-toto+json";

/// DSSE payload type for SLSA provenance
pub const PAYLOAD_TYPE_SLSA: &str = "application/vnd.in-toto+json";

/// Dead Simple Signing Envelope
///
/// Per the DSSE specification, this envelope wraps a payload with
/// one or more signatures. The payload is base64-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// Base64-encoded payload
    pub payload: String,

    /// Media type of the payload (e.g., "application/vnd.in-toto+json")
    pub payload_type: String,

    /// One or more signatures over the PAE-encoded message
    pub signatures: Vec<DsseSignature>,
}

/// A single signature in a DSSE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    /// Base64-encoded signature bytes
    pub sig: String,

    /// Optional key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
}

impl DsseEnvelope {
    /// Create a new unsigned DSSE envelope
    ///
    /// The payload is automatically base64-encoded.
    pub fn new(payload: &[u8], payload_type: impl Into<String>) -> Self {
        use base64::Engine;
        Self {
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            payload_type: payload_type.into(),
            signatures: Vec::new(),
        }
    }

    /// Create a DSSE envelope from a JSON-serializable payload
    pub fn from_payload<T: Serialize>(payload: &T, payload_type: impl Into<String>) -> Result<Self, serde_json::Error> {
        let json = serde_json::to_vec(payload)?;
        Ok(Self::new(&json, payload_type))
    }

    /// Compute the Pre-Authentication Encoding (PAE)
    ///
    /// PAE(type, payload) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
    /// where SP = 0x20 (space) and LEN is the decimal ASCII length
    pub fn pae(&self) -> Vec<u8> {
        Self::compute_pae(&self.payload_type, &self.payload)
    }

    /// Compute PAE for given type and payload (base64-encoded)
    pub fn compute_pae(payload_type: &str, payload_b64: &str) -> Vec<u8> {
        use base64::Engine;

        // Decode the base64 payload to get actual bytes
        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .unwrap_or_default();

        Self::compute_pae_raw(payload_type, &payload_bytes)
    }

    /// Compute PAE for raw bytes
    pub fn compute_pae_raw(payload_type: &str, payload: &[u8]) -> Vec<u8> {
        // PAE format: "DSSEv1 {len_type} {type} {len_payload} {payload}"
        // Each component separated by space (0x20)
        let mut pae = Vec::new();

        // "DSSEv1"
        pae.extend_from_slice(b"DSSEv1");
        pae.push(0x20); // space

        // Length of type (decimal ASCII)
        pae.extend_from_slice(payload_type.len().to_string().as_bytes());
        pae.push(0x20);

        // Type
        pae.extend_from_slice(payload_type.as_bytes());
        pae.push(0x20);

        // Length of payload (decimal ASCII)
        pae.extend_from_slice(payload.len().to_string().as_bytes());
        pae.push(0x20);

        // Payload
        pae.extend_from_slice(payload);

        pae
    }

    /// Get the decoded payload bytes
    pub fn payload_bytes(&self) -> Result<Vec<u8>, DsseError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(|e| DsseError::DecodeError(e.to_string()))
    }

    /// Parse the payload as JSON
    pub fn payload_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, DsseError> {
        let bytes = self.payload_bytes().map_err(|e| DsseError::DecodeError(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| DsseError::JsonError(e.to_string()))
    }

    /// Add a signature to the envelope
    pub fn add_signature(&mut self, sig: DsseSignature) {
        self.signatures.push(sig);
    }

    /// Sign the envelope with Ed25519 and add the signature
    #[cfg(feature = "signing")]
    pub fn sign_ed25519(
        &mut self,
        secret_key: &ed25519_compact::SecretKey,
        key_id: Option<String>,
    ) {
        use base64::Engine;

        let pae = self.pae();
        let signature = secret_key.sign(&pae, None);

        self.signatures.push(DsseSignature {
            sig: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
            keyid: key_id,
        });
    }

    /// Verify all signatures in the envelope
    #[cfg(feature = "signing")]
    pub fn verify_ed25519(&self, public_key: &ed25519_compact::PublicKey) -> Result<bool, DsseError> {
        use base64::Engine;

        if self.signatures.is_empty() {
            return Err(DsseError::NoSignatures);
        }

        let pae = self.pae();

        for sig in &self.signatures {
            let sig_bytes = base64::engine::general_purpose::STANDARD
                .decode(&sig.sig)
                .map_err(|e| DsseError::DecodeError(e.to_string()))?;

            let signature = ed25519_compact::Signature::from_slice(&sig_bytes)
                .map_err(|e| DsseError::InvalidSignature(e.to_string()))?;

            public_key.verify(&pae, &signature)
                .map_err(|_| DsseError::VerificationFailed)?;
        }

        Ok(true)
    }

    /// Check if the envelope has any signatures
    pub fn is_signed(&self) -> bool {
        !self.signatures.is_empty()
    }

    /// Get the number of signatures
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl DsseSignature {
    /// Create a new signature
    pub fn new(sig: impl Into<String>, keyid: Option<String>) -> Self {
        Self {
            sig: sig.into(),
            keyid,
        }
    }
}

/// Errors that can occur during DSSE operations
#[derive(Debug, Clone)]
pub enum DsseError {
    /// Base64 decoding error
    DecodeError(String),
    /// JSON parsing error
    JsonError(String),
    /// No signatures present
    NoSignatures,
    /// Invalid signature format
    InvalidSignature(String),
    /// Signature verification failed
    VerificationFailed,
}

impl std::fmt::Display for DsseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsseError::DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            DsseError::JsonError(e) => write!(f, "JSON error: {}", e),
            DsseError::NoSignatures => write!(f, "No signatures in envelope"),
            DsseError::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            DsseError::VerificationFailed => write!(f, "Signature verification failed"),
        }
    }
}

impl std::error::Error for DsseError {}

/// in-toto Statement v1.0 wrapper
///
/// This is the standard format for in-toto attestations that can be
/// wrapped in a DSSE envelope.
///
/// Specification: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    /// Statement type (always "https://in-toto.io/Statement/v1")
    #[serde(rename = "_type")]
    pub _type: String,

    /// Subjects (artifacts) this statement is about
    pub subject: Vec<InTotoSubject>,

    /// Predicate type URI (e.g., "https://slsa.dev/provenance/v1")
    pub predicate_type: String,

    /// The predicate (attestation content)
    pub predicate: serde_json::Value,
}

/// Subject (artifact) in an in-toto statement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoSubject {
    /// Artifact name or path
    pub name: String,

    /// Cryptographic digests (algorithm -> hex value)
    pub digest: std::collections::HashMap<String, String>,
}

/// Standard in-toto statement type URI
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// WSC transformation predicate type
pub const WSC_TRANSFORMATION_PREDICATE: &str = "https://wsc.dev/transformation/v1";

/// WSC composition predicate type
pub const WSC_COMPOSITION_PREDICATE: &str = "https://wsc.dev/composition/v1";

/// SLSA provenance v1 predicate type
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// Resource Descriptor for SLSA provenance
///
/// Per SLSA spec: describes an immutable software artifact (source, dependency, output)
/// <https://slsa.dev/spec/v1.0/provenance#resourcedescriptor>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDescriptor {
    /// Artifact URI (e.g., "git+https://github.com/...", "pkg:cargo/...")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Cryptographic digests (algorithm -> hex value)
    pub digest: std::collections::HashMap<String, String>,

    /// Human-readable name or identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// URI to download the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_location: Option<String>,

    /// Media type (MIME type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// Base64-encoded content (for small artifacts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Additional annotations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::HashMap<String, String>>,
}

impl ResourceDescriptor {
    /// Create a new resource descriptor with SHA-256 digest
    pub fn new_sha256(name: impl Into<String>, sha256: impl Into<String>) -> Self {
        let mut digest = std::collections::HashMap::new();
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

    /// Create from a package URL (purl)
    ///
    /// # Example
    ///
    /// ```rust
    /// use wsc_attestation::dsse::ResourceDescriptor;
    ///
    /// let dep = ResourceDescriptor::from_purl(
    ///     "pkg:cargo/serde@1.0.200",
    ///     "abc123def456..."
    /// );
    /// ```
    pub fn from_purl(purl: impl Into<String>, sha256: impl Into<String>) -> Self {
        let purl = purl.into();
        let mut desc = Self::new_sha256(&purl, sha256);
        desc.uri = Some(purl);
        desc
    }

    /// Create for a git source
    pub fn git_source(
        repo_url: impl Into<String>,
        commit: impl Into<String>,
    ) -> Self {
        let commit = commit.into();
        let mut digest = std::collections::HashMap::new();
        digest.insert("gitCommit".to_string(), commit.clone());

        Self {
            uri: Some(format!("git+{}", repo_url.into())),
            digest,
            name: None,
            download_location: None,
            media_type: None,
            content: None,
            annotations: None,
        }
    }

    /// Add a URI
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Add download location
    pub fn with_download_location(mut self, location: impl Into<String>) -> Self {
        self.download_location = Some(location.into());
        self
    }

    /// Add media type
    pub fn with_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.media_type = Some(media_type.into());
        self
    }

    /// Add an annotation
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations
            .get_or_insert_with(std::collections::HashMap::new)
            .insert(key.into(), value.into());
        self
    }
}

impl InTotoStatement {
    /// Create a new in-toto statement
    pub fn new<P: Serialize>(
        predicate_type: impl Into<String>,
        predicate: &P,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self {
            _type: INTOTO_STATEMENT_TYPE.to_string(),
            subject: Vec::new(),
            predicate_type: predicate_type.into(),
            predicate: serde_json::to_value(predicate)?,
        })
    }

    /// Add a subject to the statement
    pub fn add_subject(&mut self, name: impl Into<String>, sha256: impl Into<String>) {
        let mut digest = std::collections::HashMap::new();
        digest.insert("sha256".to_string(), sha256.into());

        self.subject.push(InTotoSubject {
            name: name.into(),
            digest,
        });
    }

    /// Wrap in a DSSE envelope
    pub fn to_dsse(&self) -> Result<DsseEnvelope, serde_json::Error> {
        DsseEnvelope::from_payload(self, PAYLOAD_TYPE_INTOTO)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl InTotoSubject {
    /// Create a new subject with SHA-256 digest
    pub fn new(name: impl Into<String>, sha256: impl Into<String>) -> Self {
        let mut digest = std::collections::HashMap::new();
        digest.insert("sha256".to_string(), sha256.into());

        Self {
            name: name.into(),
            digest,
        }
    }

    /// Add an additional digest algorithm
    pub fn with_digest(mut self, algorithm: impl Into<String>, value: impl Into<String>) -> Self {
        self.digest.insert(algorithm.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsse_envelope_creation() {
        let payload = b"test payload";
        let envelope = DsseEnvelope::new(payload, "text/plain");

        assert_eq!(envelope.payload_type, "text/plain");
        assert!(!envelope.is_signed());
        assert_eq!(envelope.signature_count(), 0);

        // Verify we can decode the payload
        let decoded = envelope.payload_bytes().unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_dsse_pae_computation() {
        // Test vector from DSSE spec
        let payload_type = "application/vnd.in-toto+json";
        let payload = b"hello world";

        let pae = DsseEnvelope::compute_pae_raw(payload_type, payload);

        // PAE should start with "DSSEv1 "
        assert!(pae.starts_with(b"DSSEv1 "));

        // Should contain the payload type length, type, payload length, and payload
        let pae_str = String::from_utf8_lossy(&pae);
        // "application/vnd.in-toto+json" is 28 characters
        assert!(pae_str.contains("28"), "Expected 28, got: {}", pae_str);
        assert!(pae_str.contains("application/vnd.in-toto+json"));
        assert!(pae_str.contains("11")); // length of "hello world"
    }

    #[test]
    fn test_dsse_from_payload() {
        #[derive(Serialize, Deserialize)]
        struct TestPayload {
            message: String,
        }

        let payload = TestPayload { message: "test".to_string() };
        let envelope = DsseEnvelope::from_payload(&payload, "application/json").unwrap();

        assert_eq!(envelope.payload_type, "application/json");

        // Verify we can parse it back
        let parsed: TestPayload = envelope.payload_json().unwrap();
        assert_eq!(parsed.message, "test");
    }

    #[test]
    fn test_intoto_statement() {
        #[derive(Serialize)]
        struct TestPredicate {
            tool: String,
        }

        let predicate = TestPredicate { tool: "test-tool".to_string() };
        let mut statement = InTotoStatement::new(WSC_TRANSFORMATION_PREDICATE, &predicate).unwrap();

        statement.add_subject("artifact.wasm", "abc123def456");

        assert_eq!(statement._type, INTOTO_STATEMENT_TYPE);
        assert_eq!(statement.predicate_type, WSC_TRANSFORMATION_PREDICATE);
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].name, "artifact.wasm");
        assert_eq!(statement.subject[0].digest.get("sha256"), Some(&"abc123def456".to_string()));
    }

    #[test]
    fn test_intoto_to_dsse() {
        #[derive(Serialize)]
        struct TestPredicate {
            version: String,
        }

        let predicate = TestPredicate { version: "1.0".to_string() };
        let mut statement = InTotoStatement::new(WSC_TRANSFORMATION_PREDICATE, &predicate).unwrap();
        statement.add_subject("test.wasm", "sha256hash");

        let envelope = statement.to_dsse().unwrap();

        assert_eq!(envelope.payload_type, PAYLOAD_TYPE_INTOTO);
        assert!(!envelope.is_signed());

        // Verify roundtrip
        let parsed: InTotoStatement = envelope.payload_json().unwrap();
        assert_eq!(parsed._type, INTOTO_STATEMENT_TYPE);
        assert_eq!(parsed.subject[0].name, "test.wasm");
    }

    #[test]
    fn test_dsse_json_roundtrip() {
        let envelope = DsseEnvelope::new(b"test", "text/plain");
        let json = envelope.to_json().unwrap();
        let parsed = DsseEnvelope::from_json(&json).unwrap();

        assert_eq!(parsed.payload, envelope.payload);
        assert_eq!(parsed.payload_type, envelope.payload_type);
    }

    #[test]
    fn test_intoto_subject_multiple_digests() {
        let subject = InTotoSubject::new("file.txt", "sha256hash")
            .with_digest("sha512", "sha512hash")
            .with_digest("sha1", "sha1hash");

        assert_eq!(subject.digest.len(), 3);
        assert_eq!(subject.digest.get("sha256"), Some(&"sha256hash".to_string()));
        assert_eq!(subject.digest.get("sha512"), Some(&"sha512hash".to_string()));
    }

    #[cfg(feature = "signing")]
    #[test]
    fn test_dsse_sign_verify() {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();
        let mut envelope = DsseEnvelope::new(b"test payload", "text/plain");

        envelope.sign_ed25519(&keypair.sk, Some("test-key".to_string()));

        assert!(envelope.is_signed());
        assert_eq!(envelope.signature_count(), 1);
        assert_eq!(envelope.signatures[0].keyid, Some("test-key".to_string()));

        // Verify
        let result = envelope.verify_ed25519(&keypair.pk);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
