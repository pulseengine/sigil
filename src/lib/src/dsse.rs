//! DSSE (Dead Simple Signing Envelope) implementation
//!
//! Implements the DSSE protocol for signing arbitrary payloads.
//! See: https://github.com/secure-systems-lab/dsse
//!
//! DSSE provides:
//! - Payload type authentication (prevents type confusion attacks)
//! - Multi-signature support
//! - Format-agnostic payload handling
//!
//! # Example
//!
//! ```ignore
//! use wsc::dsse::{DsseEnvelope, DsseSigner};
//!
//! let payload = b"my attestation data";
//! let envelope = DsseEnvelope::sign(
//!     payload,
//!     "application/vnd.in-toto+json",
//!     &signer,
//! )?;
//!
//! // Verify
//! let verified_payload = envelope.verify(&verifier)?;
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use crate::error::WSError;

/// DSSE envelope containing a signed payload
///
/// The envelope wraps arbitrary data with cryptographic signatures,
/// ensuring both the payload and its type are authenticated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// Base64-encoded payload
    pub payload: String,

    /// Media type of the payload (e.g., "application/vnd.in-toto+json")
    pub payload_type: String,

    /// One or more signatures over PAE(payloadType, payload)
    pub signatures: Vec<DsseSignature>,
}

/// A single signature within a DSSE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Key identifier (optional, unauthenticated hint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,

    /// Base64-encoded signature over PAE(payloadType, payload)
    pub sig: String,
}

/// Trait for signing DSSE payloads
pub trait DsseSigner {
    /// Sign the PAE-encoded data and return the signature bytes
    fn sign(&self, pae: &[u8]) -> Result<Vec<u8>, WSError>;

    /// Return the key ID (optional)
    fn key_id(&self) -> Option<String> {
        None
    }
}

/// Trait for verifying DSSE signatures
pub trait DsseVerifier {
    /// Verify the signature over PAE-encoded data
    fn verify(&self, pae: &[u8], signature: &[u8]) -> Result<(), WSError>;
}

impl DsseEnvelope {
    /// Create a new DSSE envelope by signing a payload
    ///
    /// # Arguments
    ///
    /// * `payload` - Raw bytes to sign
    /// * `payload_type` - Media type (e.g., "application/vnd.in-toto+json")
    /// * `signer` - Implementation of DsseSigner
    pub fn sign(
        payload: &[u8],
        payload_type: &str,
        signer: &dyn DsseSigner,
    ) -> Result<Self, WSError> {
        // Compute PAE (Pre-Authentication Encoding)
        let pae = compute_pae(payload_type, payload);

        // Sign the PAE
        let sig_bytes = signer.sign(&pae)?;

        Ok(Self {
            payload: BASE64.encode(payload),
            payload_type: payload_type.to_string(),
            signatures: vec![DsseSignature {
                keyid: signer.key_id(),
                sig: BASE64.encode(sig_bytes),
            }],
        })
    }

    /// Create a DSSE envelope with multiple signatures
    pub fn sign_multi(
        payload: &[u8],
        payload_type: &str,
        signers: &[&dyn DsseSigner],
    ) -> Result<Self, WSError> {
        if signers.is_empty() {
            return Err(WSError::InvalidArgument);
        }

        let pae = compute_pae(payload_type, payload);
        let mut signatures = Vec::with_capacity(signers.len());

        for signer in signers {
            let sig_bytes = signer.sign(&pae)?;
            signatures.push(DsseSignature {
                keyid: signer.key_id(),
                sig: BASE64.encode(sig_bytes),
            });
        }

        Ok(Self {
            payload: BASE64.encode(payload),
            payload_type: payload_type.to_string(),
            signatures,
        })
    }

    /// Verify the envelope and return the decoded payload
    ///
    /// Verifies at least one signature is valid.
    pub fn verify(&self, verifier: &dyn DsseVerifier) -> Result<Vec<u8>, WSError> {
        if self.signatures.is_empty() {
            return Err(WSError::VerificationFailed);
        }

        // Decode payload
        let payload = BASE64.decode(&self.payload).map_err(|e| {
            WSError::InternalError(format!("Invalid base64 payload: {}", e))
        })?;

        // Compute PAE
        let pae = compute_pae(&self.payload_type, &payload);

        // Verify at least one signature
        let mut verified = false;
        for sig in &self.signatures {
            let sig_bytes = BASE64.decode(&sig.sig).map_err(|e| {
                WSError::InternalError(format!("Invalid base64 signature: {}", e))
            })?;

            if verifier.verify(&pae, &sig_bytes).is_ok() {
                verified = true;
                break;
            }
        }

        if !verified {
            return Err(WSError::VerificationFailed);
        }

        Ok(payload)
    }

    /// Verify all signatures in the envelope
    ///
    /// Returns error if any signature fails verification.
    pub fn verify_all(&self, verifier: &dyn DsseVerifier) -> Result<Vec<u8>, WSError> {
        if self.signatures.is_empty() {
            return Err(WSError::VerificationFailed);
        }

        let payload = BASE64.decode(&self.payload).map_err(|e| {
            WSError::InternalError(format!("Invalid base64 payload: {}", e))
        })?;

        let pae = compute_pae(&self.payload_type, &payload);

        for sig in &self.signatures {
            let sig_bytes = BASE64.decode(&sig.sig).map_err(|e| {
                WSError::InternalError(format!("Invalid base64 signature: {}", e))
            })?;

            verifier.verify(&pae, &sig_bytes)?;
        }

        Ok(payload)
    }

    /// Get the decoded payload without verification
    ///
    /// # Warning
    ///
    /// This does not verify signatures. Use only when verification
    /// is done separately or not required.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, WSError> {
        BASE64.decode(&self.payload).map_err(|e| {
            WSError::InternalError(format!("Invalid base64 payload: {}", e))
        })
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, WSError> {
        serde_json::to_string(self).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize DSSE envelope: {}", e))
        })
    }

    /// Serialize to pretty JSON
    pub fn to_json_pretty(&self) -> Result<String, WSError> {
        serde_json::to_string_pretty(self).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize DSSE envelope: {}", e))
        })
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, WSError> {
        serde_json::from_str(json).map_err(|e| {
            WSError::InternalError(format!("Failed to parse DSSE envelope: {}", e))
        })
    }

    /// Create an unsigned envelope (for testing or deferred signing)
    pub fn unsigned(payload: &[u8], payload_type: &str) -> Self {
        Self {
            payload: BASE64.encode(payload),
            payload_type: payload_type.to_string(),
            signatures: vec![],
        }
    }

    /// Add a signature to an existing envelope
    pub fn add_signature(&mut self, signer: &dyn DsseSigner) -> Result<(), WSError> {
        let payload = self.payload_bytes()?;
        let pae = compute_pae(&self.payload_type, &payload);
        let sig_bytes = signer.sign(&pae)?;

        self.signatures.push(DsseSignature {
            keyid: signer.key_id(),
            sig: BASE64.encode(sig_bytes),
        });

        Ok(())
    }
}

/// Compute PAE (Pre-Authentication Encoding)
///
/// PAE(type, payload) = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
///
/// Where:
/// - SP is a space character (0x20)
/// - LEN is the length as a decimal ASCII string
fn compute_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();

    // "DSSEv1 "
    pae.extend_from_slice(b"DSSEv1 ");

    // LEN(type) SP type SP
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');

    // LEN(payload) SP payload
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);

    pae
}

/// Ed25519 signer implementation for DSSE
pub struct Ed25519DsseSigner {
    secret_key: ed25519_compact::SecretKey,
    key_id: Option<String>,
}

impl Ed25519DsseSigner {
    /// Create a new Ed25519 signer
    pub fn new(secret_key: ed25519_compact::SecretKey, key_id: Option<String>) -> Self {
        Self { secret_key, key_id }
    }

    /// Create from raw secret key bytes
    pub fn from_bytes(bytes: &[u8], key_id: Option<String>) -> Result<Self, WSError> {
        let secret_key = ed25519_compact::SecretKey::from_slice(bytes)
            .map_err(|e| WSError::CryptoError(e))?;
        Ok(Self { secret_key, key_id })
    }
}

impl DsseSigner for Ed25519DsseSigner {
    fn sign(&self, pae: &[u8]) -> Result<Vec<u8>, WSError> {
        let signature = self.secret_key.sign(pae, None);
        Ok(signature.to_vec())
    }

    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }
}

/// Ed25519 verifier implementation for DSSE
pub struct Ed25519DsseVerifier {
    public_key: ed25519_compact::PublicKey,
}

impl Ed25519DsseVerifier {
    /// Create a new Ed25519 verifier
    pub fn new(public_key: ed25519_compact::PublicKey) -> Self {
        Self { public_key }
    }

    /// Create from raw public key bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WSError> {
        let public_key = ed25519_compact::PublicKey::from_slice(bytes)
            .map_err(|e| WSError::CryptoError(e))?;
        Ok(Self { public_key })
    }
}

impl DsseVerifier for Ed25519DsseVerifier {
    fn verify(&self, pae: &[u8], signature: &[u8]) -> Result<(), WSError> {
        let sig = ed25519_compact::Signature::from_slice(signature)
            .map_err(|e| WSError::CryptoError(e))?;

        self.public_key
            .verify(pae, &sig)
            .map_err(|_| WSError::VerificationFailed)
    }
}

/// Standard payload types
pub mod payload_types {
    /// in-toto statement
    pub const IN_TOTO: &str = "application/vnd.in-toto+json";

    /// SLSA provenance
    pub const SLSA_PROVENANCE: &str = "application/vnd.slsa.provenance+json";

    /// CycloneDX SBOM
    pub const CYCLONEDX: &str = "application/vnd.cyclonedx+json";

    /// WSC transformation attestation
    pub const WSC_TRANSFORMATION: &str = "application/vnd.wsc.transformation+json";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_keypair() -> (ed25519_compact::SecretKey, ed25519_compact::PublicKey) {
        let kp = ed25519_compact::KeyPair::generate();
        (kp.sk, kp.pk)
    }

    #[test]
    fn test_pae_computation() {
        let pae = compute_pae("application/example", b"hello");
        let expected = b"DSSEv1 19 application/example 5 hello";
        assert_eq!(pae, expected);
    }

    #[test]
    fn test_pae_empty_payload() {
        let pae = compute_pae("text/plain", b"");
        let expected = b"DSSEv1 10 text/plain 0 ";
        assert_eq!(pae, expected);
    }

    #[test]
    fn test_sign_and_verify() {
        let (sk, pk) = generate_test_keypair();
        let signer = Ed25519DsseSigner::new(sk, Some("test-key".to_string()));
        let verifier = Ed25519DsseVerifier::new(pk);

        let payload = b"test payload";
        let envelope = DsseEnvelope::sign(
            payload,
            payload_types::IN_TOTO,
            &signer,
        ).unwrap();

        assert_eq!(envelope.payload_type, payload_types::IN_TOTO);
        assert_eq!(envelope.signatures.len(), 1);
        assert_eq!(envelope.signatures[0].keyid, Some("test-key".to_string()));

        let verified = envelope.verify(&verifier).unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn test_json_roundtrip() {
        let (sk, _pk) = generate_test_keypair();
        let signer = Ed25519DsseSigner::new(sk, None);

        let envelope = DsseEnvelope::sign(
            b"test data",
            "application/json",
            &signer,
        ).unwrap();

        let json = envelope.to_json().unwrap();
        let parsed = DsseEnvelope::from_json(&json).unwrap();

        assert_eq!(parsed.payload, envelope.payload);
        assert_eq!(parsed.payload_type, envelope.payload_type);
        assert_eq!(parsed.signatures.len(), envelope.signatures.len());
    }

    #[test]
    fn test_multi_signature() {
        let (sk1, pk1) = generate_test_keypair();
        let (sk2, pk2) = generate_test_keypair();

        let signer1 = Ed25519DsseSigner::new(sk1, Some("key1".to_string()));
        let signer2 = Ed25519DsseSigner::new(sk2, Some("key2".to_string()));
        let verifier1 = Ed25519DsseVerifier::new(pk1);
        let verifier2 = Ed25519DsseVerifier::new(pk2);

        let envelope = DsseEnvelope::sign_multi(
            b"multi-signed payload",
            "application/json",
            &[&signer1, &signer2],
        ).unwrap();

        assert_eq!(envelope.signatures.len(), 2);

        // Either verifier should work with verify()
        assert!(envelope.verify(&verifier1).is_ok());
        assert!(envelope.verify(&verifier2).is_ok());
    }

    #[test]
    fn test_verify_fails_wrong_key() {
        let (sk, _pk) = generate_test_keypair();
        let (_, other_pk) = generate_test_keypair();

        let signer = Ed25519DsseSigner::new(sk, None);
        let wrong_verifier = Ed25519DsseVerifier::new(other_pk);

        let envelope = DsseEnvelope::sign(
            b"test",
            "application/json",
            &signer,
        ).unwrap();

        assert!(envelope.verify(&wrong_verifier).is_err());
    }

    #[test]
    fn test_unsigned_envelope() {
        let envelope = DsseEnvelope::unsigned(b"unsigned data", "text/plain");

        assert!(envelope.signatures.is_empty());
        assert_eq!(envelope.payload_bytes().unwrap(), b"unsigned data");
    }

    #[test]
    fn test_add_signature() {
        let (sk, pk) = generate_test_keypair();
        let signer = Ed25519DsseSigner::new(sk, Some("added".to_string()));
        let verifier = Ed25519DsseVerifier::new(pk);

        let mut envelope = DsseEnvelope::unsigned(b"deferred signing", "text/plain");
        assert!(envelope.signatures.is_empty());

        envelope.add_signature(&signer).unwrap();
        assert_eq!(envelope.signatures.len(), 1);

        let verified = envelope.verify(&verifier).unwrap();
        assert_eq!(verified, b"deferred signing");
    }

    #[test]
    fn test_payload_types() {
        assert!(payload_types::IN_TOTO.contains("in-toto"));
        assert!(payload_types::CYCLONEDX.contains("cyclonedx"));
        assert!(payload_types::SLSA_PROVENANCE.contains("slsa"));
    }
}
