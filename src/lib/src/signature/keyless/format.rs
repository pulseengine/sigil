use crate::Module;
use crate::error::WSError;
use crate::wasm_module::varint;
use serde_json;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use x509_parser::prelude::*;

// Re-export RekorEntry from the rekor module
use super::cert_verifier::CertificatePool;
pub use super::rekor::RekorEntry;
use super::rekor_verifier::RekorKeyring;

/// Binary format version for keyless signatures
pub const KEYLESS_VERSION: u8 = 0x02;

/// Signature type identifier for keyless signatures
pub const KEYLESS_SIG_TYPE: u8 = 0x02;

/// Standard signature type identifier
pub const STANDARD_SIG_TYPE: u8 = 0x01;

/// Maximum accepted depth of an embedded X.509 certificate chain.
///
/// Real-world Fulcio chains are length 2–3 (leaf + intermediate(s) + root).
/// Industry CAs ship at most 4–5. We cap at 8 — generous headroom while
/// rejecting adversarial 1000-cert chains that would trigger heap exhaustion
/// in `x509_parser` / WebPKI before any signature work begins.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// Keyless signature custom section format
///
/// Binary format (extends existing wasmsig format):
/// ```text
/// [version: u8 = 0x02]              // New version for keyless
/// [sig_type: u8 = 0x02]             // 0x01 = standard, 0x02 = keyless
/// [signature_len: varint]
/// [signature: bytes]
/// [cert_chain_count: u8]
/// [cert_1_len: varint]
/// [cert_1: bytes]
/// ...
/// [rekor_entry_len: varint]
/// [rekor_entry: JSON bytes]
/// [module_hash_len: varint]
/// [module_hash: bytes]
/// ```
#[derive(Debug, Clone)]
pub struct KeylessSignature {
    /// ECDSA P-256 signature over `SHA256(module_bytes_without_signature_section)`,
    /// produced by the ephemeral key whose public half is in the leaf of
    /// [`cert_chain`](Self::cert_chain). Serialized in IEEE P1363 form (r || s).
    pub signature: Vec<u8>,
    /// X.509 certificate chain from Fulcio (PEM format)
    pub cert_chain: Vec<String>,
    /// Rekor transparency log entry
    pub rekor_entry: RekorEntry,
    /// SHA256 of the module **before** the keyless signature custom section
    /// was attached. Verifiers must recompute this from the candidate module
    /// (after stripping the signature section) and reject on mismatch.
    pub module_hash: Vec<u8>,
}

impl KeylessSignature {
    /// Create a new keyless signature
    pub fn new(
        signature: Vec<u8>,
        cert_chain: Vec<String>,
        rekor_entry: RekorEntry,
        module_hash: Vec<u8>,
    ) -> Self {
        Self {
            signature,
            cert_chain,
            rekor_entry,
            module_hash,
        }
    }

    /// Serialize to bytes for WASM custom section
    ///
    /// # Binary Format
    ///
    /// The serialized format is:
    /// - Version byte (0x02)
    /// - Signature type byte (0x02 for keyless)
    /// - Signature length (varint) + signature bytes
    /// - Certificate chain count (u8)
    /// - For each certificate: length (varint) + PEM bytes
    /// - Rekor entry length (varint) + JSON bytes
    /// - Module hash length (varint) + hash bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, WSError> {
        let mut buffer = Vec::new();

        // Write version
        buffer
            .write_all(&[KEYLESS_VERSION])
            .map_err(|e| WSError::KeylessFormatError(format!("Failed to write version: {}", e)))?;

        // Write signature type
        buffer.write_all(&[KEYLESS_SIG_TYPE]).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write signature type: {}", e))
        })?;

        // Write signature
        varint::put_slice(&mut buffer, &self.signature).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write signature: {}", e))
        })?;

        // Write certificate chain count
        let cert_count = self.cert_chain.len();
        if cert_count > 255 {
            return Err(WSError::KeylessFormatError(format!(
                "Certificate chain too long: {} (max 255)",
                cert_count
            )));
        }
        buffer.write_all(&[cert_count as u8]).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write cert count: {}", e))
        })?;

        // Write each certificate
        for (i, cert_pem) in self.cert_chain.iter().enumerate() {
            varint::put_slice(&mut buffer, cert_pem.as_bytes()).map_err(|e| {
                WSError::KeylessFormatError(format!("Failed to write certificate {}: {}", i, e))
            })?;
        }

        // Serialize Rekor entry to JSON
        let rekor_json = serde_json::to_vec(&self.rekor_entry).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to serialize Rekor entry: {}", e))
        })?;

        // Write Rekor entry
        varint::put_slice(&mut buffer, &rekor_json).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write Rekor entry: {}", e))
        })?;

        // Write module hash
        varint::put_slice(&mut buffer, &self.module_hash).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write module hash: {}", e))
        })?;

        Ok(buffer)
    }

    /// Deserialize from WASM custom section bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw bytes from the WASM custom section
    ///
    /// # Returns
    ///
    /// A parsed `KeylessSignature` or an error if the format is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WSError> {
        let mut reader = Cursor::new(bytes);

        // Read and verify version
        let mut version = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut version)
            .map_err(|e| WSError::KeylessFormatError(format!("Failed to read version: {}", e)))?;
        if version[0] != KEYLESS_VERSION {
            return Err(WSError::KeylessFormatError(format!(
                "Unsupported version: {} (expected {})",
                version[0], KEYLESS_VERSION
            )));
        }

        // Read and verify signature type
        let mut sig_type = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut sig_type).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read signature type: {}", e))
        })?;
        if sig_type[0] != KEYLESS_SIG_TYPE {
            return Err(WSError::KeylessFormatError(format!(
                "Unsupported signature type: {} (expected {})",
                sig_type[0], KEYLESS_SIG_TYPE
            )));
        }

        // Read signature
        let signature = varint::get_slice(&mut reader)
            .map_err(|e| WSError::KeylessFormatError(format!("Failed to read signature: {}", e)))?;

        // Read certificate chain count
        let mut cert_count = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut cert_count).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read certificate count: {}", e))
        })?;

        // Read certificates
        let mut cert_chain = Vec::new();
        for i in 0..cert_count[0] {
            let cert_bytes = varint::get_slice(&mut reader).map_err(|e| {
                WSError::KeylessFormatError(format!("Failed to read certificate {}: {}", i, e))
            })?;
            let cert_pem = String::from_utf8(cert_bytes).map_err(|e| {
                WSError::KeylessFormatError(format!("Certificate {} is not valid UTF-8: {}", i, e))
            })?;
            cert_chain.push(cert_pem);
        }

        // Read Rekor entry
        let rekor_json = varint::get_slice(&mut reader).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read Rekor entry: {}", e))
        })?;
        let rekor_entry: RekorEntry = serde_json::from_slice(&rekor_json).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to parse Rekor entry JSON: {}", e))
        })?;

        // Read module hash
        let module_hash = varint::get_slice(&mut reader).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read module hash: {}", e))
        })?;

        Ok(Self {
            signature,
            cert_chain,
            rekor_entry,
            module_hash,
        })
    }

    /// Extract identity from the leaf certificate
    ///
    /// The identity is typically stored in the Subject Alternative Name (SAN) extension,
    /// which contains the email, URI, or other identity from the OIDC token.
    ///
    /// # Returns
    ///
    /// The identity string (e.g., "user@example.com", "https://github.com/user/repo")
    pub fn get_identity(&self) -> Result<String, WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }

        // Parse the leaf certificate (first in chain)
        let leaf_pem = &self.cert_chain[0];
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes())
            .map_err(|e| WSError::CertificateError(format!("Failed to parse PEM: {}", e)))?;

        let cert = pem.parse_x509().map_err(|e| {
            WSError::CertificateError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        // Look for Subject Alternative Name extension
        if let Some(san_ext) =
            cert.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)?
            && let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
                // Try different SAN types in order of preference
                for name in &san.general_names {
                    match name {
                        GeneralName::RFC822Name(email) => {
                            return Ok(email.to_string());
                        }
                        GeneralName::URI(uri) => {
                            return Ok(uri.to_string());
                        }
                        GeneralName::DNSName(dns) => {
                            return Ok(dns.to_string());
                        }
                        _ => continue,
                    }
                }
            }

        // Fall back to subject common name if no SAN found
        for rdn in cert.subject().iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME
                    && let Ok(cn) = attr.as_str() {
                        return Ok(cn.to_string());
                    }
            }
        }

        Err(WSError::CertificateError(
            "No identity found in certificate".to_string(),
        ))
    }

    /// Extract issuer from the leaf certificate
    ///
    /// The issuer identifies the OIDC provider that issued the identity token
    /// (e.g., "https://accounts.google.com", "https://token.actions.githubusercontent.com").
    ///
    /// For Fulcio certificates, this is stored in a custom OID extension.
    ///
    /// # Returns
    ///
    /// The issuer URL string
    pub fn get_issuer(&self) -> Result<String, WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }

        // Parse the leaf certificate (first in chain)
        let leaf_pem = &self.cert_chain[0];
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes())
            .map_err(|e| WSError::CertificateError(format!("Failed to parse PEM: {}", e)))?;

        let cert = pem.parse_x509().map_err(|e| {
            WSError::CertificateError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        // Sigstore/Fulcio uses custom OIDs for OIDC issuer:
        // - 1.3.6.1.4.1.57264.1.1 (v1, deprecated but still common)
        // - 1.3.6.1.4.1.57264.1.8 (v2, Issuer V2)
        const OIDC_ISSUER_V1: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];
        const OIDC_ISSUER_V2: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 8];

        // Try to find the OIDC issuer in certificate extensions
        for ext in cert.extensions() {
            let oid_components: Vec<u64> = match ext.oid.iter() {
                Some(iter) => iter.collect(),
                None => continue,
            };

            // Check for OIDC Issuer v1 or v2
            if oid_components == OIDC_ISSUER_V1 || oid_components == OIDC_ISSUER_V2 {
                // The extension value is a UTF8String containing the issuer URL
                // It may be wrapped in ASN.1 encoding, try to extract the string
                let value = ext.value;

                // Try to parse as ASN.1 UTF8String first
                if let Ok((_, utf8_str)) = der_parser::der::parse_der_utf8string(value) {
                    if let Ok(s) = utf8_str.as_str() {
                        return Ok(s.to_string());
                    }
                }

                // Fallback: try to interpret raw bytes as UTF-8
                if let Ok(s) = std::str::from_utf8(value) {
                    return Ok(s.to_string());
                }
            }
        }

        // Fallback: extract certificate issuer common name
        // This is not the OIDC issuer, but provides some information
        for rdn in cert.issuer().iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME
                    && let Ok(cn) = attr.as_str()
                {
                    return Ok(cn.to_string());
                }
            }
        }

        Err(WSError::CertificateError(
            "No OIDC issuer found in certificate".to_string(),
        ))
    }

    /// Verify the certificate chain
    ///
    /// This performs full RFC 5280 certificate chain validation:
    /// - Validates certificate chain up to Fulcio root CA
    /// - Checks certificate signatures at each level
    /// - Verifies validity periods match Rekor integrated_time
    /// - Validates certificate extensions (Key Usage, Extended Key Usage)
    ///
    /// # Returns
    ///
    /// Ok if the certificate chain is valid, error otherwise
    ///
    /// # Security
    ///
    /// Uses WebPKI (rustls-webpki) for cryptographic verification.
    /// Trust anchors are embedded from Sigstore TUF repository.
    pub fn verify_cert_chain(&self) -> Result<(), WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "Empty certificate chain".to_string(),
            ));
        }

        // SECURITY: bound chain depth before invoking x509_parser/WebPKI.
        // An adversarial 1000-cert chain would otherwise trigger heap
        // exhaustion during PEM/DER decoding.
        if self.cert_chain.len() > MAX_CHAIN_DEPTH {
            return Err(WSError::ChainTooDeep(MAX_CHAIN_DEPTH));
        }

        // Load Fulcio trusted roots
        let cert_pool = CertificatePool::from_embedded_trust_root().map_err(|e| {
            WSError::CertificateError(format!("Failed to load trusted roots: {}", e))
        })?;

        // Parse integrated_time from Rekor entry (RFC3339 format)
        let integrated_time =
            chrono::DateTime::parse_from_rfc3339(&self.rekor_entry.integrated_time).map_err(
                |e| WSError::CertificateError(format!("Failed to parse integrated_time: {}", e)),
            )?;

        let integrated_time_unix = integrated_time.timestamp();

        // Verify the leaf certificate (first in chain)
        // The leaf certificate must chain up to a trusted Fulcio root CA
        let leaf_cert_pem = self
            .cert_chain
            .first()
            .ok_or_else(|| WSError::CertificateError("No leaf certificate in chain".to_string()))?;

        cert_pool
            .verify_pem_cert(leaf_cert_pem.as_bytes(), integrated_time_unix)
            .map_err(|e| {
                WSError::CertificateError(format!("Certificate verification failed: {}", e))
            })?;

        log::debug!("Certificate chain verified successfully");
        Ok(())
    }

    /// Verify the Rekor inclusion proof
    ///
    /// This performs complete Rekor transparency log verification:
    /// - Verifies the Merkle tree inclusion proof
    /// - Checks the signed entry timestamp (SET)
    /// - Validates against Rekor's public key
    /// - Verifies checkpoint signatures when available
    ///
    /// # Security
    ///
    /// This ensures that the signature was actually logged in Rekor's
    /// transparency log, providing non-repudiation and auditability.
    ///
    /// # Returns
    ///
    /// Ok if the inclusion proof is valid, error otherwise
    pub fn verify_rekor_inclusion(&self) -> Result<(), WSError> {
        log::debug!(
            "Verifying Rekor inclusion proof for entry {}",
            self.rekor_entry.uuid
        );

        // Load Rekor public keys from embedded trust root
        let keyring = RekorKeyring::from_embedded_trust_root()
            .map_err(|e| WSError::RekorError(format!("Failed to load Rekor public keys: {}", e)))?;

        // Verify the inclusion proof using the full verification implementation
        // This performs:
        // 1. Merkle tree inclusion proof verification (RFC 6962)
        // 2. Signed Entry Timestamp (SET) verification
        // 3. Checkpoint signature verification (if available)
        keyring.verify_inclusion_proof(&self.rekor_entry)?;

        log::debug!("Rekor inclusion proof verified successfully");
        Ok(())
    }

    /// Verify that this signature actually binds to the given module.
    ///
    /// This is the artifact-integrity step of keyless verification. It is
    /// **independent of** certificate chain validation and Rekor SET
    /// verification, which only attest to "this Fulcio cert exists and is
    /// known to the transparency log." Without this check, an attacker who
    /// obtains any valid Fulcio cert + Rekor entry can splice the signature
    /// blob onto an arbitrary module and the verifier will accept it
    /// (issue #135).
    ///
    /// Two checks run in sequence; failing either rejects the module:
    ///
    /// 1. **Hash binding.** Strip the embedded signature custom section,
    ///    serialize the remaining module, recompute its SHA-256, and require
    ///    it to equal [`Self::module_hash`]. This proves the candidate
    ///    module's bytes are the bytes the signer covered.
    /// 2. **Signature authenticity.** Extract the ECDSA P-256 public key
    ///    from the leaf certificate and verify [`Self::signature`] is a
    ///    valid signature over `SHA256(stripped_module_bytes)`. This proves
    ///    the cert's holder actually signed *this* hash, not someone else's.
    ///
    /// On any failure, returns [`WSError::VerificationFailed`] and emits a
    /// `log::error!` with the specific reason. The error variant does not
    /// distinguish hash vs. signature failure to avoid leaking which check
    /// a tampered artifact tripped.
    pub fn verify_artifact_binding(&self, module: &Module) -> Result<(), WSError> {
        use ecdsa::signature::DigestVerifier;
        use p256::ecdsa::{Signature as P256Signature, VerifyingKey};

        // Step 1: Recompute the module hash over the bytes the signer
        // covered (i.e., the module with the signature custom section
        // removed). The sign path computes the hash *before* attaching the
        // signature, so verify must mirror that by stripping it.
        let (unsigned_module, _stripped_signature_bytes) = module
            .clone()
            .detach_signature()
            .map_err(|_| WSError::NoSignatures)?;

        let mut unsigned_bytes = Vec::new();
        unsigned_module.serialize(&mut unsigned_bytes).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize stripped module: {}", e))
        })?;

        let recomputed_hash = Sha256::digest(&unsigned_bytes);
        if &recomputed_hash[..] != self.module_hash.as_slice() {
            log::error!(
                "Keyless artifact binding rejected: module hash mismatch \
                 (expected {}, recomputed {})",
                hex::encode(&self.module_hash),
                hex::encode(recomputed_hash),
            );
            return Err(WSError::VerificationFailed);
        }

        // Step 2: Extract the leaf cert's SPKI as a P-256 verifying key and
        // verify the signature blob against the recomputed digest. The sign
        // path uses `signing_key.sign_digest(Sha256)` with the same module
        // bytes — verify must use `verify_digest` symmetrically.
        let leaf_pem = self.cert_chain.first().ok_or_else(|| {
            log::error!("Keyless artifact binding rejected: empty certificate chain");
            WSError::VerificationFailed
        })?;

        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes()).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: failed to parse leaf cert PEM: {}",
                e
            );
            WSError::VerificationFailed
        })?;
        let cert = pem.parse_x509().map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: failed to parse leaf X.509: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        // Fulcio issues ECDSA P-256 keys (matching the sign path at
        // signer.rs `SigningKey::<p256::NistP256>::random`). The SPKI's
        // BIT STRING `data` field is the SEC1-encoded uncompressed point
        // (0x04 || x || y) for P-256, which `from_sec1_bytes` accepts.
        let spki_bits = cert.public_key().subject_public_key.data.as_ref();
        let verifying_key = VerifyingKey::from_sec1_bytes(spki_bits).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: leaf cert SPKI is not a valid \
                 ECDSA P-256 key: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        let signature = P256Signature::from_slice(&self.signature).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: signature blob is not a valid \
                 ECDSA P-256 signature: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&unsigned_bytes);
        verifying_key.verify_digest(hasher, &signature).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: ECDSA verify failed: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        log::debug!("Keyless artifact binding verified successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_signature() -> KeylessSignature {
        let signature = vec![1, 2, 3, 4, 5];
        let cert_chain = vec![
            "-----BEGIN CERTIFICATE-----\ntest cert 1\n-----END CERTIFICATE-----".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest cert 2\n-----END CERTIFICATE-----".to_string(),
        ];
        let rekor_entry = RekorEntry {
            uuid: "test-uuid-1234".to_string(),
            log_index: 42,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![10, 20, 30, 40],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T00:00:00Z".to_string(),
        };
        let module_hash = vec![0xde, 0xad, 0xbe, 0xef];

        KeylessSignature::new(signature, cert_chain, rekor_entry, module_hash)
    }

    #[test]
    fn test_serialization_roundtrip() {
        let sig = create_test_signature();

        // Serialize to bytes
        let bytes = sig.to_bytes().expect("Serialization failed");

        // Verify format markers
        assert_eq!(bytes[0], KEYLESS_VERSION);
        assert_eq!(bytes[1], KEYLESS_SIG_TYPE);

        // Deserialize back
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        // Verify all fields match
        assert_eq!(deserialized.signature, sig.signature);
        assert_eq!(deserialized.cert_chain, sig.cert_chain);
        assert_eq!(deserialized.rekor_entry.uuid, sig.rekor_entry.uuid);
        assert_eq!(
            deserialized.rekor_entry.log_index,
            sig.rekor_entry.log_index
        );
        assert_eq!(
            deserialized.rekor_entry.inclusion_proof,
            sig.rekor_entry.inclusion_proof
        );
        assert_eq!(
            deserialized.rekor_entry.integrated_time,
            sig.rekor_entry.integrated_time
        );
        assert_eq!(deserialized.module_hash, sig.module_hash);
    }

    #[test]
    fn test_empty_cert_chain() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 0);
    }

    #[test]
    fn test_single_cert_chain() {
        let mut sig = create_test_signature();
        sig.cert_chain =
            vec!["-----BEGIN CERTIFICATE-----\nsingle\n-----END CERTIFICATE-----".to_string()];

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 1);
        assert_eq!(deserialized.cert_chain[0], sig.cert_chain[0]);
    }

    #[test]
    fn test_max_cert_chain() {
        let mut sig = create_test_signature();
        // Create 255 certificates (max allowed)
        sig.cert_chain = (0..255)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\ncert {}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 255);
    }

    #[test]
    fn test_too_many_certs() {
        let mut sig = create_test_signature();
        // Create 256 certificates (one too many)
        sig.cert_chain = (0..256)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\ncert {}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let result = sig.to_bytes();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::KeylessFormatError(_)
        ));
    }

    #[test]
    fn test_invalid_version() {
        let sig = create_test_signature();
        let mut bytes = sig.to_bytes().expect("Serialization failed");

        // Corrupt version byte
        bytes[0] = 0xFF;

        let result = KeylessSignature::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::KeylessFormatError(_)
        ));
    }

    #[test]
    fn test_invalid_signature_type() {
        let sig = create_test_signature();
        let mut bytes = sig.to_bytes().expect("Serialization failed");

        // Corrupt signature type byte
        bytes[1] = STANDARD_SIG_TYPE;

        let result = KeylessSignature::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::KeylessFormatError(_)
        ));
    }

    #[test]
    fn test_truncated_data() {
        let sig = create_test_signature();
        let bytes = sig.to_bytes().expect("Serialization failed");

        // Try to deserialize truncated data
        let truncated = &bytes[0..5];
        let result = KeylessSignature::from_bytes(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekor_entry_json_serialization() {
        let entry = RekorEntry {
            uuid: "test-uuid".to_string(),
            log_index: 123,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![1, 2, 3],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&entry).expect("JSON serialization failed");
        let deserialized: RekorEntry =
            serde_json::from_str(&json).expect("JSON deserialization failed");

        assert_eq!(deserialized.uuid, entry.uuid);
        assert_eq!(deserialized.log_index, entry.log_index);
        assert_eq!(deserialized.body, entry.body);
        assert_eq!(deserialized.log_id, entry.log_id);
        assert_eq!(deserialized.inclusion_proof, entry.inclusion_proof);
        assert_eq!(
            deserialized.signed_entry_timestamp,
            entry.signed_entry_timestamp
        );
        assert_eq!(deserialized.integrated_time, entry.integrated_time);
    }

    #[test]
    fn test_verify_cert_chain_rejects_invalid() {
        let sig = create_test_signature();
        // Real implementation should reject fake test certificates
        // (create_test_signature uses dummy PEM data, not real Fulcio certs)
        assert!(sig.verify_cert_chain().is_err());

        // Empty chain should also be rejected
        let mut empty_sig = sig.clone();
        empty_sig.cert_chain = vec![];
        assert!(empty_sig.verify_cert_chain().is_err());
    }

    #[test]
    fn test_verify_rekor_inclusion_rejects_invalid() {
        let sig = create_test_signature();
        // The test data has invalid Rekor entry, so verification should fail
        // This proves that real verification is happening (not just a stub)
        let result = sig.verify_rekor_inclusion();
        assert!(
            result.is_err(),
            "Expected verification to fail with invalid test data"
        );

        // Verify we get a Rekor error (not some other error type)
        match result {
            Err(WSError::RekorError(_)) => {} // Expected
            Err(e) => panic!("Expected RekorError, got: {:?}", e),
            Ok(_) => panic!("Expected verification to fail"),
        }
    }

    #[test]
    fn test_get_identity_no_certs() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let result = sig.get_identity();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::CertificateError(_)));
    }

    #[test]
    fn test_get_issuer_no_certs() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let result = sig.get_issuer();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::CertificateError(_)));
    }

    #[test]
    fn test_large_signature() {
        let mut sig = create_test_signature();
        // Create a large signature (64 bytes, typical for Ed25519)
        sig.signature = vec![0x42; 64];

        let bytes = sig.to_bytes().expect("Serialization failed");
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized.signature.len(), 64);
        assert_eq!(deserialized.signature, sig.signature);
    }

    #[test]
    fn test_verify_cert_chain_rejects_too_deep() {
        // A 100-cert synthetic chain must be rejected before any x509 parsing.
        // This exercises the MAX_CHAIN_DEPTH guard in verify_cert_chain.
        let mut sig = create_test_signature();
        sig.cert_chain = (0..100)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\nfake-cert-{}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let result = sig.verify_cert_chain();
        match result {
            Err(WSError::ChainTooDeep(max)) => assert_eq!(max, MAX_CHAIN_DEPTH),
            Err(other) => panic!("expected ChainTooDeep, got {:?}", other),
            Ok(_) => panic!("expected ChainTooDeep, got Ok"),
        }
    }

    #[test]
    fn test_verify_cert_chain_at_max_depth_proceeds_to_parser() {
        // A chain of MAX_CHAIN_DEPTH bogus PEMs must NOT be rejected by the
        // depth check; it should fall through to PEM/X.509 parsing and fail
        // there. This proves the bound is at MAX_CHAIN_DEPTH+1, not below.
        let mut sig = create_test_signature();
        sig.cert_chain = (0..MAX_CHAIN_DEPTH)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\nfake-cert-{}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let result = sig.verify_cert_chain();
        // Must not be rejected by depth guard
        assert!(!matches!(result, Err(WSError::ChainTooDeep(_))));
        // But it must still fail (these aren't real Fulcio certs)
        assert!(result.is_err());
    }

    #[test]
    fn test_large_module_hash() {
        let mut sig = create_test_signature();
        // Create a SHA-256 hash (32 bytes)
        sig.module_hash = vec![0xFF; 32];

        let bytes = sig.to_bytes().expect("Serialization failed");
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized.module_hash.len(), 32);
        assert_eq!(deserialized.module_hash, sig.module_hash);
    }

    // -----------------------------------------------------------------
    // Artifact-binding tests for issue #135
    //
    // These tests reproduce the class of tampering the original verifier
    // accepted (signature blob present and well-formed, but the artifact
    // bytes don't match what the cert holder actually signed). Each test
    // builds a real cert with a real ECDSA P-256 keypair, signs a real
    // module, then mutates one piece of the bundle and asserts rejection.
    // -----------------------------------------------------------------

    /// Test fixture: a real WASM module + a KeylessSignature whose cert,
    /// signature, and module_hash all consistently bind to that module.
    /// Calling [`verify_artifact_binding`] on `(signed_module, keyless_sig)`
    /// must succeed; tamper any one piece and it must fail.
    struct ArtifactBindingFixture {
        signed_module: crate::Module,
        keyless_sig: KeylessSignature,
        /// A second, independently-generated cert chain (with a different
        /// public key) for the "swap the cert" tamper test.
        other_cert_pem: String,
    }

    fn build_artifact_binding_fixture() -> ArtifactBindingFixture {
        use crate::wasm_module::{Module, Section, StandardSection, SectionId};
        use ecdsa::signature::DigestSigner;
        use p256::pkcs8::DecodePrivateKey;

        // 1. Build a realistic-enough module: WASM magic + version, plus a
        // standard section so the hash covers more than just the header.
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(
                    SectionId::Type,
                    vec![0x01, 0x60, 0x00, 0x00],
                )),
                Section::Standard(StandardSection::new(
                    SectionId::Function,
                    vec![0x01, 0x00],
                )),
                Section::Standard(StandardSection::new(
                    SectionId::Code,
                    vec![0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b],
                )),
            ],
        };

        // 2. Generate an ECDSA P-256 keypair via rcgen, then re-import the
        // PKCS#8 PEM into p256 so we can both (a) mint a real cert that
        // embeds the public key and (b) sign the module hash with the
        // matching private key. Going rcgen→p256 avoids hand-rolling
        // PKCS#8 export from p256.
        let cert_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("rcgen keypair generation");
        let signing_key_pem = cert_keypair.serialize_pem();
        let secret = p256::SecretKey::from_pkcs8_pem(&signing_key_pem)
            .expect("p256 import of rcgen PKCS8 PEM");
        let signing_key = ecdsa::SigningKey::<p256::NistP256>::from(&secret);

        let params = rcgen::CertificateParams::new(vec!["fixture.local".to_string()])
            .expect("cert params");
        let cert = params.self_signed(&cert_keypair).expect("self-signed cert");
        let cert_pem = cert.pem();

        // 3. Sign the module hash exactly the way `KeylessSigner::sign_module` does.
        let mut module_bytes = Vec::new();
        module
            .clone()
            .serialize(&mut module_bytes)
            .expect("module serialize");

        let mut hasher = Sha256::new();
        hasher.update(&module_bytes);
        let signature: p256::ecdsa::Signature = signing_key.sign_digest(hasher.clone());
        let module_hash = hasher.finalize().to_vec();

        // 4. Build the KeylessSignature blob and embed it. The Rekor entry
        // is fixture data — `verify_artifact_binding` does not consult it.
        let rekor_entry = RekorEntry {
            uuid: "fixture-rekor-uuid".to_string(),
            log_index: 1,
            body: String::new(),
            log_id: "fixture-log-id".to_string(),
            inclusion_proof: vec![],
            signed_entry_timestamp: String::new(),
            integrated_time: "2026-01-01T00:00:00Z".to_string(),
        };
        let keyless_sig = KeylessSignature::new(
            signature.to_bytes().to_vec(),
            vec![cert_pem.clone()],
            rekor_entry,
            module_hash,
        );

        let sig_blob = keyless_sig.to_bytes().expect("keyless sig serialize");
        let signed_module = module.attach_signature(&sig_blob).expect("attach signature");

        // 5. Mint an unrelated cert with a different keypair for the
        // cert-substitution test.
        let other_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("other keypair");
        let other_params = rcgen::CertificateParams::new(vec!["other.local".to_string()])
            .expect("other params");
        let other_cert = other_params
            .self_signed(&other_keypair)
            .expect("other self-signed");

        ArtifactBindingFixture {
            signed_module,
            keyless_sig,
            other_cert_pem: other_cert.pem(),
        }
    }

    #[test]
    fn test_verify_artifact_binding_accepts_genuine_signed_module() {
        let fx = build_artifact_binding_fixture();
        fx.keyless_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect("genuine signed module must verify");
    }

    /// Reproduces issue #135 exactly: flip a byte inside the signed
    /// payload (not in the signature section), keep the signature blob
    /// intact, assert verification rejects.
    #[test]
    fn test_verify_artifact_binding_rejects_byte_flipped_module() {
        use crate::wasm_module::{Section, SectionLike, StandardSection};

        let fx = build_artifact_binding_fixture();

        // Tamper a byte inside the Code section's payload — well outside
        // the signature custom section, so the signature blob still
        // parses and the cert/Rekor checks would still succeed. We
        // rebuild the section (rather than mutating in place) because
        // `StandardSection`'s fields are private.
        let tampered_sections: Vec<Section> = fx
            .signed_module
            .sections
            .iter()
            .map(|s| match s {
                Section::Standard(std_sec) if std_sec.id() == crate::SectionId::Code => {
                    let mut payload = std_sec.payload().to_vec();
                    assert!(!payload.is_empty(), "Code section has bytes");
                    payload[0] ^= 0xFF;
                    Section::Standard(StandardSection::new(std_sec.id(), payload))
                }
                other => other.clone(),
            })
            .collect();
        let tampered = crate::Module {
            header: fx.signed_module.header,
            sections: tampered_sections,
        };

        let err = fx
            .keyless_sig
            .verify_artifact_binding(&tampered)
            .expect_err("tampered module must be rejected");
        assert!(
            matches!(err, WSError::VerificationFailed),
            "expected VerificationFailed, got: {:?}",
            err
        );
    }

    /// Tampering the signature blob (not the artifact) must also be
    /// rejected — proves the ECDSA verify leg fires even when the hash
    /// check would pass.
    #[test]
    fn test_verify_artifact_binding_rejects_corrupted_signature() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        // Flip the high bit of the first signature byte — keeps the
        // length valid (so `Signature::from_slice` succeeds) but breaks
        // the cryptographic check.
        tampered_sig.signature[0] ^= 0x80;

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("corrupted signature must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Pre-image attack: keep the real signature, swap the stored
    /// `module_hash` to whatever the attacker wants the verifier to
    /// recompute over. The hash check passes (we tampered the field to
    /// match), but the ECDSA verify must still reject — because
    /// `signature` was made over the genuine hash, not the substituted
    /// one. This protects against an attacker who can recompute hashes
    /// but not forge ECDSA signatures.
    #[test]
    fn test_verify_artifact_binding_rejects_substituted_module_hash() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        tampered_sig.module_hash = vec![0xAA; 32];

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("hash substitution must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Replace the leaf cert with an unrelated valid cert (different
    /// keypair). The hash check passes (artifact unchanged), but ECDSA
    /// verify under the new public key must fail.
    #[test]
    fn test_verify_artifact_binding_rejects_substituted_cert() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        tampered_sig.cert_chain = vec![fx.other_cert_pem.clone()];

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("cert substitution must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// If the module has no signature section at all,
    /// `verify_artifact_binding` must surface that as `NoSignatures`
    /// rather than silently passing or returning a confusing error.
    #[test]
    fn test_verify_artifact_binding_rejects_module_without_signature_section() {
        let fx = build_artifact_binding_fixture();
        let (unsigned_module, _) = fx
            .signed_module
            .clone()
            .detach_signature()
            .expect("fixture is signed");

        let err = fx
            .keyless_sig
            .verify_artifact_binding(&unsigned_module)
            .expect_err("unsigned module must be rejected");
        assert!(
            matches!(err, WSError::NoSignatures),
            "expected NoSignatures, got: {:?}",
            err
        );
    }

    /// Empty cert chain must be rejected (defense in depth — the chain
    /// check in `verify()` already catches this, but the binding method
    /// is a public API and must fail-closed independently).
    #[test]
    fn test_verify_artifact_binding_rejects_empty_cert_chain() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        tampered_sig.cert_chain.clear();

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("empty cert chain must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }
}
