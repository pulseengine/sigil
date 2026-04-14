//! Signed Certificate Timestamp (SCT) monitoring (Phase 4.2).
//!
//! Monitors Certificate Transparency logs for certificate mis-issuance.
//! SCTs prove a certificate was submitted to a CT log before issuance,
//! enabling detection of rogue CA certificates.

#![forbid(unsafe_code)]

use crate::error::WSError;
use serde::{Deserialize, Serialize};

// ── Hash & Signature Algorithm Enums ──────────────────────────────────

/// Hash algorithm used in an SCT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256 (the only algorithm currently used in CT).
    Sha256,
}

/// Signature algorithm used in an SCT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ECDSA (typically P-256), the most common CT log algorithm.
    Ecdsa,
    /// Ed25519, used by some newer CT logs.
    Ed25519,
}

// ── Core Data Types ───────────────────────────────────────────────────

/// A parsed Signed Certificate Timestamp.
///
/// An SCT is a promise from a Certificate Transparency log that a given
/// certificate will be included in the log within a maximum merge delay.
/// The CT log signs the SCT with its private key so that relying parties
/// can verify it against the log's well-known public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SctEntry {
    /// SHA-256 hash of the CT log's DER-encoded public key.
    pub log_id: [u8; 32],

    /// Timestamp in milliseconds since the Unix epoch.
    pub timestamp: u64,

    /// SCT extensions (usually empty per RFC 6962).
    pub extensions: Vec<u8>,

    /// The CT log's digital signature over the SCT data.
    pub signature: Vec<u8>,

    /// Hash algorithm used to produce the signature.
    pub hash_algorithm: HashAlgorithm,

    /// Signature algorithm used by the CT log.
    pub signature_algorithm: SignatureAlgorithm,
}

/// A well-known, trusted Certificate Transparency log.
///
/// CT log operators publish their public keys so that SCT signatures can
/// be verified offline. This struct captures the metadata needed for that
/// verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedCtLog {
    /// SHA-256 of the log's DER-encoded SubjectPublicKeyInfo.
    pub log_id: [u8; 32],

    /// Raw DER-encoded public key bytes.
    pub public_key: Vec<u8>,

    /// Human-readable description (e.g. "Google Argon 2024").
    pub description: String,

    /// Log submission endpoint URL.
    pub url: String,
}

/// Result of verifying a single SCT against a trusted CT log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SctVerification {
    /// The log that issued this SCT.
    pub log_id: [u8; 32],

    /// Human-readable log description.
    pub log_description: String,

    /// SCT timestamp (milliseconds since epoch).
    pub timestamp: u64,

    /// Whether the SCT signature was valid.
    pub valid: bool,
}

/// Result of monitoring a certificate for unexpected issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SctMonitorResult {
    /// The domain the certificate was issued for.
    pub domain: String,

    /// Number of SCTs found in or alongside the certificate.
    pub sct_count: usize,

    /// Whether every SCT was valid.
    pub all_valid: bool,

    /// `true` if the certificate covers a monitored domain but was not
    /// requested by the domain owner — potential mis-issuance.
    pub unexpected: bool,
}

// ── Default Trusted CT Logs ───────────────────────────────────────────

/// Returns PLACEHOLDER CT log entries for development/testing only.
///
/// # Security Warning
///
/// These entries contain **truncated placeholder public keys** (ending in
/// 0xdeadbeef, 0xcafebabe, 0xfeedface) and MUST NOT be used for production
/// SCT verification. Replace with real CT log keys from the Chrome CT log
/// list or Apple's CT policy before deploying.
///
/// Additionally, `verify_sct()` does not yet perform cryptographic signature
/// verification — see the warning in that function.
pub fn default_trusted_logs() -> Vec<TrustedCtLog> {
    log::warn!(
        "Using placeholder CT log keys — these are NOT real public keys. \
         SCT verification results are meaningless until real keys are configured."
    );
    vec![
        TrustedCtLog {
            log_id: [
                0xa4, 0xb9, 0x09, 0x90, 0xb4, 0x18, 0x58, 0x14,
                0x87, 0xbb, 0x13, 0xa2, 0xcc, 0x67, 0x70, 0x0a,
                0x3c, 0x35, 0x98, 0x04, 0xf9, 0x1b, 0xdf, 0xb8,
                0xe3, 0x77, 0xcd, 0x0e, 0xc8, 0x0d, 0xdc, 0x10,
            ],
            public_key: vec![
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                0x42, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
            ],
            description: "Google Argon 2025".to_string(),
            url: "https://ct.googleapis.com/logs/argon2025/".to_string(),
        },
        TrustedCtLog {
            log_id: [
                0x63, 0xf2, 0xdb, 0xcd, 0xe8, 0x3b, 0xcc, 0x2c,
                0xcf, 0x0b, 0x72, 0x84, 0x27, 0x57, 0x6b, 0x33,
                0xa4, 0x8d, 0x61, 0x77, 0x8f, 0xbd, 0x75, 0xa6,
                0x38, 0xb1, 0xc7, 0x68, 0x54, 0x4b, 0xd8, 0x8d,
            ],
            public_key: vec![
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                0x42, 0x00, 0x04, 0xca, 0xfe, 0xba, 0xbe,
            ],
            description: "Cloudflare Nimbus 2025".to_string(),
            url: "https://ct.cloudflare.com/logs/nimbus2025/".to_string(),
        },
        TrustedCtLog {
            log_id: [
                0x56, 0x14, 0x06, 0x9a, 0x2f, 0xd7, 0xc2, 0xec,
                0xd3, 0xf5, 0xe1, 0xbd, 0x44, 0xb2, 0x3e, 0xc7,
                0x46, 0x76, 0xb9, 0xbc, 0x99, 0x11, 0x5c, 0xc0,
                0xef, 0x94, 0x98, 0x55, 0xd6, 0x89, 0xd0, 0xdd,
            ],
            public_key: vec![
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                0x42, 0x00, 0x04, 0xfe, 0xed, 0xfa, 0xce,
            ],
            description: "DigiCert Yeti 2025".to_string(),
            url: "https://yeti2025.ct.digicert.com/log/".to_string(),
        },
    ]
}

// ── SCT Verifier ──────────────────────────────────────────────────────

/// Verifies Signed Certificate Timestamps against known CT log public keys.
///
/// The verifier is initialised with a set of [`TrustedCtLog`] entries and
/// can then check individual SCTs or scan a certificate for embedded SCTs.
pub struct SctVerifier {
    trusted_logs: Vec<TrustedCtLog>,
}

impl SctVerifier {
    /// Create a new verifier with the given set of trusted logs.
    pub fn new(trusted_logs: Vec<TrustedCtLog>) -> Self {
        Self { trusted_logs }
    }

    /// Look up a trusted log by its 32-byte log ID.
    pub fn find_log(&self, log_id: &[u8; 32]) -> Option<&TrustedCtLog> {
        self.trusted_logs.iter().find(|l| &l.log_id == log_id)
    }

    /// Verify a single SCT against the certificate's DER encoding.
    ///
    /// Returns [`SctVerification`] indicating whether the SCT was issued
    /// by a known log and whether the signature is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the SCT references an unknown log.
    pub fn verify_sct(
        &self,
        sct: &SctEntry,
        cert_der: &[u8],
    ) -> Result<SctVerification, WSError> {
        let log = self.find_log(&sct.log_id).ok_or_else(|| {
            WSError::CertificateError(format!(
                "Unknown CT log ID: {}",
                hex::encode(sct.log_id)
            ))
        })?;

        // Build the data that should have been signed by the CT log:
        //   version (1) || signature_type (1) || timestamp (8) ||
        //   entry_type (2) || cert_length (3) || cert || extensions_length (2) || extensions
        let mut signed_data = Vec::new();
        // SCT v1
        signed_data.push(0x00);
        // certificate_timestamp
        signed_data.push(0x00);
        // timestamp
        signed_data.extend_from_slice(&sct.timestamp.to_be_bytes());
        // entry_type: x509_entry = 0x0000
        signed_data.extend_from_slice(&[0x00, 0x00]);
        // certificate length (3 bytes, big-endian)
        let cert_len = cert_der.len() as u32;
        signed_data.push(((cert_len >> 16) & 0xff) as u8);
        signed_data.push(((cert_len >> 8) & 0xff) as u8);
        signed_data.push((cert_len & 0xff) as u8);
        // certificate
        signed_data.extend_from_slice(cert_der);
        // extensions length (2 bytes, big-endian)
        let ext_len = sct.extensions.len() as u16;
        signed_data.extend_from_slice(&ext_len.to_be_bytes());
        // extensions
        signed_data.extend_from_slice(&sct.extensions);

        // SECURITY WARNING: Full cryptographic SCT verification is not yet
        // implemented. This performs only structural validation — it does NOT
        // verify the ECDSA/Ed25519 signature. SCT results should be treated
        // as ADVISORY ONLY until crypto verification is added.
        //
        // TODO: Implement actual signature verification:
        //   - ECDSA P-256: parse log.public_key as SPKI, verify with p256 crate
        //   - Ed25519: parse log.public_key, verify with ed25519-compact
        //
        // Without this, a forged SCT with a plausible-length signature will
        // pass validation. Do NOT use SCT results for security decisions.
        log::warn!(
            "SCT verification is structural only — cryptographic signature \
             verification is not yet implemented. Do not rely on SCT results \
             for security decisions."
        );
        let valid = !sct.signature.is_empty()
            && !log.public_key.is_empty()
            && sct.signature.len() >= 8;

        Ok(SctVerification {
            log_id: sct.log_id,
            log_description: log.description.clone(),
            timestamp: sct.timestamp,
            valid,
        })
    }

    /// Scan a DER-encoded certificate for embedded SCTs and verify each.
    ///
    /// Embedded SCTs live in the X.509v3 extension with OID
    /// `1.3.6.1.4.1.11129.2.4.2`.  This method extracts them and calls
    /// [`verify_sct`](Self::verify_sct) for every SCT found.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate cannot be parsed.
    pub fn verify_embedded_scts(
        &self,
        cert_der: &[u8],
    ) -> Result<Vec<SctVerification>, WSError> {
        // Parse the certificate to look for the SCT list extension.
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
            .map_err(|e| WSError::X509Error(format!("Failed to parse certificate: {:?}", e)))?;

        let mut results = Vec::new();

        // OID for SCT list: 1.3.6.1.4.1.11129.2.4.2
        let sct_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

        for ext in cert.extensions() {
            if ext.oid.to_string() == sct_oid.to_string() {
                // The extension value is a TLS-encoded SignedCertificateTimestampList.
                // Parse individual SCTs from the list.
                let scts = parse_sct_list(ext.value)?;
                for sct in &scts {
                    match self.verify_sct(sct, cert_der) {
                        Ok(v) => results.push(v),
                        Err(_) => {
                            // Unknown log — record as invalid verification.
                            results.push(SctVerification {
                                log_id: sct.log_id,
                                log_description: "Unknown".to_string(),
                                timestamp: sct.timestamp,
                                valid: false,
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

// ── SCT List Parsing ──────────────────────────────────────────────────

/// Parse a TLS-encoded `SignedCertificateTimestampList` (RFC 6962 Section 3.3).
///
/// The format is:
///   - 2-byte total list length
///   - For each SCT:
///     - 2-byte SCT length
///     - SCT data (version, log_id, timestamp, extensions, signature)
pub fn parse_sct_list(data: &[u8]) -> Result<Vec<SctEntry>, WSError> {
    if data.len() < 2 {
        return Err(WSError::CertificateError(
            "SCT list too short".to_string(),
        ));
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(WSError::CertificateError(
            "SCT list length exceeds available data".to_string(),
        ));
    }

    let mut entries = Vec::new();
    let mut offset = 2usize;
    let end = 2 + list_len;

    while offset + 2 <= end {
        let sct_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + sct_len > end {
            return Err(WSError::CertificateError(
                "SCT entry length exceeds list boundary".to_string(),
            ));
        }

        let sct_data = &data[offset..offset + sct_len];
        let entry = parse_single_sct(sct_data)?;
        entries.push(entry);
        offset += sct_len;
    }

    Ok(entries)
}

/// Parse a single serialised SCT (RFC 6962 Section 3.2).
///
/// Layout:
///   - 1 byte  version (0x00 = v1)
///   - 32 bytes log_id
///   - 8 bytes  timestamp
///   - 2 bytes  extensions length
///   - N bytes  extensions
///   - 1 byte   hash algorithm
///   - 1 byte   signature algorithm
///   - 2 bytes  signature length
///   - M bytes  signature
fn parse_single_sct(data: &[u8]) -> Result<SctEntry, WSError> {
    // Minimum: 1 + 32 + 8 + 2 + 1 + 1 + 2 = 47 bytes (no extensions, no sig body)
    if data.len() < 47 {
        return Err(WSError::CertificateError(
            "SCT entry too short".to_string(),
        ));
    }

    let version = data[0];
    if version != 0x00 {
        return Err(WSError::CertificateError(format!(
            "Unsupported SCT version: {}",
            version
        )));
    }

    let mut log_id = [0u8; 32];
    log_id.copy_from_slice(&data[1..33]);

    let timestamp = u64::from_be_bytes([
        data[33], data[34], data[35], data[36],
        data[37], data[38], data[39], data[40],
    ]);

    let ext_len = u16::from_be_bytes([data[41], data[42]]) as usize;

    let ext_end = 43 + ext_len;
    if data.len() < ext_end + 4 {
        return Err(WSError::CertificateError(
            "SCT entry truncated after extensions".to_string(),
        ));
    }

    let extensions = data[43..ext_end].to_vec();

    let hash_alg_byte = data[ext_end];
    let sig_alg_byte = data[ext_end + 1];

    let hash_algorithm = match hash_alg_byte {
        4 => HashAlgorithm::Sha256, // RFC 5246 HashAlgorithm sha256 = 4
        _ => {
            return Err(WSError::CertificateError(format!(
                "Unsupported hash algorithm: {}",
                hash_alg_byte
            )));
        }
    };

    let signature_algorithm = match sig_alg_byte {
        3 => SignatureAlgorithm::Ecdsa,  // RFC 5246 SignatureAlgorithm ecdsa = 3
        7 => SignatureAlgorithm::Ed25519, // Ed25519 (draft-josefsson-eddsa-ed25519)
        _ => {
            return Err(WSError::CertificateError(format!(
                "Unsupported signature algorithm: {}",
                sig_alg_byte
            )));
        }
    };

    let sig_len = u16::from_be_bytes([data[ext_end + 2], data[ext_end + 3]]) as usize;
    let sig_start = ext_end + 4;

    if data.len() < sig_start + sig_len {
        return Err(WSError::CertificateError(
            "SCT signature truncated".to_string(),
        ));
    }

    let signature = data[sig_start..sig_start + sig_len].to_vec();

    Ok(SctEntry {
        log_id,
        timestamp,
        extensions,
        signature,
        hash_algorithm,
        signature_algorithm,
    })
}

// ── Serialisation helpers ─────────────────────────────────────────────

/// Serialise an [`SctEntry`] into the TLS wire format (RFC 6962 Section 3.2).
pub fn serialize_sct(sct: &SctEntry) -> Vec<u8> {
    let mut out = Vec::new();

    // version
    out.push(0x00);
    // log_id
    out.extend_from_slice(&sct.log_id);
    // timestamp
    out.extend_from_slice(&sct.timestamp.to_be_bytes());
    // extensions length + extensions
    let ext_len = sct.extensions.len() as u16;
    out.extend_from_slice(&ext_len.to_be_bytes());
    out.extend_from_slice(&sct.extensions);
    // hash algorithm
    let hash_byte: u8 = match sct.hash_algorithm {
        HashAlgorithm::Sha256 => 4,
    };
    out.push(hash_byte);
    // signature algorithm
    let sig_alg_byte: u8 = match sct.signature_algorithm {
        SignatureAlgorithm::Ecdsa => 3,
        SignatureAlgorithm::Ed25519 => 7,
    };
    out.push(sig_alg_byte);
    // signature length + signature
    let sig_len = sct.signature.len() as u16;
    out.extend_from_slice(&sig_len.to_be_bytes());
    out.extend_from_slice(&sct.signature);

    out
}

/// Serialise a list of [`SctEntry`] values into TLS `SignedCertificateTimestampList` format.
pub fn serialize_sct_list(scts: &[SctEntry]) -> Vec<u8> {
    let mut inner = Vec::new();
    for sct in scts {
        let encoded = serialize_sct(sct);
        let len = encoded.len() as u16;
        inner.extend_from_slice(&len.to_be_bytes());
        inner.extend_from_slice(&encoded);
    }

    let mut out = Vec::new();
    let list_len = inner.len() as u16;
    out.extend_from_slice(&list_len.to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

// ── SCT Monitor ───────────────────────────────────────────────────────

/// Monitors Certificate Transparency logs for unexpected certificate issuance.
///
/// The monitor is configured with a list of domains that the operator owns.
/// When a certificate is checked, the monitor determines whether it covers
/// one of the expected domains and whether all embedded SCTs are valid.
pub struct SctMonitor {
    expected_domains: Vec<String>,
    verifier: SctVerifier,
}

impl SctMonitor {
    /// Create a new monitor for the given domains.
    ///
    /// Uses the [`default_trusted_logs`] set for SCT verification.
    pub fn new(expected_domains: Vec<String>) -> Self {
        Self {
            expected_domains,
            verifier: SctVerifier::new(default_trusted_logs()),
        }
    }

    /// Create a monitor with custom trusted logs.
    pub fn with_logs(expected_domains: Vec<String>, trusted_logs: Vec<TrustedCtLog>) -> Self {
        Self {
            expected_domains,
            verifier: SctVerifier::new(trusted_logs),
        }
    }

    /// Check a DER-encoded certificate for unexpected issuance.
    ///
    /// Extracts the Subject Alternative Names from the certificate, checks
    /// whether any match the monitored domains, verifies embedded SCTs,
    /// and flags unexpected certificates.
    pub fn check_certificate(
        &self,
        cert_der: &[u8],
    ) -> Result<SctMonitorResult, WSError> {
        // Parse the certificate to extract SANs.
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
            .map_err(|e| WSError::X509Error(format!("Failed to parse certificate: {:?}", e)))?;

        // Extract DNS names from Subject Alternative Name extension.
        let mut domains: Vec<String> = Vec::new();
        for ext in cert.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        domains.push(dns.to_string());
                    }
                }
            }
        }

        // Determine primary domain for reporting.
        let domain = domains.first().cloned().unwrap_or_else(|| {
            cert.subject().to_string()
        });

        // Check whether this certificate is for one of our monitored domains
        // but was *not* expected — indicating potential mis-issuance.
        let matches_monitored = domains.iter().any(|d| {
            self.expected_domains.iter().any(|exp| {
                d == exp || d.ends_with(&format!(".{}", exp))
            })
        });

        // If it matches a monitored domain, flag as unexpected (the caller
        // would cross-reference against their own issuance records).
        let unexpected = matches_monitored;

        // Verify embedded SCTs.
        let verifications = self.verifier.verify_embedded_scts(cert_der)?;
        let sct_count = verifications.len();
        let all_valid = !verifications.is_empty() && verifications.iter().all(|v| v.valid);

        Ok(SctMonitorResult {
            domain,
            sct_count,
            all_valid,
            unexpected,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal SCT entry for testing.
    fn make_test_sct(log_id: [u8; 32], timestamp: u64) -> SctEntry {
        SctEntry {
            log_id,
            timestamp,
            extensions: Vec::new(),
            signature: vec![0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x02],
            hash_algorithm: HashAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::Ecdsa,
        }
    }

    /// Helper: return the log_id of the first default trusted log.
    fn first_default_log_id() -> [u8; 32] {
        default_trusted_logs()[0].log_id
    }

    // ── 1. SCT entry construction ─────────────────────────────────────

    #[test]
    fn test_sct_entry_fields() {
        let log_id = [0xaa; 32];
        let sct = make_test_sct(log_id, 1_700_000_000_000);

        assert_eq!(sct.log_id, log_id);
        assert_eq!(sct.timestamp, 1_700_000_000_000);
        assert!(sct.extensions.is_empty());
        assert_eq!(sct.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(sct.signature_algorithm, SignatureAlgorithm::Ecdsa);
    }

    // ── 2. Serialisation round-trip ───────────────────────────────────

    #[test]
    fn test_sct_serialize_roundtrip() {
        let sct = make_test_sct([0x11; 32], 1_600_000_000_000);
        let bytes = serialize_sct(&sct);
        let parsed = parse_single_sct(&bytes).expect("round-trip parse should succeed");

        assert_eq!(parsed.log_id, sct.log_id);
        assert_eq!(parsed.timestamp, sct.timestamp);
        assert_eq!(parsed.extensions, sct.extensions);
        assert_eq!(parsed.signature, sct.signature);
        assert_eq!(parsed.hash_algorithm, sct.hash_algorithm);
        assert_eq!(parsed.signature_algorithm, sct.signature_algorithm);
    }

    // ── 3. SCT list serialisation round-trip ──────────────────────────

    #[test]
    fn test_sct_list_roundtrip() {
        let scts = vec![
            make_test_sct([0x01; 32], 100),
            make_test_sct([0x02; 32], 200),
        ];
        let encoded = serialize_sct_list(&scts);
        let decoded = parse_sct_list(&encoded).expect("list round-trip should succeed");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].log_id, [0x01; 32]);
        assert_eq!(decoded[1].log_id, [0x02; 32]);
        assert_eq!(decoded[0].timestamp, 100);
        assert_eq!(decoded[1].timestamp, 200);
    }

    // ── 4. Verification with known log ────────────────────────────────

    #[test]
    fn test_verify_sct_known_log() {
        let log_id = first_default_log_id();
        let sct = make_test_sct(log_id, 1_700_000_000_000);

        let verifier = SctVerifier::new(default_trusted_logs());
        let result = verifier
            .verify_sct(&sct, b"fake-cert-der")
            .expect("known log should not error");

        assert_eq!(result.log_id, log_id);
        assert!(result.valid);
        assert_eq!(result.timestamp, 1_700_000_000_000);
        assert!(!result.log_description.is_empty());
    }

    // ── 5. Verification with unknown log ──────────────────────────────

    #[test]
    fn test_verify_sct_unknown_log() {
        let sct = make_test_sct([0xff; 32], 1_700_000_000_000);

        let verifier = SctVerifier::new(default_trusted_logs());
        let result = verifier.verify_sct(&sct, b"fake-cert-der");

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown CT log"));
    }

    // ── 6. Trusted log lookup by ID ───────────────────────────────────

    #[test]
    fn test_find_log_by_id() {
        let logs = default_trusted_logs();
        let verifier = SctVerifier::new(logs.clone());

        // Each default log should be found by its ID.
        for log in &logs {
            let found = verifier.find_log(&log.log_id);
            assert!(found.is_some(), "log '{}' should be found", log.description);
            assert_eq!(found.unwrap().description, log.description);
        }

        // Unknown ID should return None.
        assert!(verifier.find_log(&[0x00; 32]).is_none());
    }

    // ── 7. Default trusted logs are populated ─────────────────────────

    #[test]
    fn test_default_trusted_logs() {
        let logs = default_trusted_logs();
        assert!(logs.len() >= 3, "should have at least 3 default logs");

        for log in &logs {
            assert!(!log.description.is_empty());
            assert!(!log.url.is_empty());
            assert!(!log.public_key.is_empty());
            assert_ne!(log.log_id, [0u8; 32]);
        }
    }

    // ── 8. Monitor configuration ──────────────────────────────────────

    #[test]
    fn test_monitor_configuration() {
        let domains = vec!["example.com".to_string(), "test.org".to_string()];
        let monitor = SctMonitor::new(domains);

        assert_eq!(monitor.expected_domains.len(), 2);
        assert_eq!(monitor.expected_domains[0], "example.com");
        assert_eq!(monitor.expected_domains[1], "test.org");
    }

    // ── 9. SctVerification result types ───────────────────────────────

    #[test]
    fn test_sct_verification_result() {
        let v = SctVerification {
            log_id: [0xab; 32],
            log_description: "Test Log".to_string(),
            timestamp: 42,
            valid: true,
        };
        assert!(v.valid);
        assert_eq!(v.log_description, "Test Log");

        let v_invalid = SctVerification {
            valid: false,
            ..v.clone()
        };
        assert!(!v_invalid.valid);
    }

    // ── 10. SctMonitorResult types ────────────────────────────────────

    #[test]
    fn test_sct_monitor_result_fields() {
        let r = SctMonitorResult {
            domain: "example.com".to_string(),
            sct_count: 3,
            all_valid: true,
            unexpected: false,
        };
        assert_eq!(r.domain, "example.com");
        assert_eq!(r.sct_count, 3);
        assert!(r.all_valid);
        assert!(!r.unexpected);
    }

    // ── 11. SCT entry JSON round-trip via serde ───────────────────────

    #[test]
    fn test_sct_entry_serde_roundtrip() {
        let sct = make_test_sct([0x99; 32], 1_650_000_000_000);
        let json = serde_json::to_string(&sct).expect("serialise");
        let parsed: SctEntry = serde_json::from_str(&json).expect("deserialise");

        assert_eq!(parsed.log_id, sct.log_id);
        assert_eq!(parsed.timestamp, sct.timestamp);
        assert_eq!(parsed.signature, sct.signature);

        // Verify camelCase serialisation is used.
        assert!(json.contains("logId"), "field should be camelCase: {}", json);
        assert!(json.contains("hashAlgorithm"), "field should be camelCase: {}", json);
        assert!(json.contains("signatureAlgorithm"), "field should be camelCase: {}", json);
    }

    // ── 12. Parse truncated SCT list ──────────────────────────────────

    #[test]
    fn test_parse_sct_list_too_short() {
        let result = parse_sct_list(&[0x00]);
        assert!(result.is_err());
    }

    // ── 13. Parse SCT list with length mismatch ───────────────────────

    #[test]
    fn test_parse_sct_list_length_mismatch() {
        // Claim list is 255 bytes but only provide 2 header bytes.
        let result = parse_sct_list(&[0x00, 0xFF]);
        assert!(result.is_err());
    }

    // ── 14. Empty SCT signature is invalid ────────────────────────────

    #[test]
    fn test_empty_signature_is_invalid() {
        let log_id = first_default_log_id();
        let mut sct = make_test_sct(log_id, 1_700_000_000_000);
        sct.signature = Vec::new();

        let verifier = SctVerifier::new(default_trusted_logs());
        let result = verifier
            .verify_sct(&sct, b"cert")
            .expect("should not error for known log");

        assert!(!result.valid, "empty signature should be invalid");
    }

    // ── 15. Ed25519 signature algorithm round-trip ────────────────────

    #[test]
    fn test_ed25519_sct_roundtrip() {
        let mut sct = make_test_sct([0x77; 32], 500);
        sct.signature_algorithm = SignatureAlgorithm::Ed25519;

        let bytes = serialize_sct(&sct);
        let parsed = parse_single_sct(&bytes).expect("parse Ed25519 SCT");

        assert_eq!(parsed.signature_algorithm, SignatureAlgorithm::Ed25519);
    }

    // ── 16. Monitor with custom logs ──────────────────────────────────

    #[test]
    fn test_monitor_with_custom_logs() {
        let log = TrustedCtLog {
            log_id: [0xcc; 32],
            public_key: vec![0x01, 0x02, 0x03],
            description: "Custom Log".to_string(),
            url: "https://custom.example.com/ct/".to_string(),
        };
        let monitor = SctMonitor::with_logs(
            vec!["mysite.com".to_string()],
            vec![log.clone()],
        );

        assert_eq!(monitor.expected_domains, vec!["mysite.com"]);
        let found = monitor.verifier.find_log(&[0xcc; 32]);
        assert!(found.is_some());
        assert_eq!(found.unwrap().description, "Custom Log");
    }

    // ── 17. TrustedCtLog serde round-trip ─────────────────────────────

    #[test]
    fn test_trusted_ct_log_serde() {
        let log = TrustedCtLog {
            log_id: [0xdd; 32],
            public_key: vec![0xfe, 0xed],
            description: "Serde Test".to_string(),
            url: "https://log.example.com/".to_string(),
        };
        let json = serde_json::to_string(&log).expect("serialise");
        let parsed: TrustedCtLog = serde_json::from_str(&json).expect("deserialise");

        assert_eq!(parsed.log_id, log.log_id);
        assert_eq!(parsed.public_key, log.public_key);
        assert!(json.contains("logId"));
        assert!(json.contains("publicKey"));
    }
}
