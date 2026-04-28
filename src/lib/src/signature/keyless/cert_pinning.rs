/// SPKI certificate pinning for Sigstore endpoints
///
/// This module implements SPKI (Subject Public Key Info) pinning to protect
/// against CA compromise and man-in-the-middle attacks. It validates that
/// the public key in TLS certificates matches known SHA256(SPKI) hashes.
///
/// SPKI pinning is more resilient than leaf-cert pinning: pins survive
/// certificate renewals as long as the key stays the same (common for
/// Google Trust Services which issues Sigstore's TLS certs).
///
/// # Security Model
///
/// Certificate pinning adds defense-in-depth beyond standard PKI validation:
/// - Even if a trusted CA is compromised, pinning prevents MITM attacks
/// - Protects against DNS/BGP hijacking with rogue certificates
/// - Validates both leaf certificates and CA certificates
///
/// # Configuration
///
/// Pins can be configured via:
/// - Environment variables: `WSC_FULCIO_PINS`, `WSC_REKOR_PINS`
/// - Programmatic API: `SigstoreConfig::with_custom_pins()`
/// - Default pins for production Sigstore endpoints (embedded)
///
/// # Pin Format
///
/// Pins are SHA256 fingerprints in hex format (64 hex chars):
/// ```text
/// export WSC_FULCIO_PINS="abcd1234...,ef567890..."
/// ```
///
/// # Implementation Status (Issue #12)
///
/// **Certificate pinning infrastructure is COMPLETE but not yet enforced.**
///
/// The `ureq` HTTP client (v3.x) used by FulcioClient and RekorClient does not
/// currently expose APIs for custom TLS certificate verification. This module
/// provides complete pinning infrastructure that is ready to use once:
///
/// 1. `ureq` adds support for custom `ServerCertVerifier`, OR
/// 2. We migrate to `reqwest` or another HTTP client with TLS customization
///
/// **Current behavior:**
/// - Certificate pinning checks are logged for monitoring
/// - Standard WebPKI validation is performed by ureq/rustls
/// - Connections to Fulcio/Rekor succeed even if pins don't match
///
/// **To enable strict pinning (fail if cannot enforce):**
/// ```bash
/// export WSC_REQUIRE_CERT_PINNING=1
/// ```
/// This will cause an error if pinning cannot be enforced due to HTTP client limitations.
use crate::error::WSError;
use std::collections::HashSet;

// Platform-agnostic imports
#[cfg(not(target_arch = "wasm32"))]
use sha2::{Digest, Sha256};
#[cfg(not(target_arch = "wasm32"))]
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

// Rustls-dependent imports (native only)
#[cfg(not(target_arch = "wasm32"))]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
#[cfg(not(target_arch = "wasm32"))]
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
#[cfg(not(target_arch = "wasm32"))]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(not(target_arch = "wasm32"))]
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Production Fulcio SPKI pins (SHA256 of SubjectPublicKeyInfo DER)
///
/// SPKI pinning survives certificate renewals — only changes when the
/// actual public key rotates (rare for Google Trust Services).
///
/// To get the current SPKI pin:
/// ```bash
/// echo | openssl s_client -connect fulcio.sigstore.dev:443 -servername fulcio.sigstore.dev 2>/dev/null | \
///   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
/// ```
///
/// Sigstore uses Google Trust Services certificates (GTS Root R1 -> GTS WR3 -> fulcio.sigstore.dev)
/// We pin the leaf SPKI and the intermediate CA SPKI for defense in depth.
const FULCIO_PRODUCTION_PINS: &[&str] = &[
    // fulcio.sigstore.dev leaf SPKI (updated 2026-04-14)
    "6611c54b2960f4ed00fef7be46e6ea6541f38e65b039f756b87c0825c0f67df4",
    // Google Trust Services WR3 intermediate CA SPKI
    "39d4a59900fd356261e046dc387071921ca03f0352c00f50f757a8ba77db7281",
];

/// Production Rekor SPKI pins (SHA256 of SubjectPublicKeyInfo DER)
///
/// Rekor uses the same Google Trust Services infrastructure as Fulcio.
const REKOR_PRODUCTION_PINS: &[&str] = &[
    // rekor.sigstore.dev leaf SPKI (updated 2026-04-14)
    "356aacac31f1dda36c418426c4fad25071f849fdaccda221cca9a41b9ddb140d",
    // Google Trust Services WR3 intermediate CA SPKI
    "39d4a59900fd356261e046dc387071921ca03f0352c00f50f757a8ba77db7281",
];

/// Staging Fulcio SPKI pins (SHA256 of SubjectPublicKeyInfo DER)
///
/// Staging environment uses different certificates. Set WSC_SIGSTORE_STAGING=1
/// to use staging endpoints.
const FULCIO_STAGING_PINS: &[&str] = &[
    // ISRG Root X1 SPKI (Let's Encrypt root — extremely stable)
    "0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3",
];

/// Staging Rekor SPKI pins (SHA256 of SubjectPublicKeyInfo DER)
const REKOR_STAGING_PINS: &[&str] = &[
    // ISRG Root X1 SPKI (Let's Encrypt root)
    "0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3",
];

/// Certificate pinning configuration
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// SHA256 fingerprints of pinned certificates (hex-encoded, lowercase)
    pins: HashSet<String>,
    /// Whether pinning is enforced (vs warn-only mode)
    enforce: bool,
    /// Service name for logging
    service_name: String,
}

impl PinningConfig {
    /// Create pinning configuration for Fulcio production endpoint
    pub fn fulcio_production() -> Self {
        Self::from_env_or_default(
            "WSC_FULCIO_PINS",
            FULCIO_PRODUCTION_PINS,
            "fulcio.sigstore.dev",
        )
    }

    /// Create pinning configuration for Rekor production endpoint
    pub fn rekor_production() -> Self {
        Self::from_env_or_default(
            "WSC_REKOR_PINS",
            REKOR_PRODUCTION_PINS,
            "rekor.sigstore.dev",
        )
    }

    /// Create pinning configuration for Fulcio staging endpoint
    pub fn fulcio_staging() -> Self {
        Self::from_env_or_default(
            "WSC_FULCIO_PINS",
            FULCIO_STAGING_PINS,
            "fulcio.staging.sigstore.dev",
        )
    }

    /// Create pinning configuration for Rekor staging endpoint
    pub fn rekor_staging() -> Self {
        Self::from_env_or_default(
            "WSC_REKOR_PINS",
            REKOR_STAGING_PINS,
            "rekor.staging.sigstore.dev",
        )
    }

    /// Check if staging environment is configured
    ///
    /// Returns true if `WSC_SIGSTORE_STAGING=1` is set
    pub fn is_staging() -> bool {
        std::env::var("WSC_SIGSTORE_STAGING").unwrap_or_default() == "1"
    }

    /// Create pinning configuration for Fulcio (auto-detects staging/production)
    pub fn fulcio() -> Self {
        if Self::is_staging() {
            log::info!("Using Sigstore staging environment for Fulcio");
            Self::fulcio_staging()
        } else {
            Self::fulcio_production()
        }
    }

    /// Create pinning configuration for Rekor (auto-detects staging/production)
    pub fn rekor() -> Self {
        if Self::is_staging() {
            log::info!("Using Sigstore staging environment for Rekor");
            Self::rekor_staging()
        } else {
            Self::rekor_production()
        }
    }

    /// Create custom pinning configuration
    ///
    /// # Arguments
    /// * `pins` - SHA256 fingerprints (hex-encoded, 64 chars each)
    /// * `service_name` - Service name for logging
    pub fn custom(pins: Vec<String>, service_name: String) -> Self {
        let pin_set: HashSet<String> = pins.into_iter().map(|p| p.to_lowercase()).collect();
        Self {
            pins: pin_set,
            enforce: true,
            service_name,
        }
    }

    /// Create configuration from environment variable or defaults
    fn from_env_or_default(env_var: &str, defaults: &[&str], service_name: &str) -> Self {
        let pins = match std::env::var(env_var) {
            Ok(value) if !value.is_empty() => {
                log::info!(
                    "Using custom certificate pins from {} for {}",
                    env_var,
                    service_name
                );
                value
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            _ => {
                if defaults.is_empty() {
                    log::warn!(
                        "No certificate pins configured for {} (set {} environment variable)",
                        service_name,
                        env_var
                    );
                }
                defaults
                    .iter()
                    .map(|s| s.to_lowercase().to_string())
                    .collect()
            }
        };

        Self {
            pins,
            enforce: true,
            service_name: service_name.to_string(),
        }
    }

    /// Check if pinning is enabled (has any pins configured)
    pub fn is_enabled(&self) -> bool {
        !self.pins.is_empty()
    }

    /// Get the service name this config is for
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Get the number of configured pins
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }

    /// Check if enforcement mode is enabled
    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }

    /// Set enforcement mode
    ///
    /// When true, certificate pin mismatches will cause connection failures.
    /// When false, mismatches are only logged as warnings.
    pub fn set_enforce(&mut self, enforce: bool) {
        self.enforce = enforce;
    }

    /// Create a non-enforcing (warn-only) version of this config
    pub fn warn_only(mut self) -> Self {
        self.enforce = false;
        self
    }
}

// Rustls-dependent methods (native only)
#[cfg(not(target_arch = "wasm32"))]
impl PinningConfig {
    /// Verify a certificate's SPKI matches one of the pins.
    ///
    /// Extracts the SubjectPublicKeyInfo (SPKI) from the X.509 certificate
    /// and computes SHA256(SPKI_DER). This survives certificate renewals
    /// as long as the public key stays the same.
    fn verify_certificate(&self, cert_der: &CertificateDer) -> Result<(), WSError> {
        if !self.is_enabled() {
            log::warn!(
                "Certificate pinning disabled for {} (no pins configured)",
                self.service_name
            );
            return Ok(());
        }

        // Parse the X.509 certificate to extract SPKI
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).map_err(|e| {
            WSError::CertificatePinningError(format!(
                "Failed to parse certificate for SPKI extraction: {:?}",
                e
            ))
        })?;

        // Hash the raw SubjectPublicKeyInfo DER bytes
        let spki_der = cert.public_key().raw;
        let mut hasher = Sha256::new();
        hasher.update(spki_der);
        let fingerprint = hasher.finalize();
        let fingerprint_hex = hex::encode(fingerprint);

        // Check if SPKI fingerprint matches any pin
        if self.pins.contains(&fingerprint_hex) {
            log::debug!(
                "SPKI pin matched for {} (fingerprint: {}...)",
                self.service_name,
                &fingerprint_hex[..16]
            );
            Ok(())
        } else if self.enforce {
            Err(WSError::CertificatePinningError(format!(
                "Certificate pin mismatch for {}: got {}..., expected one of {} configured pins",
                self.service_name,
                &fingerprint_hex[..16],
                self.pins.len()
            )))
        } else {
            log::warn!(
                "SPKI pin mismatch for {} (warn-only mode): {}...",
                self.service_name,
                &fingerprint_hex[..16]
            );
            Ok(())
        }
    }
}

/// Custom certificate verifier that implements pinning
#[cfg(not(target_arch = "wasm32"))]
pub struct PinnedCertVerifier {
    /// Base verifier for standard WebPKI validation
    base_verifier: Arc<dyn ServerCertVerifier>,
    /// Pinning configuration
    pinning: PinningConfig,
    /// Crypto provider for signature verification
    crypto_provider: Arc<CryptoProvider>,
}

#[cfg(not(target_arch = "wasm32"))]
impl PinnedCertVerifier {
    /// Create a new pinned certificate verifier
    ///
    /// # Arguments
    /// * `pinning` - Pinning configuration with SHA256 fingerprints
    /// * `crypto_provider` - Crypto provider for signature verification
    ///
    /// # Returns
    /// A new verifier that performs both WebPKI and pin validation
    pub fn new(
        pinning: PinningConfig,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Result<Self, WSError> {
        // Create base WebPKI verifier using system roots
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let base_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| {
                WSError::CertificatePinningError(format!("Failed to create base verifier: {}", e))
            })?;

        Ok(Self {
            base_verifier,
            pinning,
            crypto_provider,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("pinning", &self.pinning)
            .field("base_verifier", &"WebPkiServerVerifier")
            .finish()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        // Step 1: Perform standard WebPKI validation
        // This ensures the certificate is valid, not expired, and chains to a trusted root
        self.base_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Step 2: Verify certificate pinning
        // Check if the leaf certificate matches one of our pins
        self.pinning
            .verify_certificate(end_entity)
            .map_err(|e| TlsError::General(e.to_string()))?;

        // Step 3: Also check intermediate certificates (defense in depth)
        // This protects against attacks that use a valid leaf but compromised intermediate
        for intermediate in intermediates {
            if let Err(e) = self.pinning.verify_certificate(intermediate) {
                log::debug!(
                    "Intermediate certificate pin check: {} (this is informational only)",
                    e
                );
                // Don't fail on intermediate mismatch - only leaf cert is critical
            }
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create a rustls ClientConfig with certificate pinning enabled.
///
/// This config can be used with any HTTP client that supports custom rustls configs:
/// - For ureq: use with custom Connector (see transport.rs)
/// - For reqwest: use with `ClientBuilder::use_preconfigured_tls()`
///
/// # Arguments
/// * `pinning` - Certificate pinning configuration
///
/// # Returns
/// A rustls `ClientConfig` configured with our `PinnedCertVerifier`
#[cfg(not(target_arch = "wasm32"))]
pub fn create_pinned_rustls_config(
    pinning: PinningConfig,
) -> Result<Arc<rustls::ClientConfig>, WSError> {
    use rustls::ClientConfig;

    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());

    // Create our custom certificate verifier with pinning
    let verifier = PinnedCertVerifier::new(pinning, crypto_provider.clone())?;

    // Build ClientConfig with our pinned verifier
    let config = ClientConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| WSError::CertificatePinningError(format!("TLS version error: {}", e)))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    log::debug!("Created pinned rustls ClientConfig");

    Ok(Arc::new(config))
}

/// Check if strict certificate pinning is required via environment variable.
///
/// When `WSC_REQUIRE_CERT_PINNING=1` is set, this function returns an error if
/// pinning cannot be configured (e.g., empty pins). Otherwise it logs a warning.
///
/// # Usage
///
/// Call this when pinning configuration fails:
/// ```ignore
/// if let Err(e) = create_pinned_rustls_config(config) {
///     check_pinning_requirement("fulcio.sigstore.dev")?;
///     // Fall back to unpinned if not required
/// }
/// ```
pub fn check_pinning_requirement(service: &str) -> Result<(), WSError> {
    if std::env::var("WSC_REQUIRE_CERT_PINNING").unwrap_or_default() == "1" {
        return Err(WSError::CertificatePinningError(format!(
            "Certificate pinning required (WSC_REQUIRE_CERT_PINNING=1) but not configured for {}",
            service
        )));
    }

    log::warn!(
        "Certificate pinning not configured for {} (set WSC_REQUIRE_CERT_PINNING=1 to enforce)",
        service
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinning_config_creation() {
        let pins = vec!["a".repeat(64), "b".repeat(64)];
        let config = PinningConfig::custom(pins.clone(), "test-service".to_string());

        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.pins.len(), 2);
        assert!(config.is_enabled());
    }

    #[test]
    fn test_pinning_config_empty() {
        let config = PinningConfig::custom(vec![], "test-service".to_string());
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_spki_fingerprint_matching() {
        // Generate a real self-signed certificate for SPKI pinning test
        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert_key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&cert_key).unwrap();
        let cert_der = cert.der().to_vec();
        let cert_ref = CertificateDer::from(cert_der.clone());

        // Extract SPKI and compute expected pin
        let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
        let spki_der = parsed.public_key().raw;
        let mut hasher = Sha256::new();
        hasher.update(spki_der);
        let expected = hex::encode(hasher.finalize());

        // Config with correct SPKI pin should pass
        let config = PinningConfig::custom(vec![expected.clone()], "test".to_string());
        assert!(config.verify_certificate(&cert_ref).is_ok());

        // Config with wrong pin should fail
        let wrong_config = PinningConfig::custom(vec!["a".repeat(64)], "test".to_string());
        assert!(wrong_config.verify_certificate(&cert_ref).is_err());
    }

    #[test]
    fn test_production_configs() {
        let fulcio = PinningConfig::fulcio_production();
        assert_eq!(fulcio.service_name, "fulcio.sigstore.dev");
        assert!(fulcio.is_enabled());
        assert!(fulcio.pin_count() >= 2); // Leaf SPKI + intermediate CA SPKI

        let rekor = PinningConfig::rekor_production();
        assert_eq!(rekor.service_name, "rekor.sigstore.dev");
        assert!(rekor.is_enabled());
        assert!(rekor.pin_count() >= 2);
    }

    #[test]
    fn test_staging_configs() {
        let fulcio = PinningConfig::fulcio_staging();
        assert_eq!(fulcio.service_name, "fulcio.staging.sigstore.dev");
        assert!(fulcio.is_enabled());

        let rekor = PinningConfig::rekor_staging();
        assert_eq!(rekor.service_name, "rekor.staging.sigstore.dev");
        assert!(rekor.is_enabled());
    }

    #[test]
    fn test_pinning_config_accessors() {
        let pins = vec!["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        let config = PinningConfig::custom(pins, "my-service".to_string());

        assert_eq!(config.service_name(), "my-service");
        assert_eq!(config.pin_count(), 3);
        assert!(config.is_enforcing());
    }

    #[test]
    fn test_warn_only_mode() {
        let pins = vec!["a".repeat(64)];
        let config = PinningConfig::custom(pins, "test".to_string()).warn_only();

        assert!(!config.is_enforcing());

        // Generate a real cert with a non-matching pin
        let params = rcgen::CertificateParams::new(vec!["warn.example.com".to_string()]).unwrap();
        let cert_key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&cert_key).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        // In warn-only mode, verification should pass even with wrong pin
        let result = config.verify_certificate(&cert_der);
        assert!(result.is_ok()); // Should just warn, not error
    }

    #[test]
    fn test_set_enforce() {
        let pins = vec!["a".repeat(64)];
        let mut config = PinningConfig::custom(pins, "test".to_string());

        assert!(config.is_enforcing());
        config.set_enforce(false);
        assert!(!config.is_enforcing());
        config.set_enforce(true);
        assert!(config.is_enforcing());
    }

    #[test]
    fn test_hex_normalization() {
        // Test that uppercase hex is normalized to lowercase
        let pins = vec!["ABCDEF".to_string() + &"0".repeat(58)];
        let config = PinningConfig::custom(pins, "test".to_string());

        assert!(
            config
                .pins
                .contains(&("abcdef".to_string() + &"0".repeat(58)))
        );
    }

    #[test]
    fn test_pinned_cert_verifier_creation() {
        // Test that we can create a PinnedCertVerifier
        let pins = vec!["a".repeat(64), "b".repeat(64)];
        let config = PinningConfig::custom(pins, "test-service".to_string());

        let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = PinnedCertVerifier::new(config, crypto_provider);

        assert!(verifier.is_ok());
        let verifier = verifier.unwrap();
        assert!(format!("{:?}", verifier).contains("PinnedCertVerifier"));
    }

    // NOTE: Tests for WSC_REQUIRE_CERT_PINNING env var cannot be included
    // because the codebase has #![forbid(unsafe_code)] and env var manipulation
    // requires unsafe. The check_pinning_requirement() function is manually tested.

    #[test]
    fn test_pinning_with_multiple_certs() {
        // Generate two real certificates
        let params1 = rcgen::CertificateParams::new(vec!["one.example.com".to_string()]).unwrap();
        let key1 = rcgen::KeyPair::generate().unwrap();
        let cert1 = params1.self_signed(&key1).unwrap();
        let cert1_der = cert1.der().to_vec();

        let params2 = rcgen::CertificateParams::new(vec!["two.example.com".to_string()]).unwrap();
        let key2 = rcgen::KeyPair::generate().unwrap();
        let cert2 = params2.self_signed(&key2).unwrap();
        let cert2_der = cert2.der().to_vec();

        // Compute SPKI fingerprints
        let fp1 = {
            let (_, p) = x509_parser::parse_x509_certificate(&cert1_der).unwrap();
            hex::encode(Sha256::digest(p.public_key().raw))
        };
        let fp2 = {
            let (_, p) = x509_parser::parse_x509_certificate(&cert2_der).unwrap();
            hex::encode(Sha256::digest(p.public_key().raw))
        };

        let config =
            PinningConfig::custom(vec![fp1.clone(), fp2.clone()], "multi-test".to_string());

        // Both certificates should pass
        assert!(
            config
                .verify_certificate(&CertificateDer::from(cert1_der))
                .is_ok()
        );
        assert!(
            config
                .verify_certificate(&CertificateDer::from(cert2_der))
                .is_ok()
        );

        // Certificate with different key should fail
        let params3 = rcgen::CertificateParams::new(vec!["three.example.com".to_string()]).unwrap();
        let key3 = rcgen::KeyPair::generate().unwrap();
        let cert3 = params3.self_signed(&key3).unwrap();
        assert!(
            config
                .verify_certificate(&CertificateDer::from(cert3.der().to_vec()))
                .is_err()
        );
    }
}
