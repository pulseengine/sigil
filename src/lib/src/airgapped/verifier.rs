//! Air-gapped verifier for offline signature verification

use crate::error::WSError;
use crate::signature::keyless::{CertificatePool, KeylessSignature, RekorEntry, RekorKeyring};
use crate::time::{TimeSource, BUILD_TIMESTAMP};

use super::{
    AirGappedConfig, DeviceSecurityState, GracePeriodBehavior, KeyStore, SignedTrustBundle,
    TrustBundle, TrustStore,
};

/// Air-gapped verifier for embedded devices
///
/// Verifies Sigstore keyless signatures without network access
/// using a pre-provisioned trust bundle.
pub struct AirGappedVerifier<T: TimeSource = crate::time::BuildTimeSource> {
    /// Trust bundle (already verified)
    trust_bundle: TrustBundle,

    /// Configuration
    config: AirGappedConfig,

    /// Optional time source for freshness checks
    time_source: Option<T>,

    /// Device state for anti-rollback (optional)
    device_state: Option<DeviceSecurityState>,
}

impl<T: TimeSource> AirGappedVerifier<T> {
    /// Create a new verifier from a signed trust bundle
    ///
    /// # Arguments
    ///
    /// * `signed_bundle` - Trust bundle with signature
    /// * `bundle_verifier_key` - Ed25519 public key to verify bundle signature
    /// * `config` - Verification configuration
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Bundle signature is invalid
    /// - Bundle format is unsupported
    pub fn new(
        signed_bundle: &SignedTrustBundle,
        bundle_verifier_key: &[u8],
        config: AirGappedConfig,
    ) -> Result<Self, WSError> {
        // Verify bundle signature
        signed_bundle.verify(bundle_verifier_key)?;

        Ok(Self {
            trust_bundle: signed_bundle.bundle.clone(),
            config,
            time_source: None,
            device_state: None,
        })
    }

    /// Create verifier from storage backends
    ///
    /// This constructor abstracts the storage mechanism, allowing the same
    /// verification code to work with:
    /// - HSM/TPM for production devices
    /// - File system for development
    /// - Compiled-in bundles for constrained embedded
    ///
    /// # Arguments
    ///
    /// * `trust_store` - Backend for loading the trust bundle
    /// * `key_store` - Backend for loading the verifier public key
    /// * `config` - Verification configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Development: file-based
    /// let verifier = AirGappedVerifier::from_stores(
    ///     &FileTrustStore::new("bundle.json"),
    ///     &FileKeyStore::new("verifier.pub"),
    ///     config,
    /// )?;
    ///
    /// // Production: HSM-backed
    /// let verifier = AirGappedVerifier::from_stores(
    ///     &HsmTrustStore::new(slot),
    ///     &HsmKeyStore::new(key_id),
    ///     config,
    /// )?;
    /// ```
    pub fn from_stores(
        trust_store: &dyn TrustStore,
        key_store: &dyn KeyStore,
        config: AirGappedConfig,
    ) -> Result<Self, WSError> {
        // Load bundle from storage
        let signed_bundle = trust_store.load_bundle()?;

        // Load verifier key from storage
        let verifier_key = key_store.load_verifier_key()?;

        // Verify and create
        Self::new(&signed_bundle, &verifier_key, config)
    }

    /// Create verifier with time source for freshness checks
    pub fn with_time_source(mut self, time_source: T) -> Self {
        self.time_source = Some(time_source);
        self
    }

    /// Create verifier with device state for anti-rollback
    pub fn with_device_state(mut self, state: DeviceSecurityState) -> Result<Self, WSError> {
        // Check bundle version against stored state
        if self.config.enforce_rollback_protection
            && !state.check_bundle_version(self.trust_bundle.version)
        {
            return Err(WSError::VerificationError(format!(
                "Trust bundle version {} is older than device state version {}",
                self.trust_bundle.version, state.bundle_version
            )));
        }

        self.device_state = Some(state);
        Ok(self)
    }

    /// Get the trust bundle
    pub fn trust_bundle(&self) -> &TrustBundle {
        &self.trust_bundle
    }

    /// Get the device state (if set)
    pub fn device_state(&self) -> Option<&DeviceSecurityState> {
        self.device_state.as_ref()
    }

    /// Get mutable device state for updates
    pub fn device_state_mut(&mut self) -> Option<&mut DeviceSecurityState> {
        self.device_state.as_mut()
    }

    /// Check trust bundle health
    ///
    /// Returns warnings about expiring/expired bundle.
    /// If no time source is configured, includes an `UnreliableTimeSource` warning
    /// and falls back to build timestamp for health estimation.
    pub fn check_bundle_health(&self) -> Vec<VerificationWarning> {
        let mut warnings = Vec::new();

        // Get current time (use time source if available, otherwise build time with warning)
        let current_time = match self.time_source.as_ref().and_then(|ts| ts.now_unix().ok()) {
            Some(t) => t,
            None => {
                warnings.push(VerificationWarning::UnreliableTimeSource);
                BUILD_TIMESTAMP
            }
        };

        // Check if bundle is expired
        if current_time > self.trust_bundle.validity.not_after {
            let days_overdue = (current_time - self.trust_bundle.validity.not_after) / 86400;

            if self.trust_bundle.is_in_grace_period(current_time) {
                warnings.push(VerificationWarning::BundleInGracePeriod {
                    days_overdue: days_overdue as u32,
                });
            } else {
                warnings.push(VerificationWarning::BundleExpired {
                    days_overdue: days_overdue as u32,
                });
            }
        } else {
            // Check if bundle is expiring soon (within 30 days)
            let days_remaining = (self.trust_bundle.validity.not_after - current_time) / 86400;
            if days_remaining <= 30 {
                warnings.push(VerificationWarning::BundleExpiringSoon {
                    days_remaining: days_remaining as u32,
                });
            }
        }

        warnings
    }

    /// Verify a keyless signature, entirely offline.
    ///
    /// The embedded model: the caller hashes the module it is about to load
    /// and asks whether that 32-byte hash is validly signed. This method:
    /// 1. Checks trust-bundle validity and signature freshness (time-gated).
    /// 2. Validates the certificate chain to a bundle Fulcio root and checks
    ///    the leaf was valid at Rekor's `integrated_time` (codeSigning EKU).
    /// 3. Verifies the Rekor **SET** signature against a bundle Rekor key.
    /// 4. Verifies the **ECDSA P-256** signature over `module_hash` using the
    ///    leaf cert's public key (self-binding to the module).
    /// 5. Checks the revocation list and identity requirements.
    ///
    /// The cryptographic steps 2-5 are delegated to `verify_crypto`.
    ///
    /// # Not verified offline
    ///
    /// - **Rekor inclusion proof (Merkle).** The SET signature over the entry
    ///   IS verified, but the Merkle inclusion proof is NOT. This mirrors the
    ///   online path's deliberate skip (`signer.rs`): the current inclusion
    ///   verifier recomputes the wrong tiled-log shard root for Rekor v2
    ///   (`log2025-*`) entries, so enabling it fail-closed would reject
    ///   legitimate signatures (issue #137). The returned
    ///   [`VerificationResult::inclusion_verified`] is therefore always
    ///   `false` on this path.
    /// - **SCT / CT-log verification.** No CT-log key is provisioned in the
    ///   `TrustBundle`, so signed certificate timestamps are not checked
    ///   (see DD-12).
    ///
    /// The Rekor **body binding** (#135 UCA-2) — that the stapled entry
    /// references this exact module_hash/signature/leaf cert — IS verified
    /// offline, matching the online path.
    pub fn verify_signature(
        &self,
        signature: &KeylessSignature,
        module_hash: &[u8; 32],
    ) -> Result<VerificationResult, WSError> {
        let mut warnings = Vec::new();

        // Get current time for bundle validity check
        // SECURITY: Fail closed when no time source is available. Without a reliable
        // clock, all time-based checks (expiry, freshness, grace period) are meaningless.
        let current_time =
            self.time_source
                .as_ref()
                .and_then(|ts| ts.now_unix().ok())
                .ok_or_else(|| {
                    WSError::VerificationError(
                "No time source available: air-gapped verification requires a reliable clock \
                 to enforce bundle expiry and signature freshness. Configure a time source \
                 via with_time_source() or use BuildTimeSource for development only.".to_string(),
            )
                })?;

        // 1. Check bundle validity
        if !self.trust_bundle.is_valid(current_time) {
            if self.trust_bundle.is_in_grace_period(current_time) {
                match self.config.grace_period_behavior {
                    GracePeriodBehavior::Strict => {
                        return Err(WSError::VerificationError(
                            "Trust bundle has expired".to_string(),
                        ));
                    }
                    GracePeriodBehavior::WarnDuringGrace | GracePeriodBehavior::WarnOnly => {
                        let days_overdue =
                            (current_time - self.trust_bundle.validity.not_after) / 86400;
                        warnings.push(VerificationWarning::BundleInGracePeriod {
                            days_overdue: days_overdue as u32,
                        });
                    }
                }
            } else {
                match self.config.grace_period_behavior {
                    GracePeriodBehavior::Strict | GracePeriodBehavior::WarnDuringGrace => {
                        return Err(WSError::VerificationError(
                            "Trust bundle has expired (past grace period)".to_string(),
                        ));
                    }
                    GracePeriodBehavior::WarnOnly => {
                        let days_overdue =
                            (current_time - self.trust_bundle.validity.not_after) / 86400;
                        warnings.push(VerificationWarning::BundleExpired {
                            days_overdue: days_overdue as u32,
                        });
                    }
                }
            }
        }

        // 2. Parse integrated_time from Rekor entry
        let integrated_time = self.parse_integrated_time(&signature.rekor_entry)?;

        // 3. Check signature freshness (if max age configured)
        if let Some(max_age) = self.config.max_signature_age {
            let max_age_secs = max_age.as_secs();
            if current_time > integrated_time + max_age_secs {
                let age_days = (current_time - integrated_time) / 86400;
                return Err(WSError::VerificationError(format!(
                    "Signature is too old ({} days, max {} days)",
                    age_days,
                    max_age_secs / 86400
                )));
            }
        }

        // 4. Verify signature is not before build time
        if integrated_time < BUILD_TIMESTAMP {
            return Err(WSError::VerificationError(format!(
                "Signature timestamp {} is before build time {}",
                integrated_time, BUILD_TIMESTAMP
            )));
        }

        // 5. Verify module hash matches
        if signature.module_hash != *module_hash {
            return Err(WSError::VerificationError(
                "Module hash mismatch".to_string(),
            ));
        }

        // 6. Extract identity from certificate
        let identity = self.extract_identity(signature)?;

        // 7. Check identity requirements
        if let Some(ref requirements) = self.config.identity_requirements {
            if !requirements.matches_issuer(&identity.issuer) {
                return Err(WSError::VerificationError(format!(
                    "Issuer '{}' not in allowed list",
                    identity.issuer
                )));
            }
            if !requirements.matches_subject(&identity.subject) {
                return Err(WSError::VerificationError(format!(
                    "Subject '{}' not in allowed list",
                    identity.subject
                )));
            }
        }

        // 8. Check revocation list
        if self.config.check_revocations {
            let cert_fingerprint = self.compute_cert_fingerprint(signature)?;
            if self.trust_bundle.is_revoked(&cert_fingerprint) {
                return Err(WSError::VerificationError(
                    "Certificate has been revoked".to_string(),
                ));
            }
        }

        // 9. Verify the actual cryptographic signature
        // This uses the existing KeylessSignature verification
        self.verify_crypto(signature, module_hash)?;

        Ok(VerificationResult {
            valid: true,
            identity: Some(identity),
            signature_time: integrated_time,
            module_hash: *module_hash,
            // Rekor inclusion proof (Merkle) is intentionally NOT verified on
            // the offline path (SET signature IS verified). See the doc on
            // `verify_signature` and issue #137.
            inclusion_verified: false,
            warnings,
        })
    }

    /// Parse integrated_time from Rekor entry
    fn parse_integrated_time(&self, entry: &RekorEntry) -> Result<u64, WSError> {
        // The integrated_time is stored as an ISO 8601 string or Unix timestamp
        crate::time::parse_timestamp(&entry.integrated_time)
    }

    /// Extract identity from signature certificate
    fn extract_identity(&self, signature: &KeylessSignature) -> Result<SignerIdentity, WSError> {
        let issuer = signature
            .get_issuer()
            .unwrap_or_else(|_| "unknown".to_string());
        let subject = signature
            .get_identity()
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(SignerIdentity {
            issuer,
            subject,
            claims: std::collections::BTreeMap::new(),
        })
    }

    /// Compute certificate fingerprint for revocation check
    fn compute_cert_fingerprint(&self, signature: &KeylessSignature) -> Result<String, WSError> {
        if signature.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }

        // Get leaf certificate (first in chain)
        let leaf_pem = &signature.cert_chain[0];

        // Extract DER from PEM
        let der = leaf_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        let der_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &der)
            .map_err(|e| WSError::CertificateError(format!("Invalid certificate PEM: {}", e)))?;

        let hash = hmac_sha256::Hash::hash(&der_bytes);
        Ok(hex::encode(hash))
    }

    /// Cryptographically verify a keyless signature entirely offline,
    /// anchored to the provisioned [`TrustBundle`](TrustBundle).
    ///
    /// This mirrors the online orchestration order in
    /// `signer.rs::verify_module` (cert chain -> Rekor SET -> signature
    /// binding -> Rekor body binding -> revocation), but every trust decision
    /// is anchored to `self.trust_bundle` rather than the compiled-in
    /// `trusted_root.json`. It delegates to the same tested primitives the
    /// online path uses: [`CertificatePool`] (RFC-5280 path validation),
    /// [`RekorKeyring`] (SET verification), and
    /// `KeylessSignature::verify_rekor_body_binds_to_bundle` (#135 UCA-2).
    ///
    /// Steps, in order:
    ///
    /// 1. **Hash-binding sanity.** The caller's `module_hash` must equal the
    ///    signature's recorded `module_hash`. On mismatch this returns a
    ///    clear, non-crypto error (for a good message). The *real* binding is
    ///    step 4, which cannot pass unless the hashes are equal.
    /// 2. **Certificate chain.** Build a [`CertificatePool`] from the bundle's
    ///    Fulcio roots and path-validate the leaf at Rekor's `integrated_time`
    ///    (RFC-5280 chain building, validity-at-time, codeSigning EKU).
    /// 3. **Rekor SET.** Build a [`RekorKeyring`] from the bundle's Rekor keys
    ///    and verify the Signed Entry Timestamp. MANDATORY.
    /// 4. **Signature.** Extract the leaf's ECDSA P-256 public key from its
    ///    SPKI (the SEC1 point in the BIT STRING — *not* the whole SPKI DER)
    ///    and verify `signature.signature` (P1363 `r||s`) over the 32-byte
    ///    `module_hash` via `verify_prehash`. Self-binding: only passes if
    ///    `module_hash` is exactly the digest the ephemeral key signed.
    /// 5. **Rekor body binding.** The stapled Rekor entry body must reference
    ///    *this* triple (module_hash / signature / leaf cert). Steps 3-4 only
    ///    prove the entry was logged and the signature/cert/hash are mutually
    ///    consistent; without this a holder of a legitimate Fulcio cert could
    ///    staple any unrelated public Rekor entry (#135 UCA-2). Self-contained
    ///    (no network), so it applies offline exactly as online.
    /// 6. **Revocation.** Reject if the leaf's SHA-256 fingerprint appears in
    ///    the bundle's revocation list. An empty list means nothing is
    ///    revoked (not "unchecked").
    ///
    /// The Rekor **inclusion proof (Merkle) is NOT verified** here — see the
    /// note on [`verify_signature`](Self::verify_signature).
    fn verify_crypto(
        &self,
        signature: &KeylessSignature,
        module_hash: &[u8; 32],
    ) -> Result<(), WSError> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
        use x509_parser::prelude::*;

        if signature.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }
        let leaf_pem = &signature.cert_chain[0];

        // 1. Hash-binding sanity (clear message; the real binding is step 4).
        if signature.module_hash.as_slice() != &module_hash[..] {
            log::error!(
                "Air-gapped keyless verification rejected: module hash mismatch \
                 (caller {}, signature {})",
                hex::encode(module_hash),
                hex::encode(&signature.module_hash),
            );
            return Err(WSError::VerificationError(
                "module hash mismatch: caller-provided hash does not match the \
                 signed module hash"
                    .to_string(),
            ));
        }

        // Parse Rekor integrated_time (RFC3339 -> unix). Parsed inline (not via
        // self.parse_integrated_time) so verify_crypto stays independently
        // testable; mirrors format.rs::verify_cert_chain.
        let integrated_time_unix =
            chrono::DateTime::parse_from_rfc3339(&signature.rekor_entry.integrated_time)
                .map_err(|e| {
                    WSError::CertificateError(format!("Failed to parse integrated_time: {}", e))
                })?
                .timestamp();

        // 2. Certificate chain anchored to the bundle's Fulcio roots.
        let cert_pool =
            CertificatePool::from_pem_authorities(&self.trust_bundle.certificate_authorities)
                .map_err(|e| {
                    WSError::CertificateError(format!(
                        "Failed to build trust anchors from bundle: {}",
                        e
                    ))
                })?;
        cert_pool
            .verify_pem_cert(leaf_pem.as_bytes(), integrated_time_unix)
            .map_err(|e| {
                WSError::CertificateError(format!("Certificate verification failed: {}", e))
            })?;

        // 3. Rekor SET (MANDATORY). Inclusion proof (Merkle) is deliberately
        //    NOT verified offline (see verify_signature docs / issue #137).
        let keyring = RekorKeyring::from_pem_logs(&self.trust_bundle.transparency_logs)?;
        keyring.verify_set(&signature.rekor_entry)?;

        // 4. Signature over the module hash. Extract the leaf's P-256 key the
        //    correct way: the SEC1-encoded point in the SPKI BIT STRING, NOT
        //    the whole SPKI DER (mirrors format.rs verify_artifact_binding).
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes()).map_err(|e| {
            WSError::CertificateError(format!("Failed to parse leaf cert PEM: {}", e))
        })?;
        let cert = pem
            .parse_x509()
            .map_err(|e| WSError::CertificateError(format!("Failed to parse leaf X.509: {}", e)))?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(cert.public_key().subject_public_key.data.as_ref())
                .map_err(|e| {
                    WSError::VerificationError(format!(
                        "leaf certificate is not a valid ECDSA P-256 key: {}",
                        e
                    ))
                })?;
        // Fold a malformed-signature parse error into the same message as a
        // verify failure so a tampered signature asserts on one stable string
        // regardless of whether it was malformed or merely wrong.
        let sig = P256Signature::from_slice(&signature.signature).map_err(|e| {
            WSError::VerificationError(format!("signature verification failed: {}", e))
        })?;
        verifying_key
            .verify_prehash(&module_hash[..], &sig)
            .map_err(|e| {
                WSError::VerificationError(format!("signature verification failed: {}", e))
            })?;

        // 5. Rekor body binding (issue #135 UCA-2). Steps 3 and 4 only prove
        // "this entry was logged by Rekor" and "this signature/cert/hash are
        // mutually consistent" — NEITHER proves the Rekor entry binds to *this*
        // triple. Without it, a holder of a legitimate Fulcio cert can sign a
        // malicious module and staple any unrelated public Rekor entry to pass.
        // The check is self-contained (entry body vs module_hash/signature/leaf
        // cert) so it applies offline exactly as it does online (signer.rs:664).
        signature.verify_rekor_body_binds_to_bundle()?;

        // 6. Revocation. Empty list means nothing revoked (not "unchecked").
        let fingerprint = self.compute_cert_fingerprint(signature)?;
        if self.trust_bundle.is_revoked(&fingerprint) {
            log::error!(
                "Air-gapped keyless verification rejected: leaf certificate {} is revoked",
                fingerprint
            );
            return Err(WSError::VerificationError(format!(
                "certificate has been revoked (fingerprint {})",
                fingerprint
            )));
        }

        Ok(())
    }
}

/// Verification result
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub valid: bool,

    /// Signing identity from certificate
    pub identity: Option<SignerIdentity>,

    /// Signature timestamp (Rekor integrated_time)
    pub signature_time: u64,

    /// Module hash that was verified
    pub module_hash: [u8; 32],

    /// Whether the Rekor **inclusion proof (Merkle)** was cryptographically
    /// verified. Always `false` on the air-gapped/offline path: the Rekor
    /// **SET** signature is verified, but the Merkle inclusion proof is not
    /// (mirrors the online path's deliberate skip; see the doc on
    /// [`AirGappedVerifier::verify_signature`] and issue #137). Callers that
    /// require full transparency-log inclusion must not treat a successful
    /// offline result as inclusion-verified.
    pub inclusion_verified: bool,

    /// Warnings (non-fatal issues)
    pub warnings: Vec<VerificationWarning>,
}

/// Signer identity extracted from certificate
#[derive(Debug, Clone)]
pub struct SignerIdentity {
    /// OIDC issuer (e.g., "https://token.actions.githubusercontent.com")
    pub issuer: String,

    /// Subject (e.g., workflow URL for GitHub Actions)
    pub subject: String,

    /// Additional claims from certificate
    pub claims: std::collections::BTreeMap<String, String>,
}

/// Verification warnings (non-fatal)
#[derive(Debug, Clone)]
pub enum VerificationWarning {
    /// Trust bundle expires soon
    BundleExpiringSoon { days_remaining: u32 },

    /// Using bundle within grace period
    BundleInGracePeriod { days_overdue: u32 },

    /// Bundle is fully expired (only in WarnOnly mode)
    BundleExpired { days_overdue: u32 },

    /// Signature is older than recommended
    SignatureAge { age_days: u32 },

    /// Time source is not reliable
    UnreliableTimeSource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airgapped::TrustBundle;

    #[test]
    fn test_verifier_creation() {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();
        let bundle = TrustBundle::new(1, 365);
        let seed = keypair.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap();

        let verifier = AirGappedVerifier::<crate::time::BuildTimeSource>::new(
            &signed,
            keypair.pk.as_ref(),
            AirGappedConfig::default(),
        );

        assert!(verifier.is_ok());
    }

    #[test]
    fn test_verifier_wrong_key_fails() {
        use ed25519_compact::KeyPair;

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let bundle = TrustBundle::new(1, 365);
        let seed1 = keypair1.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed1.as_ref()).unwrap();

        let result = AirGappedVerifier::<crate::time::BuildTimeSource>::new(
            &signed,
            keypair2.pk.as_ref(), // Wrong key
            AirGappedConfig::default(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_bundle_health_check() {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();
        let mut bundle = TrustBundle::new(1, 365);

        // Make bundle expire in 10 days
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        bundle.validity.not_after = now + 10 * 86400;

        let seed = keypair.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap();

        let verifier = AirGappedVerifier::<crate::time::SystemTimeSource>::new(
            &signed,
            keypair.pk.as_ref(),
            AirGappedConfig::default(),
        )
        .unwrap()
        .with_time_source(crate::time::SystemTimeSource);

        let warnings = verifier.check_bundle_health();
        assert!(warnings
            .iter()
            .any(|w| matches!(w, VerificationWarning::BundleExpiringSoon { .. })));
    }

    #[test]
    fn test_rollback_protection() {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();

        // Create bundle with version 5
        let bundle = TrustBundle::new(5, 365);
        let seed = keypair.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap();

        // Device state expects version >= 10
        let mut state = DeviceSecurityState::new(BUILD_TIMESTAMP);
        state.bundle_version = 10;

        let config = AirGappedConfig::default().with_rollback_protection();

        let verifier = AirGappedVerifier::<crate::time::BuildTimeSource>::new(
            &signed,
            keypair.pk.as_ref(),
            config,
        )
        .unwrap();

        // Should fail due to rollback protection
        let result = verifier.with_device_state(state);
        assert!(result.is_err());
    }

    // ================================================================
    // Offline keyless verification (issue #219 / REQ-23)
    //
    // These build a real Fulcio-style chain with rcgen (self-signed P-256
    // root CA + codeSigning leaf), a real ECDSA P-256 module signature, and
    // a real minted Rekor SET, then exercise the offline `verify_crypto`
    // path against a provisioned `TrustBundle`. Each negative test perturbs
    // exactly one input and asserts on that step's specific failure.
    //
    // A single end-to-end fixture (cert + SET for the *same* signature) is
    // buildable here because the test mints the Rekor key itself and can
    // therefore mint a valid SET; there is no need to fall back to
    // separately-triggered units.
    // ================================================================

    use crate::airgapped::TransparencyLog;
    use crate::signature::keyless::RekorEntry;
    use ecdsa::signature::DigestSigner;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
    use sha2::{Digest as _, Sha256};

    const INTEGRATED_TIME: &str = "2030-06-01T00:00:00Z";
    const REKOR_LOG_ID: &str = "test-rekor-log-id";
    const CA_NB: &str = "2020-01-01T00:00:00Z";
    const CA_NA: &str = "2040-01-01T00:00:00Z";
    const LEAF_NB: &str = "2029-01-01T00:00:00Z";
    const LEAF_NA: &str = "2031-01-01T00:00:00Z";

    fn ts(s: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp()
    }

    fn odt(unix: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    fn mh() -> [u8; 32] {
        Sha256::digest(b"test module bytes").into()
    }

    /// Self-signed P-256 root CA valid over `[nb, na]`.
    fn gen_ca(nb: i64, na: i64) -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["test-ca.local".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.not_before = odt(nb);
        params.not_after = odt(na);
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    /// codeSigning leaf signed by `ca`, valid over `[nb, na]`. Returns the
    /// leaf PEM and the matching P-256 signing key (rcgen -> p256, mirroring
    /// `format.rs`).
    fn gen_leaf(
        ca: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
        nb: i64,
        na: i64,
    ) -> (String, p256::ecdsa::SigningKey) {
        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let secret = p256::SecretKey::from_pkcs8_pem(&leaf_key.serialize_pem()).unwrap();
        let signing_key = p256::ecdsa::SigningKey::from(&secret);

        let mut params = rcgen::CertificateParams::new(vec!["leaf.local".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        params.not_before = odt(nb);
        params.not_after = odt(na);
        let leaf = params.signed_by(&leaf_key, ca, ca_key).unwrap();
        (leaf.pem(), signing_key)
    }

    /// A CA-capable intermediate signed by `root`, valid over `[nb, na]`.
    fn gen_intermediate(
        root: &rcgen::Certificate,
        root_key: &rcgen::KeyPair,
        nb: i64,
        na: i64,
    ) -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["test-intermediate.local".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.not_before = odt(nb);
        params.not_after = odt(na);
        let cert = params.signed_by(&key, root, root_key).unwrap();
        (cert, key)
    }

    /// A Rekor log entry (public key PEM + fixed `log_id`) and its P-256
    /// signing key. Every call uses the same `log_id` but a fresh key, so a
    /// "wrong key, same log_id" bundle is one more call away.
    fn gen_rekor_log() -> (TransparencyLog, p256::ecdsa::SigningKey) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let secret = p256::SecretKey::from_pkcs8_pem(&kp.serialize_pem()).unwrap();
        let sk = p256::ecdsa::SigningKey::from(&secret);
        let spki_der = sk.verifying_key().to_public_key_der().unwrap();
        let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki_der.as_bytes().to_vec()));
        let mut log = TransparencyLog::new("https://rekor.test", &pem, 3650).unwrap();
        log.log_id = REKOR_LOG_ID.to_string();
        (log, sk)
    }

    /// Mint a valid SET over `{body, integratedTime, logID, logIndex}` exactly
    /// as `RekorKeyring::verify_set` reconstructs and checks it.
    fn mint_set(
        rekor_sk: &p256::ecdsa::SigningKey,
        body: &str,
        integrated_unix: i64,
        log_index: u64,
    ) -> String {
        let entry_json = serde_json::json!({
            "body": body,
            "integratedTime": integrated_unix,
            "logID": REKOR_LOG_ID,
            "logIndex": log_index,
        });
        let canonical = serde_jcs::to_vec(&entry_json).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let sig: p256::ecdsa::Signature = rekor_sk.sign_digest(hasher);
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.to_der().as_bytes(),
        )
    }

    /// Build a base64'd `hashedrekord/0.0.1` body that binds to `signature`,
    /// `leaf_cert_pem` and `module_hash` — the exact shape
    /// `verify_rekor_body_binds_to_bundle` (format.rs) checks: hash value =
    /// hex(module_hash), signature.content = base64(signature), and
    /// publicKey.content = base64(leaf cert PEM). Mirrors the online test
    /// helper of the same name.
    fn build_hashedrekord_body(
        signature_bytes: &[u8],
        leaf_cert_pem: &str,
        module_hash: &[u8],
    ) -> String {
        let engine = &base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": base64::Engine::encode(engine, signature_bytes),
                    "publicKey": {
                        "content": base64::Engine::encode(engine, leaf_cert_pem.as_bytes()),
                    },
                },
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": hex::encode(module_hash),
                    },
                },
            },
        });
        base64::Engine::encode(engine, serde_json::to_vec(&body).unwrap())
    }

    /// Assemble a `KeylessSignature` whose P-256 signature binds `module_hash`
    /// (via prehash), whose Rekor entry body is a real `hashedrekord` binding
    /// that same triple (module_hash / signature / leaf cert), and whose SET is
    /// minted over that body by `rekor_sk`.
    fn assemble_sig(
        leaf_pem: String,
        leaf_sk: &p256::ecdsa::SigningKey,
        module_hash: [u8; 32],
        rekor_sk: &p256::ecdsa::SigningKey,
    ) -> KeylessSignature {
        let sig: p256::ecdsa::Signature = leaf_sk.sign_prehash(&module_hash).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();
        // Real hashedrekord body bound to this signature/cert/hash, then the
        // SET is minted over that exact body.
        let body = build_hashedrekord_body(&sig_bytes, &leaf_pem, &module_hash);
        let integrated_unix = ts(INTEGRATED_TIME);
        let set_b64 = mint_set(rekor_sk, &body, integrated_unix, 1);
        let rekor_entry = RekorEntry {
            uuid: "test-uuid".to_string(),
            log_index: 1,
            body,
            log_id: REKOR_LOG_ID.to_string(),
            inclusion_proof: vec![],
            signed_entry_timestamp: set_b64,
            integrated_time: INTEGRATED_TIME.to_string(),
        };
        KeylessSignature::new(sig_bytes, vec![leaf_pem], rekor_entry, module_hash.to_vec())
    }

    fn build_bundle(root_pem: String, rekor_log: TransparencyLog) -> TrustBundle {
        let mut bundle = TrustBundle::new(1, 3650);
        bundle
            .certificate_authorities
            .push(super::super::CertificateAuthority::new(
                "Test Fulcio",
                "https://fulcio.test",
                vec![root_pem],
                3650,
            ));
        bundle.transparency_logs.push(rekor_log);
        bundle
    }

    /// Build a complete case. `anchor_matches_signer == false` anchors a
    /// *different* root in the bundle than the one that signed the leaf, so
    /// chain building fails. `leaf_nb/leaf_na` control the leaf's validity
    /// window (for the expiry test). Returns the unsigned bundle (so tests
    /// can mutate revocations), the signature, the module hash, and the
    /// leaf's signing key (for the tamper test).
    fn build_case(
        leaf_nb: i64,
        leaf_na: i64,
        anchor_matches_signer: bool,
    ) -> (
        TrustBundle,
        KeylessSignature,
        [u8; 32],
        p256::ecdsa::SigningKey,
    ) {
        let (ca_signer, ca_key) = gen_ca(ts(CA_NB), ts(CA_NA));
        let (leaf_pem, leaf_sk) = gen_leaf(&ca_signer, &ca_key, leaf_nb, leaf_na);
        let (rekor_log, rekor_sk) = gen_rekor_log();
        let module_hash = mh();
        let sig = assemble_sig(leaf_pem, &leaf_sk, module_hash, &rekor_sk);
        let anchor_pem = if anchor_matches_signer {
            ca_signer.pem()
        } else {
            let (ca_other, _k) = gen_ca(ts(CA_NB), ts(CA_NA));
            ca_other.pem()
        };
        let bundle = build_bundle(anchor_pem, rekor_log);
        (bundle, sig, module_hash, leaf_sk)
    }

    fn valid_case() -> (
        TrustBundle,
        KeylessSignature,
        [u8; 32],
        p256::ecdsa::SigningKey,
    ) {
        build_case(ts(LEAF_NB), ts(LEAF_NA), true)
    }

    fn verifier_for(bundle: &TrustBundle) -> AirGappedVerifier<crate::time::BuildTimeSource> {
        use ed25519_compact::KeyPair;
        let kp = KeyPair::generate();
        let signed = SignedTrustBundle::sign(bundle.clone(), kp.sk.seed().as_ref()).unwrap();
        AirGappedVerifier::<crate::time::BuildTimeSource>::new(
            &signed,
            kp.pk.as_ref(),
            AirGappedConfig::default(),
        )
        .unwrap()
    }

    #[test]
    fn test_offline_verify_crypto_positive() {
        let (bundle, sig, module_hash, _sk) = valid_case();
        let verifier = verifier_for(&bundle);
        let r = verifier.verify_crypto(&sig, &module_hash);
        assert!(
            r.is_ok(),
            "expected offline verify_crypto to succeed, got: {:?}",
            r.err()
        );
    }

    /// Full public entry point (`verify_signature`): a properly signed module
    /// chaining to the bundle root, with a valid SET, verifies -> Ok, and the
    /// result explicitly reports the Rekor inclusion proof as NOT verified.
    fn verifier_for_system(
        bundle: &TrustBundle,
    ) -> AirGappedVerifier<crate::time::SystemTimeSource> {
        use ed25519_compact::KeyPair;
        let kp = KeyPair::generate();
        let signed = SignedTrustBundle::sign(bundle.clone(), kp.sk.seed().as_ref()).unwrap();
        AirGappedVerifier::<crate::time::SystemTimeSource>::new(
            &signed,
            kp.pk.as_ref(),
            AirGappedConfig::default(),
        )
        .unwrap()
        .with_time_source(crate::time::SystemTimeSource)
    }

    #[test]
    fn test_offline_full_path_inclusion_not_verified() {
        let (bundle, sig, module_hash, _sk) = valid_case();
        let verifier = verifier_for_system(&bundle);
        let result = verifier
            .verify_signature(&sig, &module_hash)
            .expect("offline verify_signature should succeed");
        assert!(result.valid);
        assert!(
            !result.inclusion_verified,
            "offline path must not claim the Rekor inclusion proof was verified"
        );
    }

    #[test]
    fn test_offline_tampered_signature() {
        // Well-formed signature (same key) but over a *different* prehash, so
        // it reaches verify_prehash and fails there rather than failing to parse.
        let (bundle, mut sig, module_hash, leaf_sk) = valid_case();
        let other: p256::ecdsa::Signature = leaf_sk.sign_prehash(&[0xAA; 32]).unwrap();
        sig.signature = other.to_bytes().to_vec();
        let verifier = verifier_for(&bundle);
        let err = verifier.verify_crypto(&sig, &module_hash).unwrap_err();
        match err {
            WSError::VerificationError(m) => {
                assert!(m.contains("signature verification failed"), "got: {}", m)
            }
            o => panic!("expected VerificationError(signature ...), got {:?}", o),
        }
    }

    #[test]
    fn test_offline_wrong_root() {
        // Leaf chains to root B; bundle anchors root A -> chain build fails.
        let (bundle, sig, module_hash, _sk) = build_case(ts(LEAF_NB), ts(LEAF_NA), false);
        let verifier = verifier_for(&bundle);
        let err = verifier.verify_crypto(&sig, &module_hash).unwrap_err();
        match err {
            // The leaf's signature does not verify under the wrong anchor's key.
            WSError::CertificateError(m) => assert!(
                m.contains("Certificate verification failed")
                    && m.contains("InvalidSignatureForPublicKey"),
                "got: {}",
                m
            ),
            o => panic!("expected CertificateError (chain), got {:?}", o),
        }
    }

    #[test]
    fn test_offline_multi_cert_ordering_last_is_root() {
        // Exercises the one net-new trust decision in from_pem_authorities:
        // the LAST cert in certificates_pem is the anchor, earlier ones are
        // intermediates. Chain: root -> leaf (leaf signed directly by root),
        // plus a decoy intermediate (signed by root, never signs the leaf) so
        // certificates_pem has >1 entry. This makes the ordering discriminating:
        // only the correct order leaves the leaf chaining to the anchor.
        let (root, root_key) = gen_ca(ts(CA_NB), ts(CA_NA));
        let (inter, _inter_key) = gen_intermediate(&root, &root_key, ts(CA_NB), ts(CA_NA));
        let (leaf_pem, leaf_sk) = gen_leaf(&root, &root_key, ts(LEAF_NB), ts(LEAF_NA));
        let (rekor_log, rekor_sk) = gen_rekor_log();
        let module_hash = mh();
        let sig = assemble_sig(leaf_pem, &leaf_sk, module_hash, &rekor_sk);

        // Correct order [intermediate, root]: last = self-signed root becomes
        // the trust anchor; the leaf chains to it -> Ok.
        let mut ok_bundle = TrustBundle::new(1, 3650);
        ok_bundle
            .certificate_authorities
            .push(super::super::CertificateAuthority::new(
                "Test Fulcio",
                "https://fulcio.test",
                vec![inter.pem(), root.pem()],
                3650,
            ));
        ok_bundle.transparency_logs.push(rekor_log.clone());
        assert!(
            verifier_for(&ok_bundle)
                .verify_crypto(&sig, &module_hash)
                .is_ok(),
            "correct [intermediate, root] ordering must verify"
        );

        // Reversed order [root, intermediate]: last = the decoy intermediate is
        // mistakenly treated as the anchor; the real root is demoted to a
        // non-anchor, so the leaf's path no longer terminates -> reject. Proves
        // the last-is-root rule is load-bearing, not incidental.
        let mut bad_bundle = TrustBundle::new(1, 3650);
        bad_bundle
            .certificate_authorities
            .push(super::super::CertificateAuthority::new(
                "Test Fulcio",
                "https://fulcio.test",
                vec![root.pem(), inter.pem()],
                3650,
            ));
        bad_bundle.transparency_logs.push(rekor_log);
        let err = verifier_for(&bad_bundle)
            .verify_crypto(&sig, &module_hash)
            .unwrap_err();
        match err {
            WSError::CertificateError(m) => {
                assert!(m.contains("Certificate verification failed"), "got: {}", m)
            }
            o => panic!("expected CertificateError (reversed ordering), got {:?}", o),
        }
    }

    #[test]
    fn test_offline_expired_leaf() {
        // Leaf validity window is entirely before integrated_time (2030).
        let (bundle, sig, module_hash, _sk) =
            build_case(ts("2019-01-01T00:00:00Z"), ts("2020-01-01T00:00:00Z"), true);
        let verifier = verifier_for(&bundle);
        let err = verifier.verify_crypto(&sig, &module_hash).unwrap_err();
        match err {
            // Proves validity-at-integrated_time is enforced: the verification
            // time (2030, from the Rekor entry) is past the leaf's not_after.
            WSError::CertificateError(m) => assert!(
                m.contains("Certificate verification failed") && m.contains("CertExpired"),
                "got: {}",
                m
            ),
            o => panic!("expected CertificateError (expired), got {:?}", o),
        }
    }

    #[test]
    fn test_offline_revoked_leaf() {
        let (mut bundle, sig, module_hash, _sk) = valid_case();
        // Fingerprint the leaf via the same function the verifier uses.
        let fp = verifier_for(&bundle)
            .compute_cert_fingerprint(&sig)
            .unwrap();
        bundle.revocations.push(fp);
        let verifier = verifier_for(&bundle);
        let err = verifier.verify_crypto(&sig, &module_hash).unwrap_err();
        match err {
            WSError::VerificationError(m) => assert!(m.contains("revoked"), "got: {}", m),
            o => panic!("expected VerificationError (revoked), got {:?}", o),
        }
    }

    #[test]
    fn test_offline_wrong_rekor_key() {
        // Same log_id, different key -> verify_set finds a key but the SET
        // signature check fails.
        let (mut bundle, sig, module_hash, _sk) = valid_case();
        let (wrong_log, _wrong_sk) = gen_rekor_log();
        bundle.transparency_logs[0] = wrong_log;
        let verifier = verifier_for(&bundle);
        let err = verifier.verify_crypto(&sig, &module_hash).unwrap_err();
        match err {
            WSError::RekorError(m) => {
                assert!(
                    m.contains("SET signature verification failed"),
                    "got: {}",
                    m
                )
            }
            o => panic!("expected RekorError (SET), got {:?}", o),
        }
    }

    #[test]
    fn test_offline_hash_mismatch() {
        // Caller-provided hash differs from signature.module_hash -> clear,
        // non-crypto error at the hash-binding step.
        let (bundle, sig, _mh, _sk) = valid_case();
        let verifier = verifier_for(&bundle);
        let err = verifier.verify_crypto(&sig, &[0x11; 32]).unwrap_err();
        match err {
            WSError::VerificationError(m) => {
                assert!(m.contains("module hash mismatch"), "got: {}", m)
            }
            o => panic!("expected VerificationError (hash mismatch), got {:?}", o),
        }
    }

    /// Regression for #135 UCA-2 (offline): a fully valid cert chain + SET +
    /// P-256 signature over the REAL module hash, but the stapled Rekor entry
    /// body references a DIFFERENT artifact hash. Steps 1-4 pass (the SET is
    /// re-minted over the mismatched body so it verifies), so the failure lands
    /// specifically at step 5, body-binding. Distinguished from the step-4
    /// signature error by its variant: body-binding returns the opaque
    /// `WSError::VerificationFailed`, not `VerificationError(_)`.
    #[test]
    fn test_offline_rekor_body_mismatch() {
        let (ca, ca_key) = gen_ca(ts(CA_NB), ts(CA_NA));
        let (leaf_pem, leaf_sk) = gen_leaf(&ca, &ca_key, ts(LEAF_NB), ts(LEAF_NA));
        let (rekor_log, rekor_sk) = gen_rekor_log();
        let module_hash = mh();

        // Genuine P-256 signature over the real module hash.
        let sig: p256::ecdsa::Signature = leaf_sk.sign_prehash(&module_hash).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // Body references a DIFFERENT module hash -> it does not bind, even
        // though it carries the real signature and leaf cert.
        let wrong_hash = [0x99u8; 32];
        let body = build_hashedrekord_body(&sig_bytes, &leaf_pem, &wrong_hash);

        // Re-mint the SET over this exact body so step 3 (SET) still passes and
        // the rejection is attributable to body-binding, not the SET.
        let set_b64 = mint_set(&rekor_sk, &body, ts(INTEGRATED_TIME), 1);
        let rekor_entry = RekorEntry {
            uuid: "test-uuid".to_string(),
            log_index: 1,
            body,
            log_id: REKOR_LOG_ID.to_string(),
            inclusion_proof: vec![],
            signed_entry_timestamp: set_b64,
            integrated_time: INTEGRATED_TIME.to_string(),
        };
        let sig_obj =
            KeylessSignature::new(sig_bytes, vec![leaf_pem], rekor_entry, module_hash.to_vec());

        let bundle = build_bundle(ca.pem(), rekor_log);
        let err = verifier_for(&bundle)
            .verify_crypto(&sig_obj, &module_hash)
            .unwrap_err();
        match err {
            WSError::VerificationFailed => {}
            o => panic!(
                "expected VerificationFailed (Rekor body binding), got {:?}",
                o
            ),
        }
    }
}
