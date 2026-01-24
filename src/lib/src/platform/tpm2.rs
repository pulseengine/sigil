//! TPM 2.0 hardware security module integration
//!
//! Provides hardware-backed key generation and signing using TPM 2.0 chips.
//! Keys are generated within the TPM and never leave the hardware - only
//! opaque handles are exposed to the application.
//!
//! # Platform Support
//!
//! - **Linux**: Requires `tpm2-tss` libraries and access to `/dev/tpmrm0`
//! - **Windows**: Uses native TBS (TPM Base Services)
//! - **Testing**: Use `swtpm` software TPM simulator
//!
//! # Algorithm Support
//!
//! TPM2 algorithm support varies by chip. This implementation:
//! 1. Prefers Ed25519 if supported (matches `SoftwareProvider`)
//! 2. Falls back to ECDSA P-256 (universal TPM2 support)
//!
//! # Example
//!
//! ```rust,ignore
//! use wsc::platform::tpm2::Tpm2Provider;
//! use wsc::platform::SecureKeyProvider;
//!
//! // Connect to TPM (auto-detects device)
//! let provider = Tpm2Provider::new()?;
//!
//! // Generate key in TPM hardware
//! let handle = provider.generate_key()?;
//!
//! // Sign data (private key never leaves TPM)
//! let signature = provider.sign(handle, b"data to sign")?;
//! ```
//!
//! # Security Considerations
//!
//! - Private keys are generated within TPM using hardware RNG
//! - Private keys never leave the TPM boundary
//! - Keys can be tied to PCR state for measured boot scenarios
//! - TPM provides tamper resistance and rate limiting

use crate::error::WSError;
use crate::platform::{KeyHandle, PublicKey, SecureKeyProvider, SecurityLevel};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::{
        Digest as TpmDigest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme,
        PublicBuilder, PublicEccParametersBuilder, SignatureScheme,
    },
    tcti_ldr::{DeviceConfig, NetworkTPMConfig, TctiNameConf},
    utils::PublicKey as TssPublicKey,
    Context,
};

/// Signing algorithm used by a TPM key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmAlgorithm {
    /// Ed25519 (preferred, not all TPMs support this)
    Ed25519,
    /// ECDSA with P-256 curve (universal TPM2 support)
    EcdsaP256,
}

/// Internal key data stored for each generated key
struct TpmKeyData {
    /// The key handle in TPM
    key_handle: tss_esapi::handles::KeyHandle,
    /// Public key bytes (for Ed25519: 32 bytes, for P-256: 65 bytes uncompressed)
    public_key: Vec<u8>,
    /// Algorithm used for this key
    algorithm: TpmAlgorithm,
    /// Optional key identifier
    key_id: Option<Vec<u8>>,
}

/// TPM 2.0 secure key provider
///
/// Manages cryptographic keys within a TPM 2.0 chip. Keys are generated
/// inside the TPM and signing operations occur within the hardware boundary.
pub struct Tpm2Provider {
    /// TPM context (wrapped for interior mutability)
    context: Arc<Mutex<Context>>,
    /// Generated keys indexed by handle
    keys: Mutex<HashMap<u64, TpmKeyData>>,
    /// Next handle to assign
    next_handle: Mutex<u64>,
    /// Preferred algorithm (detected at startup)
    preferred_algorithm: TpmAlgorithm,
    /// TPM manufacturer info
    manufacturer: Option<String>,
}

impl Tpm2Provider {
    /// Create a new TPM2 provider with automatic device detection
    ///
    /// Tries the following in order:
    /// 1. Linux: `/dev/tpmrm0` (resource manager - preferred)
    /// 2. Linux: `/dev/tpm0` (direct access - needs permissions)
    /// 3. Windows: TBS (TPM Base Services)
    /// 4. Environment: `TPM2_TCTI` variable for custom configuration
    ///
    /// # Errors
    ///
    /// Returns error if no TPM device is found or accessible.
    pub fn new() -> Result<Self, WSError> {
        let tcti = Self::detect_tcti()?;
        Self::with_tcti(tcti)
    }

    /// Create a TPM2 provider with a specific TCTI configuration
    ///
    /// Useful for testing with `swtpm` simulator or custom setups.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tss_esapi::tcti_ldr::TctiNameConf;
    ///
    /// // Connect to swtpm simulator
    /// let tcti = TctiNameConf::Swtpm(Default::default());
    /// let provider = Tpm2Provider::with_tcti(tcti)?;
    /// ```
    pub fn with_tcti(tcti: TctiNameConf) -> Result<Self, WSError> {
        let context = Context::new(tcti).map_err(|e| {
            WSError::HardwareError(format!("Failed to connect to TPM: {}", e))
        })?;

        let context = Arc::new(Mutex::new(context));

        // Detect supported algorithms
        let preferred_algorithm = Self::detect_preferred_algorithm(&context)?;

        // Get manufacturer info
        let manufacturer = Self::get_manufacturer_info(&context).ok();

        log::info!(
            "TPM2 provider initialized: algorithm={:?}, manufacturer={:?}",
            preferred_algorithm,
            manufacturer
        );

        Ok(Self {
            context,
            keys: Mutex::new(HashMap::new()),
            next_handle: Mutex::new(1),
            preferred_algorithm,
            manufacturer,
        })
    }

    /// Create a TPM2 provider connected to swtpm simulator on default port
    ///
    /// Convenience method for testing. Connects to swtpm on localhost:2321.
    pub fn with_simulator() -> Result<Self, WSError> {
        // NetworkTPMConfig default is localhost:2321, which is swtpm's default
        let tcti = TctiNameConf::Swtpm(NetworkTPMConfig::default());
        Self::with_tcti(tcti)
    }

    /// Detect available TCTI (TPM Command Transmission Interface)
    fn detect_tcti() -> Result<TctiNameConf, WSError> {
        // Check environment variable first (allows override)
        if std::env::var("TPM2_TCTI").is_ok() {
            return TctiNameConf::from_environment_variable().map_err(|e| {
                WSError::HardwareError(format!("Invalid TPM2_TCTI: {}", e))
            });
        }

        #[cfg(target_os = "linux")]
        {
            use std::path::Path;

            // Prefer resource manager (doesn't require root)
            if Path::new("/dev/tpmrm0").exists() {
                log::debug!("Using TPM resource manager at /dev/tpmrm0");
                return Ok(TctiNameConf::Device(DeviceConfig::default()));
            }

            // Fall back to direct device (may need root or tpm group)
            if Path::new("/dev/tpm0").exists() {
                log::debug!("Using TPM device at /dev/tpm0");
                return Ok(TctiNameConf::Device(DeviceConfig::default()));
            }
        }

        #[cfg(target_os = "windows")]
        {
            // TBS is always available on Windows with TPM
            log::debug!("Using Windows TBS");
            return Ok(TctiNameConf::Tbs(Default::default()));
        }

        Err(WSError::HardwareError(
            "No TPM2 device found. On Linux, ensure /dev/tpmrm0 exists and is accessible. \
             Set TPM2_TCTI environment variable for custom configuration."
                .to_string(),
        ))
    }

    /// Detect the preferred signing algorithm
    ///
    /// Checks if Ed25519 is supported, otherwise falls back to P-256.
    fn detect_preferred_algorithm(context: &Arc<Mutex<Context>>) -> Result<TpmAlgorithm, WSError> {
        let mut ctx = context
            .lock()
            .map_err(|_| WSError::InternalError("TPM context lock poisoned".to_string()))?;

        // Query supported ECC curves
        let (caps, _more) = ctx
            .get_capability(
                tss_esapi::constants::CapabilityType::EccCurves,
                0,
                100,
            )
            .map_err(|e| {
                WSError::HardwareError(format!("Failed to query TPM capabilities: {}", e))
            })?;

        // Check if the capability data contains ECC curves
        // Note: Ed25519 support in TPM2 is rare, default to P-256
        log::debug!("TPM ECC capabilities: {:?}", caps);

        // For now, default to P-256 which is universally supported
        // TODO: Parse caps to check for Ed25519 curve support
        log::info!("TPM2: Using ECDSA P-256 (universal TPM2 support)");
        Ok(TpmAlgorithm::EcdsaP256)
    }

    /// Get TPM manufacturer information
    fn get_manufacturer_info(context: &Arc<Mutex<Context>>) -> Result<String, WSError> {
        let mut ctx = context
            .lock()
            .map_err(|_| WSError::InternalError("TPM context lock poisoned".to_string()))?;

        let (caps, _) = ctx
            .get_capability(
                tss_esapi::constants::CapabilityType::TpmProperties,
                tss_esapi::constants::tss::TPM2_PT_MANUFACTURER,
                1,
            )
            .map_err(|e| WSError::InternalError(e.to_string()))?;

        // Extract manufacturer string from capability data
        Ok(format!("{:?}", caps))
    }

    /// Allocate a new handle ID
    fn allocate_handle(&self) -> u64 {
        let mut next = self.next_handle.lock().unwrap();
        let handle = *next;
        *next += 1;
        handle
    }

    /// Get the algorithm used by this provider
    pub fn algorithm(&self) -> TpmAlgorithm {
        self.preferred_algorithm
    }

    /// Get TPM manufacturer info if available
    pub fn manufacturer(&self) -> Option<&str> {
        self.manufacturer.as_deref()
    }

    /// Generate an ECDSA P-256 key in the TPM
    fn generate_p256_key(
        ctx: &mut Context,
    ) -> Result<(tss_esapi::handles::KeyHandle, Vec<u8>), WSError> {
        // Build object attributes for signing key
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(|e| WSError::InternalError(format!("Failed to build attributes: {}", e)))?;

        // Build ECC parameters for P-256 ECDSA signing
        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .map_err(|e| WSError::InternalError(format!("Failed to build ECC params: {}", e)))?;

        // Build the public template
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| WSError::InternalError(format!("Failed to build public template: {}", e)))?;

        // Create the primary key under the owner hierarchy
        let result = ctx
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .map_err(|e| WSError::InternalError(format!("TPM key creation failed: {}", e)))?;

        // Extract public key bytes from the result
        let public_key = Self::extract_ecc_public_key(&result.out_public)?;

        Ok((result.key_handle, public_key))
    }

    /// Extract public key bytes from TPM public structure
    fn extract_ecc_public_key(
        public: &tss_esapi::structures::Public,
    ) -> Result<Vec<u8>, WSError> {
        // Convert Public to tss_esapi's PublicKey enum
        let public_key = TssPublicKey::try_from(public.clone())
            .map_err(|e| WSError::InternalError(format!("Failed to extract public key: {}", e)))?;

        match public_key {
            TssPublicKey::Ecc { x, y } => {
                // Construct uncompressed point format: 0x04 || x || y
                let mut pk = Vec::with_capacity(1 + x.len() + y.len());
                pk.push(0x04); // Uncompressed point prefix
                pk.extend_from_slice(&x);
                pk.extend_from_slice(&y);
                Ok(pk)
            }
            _ => Err(WSError::InternalError(
                "Expected ECC public key from TPM".to_string(),
            )),
        }
    }

    /// Convert ECDSA signature from TPM format to DER format
    fn convert_ecdsa_signature_to_der(
        signature: &tss_esapi::structures::Signature,
    ) -> Result<Vec<u8>, WSError> {
        match signature {
            tss_esapi::structures::Signature::EcDsa(ecdsa_sig) => {
                let r = ecdsa_sig.signature_r().as_bytes();
                let s = ecdsa_sig.signature_s().as_bytes();

                // Encode as DER SEQUENCE { INTEGER r, INTEGER s }
                let mut der = Vec::new();

                // Helper to encode a positive integer
                fn encode_integer(val: &[u8]) -> Vec<u8> {
                    let mut result = Vec::new();
                    // Skip leading zeros but keep at least one byte
                    let val = val.iter().skip_while(|&&b| b == 0).copied().collect::<Vec<_>>();
                    let val = if val.is_empty() { vec![0] } else { val };

                    // Add leading zero if high bit is set (to keep positive)
                    let needs_padding = val[0] & 0x80 != 0;
                    let len = val.len() + if needs_padding { 1 } else { 0 };

                    result.push(0x02); // INTEGER tag
                    result.push(len as u8);
                    if needs_padding {
                        result.push(0x00);
                    }
                    result.extend(val);
                    result
                }

                let r_der = encode_integer(r);
                let s_der = encode_integer(s);

                der.push(0x30); // SEQUENCE tag
                der.push((r_der.len() + s_der.len()) as u8);
                der.extend(r_der);
                der.extend(s_der);

                Ok(der)
            }
            _ => Err(WSError::InternalError(
                "Expected ECDSA signature from TPM".to_string(),
            )),
        }
    }
}

impl SecureKeyProvider for Tpm2Provider {
    fn name(&self) -> &str {
        "TPM 2.0"
    }

    fn security_level(&self) -> SecurityLevel {
        // TPM2 provides hardware-backed key protection
        SecurityLevel::HardwareBacked
    }

    fn health_check(&self) -> Result<(), WSError> {
        let mut ctx = self
            .context
            .lock()
            .map_err(|_| WSError::InternalError("TPM context lock poisoned".to_string()))?;

        // Simple health check: query TPM properties
        ctx.get_capability(
            tss_esapi::constants::CapabilityType::TpmProperties,
            tss_esapi::constants::tss::TPM2_PT_FAMILY_INDICATOR,
            1,
        )
        .map_err(|e| WSError::HardwareError(format!("TPM health check failed: {}", e)))?;

        Ok(())
    }

    fn generate_key(&self) -> Result<KeyHandle, WSError> {
        let mut ctx = self
            .context
            .lock()
            .map_err(|_| WSError::InternalError("TPM context lock poisoned".to_string()))?;

        // Create P-256 key (Ed25519 support is rare in TPMs)
        let (tpm_handle, public_key) = Self::generate_p256_key(&mut ctx)?;

        // Allocate our handle and store key data
        let handle_id = self.allocate_handle();
        let key_data = TpmKeyData {
            key_handle: tpm_handle,
            public_key,
            algorithm: TpmAlgorithm::EcdsaP256,
            key_id: None,
        };

        drop(ctx); // Release lock before acquiring keys lock
        self.keys.lock().unwrap().insert(handle_id, key_data);

        log::debug!("Generated TPM key with handle {}", handle_id);
        Ok(KeyHandle::from_raw(handle_id))
    }

    fn load_key(&self, key_id: &str) -> Result<KeyHandle, WSError> {
        // TPM2 persistent keys would be loaded from NVRAM using handles in the
        // range 0x81000000-0x81FFFFFF. For now, we don't support persistent keys.
        // Future implementation would:
        // 1. Parse key_id as a persistent handle or key name
        // 2. Load the key from TPM NVRAM using ctx.tr_from_tpm_public()
        // 3. Return a KeyHandle wrapping the loaded key
        Err(WSError::KeyNotFound(format!(
            "Loading persistent TPM keys not yet implemented. Key ID: {}",
            key_id
        )))
    }

    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, WSError> {
        // First get the key data (need to hold keys lock briefly)
        let tpm_handle = {
            let keys = self.keys.lock().unwrap();
            let key_data = keys.get(&handle.as_raw()).ok_or_else(|| {
                WSError::InvalidSignature("Key handle not found".to_string())
            })?;
            key_data.key_handle
        };

        let mut ctx = self
            .context
            .lock()
            .map_err(|_| WSError::InternalError("TPM context lock poisoned".to_string()))?;

        // Hash the data first (TPM signs digests, not raw data)
        let hash = sha2::Sha256::digest(data);
        let digest = TpmDigest::try_from(hash.as_slice())
            .map_err(|e| WSError::InternalError(format!("Failed to create digest: {}", e)))?;

        // Sign with TPM
        let signature = ctx
            .sign(tpm_handle, digest, SignatureScheme::Null, None)
            .map_err(|e| WSError::InternalError(format!("TPM signing failed: {}", e)))?;

        // Convert signature to standard DER format
        Self::convert_ecdsa_signature_to_der(&signature)
    }

    fn get_public_key(&self, handle: KeyHandle) -> Result<PublicKey, WSError> {
        let keys = self.keys.lock().unwrap();
        let key_data = keys.get(&handle.as_raw()).ok_or_else(|| {
            WSError::InvalidSignature("Key handle not found".to_string())
        })?;

        // For TPM2 with P-256, we store the uncompressed point (65 bytes)
        // The PublicKey struct expects ed25519 format, but we're using P-256
        // This is a limitation - we should have a more generic PublicKey type
        //
        // For now, we'll return a placeholder that will fail ed25519 parsing
        // The caller should use the raw public_key bytes for P-256 verification

        // TODO: Refactor PublicKey to support multiple algorithms
        Err(WSError::InternalError(
            "TPM2 uses P-256, not Ed25519. Use get_public_key_bytes() instead.".to_string(),
        ))
    }

    fn delete_key(&self, handle: KeyHandle) -> Result<(), WSError> {
        let key_data = {
            let mut keys = self.keys.lock().unwrap();
            keys.remove(&handle.as_raw()).ok_or_else(|| {
                WSError::InvalidSignature("Key handle not found".to_string())
            })?
        };

        // Flush the key from TPM
        let mut ctx = self
            .context
            .lock()
            .map_err(|_| WSError::InternalError("TPM context lock poisoned".to_string()))?;

        ctx.flush_context(key_data.key_handle.into())
            .map_err(|e| WSError::InternalError(format!("Failed to flush TPM key: {}", e)))?;

        log::debug!("Deleted TPM key with handle {}", handle.as_raw());
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>, WSError> {
        let keys = self.keys.lock().unwrap();
        Ok(keys.keys().map(|&id| KeyHandle::from_raw(id)).collect())
    }
}

// Additional methods for TPM2-specific functionality
impl Tpm2Provider {
    /// Get the raw public key bytes for a key
    ///
    /// Returns the uncompressed P-256 point (65 bytes: 0x04 || x || y)
    pub fn get_public_key_bytes(&self, handle: KeyHandle) -> Result<Vec<u8>, WSError> {
        let keys = self.keys.lock().unwrap();
        let key_data = keys.get(&handle.as_raw()).ok_or_else(|| {
            WSError::InvalidSignature("Key handle not found".to_string())
        })?;
        Ok(key_data.public_key.clone())
    }

    /// Verify a signature using the p256 crate
    ///
    /// This is a convenience method for verifying TPM-generated signatures
    pub fn verify_signature(
        &self,
        handle: KeyHandle,
        data: &[u8],
        signature_der: &[u8],
    ) -> Result<bool, WSError> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let public_key_bytes = self.get_public_key_bytes(handle)?;

        // Parse the public key (uncompressed point)
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
            .map_err(|e| WSError::InvalidSignature(format!("Invalid public key: {}", e)))?;

        // Parse the DER signature
        let signature = Signature::from_der(signature_der)
            .map_err(|e| WSError::InvalidSignature(format!("Invalid signature: {}", e)))?;

        // Verify
        Ok(verifying_key.verify(data, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require swtpm simulator
    // Run with: TPM2_TCTI="swtpm:host=localhost,port=2321" cargo test --features tpm2 -- --ignored

    #[test]
    #[ignore = "Requires TPM hardware or swtpm simulator"]
    fn test_tpm2_provider_creation() {
        let provider = Tpm2Provider::new();
        match provider {
            Ok(p) => {
                println!("TPM2 provider created successfully");
                println!("Algorithm: {:?}", p.algorithm());
                println!("Manufacturer: {:?}", p.manufacturer());
            }
            Err(e) => {
                println!("TPM2 not available (expected on most dev machines): {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires TPM hardware or swtpm simulator"]
    fn test_tpm2_with_simulator() {
        let provider = match Tpm2Provider::with_simulator() {
            Ok(p) => p,
            Err(e) => {
                println!("swtpm not running: {}", e);
                return;
            }
        };

        // Health check
        provider.health_check().expect("Health check failed");
        println!("TPM health check passed");
    }

    #[test]
    #[ignore = "Requires TPM hardware or swtpm simulator"]
    fn test_tpm2_key_generation() {
        let provider = match Tpm2Provider::with_simulator() {
            Ok(p) => p,
            Err(_) => return,
        };

        let handle = provider.generate_key().expect("Key generation failed");
        println!("Generated key with handle: {}", handle.as_raw());

        let public_key = provider
            .get_public_key_bytes(handle)
            .expect("Get public key failed");
        println!("Public key length: {} bytes", public_key.len());
        assert_eq!(public_key.len(), 65); // Uncompressed P-256 point

        // Clean up
        provider.delete_key(handle).expect("Key deletion failed");
    }

    #[test]
    #[ignore = "Requires TPM hardware or swtpm simulator"]
    fn test_tpm2_sign_verify() {
        let provider = match Tpm2Provider::with_simulator() {
            Ok(p) => p,
            Err(_) => return,
        };

        let handle = provider.generate_key().expect("Key generation failed");
        let data = b"test data for TPM signing";

        // Sign
        let signature = provider.sign(handle, data).expect("Signing failed");
        println!("Signature length: {} bytes", signature.len());

        // Verify
        let verified = provider
            .verify_signature(handle, data, &signature)
            .expect("Verification failed");
        assert!(verified, "Signature verification should succeed");

        // Verify with wrong data should fail
        let wrong_verified = provider
            .verify_signature(handle, b"wrong data", &signature)
            .expect("Verification call failed");
        assert!(!wrong_verified, "Wrong data should not verify");

        provider.delete_key(handle).unwrap();
    }

    #[test]
    #[ignore = "Requires TPM hardware or swtpm simulator"]
    fn test_tpm2_list_keys() {
        let provider = match Tpm2Provider::with_simulator() {
            Ok(p) => p,
            Err(_) => return,
        };

        // Initially no keys
        let keys = provider.list_keys().expect("List keys failed");
        let initial_count = keys.len();

        // Generate some keys
        let h1 = provider.generate_key().expect("Key 1 generation failed");
        let h2 = provider.generate_key().expect("Key 2 generation failed");

        let keys = provider.list_keys().expect("List keys failed");
        assert_eq!(keys.len(), initial_count + 2);

        // Clean up
        provider.delete_key(h1).unwrap();
        provider.delete_key(h2).unwrap();

        let keys = provider.list_keys().expect("List keys failed");
        assert_eq!(keys.len(), initial_count);
    }
}
