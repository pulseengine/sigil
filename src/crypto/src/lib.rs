//! Hardware-backed cryptographic operations provider
//!
//! This component exports the `wsc:crypto/hardware-signing` interface,
//! delegating to wsc's platform module for the actual cryptographic operations.
//!
//! # Generated Bindings
//!
//! `rust_wasm_component_bindgen` generates:
//! - `crypto_provider_bindings` - WASM bindings (for component)
//! - `crypto_provider_bindings_host` - Native bindings (for native builds)
//!
//! The `Guest` trait from the bindings is implemented here.

// Only compile for wasm32 OR native (via bindings_host)
// The native-guest bindings provide a no-op export! macro

use crypto_provider_bindings::exports::wsc::crypto::hardware_signing::{
    Guest, HardwareError, KeyHandle, PublicKeyInfo, SecurityLevel, SigningAlgorithm,
    BackendInfo,
};

// Key usage flags (bit constants)
// These match the WIT interface definition
#[allow(dead_code)]
const KEY_USAGE_SIGN: u8 = 0x01;
#[allow(dead_code)]
const KEY_USAGE_VERIFY: u8 = 0x02;
#[allow(dead_code)]
const KEY_USAGE_EXPORTABLE: u8 = 0x04;

use std::sync::OnceLock;
use wsc::platform::software::SoftwareProvider;
use wsc::platform::{SecureKeyProvider, SecurityLevel as WscSecurityLevel};

// Global provider instance (initialized on first use)
static PROVIDER: OnceLock<SoftwareProvider> = OnceLock::new();

fn get_provider() -> &'static SoftwareProvider {
    PROVIDER.get_or_init(SoftwareProvider::new)
}

// Convert wsc SecurityLevel to WIT SecurityLevel
fn convert_security_level(level: WscSecurityLevel) -> SecurityLevel {
    match level {
        WscSecurityLevel::Software => SecurityLevel::Software,
        WscSecurityLevel::HardwareBasic => SecurityLevel::HardwareBasic,
        WscSecurityLevel::HardwareBacked => SecurityLevel::HardwareBacked,
        WscSecurityLevel::HardwareCertified => SecurityLevel::HardwareCertified,
    }
}

// Convert WIT SigningAlgorithm to wsc - currently only Ed25519 supported
fn _validate_algorithm(algorithm: SigningAlgorithm) -> Result<(), HardwareError> {
    match algorithm {
        SigningAlgorithm::Ed25519 => Ok(()),
        SigningAlgorithm::EcdsaP256 | SigningAlgorithm::EcdsaP384 => {
            Err(HardwareError::UnsupportedAlgorithm(
                "Only Ed25519 is currently supported".to_string(),
            ))
        }
    }
}

/// Component implementation
struct CryptoProviderComponent;

impl Guest for CryptoProviderComponent {
    fn is_available() -> bool {
        // Software provider is always available
        true
    }

    fn get_backend_info() -> Result<BackendInfo, HardwareError> {
        let provider = get_provider();
        Ok(BackendInfo {
            name: provider.name().to_string(),
            level: convert_security_level(provider.security_level()),
            algorithms: vec![SigningAlgorithm::Ed25519], // Currently only Ed25519
            manufacturer: None,
            firmware_version: None,
        })
    }

    fn get_security_level() -> SecurityLevel {
        let provider = get_provider();
        convert_security_level(provider.security_level())
    }

    fn generate_key(
        algorithm: SigningAlgorithm,
        _usage: u8,  // Key usage flags (KEY_USAGE_SIGN | KEY_USAGE_VERIFY | KEY_USAGE_EXPORTABLE)
        _key_id: Option<String>,
    ) -> Result<KeyHandle, HardwareError> {
        // Validate algorithm
        _validate_algorithm(algorithm)?;

        let provider = get_provider();
        let handle = provider.generate_key().map_err(|e| {
            HardwareError::GenerationFailed(format!("Key generation failed: {}", e))
        })?;

        Ok(handle.as_raw())
    }

    fn sign(handle: KeyHandle, data: Vec<u8>) -> Result<Vec<u8>, HardwareError> {
        let provider = get_provider();
        let key_handle = wsc::platform::KeyHandle::from_raw(handle);

        provider.sign(key_handle, &data).map_err(|e| {
            HardwareError::SigningFailed(format!("Signing failed: {}", e))
        })
    }

    fn get_public_key(handle: KeyHandle) -> Result<PublicKeyInfo, HardwareError> {
        let provider = get_provider();
        let key_handle = wsc::platform::KeyHandle::from_raw(handle);

        let public_key = provider.get_public_key(key_handle).map_err(|e| {
            HardwareError::KeyNotFound(format!("Failed to get public key: {}", e))
        })?;

        // Get DER-encoded public key
        let der_bytes = public_key.to_der();

        Ok(PublicKeyInfo {
            handle,
            algorithm: SigningAlgorithm::Ed25519,
            public_key_der: der_bytes,
            // Convert key_id from Vec<u8> to String (UTF-8)
            key_id: public_key.key_id.as_ref().and_then(|id| {
                String::from_utf8(id.clone()).ok()
            }),
        })
    }

    fn verify(
        public_key_der: Vec<u8>,
        algorithm: SigningAlgorithm,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, HardwareError> {
        // Validate algorithm
        _validate_algorithm(algorithm)?;

        // Parse the public key from DER
        let public_key = wsc::PublicKey::from_der(&public_key_der).map_err(|e| {
            HardwareError::SigningFailed(format!("Invalid public key: {}", e))
        })?;

        // Verify the signature using the inner ed25519_compact::PublicKey directly
        // Note: public_key.pk is the raw ed25519 key, to_bytes() adds a prefix
        use ed25519_compact::Signature;

        let sig = Signature::from_slice(&signature).map_err(|e| {
            HardwareError::SigningFailed(format!("Invalid signature format: {}", e))
        })?;

        match public_key.pk.verify(&data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn delete_key(handle: KeyHandle) -> Result<(), HardwareError> {
        let provider = get_provider();
        let key_handle = wsc::platform::KeyHandle::from_raw(handle);

        provider.delete_key(key_handle).map_err(|e| {
            HardwareError::KeyNotFound(format!("Failed to delete key: {}", e))
        })
    }

    fn list_keys() -> Result<Vec<KeyHandle>, HardwareError> {
        let provider = get_provider();

        let handles = provider.list_keys().map_err(|e| {
            HardwareError::NotAvailable(format!("Failed to list keys: {}", e))
        })?;

        Ok(handles.into_iter().map(|h| h.as_raw()).collect())
    }
}

// Export the component implementation
crypto_provider_bindings::export!(CryptoProviderComponent with_types_in crypto_provider_bindings);
