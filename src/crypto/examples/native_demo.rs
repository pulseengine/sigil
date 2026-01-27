//! Native demo using WIT bindings for hardware-signing interface
//!
//! This demonstrates using `crypto_provider_bindings_host` - the native
//! bindings generated from the WIT interface - to build a native application
//! with the same API as the WASM component.

use crypto_provider_bindings::exports::wsc::crypto::hardware_signing::{
    Guest, HardwareError, KeyHandle, PublicKeyInfo, SecurityLevel, SigningAlgorithm,
    BackendInfo,
};

use std::sync::OnceLock;
use wsc::platform::software::SoftwareProvider;
use wsc::platform::{SecureKeyProvider, SecurityLevel as WscSecurityLevel};

// Global provider instance (same pattern as WASM component)
static PROVIDER: OnceLock<SoftwareProvider> = OnceLock::new();

fn get_provider() -> &'static SoftwareProvider {
    PROVIDER.get_or_init(SoftwareProvider::new)
}

fn convert_security_level(level: WscSecurityLevel) -> SecurityLevel {
    match level {
        WscSecurityLevel::Software => SecurityLevel::Software,
        WscSecurityLevel::HardwareBasic => SecurityLevel::HardwareBasic,
        WscSecurityLevel::HardwareBacked => SecurityLevel::HardwareBacked,
        WscSecurityLevel::HardwareCertified => SecurityLevel::HardwareCertified,
    }
}

/// Native implementation of the Guest trait
/// This is the same implementation as the WASM component, but using native bindings
struct NativeCryptoProvider;

impl Guest for NativeCryptoProvider {
    fn is_available() -> bool {
        true
    }

    fn get_backend_info() -> Result<BackendInfo, HardwareError> {
        let provider = get_provider();
        Ok(BackendInfo {
            name: provider.name().to_string(),
            level: convert_security_level(provider.security_level()),
            algorithms: vec![SigningAlgorithm::Ed25519],
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
        _usage: u8,
        _key_id: Option<String>,
    ) -> Result<KeyHandle, HardwareError> {
        if !matches!(algorithm, SigningAlgorithm::Ed25519) {
            return Err(HardwareError::UnsupportedAlgorithm(
                "Only Ed25519 is supported".to_string(),
            ));
        }

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

        Ok(PublicKeyInfo {
            handle,
            algorithm: SigningAlgorithm::Ed25519,
            public_key_der: public_key.to_der(),
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
        if !matches!(algorithm, SigningAlgorithm::Ed25519) {
            return Err(HardwareError::UnsupportedAlgorithm(
                "Only Ed25519 is supported".to_string(),
            ));
        }

        let public_key = wsc::PublicKey::from_der(&public_key_der).map_err(|e| {
            HardwareError::SigningFailed(format!("Invalid public key: {}", e))
        })?;

        // Use the inner ed25519_compact::PublicKey directly
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

// Key usage flags
const KEY_USAGE_SIGN: u8 = 0x01;
#[allow(dead_code)]
const KEY_USAGE_VERIFY: u8 = 0x02;

fn main() {
    println!("=== Native Crypto Provider Demo ===\n");

    // Check availability
    println!("Provider available: {}", NativeCryptoProvider::is_available());

    // Get backend info
    match NativeCryptoProvider::get_backend_info() {
        Ok(info) => {
            println!("Backend: {}", info.name);
            println!("Security level: {:?}", info.level);
            println!("Algorithms: {:?}", info.algorithms);
        }
        Err(e) => println!("Error getting backend info: {:?}", e),
    }

    println!("\n--- Key Generation ---");

    // Generate a key
    let handle = match NativeCryptoProvider::generate_key(
        SigningAlgorithm::Ed25519,
        KEY_USAGE_SIGN,
        Some("demo-key".to_string()),
    ) {
        Ok(h) => {
            println!("Generated key with handle: {}", h);
            h
        }
        Err(e) => {
            println!("Error generating key: {:?}", e);
            return;
        }
    };

    // Get public key
    match NativeCryptoProvider::get_public_key(handle) {
        Ok(info) => {
            println!("Public key (DER): {} bytes", info.public_key_der.len());
            println!("Algorithm: {:?}", info.algorithm);
        }
        Err(e) => println!("Error getting public key: {:?}", e),
    }

    println!("\n--- Signing ---");

    let message = b"Hello from native WIT bindings!".to_vec();
    println!("Message: {:?}", String::from_utf8_lossy(&message));

    let signature = match NativeCryptoProvider::sign(handle, message.clone()) {
        Ok(sig) => {
            println!("Signature: {} bytes", sig.len());
            println!("Signature (hex): {}", hex::encode(&sig));
            sig
        }
        Err(e) => {
            println!("Error signing: {:?}", e);
            return;
        }
    };

    println!("\n--- Verification ---");

    // Get public key for verification
    let pub_key_info = NativeCryptoProvider::get_public_key(handle).unwrap();

    match NativeCryptoProvider::verify(
        pub_key_info.public_key_der,
        SigningAlgorithm::Ed25519,
        message.clone(),
        signature.clone(),
    ) {
        Ok(valid) => println!("Signature valid: {}", valid),
        Err(e) => println!("Error verifying: {:?}", e),
    }

    // Try with wrong message
    let wrong_message = b"Wrong message".to_vec();
    match NativeCryptoProvider::verify(
        NativeCryptoProvider::get_public_key(handle).unwrap().public_key_der,
        SigningAlgorithm::Ed25519,
        wrong_message,
        signature,
    ) {
        Ok(valid) => println!("Wrong message signature valid: {} (expected false)", valid),
        Err(e) => println!("Error verifying: {:?}", e),
    }

    println!("\n--- Cleanup ---");

    // List keys
    match NativeCryptoProvider::list_keys() {
        Ok(keys) => println!("Keys before delete: {:?}", keys),
        Err(e) => println!("Error listing keys: {:?}", e),
    }

    // Delete key
    match NativeCryptoProvider::delete_key(handle) {
        Ok(()) => println!("Key deleted successfully"),
        Err(e) => println!("Error deleting key: {:?}", e),
    }

    // List keys again
    match NativeCryptoProvider::list_keys() {
        Ok(keys) => println!("Keys after delete: {:?}", keys),
        Err(e) => println!("Error listing keys: {:?}", e),
    }

    println!("\n=== Demo Complete ===");
}
