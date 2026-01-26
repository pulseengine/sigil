//! Host implementation of wsc:crypto WIT interface.
//!
//! This module provides the wasmtime host bindings that bridge the
//! `wsc:crypto/hardware-signing` WIT interface to our `SecureKeyProvider` trait.

use crate::error::WSError;
use crate::platform::{KeyHandle, SecureKeyProvider, SecurityLevel};
use std::sync::Arc;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};

// Generate host bindings from WIT
wasmtime::component::bindgen!({
    path: "../../wit/deps/wsc-crypto",
    world: "crypto-guest",
    async: false,
});

/// State held by the wasmtime Store for crypto operations.
pub struct CryptoHostState<P: SecureKeyProvider> {
    /// The crypto provider (TPM, HSM, software, etc.)
    provider: Arc<P>,
    /// Resource table for wasmtime component model
    pub table: ResourceTable,
}

impl<P: SecureKeyProvider> CryptoHostState<P> {
    /// Create new host state with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            table: ResourceTable::new(),
        }
    }

    /// Get a reference to the crypto provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

// Map our SecurityLevel to the WIT SecurityLevel
fn to_wit_security_level(level: SecurityLevel) -> wsc::crypto::hardware_signing::SecurityLevel {
    match level {
        SecurityLevel::Software => wsc::crypto::hardware_signing::SecurityLevel::Software,
        SecurityLevel::HardwareBasic => wsc::crypto::hardware_signing::SecurityLevel::HardwareBasic,
        SecurityLevel::HardwareBacked => wsc::crypto::hardware_signing::SecurityLevel::HardwareBacked,
        SecurityLevel::HardwareCertified => wsc::crypto::hardware_signing::SecurityLevel::HardwareCertified,
    }
}

// Implement the WIT hardware-signing interface for our host state
impl<P: SecureKeyProvider + 'static> wsc::crypto::hardware_signing::Host for CryptoHostState<P> {
    fn is_available(&mut self) -> bool {
        self.provider.health_check().is_ok()
    }

    fn get_backend_info(&mut self) -> Result<wsc::crypto::hardware_signing::BackendInfo, wsc::crypto::hardware_signing::HardwareError> {
        Ok(wsc::crypto::hardware_signing::BackendInfo {
            name: self.provider.name().to_string(),
            level: to_wit_security_level(self.provider.security_level()),
            algorithms: vec![wsc::crypto::hardware_signing::SigningAlgorithm::Ed25519],
            manufacturer: None,
            firmware_version: None,
        })
    }

    fn get_security_level(&mut self) -> wsc::crypto::hardware_signing::SecurityLevel {
        to_wit_security_level(self.provider.security_level())
    }

    fn generate_key(
        &mut self,
        algorithm: wsc::crypto::hardware_signing::SigningAlgorithm,
        _usage: u8,
        _key_id: Option<String>,
    ) -> Result<u64, wsc::crypto::hardware_signing::HardwareError> {
        // Currently we only support Ed25519
        if algorithm != wsc::crypto::hardware_signing::SigningAlgorithm::Ed25519 {
            return Err(wsc::crypto::hardware_signing::HardwareError::UnsupportedAlgorithm(
                format!("Only Ed25519 is currently supported, got {:?}", algorithm)
            ));
        }

        self.provider
            .generate_key()
            .map(|h| h.as_raw())
            .map_err(|e| wsc::crypto::hardware_signing::HardwareError::GenerationFailed(e.to_string()))
    }

    fn sign(
        &mut self,
        handle: u64,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, wsc::crypto::hardware_signing::HardwareError> {
        let key_handle = KeyHandle::from_raw(handle);

        self.provider
            .sign(key_handle, &data)
            .map_err(|e| wsc::crypto::hardware_signing::HardwareError::SigningFailed(e.to_string()))
    }

    fn get_public_key(
        &mut self,
        handle: u64,
    ) -> Result<wsc::crypto::hardware_signing::PublicKeyInfo, wsc::crypto::hardware_signing::HardwareError> {
        let key_handle = KeyHandle::from_raw(handle);

        let public_key = self.provider
            .get_public_key(key_handle)
            .map_err(|e| wsc::crypto::hardware_signing::HardwareError::KeyNotFound(e.to_string()))?;

        // Get raw public key bytes (32 bytes for Ed25519)
        let public_key_der = public_key.pk.as_ref().to_vec();

        Ok(wsc::crypto::hardware_signing::PublicKeyInfo {
            handle,
            algorithm: wsc::crypto::hardware_signing::SigningAlgorithm::Ed25519,
            public_key_der,
            // Convert key_id from Option<Vec<u8>> to Option<String>
            key_id: public_key.key_id.and_then(|bytes| String::from_utf8(bytes).ok()),
        })
    }

    fn verify(
        &mut self,
        public_key_der: Vec<u8>,
        algorithm: wsc::crypto::hardware_signing::SigningAlgorithm,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, wsc::crypto::hardware_signing::HardwareError> {
        if algorithm != wsc::crypto::hardware_signing::SigningAlgorithm::Ed25519 {
            return Err(wsc::crypto::hardware_signing::HardwareError::UnsupportedAlgorithm(
                format!("Only Ed25519 is currently supported, got {:?}", algorithm)
            ));
        }

        // Parse public key
        let pk = ed25519_compact::PublicKey::from_slice(&public_key_der)
            .map_err(|e| wsc::crypto::hardware_signing::HardwareError::InvalidHandle(
                format!("Invalid public key: {}", e)
            ))?;

        // Parse signature
        let sig = ed25519_compact::Signature::from_slice(&signature)
            .map_err(|e| wsc::crypto::hardware_signing::HardwareError::InvalidHandle(
                format!("Invalid signature: {}", e)
            ))?;

        // Verify
        Ok(pk.verify(&data, &sig).is_ok())
    }

    fn delete_key(&mut self, handle: u64) -> Result<(), wsc::crypto::hardware_signing::HardwareError> {
        let key_handle = KeyHandle::from_raw(handle);

        self.provider
            .delete_key(key_handle)
            .map_err(|e| wsc::crypto::hardware_signing::HardwareError::KeyNotFound(e.to_string()))
    }

    fn list_keys(&mut self) -> Result<Vec<u64>, wsc::crypto::hardware_signing::HardwareError> {
        self.provider
            .list_keys()
            .map(|handles| handles.into_iter().map(|h| h.as_raw()).collect())
            .map_err(|e| wsc::crypto::hardware_signing::HardwareError::NotAvailable(e.to_string()))
    }
}

/// WSC Runtime for hosting WASM components with hardware crypto.
///
/// This runtime provides a wasmtime-based execution environment that
/// implements the `wsc:crypto` WIT interface, allowing WASM components
/// to access hardware-backed cryptographic operations.
pub struct WscRuntime<P: SecureKeyProvider + 'static> {
    engine: Engine,
    linker: Linker<CryptoHostState<P>>,
}

impl<P: SecureKeyProvider + Send + Sync + 'static> WscRuntime<P> {
    /// Create a new runtime.
    pub fn new() -> Result<Self, WSError> {
        let mut config = Config::new();
        config.wasm_component_model(true);

        let engine = Engine::new(&config)
            .map_err(|e| WSError::InternalError(format!("Failed to create wasmtime engine: {}", e)))?;

        let mut linker = Linker::new(&engine);

        // Add wsc:crypto imports to the linker
        CryptoGuest::add_to_linker(&mut linker, |state| state)
            .map_err(|e| WSError::InternalError(format!("Failed to add crypto bindings: {}", e)))?;

        Ok(Self { engine, linker })
    }

    /// Get a reference to the wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Load a WASM component from bytes.
    pub fn load_component(&self, bytes: &[u8]) -> Result<Component, WSError> {
        Component::from_binary(&self.engine, bytes)
            .map_err(|e| WSError::InternalError(format!("Failed to load component: {}", e)))
    }

    /// Create a store with the given crypto provider.
    pub fn create_store(&self, provider: P) -> Store<CryptoHostState<P>> {
        Store::new(&self.engine, CryptoHostState::new(provider))
    }

    /// Instantiate a component in a store.
    pub fn instantiate(
        &self,
        store: &mut Store<CryptoHostState<P>>,
        component: &Component,
    ) -> Result<CryptoGuest, WSError> {
        CryptoGuest::instantiate(store, component, &self.linker)
            .map_err(|e| WSError::InternalError(format!("Failed to instantiate component: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::software::SoftwareProvider;

    #[test]
    fn test_crypto_host_state_creation() {
        let provider = SoftwareProvider::new();
        let state = CryptoHostState::new(provider);
        assert_eq!(state.provider().name(), "Software (Development Only)");
    }

    #[test]
    fn test_runtime_creation() {
        let runtime: WscRuntime<SoftwareProvider> = WscRuntime::new().unwrap();
        let _ = runtime.engine();
    }

    #[test]
    fn test_host_trait_implementation() {
        let provider = SoftwareProvider::new();
        let mut state = CryptoHostState::new(provider);

        // Test is_available
        assert!(wsc::crypto::hardware_signing::Host::is_available(&mut state));

        // Test get_security_level
        let level = wsc::crypto::hardware_signing::Host::get_security_level(&mut state);
        assert_eq!(level, wsc::crypto::hardware_signing::SecurityLevel::Software);

        // Test generate_key
        let handle = wsc::crypto::hardware_signing::Host::generate_key(
            &mut state,
            wsc::crypto::hardware_signing::SigningAlgorithm::Ed25519,
            0x01, // sign usage
            Some("test-key".to_string()),
        ).unwrap();
        assert!(handle > 0);

        // Test sign
        let data = b"test data to sign".to_vec();
        let signature = wsc::crypto::hardware_signing::Host::sign(&mut state, handle, data.clone()).unwrap();
        assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes

        // Test get_public_key
        let pk_info = wsc::crypto::hardware_signing::Host::get_public_key(&mut state, handle).unwrap();
        assert_eq!(pk_info.handle, handle);
        assert_eq!(pk_info.public_key_der.len(), 32); // Ed25519 public key is 32 bytes

        // Test verify
        let verified = wsc::crypto::hardware_signing::Host::verify(
            &mut state,
            pk_info.public_key_der,
            wsc::crypto::hardware_signing::SigningAlgorithm::Ed25519,
            data,
            signature,
        ).unwrap();
        assert!(verified);

        // Test list_keys
        let keys = wsc::crypto::hardware_signing::Host::list_keys(&mut state).unwrap();
        assert!(keys.contains(&handle));

        // Test delete_key
        wsc::crypto::hardware_signing::Host::delete_key(&mut state, handle).unwrap();
        let keys = wsc::crypto::hardware_signing::Host::list_keys(&mut state).unwrap();
        assert!(!keys.contains(&handle));
    }
}
