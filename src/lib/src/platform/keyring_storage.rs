/// Cross-platform keyring/keychain key storage provider
///
/// This implementation stores Ed25519 private keys in the OS credential store:
/// - **macOS**: Keychain (encrypted at rest, Touch ID optional)
/// - **Linux**: secret-service (GNOME Keyring, KDE Wallet)
/// - **Windows**: Credential Manager
///
/// # Security Level
///
/// This is `HardwareBasic` because:
/// - Keys are encrypted at rest by the OS
/// - Access can require user authentication (Touch ID, password)
/// - Keys are NOT in hardware - software Ed25519 crypto
///
/// # Architecture
///
/// ```text
/// ┌──────────────────────────────────────────────┐
/// │           KeyringProvider                     │
/// │  (SecureKeyProvider implementation)           │
/// ├──────────────────────────────────────────────┤
/// │  In-memory cache (handle → key_id mapping)    │
/// │  Software Ed25519 signing (ed25519-compact)   │
/// └─────────────────┬────────────────────────────┘
///                   │
///                   ▼
/// ┌──────────────────────────────────────────────┐
/// │           OS Credential Store                 │
/// │  (keyring crate abstraction)                  │
/// ├──────────────────────────────────────────────┤
/// │  macOS: Keychain.framework                    │
/// │  Linux: secret-service D-Bus API              │
/// │  Windows: Credential Manager                  │
/// └──────────────────────────────────────────────┘
/// ```
///
/// # Example
///
/// ```ignore
/// use wsc::platform::keyring_storage::KeyringProvider;
/// use wsc::platform::SecureKeyProvider;
///
/// let provider = KeyringProvider::new("my-app")?;
///
/// // Generate a new key (stored in OS keychain)
/// let handle = provider.generate_key()?;
///
/// // Sign data (key loaded from keychain, signing in memory)
/// let signature = provider.sign(handle, b"data to sign")?;
///
/// // Key persists across restarts
/// let handle2 = provider.load_key("key-123")?;
/// ```

use super::{Attestation, KeyHandle, SecureKeyProvider, SecurityLevel};
use crate::error::WSError;
use crate::signature::{KeyPair, PublicKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Service name prefix for keyring entries
const KEYRING_SERVICE: &str = "wsc-crypto";

/// In-memory key cache
///
/// Maps handles to (key_id, cached_keypair)
/// The keypair is cached to avoid repeated keyring lookups during signing sessions
struct KeyCache {
    next_handle: u64,
    /// Maps handle -> (key_id, keypair)
    keys: HashMap<u64, (String, KeyPair)>,
    /// Maps key_id -> handle (for load_key)
    id_to_handle: HashMap<String, u64>,
}

impl KeyCache {
    fn new() -> Self {
        KeyCache {
            next_handle: 1,
            keys: HashMap::new(),
            id_to_handle: HashMap::new(),
        }
    }

    fn insert(&mut self, key_id: String, keypair: KeyPair) -> KeyHandle {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.id_to_handle.insert(key_id.clone(), handle);
        self.keys.insert(handle, (key_id, keypair));
        KeyHandle::from_raw(handle)
    }

    fn get(&self, handle: KeyHandle) -> Option<&(String, KeyPair)> {
        self.keys.get(&handle.as_raw())
    }

    fn get_by_id(&self, key_id: &str) -> Option<KeyHandle> {
        self.id_to_handle.get(key_id).map(|&h| KeyHandle::from_raw(h))
    }

    fn remove(&mut self, handle: KeyHandle) -> Option<(String, KeyPair)> {
        if let Some((key_id, kp)) = self.keys.remove(&handle.as_raw()) {
            self.id_to_handle.remove(&key_id);
            Some((key_id, kp))
        } else {
            None
        }
    }

    fn list(&self) -> Vec<KeyHandle> {
        self.keys.keys().map(|&h| KeyHandle::from_raw(h)).collect()
    }
}

/// Cross-platform keyring provider
///
/// Stores Ed25519 keys in the OS credential store with software-based signing.
pub struct KeyringProvider {
    /// Application name (used as keyring service name)
    app_name: String,
    /// In-memory key cache
    cache: Arc<Mutex<KeyCache>>,
}

impl KeyringProvider {
    /// Create a new keyring provider
    ///
    /// # Arguments
    ///
    /// * `app_name` - Application identifier (used in keyring service name)
    ///
    /// # Returns
    ///
    /// A new `KeyringProvider` or error if keyring is unavailable
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = KeyringProvider::new("my-signing-tool")?;
    /// ```
    pub fn new(app_name: &str) -> Result<Self, WSError> {
        // Test that keyring is available by creating a test entry
        let service = format!("{}-{}", KEYRING_SERVICE, app_name);
        let entry = keyring::Entry::new(&service, "__test__")
            .map_err(|e| WSError::InternalError(format!("Keyring unavailable: {}", e)))?;

        // Try to delete any stale test entry (ignore errors)
        let _ = entry.delete_credential();

        log::info!(
            "Keyring provider initialized for '{}' - keys stored in OS credential store",
            app_name
        );

        Ok(KeyringProvider {
            app_name: app_name.to_string(),
            cache: Arc::new(Mutex::new(KeyCache::new())),
        })
    }

    /// Get the full service name for keyring entries
    fn service_name(&self) -> String {
        format!("{}-{}", KEYRING_SERVICE, self.app_name)
    }

    /// Store a secret key in the keyring
    fn store_secret_key(&self, key_id: &str, secret_bytes: &[u8]) -> Result<(), WSError> {
        let entry = keyring::Entry::new(&self.service_name(), key_id)
            .map_err(|e| WSError::InternalError(format!("Failed to create keyring entry: {}", e)))?;

        entry
            .set_secret(secret_bytes)
            .map_err(|e| WSError::InternalError(format!("Failed to store key in keyring: {}", e)))?;

        Ok(())
    }

    /// Load a secret key from the keyring
    fn load_secret_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, WSError> {
        let entry = keyring::Entry::new(&self.service_name(), key_id)
            .map_err(|e| WSError::InternalError(format!("Failed to create keyring entry: {}", e)))?;

        let secret = entry.get_secret().map_err(|e| match e {
            keyring::Error::NoEntry => {
                WSError::InternalError(format!("Key '{}' not found in keyring", key_id))
            }
            _ => WSError::InternalError(format!("Failed to load key from keyring: {}", e)),
        })?;

        Ok(Zeroizing::new(secret))
    }

    /// Delete a secret key from the keyring
    fn delete_secret_key(&self, key_id: &str) -> Result<(), WSError> {
        let entry = keyring::Entry::new(&self.service_name(), key_id)
            .map_err(|e| WSError::InternalError(format!("Failed to create keyring entry: {}", e)))?;

        entry.delete_credential().map_err(|e| match e {
            keyring::Error::NoEntry => {
                WSError::InternalError(format!("Key '{}' not found in keyring", key_id))
            }
            _ => WSError::InternalError(format!("Failed to delete key from keyring: {}", e)),
        })?;

        Ok(())
    }

    /// Generate a unique key ID
    fn generate_key_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Reconstruct a KeyPair from secret key bytes
    fn keypair_from_secret(secret_bytes: &[u8]) -> Result<KeyPair, WSError> {
        if secret_bytes.len() != 64 {
            return Err(WSError::InternalError(format!(
                "Invalid secret key length: {} (expected 64)",
                secret_bytes.len()
            )));
        }

        let sk = ed25519_compact::SecretKey::from_slice(secret_bytes)
            .map_err(|e| WSError::InternalError(format!("Invalid secret key: {}", e)))?;

        let pk = sk.public_key();

        Ok(KeyPair {
            pk: PublicKey { pk, key_id: None },
            sk: crate::signature::SecretKey { sk },
        })
    }
}

impl SecureKeyProvider for KeyringProvider {
    fn name(&self) -> &str {
        "OS Keyring (Secure Storage)"
    }

    fn security_level(&self) -> SecurityLevel {
        // HardwareBasic because keys are encrypted at rest by the OS
        // but actual crypto operations are in software
        SecurityLevel::HardwareBasic
    }

    fn health_check(&self) -> Result<(), WSError> {
        // Try to access the keyring
        let entry = keyring::Entry::new(&self.service_name(), "__health_check__")
            .map_err(|e| WSError::InternalError(format!("Keyring unavailable: {}", e)))?;

        // Clean up any stale health check entry
        let _ = entry.delete_credential();

        Ok(())
    }

    fn generate_key(&self) -> Result<KeyHandle, WSError> {
        // Generate new Ed25519 keypair
        let keypair = KeyPair::generate();
        let key_id = Self::generate_key_id();

        // Store secret key in keyring (64 bytes for ed25519-compact)
        let secret_bytes = keypair.sk.sk.as_ref();
        self.store_secret_key(&key_id, secret_bytes)?;

        log::debug!("Generated new key '{}' and stored in keyring", key_id);

        // Cache the key for fast access
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        Ok(cache.insert(key_id, keypair))
    }

    fn load_key(&self, key_id: &str) -> Result<KeyHandle, WSError> {
        // Check cache first
        {
            let cache = self
                .cache
                .lock()
                .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

            if let Some(handle) = cache.get_by_id(key_id) {
                return Ok(handle);
            }
        }

        // Load from keyring
        let secret_bytes = self.load_secret_key(key_id)?;
        let keypair = Self::keypair_from_secret(&secret_bytes)?;

        log::debug!("Loaded key '{}' from keyring", key_id);

        // Cache it
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        Ok(cache.insert(key_id.to_string(), keypair))
    }

    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, WSError> {
        let cache = self
            .cache
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        let (_, keypair) = cache
            .get(handle)
            .ok_or_else(|| WSError::InternalError("Invalid key handle".to_string()))?;

        let signature = keypair.sk.sk.sign(data, None);
        Ok(signature.to_vec())
    }

    fn get_public_key(&self, handle: KeyHandle) -> Result<PublicKey, WSError> {
        let cache = self
            .cache
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        let (_, keypair) = cache
            .get(handle)
            .ok_or_else(|| WSError::InternalError("Invalid key handle".to_string()))?;

        Ok(keypair.pk.clone())
    }

    fn attestation(&self, _handle: KeyHandle) -> Result<Option<Attestation>, WSError> {
        // Keyring-stored keys cannot provide hardware attestation
        // In the future, we could provide attestation about the keyring backend
        // (e.g., macOS Secure Enclave for key encryption)
        Ok(None)
    }

    fn delete_key(&self, handle: KeyHandle) -> Result<(), WSError> {
        // Remove from cache and get key_id
        let key_id = {
            let mut cache = self
                .cache
                .lock()
                .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

            let (key_id, _) = cache
                .remove(handle)
                .ok_or_else(|| WSError::InternalError("Invalid key handle".to_string()))?;
            key_id
        };

        // Delete from keyring
        self.delete_secret_key(&key_id)?;

        log::debug!("Deleted key '{}' from keyring", key_id);
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>, WSError> {
        let cache = self
            .cache
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        Ok(cache.list())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> KeyringProvider {
        KeyringProvider::new("test").expect("Failed to create test provider")
    }

    #[test]
    fn test_provider_creation() {
        let provider = test_provider();
        assert_eq!(provider.name(), "OS Keyring (Secure Storage)");
        assert_eq!(provider.security_level(), SecurityLevel::HardwareBasic);
    }

    #[test]
    fn test_health_check() {
        let provider = test_provider();
        assert!(provider.health_check().is_ok());
    }

    #[test]
    fn test_generate_and_sign() {
        let provider = test_provider();

        // Generate key
        let handle = provider.generate_key().expect("Failed to generate key");

        // Sign data
        let data = b"test data to sign";
        let signature = provider.sign(handle, data).expect("Failed to sign");
        assert_eq!(signature.len(), 64);

        // Verify with public key
        let public_key = provider
            .get_public_key(handle)
            .expect("Failed to get public key");

        let sig =
            ed25519_compact::Signature::from_slice(&signature).expect("Invalid signature format");
        assert!(public_key.pk.verify(data, &sig).is_ok());

        // Clean up
        provider.delete_key(handle).expect("Failed to delete key");
    }

    #[test]
    fn test_key_persistence() {
        let provider = test_provider();

        // Generate key and get its ID
        let handle1 = provider.generate_key().expect("Failed to generate key");

        // Get the key_id from cache
        let key_id = {
            let cache = provider.cache.lock().unwrap();
            let (key_id, _) = cache.get(handle1).unwrap();
            key_id.clone()
        };

        // Sign some data
        let data = b"test data";
        let sig1 = provider.sign(handle1, data).expect("Failed to sign");

        // Clear the cache (simulating restart)
        {
            let mut cache = provider.cache.lock().unwrap();
            cache.keys.clear();
            cache.id_to_handle.clear();
        }

        // Load the key by ID
        let handle2 = provider.load_key(&key_id).expect("Failed to load key");

        // Sign again
        let sig2 = provider.sign(handle2, data).expect("Failed to sign");

        // Signatures should match (same key)
        assert_eq!(sig1, sig2);

        // Clean up
        provider.delete_key(handle2).expect("Failed to delete key");
    }

    #[test]
    fn test_delete_key() {
        let provider = test_provider();

        // Generate key
        let handle = provider.generate_key().expect("Failed to generate key");

        // Get key_id
        let key_id = {
            let cache = provider.cache.lock().unwrap();
            let (key_id, _) = cache.get(handle).unwrap();
            key_id.clone()
        };

        // Delete it
        provider.delete_key(handle).expect("Failed to delete key");

        // Verify it's gone from keyring
        let result = provider.load_secret_key(&key_id);
        assert!(result.is_err());
    }
}
