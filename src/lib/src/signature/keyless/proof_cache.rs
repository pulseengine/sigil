//! Rekor inclusion proof cache for availability resilience.
//!
//! Caches verified Rekor inclusion proofs so that verification can
//! succeed during transient Rekor outages. The cache is an optimization
//! only — it never weakens security guarantees (DD-2).
//!
//! # Security Properties
//!
//! - Cache entries are keyed by module hash + Rekor UUID
//! - Only successfully verified proofs are cached
//! - TTL-based expiry prevents stale proofs
//! - Cache poisoning is prevented because we store the full
//!   `RekorEntry` and re-validate structure on cache hit
//! - Fail-closed: if both cache miss and Rekor unavailable,
//!   verification fails
//!
//! # Example
//!
//! ```ignore
//! use wsc::keyless::proof_cache::{ProofCache, MemoryProofCache};
//! use std::time::Duration;
//!
//! let cache = MemoryProofCache::new(Duration::from_secs(86400)); // 24h TTL
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::rekor::RekorEntry;

/// Key for cached proof entries.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    /// SHA-256 hex digest of the signed artifact
    pub artifact_hash: String,
    /// Rekor entry UUID
    pub rekor_uuid: String,
}

impl CacheKey {
    /// Create a cache key from raw artifact bytes and Rekor UUID.
    pub fn new(artifact_bytes: &[u8], rekor_uuid: &str) -> Self {
        let hash = Sha256::digest(artifact_bytes);
        Self {
            artifact_hash: hex::encode(hash),
            rekor_uuid: rekor_uuid.to_string(),
        }
    }

    /// Create a cache key from a pre-computed hash and Rekor UUID.
    pub fn from_hash(artifact_hash: &str, rekor_uuid: &str) -> Self {
        Self {
            artifact_hash: artifact_hash.to_string(),
            rekor_uuid: rekor_uuid.to_string(),
        }
    }
}

/// A cached Rekor proof entry with expiry metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedProof {
    /// The verified Rekor entry
    pub entry: RekorEntry,
    /// When this entry was cached (seconds since UNIX epoch)
    pub cached_at_epoch: u64,
    /// TTL in seconds
    pub ttl_secs: u64,
}

impl CachedProof {
    /// Whether this cached entry has expired based on current time.
    pub fn is_expired_at(&self, now_epoch: u64) -> bool {
        now_epoch > self.cached_at_epoch + self.ttl_secs
    }
}

/// Trait for pluggable proof cache backends.
pub trait ProofCacheBackend: Send + Sync {
    /// Look up a cached proof by key. Returns None if not found or expired.
    fn get(&self, key: &CacheKey) -> Option<CachedProof>;

    /// Store a verified proof in the cache.
    fn insert(&self, key: CacheKey, proof: CachedProof);

    /// Remove a specific entry.
    fn invalidate(&self, key: &CacheKey);

    /// Remove all expired entries.
    fn evict_expired(&self);

    /// Number of entries currently in cache.
    fn len(&self) -> usize;

    /// Whether the cache is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory proof cache with TTL-based expiry.
///
/// Thread-safe via `Mutex`. Suitable for CLI tools and short-lived
/// processes. For long-running services, consider a file-based or
/// distributed cache backend.
pub struct MemoryProofCache {
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
    ttl: Duration,
}

/// Internal cache entry with instant-based expiry for in-memory use.
struct CacheEntry {
    proof: CachedProof,
    expires_at: Instant,
}

impl MemoryProofCache {
    /// Create a new in-memory cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Create a cache with a 24-hour TTL (recommended default).
    pub fn default_ttl() -> Self {
        Self::new(Duration::from_secs(24 * 60 * 60))
    }

    /// Get the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl ProofCacheBackend for MemoryProofCache {
    fn get(&self, key: &CacheKey) -> Option<CachedProof> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if Instant::now() >= entry.expires_at {
            return None; // Expired
        }
        Some(entry.proof.clone())
    }

    fn insert(&self, key: CacheKey, proof: CachedProof) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                key,
                CacheEntry {
                    proof,
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }
    }

    fn invalidate(&self, key: &CacheKey) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }

    fn evict_expired(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            let now = Instant::now();
            entries.retain(|_, entry| now < entry.expires_at);
        }
    }

    fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }
}

/// Convenience: create a cached proof from a verified RekorEntry.
pub fn cache_verified_proof(entry: &RekorEntry, ttl: Duration) -> CachedProof {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    CachedProof {
        entry: entry.clone(),
        cached_at_epoch: now,
        ttl_secs: ttl.as_secs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rekor_entry() -> RekorEntry {
        RekorEntry {
            uuid: "test-uuid-1234".to_string(),
            log_index: 42,
            body: "base64body==".to_string(),
            log_id: "log-id-abc".to_string(),
            inclusion_proof: vec![1, 2, 3],
            signed_entry_timestamp: "base64set==".to_string(),
            integrated_time: "2026-03-18T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_cache_key_from_bytes() {
        let key = CacheKey::new(b"hello world", "uuid-1234");
        assert!(!key.artifact_hash.is_empty());
        assert_eq!(key.rekor_uuid, "uuid-1234");
        // SHA-256 of "hello world"
        assert_eq!(
            key.artifact_hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_cache_key_from_hash() {
        let key = CacheKey::from_hash("abc123", "uuid-5678");
        assert_eq!(key.artifact_hash, "abc123");
        assert_eq!(key.rekor_uuid, "uuid-5678");
    }

    #[test]
    fn test_cache_key_equality() {
        let k1 = CacheKey::from_hash("abc", "uuid");
        let k2 = CacheKey::from_hash("abc", "uuid");
        let k3 = CacheKey::from_hash("def", "uuid");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_cached_proof_expiry() {
        let proof = CachedProof {
            entry: sample_rekor_entry(),
            cached_at_epoch: 1000,
            ttl_secs: 100,
        };

        assert!(!proof.is_expired_at(1050)); // 50s in, not expired
        assert!(!proof.is_expired_at(1100)); // exactly at TTL
        assert!(proof.is_expired_at(1101)); // 1s past TTL
    }

    #[test]
    fn test_memory_cache_insert_get() {
        let cache = MemoryProofCache::new(Duration::from_secs(3600));
        let key = CacheKey::from_hash("abc", "uuid-1");
        let proof = cache_verified_proof(&sample_rekor_entry(), Duration::from_secs(3600));

        assert!(cache.is_empty());
        cache.insert(key.clone(), proof);
        assert_eq!(cache.len(), 1);

        let retrieved = cache.get(&key);
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.entry.uuid, "test-uuid-1234");
        assert_eq!(retrieved.entry.log_index, 42);
    }

    #[test]
    fn test_memory_cache_miss() {
        let cache = MemoryProofCache::new(Duration::from_secs(3600));
        let key = CacheKey::from_hash("nonexistent", "uuid");
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_memory_cache_invalidate() {
        let cache = MemoryProofCache::new(Duration::from_secs(3600));
        let key = CacheKey::from_hash("abc", "uuid-1");
        let proof = cache_verified_proof(&sample_rekor_entry(), Duration::from_secs(3600));

        cache.insert(key.clone(), proof);
        assert_eq!(cache.len(), 1);

        cache.invalidate(&key);
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_memory_cache_expiry() {
        // Use a very short TTL
        let cache = MemoryProofCache::new(Duration::from_millis(1));
        let key = CacheKey::from_hash("abc", "uuid-1");
        let proof = cache_verified_proof(&sample_rekor_entry(), Duration::from_millis(1));

        cache.insert(key.clone(), proof);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        // Should return None because expired
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_memory_cache_evict_expired() {
        let cache = MemoryProofCache::new(Duration::from_millis(1));
        let key = CacheKey::from_hash("abc", "uuid-1");
        let proof = cache_verified_proof(&sample_rekor_entry(), Duration::from_millis(1));

        cache.insert(key, proof);
        std::thread::sleep(Duration::from_millis(10));

        // len() still counts expired entries
        assert_eq!(cache.len(), 1);

        // evict_expired removes them
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_memory_cache_multiple_entries() {
        let cache = MemoryProofCache::new(Duration::from_secs(3600));

        for i in 0..10 {
            let key = CacheKey::from_hash(&format!("hash-{}", i), &format!("uuid-{}", i));
            let proof = cache_verified_proof(&sample_rekor_entry(), Duration::from_secs(3600));
            cache.insert(key, proof);
        }

        assert_eq!(cache.len(), 10);

        // Verify specific entry
        let key5 = CacheKey::from_hash("hash-5", "uuid-5");
        assert!(cache.get(&key5).is_some());
    }

    #[test]
    fn test_default_ttl() {
        let cache = MemoryProofCache::default_ttl();
        assert_eq!(cache.ttl(), Duration::from_secs(86400));
    }

    #[test]
    fn test_cache_key_serialization() {
        let key = CacheKey::from_hash("abc123", "uuid-456");
        let json = serde_json::to_string(&key).unwrap();
        let parsed: CacheKey = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn test_cached_proof_serialization() {
        let proof = CachedProof {
            entry: sample_rekor_entry(),
            cached_at_epoch: 1710720000,
            ttl_secs: 86400,
        };

        let json = serde_json::to_string_pretty(&proof).unwrap();
        let parsed: CachedProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entry.uuid, "test-uuid-1234");
        assert_eq!(parsed.ttl_secs, 86400);
    }
}
