//! Rekor inclusion proof cache for availability resilience.
//!
//! Caches verified Rekor inclusion proofs so that verification can
//! succeed during transient Rekor outages. The cache is an optimization
//! only — it never weakens security guarantees (DD-2).
//!
//! # Security Properties
//!
//! - Cache entries are keyed by module hash + a digest over the **full**
//!   Rekor entry content (body, SET, log id/index, integrated time,
//!   inclusion proof, uuid). A hit therefore means "an entry
//!   byte-identical to this one was already fully verified", so skipping
//!   re-verification on hit is sound (issue #139 / UCA-4).
//! - Only successfully verified proofs are cached (after the Rekor SET
//!   passes). Merkle inclusion-proof verification is not yet on this path —
//!   see issue #137 / UCA-1.
//! - TTL-based expiry prevents stale proofs
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
///
/// Equality and hashing cover **all** fields. `entry_digest` binds the full
/// Rekor entry content so that a cache hit cannot be forged by keeping the
/// artifact hash + UUID while mutating the body, SET, or inclusion proof
/// (issue #139 / UCA-4). The `new`/`from_hash` constructors leave it empty
/// (legacy/weakly-bound keys, used only in tests); the production verify
/// path uses [`CacheKey::from_entry`].
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    /// SHA-256 hex digest of the signed artifact
    pub artifact_hash: String,
    /// Rekor entry UUID (human-readable; not sufficient for binding on its own)
    pub rekor_uuid: String,
    /// SHA-256 hex digest over the full Rekor entry content. Empty for keys
    /// built via [`CacheKey::new`] / [`CacheKey::from_hash`].
    #[serde(default)]
    pub entry_digest: String,
}

impl CacheKey {
    /// Create a cache key from raw artifact bytes and Rekor UUID.
    pub fn new(artifact_bytes: &[u8], rekor_uuid: &str) -> Self {
        let hash = Sha256::digest(artifact_bytes);
        Self {
            artifact_hash: hex::encode(hash),
            rekor_uuid: rekor_uuid.to_string(),
            entry_digest: String::new(),
        }
    }

    /// Create a cache key from a pre-computed hash and Rekor UUID.
    pub fn from_hash(artifact_hash: &str, rekor_uuid: &str) -> Self {
        Self {
            artifact_hash: artifact_hash.to_string(),
            rekor_uuid: rekor_uuid.to_string(),
            entry_digest: String::new(),
        }
    }

    /// Create a cache key bound to the full Rekor entry content.
    ///
    /// The `entry_digest` is a SHA-256 over every security-relevant field of
    /// the entry, with a domain separator between fields so that no field
    /// boundary can be shifted. A hit on this key therefore proves the cached
    /// proof was produced for a byte-identical entry — making it safe to skip
    /// SET + inclusion-proof re-verification on hit (issues #137 / #139).
    pub fn from_entry(artifact_hash: &str, entry: &RekorEntry) -> Self {
        let mut hasher = Sha256::new();
        let log_index = entry.log_index.to_le_bytes();
        // Length-prefix + separate every field so concatenations are
        // unambiguous (no byte can shift across a field boundary).
        for field in [
            entry.uuid.as_bytes(),
            entry.body.as_bytes(),
            entry.signed_entry_timestamp.as_bytes(),
            entry.log_id.as_bytes(),
            entry.integrated_time.as_bytes(),
            entry.inclusion_proof.as_slice(),
            log_index.as_slice(),
        ] {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        Self {
            artifact_hash: artifact_hash.to_string(),
            rekor_uuid: entry.uuid.clone(),
            entry_digest: hex::encode(hasher.finalize()),
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

/// Default maximum cache entries (SC-25 / SC-34).
const DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;

/// In-memory proof cache with TTL-based expiry and bounded size.
///
/// Thread-safe via `Mutex`. Suitable for CLI tools and short-lived
/// processes. For long-running services, consider a file-based or
/// distributed cache backend.
///
/// # Security (SC-25 / SC-34)
///
/// The cache enforces a maximum entry count to prevent unbounded memory
/// growth from cache flooding attacks (H-36 / AS-34). When the limit is
/// reached, expired entries are evicted first; if still over limit, the
/// oldest entries are removed.
pub struct MemoryProofCache {
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}

/// Internal cache entry with instant-based expiry for in-memory use.
struct CacheEntry {
    proof: CachedProof,
    inserted_at: Instant,
    expires_at: Instant,
}

impl MemoryProofCache {
    /// Create a new in-memory cache with the given TTL and default size limit.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries: DEFAULT_MAX_CACHE_ENTRIES,
        }
    }

    /// Create a cache with custom TTL and maximum entry count.
    pub fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
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

    /// Get the maximum entry count.
    pub fn max_entries(&self) -> usize {
        self.max_entries
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
            let now = Instant::now();

            // SC-34: Enforce maximum entry count to prevent cache flooding (H-36)
            if entries.len() >= self.max_entries {
                // First try evicting expired entries
                entries.retain(|_, entry| now < entry.expires_at);

                // If still over limit, evict oldest entries
                if entries.len() >= self.max_entries {
                    let evict_count = entries.len() - self.max_entries + 1;
                    let mut by_age: Vec<(CacheKey, Instant)> = entries
                        .iter()
                        .map(|(k, v)| (k.clone(), v.inserted_at))
                        .collect();
                    by_age.sort_by_key(|(_, inserted)| *inserted);
                    for (old_key, _) in by_age.into_iter().take(evict_count) {
                        entries.remove(&old_key);
                    }
                    log::debug!(
                        "Cache at capacity ({}): evicted {} oldest entries",
                        self.max_entries,
                        evict_count
                    );
                }
            }

            entries.insert(
                key,
                CacheEntry {
                    proof,
                    inserted_at: now,
                    expires_at: now + self.ttl,
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
    fn test_cache_key_from_entry_is_stable() {
        // Identical entries must produce identical keys (cache hits work).
        let k1 = CacheKey::from_entry("artifacthash", &sample_rekor_entry());
        let k2 = CacheKey::from_entry("artifacthash", &sample_rekor_entry());
        assert_eq!(k1, k2);
        assert!(!k1.entry_digest.is_empty());
        assert_eq!(k1.rekor_uuid, "test-uuid-1234");
    }

    #[test]
    fn test_cache_key_from_entry_binds_every_field() {
        // UCA-4: mutating ANY security-relevant entry field must change the
        // key, so an attacker cannot force a hit (and thus skip SET +
        // inclusion-proof re-verification) by reusing the artifact hash +
        // UUID while swapping the body / SET / log fields / inclusion proof.
        let base = CacheKey::from_entry("artifacthash", &sample_rekor_entry());

        let mutators: Vec<(&str, fn(&mut RekorEntry))> = vec![
            ("uuid", |e| e.uuid = "different-uuid".to_string()),
            ("log_index", |e| e.log_index = 43),
            ("body", |e| e.body = "tampered==".to_string()),
            ("log_id", |e| e.log_id = "different-log".to_string()),
            ("inclusion_proof", |e| e.inclusion_proof = vec![9, 9, 9]),
            ("signed_entry_timestamp", |e| {
                e.signed_entry_timestamp = "forged==".to_string()
            }),
            ("integrated_time", |e| {
                e.integrated_time = "2030-01-01T00:00:00Z".to_string()
            }),
        ];

        for (field, mutate) in mutators {
            let mut entry = sample_rekor_entry();
            mutate(&mut entry);
            let mutated = CacheKey::from_entry("artifacthash", &entry);
            assert_ne!(
                base, mutated,
                "mutating `{field}` must change the cache key but did not"
            );
        }

        // And changing the artifact hash alone must also change the key.
        let other_artifact = CacheKey::from_entry("otherhash", &sample_rekor_entry());
        assert_ne!(base, other_artifact);
    }

    #[test]
    fn test_cache_key_from_entry_no_field_boundary_ambiguity() {
        // Length-prefixing must prevent shifting a byte across a field
        // boundary from yielding the same key.
        let mut a = sample_rekor_entry();
        a.body = "ab".to_string();
        a.log_id = "c".to_string();
        let mut b = sample_rekor_entry();
        b.body = "a".to_string();
        b.log_id = "bc".to_string();
        assert_ne!(
            CacheKey::from_entry("h", &a),
            CacheKey::from_entry("h", &b)
        );
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
