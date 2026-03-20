//! OCI 1.1 Referrers API for signature storage.
//!
//! Stores signatures as referrers to the signed image instead of
//! using tag-based storage. Reduces signature loss from registry GC (AS-19).
//!
//! # Overview
//!
//! OCI 1.1 introduced the Referrers API, which allows artifacts (like signatures)
//! to be stored as referrers to a subject manifest. This is superior to tag-based
//! storage because:
//!
//! - Referrers are linked to the subject manifest by digest, not tag
//! - Registries that implement OCI 1.1 will not garbage-collect referrers
//! - Multiple signatures can coexist without tag conflicts
//!
//! This module delegates actual registry operations to `oras` or `crane` CLI tools.

use crate::error::WSError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::process::Command;

use super::digest::ImageReference;

/// Artifact types for OCI referrer storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    /// Sigstore bundle v0.3 format
    #[serde(rename = "application/vnd.dev.sigstore.bundle.v0.3+json")]
    SigstoreBundleV03,

    /// Cosign simple signing format
    #[serde(rename = "application/vnd.dev.cosign.simplesigning.v1+json")]
    CosignSimpleSigning,

    /// Custom artifact type
    #[serde(untagged)]
    Custom(String),
}

impl ArtifactType {
    /// Return the media type string for this artifact type.
    pub fn as_str(&self) -> &str {
        match self {
            ArtifactType::SigstoreBundleV03 => {
                "application/vnd.dev.sigstore.bundle.v0.3+json"
            }
            ArtifactType::CosignSimpleSigning => {
                "application/vnd.dev.cosign.simplesigning.v1+json"
            }
            ArtifactType::Custom(s) => s.as_str(),
        }
    }

    /// Parse an artifact type from a media type string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "application/vnd.dev.sigstore.bundle.v0.3+json" => ArtifactType::SigstoreBundleV03,
            "application/vnd.dev.cosign.simplesigning.v1+json" => {
                ArtifactType::CosignSimpleSigning
            }
            other => ArtifactType::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Configuration for OCI 1.1 referrers API usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferrerConfig {
    /// Whether to use the referrers API for signature storage.
    #[serde(default)]
    pub enabled: bool,

    /// Whether to fall back to tag-based storage if the registry
    /// does not support the referrers API.
    #[serde(default = "default_true")]
    pub fallback_to_tag: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ReferrerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fallback_to_tag: true,
        }
    }
}

/// A reference to a stored signature in a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureReference {
    /// Digest of the referrer manifest (e.g., "sha256:abc123...").
    pub digest: String,

    /// Artifact type of the stored signature.
    pub artifact_type: String,

    /// Size of the stored artifact in bytes, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Check whether a registry supports the OCI 1.1 referrers API.
///
/// Probes the `/_oci/artifacts/referrers/` endpoint (or uses `oras discover`)
/// to determine support.
///
/// # Arguments
///
/// * `registry` - Registry hostname (e.g., "ghcr.io")
///
/// # Returns
///
/// `Ok(true)` if the registry supports referrers, `Ok(false)` otherwise.
pub fn check_referrers_support(registry: &str) -> Result<bool, WSError> {
    // Try oras discover with a known image to probe referrers support.
    // If oras is not installed, try crane.
    if let Some(supported) = probe_with_oras(registry) {
        return Ok(supported);
    }

    if let Some(supported) = probe_with_crane(registry) {
        return Ok(supported);
    }

    Err(WSError::InternalError(
        "Cannot check referrers support: 'oras' or 'crane' must be installed.".to_string(),
    ))
}

/// List existing referrers for an image.
///
/// Returns all artifacts that reference the given image, optionally
/// filtered by artifact type.
///
/// # Arguments
///
/// * `image` - The image to list referrers for (must have a digest)
/// * `artifact_type` - Optional artifact type filter
///
/// # Returns
///
/// A list of signature references attached to the image.
pub fn list_referrers(
    image: &ImageReference,
    artifact_type: Option<&str>,
) -> Result<Vec<SignatureReference>, WSError> {
    let digest_ref = image.digest_reference().map_err(|_| {
        WSError::InternalError(
            "Cannot list referrers without a digest. Resolve the image first.".to_string(),
        )
    })?;

    // Try oras first, then crane
    if let Some(refs) = list_with_oras(&digest_ref, artifact_type) {
        return Ok(refs);
    }

    if let Some(refs) = list_with_crane(&digest_ref, artifact_type) {
        return Ok(refs);
    }

    Err(WSError::InternalError(
        "Cannot list referrers: 'oras' or 'crane' must be installed.".to_string(),
    ))
}

/// Store a signature as a referrer to the given image.
///
/// Pushes the signature bytes as an OCI artifact referencing the subject image.
///
/// # Arguments
///
/// * `image` - The subject image (must have a digest)
/// * `signature` - Raw signature bytes to store
/// * `artifact_type` - The artifact media type for the referrer
///
/// # Returns
///
/// A `SignatureReference` describing the stored artifact.
pub fn store_as_referrer(
    image: &ImageReference,
    signature: &[u8],
    artifact_type: &str,
) -> Result<SignatureReference, WSError> {
    let digest_ref = image.digest_reference().map_err(|_| {
        WSError::InternalError(
            "Cannot store referrer without a digest. Resolve the image first.".to_string(),
        )
    })?;

    // Write signature to a temporary file for oras/crane to read
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(format!("wsc-sig-{}.json", uuid::Uuid::new_v4()));

    std::fs::write(&tmp_path, signature).map_err(|e| {
        WSError::InternalError(format!("Failed to write temporary signature file: {}", e))
    })?;

    let result = store_with_oras(&digest_ref, &tmp_path, artifact_type)
        .or_else(|| store_with_crane(&digest_ref, &tmp_path, artifact_type));

    // Clean up temporary file regardless of outcome
    let _ = std::fs::remove_file(&tmp_path);

    result.ok_or_else(|| {
        WSError::InternalError(
            "Cannot store referrer: 'oras' or 'crane' must be installed.".to_string(),
        )
    })
}

// --- Internal helpers for tool delegation ---

/// Probe referrers support using `oras`.
fn probe_with_oras(registry: &str) -> Option<bool> {
    // `oras discover` against a known repository will fail with a specific
    // error if referrers are not supported. We use a synthetic reference
    // and check the exit code / stderr for indicators.
    let output = Command::new("oras")
        .args([
            "discover",
            "--distribution-spec",
            "v1.1-referrers-api",
            &format!("{}/oci-conformance/test:latest", registry),
        ])
        .output()
        .ok()?;

    let stderr = String::from_utf8_lossy(&output.stderr);

    // If oras exits successfully or fails only because the image does not
    // exist (not because referrers are unsupported), the registry likely
    // supports the API.
    if output.status.success() {
        return Some(true);
    }

    // "not found" means the image doesn't exist but the API was reachable
    if stderr.contains("not found") || stderr.contains("NAME_UNKNOWN") {
        return Some(true);
    }

    // Explicit unsupported indicator
    if stderr.contains("referrers API is not supported") || stderr.contains("404") {
        return Some(false);
    }

    // Ambiguous -- could not determine
    Some(false)
}

/// Probe referrers support using `crane`.
fn probe_with_crane(registry: &str) -> Option<bool> {
    // crane does not have a direct referrers command, but we can try
    // to list the manifest and check the response headers/errors.
    let output = Command::new("crane")
        .args(["manifest", &format!("{}/oci-conformance/test:latest", registry)])
        .output()
        .ok()?;

    if output.status.success() {
        // If we can fetch the manifest, the registry is reachable.
        // Check the manifest for OCI 1.1 indicators.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("oci.image.manifest") || stdout.contains("application/vnd.oci.image") {
            return Some(true);
        }
    }

    // Cannot determine from crane alone
    None
}

/// List referrers using `oras discover`.
fn list_with_oras(
    digest_ref: &str,
    artifact_type: Option<&str>,
) -> Option<Vec<SignatureReference>> {
    let mut cmd = Command::new("oras");
    cmd.args(["discover", "--output", "json", digest_ref]);

    if let Some(at) = artifact_type {
        cmd.args(["--artifact-type", at]);
    }

    let output = cmd.output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    parse_oras_discover_output(&stdout)
}

/// Parse JSON output from `oras discover --output json`.
fn parse_oras_discover_output(json: &str) -> Option<Vec<SignatureReference>> {
    // oras discover --output json returns:
    // { "manifests": [ { "digest": "sha256:...", "artifactType": "...", "size": N }, ... ] }
    let parsed: serde_json::Value = serde_json::from_str(json).ok()?;
    let manifests = parsed.get("manifests")?.as_array()?;

    let refs = manifests
        .iter()
        .filter_map(|m| {
            let digest = m.get("digest")?.as_str()?.to_string();
            let artifact_type = m.get("artifactType")?.as_str()?.to_string();
            let size = m.get("size").and_then(|s| s.as_u64());
            Some(SignatureReference {
                digest,
                artifact_type,
                size,
            })
        })
        .collect();

    Some(refs)
}

/// List referrers using `crane` (limited support).
fn list_with_crane(
    _digest_ref: &str,
    _artifact_type: Option<&str>,
) -> Option<Vec<SignatureReference>> {
    // crane does not natively support listing referrers as of v0.19.
    // This is a placeholder for future crane versions that may add support.
    None
}

/// Store a referrer using `oras attach`.
fn store_with_oras(
    digest_ref: &str,
    file_path: &std::path::Path,
    artifact_type: &str,
) -> Option<SignatureReference> {
    let file_arg = format!(
        "{}:{}",
        file_path.display(),
        artifact_type
    );

    let output = Command::new("oras")
        .args([
            "attach",
            "--artifact-type",
            artifact_type,
            digest_ref,
            &file_arg,
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // oras attach prints the digest of the attached manifest
    let digest = stdout
        .lines()
        .find(|l| l.contains("sha256:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "sha256:unknown".to_string());

    Some(SignatureReference {
        digest,
        artifact_type: artifact_type.to_string(),
        size: None,
    })
}

/// Store a referrer using `crane` (limited support).
fn store_with_crane(
    _digest_ref: &str,
    _file_path: &std::path::Path,
    _artifact_type: &str,
) -> Option<SignatureReference> {
    // crane does not natively support attaching referrers as of v0.19.
    // This is a placeholder for future crane versions.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_type_sigstore_bundle() {
        let at = ArtifactType::SigstoreBundleV03;
        assert_eq!(at.as_str(), "application/vnd.dev.sigstore.bundle.v0.3+json");
        assert_eq!(at.to_string(), "application/vnd.dev.sigstore.bundle.v0.3+json");
    }

    #[test]
    fn test_artifact_type_cosign() {
        let at = ArtifactType::CosignSimpleSigning;
        assert_eq!(
            at.as_str(),
            "application/vnd.dev.cosign.simplesigning.v1+json"
        );
    }

    #[test]
    fn test_artifact_type_custom() {
        let at = ArtifactType::Custom("application/vnd.example.sig+json".to_string());
        assert_eq!(at.as_str(), "application/vnd.example.sig+json");
    }

    #[test]
    fn test_artifact_type_from_str_known() {
        let at = ArtifactType::from_str("application/vnd.dev.sigstore.bundle.v0.3+json");
        assert_eq!(at, ArtifactType::SigstoreBundleV03);

        let at = ArtifactType::from_str("application/vnd.dev.cosign.simplesigning.v1+json");
        assert_eq!(at, ArtifactType::CosignSimpleSigning);
    }

    #[test]
    fn test_artifact_type_from_str_custom() {
        let at = ArtifactType::from_str("application/vnd.custom+json");
        assert_eq!(
            at,
            ArtifactType::Custom("application/vnd.custom+json".to_string())
        );
    }

    #[test]
    fn test_artifact_type_serialization_roundtrip() {
        let types = vec![
            ArtifactType::SigstoreBundleV03,
            ArtifactType::CosignSimpleSigning,
            ArtifactType::Custom("application/vnd.test+json".to_string()),
        ];

        for at in &types {
            let json = serde_json::to_string(at).unwrap();
            let parsed: ArtifactType = serde_json::from_str(&json).unwrap();
            assert_eq!(at.as_str(), parsed.as_str());
        }
    }

    #[test]
    fn test_referrer_config_default() {
        let config = ReferrerConfig::default();
        assert!(!config.enabled);
        assert!(config.fallback_to_tag);
    }

    #[test]
    fn test_referrer_config_serialization_roundtrip() {
        let config = ReferrerConfig {
            enabled: true,
            fallback_to_tag: false,
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: ReferrerConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.enabled);
        assert!(!parsed.fallback_to_tag);
    }

    #[test]
    fn test_referrer_config_defaults_in_deserialization() {
        // Deserializing an empty object should use defaults
        let json = "{}";
        let config: ReferrerConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
        assert!(config.fallback_to_tag);
    }

    #[test]
    fn test_signature_reference_serialization() {
        let sig_ref = SignatureReference {
            digest: "sha256:abc123def456".to_string(),
            artifact_type: "application/vnd.dev.sigstore.bundle.v0.3+json".to_string(),
            size: Some(1024),
        };

        let json = serde_json::to_string(&sig_ref).unwrap();
        assert!(json.contains("sha256:abc123def456"));
        assert!(json.contains("artifactType"));

        let parsed: SignatureReference = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.digest, sig_ref.digest);
        assert_eq!(parsed.artifact_type, sig_ref.artifact_type);
        assert_eq!(parsed.size, Some(1024));
    }

    #[test]
    fn test_signature_reference_without_size() {
        let sig_ref = SignatureReference {
            digest: "sha256:abc123".to_string(),
            artifact_type: "application/vnd.dev.cosign.simplesigning.v1+json".to_string(),
            size: None,
        };

        let json = serde_json::to_string(&sig_ref).unwrap();
        // size should be omitted when None
        assert!(!json.contains("size"));
    }

    #[test]
    fn test_parse_oras_discover_output_valid() {
        let json = r#"{
            "manifests": [
                {
                    "digest": "sha256:aaa111",
                    "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "size": 512
                },
                {
                    "digest": "sha256:bbb222",
                    "artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
                    "size": 1024
                }
            ]
        }"#;

        let refs = parse_oras_discover_output(json).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].digest, "sha256:aaa111");
        assert_eq!(
            refs[0].artifact_type,
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );
        assert_eq!(refs[0].size, Some(512));
        assert_eq!(refs[1].digest, "sha256:bbb222");
    }

    #[test]
    fn test_parse_oras_discover_output_empty() {
        let json = r#"{ "manifests": [] }"#;
        let refs = parse_oras_discover_output(json).unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_parse_oras_discover_output_invalid_json() {
        let result = parse_oras_discover_output("not json");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_oras_discover_output_missing_fields() {
        let json = r#"{
            "manifests": [
                { "digest": "sha256:aaa111" },
                { "digest": "sha256:bbb222", "artifactType": "test/type" }
            ]
        }"#;

        let refs = parse_oras_discover_output(json).unwrap();
        // First entry is missing artifactType, so it should be filtered out
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].digest, "sha256:bbb222");
    }

    #[test]
    fn test_list_referrers_requires_digest() {
        let image = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1").unwrap();
        let result = list_referrers(&image, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_store_as_referrer_requires_digest() {
        let image = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1").unwrap();
        let result = store_as_referrer(&image, b"test", "test/type");
        assert!(result.is_err());
    }

    #[test]
    fn test_artifact_type_equality() {
        assert_eq!(ArtifactType::SigstoreBundleV03, ArtifactType::SigstoreBundleV03);
        assert_ne!(ArtifactType::SigstoreBundleV03, ArtifactType::CosignSimpleSigning);
        assert_ne!(
            ArtifactType::SigstoreBundleV03,
            ArtifactType::Custom("application/vnd.dev.sigstore.bundle.v0.3+json".to_string())
        );
    }
}
