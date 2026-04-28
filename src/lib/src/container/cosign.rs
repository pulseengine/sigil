//! Cosign subprocess delegation with binary integrity verification.
//!
//! Provides safe delegation to `cosign` for container signing while
//! verifying binary integrity before invocation (AS-20, UCA-20).

use crate::error::WSError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use super::digest::ImageReference;

/// Configuration for cosign delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignConfig {
    /// Path to cosign binary (default: search PATH)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<PathBuf>,

    /// Expected SHA-256 hash of the cosign binary (for integrity verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,

    /// Expected cosign version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,

    /// Whether to require binary integrity verification
    #[serde(default)]
    pub require_integrity_check: bool,

    /// Additional cosign flags
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra_flags: HashMap<String, String>,
}

impl Default for CosignConfig {
    fn default() -> Self {
        Self {
            binary_path: None,
            expected_hash: None,
            expected_version: None,
            require_integrity_check: false,
            extra_flags: HashMap::new(),
        }
    }
}

/// Result of a cosign signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningResult {
    /// The image reference that was signed (always digest-bound)
    pub image: String,

    /// Whether the signing succeeded
    pub success: bool,

    /// Cosign's stdout output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,

    /// Cosign binary version used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cosign_version: Option<String>,

    /// SHA-256 hash of the cosign binary used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cosign_binary_hash: Option<String>,
}

/// Result of a cosign verification operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    /// The image reference verified
    pub image: String,

    /// Whether the signature is valid
    pub verified: bool,

    /// OIDC issuer from the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// OIDC subject (signer identity)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Cosign's stdout output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// Cosign binary information after integrity check.
#[derive(Debug, Clone)]
pub struct CosignBinaryInfo {
    /// Path to the binary
    pub path: PathBuf,
    /// Version string
    pub version: String,
    /// SHA-256 hash of the binary
    pub sha256: String,
}

/// Cosign delegator that manages subprocess invocation with integrity checks.
pub struct CosignDelegator {
    config: CosignConfig,
    binary_info: Option<CosignBinaryInfo>,
}

impl CosignDelegator {
    /// Create a new delegator with default config.
    pub fn new() -> Result<Self, WSError> {
        Self::with_config(CosignConfig::default())
    }

    /// Create a new delegator with explicit configuration.
    pub fn with_config(config: CosignConfig) -> Result<Self, WSError> {
        let mut delegator = Self {
            config,
            binary_info: None,
        };

        // Verify binary integrity on construction
        delegator.verify_binary()?;

        Ok(delegator)
    }

    /// Locate and verify the cosign binary.
    fn verify_binary(&mut self) -> Result<(), WSError> {
        // Find the binary
        let path = if let Some(ref explicit) = self.config.binary_path {
            if !explicit.exists() {
                return Err(WSError::InternalError(format!(
                    "Cosign binary not found at: {}",
                    explicit.display()
                )));
            }
            explicit.clone()
        } else {
            find_cosign_in_path()?
        };

        // Get version
        let version = get_cosign_version(&path)?;

        // Check version if expected
        if let Some(ref expected) = self.config.expected_version {
            if !version.contains(expected) {
                return Err(WSError::InternalError(format!(
                    "Cosign version mismatch: expected '{}', got '{}'",
                    expected, version
                )));
            }
        }

        // Compute SHA-256 hash of binary
        let sha256 = hash_file(&path)?;

        // Verify hash if expected
        if let Some(ref expected_hash) = self.config.expected_hash {
            if sha256 != *expected_hash {
                return Err(WSError::InternalError(format!(
                    "Cosign binary integrity check failed (AS-20)!\n\
                     Expected: {}\n\
                     Got:      {}\n\
                     Path:     {}",
                    expected_hash,
                    sha256,
                    path.display()
                )));
            }
        } else if self.config.require_integrity_check {
            return Err(WSError::InternalError(
                "Cosign integrity check required but no expected_hash configured".to_string(),
            ));
        }

        self.binary_info = Some(CosignBinaryInfo {
            path,
            version,
            sha256,
        });

        Ok(())
    }

    /// Sign a container image using cosign keyless signing.
    ///
    /// Requires the image to have a digest (call `image.resolve()` first).
    /// This enforces AS-18 (tag mutation attack prevention).
    pub fn sign(&self, image: &ImageReference) -> Result<SigningResult, WSError> {
        let info = self.binary_info.as_ref().ok_or(WSError::InternalError(
            "Cosign binary not verified".to_string(),
        ))?;

        // Enforce digest-bound signing (UCA-18)
        let digest_ref = image.digest_reference().map_err(|_| {
            WSError::InternalError(
                "Refusing to sign by tag only (AS-18). Resolve to digest first.".to_string(),
            )
        })?;

        let mut cmd = Command::new(&info.path);
        cmd.args(["sign", "--yes", &digest_ref]);

        // Add extra flags
        for (key, value) in &self.config.extra_flags {
            cmd.arg(format!("--{}", key));
            if !value.is_empty() {
                cmd.arg(value);
            }
        }

        let output = cmd
            .output()
            .map_err(|e| WSError::InternalError(format!("Failed to execute cosign: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(WSError::InternalError(format!(
                "Cosign signing failed:\nstdout: {}\nstderr: {}",
                stdout, stderr
            )));
        }

        Ok(SigningResult {
            image: digest_ref,
            success: true,
            output: Some(format!("{}{}", stdout, stderr).trim().to_string()),
            cosign_version: Some(info.version.clone()),
            cosign_binary_hash: Some(info.sha256.clone()),
        })
    }

    /// Verify a container image signature using cosign.
    ///
    /// Validates that the signature's embedded digest matches the image (AS-21).
    pub fn verify(
        &self,
        image: &ImageReference,
        expected_issuer: Option<&str>,
        expected_identity: Option<&str>,
    ) -> Result<VerificationResult, WSError> {
        let info = self.binary_info.as_ref().ok_or(WSError::InternalError(
            "Cosign binary not verified".to_string(),
        ))?;

        // Use digest reference if available (preferred), otherwise full reference
        let reference = if image.has_digest() {
            image
                .digest_reference()
                .unwrap_or_else(|_| image.full_reference())
        } else {
            image.full_reference()
        };

        let mut cmd = Command::new(&info.path);
        cmd.args(["verify", &reference]);

        if let Some(issuer) = expected_issuer {
            cmd.args(["--certificate-oidc-issuer", issuer]);
        }

        if let Some(identity) = expected_identity {
            cmd.args(["--certificate-identity-regexp", identity]);
        }

        let output = cmd.output().map_err(|e| {
            WSError::InternalError(format!("Failed to execute cosign verify: {}", e))
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        Ok(VerificationResult {
            image: reference,
            verified: output.status.success(),
            issuer: expected_issuer.map(|s| s.to_string()),
            subject: expected_identity.map(|s| s.to_string()),
            output: Some(stdout.trim().to_string()),
        })
    }

    /// Get information about the verified cosign binary.
    pub fn binary_info(&self) -> Option<&CosignBinaryInfo> {
        self.binary_info.as_ref()
    }
}

/// Find cosign binary on PATH.
fn find_cosign_in_path() -> Result<PathBuf, WSError> {
    which("cosign").ok_or(WSError::InternalError(
        "cosign not found on PATH. Install from https://docs.sigstore.dev/cosign/installation/"
            .to_string(),
    ))
}

/// Simple `which` implementation.
fn which(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(binary);
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

/// Get cosign version string.
fn get_cosign_version(path: &PathBuf) -> Result<String, WSError> {
    let output = Command::new(path)
        .arg("version")
        .output()
        .map_err(|e| WSError::InternalError(format!("Failed to get cosign version: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout.trim().to_string())
}

/// Compute SHA-256 hash of a file.
fn hash_file(path: &PathBuf) -> Result<String, WSError> {
    let bytes = std::fs::read(path).map_err(|e| {
        WSError::InternalError(format!(
            "Failed to read cosign binary at '{}': {}",
            path.display(),
            e
        ))
    })?;
    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CosignConfig::default();
        assert!(config.binary_path.is_none());
        assert!(config.expected_hash.is_none());
        assert!(!config.require_integrity_check);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = CosignConfig {
            binary_path: Some(PathBuf::from("/usr/local/bin/cosign")),
            expected_hash: Some("abc123".to_string()),
            expected_version: Some("2.4.0".to_string()),
            require_integrity_check: true,
            extra_flags: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: CosignConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.require_integrity_check, true);
        assert_eq!(parsed.expected_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_signing_result_serialization() {
        let result = SigningResult {
            image: "ghcr.io/pulseengine/wsc@sha256:abc123".to_string(),
            success: true,
            output: Some("Signed.".to_string()),
            cosign_version: Some("2.4.0".to_string()),
            cosign_binary_hash: Some("deadbeef".to_string()),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("cosignVersion"));
        assert!(json.contains("cosignBinaryHash"));
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            image: "ghcr.io/pulseengine/wsc@sha256:abc123".to_string(),
            verified: true,
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            subject: Some(".*@pulseengine".to_string()),
            output: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("verified"));
        assert!(json.contains("issuer"));
    }

    #[test]
    fn test_which_nonexistent() {
        assert!(which("this-binary-surely-does-not-exist-xyz").is_none());
    }

    #[test]
    fn test_which_existing() {
        // `ls` should exist on any Unix-like system
        if cfg!(unix) {
            assert!(which("ls").is_some());
        }
    }

    #[test]
    fn test_hash_file_nonexistent() {
        let result = hash_file(&PathBuf::from("/nonexistent/path/cosign"));
        assert!(result.is_err());
    }

    #[test]
    fn test_cosign_missing_binary() {
        let config = CosignConfig {
            binary_path: Some(PathBuf::from("/nonexistent/cosign")),
            ..Default::default()
        };
        let result = CosignDelegator::with_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_integrity_check_required_no_hash() {
        // If cosign is on PATH but no expected hash and require_integrity_check is true
        let config = CosignConfig {
            require_integrity_check: true,
            expected_hash: None,
            ..Default::default()
        };
        // This will either fail because cosign is not found, or because
        // integrity check is required but no expected hash is set
        let result = CosignDelegator::with_config(config);
        assert!(result.is_err());
    }
}
