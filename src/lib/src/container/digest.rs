//! OCI image reference parsing and tag-to-digest resolution.
//!
//! Ensures all signing operations use immutable digest references,
//! preventing tag mutation attacks (AS-18, UCA-18).

use crate::error::WSError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::process::Command;

/// An OCI image reference with optional tag and digest.
///
/// At least one of `tag` or `digest` must be present.
/// For signing, `digest` is always required — use `resolve()` to
/// convert tag-only references to digest-bound references.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageReference {
    /// Registry hostname (e.g., "ghcr.io")
    pub registry: String,

    /// Repository path (e.g., "pulseengine/wsc")
    pub repository: String,

    /// Mutable tag (e.g., "v0.5.1", "latest")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Immutable digest (e.g., "sha256:abc123...")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl ImageReference {
    /// Parse an image reference string.
    ///
    /// Supports formats:
    /// - `registry/repo:tag`
    /// - `registry/repo@sha256:digest`
    /// - `registry/repo:tag@sha256:digest`
    pub fn parse(reference: &str) -> Result<Self, WSError> {
        // Split off digest first (if present)
        let (rest, digest) = if let Some(idx) = reference.find('@') {
            let (r, d) = reference.split_at(idx);
            (r, Some(d[1..].to_string()))
        } else {
            (reference, None)
        };

        // Split off tag (if present)
        // Need to find the LAST colon that's not part of a port number
        // A tag colon comes after the repository path (after a '/')
        let (name, tag) = if let Some(slash_idx) = rest.rfind('/') {
            let after_slash = &rest[slash_idx + 1..];
            if let Some(colon_idx) = after_slash.find(':') {
                let tag_start = slash_idx + 1 + colon_idx;
                (&rest[..tag_start], Some(rest[tag_start + 1..].to_string()))
            } else {
                (rest, None)
            }
        } else {
            (rest, None)
        };

        if tag.is_none() && digest.is_none() {
            return Err(WSError::UsageError(
                "Image reference must include a tag or digest",
            ));
        }

        // Split registry from repository
        let (registry, repository) = if let Some(slash_idx) = name.find('/') {
            let reg = &name[..slash_idx];
            // Heuristic: registry contains a dot or colon, or is "localhost"
            if reg.contains('.') || reg.contains(':') || reg == "localhost" {
                (reg.to_string(), name[slash_idx + 1..].to_string())
            } else {
                // Docker Hub shorthand (e.g., "library/nginx:latest")
                ("docker.io".to_string(), name.to_string())
            }
        } else {
            return Err(WSError::UsageError(
                "Image reference must include registry and repository",
            ));
        };

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// Full reference string for display and cosign invocation.
    pub fn full_reference(&self) -> String {
        let mut s = format!("{}/{}", self.registry, self.repository);
        if let Some(ref tag) = self.tag {
            s.push(':');
            s.push_str(tag);
        }
        if let Some(ref digest) = self.digest {
            s.push('@');
            s.push_str(digest);
        }
        s
    }

    /// Digest-only reference (for signing).
    ///
    /// Returns `registry/repo@digest` format. Panics if digest is None.
    pub fn digest_reference(&self) -> Result<String, WSError> {
        let digest = self.digest.as_ref().ok_or(WSError::InternalError(
            "Cannot create digest reference without digest. Call resolve() first.".to_string(),
        ))?;
        Ok(format!("{}/{}@{}", self.registry, self.repository, digest))
    }

    /// Whether this reference has an immutable digest.
    pub fn has_digest(&self) -> bool {
        self.digest.is_some()
    }

    /// Resolve tag to digest using `crane digest` or `cosign triangulate`.
    ///
    /// If the reference already has a digest, returns self unchanged.
    /// Otherwise, queries the registry to get the manifest digest.
    pub fn resolve(&self) -> Result<Self, WSError> {
        if self.has_digest() {
            return Ok(self.clone());
        }

        let tag = self.tag.as_ref().ok_or(WSError::InternalError(
            "Cannot resolve: no tag or digest".to_string(),
        ))?;

        let tagged_ref = format!("{}/{}:{}", self.registry, self.repository, tag);

        // Try crane first, fall back to skopeo
        let digest = resolve_with_crane(&tagged_ref)
            .or_else(|| resolve_with_skopeo(&tagged_ref))
            .ok_or_else(|| {
                WSError::InternalError(format!(
                    "Failed to resolve digest for '{}'. Ensure 'crane' or 'skopeo' is installed.",
                    tagged_ref
                ))
            })?;

        Ok(Self {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            tag: self.tag.clone(),
            digest: Some(digest),
        })
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full_reference())
    }
}

fn resolve_with_crane(reference: &str) -> Option<String> {
    Command::new("crane")
        .args(["digest", reference])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("sha256:"))
}

fn resolve_with_skopeo(reference: &str) -> Option<String> {
    Command::new("skopeo")
        .args(["inspect", "--format", "{{.Digest}}", &format!("docker://{}", reference)])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("sha256:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tag_only() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "pulseengine/wsc");
        assert_eq!(r.tag.as_deref(), Some("v0.5.1"));
        assert!(r.digest.is_none());
    }

    #[test]
    fn test_parse_digest_only() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc@sha256:abc123").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "pulseengine/wsc");
        assert!(r.tag.is_none());
        assert_eq!(r.digest.as_deref(), Some("sha256:abc123"));
    }

    #[test]
    fn test_parse_tag_and_digest() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1@sha256:abc123").unwrap();
        assert_eq!(r.tag.as_deref(), Some("v0.5.1"));
        assert_eq!(r.digest.as_deref(), Some("sha256:abc123"));
    }

    #[test]
    fn test_parse_no_tag_or_digest() {
        assert!(ImageReference::parse("ghcr.io/pulseengine/wsc").is_err());
    }

    #[test]
    fn test_full_reference() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1").unwrap();
        assert_eq!(r.full_reference(), "ghcr.io/pulseengine/wsc:v0.5.1");

        let r = ImageReference::parse("ghcr.io/pulseengine/wsc@sha256:abc123").unwrap();
        assert_eq!(r.full_reference(), "ghcr.io/pulseengine/wsc@sha256:abc123");
    }

    #[test]
    fn test_digest_reference() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1@sha256:abc123").unwrap();
        assert_eq!(
            r.digest_reference().unwrap(),
            "ghcr.io/pulseengine/wsc@sha256:abc123"
        );
    }

    #[test]
    fn test_digest_reference_missing() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1").unwrap();
        assert!(r.digest_reference().is_err());
    }

    #[test]
    fn test_has_digest() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1").unwrap();
        assert!(!r.has_digest());

        let r = ImageReference::parse("ghcr.io/pulseengine/wsc@sha256:abc123").unwrap();
        assert!(r.has_digest());
    }

    #[test]
    fn test_resolve_already_has_digest() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc@sha256:abc123").unwrap();
        let resolved = r.resolve().unwrap();
        assert_eq!(resolved.digest.as_deref(), Some("sha256:abc123"));
    }

    #[test]
    fn test_docker_hub_shorthand() {
        let r = ImageReference::parse("library/nginx:latest").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/nginx");
    }

    #[test]
    fn test_display() {
        let r = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1").unwrap();
        assert_eq!(format!("{}", r), "ghcr.io/pulseengine/wsc:v0.5.1");
    }
}
