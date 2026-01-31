/// Certificate pinning for Sigstore endpoints (Issue #12)
///
/// Provides defense-in-depth against CA compromise and MITM attacks.
/// Note: Rustls-dependent types (PinnedCertVerifier, create_pinned_rustls_config)
/// are only available on native targets (not wasm32).
pub mod cert_pinning;
pub mod cert_verifier;
/// Rate limiting for Sigstore API endpoints (Issue #6)
pub mod rate_limit;
/// Keyless signing support for wsc
///
/// This module implements keyless (ephemeral key) signing using:
/// - OIDC identity tokens (GitHub Actions, Google Cloud, GitLab CI)
/// - Fulcio for short-lived certificates
/// - Rekor for transparency log entries
mod format;
pub mod fulcio;
pub mod merkle;
pub mod oidc;
pub mod rekor;
pub mod rekor_verifier;
pub mod signer;
/// Custom TLS transport with certificate pinning (Issue #12)
/// Note: Only available on native targets (not wasm32).
#[cfg(not(target_arch = "wasm32"))]
pub mod transport;

// Certificate pinning types (Issue #12)
// Platform-agnostic types
pub use cert_pinning::{PinningConfig, check_pinning_requirement};
// Rustls-dependent types (native only)
#[cfg(not(target_arch = "wasm32"))]
pub use cert_pinning::{PinnedCertVerifier, create_pinned_rustls_config};
pub use cert_verifier::{CertVerificationError, CertificatePool};
pub use format::*;
pub use fulcio::{FulcioCertificate, FulcioClient};
pub use oidc::{
    GitHubOidcProvider, GitLabOidcProvider, GoogleOidcProvider, OidcProvider, OidcToken,
    detect_oidc_provider,
};
pub use rekor::{RekorClient, RekorEntry};
pub use rekor_verifier::RekorKeyring;
pub use signer::{KeylessConfig, KeylessSigner, KeylessVerifier, KeylessVerificationResult};
