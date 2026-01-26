//! A proof of concept implementation of the WebAssembly module signature proposal.

// The `PublicKey::verify()` function is what most runtimes should use or reimplement if they don't need partial verification.
// The `SecretKey::sign()` function is what most 3rd-party signing tools can use or reimplement if they don't need support for multiple signatures.

#![allow(clippy::vec_init_then_push)]
#![forbid(unsafe_code)]

// Compile-time guard: async feature requires native target (until WASI 0.3)
#[cfg(all(target_arch = "wasm32", feature = "async"))]
compile_error!(
    "The 'async' feature is not supported on WASM targets until WASI 0.3 (expected Feb 2026). \
    Use the default 'sync' feature for WASM builds."
);

mod error;
mod signature;
mod split;
mod wasm_module;

/// Secure file operations with restrictive permissions
///
/// Provides utilities for securely reading and writing sensitive files
/// such as private keys and tokens. On Unix systems, it enforces restrictive
/// permissions (0600 = owner read/write only) to prevent credential theft.
pub mod secure_file;

/// Time validation for offline-first verification
///
/// Provides time source abstraction for embedded and edge devices that may not
/// have reliable system clocks. Supports multiple strategies including build-time
/// lower bounds and custom time sources (RTC, GPS, NTP).
pub mod time;

/// Platform-specific hardware security integration
///
/// Provides unified interface for hardware-backed cryptographic operations
/// across TPM 2.0, Secure Elements, TrustZone, and software fallback.
pub mod platform;

/// Certificate provisioning for IoT devices
///
/// Provides tools for offline certificate provisioning in factory/manufacturing
/// environments. Includes CA management, device identity, and provisioning workflows.
pub mod provisioning;

/// Component composition and provenance tracking
///
/// Provides support for WebAssembly component composition with full provenance
/// tracking, enabling supply chain security and compliance with SLSA, in-toto,
/// and SBOM standards.
pub mod composition;

/// Metrics collection for signing operations (Issue #3)
///
/// Provides observability for signing and validation operations with
/// Prometheus-compatible export format.
pub mod metrics;

/// Air-gapped verification for embedded devices
///
/// Enables offline verification of Sigstore keyless signatures using
/// pre-provisioned trust bundles. Designed for IoT, automotive, and
/// edge devices without network access at runtime.
pub mod airgapped;

/// Audit logging for security-sensitive operations
///
/// Provides structured audit logging for signing and verification operations,
/// designed for compliance with ISO/SAE 21434, IEC 62443, and SOC 2 requirements.
/// Supports JSON output for SIEM integration.
pub mod audit;

/// Supply chain verification policy engine
///
/// Provides a TOML-based policy engine for enforcing SLSA levels and
/// supply chain security policies on WebAssembly transformation chains.
/// Supports per-rule enforcement modes (strict vs report).
pub mod policy;

/// DSSE (Dead Simple Signing Envelope) implementation
///
/// Provides the standard DSSE envelope format for signing attestations.
/// Used as the wrapper for all embedded attestations, enabling extraction
/// and verification with standard tooling (cosign, sigstore-rs, etc.).
/// See: https://github.com/secure-systems-lab/dsse
pub mod dsse;

/// in-toto Statement v1.0 implementation
///
/// Provides the in-toto attestation framework Statement layer.
/// Statements bind predicates (SLSA provenance, etc.) to subjects (artifacts).
/// See: https://github.com/in-toto/attestation
pub mod intoto;

/// SLSA v1.0 Provenance predicate
///
/// Provides SLSA Build provenance attestation format for supply chain security.
/// Describes how artifacts were built, including inputs, builder, and metadata.
/// See: https://slsa.dev/spec/v1.0/provenance
pub mod slsa;

/// HTTP client abstraction for sync/async support
///
/// Provides a unified HTTP client interface using `maybe_async` for compile-time
/// sync/async selection. Uses `ureq` in sync mode (default) and `reqwest` in async mode.
/// Not available on WASM targets - use WASI HTTP instead.
#[cfg(not(target_arch = "wasm32"))]
pub mod http;

/// Wasmtime runtime for hosting WASM components with hardware crypto
///
/// Provides a wasmtime-based execution environment that implements the
/// `wsc:crypto` WIT interface, allowing WASM components to access
/// hardware-backed cryptographic operations (TPM, HSM, Secure Element)
/// through opaque key handles.
///
/// # Feature Flag
///
/// This module requires the `runtime` feature:
///
/// ```toml
/// [dependencies]
/// wsc = { version = "0.5", features = ["runtime"] }
/// ```
#[cfg(all(feature = "runtime", not(target_arch = "wasm32")))]
pub mod runtime;

#[allow(unused_imports)]
pub use error::*;
#[allow(unused_imports)]
pub use signature::*;
#[allow(unused_imports)]
pub use split::*;
#[allow(unused_imports)]
pub use wasm_module::*;

// Re-export keyless module for public API
pub use signature::keyless;

pub mod reexports {
    pub use {anyhow, ct_codecs, getrandom, hmac_sha256, log, regex, thiserror};
}

const SIGNATURE_WASM_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_WASM_MODULE_CONTENT_TYPE: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;
