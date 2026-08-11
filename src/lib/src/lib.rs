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

// `wasm_module`, `split`, `secure_file`, and the classic signature core
// (`signature/{hash,info,keys,matrix,multi,sig_sections,simple}`) live in the
// `wsc-verify-core` crate so the verification path builds for `wasm32-*`
// without dragging in TLS/X.509. This crate re-exports them so the public
// `wsc::*` API is unchanged.
pub use wsc_verify_core::secure_file;
pub use wsc_verify_core::wasm_module;
pub use wsc_verify_core::{
    CoreError, SIGNATURE_HASH_FUNCTION, SIGNATURE_VERSION, SIGNATURE_WASM_DOMAIN,
    SIGNATURE_WASM_MODULE_CONTENT_TYPE,
};

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

/// Format-agnostic artifact signing and verification
///
/// Provides a trait-based abstraction for signing different artifact formats
/// (WASM, ELF, MCUboot) with the same Ed25519 signing core. Includes format
/// detection, consistency validation, and per-format signature embedding.
pub mod format;

/// DSSE (Dead Simple Signing Envelope) implementation
///
/// Provides the standard DSSE envelope format for signing attestations.
/// Used as the wrapper for all embedded attestations, enabling extraction
/// and verification with standard tooling (cosign, sigstore-rs, etc.).
/// See: https://github.com/secure-systems-lab/dsse
///
/// Carved out into the standalone `no_std` `wsc-dsse` crate (issue #218 /
/// REQ-24) so embedded/offline consumers can verify DSSE envelopes without
/// wsc's registry/TLS/X.509 tree. Re-exported here so `wsc::dsse::*` still
/// resolves for existing callers.
pub use wsc_dsse as dsse;

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

/// Transcoding attestation protocol for WASM-to-native compilation
///
/// Provides the attestation format for recording provenance when compiling
/// WASM modules to native code (ARM ELF, MCUboot). Uses in-toto Statement
/// with a custom predicate to capture source verification, compiler identity,
/// target platform, and compilation parameters.
pub mod transcoding;

/// Container image signing via cosign delegation
///
/// Provides safe cosign subprocess delegation with binary integrity
/// verification, tag-to-digest resolution, and digest-bound signatures.
/// Addresses UCA-18 through UCA-21 from STPA-Sec analysis.
pub mod container;

/// Post-quantum cryptography support (SLH-DSA / FIPS 205)
///
/// Trait-based abstraction for post-quantum signature schemes alongside
/// classical Ed25519. Defines SLH-DSA parameter sets and hybrid signing
/// for the PQC transition period.
pub mod pqc;

/// Signed Certificate Timestamp (SCT) monitoring (Phase 4.2)
///
/// Monitors Certificate Transparency logs for certificate mis-issuance.
/// SCTs prove a certificate was submitted to a CT log before issuance,
/// enabling detection of rogue CA certificates.
pub mod sct;

/// Build environment attestation for SLSA provenance
///
/// Captures build environment metadata (Rust, Bazel, Nix versions, platform)
/// for embedding in SLSA provenance as internal parameters. Supports both
/// automatic detection and CI environment variable configuration via WSC_*
/// prefix. Addresses Ferrocene RUSTC_CSTR_0030 for tool version verification.
pub mod build_env;

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
// Wide re-export of the verification core's top-level items so existing
// callers continue to see `wsc::Module`, `wsc::PublicKey`, etc.
#[allow(unused_imports)]
pub use wsc_verify_core::signature::*;
#[allow(unused_imports)]
pub use wsc_verify_core::wasm_module::*;

// Re-export keyless module for public API
pub use signature::keyless;

pub mod reexports {
    pub use {anyhow, ct_codecs, getrandom, hmac_sha256, log, regex, thiserror};
}
