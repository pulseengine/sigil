//! Wasmtime runtime for hosting WASM components with hardware crypto.
//!
//! This module provides the host-side implementation of the `wsc:crypto`
//! WIT interface, allowing WASM components to access hardware-backed
//! cryptographic operations (TPM, HSM, Secure Element) through opaque handles.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  WASM Component (guest)                                      │
//! │  imports: wsc:crypto/hardware-signing                        │
//! │                                                              │
//! │  // Component code calls:                                    │
//! │  let handle = hardware_signing::generate_key(...)?;          │
//! │  let sig = hardware_signing::sign(handle, data)?;            │
//! └─────────────────────────┬───────────────────────────────────┘
//!                           │ WIT call
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  CryptoHost (this module)                                    │
//! │  implements: wsc:crypto/hardware-signing                     │
//! │                                                              │
//! │  Bridges WIT interface to SecureKeyProvider trait            │
//! └─────────────────────────┬───────────────────────────────────┘
//!                           │ Rust trait call
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  SecureKeyProvider implementation                            │
//! │  (SoftwareProvider, KeyringProvider, TPM2Provider, etc.)     │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Feature Flag
//!
//! This module requires the `runtime` feature:
//!
//! ```toml
//! [dependencies]
//! wsc = { version = "0.5", features = ["runtime"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use wsc::runtime::{WscRuntime, CryptoHostState};
//! use wsc::platform::SoftwareProvider;
//!
//! // Create runtime with software crypto backend
//! let provider = SoftwareProvider::new()?;
//! let mut runtime = WscRuntime::new(provider)?;
//!
//! // Load and run a WASM component
//! let component_bytes = std::fs::read("signing-tool.wasm")?;
//! runtime.run_component(&component_bytes, &["sign", "input.wasm"])?;
//! ```

mod crypto_host;

pub use crypto_host::{CryptoHostState, WscRuntime};

// Re-export key types for convenience
pub use crate::platform::{KeyHandle, SecureKeyProvider, SecurityLevel};
