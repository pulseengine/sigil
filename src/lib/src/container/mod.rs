//! Container image signing via cosign delegation.
//!
//! Provides safe cosign subprocess delegation with binary integrity
//! verification, tag-to-digest resolution, and digest-bound signatures.
//! Addresses UCA-18 through UCA-21 from the STPA-Sec analysis.
//!
//! # Design
//!
//! sigil delegates container signing to cosign but enforces:
//! - Binary integrity verification before invocation (AS-20)
//! - Tag-to-digest resolution (AS-18)
//! - Digest binding in signatures (AS-21)
//! - Signature existence verification (AS-19)
//!
//! # Example
//!
//! ```ignore
//! use wsc::container::{ImageReference, CosignDelegator};
//!
//! let delegator = CosignDelegator::new()?;
//! let image = ImageReference::parse("ghcr.io/pulseengine/wsc:v0.5.1")?;
//! let resolved = delegator.resolve_digest(&image)?;
//! delegator.sign(&resolved)?;
//! ```

pub mod bundle;
pub mod cosign;
pub mod digest;
pub mod referrer;

pub use bundle::SigstoreBundle;
pub use cosign::{CosignConfig, CosignDelegator};
pub use digest::ImageReference;
pub use referrer::{ReferrerConfig, SignatureReference};
