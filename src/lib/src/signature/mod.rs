mod hash;
mod info;
pub mod keyless;
mod keys;
mod matrix;
mod multi;
mod sig_sections;
mod simple;

pub use info::*;
pub use keys::*;
pub use matrix::*;

pub(crate) use hash::*;

// Re-export signature data structures for fuzzing and advanced use cases
pub use sig_sections::{
    MAX_HASHES, MAX_SIGNATURES, SIGNATURE_SECTION_DELIMITER_NAME, SIGNATURE_SECTION_HEADER_NAME,
    SignatureData, SignatureForHashes, SignedHashes, new_delimiter_section,
};
