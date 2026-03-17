//! Fuzz target for ELF binary parsing
//!
//! Tests the ELF artifact parser which handles:
//! - ELF header validation (magic bytes, class, endianness)
//! - Section header table parsing and consistency checks (SC-12)
//! - Section overlap detection (UCA-13)
//! - Resource bounds enforcement (UCA-17: 256MB max, 4096 max sections)
//! - .sigil section discovery
//! - Full-file hash computation (AS-14)
//!
//! Security concerns:
//! - Malformed section headers with overlapping ranges
//! - Integer overflows in offset/size calculations
//! - Excessive section counts triggering memory exhaustion
//! - Inconsistent 32-bit vs 64-bit header fields
//! - Circular or out-of-bounds string table references
//! - Polyglot files with both WASM and ELF magic (AS-17)

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::format::elf::ElfArtifact;
use wsc::format::{FormatType, SignableArtifact, validate_format_consistency};

fuzz_target!(|data: &[u8]| {
    // Test ELF parsing with all validation checks
    if let Ok(artifact) = ElfArtifact::from_bytes(data.to_vec()) {
        // Exercise hash computation (must not panic)
        let _ = artifact.compute_hash();

        // Exercise format type
        assert_eq!(artifact.format_type(), FormatType::Elf);

        // Exercise content bytes access
        let _ = artifact.content_bytes();

        // Exercise signature detachment
        let _ = artifact.detach_signature();

        // Exercise serialization
        let mut output = Vec::new();
        let _ = artifact.serialize(&mut output);
    }

    // Test format detection on the input
    let _ = FormatType::detect(data);

    // Test format consistency validation
    // This should catch polyglot files (AS-17)
    if data.len() >= 4 {
        let _ = validate_format_consistency(FormatType::Elf, data);
        let _ = validate_format_consistency(FormatType::Wasm, data);
        let _ = validate_format_consistency(FormatType::Mcuboot, data);
    }
});
