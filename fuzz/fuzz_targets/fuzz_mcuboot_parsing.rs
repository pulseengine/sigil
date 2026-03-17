//! Fuzz target for MCUboot firmware image parsing
//!
//! Tests the MCUboot artifact parser which handles:
//! - MCUboot magic byte validation
//! - Image header parsing (ih_img_size, ih_hdr_size)
//! - Independent image size verification (SC-13)
//! - Header size vs file content consistency (UCA-14, AS-15)
//! - Resource bounds enforcement (16MB max)
//! - Payload extraction
//! - TLV trailer signature embedding
//!
//! Security concerns:
//! - Header ih_img_size declares smaller size than actual content,
//!   causing partial-image signature (AS-15)
//! - Integer overflows in header_size + image_size calculation
//! - Truncated input with valid magic but incomplete header
//! - Maximum size enforcement bypass
//! - TLV serialization with signature attachment

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::format::mcuboot::McubootArtifact;
use wsc::format::{FormatType, SignableArtifact};

fuzz_target!(|data: &[u8]| {
    // Test MCUboot parsing with all validation checks
    if let Ok(mut artifact) = McubootArtifact::from_bytes(data.to_vec()) {
        // Exercise hash computation (must not panic)
        let _ = artifact.compute_hash();

        // Exercise format type
        assert_eq!(artifact.format_type(), FormatType::Mcuboot);

        // Exercise content bytes (payload extraction)
        let payload_len = artifact.content_bytes().len();
        // Payload must not be empty if parsing succeeded
        assert!(payload_len > 0);

        // Exercise signature attachment and serialization roundtrip
        let fake_sig = vec![0xAA; 64]; // Ed25519 signature size
        if artifact.attach_signature(&fake_sig).is_ok() {
            let mut output = Vec::new();
            let _ = artifact.serialize(&mut output);

            // Output should be larger than payload (TLV trailer added)
            if !output.is_empty() {
                assert!(output.len() >= payload_len);
            }
        }

        // Exercise signature detachment
        let _ = artifact.detach_signature();
    }
});
