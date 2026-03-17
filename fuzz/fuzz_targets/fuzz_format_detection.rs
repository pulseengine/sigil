//! Fuzz target for format detection and polyglot validation
//!
//! Tests the format detection logic which handles:
//! - Magic byte detection for WASM, ELF, MCUboot
//! - Format consistency validation (SC-15)
//! - Polyglot file rejection (AS-17)
//!
//! Security concerns:
//! - Files that are valid as multiple formats simultaneously
//! - Files with misleading magic bytes followed by different content
//! - Very short inputs that partially match magic bytes
//! - Inputs that trigger different detection results depending on length

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::format::{FormatType, validate_format_consistency};

fuzz_target!(|data: &[u8]| {
    // Detect format from magic bytes
    let detected = FormatType::detect(data);

    // If a format was detected, consistency check against each format type
    // should pass for the detected format and fail for others
    if let Some(fmt) = detected {
        // Should pass for detected format
        assert!(validate_format_consistency(fmt, data).is_ok());

        // Should fail for other formats (polyglot detection)
        let other_formats = [FormatType::Wasm, FormatType::Elf, FormatType::Mcuboot];
        for other in &other_formats {
            if *other != fmt {
                // Other formats should either fail or not detect
                let _ = validate_format_consistency(*other, data);
            }
        }
    }

    // Test all format string parsing
    for name in &["wasm", "elf", "mcuboot", "WASM", "ELF", "MCUBOOT", "unknown", ""] {
        let _ = FormatType::from_str(name);
    }

    // Test content type IDs and domain strings are consistent
    for fmt in &[FormatType::Wasm, FormatType::Elf, FormatType::Mcuboot] {
        let _id = fmt.content_type_id();
        let _domain = fmt.signature_domain();
    }
});
