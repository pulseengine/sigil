//! Build script for wsc library
//!
//! Sets the WSC_BUILD_TIMESTAMP environment variable for use in time.rs.
//! This provides a compile-time lower bound for time validation.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Get current Unix timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_secs();

    // Set as environment variable for compile-time access
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-env=WSC_BUILD_TIMESTAMP={}", timestamp);

    // Declare the `kani` cfg used by Kani harnesses so rustc does not warn
    // under non-Kani builds. See Kani docs:
    // https://model-checking.github.io/kani/cargo-features.html
    println!("cargo::rustc-check-cfg=cfg(kani)");
}
