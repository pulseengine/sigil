// The classic signature core (`hash`, `info`, `keys`, `matrix`, `multi`,
// `sig_sections`, `simple`) lives in `wsc-verify-core` so it builds for
// `wasm32-*` without TLS/X.509 deps. Re-export it here so the existing
// `wsc::signature::*` public API is unchanged.
pub use wsc_verify_core::signature::*;

/// Keyless signing support — OIDC + Fulcio + Rekor. Stays in `wsc` because
/// it depends on `rustls`/`ureq`/`x509-parser`, which the carved core
/// deliberately avoids.
pub mod keyless;
