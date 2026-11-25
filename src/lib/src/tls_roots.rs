//! Root certificates for outbound TLS: the operating system's trust store.
//!
//! sigil bundles no root certificates. Every HTTPS connection it makes
//! (Fulcio, Rekor, OIDC token endpoints, the Sigstore trusted root, and the
//! base WebPKI check under certificate pinning) trusts exactly what the host
//! trusts:
//!
//! - **native targets**: the platform store, through `rustls-native-certs`
//!   (macOS keychain trust settings, the Windows certificate store, the
//!   OpenSSL-style bundle and directories on Linux and other Unix systems).
//!   If `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, those replace the
//!   platform store on every OS.
//! - **wasm32**: there is no platform store, so `SSL_CERT_FILE` (a PEM bundle
//!   the runtime makes readable) is the only source.
//!
//! There is no fallback to a compiled-in root set. An empty store is an
//! error that names the fix, never a silent switch to roots the operator did
//! not choose.

use crate::error::WSError;
use rustls_pki_types::CertificateDer;

/// What to do when no root certificate could be loaded.
pub const NO_ROOTS_HELP: &str = "sigil uses the operating system's trust store and bundles no \
     root certificates. Install the system CA bundle (the `ca-certificates` package on \
     Debian, Ubuntu, Alpine and Fedora; it is often missing from minimal container images), \
     or set SSL_CERT_FILE to a PEM file of trusted root certificates";

fn no_roots(detail: &str) -> WSError {
    WSError::NoTrustedRoots(format!("{detail}. {NO_ROOTS_HELP}"))
}

/// The root certificates the host trusts, in DER.
///
/// Errors with [`WSError::NoTrustedRoots`] when none can be loaded.
#[cfg(not(target_arch = "wasm32"))]
pub fn os_root_certs() -> Result<Vec<CertificateDer<'static>>, WSError> {
    let loaded = rustls_native_certs::load_native_certs();
    for e in &loaded.errors {
        log::warn!("trust store: {e}");
    }
    if loaded.certs.is_empty() {
        let detail = if loaded.errors.is_empty() {
            "the trust store is empty".to_string()
        } else {
            let errs: Vec<String> = loaded.errors.iter().map(|e| e.to_string()).collect();
            format!("the trust store could not be read ({})", errs.join("; "))
        };
        return Err(no_roots(&detail));
    }
    Ok(loaded.certs)
}

/// The root certificates in `SSL_CERT_FILE`, in DER (wasm32 has no platform
/// store).
///
/// Errors with [`WSError::NoTrustedRoots`] when the variable is unset, the
/// file cannot be read, or it holds no certificate.
#[cfg(target_arch = "wasm32")]
pub fn os_root_certs() -> Result<Vec<CertificateDer<'static>>, WSError> {
    let path = std::env::var_os("SSL_CERT_FILE")
        .ok_or_else(|| no_roots("SSL_CERT_FILE is not set and wasm32 has no platform store"))?;
    let data = std::fs::read(&path).map_err(|e| {
        no_roots(&format!(
            "SSL_CERT_FILE={} could not be read ({e})",
            std::path::Path::new(&path).display()
        ))
    })?;
    let certs = pem_certificates(&data);
    if certs.is_empty() {
        return Err(no_roots(&format!(
            "SSL_CERT_FILE={} holds no PEM certificate",
            std::path::Path::new(&path).display()
        )));
    }
    Ok(certs)
}

#[cfg(any(target_arch = "wasm32", test))]
fn pem_certificates(data: &[u8]) -> Vec<CertificateDer<'static>> {
    pem::parse_many(data)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect()
}

/// A rustls root store built from [`os_root_certs`].
///
/// Errors with [`WSError::NoTrustedRoots`] when no loaded certificate parses
/// as a trust anchor.
pub fn os_root_store() -> Result<rustls::RootCertStore, WSError> {
    let certs = os_root_certs()?;
    let total = certs.len();
    let mut store = rustls::RootCertStore::empty();
    let (added, ignored) = store.add_parsable_certificates(certs);
    if ignored > 0 {
        log::warn!("trust store: {ignored} of {total} certificates could not be used as roots");
    }
    if added == 0 {
        return Err(no_roots(&format!(
            "none of the {total} certificates in the trust store is a usable root"
        )));
    }
    log::debug!("trust store: {added} root certificates");
    Ok(store)
}

/// ureq TLS settings that trust [`os_root_certs`] and use the ring provider.
///
/// Every `ureq::Agent` sigil builds must use this: ureq is compiled without
/// its bundled roots, so an agent without explicit roots fails its first
/// HTTPS request instead of falling back to them.
pub fn ureq_tls_config() -> Result<ureq::tls::TlsConfig, WSError> {
    let certs: Vec<ureq::tls::Certificate<'static>> = os_root_certs()?
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();
    Ok(ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
        .unversioned_rustls_crypto_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .build())
}

/// A ureq agent that trusts [`os_root_certs`], with HTTP status codes
/// returned as responses rather than errors.
pub fn os_agent() -> Result<ureq::Agent, WSError> {
    Ok(ureq::Agent::config_builder()
        .http_status_as_error(false)
        .tls_config(ureq_tls_config()?)
        .build()
        .into())
}

/// The body of a 2xx response, or an error naming the status and quoting
/// the first 200 characters of the body.
///
/// [`os_agent`] returns HTTP error statuses as responses, so a caller that
/// expects success must check the status; otherwise an error page reaches a
/// JSON parser and the status is lost ("expected value at line 1 column 1").
pub fn success_body(response: ureq::http::Response<ureq::Body>) -> Result<String, String> {
    let status = response.status();
    let body = response
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read response body: {e}"))?;
    if status.is_success() {
        return Ok(body);
    }
    let snippet: String = body.chars().take(200).collect();
    Err(format!("HTTP {status}: {snippet}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_certificates_reads_only_certificate_blocks() {
        let ca = rcgen::generate_simple_self_signed(vec!["test".into()]).unwrap();
        let cert_pem = ca.cert.pem();
        let key_pem = ca.signing_key.serialize_pem();
        let both = format!("{key_pem}\n{cert_pem}\n{cert_pem}");
        assert_eq!(pem_certificates(both.as_bytes()).len(), 2);
        assert!(pem_certificates(key_pem.as_bytes()).is_empty());
        assert!(pem_certificates(b"").is_empty());
    }

    #[test]
    fn no_roots_error_names_the_fix() {
        let msg = no_roots("the trust store is empty").to_string();
        assert!(msg.contains("ca-certificates"), "{msg}");
        assert!(msg.contains("SSL_CERT_FILE"), "{msg}");
    }
}
