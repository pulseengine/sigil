//! Custom TLS transport with certificate pinning support
//!
//! This module provides a pinned HTTP client that enforces certificate pinning
//! for Sigstore endpoints (Fulcio, Rekor). It creates a custom rustls connector
//! that uses our `PinnedCertVerifier` for defense-in-depth against CA compromise.
//!
//! # Security
//!
//! Certificate pinning provides defense-in-depth against:
//! - CA compromise (even a trusted CA cannot issue rogue certificates)
//! - DNS/BGP hijacking with valid-looking certificates
//! - Targeted MITM attacks on specific infrastructure
//!
//! # Architecture
//!
//! This module creates a custom connector chain:
//! 1. `TcpConnector` - Opens raw TCP socket
//! 2. `PinnedRustlsConnector` - Wraps socket in TLS with certificate pinning
//!
//! The pinning is enforced at the TLS layer during the handshake, before any
//! HTTP data is exchanged.
//!
//! # Usage
//!
//! ```ignore
//! use wsc::signature::keyless::transport::create_pinned_agent;
//! use wsc::signature::keyless::cert_pinning::PinningConfig;
//!
//! let config = PinningConfig::fulcio_production();
//! let agent = create_pinned_agent(config)?;
//! let response = agent.get("https://fulcio.sigstore.dev/api/v2/...").call()?;
//! ```

use crate::error::WSError;
use crate::signature::keyless::cert_pinning::{PinningConfig, PinnedCertVerifier};
use std::convert::TryInto;
use std::fmt;
use std::sync::Arc;

#[cfg(not(target_os = "wasi"))]
use rustls::{ClientConfig, ClientConnection, StreamOwned};
#[cfg(not(target_os = "wasi"))]
use rustls_pki_types::ServerName;
#[cfg(not(target_os = "wasi"))]
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, TcpConnector,
    Transport, TransportAdapter,
};

/// Custom rustls connector with certificate pinning.
///
/// This connector wraps TLS connections with our `PinnedCertVerifier` which
/// validates certificates against known SHA256 fingerprints in addition to
/// standard WebPKI validation.
#[cfg(not(target_os = "wasi"))]
pub struct PinnedRustlsConnector {
    /// Cached rustls ClientConfig with pinned verifier
    config: Arc<ClientConfig>,
}

#[cfg(not(target_os = "wasi"))]
impl PinnedRustlsConnector {
    /// Create a new connector with certificate pinning enabled.
    ///
    /// # Arguments
    /// * `pinning` - Certificate pinning configuration
    ///
    /// # Errors
    /// Returns error if TLS configuration fails
    pub fn new(pinning: PinningConfig) -> Result<Self, WSError> {
        let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());

        // Create our custom certificate verifier with pinning
        let verifier = PinnedCertVerifier::new(pinning, crypto_provider.clone())?;

        // Build ClientConfig with our pinned verifier
        let config = ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| WSError::CertificatePinningError(format!("TLS version error: {}", e)))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        log::info!("Created PinnedRustlsConnector with certificate pinning");

        Ok(Self {
            config: Arc::new(config),
        })
    }
}

#[cfg(not(target_os = "wasi"))]
impl fmt::Debug for PinnedRustlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedRustlsConnector")
            .field("config", &"ClientConfig with PinnedCertVerifier")
            .finish()
    }
}

/// TLS transport wrapper for pinned connections.
#[cfg(not(target_os = "wasi"))]
pub struct PinnedRustlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter<Box<dyn Transport>>>,
}

#[cfg(not(target_os = "wasi"))]
impl fmt::Debug for PinnedRustlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedRustlsTransport").finish()
    }
}

#[cfg(not(target_os = "wasi"))]
impl<In: Transport> Connector<In> for PinnedRustlsConnector {
    type Out = Either<In, PinnedRustlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            panic!("PinnedRustlsConnector requires a chained transport");
        };

        // Only add TLS if connecting via HTTPS and not already TLS
        if !details.needs_tls() || transport.is_tls() {
            log::trace!("PinnedRustlsConnector: Skip (not HTTPS or already TLS)");
            return Ok(Some(Either::A(transport)));
        }

        log::trace!("PinnedRustlsConnector: Wrapping connection in pinned TLS");

        // Get server name from URI
        let name_borrowed: ServerName<'_> = details
            .uri
            .authority()
            .expect("uri authority for tls")
            .host()
            .try_into()
            .map_err(|e| {
                log::debug!("PinnedRustlsConnector: invalid dns name: {}", e);
                ureq::Error::Tls("Invalid DNS name for TLS")
            })?;
        let name = name_borrowed.to_owned();

        // Create TLS connection with our pinned config
        let conn = ClientConnection::new(self.config.clone(), name)?;
        let stream = StreamOwned {
            conn,
            sock: TransportAdapter::new(transport.boxed()),
        };

        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );

        let transport = PinnedRustlsTransport { buffers, stream };

        log::debug!("PinnedRustlsConnector: Wrapped TLS with certificate pinning");

        Ok(Some(Either::B(transport)))
    }
}

#[cfg(not(target_os = "wasi"))]
impl Transport for PinnedRustlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        use std::io::Write;

        self.stream.sock.set_timeout(timeout);
        let output = self.buffers.output();
        self.stream.write_all(&output[..amount])?;
        self.stream.flush()?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        use std::io::Read;

        self.stream.sock.set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        !self.stream.conn.is_handshaking()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

/// Create a ureq Agent with certificate pinning enabled.
///
/// This function creates an HTTP client that:
/// 1. Performs standard WebPKI certificate validation
/// 2. Additionally checks certificates against pinned SHA256 fingerprints
/// 3. Fails the connection if pins don't match (when enforce mode is on)
///
/// # Arguments
/// * `pinning` - Certificate pinning configuration with SHA256 fingerprints
///
/// # Returns
/// A configured ureq::Agent that enforces certificate pinning
///
/// # Errors
/// Returns `WSError::CertificatePinningError` if TLS configuration fails
#[cfg(not(target_os = "wasi"))]
pub fn create_pinned_agent(pinning: PinningConfig) -> Result<ureq::Agent, WSError> {
    use ureq::unversioned::resolver::DefaultResolver;

    // Create custom connector chain: TCP -> Pinned TLS
    let connector = ()
        .chain(TcpConnector::default())
        .chain(PinnedRustlsConnector::new(pinning)?);

    // Build agent with custom connector
    let config = ureq::config::Config::builder()
        .http_status_as_error(false)
        .build();

    let resolver = DefaultResolver::default();
    let agent = ureq::Agent::with_parts(config, connector, resolver);

    log::info!("Created HTTP agent with certificate pinning enabled");

    Ok(agent)
}

/// Create a ureq Agent without certificate pinning (fallback).
///
/// This function creates a standard HTTP client without custom TLS configuration.
/// Use this when certificate pinning is disabled or not available.
///
/// # Returns
/// A configured ureq::Agent with standard WebPKI validation
#[cfg(not(target_os = "wasi"))]
pub fn create_standard_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

/// Create an HTTP agent with optional certificate pinning.
///
/// This is the recommended function for creating HTTP clients. It automatically:
/// - Enables certificate pinning if a valid `PinningConfig` is provided
/// - Falls back to standard WebPKI if pinning config is empty or fails
/// - Respects `WSC_REQUIRE_CERT_PINNING` environment variable
///
/// # Arguments
/// * `pinning` - Optional certificate pinning configuration
///
/// # Returns
/// A configured ureq::Agent
///
/// # Errors
/// Returns error only if `WSC_REQUIRE_CERT_PINNING=1` and pinning cannot be configured
#[cfg(not(target_os = "wasi"))]
pub fn create_agent_with_optional_pinning(
    pinning: Option<PinningConfig>,
) -> Result<ureq::Agent, WSError> {
    let require_pinning = std::env::var("WSC_REQUIRE_CERT_PINNING")
        .unwrap_or_default()
        == "1";

    match pinning {
        Some(config) if config.is_enabled() => {
            match create_pinned_agent(config) {
                Ok(agent) => Ok(agent),
                Err(e) => {
                    if require_pinning {
                        Err(e)
                    } else {
                        log::warn!("Failed to enable certificate pinning: {}. Falling back to standard TLS.", e);
                        Ok(create_standard_agent())
                    }
                }
            }
        }
        _ => {
            if require_pinning {
                Err(WSError::CertificatePinningError(
                    "Certificate pinning required (WSC_REQUIRE_CERT_PINNING=1) but no pins configured".to_string()
                ))
            } else {
                log::debug!("Certificate pinning disabled, using standard TLS");
                Ok(create_standard_agent())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_standard_agent() {
        let agent = create_standard_agent();
        // Just verify it can be created
        assert!(format!("{:?}", agent).contains("Agent"));
    }

    #[test]
    fn test_create_pinned_agent() {
        // Create with test pins
        let pins = vec!["a".repeat(64), "b".repeat(64)];
        let config = PinningConfig::custom(pins, "test-service".to_string());

        let result = create_pinned_agent(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_agent_with_optional_pinning_none() {
        // Should fall back to standard agent when no pinning configured
        let result = create_agent_with_optional_pinning(None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_agent_with_optional_pinning_some() {
        let pins = vec!["a".repeat(64)];
        let config = PinningConfig::custom(pins, "test".to_string());

        let result = create_agent_with_optional_pinning(Some(config));
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_agent_with_empty_pinning_config() {
        // Empty config should fall back to standard agent
        let config = PinningConfig::custom(vec![], "test".to_string());

        let result = create_agent_with_optional_pinning(Some(config));
        assert!(result.is_ok());
    }

    #[test]
    fn test_pinned_connector_creation() {
        let pins = vec!["a".repeat(64)];
        let config = PinningConfig::custom(pins, "test".to_string());

        let connector = PinnedRustlsConnector::new(config);
        assert!(connector.is_ok());

        // Check debug output
        let connector = connector.unwrap();
        assert!(format!("{:?}", connector).contains("PinnedRustlsConnector"));
    }
}
