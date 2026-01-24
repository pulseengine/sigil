//! HTTP client abstraction for sync/async support
//!
//! This module provides a unified HTTP client interface that works in both
//! synchronous and asynchronous contexts using the `maybe_async` crate.
//!
//! # Feature Flags
//!
//! - `sync` (default): Uses `ureq` for synchronous HTTP requests
//! - `async`: Uses `reqwest` with `tokio` for asynchronous HTTP requests
//!
//! # Example
//!
//! ```ignore
//! use wsc::http::{HttpClient, SimpleHttpClient};
//!
//! let client = SimpleHttpClient::new();
//! let response = client.get("https://example.com/api", &headers)?;
//! ```

use crate::error::WSError;
use std::collections::HashMap;

/// HTTP response structure
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: u16,
    /// Response body as bytes
    pub body: Vec<u8>,
    /// Response headers
    pub headers: HashMap<String, String>,
}

impl HttpResponse {
    /// Check if the response status indicates success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Get the response body as a UTF-8 string
    pub fn text(&self) -> Result<String, WSError> {
        String::from_utf8(self.body.clone())
            .map_err(|e| WSError::InternalError(format!("Invalid UTF-8 in response: {}", e)))
    }

    /// Parse the response body as JSON
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, WSError> {
        serde_json::from_slice(&self.body)
            .map_err(|e| WSError::InternalError(format!("JSON parse error: {}", e)))
    }
}

/// Trait for HTTP clients supporting both sync and async operations
///
/// This trait uses `maybe_async` to provide a unified API that works
/// in both synchronous and asynchronous contexts based on feature flags.
#[maybe_async::maybe_async]
pub trait HttpClient: Send + Sync {
    /// Perform a GET request
    ///
    /// # Arguments
    /// * `url` - The URL to request
    /// * `headers` - Optional headers to include
    async fn get(
        &self,
        url: &str,
        headers: &HashMap<String, String>,
    ) -> Result<HttpResponse, WSError>;

    /// Perform a POST request with a body
    ///
    /// # Arguments
    /// * `url` - The URL to request
    /// * `body` - Request body bytes
    /// * `content_type` - Content-Type header value
    /// * `headers` - Additional headers to include
    async fn post(
        &self,
        url: &str,
        body: &[u8],
        content_type: &str,
        headers: &HashMap<String, String>,
    ) -> Result<HttpResponse, WSError>;
}

/// Simple HTTP client implementation
///
/// Uses `ureq` in sync mode and `reqwest` in async mode.
#[derive(Debug, Clone)]
pub struct SimpleHttpClient {
    /// User-Agent header value
    user_agent: String,
    /// Request timeout in seconds
    timeout_secs: u64,
}

impl Default for SimpleHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleHttpClient {
    /// Create a new HTTP client with default settings
    pub fn new() -> Self {
        Self {
            user_agent: format!("wsc/{}", env!("CARGO_PKG_VERSION")),
            timeout_secs: 30,
        }
    }

    /// Create a client with custom timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Create a client with custom user agent
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }
}

// Synchronous implementation using ureq
#[cfg(all(feature = "sync", not(target_arch = "wasm32")))]
mod sync_impl {
    use super::*;

    #[maybe_async::sync_impl]
    impl HttpClient for SimpleHttpClient {
        fn get(
            &self,
            url: &str,
            headers: &HashMap<String, String>,
        ) -> Result<HttpResponse, WSError> {
            let config = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(std::time::Duration::from_secs(self.timeout_secs)))
                .build();
            let agent = ureq::Agent::new_with_config(config);

            let mut request = agent.get(url);
            request = request.header("User-Agent", &self.user_agent);

            for (key, value) in headers {
                request = request.header(key, value);
            }

            let response = request.call().map_err(|e| {
                WSError::InternalError(format!("HTTP GET failed: {}", e))
            })?;

            let status = response.status().as_u16();
            let mut response_headers = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(v) = value.to_str() {
                    response_headers.insert(name.to_string(), v.to_string());
                }
            }

            let body = response
                .into_body()
                .read_to_vec()
                .map_err(|e| WSError::InternalError(format!("Failed to read response body: {}", e)))?;

            Ok(HttpResponse {
                status,
                body,
                headers: response_headers,
            })
        }

        fn post(
            &self,
            url: &str,
            body: &[u8],
            content_type: &str,
            headers: &HashMap<String, String>,
        ) -> Result<HttpResponse, WSError> {
            let config = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(std::time::Duration::from_secs(self.timeout_secs)))
                .build();
            let agent = ureq::Agent::new_with_config(config);

            let mut request = agent.post(url);
            request = request.header("User-Agent", &self.user_agent);
            request = request.header("Content-Type", content_type);

            for (key, value) in headers {
                request = request.header(key, value);
            }

            let response = request.send(body).map_err(|e| {
                WSError::InternalError(format!("HTTP POST failed: {}", e))
            })?;

            let status = response.status().as_u16();
            let mut response_headers = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(v) = value.to_str() {
                    response_headers.insert(name.to_string(), v.to_string());
                }
            }

            let body = response
                .into_body()
                .read_to_vec()
                .map_err(|e| WSError::InternalError(format!("Failed to read response body: {}", e)))?;

            Ok(HttpResponse {
                status,
                body,
                headers: response_headers,
            })
        }
    }
}

// Asynchronous implementation using reqwest
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
mod async_impl {
    use super::*;

    #[maybe_async::async_impl]
    impl HttpClient for SimpleHttpClient {
        async fn get(
            &self,
            url: &str,
            headers: &HashMap<String, String>,
        ) -> Result<HttpResponse, WSError> {
            let client = reqwest::Client::builder()
                .user_agent(&self.user_agent)
                .timeout(std::time::Duration::from_secs(self.timeout_secs))
                .build()
                .map_err(|e| WSError::InternalError(format!("Failed to create HTTP client: {}", e)))?;

            let mut request = client.get(url);

            for (key, value) in headers {
                request = request.header(key, value);
            }

            let response = request.send().await.map_err(|e| {
                WSError::InternalError(format!("HTTP GET failed: {}", e))
            })?;

            let status = response.status().as_u16();
            let response_headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let body = response.bytes().await.map_err(|e| {
                WSError::InternalError(format!("Failed to read response body: {}", e))
            })?;

            Ok(HttpResponse {
                status,
                body: body.to_vec(),
                headers: response_headers,
            })
        }

        async fn post(
            &self,
            url: &str,
            body: &[u8],
            content_type: &str,
            headers: &HashMap<String, String>,
        ) -> Result<HttpResponse, WSError> {
            let client = reqwest::Client::builder()
                .user_agent(&self.user_agent)
                .timeout(std::time::Duration::from_secs(self.timeout_secs))
                .build()
                .map_err(|e| WSError::InternalError(format!("Failed to create HTTP client: {}", e)))?;

            let mut request = client
                .post(url)
                .header("Content-Type", content_type)
                .body(body.to_vec());

            for (key, value) in headers {
                request = request.header(key, value);
            }

            let response = request.send().await.map_err(|e| {
                WSError::InternalError(format!("HTTP POST failed: {}", e))
            })?;

            let status = response.status().as_u16();
            let response_headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let body = response.bytes().await.map_err(|e| {
                WSError::InternalError(format!("Failed to read response body: {}", e))
            })?;

            Ok(HttpResponse {
                status,
                body: body.to_vec(),
                headers: response_headers,
            })
        }
    }
}

// WASM target placeholder - HTTP not available in WASM components
// WASM uses WASI HTTP which requires different handling (WASI 0.3 for async)
// For now, the crypto component doesn't need HTTP, so we provide a stub
#[cfg(target_arch = "wasm32")]
impl SimpleHttpClient {
    /// WASM stub - HTTP not available
    pub fn get_sync(
        &self,
        _url: &str,
        _headers: &HashMap<String, String>,
    ) -> Result<HttpResponse, WSError> {
        Err(WSError::InternalError(
            "HTTP client not available for WASM target".to_string(),
        ))
    }

    /// WASM stub - HTTP not available
    pub fn post_sync(
        &self,
        _url: &str,
        _body: &[u8],
        _content_type: &str,
        _headers: &HashMap<String, String>,
    ) -> Result<HttpResponse, WSError> {
        Err(WSError::InternalError(
            "HTTP client not available for WASM target".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_response_is_success() {
        let response = HttpResponse {
            status: 200,
            body: vec![],
            headers: HashMap::new(),
        };
        assert!(response.is_success());

        let response = HttpResponse {
            status: 404,
            body: vec![],
            headers: HashMap::new(),
        };
        assert!(!response.is_success());
    }

    #[test]
    fn test_http_response_text() {
        let response = HttpResponse {
            status: 200,
            body: b"hello world".to_vec(),
            headers: HashMap::new(),
        };
        assert_eq!(response.text().unwrap(), "hello world");
    }

    #[test]
    fn test_simple_http_client_builder() {
        let client = SimpleHttpClient::new()
            .with_timeout(60)
            .with_user_agent("test-agent/1.0");

        assert_eq!(client.timeout_secs, 60);
        assert_eq!(client.user_agent, "test-agent/1.0");
    }
}
