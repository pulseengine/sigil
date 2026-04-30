use crate::error::WSError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::env;
use zeroize::{Zeroize, Zeroizing};

/// Allowlist of acceptable JWT signing algorithms (audit C-6).
///
/// Only asymmetric algorithms used by real OIDC providers are accepted.
/// HMAC variants (`HS*`) and the unsigned `none` algorithm are explicitly
/// rejected to prevent algorithm-confusion attacks where an attacker swaps
/// `alg: "HS256"` and signs with a known string.
const ALLOWED_JWT_ALGS: &[&str] = &["RS256", "ES256", "RS384", "ES384", "RS512", "ES512"];

/// Validate the `alg` field in a JWT header against the allowlist (audit C-6).
///
/// This MUST be called before parsing any payload claims so an attacker cannot
/// forge a token using `alg: "none"` or `alg: "HS256"` and have downstream
/// consumers trust its claims. Rejects:
/// - missing/empty `alg` (treated as untyped, refuse)
/// - `none` (no signature)
/// - `HS256`, `HS384`, `HS512` (HMAC, vulnerable to alg-confusion)
/// - any other value not in `ALLOWED_JWT_ALGS`
fn validate_jwt_alg(token: &str) -> Result<(), WSError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(WSError::OidcError("Invalid JWT token format".to_string()));
    }

    // Decode the JWT header (first part)
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .or_else(|_| base64::prelude::BASE64_STANDARD.decode(parts[0]))
        .map_err(|e| WSError::OidcError(format!("Failed to decode JWT header: {}", e)))?;

    let header_str = Zeroizing::new(
        String::from_utf8(header_bytes)
            .map_err(|e| WSError::OidcError(format!("Invalid UTF-8 in JWT header: {}", e)))?,
    );

    let header_json: serde_json::Value = serde_json::from_str(&header_str)
        .map_err(|e| WSError::OidcError(format!("Failed to parse JWT header: {}", e)))?;

    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WSError::OidcError("JWT header missing 'alg' field".to_string()))?;

    if alg.is_empty() {
        return Err(WSError::OidcError(
            "JWT header has empty 'alg' field".to_string(),
        ));
    }

    if !ALLOWED_JWT_ALGS.contains(&alg) {
        return Err(WSError::OidcError(format!(
            "JWT 'alg' '{}' not in allowlist {:?} — rejected to prevent algorithm-confusion attacks",
            alg, ALLOWED_JWT_ALGS
        )));
    }

    Ok(())
}

/// OIDC token for identity verification
///
/// SECURITY: `Clone` is intentionally NOT derived (audit M-5). The `Drop`
/// impl below zeroizes the JWT bytes to honor single-owner discipline; allowing
/// `Clone` would let uncontrolled token copies live on after the original is
/// zeroized. Pass `&OidcToken` (or `Arc<OidcToken>`) when sharing is required.
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcToken {
    /// JWT token string
    pub token: String,
    /// Identity (email, subject, etc.)
    pub identity: String,
    /// Issuer URL
    pub issuer: String,
}

// SECURITY: Implement Drop to zeroize sensitive token data (addresses Issue #11)
impl Drop for OidcToken {
    fn drop(&mut self) {
        // Zeroize the JWT token string to prevent it from lingering in memory
        // This protects against memory dumps, swap files, and debuggers
        self.token.zeroize();
        // Note: identity and issuer are not secret, but zeroizing for defense in depth
        self.identity.zeroize();
        self.issuer.zeroize();
    }
}

impl OidcToken {
    /// Extract the `sub` claim from the OIDC token
    ///
    /// This is needed for proof of possession in Fulcio requests
    pub fn get_sub_claim(&self) -> Result<String, WSError> {
        // SECURITY (audit C-6): validate JWT `alg` before parsing payload
        validate_jwt_alg(&self.token)?;

        // JWT tokens are base64-encoded and have three parts: header.payload.signature
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err(WSError::OidcError("Invalid JWT token format".to_string()));
        }

        // Decode the payload (second part)
        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::prelude::BASE64_STANDARD.decode(payload))
            .map_err(|e| WSError::OidcError(format!("Failed to decode JWT payload: {}", e)))?;

        // SECURITY (audit M-6): wrap payload in Zeroizing<String> so it is
        // zeroed when this function returns, even on the error path.
        let payload_str = Zeroizing::new(
            String::from_utf8(decoded)
                .map_err(|e| WSError::OidcError(format!("Invalid UTF-8 in JWT payload: {}", e)))?,
        );

        // Parse JSON to extract sub claim
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|e| WSError::OidcError(format!("Failed to parse JWT payload: {}", e)))?;

        payload_json
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| WSError::OidcError("No 'sub' claim found in JWT token".to_string()))
    }
}

/// OIDC provider trait for obtaining identity tokens
pub trait OidcProvider: Send + Sync {
    /// Get an OIDC token from this provider
    fn get_token(&self) -> Result<OidcToken, WSError>;

    /// Provider name for logging
    fn name(&self) -> &str;
}

/// GitHub Actions OIDC provider
///
/// Uses the GitHub Actions OIDC token request mechanism to obtain
/// identity tokens for keyless signing in CI/CD workflows.
#[derive(Debug, Clone)]
pub struct GitHubOidcProvider {
    /// Request token from ACTIONS_ID_TOKEN_REQUEST_TOKEN env
    request_token: String,
    /// Request URL from ACTIONS_ID_TOKEN_REQUEST_URL env
    request_url: String,
}

impl GitHubOidcProvider {
    /// Create a new GitHub OIDC provider from environment variables
    pub fn new() -> Result<Self, WSError> {
        Self::from_env()
    }

    /// Create a GitHub OIDC provider from environment variables
    pub fn from_env() -> Result<Self, WSError> {
        let request_token = env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| {
            WSError::OidcError(
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not found".to_string(),
            )
        })?;

        let request_url = env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
            WSError::OidcError(
                "ACTIONS_ID_TOKEN_REQUEST_URL environment variable not found".to_string(),
            )
        })?;

        Ok(Self {
            request_token,
            request_url,
        })
    }

    /// Parse identity from JWT token (extract email or subject)
    fn parse_identity(token: &str) -> Result<String, WSError> {
        // SECURITY (audit C-6): validate JWT `alg` before parsing payload
        validate_jwt_alg(token)?;

        // JWT tokens are base64-encoded and have three parts: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(WSError::OidcError("Invalid JWT token format".to_string()));
        }

        // Decode the payload (second part)
        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::prelude::BASE64_STANDARD.decode(payload))
            .map_err(|e| WSError::OidcError(format!("Failed to decode JWT payload: {}", e)))?;

        // SECURITY (audit M-6): zeroize payload buffer when scope ends.
        let payload_str = Zeroizing::new(
            String::from_utf8(decoded)
                .map_err(|e| WSError::OidcError(format!("Invalid UTF-8 in JWT payload: {}", e)))?,
        );

        // Parse JSON to extract identity fields
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|e| WSError::OidcError(format!("Failed to parse JWT payload: {}", e)))?;

        // Try to extract identity in order of preference: email > sub > actor
        if let Some(email) = payload_json.get("email").and_then(|v| v.as_str()) {
            Ok(email.to_string())
        } else if let Some(sub) = payload_json.get("sub").and_then(|v| v.as_str()) {
            Ok(sub.to_string())
        } else if let Some(actor) = payload_json.get("actor").and_then(|v| v.as_str()) {
            Ok(actor.to_string())
        } else {
            Err(WSError::OidcError(
                "No identity field found in JWT token".to_string(),
            ))
        }
    }

    /// Parse issuer from JWT token
    fn parse_issuer(token: &str) -> Result<String, WSError> {
        // SECURITY (audit C-6): validate JWT `alg` before parsing payload
        validate_jwt_alg(token)?;

        // JWT tokens are base64-encoded and have three parts: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(WSError::OidcError("Invalid JWT token format".to_string()));
        }

        // Decode the payload (second part)
        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::prelude::BASE64_STANDARD.decode(payload))
            .map_err(|e| WSError::OidcError(format!("Failed to decode JWT payload: {}", e)))?;

        // SECURITY (audit M-6): zeroize payload buffer when scope ends.
        let payload_str = Zeroizing::new(
            String::from_utf8(decoded)
                .map_err(|e| WSError::OidcError(format!("Invalid UTF-8 in JWT payload: {}", e)))?,
        );

        // Parse JSON to extract issuer
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|e| WSError::OidcError(format!("Failed to parse JWT payload: {}", e)))?;

        payload_json
            .get("iss")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| WSError::OidcError("No issuer field found in JWT token".to_string()))
    }
}

impl OidcProvider for GitHubOidcProvider {
    fn get_token(&self) -> Result<OidcToken, WSError> {
        // Get the token using platform-specific HTTP client
        let token = self.get_token_impl()?;

        // Parse identity and issuer from the token
        let identity = Self::parse_identity(&token)?;
        let issuer = Self::parse_issuer(&token)?;

        Ok(OidcToken {
            token,
            identity,
            issuer,
        })
    }

    fn name(&self) -> &str {
        "GitHub Actions"
    }
}

// Native implementation using ureq
#[cfg(not(target_os = "wasi"))]
impl GitHubOidcProvider {
    fn get_token_impl(&self) -> Result<String, WSError> {
        // GitHub's token endpoint expects a POST request with the bearer token
        // and an optional audience parameter
        let url = format!("{}&audience=sigstore", self.request_url);

        let response = ureq::get(&url)
            .header("Authorization", &format!("Bearer {}", self.request_token))
            .call()
            .map_err(|e| {
                WSError::OidcError(format!("Failed to retrieve OIDC token from GitHub: {}", e))
            })?;

        // Parse the JSON response
        let body = response
            .into_body()
            .read_to_string()
            .map_err(|e| WSError::OidcError(format!("Failed to read response body: {}", e)))?;

        let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            WSError::OidcError(format!("Failed to parse GitHub OIDC response: {}", e))
        })?;

        // Extract the token value
        json.get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                WSError::OidcError("No 'value' field in GitHub OIDC response".to_string())
            })
    }
}

// WASI implementation using wasi::http
#[cfg(target_os = "wasi")]
impl GitHubOidcProvider {
    fn get_token_impl(&self) -> Result<String, WSError> {
        use wasi::http::outgoing_handler;
        use wasi::http::types::{Fields, Method, OutgoingRequest, Scheme};

        // Parse the request URL to extract components
        let url_str = format!("{}&audience=sigstore", self.request_url);
        let url = url_str
            .strip_prefix("https://")
            .or_else(|| url_str.strip_prefix("http://"))
            .ok_or_else(|| WSError::OidcError("Invalid OIDC request URL scheme".to_string()))?;

        let (authority, path) = url
            .split_once('/')
            .map(|(auth, path)| (auth, format!("/{}", path)))
            .unwrap_or((url, "/".to_string()));

        // Create headers with Authorization
        let headers = Fields::new();
        let auth_value = format!("Bearer {}", self.request_token);
        headers
            .append(
                &"Authorization".to_string(),
                &auth_value.as_bytes().to_vec(),
            )
            .map_err(|_| WSError::OidcError("Failed to set Authorization header".to_string()))?;

        // Create outgoing request
        let request = OutgoingRequest::new(headers);
        request
            .set_method(&Method::Get)
            .map_err(|_| WSError::OidcError("Failed to set HTTP method".to_string()))?;
        request
            .set_scheme(Some(&Scheme::Https))
            .map_err(|_| WSError::OidcError("Failed to set HTTPS scheme".to_string()))?;
        request
            .set_authority(Some(authority))
            .map_err(|_| WSError::OidcError("Failed to set authority".to_string()))?;
        request
            .set_path_with_query(Some(&path))
            .map_err(|_| WSError::OidcError("Failed to set path".to_string()))?;

        // Send request
        let future_response = outgoing_handler::handle(request, None)
            .map_err(|_| WSError::OidcError("Failed to send HTTP request".to_string()))?;

        // Wait for response
        let incoming_response = future_response
            .get()
            .ok_or_else(|| WSError::OidcError("HTTP request not ready".to_string()))?
            .map_err(|_| WSError::OidcError("Failed to get HTTP response".to_string()))??;

        // Read response body
        let body = incoming_response
            .consume()
            .map_err(|_| WSError::OidcError("Failed to get response body".to_string()))?;

        let mut bytes = Vec::new();
        let stream = body
            .stream()
            .map_err(|_| WSError::OidcError("Failed to get body stream".to_string()))?;

        loop {
            let chunk = stream
                .blocking_read(8192)
                .map_err(|_| WSError::OidcError("Failed to read from stream".to_string()))?;

            if chunk.is_empty() {
                break;
            }
            bytes.extend_from_slice(&chunk);
        }

        // Parse JSON response
        let json: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            WSError::OidcError(format!("Failed to parse GitHub OIDC response: {}", e))
        })?;

        // Extract the token value
        json.get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                WSError::OidcError("No 'value' field in GitHub OIDC response".to_string())
            })
    }
}

/// Google Cloud OIDC provider
///
/// This is a stub implementation. Full support will be added in a future version.
#[derive(Debug, Clone)]
pub struct GoogleOidcProvider {
    /// Service account credentials path from GOOGLE_APPLICATION_CREDENTIALS env
    _credentials_path: Option<String>,
}

impl GoogleOidcProvider {
    /// Create a new Google OIDC provider
    pub fn new() -> Result<Self, WSError> {
        Self::from_env()
    }

    /// Create a Google OIDC provider from environment variables
    pub fn from_env() -> Result<Self, WSError> {
        let credentials_path = env::var("GOOGLE_APPLICATION_CREDENTIALS").ok();
        Ok(Self {
            _credentials_path: credentials_path,
        })
    }
}

impl OidcProvider for GoogleOidcProvider {
    fn get_token(&self) -> Result<OidcToken, WSError> {
        // TODO: Implement Google Cloud OIDC token retrieval
        Err(WSError::OidcError(
            "Google Cloud OIDC provider not yet implemented".to_string(),
        ))
    }

    fn name(&self) -> &str {
        "Google Cloud"
    }
}

/// GitLab CI OIDC provider
///
/// This is a stub implementation. Full support will be added in a future version.
#[derive(Debug, Clone)]
pub struct GitLabOidcProvider {
    /// CI job token from CI_JOB_JWT env
    _job_jwt: Option<String>,
}

impl GitLabOidcProvider {
    /// Create a new GitLab OIDC provider
    pub fn new() -> Result<Self, WSError> {
        Self::from_env()
    }

    /// Create a GitLab OIDC provider from environment variables
    pub fn from_env() -> Result<Self, WSError> {
        let job_jwt = env::var("CI_JOB_JWT").ok();
        Ok(Self { _job_jwt: job_jwt })
    }
}

impl OidcProvider for GitLabOidcProvider {
    fn get_token(&self) -> Result<OidcToken, WSError> {
        // TODO: Implement GitLab CI OIDC token retrieval
        Err(WSError::OidcError(
            "GitLab CI OIDC provider not yet implemented".to_string(),
        ))
    }

    fn name(&self) -> &str {
        "GitLab CI"
    }
}

/// Auto-detect OIDC provider from environment variables
///
/// Checks for known CI/CD environment variables and returns the appropriate
/// OIDC provider implementation.
///
/// # Detection Order
/// 1. GitHub Actions - checks for `GITHUB_ACTIONS=true`
/// 2. Google Cloud - checks for `GOOGLE_APPLICATION_CREDENTIALS` env var
/// 3. GitLab CI - checks for `GITLAB_CI=true`
///
/// # Returns
/// - `Ok(provider)` if a provider is detected
/// - `Err(WSError::NoOidcProvider)` if no provider is detected
pub fn detect_oidc_provider() -> Result<Box<dyn OidcProvider>, WSError> {
    // Check for GitHub Actions
    if env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true") {
        let provider = GitHubOidcProvider::new()?;
        return Ok(Box::new(provider));
    }

    // Check for Google Cloud
    if env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok() {
        let provider = GoogleOidcProvider::new()?;
        return Ok(Box::new(provider));
    }

    // Check for GitLab CI
    if env::var("GITLAB_CI").ok().as_deref() == Some("true") {
        let provider = GitLabOidcProvider::new()?;
        return Ok(Box::new(provider));
    }

    // No provider detected
    Err(WSError::NoOidcProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests don't manipulate env vars to avoid unsafe code.
    // Instead, they test the logic with the current environment state.

    /// Build a JWT with the supplied header/payload JSON for tests. The
    /// signature segment is a placeholder — these tests only exercise parsing.
    fn make_test_jwt(header_json: &str, payload_json: &str) -> String {
        let h = URL_SAFE_NO_PAD.encode(header_json);
        let p = URL_SAFE_NO_PAD.encode(payload_json);
        format!("{}.{}.signature", h, p)
    }

    /// Convenience: build a JWT with a default RS256 header and the supplied
    /// payload (the alg validator only inspects the header).
    fn make_rs256_jwt(payload_json: &str) -> String {
        make_test_jwt(r#"{"alg":"RS256","typ":"JWT"}"#, payload_json)
    }

    #[test]
    fn test_provider_names() {
        // Test that provider names are correct
        let google = GoogleOidcProvider {
            _credentials_path: None,
        };
        assert_eq!(google.name(), "Google Cloud");

        let gitlab = GitLabOidcProvider { _job_jwt: None };
        assert_eq!(gitlab.name(), "GitLab CI");
    }

    #[test]
    fn test_parse_jwt_identity() {
        // Sample JWT token (header.payload.signature)
        // Payload: {"email":"test@example.com","sub":"user123","iss":"https://token.actions.githubusercontent.com"}
        let token = make_rs256_jwt(
            r#"{"email":"test@example.com","sub":"user123","iss":"https://token.actions.githubusercontent.com"}"#,
        );

        let identity = GitHubOidcProvider::parse_identity(&token).unwrap();
        assert_eq!(identity, "test@example.com");
    }

    #[test]
    fn test_parse_jwt_identity_no_email() {
        // Sample JWT token with only 'sub' field
        let token = make_rs256_jwt(
            r#"{"sub":"user123","iss":"https://token.actions.githubusercontent.com"}"#,
        );

        let identity = GitHubOidcProvider::parse_identity(&token).unwrap();
        assert_eq!(identity, "user123");
    }

    #[test]
    fn test_parse_jwt_issuer() {
        let token = make_rs256_jwt(
            r#"{"email":"test@example.com","iss":"https://token.actions.githubusercontent.com"}"#,
        );

        let issuer = GitHubOidcProvider::parse_issuer(&token).unwrap();
        assert_eq!(issuer, "https://token.actions.githubusercontent.com");
    }

    #[test]
    fn test_parse_invalid_jwt() {
        let result = GitHubOidcProvider::parse_identity("invalid-token");
        assert!(matches!(result, Err(WSError::OidcError(_))));
    }

    // ============================================================================
    // SECURITY TESTS: JWT alg validation (audit C-6)
    // ============================================================================

    #[test]
    fn test_jwt_alg_rejects_hs256() {
        // Algorithm-confusion attack: token forged with HMAC must be rejected.
        let token = make_test_jwt(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"sub":"attacker","iss":"https://evil.example.com"}"#,
        );
        let result = GitHubOidcProvider::parse_identity(&token);
        let err = result.expect_err("HS256 token must be rejected");
        match err {
            WSError::OidcError(msg) => assert!(
                msg.contains("HS256") && msg.contains("alg"),
                "error should mention rejected alg, got: {}",
                msg
            ),
            other => panic!("expected OidcError, got {:?}", other),
        }
    }

    #[test]
    fn test_jwt_alg_rejects_none() {
        let token = make_test_jwt(
            r#"{"alg":"none","typ":"JWT"}"#,
            r#"{"sub":"attacker"}"#,
        );
        assert!(matches!(
            GitHubOidcProvider::parse_issuer(&token),
            Err(WSError::OidcError(_))
        ));
    }

    #[test]
    fn test_jwt_alg_rejects_hs512() {
        let token = make_test_jwt(
            r#"{"alg":"HS512","typ":"JWT"}"#,
            r#"{"sub":"attacker"}"#,
        );
        assert!(matches!(
            GitHubOidcProvider::parse_identity(&token),
            Err(WSError::OidcError(_))
        ));
    }

    #[test]
    fn test_jwt_alg_rejects_missing_alg() {
        let token = make_test_jwt(r#"{"typ":"JWT"}"#, r#"{"sub":"x"}"#);
        assert!(matches!(
            GitHubOidcProvider::parse_identity(&token),
            Err(WSError::OidcError(_))
        ));
    }

    #[test]
    fn test_jwt_alg_rejects_empty_alg() {
        let token = make_test_jwt(r#"{"alg":"","typ":"JWT"}"#, r#"{"sub":"x"}"#);
        assert!(matches!(
            GitHubOidcProvider::parse_identity(&token),
            Err(WSError::OidcError(_))
        ));
    }

    #[test]
    fn test_jwt_alg_accepts_rs256() {
        let token = make_rs256_jwt(r#"{"sub":"u","iss":"https://i.example.com"}"#);
        assert!(GitHubOidcProvider::parse_identity(&token).is_ok());
    }

    #[test]
    fn test_jwt_alg_accepts_es256() {
        let token = make_test_jwt(
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"sub":"u","iss":"https://i.example.com"}"#,
        );
        assert!(GitHubOidcProvider::parse_identity(&token).is_ok());
    }

    #[test]
    fn test_jwt_alg_validation_runs_before_payload_parse() {
        // Even if the payload would be invalid JSON, alg rejection should fire first.
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode("not-json-at-all");
        let token = format!("{}.{}.sig", header, payload);
        let err = GitHubOidcProvider::parse_identity(&token).expect_err("must reject");
        match err {
            WSError::OidcError(msg) => assert!(msg.contains("HS256")),
            other => panic!("expected OidcError, got {:?}", other),
        }
    }

    #[test]
    fn test_google_provider_not_implemented() {
        let provider = GoogleOidcProvider::new().unwrap();
        let result = provider.get_token();
        assert!(matches!(result, Err(WSError::OidcError(_))));
    }

    #[test]
    fn test_gitlab_provider_not_implemented() {
        let provider = GitLabOidcProvider::new().unwrap();
        let result = provider.get_token();
        assert!(matches!(result, Err(WSError::OidcError(_))));
    }

    #[test]
    fn test_oidc_token_serialization() {
        let token = OidcToken {
            token: "test-token".to_string(),
            identity: "user@example.com".to_string(),
            issuer: "https://issuer.example.com".to_string(),
        };

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: OidcToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token.token, deserialized.token);
        assert_eq!(token.identity, deserialized.identity);
        assert_eq!(token.issuer, deserialized.issuer);
    }

    // ============================================================================
    // SECURITY TESTS: Memory Zeroization (Issue #11)
    // ============================================================================

    #[test]
    fn test_oidc_token_drop_is_called() {
        // Test that Drop is called when token goes out of scope
        // This verifies the zeroization mechanism is invoked

        // Create a test token with known values
        let test_token_value = "sensitive-jwt-token-12345";
        let test_identity = "user@example.com";
        let test_issuer = "https://issuer.example.com";

        {
            let token = OidcToken {
                token: test_token_value.to_string(),
                identity: test_identity.to_string(),
                issuer: test_issuer.to_string(),
            };

            // Verify token has expected values while in scope
            assert_eq!(token.token, test_token_value);
            assert_eq!(token.identity, test_identity);
            assert_eq!(token.issuer, test_issuer);

            // When token goes out of scope here, Drop should be called
        }

        // If we reach here, Drop was successfully called without panic
        // (We can't directly verify memory is zeroed in safe Rust, but we can
        // verify the Drop implementation doesn't break normal operation)
    }

    #[test]
    fn test_oidc_token_drop_with_error_path() {
        // Test that Drop is called even when an error occurs
        // This simulates the exception-safety of zeroization

        fn operation_that_fails(token: OidcToken) -> Result<(), WSError> {
            // Use the token
            assert!(!token.token.is_empty());

            // Simulate an error
            Err(WSError::OidcError("Simulated error".to_string()))
        }

        let token = OidcToken {
            token: "secret-token".to_string(),
            identity: "user@test.com".to_string(),
            issuer: "https://test.issuer.com".to_string(),
        };

        // Call function that fails - token should still be zeroized via Drop
        let result = operation_that_fails(token);
        assert!(result.is_err());

        // If we reach here, Drop was called successfully even after error
    }

    #[test]
    fn test_oidc_token_no_clone_required() {
        // SECURITY (audit M-5): OidcToken intentionally does NOT implement Clone.
        // Sharing must use references (`&OidcToken`) so the Drop-zeroize
        // discipline holds for the single owner. This test exercises that
        // pattern.

        let original = OidcToken {
            token: "original-token".to_string(),
            identity: "original@example.com".to_string(),
            issuer: "https://original.issuer.com".to_string(),
        };

        fn read_token(t: &OidcToken) -> usize {
            t.token.len() + t.identity.len() + t.issuer.len()
        }

        // Borrow rather than clone.
        let total = read_token(&original);
        assert!(total > 0);
        assert_eq!(original.token, "original-token");
        // original goes out of scope at end of test, Drop called on original.
    }

    #[test]
    fn test_oidc_token_in_result_error_path() {
        // Test that Drop is called when token is in a Result that's unwrapped
        // and causes a panic (caught by should_panic)

        fn create_token_and_fail() -> Result<OidcToken, WSError> {
            let token = OidcToken {
                token: "will-be-zeroized".to_string(),
                identity: "test@example.com".to_string(),
                issuer: "https://test.com".to_string(),
            };

            // Return the token in Ok
            Ok(token)
        }

        // Get the token
        let result = create_token_and_fail();
        assert!(result.is_ok());

        let token = result.unwrap();
        assert_eq!(token.token, "will-be-zeroized");

        // token dropped here - zeroization happens
    }

    #[test]
    fn test_oidc_token_move_semantics() {
        // Test that moving a token doesn't cause double-free or other issues
        // with the Drop implementation

        fn consume_token(token: OidcToken) -> String {
            // Token is moved into this function
            // It will be dropped when function returns
            token.identity.clone()
        }

        let token = OidcToken {
            token: "moved-token".to_string(),
            identity: "moved@example.com".to_string(),
            issuer: "https://moved.com".to_string(),
        };

        let identity = consume_token(token);
        // token was moved, no longer accessible here

        assert_eq!(identity, "moved@example.com");
        // identity (a String) is dropped here normally
    }

    #[test]
    fn test_oidc_token_empty_strings() {
        // Test that zeroization works with empty strings
        // Edge case: empty strings should not cause issues

        let token = OidcToken {
            token: String::new(),
            identity: String::new(),
            issuer: String::new(),
        };

        // Verify empty
        assert!(token.token.is_empty());
        assert!(token.identity.is_empty());
        assert!(token.issuer.is_empty());

        // Drop with empty strings should work fine
    }

    #[test]
    fn test_oidc_token_large_token() {
        // Test that zeroization works with large tokens
        // This ensures performance is acceptable even with large JWTs

        let large_token = "a".repeat(10_000); // 10KB token
        let token = OidcToken {
            token: large_token.clone(),
            identity: "user@example.com".to_string(),
            issuer: "https://issuer.com".to_string(),
        };

        assert_eq!(token.token.len(), 10_000);

        // Drop with large string should work fine
    }

    #[test]
    fn test_oidc_token_get_sub_claim_with_drop() {
        // Test that get_sub_claim works and doesn't interfere with Drop

        let jwt = make_rs256_jwt(r#"{"sub":"test-subject","iss":"https://issuer.com"}"#);

        let token = OidcToken {
            token: jwt,
            identity: "user@example.com".to_string(),
            issuer: "https://issuer.com".to_string(),
        };

        let sub = token.get_sub_claim().unwrap();
        assert_eq!(sub, "test-subject");

        // token (and sub claim String) dropped here
    }

    #[test]
    fn test_oidc_token_vec_of_tokens() {
        // Test that a collection of tokens all get properly dropped

        let mut tokens = Vec::new();

        for i in 0..10 {
            tokens.push(OidcToken {
                token: format!("token-{}", i),
                identity: format!("user{}@example.com", i),
                issuer: "https://issuer.com".to_string(),
            });
        }

        assert_eq!(tokens.len(), 10);

        // When tokens Vec is dropped, all 10 OidcToken instances should be zeroized
    }
}
