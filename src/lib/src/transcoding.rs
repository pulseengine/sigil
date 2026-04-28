//! Transcoding attestation protocol for WASM-to-native compilation
//!
//! Defines the attestation format for when synth compiles WASM modules to
//! native code (ARM ELF, MCUboot). Uses in-toto Statement with a custom
//! `TranscodingPredicate` to record the full provenance chain from
//! signed WASM source through compilation to native output.
//!
//! # Example
//!
//! ```ignore
//! use wsc::transcoding::{TranscodingAttestationBuilder, create_transcoding_statement};
//! use wsc::intoto::DigestSet;
//!
//! let predicate = TranscodingAttestationBuilder::new()
//!     .source_digest(DigestSet::sha256("abc123"))
//!     .source_signature_status("verified")
//!     .compiler("synth", "0.1.0")
//!     .target("aarch64", "elf")
//!     .optimization_level("O2")
//!     .build()
//!     .unwrap();
//!
//! let statement = create_transcoding_statement(
//!     "firmware.elf",
//!     DigestSet::sha256("def456"),
//!     predicate,
//! );
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::intoto::{DigestSet, Statement, Subject};

/// Predicate type URI for WSC transcoding attestations (v1)
pub const TRANSCODING_PREDICATE_V1: &str = "https://wsc.dev/transcoding/v1";

/// Build type URI for WASM-to-native transcoding
pub const WASM_NATIVE_BUILD_TYPE: &str = "https://wsc.dev/WasmNativeTranscode/v1";

/// Predicate describing a WASM-to-native transcoding operation
///
/// Records the source WASM module, compiler details, target platform,
/// compilation parameters, and whether the source was verified before
/// compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodingPredicate {
    /// Information about the source WASM module
    pub source: TranscodingSource,

    /// Information about the compiler used
    pub compiler: CompilerInfo,

    /// Information about the compilation target
    pub target: TargetInfo,

    /// Compilation parameters and flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compilation_parameters: Option<CompilationParameters>,

    /// Verification status of the source module
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<SourceVerification>,
}

/// Information about the source WASM module being transcoded
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodingSource {
    /// Cryptographic digest(s) of the source WASM module
    pub digest: DigestSet,

    /// Status of the source module's signature (e.g., "verified", "unsigned")
    pub signature_status: String,

    /// Identity of the signer (e.g., OIDC email or key fingerprint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,

    /// SLSA level of the source module's provenance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slsa_level: Option<String>,

    /// URI of the source module
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Base64-encoded attestation bundle from the source module
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_bundle: Option<String>,
}

/// Information about the compiler used for transcoding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompilerInfo {
    /// Name of the compiler (e.g., "synth")
    pub name: String,

    /// Version of the compiler
    pub version: String,

    /// Cryptographic digest of the compiler binary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<DigestSet>,

    /// URI where the compiler can be obtained
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// Information about the compilation target
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    /// Target architecture (e.g., "aarch64", "thumbv7em")
    pub architecture: String,

    /// Output format (e.g., "elf", "mcuboot")
    pub output_format: String,

    /// Build profile (e.g., "release", "debug")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// Compilation parameters used during transcoding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompilationParameters {
    /// Optimization level (e.g., "O0", "O2", "Os")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimization_level: Option<String>,

    /// Whether the compilation was deterministic/reproducible
    pub verified: bool,

    /// Memory model used (e.g., "static", "heap", "mpu-protected")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_model: Option<String>,

    /// Additional compiler flags
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub flags: HashMap<String, String>,
}

/// Verification status of the source WASM module before transcoding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceVerification {
    /// Whether the source module's signature was verified
    pub signature_verified: bool,

    /// Whether the full certificate chain was verified
    pub chain_verified: bool,

    /// Policy used for verification (e.g., "strict", "permissive")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,

    /// RFC 3339 timestamp of when verification was performed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
}

/// Builder for constructing `TranscodingPredicate` with a fluent API
///
/// # Example
///
/// ```ignore
/// use wsc::transcoding::TranscodingAttestationBuilder;
/// use wsc::intoto::DigestSet;
///
/// let predicate = TranscodingAttestationBuilder::new()
///     .source_digest(DigestSet::sha256("abc123"))
///     .source_signature_status("verified")
///     .compiler("synth", "0.1.0")
///     .target("aarch64", "elf")
///     .build()
///     .unwrap();
/// ```
pub struct TranscodingAttestationBuilder {
    source_digest: Option<DigestSet>,
    source_signature_status: Option<String>,
    source_signer_identity: Option<String>,
    source_slsa_level: Option<String>,
    source_uri: Option<String>,
    source_attestation_bundle: Option<String>,
    compiler_name: Option<String>,
    compiler_version: Option<String>,
    compiler_digest: Option<DigestSet>,
    compiler_uri: Option<String>,
    target_architecture: Option<String>,
    target_output_format: Option<String>,
    target_profile: Option<String>,
    optimization_level: Option<String>,
    verified: bool,
    memory_model: Option<String>,
    flags: HashMap<String, String>,
    signature_verified: Option<bool>,
    chain_verified: Option<bool>,
    verification_policy: Option<String>,
    verified_at: Option<String>,
}

impl TranscodingAttestationBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            source_digest: None,
            source_signature_status: None,
            source_signer_identity: None,
            source_slsa_level: None,
            source_uri: None,
            source_attestation_bundle: None,
            compiler_name: None,
            compiler_version: None,
            compiler_digest: None,
            compiler_uri: None,
            target_architecture: None,
            target_output_format: None,
            target_profile: None,
            optimization_level: None,
            verified: false,
            memory_model: None,
            flags: HashMap::new(),
            signature_verified: None,
            chain_verified: None,
            verification_policy: None,
            verified_at: None,
        }
    }

    /// Set the source WASM module digest
    pub fn source_digest(mut self, digest: DigestSet) -> Self {
        self.source_digest = Some(digest);
        self
    }

    /// Set the source module's signature status
    pub fn source_signature_status(mut self, status: impl Into<String>) -> Self {
        self.source_signature_status = Some(status.into());
        self
    }

    /// Set the source module's signer identity
    pub fn source_signer_identity(mut self, identity: impl Into<String>) -> Self {
        self.source_signer_identity = Some(identity.into());
        self
    }

    /// Set the source module's SLSA level
    pub fn source_slsa_level(mut self, level: impl Into<String>) -> Self {
        self.source_slsa_level = Some(level.into());
        self
    }

    /// Set the source module's URI
    pub fn source_uri(mut self, uri: impl Into<String>) -> Self {
        self.source_uri = Some(uri.into());
        self
    }

    /// Set the source module's attestation bundle
    pub fn source_attestation_bundle(mut self, bundle: impl Into<String>) -> Self {
        self.source_attestation_bundle = Some(bundle.into());
        self
    }

    /// Set the compiler name and version
    pub fn compiler(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.compiler_name = Some(name.into());
        self.compiler_version = Some(version.into());
        self
    }

    /// Set the compiler digest
    pub fn compiler_digest(mut self, digest: DigestSet) -> Self {
        self.compiler_digest = Some(digest);
        self
    }

    /// Set the compiler URI
    pub fn compiler_uri(mut self, uri: impl Into<String>) -> Self {
        self.compiler_uri = Some(uri.into());
        self
    }

    /// Set the target architecture and output format
    pub fn target(
        mut self,
        architecture: impl Into<String>,
        output_format: impl Into<String>,
    ) -> Self {
        self.target_architecture = Some(architecture.into());
        self.target_output_format = Some(output_format.into());
        self
    }

    /// Set the target build profile
    pub fn target_profile(mut self, profile: impl Into<String>) -> Self {
        self.target_profile = Some(profile.into());
        self
    }

    /// Set the optimization level
    pub fn optimization_level(mut self, level: impl Into<String>) -> Self {
        self.optimization_level = Some(level.into());
        self
    }

    /// Set whether the compilation is verified/reproducible
    pub fn verified(mut self, verified: bool) -> Self {
        self.verified = verified;
        self
    }

    /// Set the memory model
    pub fn memory_model(mut self, model: impl Into<String>) -> Self {
        self.memory_model = Some(model.into());
        self
    }

    /// Add a compilation flag
    pub fn flag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.flags.insert(key.into(), value.into());
        self
    }

    /// Set source verification results
    pub fn source_verification(mut self, signature_verified: bool, chain_verified: bool) -> Self {
        self.signature_verified = Some(signature_verified);
        self.chain_verified = Some(chain_verified);
        self
    }

    /// Set the verification policy name
    pub fn verification_policy(mut self, policy: impl Into<String>) -> Self {
        self.verification_policy = Some(policy.into());
        self
    }

    /// Set the verification timestamp (RFC 3339)
    pub fn verified_at(mut self, timestamp: impl Into<String>) -> Self {
        self.verified_at = Some(timestamp.into());
        self
    }

    /// Build the `TranscodingPredicate`
    ///
    /// # Errors
    ///
    /// Returns `WSError::InvalidArgument` if required fields are not set:
    /// `source_digest`, `source_signature_status`, `compiler` name/version,
    /// `target` architecture/output_format.
    pub fn build(self) -> Result<TranscodingPredicate, crate::WSError> {
        let source = TranscodingSource {
            digest: self.source_digest.ok_or(crate::WSError::InvalidArgument)?,
            signature_status: self
                .source_signature_status
                .ok_or(crate::WSError::InvalidArgument)?,
            signer_identity: self.source_signer_identity,
            slsa_level: self.source_slsa_level,
            uri: self.source_uri,
            attestation_bundle: self.source_attestation_bundle,
        };

        let compiler = CompilerInfo {
            name: self.compiler_name.ok_or(crate::WSError::InvalidArgument)?,
            version: self
                .compiler_version
                .ok_or(crate::WSError::InvalidArgument)?,
            digest: self.compiler_digest,
            uri: self.compiler_uri,
        };

        let target = TargetInfo {
            architecture: self
                .target_architecture
                .ok_or(crate::WSError::InvalidArgument)?,
            output_format: self
                .target_output_format
                .ok_or(crate::WSError::InvalidArgument)?,
            profile: self.target_profile,
        };

        let compilation_parameters = if self.optimization_level.is_some()
            || self.memory_model.is_some()
            || !self.flags.is_empty()
            || self.verified
        {
            Some(CompilationParameters {
                optimization_level: self.optimization_level,
                verified: self.verified,
                memory_model: self.memory_model,
                flags: self.flags,
            })
        } else {
            None
        };

        let verification = if self.signature_verified.is_some() || self.chain_verified.is_some() {
            Some(SourceVerification {
                signature_verified: self.signature_verified.unwrap_or(false),
                chain_verified: self.chain_verified.unwrap_or(false),
                policy: self.verification_policy,
                verified_at: self.verified_at,
            })
        } else {
            None
        };

        Ok(TranscodingPredicate {
            source,
            compiler,
            target,
            compilation_parameters,
            verification,
        })
    }
}

impl Default for TranscodingAttestationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create an in-toto Statement wrapping a transcoding predicate
///
/// Binds the `TranscodingPredicate` to the output artifact (the native binary)
/// as the subject.
///
/// # Arguments
///
/// * `output_name` - Name/path of the output native binary
/// * `output_digest` - Cryptographic digest(s) of the output binary
/// * `predicate` - The transcoding predicate describing the compilation
pub fn create_transcoding_statement(
    output_name: impl Into<String>,
    output_digest: DigestSet,
    predicate: TranscodingPredicate,
) -> Statement<TranscodingPredicate> {
    let subject = Subject::with_digests(output_name, output_digest);
    Statement::new(vec![subject], TRANSCODING_PREDICATE_V1, predicate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_predicate() -> TranscodingPredicate {
        TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("aabbccdd"))
            .source_signature_status("verified")
            .source_signer_identity("user@example.com")
            .source_slsa_level("SLSA_BUILD_LEVEL_2")
            .source_uri("https://registry.example.com/module.wasm")
            .compiler("synth", "0.1.0")
            .compiler_uri("https://github.com/pulseengine/synth")
            .target("aarch64", "elf")
            .target_profile("release")
            .optimization_level("O2")
            .verified(true)
            .memory_model("static")
            .flag("lto", "thin")
            .source_verification(true, true)
            .verification_policy("strict")
            .verified_at("2026-03-17T12:00:00Z")
            .build()
            .unwrap()
    }

    #[test]
    fn test_builder_minimal() {
        let predicate = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc123"))
            .source_signature_status("unsigned")
            .compiler("synth", "0.1.0")
            .target("aarch64", "elf")
            .build()
            .unwrap();

        assert_eq!(predicate.source.signature_status, "unsigned");
        assert_eq!(predicate.compiler.name, "synth");
        assert_eq!(predicate.compiler.version, "0.1.0");
        assert_eq!(predicate.target.architecture, "aarch64");
        assert_eq!(predicate.target.output_format, "elf");
        assert!(predicate.compilation_parameters.is_none());
        assert!(predicate.verification.is_none());
        assert!(predicate.source.signer_identity.is_none());
    }

    #[test]
    fn test_builder_full() {
        let predicate = sample_predicate();

        assert_eq!(predicate.source.digest.sha256_value(), Some("aabbccdd"));
        assert_eq!(predicate.source.signature_status, "verified");
        assert_eq!(
            predicate.source.signer_identity.as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            predicate.source.slsa_level.as_deref(),
            Some("SLSA_BUILD_LEVEL_2")
        );
        assert_eq!(
            predicate.source.uri.as_deref(),
            Some("https://registry.example.com/module.wasm")
        );

        assert_eq!(predicate.compiler.name, "synth");
        assert_eq!(predicate.compiler.version, "0.1.0");
        assert_eq!(
            predicate.compiler.uri.as_deref(),
            Some("https://github.com/pulseengine/synth")
        );

        assert_eq!(predicate.target.architecture, "aarch64");
        assert_eq!(predicate.target.output_format, "elf");
        assert_eq!(predicate.target.profile.as_deref(), Some("release"));

        let params = predicate.compilation_parameters.as_ref().unwrap();
        assert_eq!(params.optimization_level.as_deref(), Some("O2"));
        assert!(params.verified);
        assert_eq!(params.memory_model.as_deref(), Some("static"));
        assert_eq!(params.flags.get("lto"), Some(&"thin".to_string()));

        let verification = predicate.verification.as_ref().unwrap();
        assert!(verification.signature_verified);
        assert!(verification.chain_verified);
        assert_eq!(verification.policy.as_deref(), Some("strict"));
        assert_eq!(
            verification.verified_at.as_deref(),
            Some("2026-03-17T12:00:00Z")
        );
    }

    #[test]
    fn test_builder_missing_source_digest() {
        let result = TranscodingAttestationBuilder::new()
            .source_signature_status("verified")
            .compiler("synth", "0.1.0")
            .target("aarch64", "elf")
            .build();
        assert!(result.is_err(), "build() should fail without source_digest");
    }

    #[test]
    fn test_builder_missing_signature_status() {
        let result = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .compiler("synth", "0.1.0")
            .target("aarch64", "elf")
            .build();
        assert!(
            result.is_err(),
            "build() should fail without signature_status"
        );
    }

    #[test]
    fn test_builder_missing_compiler() {
        let result = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .source_signature_status("verified")
            .target("aarch64", "elf")
            .build();
        assert!(result.is_err(), "build() should fail without compiler");
    }

    #[test]
    fn test_builder_missing_target() {
        let result = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .source_signature_status("verified")
            .compiler("synth", "0.1.0")
            .build();
        assert!(result.is_err(), "build() should fail without target");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let predicate = sample_predicate();

        let json = serde_json::to_string_pretty(&predicate).unwrap();
        let parsed: TranscodingPredicate = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.source.signature_status, "verified");
        assert_eq!(parsed.compiler.name, "synth");
        assert_eq!(parsed.target.architecture, "aarch64");
        assert_eq!(
            parsed
                .compilation_parameters
                .as_ref()
                .unwrap()
                .optimization_level
                .as_deref(),
            Some("O2")
        );
        assert!(parsed.verification.as_ref().unwrap().signature_verified);
    }

    #[test]
    fn test_serialization_camel_case() {
        let predicate = sample_predicate();
        let json = serde_json::to_string(&predicate).unwrap();

        // Verify camelCase field names
        assert!(json.contains("signatureStatus"));
        assert!(json.contains("signerIdentity"));
        assert!(json.contains("slsaLevel"));
        assert!(json.contains("attestationBundle").not());
        // attestationBundle is None here, check on a predicate with it set
        assert!(json.contains("outputFormat"));
        assert!(json.contains("optimizationLevel"));
        assert!(json.contains("memoryModel"));
        assert!(json.contains("signatureVerified"));
        assert!(json.contains("chainVerified"));
        assert!(json.contains("verifiedAt"));
        assert!(json.contains("compilationParameters"));
    }

    #[test]
    fn test_serialization_skip_none() {
        let predicate = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .source_signature_status("unsigned")
            .compiler("synth", "0.1.0")
            .target("aarch64", "elf")
            .build()
            .unwrap();

        let json = serde_json::to_string(&predicate).unwrap();

        // Optional fields that are None should not appear
        assert!(!json.contains("signerIdentity"));
        assert!(!json.contains("slsaLevel"));
        assert!(!json.contains("compilationParameters"));
        assert!(!json.contains("verification"));
        assert!(!json.contains("profile"));
    }

    #[test]
    fn test_create_transcoding_statement() {
        let predicate = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("source_hash"))
            .source_signature_status("verified")
            .compiler("synth", "0.1.0")
            .target("aarch64", "elf")
            .build()
            .unwrap();

        let statement = create_transcoding_statement(
            "firmware.elf",
            DigestSet::sha256("output_hash"),
            predicate,
        );

        assert_eq!(statement.type_, "https://in-toto.io/Statement/v1");
        assert_eq!(statement.predicate_type, TRANSCODING_PREDICATE_V1);
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].name, "firmware.elf");
        assert_eq!(
            statement.subject[0].digest.sha256_value(),
            Some("output_hash")
        );
        assert_eq!(statement.predicate.compiler.name, "synth");
    }

    #[test]
    fn test_statement_serialization_roundtrip() {
        let predicate = sample_predicate();
        let statement =
            create_transcoding_statement("firmware.elf", DigestSet::sha256("deadbeef"), predicate);

        let json = statement.to_json_pretty().unwrap();

        // Verify key fields are present in serialized form
        assert!(json.contains("https://in-toto.io/Statement/v1"));
        assert!(json.contains(TRANSCODING_PREDICATE_V1));
        assert!(json.contains("firmware.elf"));
        assert!(json.contains("deadbeef"));
        assert!(json.contains("synth"));
        assert!(json.contains("aarch64"));

        // Roundtrip
        let parsed: Statement<TranscodingPredicate> = Statement::from_json(&json).unwrap();
        assert_eq!(parsed.subject[0].name, "firmware.elf");
        assert_eq!(parsed.predicate.compiler.name, "synth");
        assert_eq!(parsed.predicate.target.architecture, "aarch64");
        assert_eq!(parsed.predicate.source.signature_status, "verified");
    }

    #[test]
    fn test_statement_json_bytes_roundtrip() {
        let predicate = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .source_signature_status("verified")
            .compiler("synth", "0.2.0")
            .target("thumbv7em", "mcuboot")
            .target_profile("release")
            .optimization_level("Os")
            .memory_model("mpu-protected")
            .build()
            .unwrap();

        let statement =
            create_transcoding_statement("app.mcuboot", DigestSet::sha256("112233"), predicate);

        let bytes = statement.to_json_bytes().unwrap();
        let parsed: Statement<TranscodingPredicate> = Statement::from_json_bytes(&bytes).unwrap();

        assert_eq!(parsed.subject[0].name, "app.mcuboot");
        assert_eq!(parsed.predicate.target.output_format, "mcuboot");
        assert_eq!(parsed.predicate.target.architecture, "thumbv7em");
        assert_eq!(
            parsed
                .predicate
                .compilation_parameters
                .as_ref()
                .unwrap()
                .memory_model
                .as_deref(),
            Some("mpu-protected")
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(TRANSCODING_PREDICATE_V1, "https://wsc.dev/transcoding/v1");
        assert_eq!(
            WASM_NATIVE_BUILD_TYPE,
            "https://wsc.dev/WasmNativeTranscode/v1"
        );
    }

    #[test]
    fn test_compilation_parameters_flags() {
        let predicate = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .source_signature_status("verified")
            .compiler("synth", "0.1.0")
            .target("aarch64", "elf")
            .flag("lto", "fat")
            .flag("codegen-units", "1")
            .flag("strip", "symbols")
            .build()
            .unwrap();

        let params = predicate.compilation_parameters.as_ref().unwrap();
        assert_eq!(params.flags.len(), 3);
        assert_eq!(params.flags.get("lto"), Some(&"fat".to_string()));
        assert_eq!(params.flags.get("codegen-units"), Some(&"1".to_string()));
        assert_eq!(params.flags.get("strip"), Some(&"symbols".to_string()));
    }

    #[test]
    fn test_source_with_attestation_bundle() {
        let predicate = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .source_signature_status("verified")
            .source_attestation_bundle("base64encodeddata==")
            .compiler("synth", "0.1.0")
            .target("aarch64", "elf")
            .build()
            .unwrap();

        assert_eq!(
            predicate.source.attestation_bundle.as_deref(),
            Some("base64encodeddata==")
        );

        let json = serde_json::to_string(&predicate).unwrap();
        assert!(json.contains("attestationBundle"));
        assert!(json.contains("base64encodeddata=="));
    }

    #[test]
    fn test_compiler_with_digest() {
        let compiler_digest = DigestSet::sha256("compiler_sha256_hash");
        let predicate = TranscodingAttestationBuilder::new()
            .source_digest(DigestSet::sha256("abc"))
            .source_signature_status("verified")
            .compiler("synth", "0.1.0")
            .compiler_digest(compiler_digest)
            .target("aarch64", "elf")
            .build()
            .unwrap();

        assert!(predicate.compiler.digest.is_some());
        assert_eq!(
            predicate.compiler.digest.as_ref().unwrap().sha256_value(),
            Some("compiler_sha256_hash")
        );
    }

    // Helper trait for test assertions on &str containment negation
    trait Not {
        fn not(self) -> bool;
    }

    impl Not for bool {
        fn not(self) -> bool {
            !self
        }
    }
}
