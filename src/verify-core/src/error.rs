//! Core error type for verification operations.
//!
//! `CoreError` is the error type returned by every function in this crate.
//! It is deliberately narrow — it carries only the variants the verification
//! core actually emits. `wsc::WSError` is a superset that wraps `CoreError`
//! via `From<CoreError> for WSError`, so calling code in the outer crate
//! propagates these errors with the usual `?` operator.
//!
//! Keeping this type here (not the full `WSError`) is what lets the core
//! avoid an `x509-parser` dependency: the `From<X509Error> for WSError`
//! impl in the outer crate would otherwise force x509-parser into core via
//! the orphan rule.

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("Internal error: [{0}]")]
    InternalError(String),

    #[error("Parse error")]
    ParseError,

    #[error("I/O error")]
    IOError(#[from] std::io::Error),

    #[error("EOF")]
    Eof,

    #[error("UTF-8 error")]
    UTF8Error(#[from] std::str::Utf8Error),

    #[error("Ed25519 signature function error")]
    CryptoError(#[from] ed25519_compact::Error),

    #[error("Unsupported module type")]
    UnsupportedModuleType,

    #[error("No valid signatures")]
    VerificationFailed,

    #[error("No valid signatures for the given predicates")]
    VerificationFailedForPredicates,

    #[error("No signatures found")]
    NoSignatures,

    #[error("Unsupported key type")]
    UnsupportedKeyType,

    #[error("Incompatible signature version")]
    IncompatibleSignatureVersion,

    #[error("Duplicate signature")]
    DuplicateSignature,

    #[error("Signature already attached")]
    SignatureAlreadyAttached,

    #[error("Duplicate public key")]
    DuplicatePublicKey,

    #[error("Unknown public key")]
    UnknownPublicKey,

    #[error("Too many hashes (max: {0})")]
    TooManyHashes(usize),

    #[error("Too many signatures (max: {0})")]
    TooManySignatures(usize),

    #[error("Too many certificates (max: {0})")]
    TooManyCertificates(usize),

    #[error("Too many sections (max: {0})")]
    TooManySections(usize),
}
