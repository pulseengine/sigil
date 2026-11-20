//! Signature format versions (#303, REQ-32).
//!
//! Both versions sign the same message shape:
//!
//! ```text
//! msg = "wasmsig" ‖ version ‖ content_type ‖ hash_function ‖ h_1 ‖ … ‖ h_n
//! ```
//!
//! They differ only in what each content hash `h_i` covers:
//!
//! * **v1 (0x01)**: `h_i = SHA-256(section bytes up to delimiter i)`. The
//!   8-byte module preamble is not hashed, so a signed component's preamble
//!   can be rewritten to a core-module preamble and still verify (#303).
//! * **v2 (0x02)**: `h_i = SHA-256(preamble[0..8] ‖ section bytes up to
//!   delimiter i)`. The preamble (magic + version/layer) is absorbed FIRST,
//!   at a fixed position, before any section byte.
//!
//! Domain separation between v1 and v2 comes from the version byte inside
//! `msg`: a verifier rebuilds `msg` with the version the signature header
//! declares, so a v1 signature relabelled as v2 (or the reverse) is checked
//! against a different message and fails the Ed25519 check.
//!
//! v1 stays the signer's default; v2 is opt-in. The verifier accepts both.
//! Whether v1 is ever rejected is an open owner decision, so nothing here
//! rejects v1.

use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::signature::Hash;
use crate::wasm_module::Header;
use crate::{
    SIGNATURE_HASH_FUNCTION, SIGNATURE_VERSION_V1, SIGNATURE_VERSION_V2, SIGNATURE_WASM_DOMAIN,
    SIGNATURE_WASM_MODULE_CONTENT_TYPE,
};

/// A supported signature format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SignatureVersion {
    /// v1: the module preamble is not covered by the signature. Default.
    #[default]
    V1,
    /// v2: the 8-byte module preamble is covered by the signature.
    V2,
}

impl SignatureVersion {
    /// The on-wire version byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            SignatureVersion::V1 => SIGNATURE_VERSION_V1,
            SignatureVersion::V2 => SIGNATURE_VERSION_V2,
        }
    }

    /// Parse an on-wire version byte. Any version other than 1 or 2 is a
    /// parse error.
    pub fn from_u8(version: u8) -> Result<Self, CoreError> {
        match version {
            SIGNATURE_VERSION_V1 => Ok(SignatureVersion::V1),
            SIGNATURE_VERSION_V2 => Ok(SignatureVersion::V2),
            _ => Err(CoreError::ParseError),
        }
    }

    /// Whether this version's content hash covers the module preamble.
    pub const fn binds_preamble(self) -> bool {
        matches!(self, SignatureVersion::V2)
    }

    /// A content hasher for this version, ready to absorb section bytes.
    ///
    /// For v2 the 8-byte `preamble` has already been absorbed, so it sits at
    /// a fixed position (the first 8 bytes) of every hashed stream,
    /// including each cumulative prefix hash at a signature delimiter. For
    /// v1 the hasher is empty, as before.
    pub fn content_hasher(self, preamble: &Header) -> Hash {
        let mut hasher = Hash::new();
        if self.binds_preamble() {
            hasher.update(preamble);
        }
        hasher
    }

    /// The exact message an Ed25519 signature over `hashes` covers.
    pub fn signed_message(self, hashes: &[Vec<u8>]) -> Zeroizing<Vec<u8>> {
        // SECURITY: Zeroize message buffer on drop.
        let mut msg: Zeroizing<Vec<u8>> = Zeroizing::new(vec![]);
        msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
        msg.extend_from_slice(&[
            self.as_u8(),
            SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            SIGNATURE_HASH_FUNCTION,
        ]);
        for hash in hashes {
            msg.extend_from_slice(hash);
        }
        msg
    }
}

impl TryFrom<u8> for SignatureVersion {
    type Error = CoreError;

    fn try_from(version: u8) -> Result<Self, CoreError> {
        SignatureVersion::from_u8(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-32
    #[test]
    fn version_bytes_roundtrip_and_unknown_versions_are_rejected() {
        assert_eq!(SignatureVersion::default(), SignatureVersion::V1);
        for v in [SignatureVersion::V1, SignatureVersion::V2] {
            assert_eq!(SignatureVersion::from_u8(v.as_u8()).unwrap(), v);
        }
        for bad in [0u8, 3, 0x7f, 0xff] {
            assert!(matches!(
                SignatureVersion::from_u8(bad),
                Err(CoreError::ParseError)
            ));
        }
    }

    // rivet: verifies REQ-32
    #[test]
    fn v1_and_v2_messages_differ_only_in_the_version_byte() {
        let hashes = vec![vec![0xab; 32]];
        let m1 = SignatureVersion::V1.signed_message(&hashes);
        let m2 = SignatureVersion::V2.signed_message(&hashes);
        assert_eq!(m1.len(), m2.len());
        let diff: Vec<usize> = (0..m1.len()).filter(|&i| m1[i] != m2[i]).collect();
        assert_eq!(diff, vec![SIGNATURE_WASM_DOMAIN.len()]);
    }

    // rivet: verifies REQ-32
    #[test]
    fn v2_hasher_absorbs_the_preamble_and_v1_does_not() {
        let preamble: Header = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        let mut expected_v2 = Hash::new();
        expected_v2.update(preamble);
        assert_eq!(
            SignatureVersion::V2.content_hasher(&preamble).finalize(),
            expected_v2.finalize()
        );
        assert_eq!(
            SignatureVersion::V1.content_hasher(&preamble).finalize(),
            Hash::new().finalize()
        );
    }
}
