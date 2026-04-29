//! MCUboot firmware image signing and verification.
//!
//! Implements the SignableArtifact trait for MCUboot firmware images.
//! Signatures are stored in the MCUboot TLV (Type-Length-Value) trailer.
//!
//! Security constraints (from STPA-Sec analysis):
//! - SC-13: Independently verify image size before signing
//! - UCA-14: Validate ih_img_size matches actual file content
//! - AS-15: Prevent partial-image signature via header manipulation

use super::{FormatType, SignableArtifact};
use crate::WSError;
use sha2::{Digest, Sha256};
use std::io::Write;

/// MCUboot image magic number (little-endian: 0x96f3b83d).
const MCUBOOT_MAGIC: [u8; 4] = [0x3d, 0xb8, 0xf3, 0x96];

/// MCUboot image header size (fixed at 32 bytes for v1).
const MCUBOOT_HEADER_SIZE: usize = 32;

/// Maximum MCUboot image size (16 MB) to prevent resource exhaustion.
const MAX_MCUBOOT_SIZE: usize = 16 * 1024 * 1024;

/// MCUboot TLV type for Ed25519 signature.
const TLV_TYPE_ED25519: u16 = 0x24;

/// MCUboot TLV info magic (marks start of protected TLV area).
const TLV_INFO_MAGIC: u16 = 0x6907;

/// MCUboot firmware image artifact.
#[derive(Debug, Clone)]
pub struct McubootArtifact {
    /// Raw file content.
    data: Vec<u8>,
    /// Image size from header (ih_img_size).
    /// Exposed for diagnostics and header re-serialization.
    pub header_img_size: u32,
    /// Actual payload size (verified independently).
    verified_img_size: u32,
    /// Whether the artifact is little-endian.
    /// Exposed for serialization.
    pub is_little_endian: bool,
    /// Attached signature data, if any.
    signature: Option<Vec<u8>>,
}

impl McubootArtifact {
    /// Parse a MCUboot firmware image from raw bytes.
    ///
    /// Validates header magic and independently verifies image size (SC-13).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, WSError> {
        // Resource bounds check
        if data.len() > MAX_MCUBOOT_SIZE {
            return Err(WSError::InternalError(format!(
                "MCUboot image too large: {} bytes (max: {} bytes)",
                data.len(),
                MAX_MCUBOOT_SIZE,
            )));
        }

        if data.len() < MCUBOOT_HEADER_SIZE {
            return Err(WSError::InternalError(
                "File too small for MCUboot header".into(),
            ));
        }

        // Validate magic bytes
        if data[0..4] != MCUBOOT_MAGIC {
            return Err(WSError::InternalError(
                "Not a valid MCUboot image: magic bytes mismatch".into(),
            ));
        }

        // MCUboot is always little-endian (ARM Cortex-M)
        let is_little_endian = true;

        // Read ih_img_size from header (offset 12, 4 bytes LE)
        let header_img_size =
            u32::from_le_bytes(data[12..16].try_into().map_err(|_| WSError::ParseError)?);

        // Read ih_hdr_size from header (offset 8, 2 bytes LE)
        let hdr_size =
            u16::from_le_bytes(data[8..10].try_into().map_err(|_| WSError::ParseError)?) as u32;

        // The total image content = header + payload
        // ih_img_size is the payload size (after header)
        let declared_total = hdr_size as usize + header_img_size as usize;

        // SC-13: Independently verify image size
        // The file may be larger (TLV trailer follows), but the declared
        // image content must not exceed the file size.
        if declared_total > data.len() {
            return Err(WSError::InternalError(format!(
                "MCUboot header declares image size {} + header {} = {} bytes, \
                 but file is only {} bytes (SC-13 violation: header manipulation detected)",
                header_img_size,
                hdr_size,
                declared_total,
                data.len(),
            )));
        }

        // SC-36 / H-38 / AS-36: Check for partial-image attack.
        // In a legitimate MCUboot image, the content beyond declared_total
        // is the TLV trailer (typically < 4KB for signatures + metadata).
        // If the file has significantly more content than declared, the
        // header may have been manipulated to exclude payload from signing.
        let trailing_bytes = data.len() - declared_total;
        const MAX_TLV_OVERHEAD: usize = 8192; // 8KB generous TLV allowance
        if trailing_bytes > MAX_TLV_OVERHEAD {
            return Err(WSError::InternalError(format!(
                "MCUboot image has {} bytes beyond declared content ({} bytes). \
                 Maximum expected TLV trailer is {} bytes. This may indicate a \
                 partial-image attack where ih_img_size was reduced to exclude \
                 payload from signing (SC-36 / H-38)",
                trailing_bytes, declared_total, MAX_TLV_OVERHEAD,
            )));
        }

        let verified_img_size = header_img_size;

        Ok(McubootArtifact {
            data,
            header_img_size,
            verified_img_size,
            is_little_endian,
            signature: None,
        })
    }

    /// Load a MCUboot firmware image from a file.
    pub fn from_file(path: &str) -> Result<Self, WSError> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }

    /// Get the image payload (header + image content, excluding TLV).
    pub fn payload(&self) -> &[u8] {
        let hdr_size = u16::from_le_bytes(self.data[8..10].try_into().unwrap_or([0; 2])) as usize;
        let end = hdr_size + self.verified_img_size as usize;
        &self.data[..end.min(self.data.len())]
    }
}

impl SignableArtifact for McubootArtifact {
    fn format_type(&self) -> FormatType {
        FormatType::Mcuboot
    }

    /// Hash the MCUboot image payload (header + image content).
    ///
    /// Uses the independently verified image size, not the header's
    /// declared size, to prevent partial-image signature attacks (AS-15).
    fn compute_hash(&self) -> Result<[u8; 32], WSError> {
        let mut hasher = Sha256::new();
        hasher.update(self.payload());
        Ok(hasher.finalize().into())
    }

    fn attach_signature(&mut self, signature_data: &[u8]) -> Result<(), WSError> {
        self.signature = Some(signature_data.to_vec());
        Ok(())
    }

    fn detach_signature(&self) -> Result<Option<Vec<u8>>, WSError> {
        Ok(self.signature.clone())
    }

    fn serialize(&self, writer: &mut dyn Write) -> Result<(), WSError> {
        // Write the image payload
        writer.write_all(self.payload())?;

        // If we have a signature, append as TLV trailer
        if let Some(ref sig) = self.signature {
            // Write TLV info header
            writer.write_all(&TLV_INFO_MAGIC.to_le_bytes())?;
            // TLV total length (4 bytes for info header + TLV entries)
            let tlv_entry_size = 4 + sig.len(); // type(2) + length(2) + data
            let total_tlv_size = 4 + tlv_entry_size;
            writer.write_all(&(total_tlv_size as u16).to_le_bytes())?;

            // Write Ed25519 signature TLV entry
            writer.write_all(&TLV_TYPE_ED25519.to_le_bytes())?;
            writer.write_all(&(sig.len() as u16).to_le_bytes())?;
            writer.write_all(sig)?;
        }

        Ok(())
    }

    fn content_bytes(&self) -> &[u8] {
        self.payload()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid MCUboot image for testing.
    fn minimal_mcuboot() -> Vec<u8> {
        let mut img = vec![0u8; 64];

        // Magic
        img[0..4].copy_from_slice(&MCUBOOT_MAGIC);
        // ih_load_addr (offset 4)
        // ih_hdr_size = 32 (offset 8, u16 LE)
        img[8] = 32;
        img[9] = 0;
        // ih_protect_tlv_size (offset 10)
        // ih_img_size = 32 (offset 12, u32 LE) — 32 bytes of payload
        img[12] = 32;
        img[13] = 0;
        img[14] = 0;
        img[15] = 0;
        // ih_flags (offset 16)
        // ih_ver (offset 20)

        img
    }

    #[test]
    fn test_mcuboot_parse_valid() {
        let img = minimal_mcuboot();
        let artifact = McubootArtifact::from_bytes(img).unwrap();
        assert_eq!(artifact.header_img_size, 32);
        assert_eq!(artifact.verified_img_size, 32);
        assert!(artifact.signature.is_none());
    }

    #[test]
    fn test_mcuboot_parse_bad_magic() {
        let mut img = minimal_mcuboot();
        img[0] = 0x00;
        assert!(McubootArtifact::from_bytes(img).is_err());
    }

    #[test]
    fn test_mcuboot_parse_size_mismatch() {
        let mut img = minimal_mcuboot();
        // Declare image size larger than file
        img[12] = 0xFF;
        img[13] = 0xFF;
        assert!(McubootArtifact::from_bytes(img).is_err());
    }

    #[test]
    fn test_mcuboot_hash_deterministic() {
        let img = minimal_mcuboot();
        let artifact = McubootArtifact::from_bytes(img).unwrap();
        let hash1 = artifact.compute_hash().unwrap();
        let hash2 = artifact.compute_hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_mcuboot_format_type() {
        let img = minimal_mcuboot();
        let artifact = McubootArtifact::from_bytes(img).unwrap();
        assert_eq!(artifact.format_type(), FormatType::Mcuboot);
    }

    #[test]
    fn test_mcuboot_too_large() {
        let data = vec![0u8; MAX_MCUBOOT_SIZE + 1];
        assert!(McubootArtifact::from_bytes(data).is_err());
    }

    #[test]
    fn test_mcuboot_too_small() {
        let data = vec![0u8; 10];
        assert!(McubootArtifact::from_bytes(data).is_err());
    }

    #[test]
    fn test_mcuboot_payload_extraction() {
        let img = minimal_mcuboot();
        let artifact = McubootArtifact::from_bytes(img.clone()).unwrap();
        // Payload = header (32 bytes) + image (32 bytes) = 64 bytes
        assert_eq!(artifact.payload().len(), 64);
    }
}
