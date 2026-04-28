//! ELF binary signing and verification.
//!
//! Implements the SignableArtifact trait for ELF (Executable and Linkable Format)
//! binaries. Signatures are embedded in a `.sigil` note section.
//!
//! Security constraints (from STPA-Sec analysis):
//! - SC-12: Validate section header consistency before signing
//! - UCA-13: Check for section overlaps before embedding signature
//! - UCA-17: Enforce resource bounds on ELF parsing
//! - AS-14: Hash full file content, not section-by-section

use super::{FormatType, SignableArtifact};
use crate::WSError;
use sha2::{Digest, Sha256};
use std::io::Write;

/// Maximum ELF file size (256 MB) to prevent resource exhaustion (UCA-17).
const MAX_ELF_SIZE: usize = 256 * 1024 * 1024;

/// Maximum number of ELF section headers to process (UCA-17).
const MAX_ELF_SECTIONS: usize = 4096;

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

/// Name of the signature section embedded in ELF binaries.
const SIGIL_SECTION_NAME: &str = ".sigil";

/// ELF binary artifact for signing and verification.
#[derive(Debug, Clone)]
pub struct ElfArtifact {
    /// Raw file content (complete ELF binary).
    data: Vec<u8>,
    /// Whether the ELF is 64-bit (true) or 32-bit (false).
    /// Needed for serialization and future `.sigil` section injection.
    pub is_64bit: bool,
    /// Whether the ELF is little-endian (true) or big-endian (false).
    /// Needed for serialization and future `.sigil` section injection.
    pub is_little_endian: bool,
    /// Attached signature data, if any.
    signature: Option<Vec<u8>>,
}

impl ElfArtifact {
    /// Parse an ELF binary from raw bytes.
    ///
    /// Validates the ELF header and enforces resource bounds (UCA-17).
    /// Does NOT parse individual sections — we hash the full file content (AS-14).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, WSError> {
        // Resource bounds check (UCA-17)
        if data.len() > MAX_ELF_SIZE {
            return Err(WSError::InternalError(format!(
                "ELF file too large: {} bytes (max: {} bytes)",
                data.len(),
                MAX_ELF_SIZE,
            )));
        }

        // Minimum ELF header size: 52 bytes (32-bit) or 64 bytes (64-bit)
        if data.len() < 52 {
            return Err(WSError::ParseError);
        }

        // Validate magic bytes
        if data[0..4] != ELF_MAGIC {
            return Err(WSError::InternalError(
                "Not a valid ELF file: magic bytes mismatch".into(),
            ));
        }

        // EI_CLASS: 1 = 32-bit, 2 = 64-bit
        let is_64bit = match data[4] {
            1 => false,
            2 => true,
            _ => {
                return Err(WSError::InternalError(
                    "Invalid ELF class (expected 32-bit or 64-bit)".into(),
                ));
            }
        };

        // EI_DATA: 1 = little-endian, 2 = big-endian
        let is_little_endian = match data[5] {
            1 => true,
            2 => false,
            _ => {
                return Err(WSError::InternalError(
                    "Invalid ELF data encoding (expected LE or BE)".into(),
                ));
            }
        };

        // Validate 64-bit header size
        if is_64bit && data.len() < 64 {
            return Err(WSError::ParseError);
        }

        // Validate section header count (UCA-17)
        let shnum = if is_64bit {
            Self::read_u16(&data, 60, is_little_endian) as usize
        } else {
            Self::read_u16(&data, 48, is_little_endian) as usize
        };
        if shnum > MAX_ELF_SECTIONS {
            return Err(WSError::InternalError(format!(
                "Too many ELF sections: {} (max: {})",
                shnum, MAX_ELF_SECTIONS,
            )));
        }

        // Validate section header consistency (SC-12)
        Self::validate_section_headers(&data, is_64bit, is_little_endian, shnum)?;

        // Check for existing .sigil section
        let signature = Self::find_sigil_section(&data, is_64bit, is_little_endian)?;

        Ok(ElfArtifact {
            data,
            is_64bit,
            is_little_endian,
            signature,
        })
    }

    /// Load an ELF binary from a file.
    pub fn from_file(path: &str) -> Result<Self, WSError> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }

    /// Read a u16 from the byte array at the given offset.
    fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> u16 {
        if little_endian {
            u16::from_le_bytes([data[offset], data[offset + 1]])
        } else {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        }
    }

    /// Read a u32 from the byte array at the given offset.
    fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> u32 {
        let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap_or([0; 4]);
        if little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    }

    /// Read a u64 from the byte array at the given offset.
    fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> u64 {
        let bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap_or([0; 8]);
        if little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    }

    /// Validate section headers for consistency (SC-12).
    ///
    /// Checks that sections don't overlap and stay within file bounds.
    fn validate_section_headers(
        data: &[u8],
        is_64bit: bool,
        le: bool,
        shnum: usize,
    ) -> Result<(), WSError> {
        if shnum == 0 {
            return Ok(()); // No sections to validate
        }

        let (shoff, shentsize) = if is_64bit {
            (
                Self::read_u64(data, 40, le) as usize,
                Self::read_u16(data, 58, le) as usize,
            )
        } else {
            (
                Self::read_u32(data, 32, le) as usize,
                Self::read_u16(data, 46, le) as usize,
            )
        };

        // Validate section header table is within file bounds
        let sh_table_end = shoff
            .checked_add(shnum.checked_mul(shentsize).ok_or(WSError::ParseError)?)
            .ok_or(WSError::ParseError)?;
        if sh_table_end > data.len() {
            return Err(WSError::InternalError(
                "ELF section header table extends beyond file".into(),
            ));
        }

        // Collect section ranges and check for overlaps (SC-12)
        let mut ranges: Vec<(usize, usize, usize)> = Vec::new(); // (offset, size, index)
        for i in 0..shnum {
            let sh_start = shoff + i * shentsize;
            if sh_start + shentsize > data.len() {
                return Err(WSError::ParseError);
            }

            let (sh_offset, sh_size) = if is_64bit {
                (
                    Self::read_u64(data, sh_start + 24, le) as usize,
                    Self::read_u64(data, sh_start + 32, le) as usize,
                )
            } else {
                (
                    Self::read_u32(data, sh_start + 16, le) as usize,
                    Self::read_u32(data, sh_start + 20, le) as usize,
                )
            };

            // SHT_NOBITS (type 8) sections have no file content
            let sh_type = Self::read_u32(data, sh_start + 4, le);
            if sh_type == 8 || sh_size == 0 {
                continue;
            }

            // Check section is within file bounds
            let sh_end = sh_offset.checked_add(sh_size).ok_or(WSError::ParseError)?;
            if sh_end > data.len() {
                return Err(WSError::InternalError(format!(
                    "ELF section {} extends beyond file (offset: {}, size: {})",
                    i, sh_offset, sh_size,
                )));
            }

            ranges.push((sh_offset, sh_size, i));
        }

        // Sort by offset and check for overlaps
        ranges.sort_by_key(|&(offset, _, _)| offset);
        for window in ranges.windows(2) {
            let (off1, size1, idx1) = window[0];
            let (off2, _, idx2) = window[1];
            if off1 + size1 > off2 {
                return Err(WSError::InternalError(format!(
                    "ELF sections {} and {} overlap (SC-12 violation)",
                    idx1, idx2,
                )));
            }
        }

        Ok(())
    }

    /// Find an existing .sigil section in the ELF binary.
    fn find_sigil_section(
        data: &[u8],
        is_64bit: bool,
        le: bool,
    ) -> Result<Option<Vec<u8>>, WSError> {
        let shnum = if is_64bit {
            Self::read_u16(data, 60, le) as usize
        } else {
            Self::read_u16(data, 48, le) as usize
        };

        if shnum == 0 {
            return Ok(None);
        }

        let (shoff, shentsize, shstrndx) = if is_64bit {
            (
                Self::read_u64(data, 40, le) as usize,
                Self::read_u16(data, 58, le) as usize,
                Self::read_u16(data, 62, le) as usize,
            )
        } else {
            (
                Self::read_u32(data, 32, le) as usize,
                Self::read_u16(data, 46, le) as usize,
                Self::read_u16(data, 50, le) as usize,
            )
        };

        // Get string table section
        if shstrndx >= shnum {
            return Ok(None);
        }
        let strtab_sh = shoff + shstrndx * shentsize;
        let (strtab_offset, strtab_size) = if is_64bit {
            (
                Self::read_u64(data, strtab_sh + 24, le) as usize,
                Self::read_u64(data, strtab_sh + 32, le) as usize,
            )
        } else {
            (
                Self::read_u32(data, strtab_sh + 16, le) as usize,
                Self::read_u32(data, strtab_sh + 20, le) as usize,
            )
        };

        if strtab_offset + strtab_size > data.len() {
            return Ok(None);
        }

        // Search for .sigil section by name
        for i in 0..shnum {
            let sh_start = shoff + i * shentsize;
            let name_offset = Self::read_u32(data, sh_start, le) as usize;

            if name_offset >= strtab_size {
                continue;
            }

            // Extract null-terminated string from strtab
            let name_start = strtab_offset + name_offset;
            let name_end = data[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| name_start + p)
                .unwrap_or(name_start);

            if let Ok(name) = std::str::from_utf8(&data[name_start..name_end]) {
                if name == SIGIL_SECTION_NAME {
                    let (offset, size) = if is_64bit {
                        (
                            Self::read_u64(data, sh_start + 24, le) as usize,
                            Self::read_u64(data, sh_start + 32, le) as usize,
                        )
                    } else {
                        (
                            Self::read_u32(data, sh_start + 16, le) as usize,
                            Self::read_u32(data, sh_start + 20, le) as usize,
                        )
                    };
                    if offset + size <= data.len() {
                        return Ok(Some(data[offset..offset + size].to_vec()));
                    }
                }
            }
        }

        Ok(None)
    }
}

impl SignableArtifact for ElfArtifact {
    fn format_type(&self) -> FormatType {
        FormatType::Elf
    }

    /// Hash the entire ELF file content (AS-14 defense).
    ///
    /// Hashes the complete file rather than section-by-section to prevent
    /// attacks where section headers and program headers diverge.
    fn compute_hash(&self) -> Result<[u8; 32], WSError> {
        let mut hasher = Sha256::new();
        // Hash all content except the .sigil section (if present)
        // For simplicity in this initial implementation, hash the entire file.
        // The signature section is appended, so hashing the original content
        // (before signature attachment) is the correct approach.
        hasher.update(&self.data);
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
        // Write the original ELF content
        writer.write_all(&self.data)?;

        // If we have a signature, append it as a detached file
        // Note: Full ELF section embedding requires modifying section headers,
        // which is complex. For the initial implementation, we use a detached
        // signature approach alongside the binary.
        // TODO: Implement proper .sigil section injection for embedded signatures.

        Ok(())
    }

    fn content_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid 64-bit little-endian ELF binary for testing.
    fn minimal_elf64() -> Vec<u8> {
        let mut elf = vec![0u8; 120]; // Minimum size for ELF64 with minimal sections

        // ELF magic
        elf[0..4].copy_from_slice(&ELF_MAGIC);
        // EI_CLASS: 64-bit
        elf[4] = 2;
        // EI_DATA: little-endian
        elf[5] = 1;
        // EI_VERSION
        elf[6] = 1;
        // e_type: ET_EXEC
        elf[16] = 2;
        // e_machine: EM_X86_64
        elf[18] = 0x3e;
        // e_version
        elf[20] = 1;
        // e_ehsize: 64 bytes
        elf[52] = 64;
        // e_shentsize: 64 bytes
        elf[58] = 64;
        // e_shnum: 0 (no sections)
        elf[60] = 0;

        elf
    }

    #[test]
    fn test_elf_parse_valid() {
        let elf = minimal_elf64();
        let artifact = ElfArtifact::from_bytes(elf).unwrap();
        assert!(artifact.is_64bit);
        assert!(artifact.is_little_endian);
        assert!(artifact.signature.is_none());
    }

    #[test]
    fn test_elf_parse_bad_magic() {
        let data = vec![0x00; 64];
        assert!(ElfArtifact::from_bytes(data).is_err());
    }

    #[test]
    fn test_elf_parse_too_small() {
        let data = vec![0x7f, 0x45, 0x4c, 0x46]; // Just magic, too small
        assert!(ElfArtifact::from_bytes(data).is_err());
    }

    #[test]
    fn test_elf_parse_too_large() {
        let mut data = minimal_elf64();
        data.resize(MAX_ELF_SIZE + 1, 0);
        assert!(ElfArtifact::from_bytes(data).is_err());
    }

    #[test]
    fn test_elf_hash_deterministic() {
        let elf = minimal_elf64();
        let artifact = ElfArtifact::from_bytes(elf).unwrap();
        let hash1 = artifact.compute_hash().unwrap();
        let hash2 = artifact.compute_hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_elf_format_type() {
        let elf = minimal_elf64();
        let artifact = ElfArtifact::from_bytes(elf).unwrap();
        assert_eq!(artifact.format_type(), FormatType::Elf);
    }

    #[test]
    fn test_elf_attach_detach_signature() {
        let elf = minimal_elf64();
        let mut artifact = ElfArtifact::from_bytes(elf).unwrap();
        assert!(artifact.detach_signature().unwrap().is_none());

        let sig = vec![1, 2, 3, 4];
        artifact.attach_signature(&sig).unwrap();
        assert_eq!(artifact.detach_signature().unwrap(), Some(sig));
    }
}
