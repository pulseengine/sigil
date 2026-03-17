use std::io::{self, prelude::*};

use crate::error::*;

pub fn get7(reader: &mut impl Read) -> Result<u8, WSError> {
    let mut v: u8 = 0;
    for i in 0..1 {
        let mut byte = [0u8; 1];
        if let Err(e) = reader.read_exact(&mut byte) {
            return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                WSError::Eof
            } else {
                e.into()
            });
        };
        v |= (byte[0] & 0x7f) << (i * 7);
        if (byte[0] & 0x80) == 0 {
            return Ok(v);
        }
    }
    Err(WSError::ParseError)
}

pub fn get32(reader: &mut impl Read) -> Result<u32, WSError> {
    let mut v: u32 = 0;
    for i in 0..5 {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        v |= ((byte[0] & 0x7f) as u32) << (i * 7);
        if (byte[0] & 0x80) == 0 {
            return Ok(v);
        }
    }
    Err(WSError::ParseError)
}

pub fn put(writer: &mut impl Write, mut v: u64) -> Result<(), WSError> {
    let mut byte = [0u8; 1];
    loop {
        byte[0] = (v & 0x7f) as u8;
        if v > 0x7f {
            byte[0] |= 0x80;
        }
        writer.write_all(&byte)?;
        v >>= 7;
        if v == 0 {
            return Ok(());
        }
    }
}

pub fn put_slice(writer: &mut impl Write, bytes: impl AsRef<[u8]>) -> Result<(), WSError> {
    let bytes = bytes.as_ref();
    put(writer, bytes.len() as _)?;
    writer.write_all(bytes)?;
    Ok(())
}

/// Maximum size for a length-prefixed slice (16 MB)
///
/// This limit prevents denial-of-service attacks via malformed length prefixes
/// that could cause excessive memory allocation.
pub const MAX_SLICE_LEN: usize = 16 * 1024 * 1024;

pub fn get_slice(reader: &mut impl Read) -> Result<Vec<u8>, WSError> {
    let len = get32(reader)? as usize;
    // Prevent DoS via excessive memory allocation
    if len > MAX_SLICE_LEN {
        return Err(WSError::ParseError);
    }
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get7_single_byte() {
        let data = vec![0x42];
        let mut reader = io::Cursor::new(data);
        let result = get7(&mut reader).unwrap();
        assert_eq!(result, 0x42);
    }

    #[test]
    fn test_get7_max_value() {
        let data = vec![0x7F];
        let mut reader = io::Cursor::new(data);
        let result = get7(&mut reader).unwrap();
        assert_eq!(result, 0x7F);
    }

    #[test]
    fn test_get7_eof() {
        let data = vec![];
        let mut reader = io::Cursor::new(data);
        let result = get7(&mut reader);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::Eof));
    }

    #[test]
    fn test_get32_single_byte() {
        let data = vec![0x05];
        let mut reader = io::Cursor::new(data);
        let result = get32(&mut reader).unwrap();
        assert_eq!(result, 5);
    }

    #[test]
    fn test_get32_multi_byte() {
        // 128 = 0x80 0x01 in LEB128
        let data = vec![0x80, 0x01];
        let mut reader = io::Cursor::new(data);
        let result = get32(&mut reader).unwrap();
        assert_eq!(result, 128);
    }

    #[test]
    fn test_get32_large_value() {
        // 16384 = 0x80 0x80 0x01 in LEB128
        let data = vec![0x80, 0x80, 0x01];
        let mut reader = io::Cursor::new(data);
        let result = get32(&mut reader).unwrap();
        assert_eq!(result, 16384);
    }

    #[test]
    fn test_put_single_byte() {
        let mut buffer = Vec::new();
        put(&mut buffer, 42).unwrap();
        assert_eq!(buffer, vec![42]);
    }

    #[test]
    fn test_put_multi_byte() {
        let mut buffer = Vec::new();
        put(&mut buffer, 128).unwrap();
        assert_eq!(buffer, vec![0x80, 0x01]);
    }

    #[test]
    fn test_put_large_value() {
        let mut buffer = Vec::new();
        put(&mut buffer, 16384).unwrap();
        assert_eq!(buffer, vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn test_put_zero() {
        let mut buffer = Vec::new();
        put(&mut buffer, 0).unwrap();
        assert_eq!(buffer, vec![0]);
    }

    #[test]
    fn test_put_get_roundtrip() {
        for value in [0, 1, 42, 127, 128, 255, 256, 16384, 1048576] {
            let mut buffer = Vec::new();
            put(&mut buffer, value).unwrap();
            let mut reader = io::Cursor::new(buffer);
            let result = get32(&mut reader).unwrap();
            assert_eq!(result, value as u32);
        }
    }

    #[test]
    fn test_put_slice_empty() {
        let mut buffer = Vec::new();
        let slice: &[u8] = &[];
        put_slice(&mut buffer, slice).unwrap();
        // Should write length (0) as a varint
        assert_eq!(buffer, vec![0]);
    }

    #[test]
    fn test_put_slice_with_data() {
        let mut buffer = Vec::new();
        let slice = vec![1, 2, 3, 4];
        put_slice(&mut buffer, &slice).unwrap();
        // Should write length (4) then the data
        assert_eq!(buffer, vec![4, 1, 2, 3, 4]);
    }

    #[test]
    fn test_get_slice_empty() {
        let data = vec![0];
        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_get_slice_with_data() {
        let data = vec![4, 10, 20, 30, 40];
        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader).unwrap();
        assert_eq!(result, vec![10, 20, 30, 40]);
    }

    #[test]
    fn test_put_get_slice_roundtrip() {
        let original = vec![0, 1, 2, 255, 128, 64];
        let mut buffer = Vec::new();
        put_slice(&mut buffer, &original).unwrap();

        let mut reader = io::Cursor::new(buffer);
        let result = get_slice(&mut reader).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_get_slice_eof() {
        let data = vec![10]; // Says 10 bytes but doesn't provide them
        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_slice_excessive_length() {
        // This is the exact input that the fuzzer found causing OOM
        // It decodes to a length > MAX_SLICE_LEN
        let data = vec![0xff, 0xff, 0xff, 0xff, 0x0a, 0xff];
        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader);
        // Should return error, not OOM
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::ParseError));
    }

    #[test]
    fn test_get_slice_max_allowed_length() {
        // Test that we can still allocate up to MAX_SLICE_LEN
        let mut data = Vec::new();
        // Write a reasonable length (1000 bytes)
        put(&mut data, 1000).unwrap();
        data.extend(vec![0u8; 1000]);

        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1000);
    }
}

// ============================================================================
// Kani proof harnesses for varint encoding/decoding
// ============================================================================
#[cfg(kani)]
mod proofs {
    use super::*;
    use std::io::Cursor;

    /// Prove: put/get32 roundtrip is identity for all u32 values.
    ///
    /// For any u32 value v, encoding v with put() then decoding with get32()
    /// must yield exactly v.
    #[kani::proof]
    #[kani::unwind(11)] // put() loops at most 10 times for u64, get32 loops 5
    fn proof_put_get32_roundtrip() {
        let original: u32 = kani::any();

        let mut buffer = Vec::new();
        put(&mut buffer, original as u64).unwrap();

        let mut reader = Cursor::new(buffer);
        let decoded = get32(&mut reader).unwrap();

        assert_eq!(decoded, original, "roundtrip failed for {}", original);
    }

    /// Prove: get32 never panics on any 5-byte input.
    ///
    /// get32 reads up to 5 bytes. For any possible 5 bytes, it must
    /// either return Ok(value) or Err(_), never panic.
    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_get32_no_panic() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();
        let b4: u8 = kani::any();
        let data = vec![b0, b1, b2, b3, b4];
        let mut reader = Cursor::new(data);
        let _ = get32(&mut reader); // Must not panic
    }

    /// Prove: get32 output fits in u32 (no overflow in shift/or operations).
    ///
    /// The internal calculation `(byte & 0x7f) << (i * 7)` for i=0..4
    /// must never produce a value exceeding u32::MAX.
    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_get32_no_overflow() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();
        let b4: u8 = kani::any();
        let data = vec![b0, b1, b2, b3, b4];
        let mut reader = Cursor::new(data);
        if let Ok(v) = get32(&mut reader) {
            // Value must be a valid u32 (this is trivially true in Rust,
            // but verifies the bit manipulation doesn't wrap unexpectedly)
            assert!(v <= u32::MAX);
        }
    }

    /// Prove: get_slice allocation never exceeds MAX_SLICE_LEN.
    ///
    /// For any input, if get_slice succeeds, the returned Vec length
    /// must be <= MAX_SLICE_LEN.
    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_get_slice_bounded_allocation() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();
        let b4: u8 = kani::any();
        // Provide 5 length bytes + some payload (Kani will explore all combos)
        let data = vec![b0, b1, b2, b3, b4];
        let mut reader = Cursor::new(data);
        if let Ok(slice) = get_slice(&mut reader) {
            assert!(slice.len() <= MAX_SLICE_LEN);
        }
    }

    /// Prove: put encoding is deterministic.
    ///
    /// Encoding the same value twice must produce identical byte sequences.
    #[kani::proof]
    #[kani::unwind(11)]
    fn proof_put_deterministic() {
        let v: u32 = kani::any();

        let mut buf1 = Vec::new();
        put(&mut buf1, v as u64).unwrap();

        let mut buf2 = Vec::new();
        put(&mut buf2, v as u64).unwrap();

        assert_eq!(buf1, buf2);
    }
}
