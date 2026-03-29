/// Pre-Authentication Encoding for DSSE (extracted for Rocq verification).
///
/// This is a self-contained extraction of the PAE function from dsse.rs,
/// suitable for coq-of-rust translation.

/// Compute Pre-Authentication Encoding (PAE) per DSSE spec.
///
/// PAE(payloadType, payload) =
///   "DSSEv1 " || LEN(payloadType) || " " || payloadType || " " ||
///   LEN(payload) || " " || payload
pub fn compute_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();

    // Header
    pae.extend_from_slice(b"DSSEv1 ");

    // LEN(payloadType) SP payloadType
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());

    // SP
    pae.push(b' ');

    // LEN(payload) SP payload
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);

    pae
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pae_deterministic() {
        let a = compute_pae("test", b"data");
        let b = compute_pae("test", b"data");
        assert_eq!(a, b);
    }

    #[test]
    fn test_pae_injective_types() {
        let a = compute_pae("type_a", b"data");
        let b = compute_pae("type_b", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn test_pae_injective_payloads() {
        let a = compute_pae("type", b"data_a");
        let b = compute_pae("type", b"data_b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_pae_length_prefix_prevents_ambiguity() {
        let a = compute_pae("ab", b"cd");
        let b = compute_pae("a", b"bcd");
        assert_ne!(a, b);
    }
}
