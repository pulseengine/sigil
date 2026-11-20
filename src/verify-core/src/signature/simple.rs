use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use ct_codecs::verify as ct_eq;
use log::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;

/// Constant-time check if a hash exists in a set of valid hashes.
/// SECURITY: Uses constant-time comparison to prevent timing attacks.
fn ct_contains_hash<T: AsRef<[u8]>>(valid_hashes: &HashSet<T>, h: &[u8]) -> bool {
    // Check all hashes to maintain constant time regardless of match position
    let mut found = false;
    for valid_hash in valid_hashes {
        if ct_eq(valid_hash.as_ref(), h) {
            found = true;
            // Don't break early - continue checking all to maintain constant time
        }
    }
    found
}

impl SecretKey {
    /// Sign a module with the secret key.
    ///
    /// If the module was already signed, the signature is replaced.
    ///
    /// `key_id` is the key identifier of the public key, to be stored with the signature.
    /// This parameter is optional.
    pub fn sign(&self, module: Module, key_id: Option<&Vec<u8>>) -> Result<Module, CoreError> {
        self.sign_with_version(module, key_id, SignatureVersion::V1)
    }

    /// [`SecretKey::sign`] with an explicit signature format version.
    ///
    /// `SignatureVersion::V2` binds the module's 8-byte preamble into the
    /// signed hash (#303); `SignatureVersion::V1` is byte-for-byte what
    /// [`SecretKey::sign`] emits.
    pub fn sign_with_version(
        &self,
        mut module: Module,
        key_id: Option<&Vec<u8>>,
        version: SignatureVersion,
    ) -> Result<Module, CoreError> {
        let mut out_sections = vec![Section::Custom(CustomSection::default())];
        let mut hasher = version.content_hasher(&module.header);
        for section in module.sections.into_iter() {
            if section.is_signature_header() {
                continue;
            }
            section.serialize(&mut hasher)?;
            out_sections.push(section);
        }
        let h = hasher.finalize().to_vec();

        // SECURITY: Zeroize message buffer on drop to prevent key material leakage
        let msg = version.signed_message(std::slice::from_ref(&h));

        let signature = self.sk.sign(msg.to_vec(), None).to_vec();

        let signature_for_hashes = SignatureForHashes {
            key_id: key_id.cloned(),
            alg_id: ED25519_PK_ID,
            signature,
            certificate_chain: None, // No certificates for simple signing
        };
        let signed_hashes_set = vec![SignedHashes {
            hashes: vec![h],
            signatures: vec![signature_for_hashes],
        }];
        let signature_data = SignatureData {
            specification_version: version.as_u8(),
            content_type: SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            hash_function: SIGNATURE_HASH_FUNCTION,
            signed_hashes_set,
        };
        out_sections[0] = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            signature_data.serialize()?,
        ));

        module.sections = out_sections;
        Ok(module)
    }
}

impl PublicKey {
    /// Verify a module's signature.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` allows the caller to verify a module without an embedded signature.
    ///
    /// This simplified interface verifies the entire module, with a single public key.
    pub fn verify(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
    ) -> Result<(), CoreError> {
        let stream = Module::init_from_reader(reader)?;
        let preamble = stream.header();
        let mut sections = Module::iterate(stream)?;

        // Read the signature header from the module, or reconstruct it from the detached signature.
        let signature_header_section = if let Some(detached_signature) = &detached_signature {
            Section::Custom(CustomSection::new(
                SIGNATURE_SECTION_HEADER_NAME.to_string(),
                detached_signature.to_vec(),
            ))
        } else {
            sections.next().ok_or(CoreError::ParseError)??
        };
        let signature_header = match signature_header_section {
            Section::Custom(custom_section) if custom_section.is_signature_header() => {
                custom_section
            }
            _ => {
                debug!("This module is not signed");
                return Err(CoreError::NoSignatures);
            }
        };

        // Actual signature verification starts here.
        let signature_data = signature_header.signature_data()?;
        if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
            debug!(
                "Unsupported hash function: {:02x}",
                signature_data.specification_version
            );
            return Err(CoreError::ParseError);
        }

        let version = SignatureVersion::from_u8(signature_data.specification_version)?;
        let signed_hashes_set = signature_data.signed_hashes_set;
        // Whole-module verification: ONLY the terminal (whole-stream) hash is
        // acceptable. See valid_hashes_for_pk's docs — accepting a prefix hash
        // would verify a module truncated at a signature delimiter.
        let valid_hashes = self.valid_hashes_for_pk(&signed_hashes_set, version, true)?;
        if valid_hashes.is_empty() {
            debug!("No valid signatures");
            return Err(CoreError::VerificationFailed);
        }

        // v2 binds the preamble: it is absorbed before the section bytes.
        let mut hasher = version.content_hasher(&preamble);
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.read(&mut buf)? {
                0 => break,
                n => {
                    hasher.update(&buf[..n]);
                }
            }
        }
        let h = hasher.finalize().to_vec();

        // SECURITY: Use constant-time comparison to prevent timing attacks
        if ct_contains_hash(&valid_hashes, &h) {
            Ok(())
        } else {
            Err(CoreError::VerificationFailed)
        }
    }
}

impl PublicKeySet {
    /// Verify a module's signature with multiple public keys.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` allows the caller to verify a module without an embedded signature.
    ///
    /// This simplified interface verifies the entire module, with all public keys from the set.
    /// It returns the set of public keys for which a valid signature was found.
    pub fn verify(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
    ) -> Result<HashSet<&PublicKey>, CoreError> {
        let stream = Module::init_from_reader(reader)?;
        let preamble = stream.header();
        let mut sections = Module::iterate(stream)?;

        // Read the signature header from the module, or reconstruct it from the detached signature.
        let signature_header: &Section;
        let signature_header_from_detached_signature;
        let signature_header_from_stream;
        if let Some(detached_signature) = &detached_signature {
            signature_header_from_detached_signature = Section::Custom(CustomSection::new(
                SIGNATURE_SECTION_HEADER_NAME.to_string(),
                detached_signature.to_vec(),
            ));
            signature_header = &signature_header_from_detached_signature;
        } else {
            signature_header_from_stream = sections.next().ok_or(CoreError::ParseError)??;
            signature_header = &signature_header_from_stream;
        }
        let signature_header = match signature_header {
            Section::Custom(custom_section) if custom_section.is_signature_header() => {
                custom_section
            }
            _ => {
                debug!("This module is not signed");
                return Err(CoreError::NoSignatures);
            }
        };

        // Actual signature verification starts here.
        let signature_data = signature_header.signature_data()?;
        if signature_data.content_type != SIGNATURE_WASM_MODULE_CONTENT_TYPE {
            debug!(
                "Unsupported content type: {:02x}",
                signature_data.content_type
            );
            return Err(CoreError::ParseError);
        }
        if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
            debug!(
                "Unsupported hash function: {:02x}",
                signature_data.specification_version
            );
            return Err(CoreError::ParseError);
        }
        let version = SignatureVersion::from_u8(signature_data.specification_version)?;
        let signed_hashes_set = signature_data.signed_hashes_set;
        let valid_hashes_for_pks: HashMap<&PublicKey, HashSet<&Vec<u8>>> = self
            .pks
            .iter()
            .filter_map(
                |pk| match pk.valid_hashes_for_pk(&signed_hashes_set, version, true) {
                    Ok(valid_hashes) if !valid_hashes.is_empty() => Some((pk, valid_hashes)),
                    _ => None,
                },
            )
            .collect();
        if valid_hashes_for_pks.is_empty() {
            debug!("No valid signatures");
            return Err(CoreError::VerificationFailed);
        }

        let mut hasher = version.content_hasher(&preamble);
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.read(&mut buf)? {
                0 => break,
                n => {
                    hasher.update(&buf[..n]);
                }
            }
        }
        let h = hasher.finalize().to_vec();
        let mut valid_pks = HashSet::new();
        for (pk, valid_hashes) in valid_hashes_for_pks {
            // SECURITY: Use constant-time comparison to prevent timing attacks
        if ct_contains_hash(&valid_hashes, &h) {
                valid_pks.insert(pk);
            }
        }
        if valid_pks.is_empty() {
            debug!("No valid signatures");
            return Err(CoreError::VerificationFailed);
        }
        Ok(valid_pks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn create_test_module() -> Module {
        Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        }
    }

    fn serialize_module(module: &Module) -> Vec<u8> {
        let mut buffer = Vec::new();
        module.serialize(&mut buffer).unwrap();
        buffer
    }

    #[test]
    fn test_sign_module() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        let signed_module = kp.sk.sign(module, None).unwrap();

        // First section should be signature
        assert!(signed_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_sign_module_with_key_id() {
        let kp = KeyPair::generate();
        let module = create_test_module();
        let key_id = vec![1, 2, 3, 4];

        let signed_module = kp.sk.sign(module, Some(&key_id)).unwrap();

        // Verify signature header exists
        assert!(signed_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_sign_replaces_existing_signature() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign once
        let signed_module = kp.sk.sign(module, None).unwrap();

        // Sign again - should replace signature
        let signed_module2 = kp.sk.sign(signed_module, None).unwrap();

        // Should still have only one signature header
        let sig_headers: Vec<_> = signed_module2
            .sections
            .iter()
            .filter(|s| s.is_signature_header())
            .collect();
        assert_eq!(sig_headers.len(), 1);
    }

    #[test]
    fn test_verify_signed_module() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        let signed_module = kp.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        let mut reader = Cursor::new(signed_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_unsigned_module() {
        let kp = KeyPair::generate();
        let module = create_test_module();
        let unsigned_bytes = serialize_module(&module);

        let mut reader = Cursor::new(unsigned_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoreError::NoSignatures));
    }

    #[test]
    fn test_verify_with_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let module = create_test_module();

        // Sign with key 1
        let signed_module = kp1.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        // Try to verify with key 2
        let mut reader = Cursor::new(signed_bytes);
        let result = kp2.pk.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoreError::VerificationFailed));
    }

    #[test]
    fn test_verify_with_detached_signature() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign and detach
        let signed_module = kp.sk.sign(module, None).unwrap();
        let (unsigned_module, detached_sig) = signed_module.detach_signature().unwrap();
        let unsigned_bytes = serialize_module(&unsigned_module);

        // Verify with detached signature
        let mut reader = Cursor::new(unsigned_bytes);
        let result = kp.pk.verify(&mut reader, Some(&detached_sig));
        assert!(result.is_ok());
    }

    #[test]
    fn test_public_key_set_verify() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let module = create_test_module();

        // Sign with key 1
        let signed_module = kp1.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        // Create a key set with both keys
        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp1.pk.clone()).unwrap();
        key_set.insert(kp2.pk).unwrap();

        // Verify - should find key 1
        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify(&mut reader, None);
        assert!(result.is_ok());
        let valid_pks = result.unwrap();
        assert_eq!(valid_pks.len(), 1);
        assert!(valid_pks.contains(&kp1.pk));
    }

    #[test]
    fn test_public_key_set_verify_unsigned() {
        let kp = KeyPair::generate();
        let module = create_test_module();
        let unsigned_bytes = serialize_module(&module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk).unwrap();

        let mut reader = Cursor::new(unsigned_bytes);
        let result = key_set.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoreError::NoSignatures));
    }

    #[test]
    fn test_public_key_set_verify_no_matching_keys() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let module = create_test_module();

        // Sign with key 1
        let signed_module = kp1.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        // Create key set with only key 2 (different)
        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp2.pk).unwrap();

        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoreError::VerificationFailed));
    }

    #[test]
    fn test_public_key_set_verify_with_detached_signature() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign and detach
        let signed_module = kp.sk.sign(module, None).unwrap();
        let (unsigned_module, detached_sig) = signed_module.detach_signature().unwrap();
        let unsigned_bytes = serialize_module(&unsigned_module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk.clone()).unwrap();

        // Verify with detached signature
        let mut reader = Cursor::new(unsigned_bytes);
        let result = key_set.verify(&mut reader, Some(&detached_sig));
        assert!(result.is_ok());
        let valid_pks = result.unwrap();
        assert_eq!(valid_pks.len(), 1);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign
        let signed_module = kp.sk.sign(module, None).unwrap();

        // Serialize
        let signed_bytes = serialize_module(&signed_module);

        // Verify
        let mut reader = Cursor::new(signed_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_with_modified_module_fails() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign
        let signed_module = kp.sk.sign(module, None).unwrap();
        let mut signed_bytes = serialize_module(&signed_module);

        // Modify the signed bytes (corrupt the module)
        if signed_bytes.len() > 50 {
            signed_bytes[50] ^= 0xFF;
        }

        // Verify should fail
        let mut reader = Cursor::new(signed_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_err());
    }

    // ===================================================================
    // MYTHOS DISCOVERY PoCs (uncommitted) — PublicKey::verify wrong-accept
    // ===================================================================

    /// Fixture: the shipped `sigil split` + `sigil sign` workflow.
    ///
    /// `split` inserts delimiter sections at every signed/unsigned
    /// transition; `sign_multi` then pushes a *cumulative* hash at every
    /// delimiter (the hasher is never reset), so the signature covers
    /// `h1 ‖ h2 ‖ h3` where each `hi` is the hash of a PREFIX of the
    /// section stream.
    fn create_split_signed_module(kp: &KeyPair) -> Module {
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let split_module = module
            .split(|section| matches!(section.id(), SectionId::Type | SectionId::Code))
            .unwrap();
        let (signed_module, _) = kp.sk.sign_multi(split_module, None, false, false).unwrap();
        signed_module
    }

    fn signed_hash_count(module: &Module) -> usize {
        match &module.sections[0] {
            Section::Custom(cs) => cs.signature_data().unwrap().signed_hashes_set[0]
                .hashes
                .len(),
            _ => panic!("first section is not the signature header"),
        }
    }

    /// PoC 1 — `PublicKey::verify` accepts a TRUNCATED module.
    ///
    /// `PublicKey::verify` is documented as verifying "the entire module"
    /// and takes no predicate, but it compares the whole-stream hash
    /// against the *set* of signed hashes produced by
    /// `valid_hashes_for_pk`. For a module signed through the
    /// `sigil split` / `sigil sign` workflow that set contains one entry
    /// per delimiter, each the hash of a PREFIX of the stream. Deleting
    /// every section after any delimiter therefore yields a module whose
    /// whole-stream hash is still a member of the signed set.
    #[test]
    fn poc_verify_accepts_truncated_split_signed_module() {
        let kp = KeyPair::generate();
        let signed = create_split_signed_module(&kp);

        // Sections: [sig_header, Type, D1, Function, D2, Code, D3]
        assert_eq!(signed.sections.len(), 7, "fixture shape changed");
        assert!(signed.sections[2].is_signature_delimiter());
        assert_eq!(
            signed_hash_count(&signed),
            3,
            "fixture must carry multiple prefix hashes"
        );

        // POSITIVE CONTROL: the untampered module verifies.
        let mut reader = Cursor::new(serialize_module(&signed));
        assert!(
            kp.pk.verify(&mut reader, None).is_ok(),
            "positive control failed: untampered module must verify"
        );

        // NEGATIVE CONTROL: truncating at a point that is NOT a delimiter
        // must be rejected — proves content really is hashed and compared.
        let not_at_delimiter = Module {
            header: signed.header,
            sections: signed.sections[0..=1].to_vec(), // [sig_header, Type]
        };
        let mut reader = Cursor::new(serialize_module(&not_at_delimiter));
        assert!(
            kp.pk.verify(&mut reader, None).is_err(),
            "negative control failed: non-delimiter truncation must be rejected"
        );

        // ATTACK: drop everything after the FIRST delimiter. The Function
        // and Code sections (signed by the publisher) are gone.
        let truncated = Module {
            header: signed.header,
            sections: signed.sections[0..=2].to_vec(), // [sig_header, Type, D1]
        };
        let mut reader = Cursor::new(serialize_module(&truncated));
        let result = kp.pk.verify(&mut reader, None);
        assert!(
            result.is_err(),
            "WRONG-ACCEPT: PublicKey::verify returned Ok for a module whose \
             Function and Code sections were deleted after signing"
        );
    }

    /// PoC 2 — same defect in `PublicKeySet::verify` (`valid_hashes_for_pks`
    /// + `ct_contains_hash`, lines ~212-247).
    #[test]
    fn poc_public_key_set_verify_accepts_truncated_split_signed_module() {
        let kp = KeyPair::generate();
        let signed = create_split_signed_module(&kp);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk.clone()).unwrap();

        // POSITIVE CONTROL
        let mut reader = Cursor::new(serialize_module(&signed));
        assert!(
            key_set.verify(&mut reader, None).is_ok(),
            "positive control failed: untampered module must verify"
        );

        // NEGATIVE CONTROL
        let not_at_delimiter = Module {
            header: signed.header,
            sections: signed.sections[0..=1].to_vec(),
        };
        let mut reader = Cursor::new(serialize_module(&not_at_delimiter));
        assert!(
            key_set.verify(&mut reader, None).is_err(),
            "negative control failed: non-delimiter truncation must be rejected"
        );

        // ATTACK
        let truncated = Module {
            header: signed.header,
            sections: signed.sections[0..=2].to_vec(),
        };
        let mut reader = Cursor::new(serialize_module(&truncated));
        let result = key_set.verify(&mut reader, None);
        assert!(
            result.is_err(),
            "WRONG-ACCEPT: PublicKeySet::verify returned Ok for a truncated module"
        );
    }

    /// PoC 2b — the same truncation wrong-accept through the
    /// DETACHED-signature path, which is the realistic delivery vector:
    /// publisher ships `module.wasm` + `module.sig`, an attacker serves a
    /// truncated `module.wasm`, and
    /// `sigil verify -i module.wasm --signature-file module.sig`
    /// still prints "Signature is valid."
    ///
    /// In the detached branch `sections.next()` is never called, so the raw
    /// hash starts at section 0 — but it is still compared by set membership
    /// against every prefix hash in the signed sequence.
    #[test]
    fn poc_verify_accepts_truncated_module_with_detached_signature() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let split_module = module
            .split(|section| matches!(section.id(), SectionId::Type | SectionId::Code))
            .unwrap();
        // detached = true: the module is returned unmodified, the signature
        // travels out of band.
        let (unsigned, detached_sig) = kp.sk.sign_multi(split_module, None, true, false).unwrap();

        // Sections: [Type, D1, Function, D2, Code, D3]
        assert_eq!(unsigned.sections.len(), 6, "fixture shape changed");
        assert!(unsigned.sections[1].is_signature_delimiter());

        // POSITIVE CONTROL: full file + its detached signature verifies.
        let mut reader = Cursor::new(serialize_module(&unsigned));
        assert!(
            kp.pk.verify(&mut reader, Some(&detached_sig)).is_ok(),
            "positive control failed: untampered module + detached sig must verify"
        );

        // NEGATIVE CONTROL: truncation that does not end at a delimiter.
        let not_at_delimiter = Module {
            header: unsigned.header,
            sections: unsigned.sections[0..=0].to_vec(), // [Type]
        };
        let mut reader = Cursor::new(serialize_module(&not_at_delimiter));
        assert!(
            kp.pk.verify(&mut reader, Some(&detached_sig)).is_err(),
            "negative control failed: non-delimiter truncation must be rejected"
        );

        // ATTACK: drop everything after the first delimiter.
        let truncated = Module {
            header: unsigned.header,
            sections: unsigned.sections[0..=1].to_vec(), // [Type, D1]
        };
        let mut reader = Cursor::new(serialize_module(&truncated));
        let result = kp.pk.verify(&mut reader, Some(&detached_sig));
        assert!(
            result.is_err(),
            "WRONG-ACCEPT: PublicKey::verify returned Ok for a truncated module \
             checked against the publisher's detached signature"
        );
    }

    /// PoC 4 — same set-membership mechanism WITHOUT `split`: a signature
    /// header that accumulated an older hash set authorizes the older
    /// content.
    ///
    /// `sign_multi` keeps the previous `signed_hashes_set` entries when a
    /// module is re-signed (documented: "the new signature is added to the
    /// existing ones"). If the content changed between signings, the header
    /// ends up carrying one entry per content version, all valid under the
    /// same key, and `PublicKey::verify` accepts a byte stream matching ANY
    /// of them. An attacker can therefore ship the OLD content with the NEW
    /// signature header / detached signature.
    /// #304: re-signing changed content with the same key must not keep the
    /// key's older signature. Before the fix the v2 header carried two
    /// entries and v1 content verified under it (rollback).
    ///
    /// rivet: verifies REQ-33
    #[test]
    fn poc_verify_accepts_rolled_back_content_with_newer_signature() {
        let kp = KeyPair::generate();

        // v1: sign the original module.
        let v1 = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let (signed_v1, _) = kp.sk.sign_multi(v1, None, false, false).unwrap();

        // v2: add a section to the signed module and re-sign with the SAME key.
        let mut v2_sections = signed_v1.sections.clone();
        v2_sections.push(Section::Custom(CustomSection::new(
            "meta".to_string(),
            vec![0xaa, 0xbb],
        )));
        let v2 = Module {
            header: signed_v1.header,
            sections: v2_sections,
        };
        let (signed_v2, _) = kp.sk.sign_multi(v2, None, false, false).unwrap();

        // The v2 header now authorizes two different contents.
        let entries = match &signed_v2.sections[0] {
            Section::Custom(cs) => cs.signature_data().unwrap().signed_hashes_set.len(),
            _ => panic!("no signature header"),
        };
        assert_eq!(
            entries, 1,
            "re-signing with the same key must supersede the older entry"
        );

        // POSITIVE CONTROL: v2 verifies under its own header.
        let mut reader = Cursor::new(serialize_module(&signed_v2));
        assert!(
            kp.pk.verify(&mut reader, None).is_ok(),
            "positive control failed: v2 must verify"
        );

        // NEGATIVE CONTROL: content that was never signed is rejected.
        let mut never_signed = signed_v2.clone();
        never_signed.sections[1] =
            Section::Standard(StandardSection::new(SectionId::Type, vec![9, 9, 9]));
        let mut reader = Cursor::new(serialize_module(&never_signed));
        assert!(
            kp.pk.verify(&mut reader, None).is_err(),
            "negative control failed: unsigned content must be rejected"
        );

        // ATTACK: v1 content carried under the v2 signature header.
        let rolled_back = Module {
            header: signed_v2.header,
            sections: vec![
                signed_v2.sections[0].clone(), // v2 signature header
                signed_v2.sections[1].clone(), // Type
                signed_v2.sections[2].clone(), // Code  ("meta" dropped)
            ],
        };
        let mut reader = Cursor::new(serialize_module(&rolled_back));
        let result = kp.pk.verify(&mut reader, None);
        assert!(
            result.is_err(),
            "WRONG-ACCEPT: PublicKey::verify returned Ok for rolled-back content \
             carrying the newer signature header"
        );
    }

    /// #304 must not break layered signing: an author signs v1, a
    /// distributor appends a section and signs v2 with a DIFFERENT key. The
    /// author's entry stays, so v1 still verifies under the author's key,
    /// and the distributor's key accepts only v2.
    ///
    /// rivet: verifies REQ-33
    #[test]
    fn resign_with_another_key_keeps_the_other_signers_entry() {
        let author = KeyPair::generate();
        let distributor = KeyPair::generate();
        let v1 = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let (signed_v1, _) = author.sk.sign_multi(v1, None, false, false).unwrap();
        let mut v2_sections = signed_v1.sections.clone();
        v2_sections.push(Section::Custom(CustomSection::new(
            "meta".to_string(),
            vec![0xaa, 0xbb],
        )));
        let v2 = Module {
            header: signed_v1.header,
            sections: v2_sections,
        };
        let (signed_v2, _) = distributor.sk.sign_multi(v2, None, false, false).unwrap();
        let entries = match &signed_v2.sections[0] {
            Section::Custom(cs) => cs.signature_data().unwrap().signed_hashes_set.len(),
            _ => panic!("no signature header"),
        };
        assert_eq!(
            entries, 2,
            "the author's entry must survive another key's re-sign"
        );

        let v2_bytes = serialize_module(&signed_v2);
        assert!(distributor
            .pk
            .verify(&mut Cursor::new(&v2_bytes), None)
            .is_ok());

        let rolled_back = Module {
            header: signed_v2.header,
            sections: signed_v2.sections[..3].to_vec(),
        };
        let v1_bytes = serialize_module(&rolled_back);
        assert!(
            author.pk.verify(&mut Cursor::new(&v1_bytes), None).is_ok(),
            "the author signed v1; it must still verify under the author's key"
        );
        assert!(
            distributor
                .pk
                .verify(&mut Cursor::new(&v1_bytes), None)
                .is_err(),
            "the distributor never signed v1"
        );
    }

    /// PoC 3, v1 — the 8-byte WASM preamble is not covered by a v1 signature.
    ///
    /// `SecretKey::sign` (v1, the default) hashes only `section.serialize(..)`
    /// for each section; `PublicKey::verify` consumes the preamble via
    /// `Module::init_from_reader` and, for v1, hashes only what follows.
    /// Since `init_from_reader` accepts both `WASM_HEADER` and
    /// `WASM_COMPONENT_HEADER`, the core-module preamble of a v1-signed
    /// artifact can be rewritten to the component preamble and the
    /// signature still verifies: two distinct files, one signature.
    ///
    /// Signature format v2 closes this (see
    /// `poc_verify_accepts_rewritten_module_preamble` below, which runs). v1
    /// is deliberately left unchanged: whether v1 signatures are rejected,
    /// and whether signing defaults to v2, is an open owner decision (plan
    /// v0.14.0 B1, "O2 guard"). This oracle stays ignored until then.
    #[test]
    #[ignore = "OPEN DECISION (#303): v1 signatures do not bind the 8-byte WASM \
                preamble, by design of the v1 format. v2 (opt-in, \
                SignatureVersion::V2) binds it. Whether v1 is rejected or v2 \
                becomes the default is an owner decision; this oracle fails \
                until then and is kept so the v1 gap stays visible."]
    fn poc_v1_verify_accepts_rewritten_module_preamble() {
        let kp = KeyPair::generate();
        let module = create_test_module();
        let signed = kp.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed);

        // POSITIVE CONTROL
        let mut reader = Cursor::new(signed_bytes.clone());
        assert!(
            kp.pk.verify(&mut reader, None).is_ok(),
            "positive control failed: untampered module must verify"
        );

        // ATTACK: core module -> component preamble, bytes 4..8.
        let mut relabelled = signed_bytes.clone();
        relabelled[4..8].copy_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        assert_ne!(relabelled, signed_bytes);
        let mut reader = Cursor::new(relabelled);
        let result = kp.pk.verify(&mut reader, None);
        assert!(
            result.is_err(),
            "WRONG-ACCEPT: PublicKey::verify returned Ok for a v1 artifact whose \
             WASM preamble was rewritten after signing (module -> component)"
        );
    }

    // ===================================================================
    // Signature format v2 (#303, REQ-32): the preamble is bound.
    // ===================================================================

    const CORE_PREAMBLE: Header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    const COMPONENT_PREAMBLE: Header = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

    fn create_test_component() -> Module {
        let mut m = create_test_module();
        m.header = COMPONENT_PREAMBLE;
        m
    }

    /// Rewrite the version byte of the embedded signature header (section 0)
    /// without touching the hashes or signatures: a relabelling attack.
    fn relabel_embedded(module: &Module, version: u8) -> Module {
        let mut out = module.clone();
        let payload = match &out.sections[0] {
            Section::Custom(cs) if cs.is_signature_header() => cs.payload().to_vec(),
            _ => panic!("section 0 is not the signature header"),
        };
        out.sections[0] = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            relabel_detached(&payload, version),
        ));
        out
    }

    /// Rewrite the version byte of a serialized `SignatureData`. The version
    /// is the first varint and every supported value fits in one byte.
    fn relabel_detached(payload: &[u8], version: u8) -> Vec<u8> {
        assert!(payload[0] < 0x80 && version < 0x80);
        let mut out = payload.to_vec();
        out[0] = version;
        out
    }

    fn signature_version_of(module: &Module) -> u8 {
        match &module.sections[0] {
            Section::Custom(cs) => cs.signature_data().unwrap().specification_version,
            _ => panic!("no signature header"),
        }
    }

    fn signed_hashes_of(module: &Module) -> Vec<Vec<u8>> {
        match &module.sections[0] {
            Section::Custom(cs) => cs.signature_data().unwrap().signed_hashes_set[0]
                .hashes
                .clone(),
            _ => panic!("no signature header"),
        }
    }

    /// PoC 3, v2 — the varve-reported case (component preamble rewritten to
    /// a core-module preamble) and its inverse are REJECTED under v2.
    ///
    /// This is the B1 acceptance oracle: before v2 existed this test was
    /// `#[ignore]`d and failed. It now signs with `SignatureVersion::V2`.
    // rivet: verifies REQ-32
    #[test]
    fn poc_verify_accepts_rewritten_module_preamble() {
        let kp = KeyPair::generate();
        for (original, rewritten) in [
            (COMPONENT_PREAMBLE, CORE_PREAMBLE), // varve's case (#303)
            (CORE_PREAMBLE, COMPONENT_PREAMBLE),
        ] {
            let mut module = create_test_module();
            module.header = original;
            let signed = kp
                .sk
                .sign_with_version(module, None, SignatureVersion::V2)
                .unwrap();
            assert_eq!(signature_version_of(&signed), SIGNATURE_VERSION_V2);
            let signed_bytes = serialize_module(&signed);

            // POSITIVE CONTROL
            assert!(
                kp.pk.verify(&mut Cursor::new(&signed_bytes), None).is_ok(),
                "positive control failed: untampered v2 module must verify"
            );

            // NEGATIVE CONTROL: a preamble that is neither magic is rejected
            // by the parser before any hashing.
            let mut garbage = signed_bytes.clone();
            garbage[1] = 0xff;
            assert!(matches!(
                kp.pk.verify(&mut Cursor::new(&garbage), None),
                Err(CoreError::UnsupportedModuleType)
            ));

            // ATTACK: rewrite the version/layer bytes 4..8.
            let mut relabelled = signed_bytes.clone();
            relabelled[0..8].copy_from_slice(&rewritten);
            assert_ne!(relabelled, signed_bytes);
            let result = kp.pk.verify(&mut Cursor::new(&relabelled), None);
            assert!(
                matches!(result, Err(CoreError::VerificationFailed)),
                "WRONG-ACCEPT: v2 PublicKey::verify returned {:?} for an artifact \
                 whose preamble was rewritten {:02x?} -> {:02x?}",
                result,
                original,
                rewritten
            );
        }
    }

    /// The same rewrite through `PublicKeySet::verify` and the detached path.
    // rivet: verifies REQ-32
    #[test]
    fn v2_rewritten_preamble_is_rejected_by_key_set_and_detached_verify() {
        let kp = KeyPair::generate();
        let signed = kp
            .sk
            .sign_with_version(create_test_component(), None, SignatureVersion::V2)
            .unwrap();
        let (unsigned, detached) = signed.clone().detach_signature().unwrap();
        let mut set = PublicKeySet::empty();
        set.insert(kp.pk.clone()).unwrap();

        let embedded = serialize_module(&signed);
        let bare = serialize_module(&unsigned);
        assert!(set.verify(&mut Cursor::new(&embedded), None).is_ok());
        assert!(
            kp.pk
                .verify(&mut Cursor::new(&bare), Some(&detached))
                .is_ok()
        );
        assert!(set.verify(&mut Cursor::new(&bare), Some(&detached)).is_ok());

        let mut embedded_rw = embedded.clone();
        embedded_rw[0..8].copy_from_slice(&CORE_PREAMBLE);
        let mut bare_rw = bare.clone();
        bare_rw[0..8].copy_from_slice(&CORE_PREAMBLE);
        assert!(matches!(
            set.verify(&mut Cursor::new(&embedded_rw), None),
            Err(CoreError::VerificationFailed)
        ));
        assert!(matches!(
            kp.pk.verify(&mut Cursor::new(&bare_rw), Some(&detached)),
            Err(CoreError::VerificationFailed)
        ));
        assert!(matches!(
            set.verify(&mut Cursor::new(&bare_rw), Some(&detached)),
            Err(CoreError::VerificationFailed)
        ));
    }

    /// Every preamble byte is in the v2 signed hash, not just the bytes the
    /// parser happens to distinguish. A changed version/layer byte other than
    /// the two accepted preambles is already refused by the parser
    /// (`UnsupportedModuleType`), so this checks binding at the hash level.
    // rivet: verifies REQ-32
    #[test]
    fn v2_signed_hash_changes_with_every_preamble_byte() {
        let kp = KeyPair::generate();
        let base = kp
            .sk
            .sign_with_version(create_test_component(), None, SignatureVersion::V2)
            .unwrap();
        let base_hashes = signed_hashes_of(&base);
        for i in 0..8 {
            let mut m = create_test_component();
            m.header[i] ^= 0x01;
            let signed = kp
                .sk
                .sign_with_version(m, None, SignatureVersion::V2)
                .unwrap();
            assert_ne!(
                signed_hashes_of(&signed),
                base_hashes,
                "preamble byte {} is not bound by v2",
                i
            );
        }
        // v1 control: the preamble does not reach the v1 hash.
        let mut m = create_test_component();
        m.header = CORE_PREAMBLE;
        let v1_core = kp.sk.sign(m, None).unwrap();
        let v1_comp = kp.sk.sign(create_test_component(), None).unwrap();
        assert_eq!(signed_hashes_of(&v1_core), signed_hashes_of(&v1_comp));
    }

    /// v2 sign then verify, single signature, embedded and detached, through
    /// both `PublicKey::verify` and `PublicKeySet::verify`.
    // rivet: verifies REQ-32
    #[test]
    fn v2_sign_then_verify_succeeds() {
        let kp = KeyPair::generate();
        for module in [create_test_module(), create_test_component()] {
            let signed = kp
                .sk
                .sign_with_version(module, None, SignatureVersion::V2)
                .unwrap();
            let bytes = serialize_module(&signed);
            assert!(kp.pk.verify(&mut Cursor::new(&bytes), None).is_ok());
            let mut set = PublicKeySet::empty();
            set.insert(kp.pk.clone()).unwrap();
            assert_eq!(set.verify(&mut Cursor::new(&bytes), None).unwrap().len(), 1);

            // Content tamper is still caught under v2.
            let mut tampered = bytes.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0xff;
            assert!(kp.pk.verify(&mut Cursor::new(&tampered), None).is_err());
        }
    }

    /// The default signer still emits v1, and `sign_with_version(V1)` is
    /// byte-for-byte `sign`.
    // rivet: verifies REQ-32
    #[test]
    fn signer_defaults_to_v1() {
        let kp = KeyPair::generate();
        let a = kp.sk.sign(create_test_component(), None).unwrap();
        let b = kp
            .sk
            .sign_with_version(create_test_component(), None, SignatureVersion::V1)
            .unwrap();
        assert_eq!(signature_version_of(&a), SIGNATURE_VERSION_V1);
        assert_eq!(serialize_module(&a), serialize_module(&b));
        let (c, _) = kp
            .sk
            .sign_multi(create_test_component(), None, false, false)
            .unwrap();
        assert_eq!(signature_version_of(&c), SIGNATURE_VERSION_V1);
    }

    /// A v1 signature relabelled as v2 fails, and a v2 signature relabelled
    /// as v1 fails, embedded and detached, single-key and key-set.
    // rivet: verifies REQ-32
    #[test]
    fn cross_version_relabelling_is_rejected() {
        let kp = KeyPair::generate();
        let mut set = PublicKeySet::empty();
        set.insert(kp.pk.clone()).unwrap();
        for (sign_as, relabel_to) in [
            (SignatureVersion::V1, SIGNATURE_VERSION_V2),
            (SignatureVersion::V2, SIGNATURE_VERSION_V1),
        ] {
            let signed = kp
                .sk
                .sign_with_version(create_test_component(), None, sign_as)
                .unwrap();
            // Positive control: unrelabelled verifies.
            assert!(
                kp.pk
                    .verify(&mut Cursor::new(serialize_module(&signed)), None)
                    .is_ok()
            );

            let relabelled = relabel_embedded(&signed, relabel_to);
            assert_eq!(signature_version_of(&relabelled), relabel_to);
            let bytes = serialize_module(&relabelled);
            assert!(
                matches!(
                    kp.pk.verify(&mut Cursor::new(&bytes), None),
                    Err(CoreError::VerificationFailed)
                ),
                "{:?} signature relabelled as v{} must not verify",
                sign_as,
                relabel_to
            );
            assert!(set.verify(&mut Cursor::new(&bytes), None).is_err());

            let (unsigned, detached) = signed.detach_signature().unwrap();
            let bare = serialize_module(&unsigned);
            assert!(
                kp.pk
                    .verify(&mut Cursor::new(&bare), Some(&detached))
                    .is_ok()
            );
            let detached_rl = relabel_detached(&detached, relabel_to);
            assert!(matches!(
                kp.pk.verify(&mut Cursor::new(&bare), Some(&detached_rl)),
                Err(CoreError::VerificationFailed)
            ));
        }
    }

    /// Version 3 (and 0) are still rejected at parse time, embedded and
    /// detached, even when relabelled from a valid v1 or v2 signature.
    // rivet: verifies REQ-32
    #[test]
    fn unknown_signature_version_is_rejected() {
        let kp = KeyPair::generate();
        for sign_as in [SignatureVersion::V1, SignatureVersion::V2] {
            let signed = kp
                .sk
                .sign_with_version(create_test_component(), None, sign_as)
                .unwrap();
            for bad in [0u8, 3] {
                let bytes = serialize_module(&relabel_embedded(&signed, bad));
                assert!(matches!(
                    kp.pk.verify(&mut Cursor::new(&bytes), None),
                    Err(CoreError::ParseError)
                ));
                let mut set = PublicKeySet::empty();
                set.insert(kp.pk.clone()).unwrap();
                assert!(matches!(
                    set.verify(&mut Cursor::new(&bytes), None),
                    Err(CoreError::ParseError)
                ));
                let (unsigned, detached) = signed.clone().detach_signature().unwrap();
                assert!(matches!(
                    kp.pk.verify(
                        &mut Cursor::new(serialize_module(&unsigned)),
                        Some(&relabel_detached(&detached, bad))
                    ),
                    Err(CoreError::ParseError)
                ));
            }
        }
    }

    // ---------------------------------------------------------------
    // Frozen v1 fixture: bytes produced by the pre-v2 code (origin/main
    // 101016a) from an Ed25519 key with seed [7; 32] over a 3-section
    // component. Ed25519 is deterministic, so the current v1 signer must
    // reproduce them exactly, and the current verifier must accept them.
    // ---------------------------------------------------------------

    const FIXTURE_V1_PK: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const FIXTURE_V1_SIGNED: &str = "0061736d0d0001000076097369676e6174757265010101016701f8ef0f895f2f7009f14567e30523f8631f017142b0fd5d56f7e175150b946526014400014000eca2b0c9a5d4d6bdf07ece944b42a049f6b91d0ffb50ce279bfec1c7c173d12be420a3bcdf86d7f9bfd9a054375686aac70cdd818ba666bebc0d34871e1b0f00010301020303030405060a03070809";
    const FIXTURE_V1_DETACHED: &str = "010101016701f8ef0f895f2f7009f14567e30523f8631f017142b0fd5d56f7e175150b946526014400014000eca2b0c9a5d4d6bdf07ece944b42a049f6b91d0ffb50ce279bfec1c7c173d12be420a3bcdf86d7f9bfd9a054375686aac70cdd818ba666bebc0d34871e1b0f00";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixture_key() -> (SecretKey, PublicKey) {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([7u8; 32]));
        (
            SecretKey { sk: kp.sk },
            PublicKey {
                pk: kp.pk,
                key_id: None,
            },
        )
    }

    /// v1 signatures made before v2 existed still verify unchanged, and the
    /// v1 signer still produces the same bytes.
    // rivet: verifies REQ-32
    #[test]
    fn frozen_v1_fixture_still_verifies_and_is_reproduced() {
        let (sk, pk) = fixture_key();
        assert_eq!(pk.pk.as_ref(), unhex(FIXTURE_V1_PK).as_slice());
        let signed = unhex(FIXTURE_V1_SIGNED);
        let detached = unhex(FIXTURE_V1_DETACHED);

        // Verifies (embedded, single key and key set).
        assert!(pk.verify(&mut Cursor::new(&signed), None).is_ok());
        let mut set = PublicKeySet::empty();
        set.insert(pk.clone()).unwrap();
        assert!(set.verify(&mut Cursor::new(&signed), None).is_ok());

        // Verifies detached.
        let module = Module::deserialize(&mut Cursor::new(&signed)).unwrap();
        let (unsigned, _) = module.detach_signature().unwrap();
        let bare = serialize_module(&unsigned);
        assert!(pk.verify(&mut Cursor::new(&bare), Some(&detached)).is_ok());

        // v1 still leaves the preamble unbound (the fixture is a component;
        // the core-module rewrite verifies). This pins "v1 unchanged".
        let mut rewritten = signed.clone();
        rewritten[0..8].copy_from_slice(&CORE_PREAMBLE);
        assert!(pk.verify(&mut Cursor::new(&rewritten), None).is_ok());

        // The current v1 signers reproduce the frozen bytes exactly.
        let resigned = sk.sign(create_test_component(), None).unwrap();
        assert_eq!(serialize_module(&resigned), signed);
        let (resigned_multi, _) = sk
            .sign_multi(create_test_component(), None, false, false)
            .unwrap();
        assert_eq!(serialize_module(&resigned_multi), signed);
        let (_, resigned_detached) = sk
            .sign_multi(create_test_component(), None, true, false)
            .unwrap();
        assert_eq!(resigned_detached, detached);
    }
}

/// MYTHOS DISCOVERY (uncommitted): ATTEMPTED Kani oracle for the hash-scope
/// wrong-accept in `PublicKey::verify`. **THIS IS NOT A VALID ORACLE.**
///
/// Property it tries to state: a module whose whole-stream hash equals a
/// NON-TERMINAL (prefix) hash of a signed hash sequence must be rejected.
///
/// Recorded outcome (kani 0.67.0, `cargo kani -p wsc-verify-core --harness
/// attempted_proof_verify_rejects_non_terminal_prefix_hash`):
///
/// ```text
/// SUMMARY:
///  ** 1 of 15449 failed (15448 undetermined)
/// Failed Checks: call to foreign "C" function `getentropy` is not currently
/// supported by Kani.
/// VERIFICATION:- FAILED
/// ** WARNING: A Rust construct that is not currently supported by Kani was
/// found to be reachable.
/// ```
///
/// The harness "fails" for the wrong reason (`getentropy` behind
/// `KeyPair::generate`) and 15448/15449 checks are UNDETERMINED inside
/// `ed25519_compact::sha512` and `hmac_sha256::Hash::finalize`. Per
/// AGENTS.md "Kani scope limitation" that is evidence the tool cannot reach
/// the property, NOT evidence about the property. The deterministic oracle
/// for this finding is the `poc_*` test above; the nearest primitive-layer
/// Kani proofs are `wasm_module/varint.rs:272-360` and
/// `wasm_module/mod.rs:1046`.
#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use std::io::Cursor;

    #[kani::proof]
    #[kani::unwind(4)]
    fn attempted_proof_verify_rejects_non_terminal_prefix_hash() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![2])),
            ],
        };
        let split = module
            .split(|section| matches!(section.id(), SectionId::Type | SectionId::Code))
            .unwrap();
        let (signed, _) = kp.sk.sign_multi(split, None, false, false).unwrap();

        // Truncate at the first delimiter.
        let truncated = Module {
            header: signed.header,
            sections: signed.sections[0..=2].to_vec(),
        };
        let mut buf = Vec::new();
        truncated.serialize(&mut buf).unwrap();
        let mut reader = Cursor::new(buf);
        assert!(kp.pk.verify(&mut reader, None).is_err());
    }
}
