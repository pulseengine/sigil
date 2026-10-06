use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use ct_codecs::{verify as ct_eq, Encoder, Hex};
use log::*;
use std::collections::HashSet;
use std::io::Read;
use zeroize::Zeroizing;

/// Constant-time comparison of two hash vectors.
/// Returns true only if both vectors have the same length and all hashes match.
/// SECURITY: Uses constant-time comparison to prevent timing attacks.
fn ct_eq_hashes(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Compare all hashes, accumulating result to maintain constant time
    let mut result = true;
    for (x, y) in a.iter().zip(b.iter()) {
        // ct_eq returns false for different lengths, so this is safe
        result = result && ct_eq(x, y);
    }
    result
}

/// Constant-time comparison of optional byte vectors (for key_id).
/// SECURITY: Uses constant-time comparison to prevent timing attacks.
fn ct_eq_option(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => ct_eq(x, y),
        (None, None) => true,
        _ => false,
    }
}

impl SecretKey {
    /// Sign a module with the secret key.
    ///
    /// If the module was already signed, the new signature is added to the existing ones.
    /// `key_id` is the key identifier of the public key, to be stored with the signature.
    /// This parameter is optional.
    ///
    /// `detached` prevents the signature from being embedded.
    ///
    /// `allow_extensions` allows new sections to be added to the module later, while retaining the ability for the original module to be verified.
    pub fn sign_multi(
        &self,
        mut module: Module,
        key_id: Option<&Vec<u8>>,
        detached: bool,
        allow_extensions: bool,
    ) -> Result<(Module, Vec<u8>), CoreError> {
        let mut hasher = Hash::new();
        let mut hashes = vec![];

        let mut out_sections = vec![];
        let header_section = Section::Custom(CustomSection::default());
        if !detached {
            if allow_extensions {
                module = module.split(|_| true)?;
            }
            out_sections.push(header_section);
        }
        let mut previous_signature_data = None;
        let mut last_section_was_a_signature = false;
        for (idx, section) in module.sections.iter().enumerate() {
            if let Section::Custom(custom_section) = section {
                if custom_section.is_signature_header() {
                    debug!("A signature section was already present.");
                    if idx != 0 {
                        error!("The signature section was not the first module section");
                        continue;
                    }
                    // SECURITY: Reject modules with multiple signature headers
                    // instead of panicking. A crafted module could have duplicate
                    // signature sections to trigger a DoS via assert panic.
                    if previous_signature_data.is_some() {
                        return Err(CoreError::ParseError);
                    }
                    previous_signature_data = Some(custom_section.signature_data()?);
                    continue;
                }
                if custom_section.is_signature_delimiter() {
                    section.serialize(&mut hasher)?;
                    out_sections.push(section.clone());
                    hashes.push(hasher.finalize().to_vec());
                    last_section_was_a_signature = true;
                    continue;
                }
                last_section_was_a_signature = false;
            }
            section.serialize(&mut hasher)?;
            out_sections.push(section.clone());
        }
        if !last_section_was_a_signature {
            hashes.push(hasher.finalize().to_vec());
        }
        let header_section =
            Self::build_header_section(previous_signature_data, self, key_id, hashes)?;
        if detached {
            Ok((module, header_section.payload().to_vec()))
        } else {
            out_sections[0] = header_section;
            module.sections = out_sections;
            let signature = module.sections[0].payload().to_vec();
            Ok((module, signature))
        }
    }

    fn build_header_section(
        previous_signature_data: Option<SignatureData>,
        sk: &SecretKey,
        key_id: Option<&Vec<u8>>,
        hashes: Vec<Vec<u8>>,
    ) -> Result<Section, CoreError> {
        // SECURITY: Zeroize message buffer on drop to prevent key material leakage
        let mut msg: Zeroizing<Vec<u8>> = Zeroizing::new(vec![]);
        msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
        msg.extend_from_slice(&[
            SIGNATURE_VERSION,
            SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            SIGNATURE_HASH_FUNCTION,
        ]);
        for hash in &hashes {
            msg.extend_from_slice(hash);
        }

        debug!("* Adding signature:\n");

        debug!(
            "sig = Ed25519(sk, \"{}\" ‖ {:02x} ‖ {:02x} ‖ {:02x} ‖ {})\n",
            SIGNATURE_WASM_DOMAIN,
            SIGNATURE_VERSION,
            SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            SIGNATURE_HASH_FUNCTION,
            Hex::encode_to_string(&msg[SIGNATURE_WASM_DOMAIN.len() + 2..]).unwrap_or_else(|_| "<hex error>".to_string())
        );

        let signature = sk.sk.sign(msg.to_vec(), None).to_vec();

        debug!("    = {}\n\n", Hex::encode_to_string(&signature).unwrap_or_else(|_| "<hex error>".to_string()));

        let signature_for_hashes = SignatureForHashes {
            key_id: key_id.cloned(),
            alg_id: ED25519_PK_ID,
            signature,
            certificate_chain: None,
        };
        let mut signed_hashes_set = match &previous_signature_data {
            None => vec![],
            Some(previous_signature_data)
                if previous_signature_data.specification_version == SIGNATURE_VERSION
                    && previous_signature_data.content_type
                        == SIGNATURE_WASM_MODULE_CONTENT_TYPE
                    && previous_signature_data.hash_function == SIGNATURE_HASH_FUNCTION =>
            {
                previous_signature_data.signed_hashes_set.clone()
            }
            _ => return Err(CoreError::IncompatibleSignatureVersion),
        };

        let mut new_hashes = true;
        for previous_signed_hashes_set in &mut signed_hashes_set {
            // SECURITY: Use constant-time comparison for cryptographic data
            if ct_eq_hashes(&previous_signed_hashes_set.hashes, &hashes) {
                if previous_signed_hashes_set.signatures.iter().any(|sig| {
                    // SECURITY: Use constant-time comparison for key_id and signature
                    ct_eq_option(&sig.key_id, &signature_for_hashes.key_id)
                        && ct_eq(&sig.signature, &signature_for_hashes.signature)
                }) {
                    debug!("A matching hash set was already signed with that key.");
                    return Err(CoreError::DuplicateSignature);
                }
                debug!("A matching hash set was already signed.");
                previous_signed_hashes_set
                    .signatures
                    .push(signature_for_hashes.clone());
                new_hashes = false;
                break;
            }
        }
        if new_hashes {
            debug!("No matching hash was previously signed.");
            let signatures = vec![signature_for_hashes];
            let new_signed_section_sequences = SignedHashes { hashes, signatures };
            signed_hashes_set.push(new_signed_section_sequences);
        }
        let signature_data = SignatureData {
            specification_version: SIGNATURE_VERSION,
            content_type: SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            hash_function: SIGNATURE_HASH_FUNCTION,
            signed_hashes_set,
        };
        let header_section = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            signature_data.serialize()?,
        ));
        Ok(header_section)
    }
}

impl PublicKey {
    /// Verify the signature of a module, or module subset.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` allows the caller to verify a module without an embedded signature.
    ///
    /// `predicate` should return `true` for each section that needs to be included in the signature verification.
    pub fn verify_multi<P>(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
        mut predicate: P,
    ) -> Result<(), CoreError>
    where
        P: FnMut(&Section) -> bool,
    {
        let mut sections = Module::iterate(Module::init_from_reader(reader)?)?.enumerate();
        let signature_header_section = if let Some(detached_signature) = &detached_signature {
            Section::Custom(CustomSection::new(
                SIGNATURE_SECTION_HEADER_NAME.to_string(),
                detached_signature.to_vec(),
            ))
        } else {
            sections.next().ok_or(CoreError::ParseError)?.1?
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

        let signature_data = signature_header.signature_data()?;
        if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
            debug!(
                "Unsupported hash function: {:02x}",
                signature_data.hash_function
            );
            return Err(CoreError::ParseError);
        }

        let signed_hashes_set = signature_data.signed_hashes_set;
        let valid_hashes = self.valid_hashes_for_pk(&signed_hashes_set)?;
        if valid_hashes.is_empty() {
            debug!("No valid signatures");
            return Err(CoreError::VerificationFailed);
        }
        debug!("Hashes matching the signature:");
        for valid_hash in &valid_hashes {
            debug!("  - [{}]", Hex::encode_to_string(valid_hash).unwrap_or_else(|_| "<hex error>".to_string()));
        }
        let mut hasher = Hash::new();
        let mut matching_section_ranges = vec![];
        debug!("Computed hashes:");
        let mut section_sequence_must_be_signed: Option<bool> = None;
        for (idx, section) in sections {
            let section = section?;
            section.serialize(&mut hasher)?;
            if section.is_signature_delimiter() {
                if section_sequence_must_be_signed == Some(false) {
                    section_sequence_must_be_signed = None;
                    continue;
                }
                let h = hasher.finalize().to_vec();
                debug!("  - [{}]", Hex::encode_to_string(&h).unwrap_or_else(|_| "<hex error>".to_string()));
                if !valid_hashes.contains(&h) {
                    return Err(CoreError::VerificationFailedForPredicates);
                }
                matching_section_ranges.push(0..=idx);
                section_sequence_must_be_signed = None;
            } else {
                let section_must_be_signed = predicate(&section);
                match section_sequence_must_be_signed {
                    None => section_sequence_must_be_signed = Some(section_must_be_signed),
                    Some(false) if section_must_be_signed => {
                        return Err(CoreError::VerificationFailedForPredicates);
                    }
                    Some(true) if !section_must_be_signed => {
                        return Err(CoreError::VerificationFailedForPredicates);
                    }
                    _ => {}
                }
            }
        }
        // SECURITY: fail closed when no signature delimiter was ever reached.
        //
        // The hash comparison above lives ONLY inside the
        // `is_signature_delimiter()` branch. A module that carries a signature
        // header but NO delimiter section (i.e. one signed without `wsc split`)
        // therefore runs this loop doing predicate bookkeeping only, never
        // compares the running hash against any signed hash, and used to fall
        // through to `Ok(())` — reporting "Signature is valid." for content that
        // was never checked. That is a wrong-accept reachable from
        // `wsc verify --split <rx>`, which routes here instead of the
        // whole-stream `PublicKey::verify`.
        //
        // `matching_section_ranges` is non-empty iff at least one delimiter was
        // processed, i.e. iff the signed hash was actually compared.
        if matching_section_ranges.is_empty() {
            debug!("No signature delimiter found: nothing was verified");
            return Err(CoreError::VerificationFailed);
        }

        debug!("Valid, signed ranges:");
        for range in &matching_section_ranges {
            debug!("  - {}...{}", range.start(), range.end());
        }
        Ok(())
    }

    pub(crate) fn valid_hashes_for_pk<'t>(
        &self,
        signed_hashes_set: &'t [SignedHashes],
    ) -> Result<HashSet<&'t Vec<u8>>, CoreError> {
        let mut valid_hashes = HashSet::new();
        for signed_section_sequence in signed_hashes_set {
            // SECURITY: Zeroize message buffer on drop to prevent data leakage
            let mut msg: Zeroizing<Vec<u8>> = Zeroizing::new(vec![]);
            msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
            msg.extend_from_slice(&[
                SIGNATURE_VERSION,
                SIGNATURE_WASM_MODULE_CONTENT_TYPE,
                SIGNATURE_HASH_FUNCTION,
            ]);
            let hashes = &signed_section_sequence.hashes;
            for hash in hashes {
                msg.extend_from_slice(hash);
            }
            for signature in &signed_section_sequence.signatures {
                match (&signature.key_id, &self.key_id) {
                    (Some(signature_key_id), Some(pk_key_id)) if signature_key_id != pk_key_id => {
                        continue;
                    }
                    _ => {}
                }
                if self
                    .pk
                    .verify(
                        &msg,
                        &ed25519_compact::Signature::from_slice(&signature.signature)?,
                    )
                    .is_err()
                {
                    continue;
                }
                debug!(
                    "Hash signature is valid for key [{}]",
                    Hex::encode_to_string(*self.pk).unwrap_or_else(|_| "<hex error>".to_string())
                );
                for hash in hashes {
                    valid_hashes.insert(hash);
                }
            }
        }
        Ok(valid_hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn serialize_module(module: &Module) -> Vec<u8> {
        let mut buffer = Vec::new();
        module.serialize(&mut buffer).unwrap();
        buffer
    }

    /// A module with a signature header but NO signature delimiter must be
    /// REJECTED by `verify_multi`.
    ///
    /// The hash comparison in `verify_multi` runs ONLY inside the
    /// `is_signature_delimiter()` branch. A module signed without `wsc split`
    /// has no delimiter, so the loop did predicate bookkeeping only, never
    /// compared the running hash against any signed hash, and fell through to
    /// `Ok(())` — reporting "Signature is valid." for content that was never
    /// checked. Reachable from `wsc verify --split <rx>` (src/cli/main.rs:961),
    /// which routes here instead of the whole-stream `PublicKey::verify`.
    #[test]
    fn test_verify_multi_rejects_tampered_module_without_delimiter() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        // No `.split(..)` -> no delimiter sections are inserted.
        let (signed, _) = kp.sk.sign_multi(module, None, false, false).unwrap();

        // Tamper a payload AFTER signing, leaving the signature header intact.
        let mut sections = signed.sections.clone();
        for sec in sections.iter_mut() {
            if matches!(sec, Section::Standard(_)) {
                *sec = Section::Standard(StandardSection::new(SectionId::Type, vec![9, 9, 9]));
                break;
            }
        }
        let tampered = Module {
            header: signed.header,
            sections,
        };

        // A CONSTANT predicate is essential here. `verify_multi`'s predicate
        // bookkeeping rejects when the predicate's verdict CHANGES across a run
        // of non-delimiter sections, so a varying predicate (e.g. "Type only")
        // rejects for that unrelated reason and would make this test vacuous —
        // it would pass even with the missing-delimiter guard removed. With a
        // constant predicate the bookkeeping never fires, so the ONLY thing that
        // can reject is the guard under test.
        let mut reader = Cursor::new(serialize_module(&tampered));
        let result = kp.pk.verify_multi(&mut reader, None, |_section| true);

        assert!(
            result.is_err(),
            "a tampered module with no signature delimiter must be rejected, but \
             verify_multi returned Ok — nothing was ever compared against a signed hash"
        );
    }

    /// Control: a properly split-and-signed module still verifies, so the guard
    /// above cannot pass by rejecting everything.
    #[test]
    fn test_verify_multi_accepts_properly_split_signed_module() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let split = module
            .split(|section| matches!(section.id(), SectionId::Type | SectionId::Code))
            .unwrap();
        let (signed, _) = kp.sk.sign_multi(split, None, false, false).unwrap();

        let mut reader = Cursor::new(serialize_module(&signed));
        let result = kp
            .pk
            .verify_multi(&mut reader, None, |_section| true);

        assert!(
            result.is_ok(),
            "a properly split-and-signed module must still verify: {:?}",
            result.err()
        );
    }
}
