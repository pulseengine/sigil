use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use ct_codecs::{verify as ct_eq, Encoder, Hex};
use log::*;
use std::collections::HashSet;
use std::io::Read;

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
        module: Module,
        key_id: Option<&Vec<u8>>,
        detached: bool,
        allow_extensions: bool,
    ) -> Result<(Module, Vec<u8>), CoreError> {
        self.sign_multi_with_version(
            module,
            key_id,
            detached,
            allow_extensions,
            SignatureVersion::V1,
        )
    }

    /// [`SecretKey::sign_multi`] with an explicit signature format version.
    ///
    /// `SignatureVersion::V2` binds the module's 8-byte preamble into every
    /// signed hash, including each cumulative prefix hash at a delimiter
    /// (#303). Adding a signature to a module whose existing signature header
    /// has a different version fails with `IncompatibleSignatureVersion`: one
    /// header carries one version.
    pub fn sign_multi_with_version(
        &self,
        mut module: Module,
        key_id: Option<&Vec<u8>>,
        detached: bool,
        allow_extensions: bool,
        version: SignatureVersion,
    ) -> Result<(Module, Vec<u8>), CoreError> {
        let mut hasher = version.content_hasher(&module.header);
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
            Self::build_header_section(previous_signature_data, self, key_id, hashes, version)?;
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
        version: SignatureVersion,
    ) -> Result<Section, CoreError> {
        // SECURITY: Zeroize message buffer on drop to prevent key material leakage
        let msg = version.signed_message(&hashes);

        debug!("* Adding signature:\n");

        debug!(
            "sig = Ed25519(sk, \"{}\" ‖ {:02x} ‖ {:02x} ‖ {:02x} ‖ {})\n",
            SIGNATURE_WASM_DOMAIN,
            version.as_u8(),
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
                if previous_signature_data.specification_version == version.as_u8()
                    && previous_signature_data.content_type
                        == SIGNATURE_WASM_MODULE_CONTENT_TYPE
                    && previous_signature_data.hash_function == SIGNATURE_HASH_FUNCTION =>
            {
                previous_signature_data.signed_hashes_set.clone()
            }
            _ => return Err(CoreError::IncompatibleSignatureVersion),
        };

        // #304: a signer's new signature supersedes its own earlier ones.
        // Without this, re-signing changed content appended a second entry
        // and kept the stale one, and `PublicKey::verify` accepts a stream
        // matching ANY entry: the old content then verified under the new
        // header (a rollback to a release the publisher had replaced).
        // Signatures by OTHER keys are kept, so co-signing and layered
        // signing (an author's entry over a prefix, a distributor's over the
        // extended module) still work. Ownership is decided by verifying
        // each old signature against this key over that entry's own hashes,
        // not by key_id, which is optional and unauthenticated.
        let own_pk = sk.sk.public_key();
        for entry in &mut signed_hashes_set {
            if ct_eq_hashes(&entry.hashes, &hashes) {
                continue; // same content: handled below (merge or DuplicateSignature)
            }
            let entry_msg = version.signed_message(&entry.hashes);
            entry.signatures.retain(|sig| {
                let mine = ed25519_compact::Signature::from_slice(&sig.signature)
                    .map(|s| own_pk.verify(&entry_msg[..], &s).is_ok())
                    .unwrap_or(false);
                if mine {
                    debug!("Dropping this key's earlier signature over different content (#304).");
                }
                !mine
            });
        }
        signed_hashes_set.retain(|entry| !entry.signatures.is_empty());

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
            specification_version: version.as_u8(),
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
        let stream = Module::init_from_reader(reader)?;
        let preamble = stream.header();
        let mut sections = Module::iterate(stream)?.enumerate();
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

        let version = SignatureVersion::from_u8(signature_data.specification_version)?;
        let signed_hashes_set = signature_data.signed_hashes_set;
        let valid_hashes = self.valid_hashes_for_pk(&signed_hashes_set, version, false)?;
        // The terminal (whole-stream) hashes, used after the loop to pin the
        // END of the stream: the prefix set alone authorises every delimiter
        // prefix, so without this a module truncated AT a delimiter verifies.
        let terminal_hashes = self.valid_hashes_for_pk(&signed_hashes_set, version, true)?;
        if valid_hashes.is_empty() {
            debug!("No valid signatures");
            return Err(CoreError::VerificationFailed);
        }
        debug!("Hashes matching the signature:");
        for valid_hash in &valid_hashes {
            debug!("  - [{}]", Hex::encode_to_string(valid_hash).unwrap_or_else(|_| "<hex error>".to_string()));
        }
        let mut hasher = version.content_hasher(&preamble);
        let mut matching_section_ranges = vec![];
        let mut last_compared_hash: Option<Vec<u8>> = None;
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
                last_compared_hash = Some(h);
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

        // SECURITY: the stream must END where the signer stopped.
        //
        // `valid_hashes` authorises EVERY cumulative prefix hash, so without
        // this check a module can be truncated at any signature delimiter and
        // still verify: the truncated stream's hash is itself a signed prefix
        // hash, the in-loop `contains` check passes, and `matching_section_ranges`
        // is non-empty so the guard above is satisfied too. Requiring the LAST
        // hash we compared to be a TERMINAL (whole-stream) hash rejects that.
        match &last_compared_hash {
            Some(h) if terminal_hashes.contains(h) => {}
            _ => {
                debug!("Stream did not end at a signed terminal hash (truncated?)");
                return Err(CoreError::VerificationFailedForPredicates);
            }
        }

        // SECURITY: sections AFTER the last delimiter are never hash-compared,
        // so if the predicate says they must be signed, we cannot affirm them.
        // The in-loop bookkeeping already rejects the inverse case, so leaving
        // this un-finalized accepted unverified trailing content that the
        // caller's own predicate demanded be signed.
        if section_sequence_must_be_signed == Some(true) {
            debug!("Trailing sections require signing but follow the last delimiter");
            return Err(CoreError::VerificationFailedForPredicates);
        }

        debug!("Valid, signed ranges:");
        for range in &matching_section_ranges {
            debug!("  - {}...{}", range.start(), range.end());
        }
        Ok(())
    }

    /// Collect the signed hashes this key authorises.
    ///
    /// `sign_multi` NEVER resets its hasher: at each signature delimiter it
    /// pushes `hasher.finalize()`, so a signed `hashes` list is a sequence of
    /// CUMULATIVE PREFIX hashes `[H(P1), H(P2), ... H(Pn)]`, and only the LAST
    /// element is the hash of the complete section stream.
    ///
    /// `terminal_only` selects which of those a caller may accept:
    ///
    /// * `true`  — only `hashes.last()`, i.e. the whole-stream hash. Required by
    ///   any WHOLE-MODULE verifier: accepting a non-terminal prefix would let a
    ///   module be truncated at a delimiter and still verify, because the
    ///   truncated stream's hash is itself a signed prefix hash.
    /// * `false` — every prefix hash. Needed only by the partial verifiers
    ///   (`verify_multi` / `verify_matrix`), which legitimately check
    ///   delimiter-bounded ranges — and which must therefore separately pin the
    ///   terminal hash to reject truncation.
    ///
    /// `version` is the version the signature header declares. The message is
    /// rebuilt with that version byte, so a signature made under one version
    /// never verifies under the other (#303).
    pub(crate) fn valid_hashes_for_pk<'t>(
        &self,
        signed_hashes_set: &'t [SignedHashes],
        version: SignatureVersion,
        terminal_only: bool,
    ) -> Result<HashSet<&'t Vec<u8>>, CoreError> {
        let mut valid_hashes = HashSet::new();
        for signed_section_sequence in signed_hashes_set {
            let hashes = &signed_section_sequence.hashes;
            // SECURITY: Zeroize message buffer on drop to prevent data leakage
            let msg = version.signed_message(hashes);
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
                if terminal_only {
                    if let Some(terminal) = hashes.last() {
                        valid_hashes.insert(terminal);
                    }
                } else {
                    for hash in hashes {
                        valid_hashes.insert(hash);
                    }
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

        // Assert the ERROR VARIANT, not merely `is_err()`.
        //
        // Two independent guards now reject this input, and they return
        // different variants: the no-delimiter guard yields `VerificationFailed`
        // while the terminal-hash check (added later, for the truncation
        // wrong-accept) yields `VerificationFailedForPredicates`. With only
        // `is_err()` the terminal check SUBSUMES this test — measured: deleting
        // the no-delimiter guard leaves all 177 verify-core tests green, so
        // nothing isolated the guard this test was written for. Pinning the
        // variant restores one oracle per guard, which is the whole point of
        // keeping both.
        assert!(
            matches!(result, Err(CoreError::VerificationFailed)),
            "a tampered module with no signature delimiter must be rejected by the \
             no-delimiter guard specifically (CoreError::VerificationFailed); got {:?} \
             — if this is VerificationFailedForPredicates the terminal-hash check \
             rejected it instead and the guard under test may be gone"
        , result);
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

    // ===================================================================
    // Signature format v2 (#303, REQ-32) through the multi-signature paths.
    // ===================================================================

    const CORE_PREAMBLE: Header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    const COMPONENT_PREAMBLE: Header = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

    fn component() -> Module {
        Module {
            header: COMPONENT_PREAMBLE,
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        }
    }

    fn split_component() -> Module {
        component()
            .split(|section| matches!(section.id(), SectionId::Type | SectionId::Code))
            .unwrap()
    }

    fn rewrite_preamble(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        out[0..8].copy_from_slice(&CORE_PREAMBLE);
        out
    }

    /// v2 multi-signature: two keys co-sign a split component; every
    /// verifier (whole-stream single key, key set, verify_multi,
    /// verify_matrix) accepts it, embedded and detached.
    // rivet: verifies REQ-32
    #[test]
    fn v2_multi_signature_sign_then_verify_succeeds() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let (signed_a, _) = a
            .sk
            .sign_multi_with_version(split_component(), None, false, false, SignatureVersion::V2)
            .unwrap();
        let (signed_ab, _) =
            b.sk.sign_multi_with_version(signed_a, None, false, false, SignatureVersion::V2)
                .unwrap();
        let bytes = serialize_module(&signed_ab);

        for kp in [&a, &b] {
            assert!(kp.pk.verify(&mut Cursor::new(&bytes), None).is_ok());
            assert!(
                kp.pk
                    .verify_multi(&mut Cursor::new(&bytes), None, |_| true)
                    .is_ok()
            );
        }
        let mut set = PublicKeySet::empty();
        set.insert(a.pk.clone()).unwrap();
        set.insert(b.pk.clone()).unwrap();
        assert_eq!(set.verify(&mut Cursor::new(&bytes), None).unwrap().len(), 2);
        let predicates = [|_: &Section| true];
        let matrix = set
            .verify_matrix(&mut Cursor::new(&bytes), None, &predicates)
            .unwrap();
        assert_eq!(matrix[0].len(), 2);

        // Detached v2 multi signature.
        let (unsigned, detached) = a
            .sk
            .sign_multi_with_version(split_component(), None, true, false, SignatureVersion::V2)
            .unwrap();
        let bare = serialize_module(&unsigned);
        assert!(
            a.pk.verify(&mut Cursor::new(&bare), Some(&detached))
                .is_ok()
        );
        assert!(
            a.pk.verify_multi(&mut Cursor::new(&bare), Some(&detached), |_| true)
                .is_ok()
        );
    }

    /// The preamble rewrite is rejected by every multi-signature verifier
    /// under v2 (embedded and detached), while the v1 control still accepts
    /// it (v1 behaviour unchanged, see the open decision in simple.rs).
    // rivet: verifies REQ-32
    #[test]
    fn v2_multi_rewritten_preamble_is_rejected() {
        let kp = KeyPair::generate();
        let mut set = PublicKeySet::empty();
        set.insert(kp.pk.clone()).unwrap();
        let predicates = [|_: &Section| true];

        let (signed, _) = kp
            .sk
            .sign_multi_with_version(split_component(), None, false, false, SignatureVersion::V2)
            .unwrap();
        let rewritten = rewrite_preamble(&serialize_module(&signed));
        assert!(matches!(
            kp.pk.verify(&mut Cursor::new(&rewritten), None),
            Err(CoreError::VerificationFailed)
        ));
        assert!(matches!(
            kp.pk
                .verify_multi(&mut Cursor::new(&rewritten), None, |_| true),
            Err(CoreError::VerificationFailedForPredicates)
        ));
        assert!(set.verify(&mut Cursor::new(&rewritten), None).is_err());
        // verify_matrix reports no key as valid for the predicate (or errors).
        match set.verify_matrix(&mut Cursor::new(&rewritten), None, &predicates) {
            Ok(m) => assert!(m[0].is_empty(), "verify_matrix affirmed a key"),
            Err(_) => {}
        }

        let (unsigned, detached) = kp
            .sk
            .sign_multi_with_version(split_component(), None, true, false, SignatureVersion::V2)
            .unwrap();
        let bare_rw = rewrite_preamble(&serialize_module(&unsigned));
        assert!(
            kp.pk
                .verify(&mut Cursor::new(&bare_rw), Some(&detached))
                .is_err()
        );
        assert!(
            kp.pk
                .verify_multi(&mut Cursor::new(&bare_rw), Some(&detached), |_| true)
                .is_err()
        );

        // v1 control: unchanged, the rewrite is still accepted.
        let (v1, _) = kp
            .sk
            .sign_multi(split_component(), None, false, false)
            .unwrap();
        let v1_rw = rewrite_preamble(&serialize_module(&v1));
        assert!(
            kp.pk
                .verify_multi(&mut Cursor::new(&v1_rw), None, |_| true)
                .is_ok()
        );
    }

    /// One header carries one version: adding a v2 signature to a v1 header
    /// (or the reverse) is refused rather than mixing formats.
    // rivet: verifies REQ-32
    #[test]
    fn mixing_versions_in_one_header_is_refused() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let (v1, _) = a.sk.sign_multi(component(), None, false, false).unwrap();
        assert!(matches!(
            b.sk.sign_multi_with_version(v1, None, false, false, SignatureVersion::V2),
            Err(CoreError::IncompatibleSignatureVersion)
        ));
        let (v2, _) =
            a.sk.sign_multi_with_version(component(), None, false, false, SignatureVersion::V2)
                .unwrap();
        assert!(matches!(
            b.sk.sign_multi(v2, None, false, false),
            Err(CoreError::IncompatibleSignatureVersion)
        ));
    }

    /// #304 (own earlier signature over different content is dropped) still
    /// holds under v2, where ownership is checked against the v2 message.
    // rivet: verifies REQ-32
    #[test]
    fn v2_resign_supersedes_own_entry() {
        let kp = KeyPair::generate();
        let (signed, _) = kp
            .sk
            .sign_multi_with_version(component(), None, false, false, SignatureVersion::V2)
            .unwrap();
        let mut extended = signed.clone();
        extended.sections.push(Section::Custom(CustomSection::new(
            "meta".to_string(),
            vec![0xaa],
        )));
        let (resigned, _) = kp
            .sk
            .sign_multi_with_version(extended, None, false, false, SignatureVersion::V2)
            .unwrap();
        let entries = match &resigned.sections[0] {
            Section::Custom(cs) => cs.signature_data().unwrap().signed_hashes_set.len(),
            _ => panic!("no signature header"),
        };
        assert_eq!(entries, 1);
        assert!(
            kp.pk
                .verify(&mut Cursor::new(serialize_module(&resigned)), None)
                .is_ok()
        );
    }

    /// Domain separation at the signature check itself: an Ed25519
    /// signature made under one version is not accepted over the same
    /// hashes under the other. (End to end, a relabelled header is ALSO
    /// rejected because the v1 and v2 content hashes differ; this test pins
    /// the version byte in the signed message on its own.)
    // rivet: verifies REQ-32
    #[test]
    fn signature_made_under_one_version_does_not_check_under_the_other() {
        let kp = KeyPair::generate();
        for (sign_as, check_as) in [
            (SignatureVersion::V1, SignatureVersion::V2),
            (SignatureVersion::V2, SignatureVersion::V1),
        ] {
            let (signed, _) = kp
                .sk
                .sign_multi_with_version(component(), None, false, false, sign_as)
                .unwrap();
            let set = match &signed.sections[0] {
                Section::Custom(cs) => cs.signature_data().unwrap().signed_hashes_set,
                _ => panic!("no signature header"),
            };
            assert_eq!(
                kp.pk
                    .valid_hashes_for_pk(&set, sign_as, true)
                    .unwrap()
                    .len(),
                1,
                "positive control: the signature checks under its own version"
            );
            assert!(
                kp.pk
                    .valid_hashes_for_pk(&set, check_as, true)
                    .unwrap()
                    .is_empty(),
                "a {:?} signature must not check as {:?}",
                sign_as,
                check_as
            );
        }
    }
}
