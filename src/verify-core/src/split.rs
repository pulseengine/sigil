use crate::signature::*;
use crate::wasm_module::*;

use log::*;

impl Module {
    /// Print the structure of a module to the standard output, mainly for debugging purposes.
    ///
    /// Set `verbose` to `true` in order to also print details about signature data.
    pub fn show(&self, verbose: bool) -> Result<(), CoreError> {
        for (idx, section) in self.sections.iter().enumerate() {
            println!("{}:\t{}", idx, section.display(verbose));
        }
        Ok(())
    }

    /// Prepare a module for partial verification.
    ///
    /// The predicate should return `true` if a section is part of a set that can be verified,
    /// and `false` if the section can be ignored during verification.
    ///
    /// It is highly recommended to always include the standard sections in the signed set.
    pub fn split<P>(self, mut predicate: P) -> Result<Module, CoreError>
    where
        P: FnMut(&Section) -> bool,
    {
        let mut out_sections = vec![];
        let mut flip = false;
        let mut last_was_delimiter = false;
        for (idx, section) in self.sections.into_iter().enumerate() {
            if section.is_signature_header() {
                info!("Module is already signed");
                out_sections.push(section);
                continue;
            }
            if section.is_signature_delimiter() {
                out_sections.push(section);
                last_was_delimiter = true;
                continue;
            }
            let section_can_be_signed = predicate(&section);
            if idx == 0 {
                flip = !section_can_be_signed;
            } else if section_can_be_signed == flip {
                if !last_was_delimiter {
                    let delimiter = new_delimiter_section()?;
                    out_sections.push(delimiter);
                }
                flip = !flip;
            }
            out_sections.push(section);
            last_was_delimiter = false;
        }
        if let Some(last_section) = out_sections.last()
            && !last_section.is_signature_delimiter()
        {
            let delimiter = new_delimiter_section()?;
            out_sections.push(delimiter);
        }
        Ok(Module {
            header: self.header,
            sections: out_sections,
        })
    }

    /// Detach the signature from a signed module.
    ///
    /// This function returns the module without the embedded signature,
    /// as well as the detached signature as a byte string.
    pub fn detach_signature(mut self) -> Result<(Module, Vec<u8>), CoreError> {
        let mut out_sections = vec![];
        let mut sections = self.sections.into_iter();
        let detached_signature = match sections.next() {
            None => return Err(CoreError::NoSignatures),
            Some(section) => {
                if !section.is_signature_header() {
                    return Err(CoreError::NoSignatures);
                }
                section.payload().to_vec()
            }
        };
        for section in sections {
            out_sections.push(section);
        }
        self.sections = out_sections;
        debug!("Signature detached");
        Ok((self, detached_signature))
    }

    /// Embed a detached signature into a module.
    /// This function returns the module with embedded signature.
    pub fn attach_signature(mut self, detached_signature: &[u8]) -> Result<Module, CoreError> {
        let mut out_sections = vec![];
        let sections = self.sections.into_iter();
        let signature_header = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            detached_signature.to_vec(),
        ));
        out_sections.push(signature_header);
        for section in sections {
            if section.is_signature_header() {
                return Err(CoreError::SignatureAlreadyAttached);
            }
            out_sections.push(section);
        }
        self.sections = out_sections;
        debug!("Signature attached");
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoreError, KeyPair, PublicKeySet};
    use std::collections::HashSet;
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

    #[test]
    fn test_detach_signature_no_signatures() {
        let module = create_test_module();
        let result = module.detach_signature();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoreError::NoSignatures));
    }

    #[test]
    fn test_detach_signature_with_signature() {
        let signature_data = vec![1, 2, 3, 4, 5];
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Custom(CustomSection::new(
                    SIGNATURE_SECTION_HEADER_NAME.to_string(),
                    signature_data.clone(),
                )),
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![4, 5, 6])),
            ],
        };

        let result = module.detach_signature();
        assert!(result.is_ok());
        let (new_module, detached_sig) = result.unwrap();
        assert_eq!(detached_sig, signature_data);
        assert_eq!(new_module.sections.len(), 2);
        assert!(!new_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_attach_signature() {
        let module = create_test_module();
        let signature_data = vec![10, 20, 30];

        let result = module.attach_signature(&signature_data);
        assert!(result.is_ok());
        let signed_module = result.unwrap();

        // First section should be the signature
        assert_eq!(signed_module.sections.len(), 4);
        assert!(signed_module.sections[0].is_signature_header());
        assert_eq!(signed_module.sections[0].payload(), &signature_data);
    }

    #[test]
    fn test_attach_signature_already_signed() {
        let signature_data = vec![1, 2, 3];
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Custom(CustomSection::new(
                    SIGNATURE_SECTION_HEADER_NAME.to_string(),
                    signature_data.clone(),
                )),
                Section::Standard(StandardSection::new(SectionId::Code, vec![4, 5, 6])),
            ],
        };

        let new_signature = vec![7, 8, 9];
        let result = module.attach_signature(&new_signature);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CoreError::SignatureAlreadyAttached
        ));
    }

    #[test]
    fn test_split_all_sections() {
        let module = create_test_module();

        // Predicate that includes all sections
        let result = module.split(|_| true);
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Should have original sections plus a delimiter at the end
        assert!(split_module.sections.len() >= 3);
        assert!(
            split_module
                .sections
                .last()
                .unwrap()
                .is_signature_delimiter()
        );
    }

    #[test]
    fn test_split_no_sections() {
        let module = create_test_module();

        // Predicate that includes no sections
        let result = module.split(|_| false);
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Should have delimiters inserted
        assert!(split_module.sections.len() > 3);
    }

    #[test]
    fn test_split_with_existing_signature() {
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Custom(CustomSection::new(
                    SIGNATURE_SECTION_HEADER_NAME.to_string(),
                    vec![1, 2, 3],
                )),
                Section::Standard(StandardSection::new(SectionId::Type, vec![4, 5, 6])),
            ],
        };

        let result = module.split(|_| true);
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Signature header should be preserved
        assert!(split_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_split_selective() {
        let module = create_test_module();

        // Only include Type sections
        let result = module.split(|section| matches!(section.id(), SectionId::Type));
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Should have delimiters between different section types
        let has_delimiter = split_module
            .sections
            .iter()
            .any(|s| s.is_signature_delimiter());
        assert!(has_delimiter);
    }

    #[test]
    fn test_show_non_verbose() {
        let module = create_test_module();
        // Just verify it doesn't crash
        let result = module.show(false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_verbose() {
        let module = create_test_module();
        // Just verify it doesn't crash
        let result = module.show(true);
        assert!(result.is_ok());
    }

    // ====================================================================
    // Mythos discovery PoCs (UNCOMMITTED) — split.rs delimiter trust
    // ====================================================================

    fn ser(module: &Module) -> Vec<u8> {
        let mut buffer = Vec::new();
        module.serialize(&mut buffer).unwrap();
        buffer
    }

    /// The predicate `wsc verify --split <rx>` installs (src/cli/main.rs:974).
    /// Standard sections always "must be signed"; custom sections match the rx.
    /// Delimiters never reach the predicate — `verify_multi` tests
    /// `is_signature_delimiter()` first.
    fn cli_predicate(section: &Section) -> bool {
        match section {
            Section::Standard(_) => true,
            Section::Custom(_) => false,
        }
    }

    fn truncate_to(module: &Module, n: usize) -> Module {
        Module {
            header: module.header,
            sections: module.sections[..n].to_vec(),
        }
    }

    /// FINDING 1 — a module signed through `Module::split` can be TRUNCATED at
    /// any delimiter and still verifies.
    ///
    /// `split` emits a delimiter at every predicate flip plus one at the end;
    /// `sign_multi` pushes the *cumulative* hash at every delimiter without
    /// ever resetting the hasher, so the signature authorises every prefix.
    /// `verify_multi` accepts as soon as one delimiter's running hash is in
    /// `valid_hashes` and never checks that the stream ended where the signer
    /// stopped. Signed sections can therefore be DELETED post-signing.
    #[test]
    fn poc_split_signed_module_accepts_truncation_at_a_delimiter() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        // Exactly what `wsc split --split <rx>` does (src/cli/main.rs:757).
        let split = module
            .split(|s| matches!(s.id(), SectionId::Type | SectionId::Code))
            .unwrap();
        let (signed, _) = kp.sk.sign_multi(split, None, false, false).unwrap();

        // [sighdr, Type, D1, Function, D2, Code, D3]
        assert!(signed.sections[0].is_signature_header());
        assert!(signed.sections[2].is_signature_delimiter());
        assert_eq!(signed.sections.len(), 7);

        // CONTROL A: the full signed module verifies.
        let full = kp
            .pk
            .verify_multi(&mut Cursor::new(ser(&signed)), None, cli_predicate);
        assert!(full.is_ok(), "control A: full module must verify: {:?}", full.err());

        // CONTROL B: cut at a NON-delimiter boundary ([sighdr, Type]) is
        // rejected. This proves the delimiter is the load-bearing structure
        // and that the test below is not just generic leniency.
        let cut_mid = truncate_to(&signed, 2);
        let mid = kp
            .pk
            .verify_multi(&mut Cursor::new(ser(&cut_mid)), None, cli_predicate);
        assert!(mid.is_err(), "control B: cut at a non-delimiter must be rejected");

        // CONTROL C: cut at D1 *and* tamper the surviving Type payload — must
        // be rejected. This proves the H1 comparison really executes, so an Ok
        // below cannot come from a skipped check.
        let mut tampered = truncate_to(&signed, 3);
        tampered.sections[1] =
            Section::Standard(StandardSection::new(SectionId::Type, vec![9, 9, 9]));
        let tam = kp
            .pk
            .verify_multi(&mut Cursor::new(ser(&tampered)), None, cli_predicate);
        assert!(tam.is_err(), "control C: tampered prefix must be rejected");

        // THE BUG: cut at D1. Function and Code — both signed, both
        // predicate-"must be signed" — are gone, yet verification succeeds.
        let cut_at_delim = truncate_to(&signed, 3);
        let res = kp
            .pk
            .verify_multi(&mut Cursor::new(ser(&cut_at_delim)), None, cli_predicate);
        assert!(
            res.is_err(),
            "WRONG-ACCEPT: signed Function+Code sections were deleted and \
             verify_multi still returned Ok — the signature authorises every \
             delimiter prefix and nothing checks the stream ended where the \
             signer stopped"
        );
    }

    /// FINDING 2 — `Module::split` preserves MODULE-SUPPLIED
    /// `signature_delimiter` sections verbatim (split.rs:36-40), so an attacker
    /// who controls the pre-signing input picks where the cut of FINDING 1 will
    /// land, even under `allow_extensions` / `split(|_| true)`, which on benign
    /// input emits exactly ONE delimiter (at the end) and is therefore NOT
    /// truncatable.
    #[test]
    fn poc_split_preserves_attacker_planted_delimiter() {
        let kp = KeyPair::generate();

        // --- CONTROL: benign input, same signing recipe -------------------
        let benign = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let (benign_signed, _) = kp
            .sk
            .sign_multi(benign, None, false, /* allow_extensions */ true)
            .unwrap();
        // [sighdr, Type, Function, Code, D] -> exactly one delimiter.
        assert_eq!(
            benign_signed
                .sections
                .iter()
                .filter(|s| s.is_signature_delimiter())
                .count(),
            1,
            "control: benign input yields a single, trailing delimiter"
        );
        assert!(
            kp.pk
                .verify_multi(&mut Cursor::new(ser(&benign_signed)), None, cli_predicate)
                .is_ok(),
            "control: benign signed module must verify"
        );
        // ...and the matching truncation is rejected, because there is no
        // delimiter to cut at.
        let benign_cut = truncate_to(&benign_signed, 2);
        assert!(
            kp.pk
                .verify_multi(&mut Cursor::new(ser(&benign_cut)), None, cli_predicate)
                .is_err(),
            "control: with no planted delimiter the truncation must be rejected"
        );

        // --- HOSTILE: same recipe, input carries a planted delimiter ------
        let hostile = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                // Attacker-planted: any custom section named
                // "signature_delimiter" with any payload.
                Section::Custom(CustomSection::new(
                    SIGNATURE_SECTION_DELIMITER_NAME.to_string(),
                    vec![0xde, 0xad, 0xbe, 0xef],
                )),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let (hostile_signed, _) = kp
            .sk
            .sign_multi(hostile, None, false, /* allow_extensions */ true)
            .unwrap();
        // `split` kept the planted delimiter, so there are now TWO cut points.
        assert_eq!(
            hostile_signed
                .sections
                .iter()
                .filter(|s| s.is_signature_delimiter())
                .count(),
            2,
            "split must not have silently dropped the planted delimiter"
        );
        assert!(
            kp.pk
                .verify_multi(&mut Cursor::new(ser(&hostile_signed)), None, cli_predicate)
                .is_ok(),
            "the hostile module is a fully valid signed module"
        );

        // Cut at the PLANTED delimiter: Function and Code are deleted.
        let stripped = truncate_to(&hostile_signed, 3);
        assert!(stripped.sections[2].is_signature_delimiter());
        let res = kp
            .pk
            .verify_multi(&mut Cursor::new(ser(&stripped)), None, cli_predicate);
        assert!(
            res.is_err(),
            "WRONG-ACCEPT: a delimiter planted in the UNSIGNED input survived \
             Module::split, so the signer authorised a cut point of the \
             attacker's choosing; Function+Code were stripped post-signing and \
             verify_multi returned Ok"
        );
    }

    /// FINDING 3 (secondary) — sections APPENDED after the last delimiter are
    /// never hash-compared, yet `verify_multi` returns Ok even when the
    /// verifier's predicate says they must be signed.
    #[test]
    fn poc_sections_appended_after_last_delimiter_are_unverified() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let split = module.split(|_| true).unwrap();
        let (signed, _) = kp.sk.sign_multi(split, None, false, false).unwrap();

        // CONTROL: unmodified module verifies.
        assert!(
            kp.pk
                .verify_multi(&mut Cursor::new(ser(&signed)), None, cli_predicate)
                .is_ok(),
            "control: signed module must verify"
        );

        // Append a Data section after the trailing delimiter. It is a Standard
        // section, so `cli_predicate` reports "must be signed".
        let mut sections = signed.sections.clone();
        sections.push(Section::Standard(StandardSection::new(
            SectionId::Data,
            vec![0x41, 0x41, 0x41, 0x41],
        )));
        let extended = Module {
            header: signed.header,
            sections,
        };
        let res = kp
            .pk
            .verify_multi(&mut Cursor::new(ser(&extended)), None, cli_predicate);
        assert!(
            res.is_err(),
            "WRONG-ACCEPT: an unsigned Data section appended after the last \
             delimiter was reported as must-be-signed by the predicate, was \
             never compared against any signed hash, and verify_multi still \
             returned Ok"
        );
    }

    /// Helper: run `verify_matrix` with one pk and the CLI predicate, and
    /// report whether the key came back as valid for predicate 0.
    fn matrix_says_valid(kp: &KeyPair, bytes: &[u8]) -> Result<bool, CoreError> {
        let pks = PublicKeySet::new(HashSet::from([kp.pk.clone()]));
        let res = pks.verify_matrix(&mut Cursor::new(bytes), None, &[cli_predicate])?;
        Ok(!res.is_empty() && res[0].contains(&kp.pk))
    }

    /// FINDING 1b — the SAME truncation also wrong-accepts in `verify_matrix`.
    ///
    /// Commit a63ff86 had to patch verify_multi AND verify_matrix; the
    /// truncation gap is likewise present in both. matrix.rs:113 only PRUNES a
    /// key when a delimiter hash is absent — `H1` is present, so the key
    /// survives, `compared_against_a_signed_hash` is true, and the key is
    /// reported valid for a module whose signed tail was deleted.
    #[test]
    fn poc_verify_matrix_accepts_truncation_at_a_delimiter() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let split = module
            .split(|s| matches!(s.id(), SectionId::Type | SectionId::Code))
            .unwrap();
        let (signed, _) = kp.sk.sign_multi(split, None, false, false).unwrap();

        // CONTROL A: full module -> key reported valid.
        assert_eq!(
            matrix_says_valid(&kp, &ser(&signed)).ok(),
            Some(true),
            "control A: verify_matrix must report the key valid for the full module"
        );

        // CONTROL B: cut at a NON-delimiter boundary -> rejected.
        let cut_mid = truncate_to(&signed, 2);
        assert_ne!(
            matrix_says_valid(&kp, &ser(&cut_mid)).ok(),
            Some(true),
            "control B: cut at a non-delimiter must not report the key valid"
        );

        // CONTROL C: cut at D1 with the surviving prefix tampered -> rejected.
        let mut tampered = truncate_to(&signed, 3);
        tampered.sections[1] =
            Section::Standard(StandardSection::new(SectionId::Type, vec![9, 9, 9]));
        assert_ne!(
            matrix_says_valid(&kp, &ser(&tampered)).ok(),
            Some(true),
            "control C: tampered prefix must not report the key valid"
        );

        // THE BUG.
        let cut_at_delim = truncate_to(&signed, 3);
        assert_ne!(
            matrix_says_valid(&kp, &ser(&cut_at_delim)).ok(),
            Some(true),
            "WRONG-ACCEPT in verify_matrix: signed Function+Code were deleted \
             and the key is still reported valid -- `wsc verify-matrix` prints \
             \"Valid public keys: ...\" and exits 0"
        );
    }

    /// FINDING 3b — sections appended after the last delimiter are likewise
    /// never finalized in `verify_matrix`:
    /// `section_sequence_must_be_signed_for_pks[pk]` is left at `Some(true)`
    /// and nothing after the loop converts that into a failure.
    #[test]
    fn poc_verify_matrix_accepts_sections_appended_after_last_delimiter() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };
        let split = module.split(|_| true).unwrap();
        let (signed, _) = kp.sk.sign_multi(split, None, false, false).unwrap();

        // CONTROL: unmodified module -> key valid.
        assert_eq!(
            matrix_says_valid(&kp, &ser(&signed)).ok(),
            Some(true),
            "control: verify_matrix must report the key valid for the signed module"
        );

        let mut sections = signed.sections.clone();
        sections.push(Section::Standard(StandardSection::new(
            SectionId::Data,
            vec![0x41, 0x41, 0x41, 0x41],
        )));
        let extended = Module { header: signed.header, sections };
        assert_ne!(
            matrix_says_valid(&kp, &ser(&extended)).ok(),
            Some(true),
            "WRONG-ACCEPT in verify_matrix: an unsigned, predicate-must-be-signed \
             Data section was appended after the last delimiter and the key is \
             still reported valid"
        );
    }

    #[test]
    fn test_detach_attach_roundtrip() {
        let signature_data = vec![42, 43, 44];
        let original_module = create_test_module();

        // Attach a signature
        let signed_module = original_module.attach_signature(&signature_data).unwrap();

        // Detach it
        let (unsigned_module, detached_sig) = signed_module.detach_signature().unwrap();

        // Verify the signature matches
        assert_eq!(detached_sig, signature_data);

        // Verify we're back to original structure (same number of sections)
        assert_eq!(unsigned_module.sections.len(), 3);
    }
}
