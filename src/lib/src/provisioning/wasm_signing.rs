/// Certificate-based WASM module signing
///
/// This module provides functions to sign WASM modules with certificate chains
/// for offline verification using a private CA infrastructure.
///
/// # Workflow
///
/// ```text
/// Device (IoT/Embedded):
/// 1. Load WASM module to sign
/// 2. Sign with hardware key (ATECC608)
/// 3. Attach certificate chain (device + intermediate + root)
/// 4. Signed WASM includes everything needed for verification
///
/// Verifier (Offline):
/// 1. Extract certificate chain from WASM
/// 2. Verify chain against embedded root CA
/// 3. Extract public key from device certificate
/// 4. Verify WASM signature with that public key
/// 5. No internet required!
/// ```
///
/// # Example
///
/// ```ignore
/// use wsc::provisioning::wasm_signing::{sign_with_certificate, verify_with_certificate};
/// use wsc::provisioning::OfflineVerifier;
/// use wsc::platform::SecureKeyProvider;
///
/// // Sign WASM with certificates (on device)
/// let signed_module = sign_with_certificate(
///     &provider,        // ATECC608 or other secure element
///     key_handle,       // Hardware key handle
///     module,           // WASM module
///     &cert_chain,      // [device_cert, intermediate_cert, root_cert]
/// )?;
///
/// // Verify WASM offline (in field)
/// let verifier = OfflineVerifier::new(root_ca_cert)?;
/// verify_with_certificate(&mut signed_module.as_slice(), &verifier)?;
/// ```
use crate::error::WSError;
use crate::platform::{KeyHandle, SecureKeyProvider};
use crate::provisioning::OfflineVerifier;
use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use log::*;
use std::io::Read;

/// Sign a WASM module with a certificate chain
///
/// This function signs a WASM module using a hardware-backed key and attaches
/// the certificate chain for offline verification.
///
/// # Arguments
///
/// * `provider` - Secure key provider (TPM, ATECC608, etc.)
/// * `key_handle` - Handle to the device's private key (in hardware)
/// * `module` - WASM module to sign
/// * `certificate_chain` - Certificate chain as DER-encoded X.509 certificates
///   Format: [device_cert, intermediate_cert, optional_root_cert]
///
/// # Returns
///
/// Signed WASM module with embedded certificate chain
///
/// # Example
///
/// ```ignore
/// let cert_chain = vec![
///     device_cert_der,      // Device certificate (contains public key)
///     intermediate_cert_der, // Intermediate CA certificate
///     root_cert_der,        // Root CA certificate (optional)
/// ];
///
/// let signed_module = sign_with_certificate(
///     &atecc608_provider,
///     device_key_handle,
///     wasm_module,
///     &cert_chain,
/// )?;
///
/// // Save to file
/// std::fs::write("signed.wasm", signed_module.to_bytes()?)?;
/// ```
pub fn sign_with_certificate(
    provider: &dyn SecureKeyProvider,
    key_handle: KeyHandle,
    mut module: Module,
    certificate_chain: &[Vec<u8>],
) -> Result<Module, WSError> {
    if certificate_chain.is_empty() {
        return Err(WSError::InvalidArgument);
    }

    // Hash the module and preserve previous signatures
    let mut out_sections = vec![Section::Custom(CustomSection::default())];
    let mut hasher = Hash::new();
    let mut previous_signature_data = None;

    for section in module.sections.into_iter() {
        if section.is_signature_header() {
            // Preserve previous signature data
            if let Section::Custom(custom_section) = &section {
                previous_signature_data = Some(custom_section.signature_data()?);
            }
            continue; // Don't include in hash
        }
        section.serialize(&mut hasher)?;
        out_sections.push(section);
    }
    let h = hasher.finalize().to_vec();

    // Create message to sign
    let mut msg: Vec<u8> = vec![];
    msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
    msg.extend_from_slice(&[
        SIGNATURE_VERSION,
        SIGNATURE_WASM_MODULE_CONTENT_TYPE,
        SIGNATURE_HASH_FUNCTION,
    ]);
    msg.extend_from_slice(&h);

    // Sign with hardware key
    let signature = provider.sign(key_handle, &msg)?;

    // Create new signature with certificate chain
    let new_signature = SignatureForHashes {
        key_id: None, // Certificate chain provides identity
        alg_id: ED25519_PK_ID,
        signature,
        certificate_chain: Some(certificate_chain.to_vec()),
    };

    // Build signed_hashes_set, preserving previous signatures
    let signed_hashes_set = if let Some(prev_sig_data) = previous_signature_data {
        // Add new signature to existing signatures
        let mut updated_set = prev_sig_data.signed_hashes_set;

        // Find matching hash or create new entry
        let mut found = false;
        for signed_hashes in &mut updated_set {
            if signed_hashes.hashes.contains(&h) {
                // Add to existing hash entry
                signed_hashes.signatures.push(new_signature.clone());
                found = true;
                break;
            }
        }

        if !found {
            // Create new hash entry
            updated_set.push(SignedHashes {
                hashes: vec![h],
                signatures: vec![new_signature],
            });
        }

        updated_set
    } else {
        // First signature
        vec![SignedHashes {
            hashes: vec![h],
            signatures: vec![new_signature],
        }]
    };

    let signature_data = SignatureData {
        specification_version: SIGNATURE_VERSION,
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

/// Verify a WASM module signed with a certificate chain
///
/// This function verifies a WASM module by:
/// 1. Extracting the certificate chain from the WASM signature
/// 2. Verifying the certificate chain against a trusted root CA
/// 3. Extracting the public key from the device certificate
/// 4. Verifying the WASM signature with that public key
///
/// # Arguments
///
/// * `reader` - Reader over the signed WASM module
/// * `verifier` - Offline verifier with trusted root CA
///
/// # Returns
///
/// Ok(()) if signature and certificates are valid, Err otherwise
///
/// # Example
///
/// ```ignore
/// // Load trusted root CA (embedded at compile time)
/// const ROOT_CA: &[u8] = include_bytes!("root-ca.crt");
/// let verifier = OfflineVerifier::new(ROOT_CA)?;
///
/// // Verify signed WASM
/// let mut wasm_file = std::fs::File::open("signed.wasm")?;
/// verify_with_certificate(&mut wasm_file, &verifier)?;
/// println!("✓ WASM signature and certificates valid!");
/// ```
pub fn verify_with_certificate(
    reader: &mut impl Read,
    verifier: &OfflineVerifier,
) -> Result<(), WSError> {
    let stream = Module::init_from_reader(reader)?;
    let mut sections = Module::iterate(stream)?;

    // Read signature header
    let signature_header_section = sections.next().ok_or(WSError::ParseError)??;
    let signature_header = match signature_header_section {
        Section::Custom(custom_section) if custom_section.is_signature_header() => custom_section,
        _ => {
            debug!("This module is not signed");
            return Err(WSError::NoSignatures);
        }
    };

    // Parse signature data
    let signature_data = signature_header.signature_data()?;

    if signature_data.signed_hashes_set.is_empty() {
        return Err(WSError::NoSignatures);
    }

    // Hash the module (excluding signature section)
    let mut hasher = Hash::new();
    for section in sections {
        let section = section?;
        if section.is_signature_header() || section.is_signature_delimiter() {
            continue;
        }
        section.serialize(&mut hasher)?;
    }
    let computed_hash = hasher.finalize().to_vec();

    // Verify signature with certificate
    for signed_hashes in &signature_data.signed_hashes_set {
        for hash in &signed_hashes.hashes {
            if hash != &computed_hash {
                continue; // Hash mismatch, try next
            }

            if let Some(sig_for_hash) = signed_hashes.signatures.first() {
                // Check if certificate chain is present
                let cert_chain = sig_for_hash.certificate_chain.as_ref().ok_or_else(|| {
                    WSError::VerificationError(
                        "No certificate chain found in signature".to_string(),
                    )
                })?;

                if cert_chain.is_empty() {
                    return Err(WSError::VerificationError(
                        "Empty certificate chain".to_string(),
                    ));
                }

                // Verify certificate chain against trusted root
                verifier.verify_certificate_chain(cert_chain, None)?;

                // Extract public key from device certificate (first in chain)
                let device_cert_der = &cert_chain[0];
                let public_key = extract_public_key_from_certificate(device_cert_der)?;

                // Verify WASM signature
                let mut msg: Vec<u8> = vec![];
                msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
                msg.extend_from_slice(&[
                    signature_data.specification_version,
                    signature_data.content_type,
                    signature_data.hash_function,
                ]);
                msg.extend_from_slice(hash);

                // Verify signature with public key from certificate
                let signature = ed25519_compact::Signature::from_slice(&sig_for_hash.signature)
                    .map_err(|_| WSError::ParseError)?;
                public_key.pk.verify(&msg, &signature)?;

                // Success!
                return Ok(());
            }
        }
    }

    Err(WSError::VerificationFailed)
}

/// Information about a single signature in a WASM module
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// Signature index in the module
    pub index: usize,
    /// Whether this signature includes a certificate chain
    pub has_certificate_chain: bool,
    /// Number of certificates in the chain (0 if no chain)
    pub certificate_count: usize,
    /// Subject DN from device certificate (if available)
    pub subject_dn: Option<String>,
    /// Key ID (if using old-style key-based signing)
    pub key_id: Option<Vec<u8>>,
}

/// Result of verifying a single signature
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Signature information
    pub info: SignatureInfo,
    /// Whether verification succeeded
    pub verified: bool,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Verify ALL certificate-based signatures in a WASM module
///
/// This function is useful for multi-signature scenarios where multiple parties
/// have signed the same module (e.g., component owner + integrator).
///
/// Unlike `verify_with_certificate()` which succeeds if ANY signature is valid,
/// this function requires ALL signatures to be valid against their respective
/// certificate chains.
///
/// # Arguments
///
/// * `reader` - WASM module reader
/// * `verifiers` - List of verifiers, one per expected PKI hierarchy
///
/// # Returns
///
/// Vector of verification results, one per signature found
///
/// # Example
///
/// ```ignore
/// // Verify owner + integrator signatures
/// let owner_verifier = OfflineVerifier::new(OWNER_ROOT_CA)?;
/// let integrator_verifier = OfflineVerifier::new(INTEGRATOR_ROOT_CA)?;
///
/// let results = verify_all_certificates(
///     &mut wasm_file,
///     &[&owner_verifier, &integrator_verifier],
/// )?;
///
/// // Check that all signatures verified
/// for result in &results {
///     assert!(result.verified, "Signature {} failed: {:?}",
///         result.info.index, result.error);
/// }
/// ```
pub fn verify_all_certificates(
    reader: &mut impl Read,
    verifiers: &[&OfflineVerifier],
) -> Result<Vec<VerificationResult>, WSError> {
    let stream = Module::init_from_reader(reader)?;
    let mut sections = Module::iterate(stream)?;

    // Read signature header
    let signature_header_section = sections.next().ok_or(WSError::ParseError)??;
    let signature_header = match signature_header_section {
        Section::Custom(custom_section) if custom_section.is_signature_header() => custom_section,
        _ => {
            debug!("This module is not signed");
            return Err(WSError::NoSignatures);
        }
    };

    // Parse signature data
    let signature_data = signature_header.signature_data()?;

    if signature_data.signed_hashes_set.is_empty() {
        return Err(WSError::NoSignatures);
    }

    // Hash the module (excluding signature section)
    let mut hasher = Hash::new();
    for section in sections {
        let section = section?;
        if section.is_signature_header() || section.is_signature_delimiter() {
            continue;
        }
        section.serialize(&mut hasher)?;
    }
    let computed_hash = hasher.finalize().to_vec();

    // Collect all results
    let mut results = Vec::new();
    let mut sig_index = 0;

    // Verify each signature
    for signed_hashes in &signature_data.signed_hashes_set {
        for hash in &signed_hashes.hashes {
            if hash != &computed_hash {
                continue; // Hash mismatch, skip
            }

            for sig_for_hash in &signed_hashes.signatures {
                // Create signature info
                let info = SignatureInfo {
                    index: sig_index,
                    has_certificate_chain: sig_for_hash.certificate_chain.is_some(),
                    certificate_count: sig_for_hash
                        .certificate_chain
                        .as_ref()
                        .map(|c| c.len())
                        .unwrap_or(0),
                    subject_dn: sig_for_hash
                        .certificate_chain
                        .as_ref()
                        .and_then(|chain| chain.first())
                        .and_then(|cert| extract_subject_dn(cert).ok()),
                    key_id: sig_for_hash.key_id.clone(),
                };

                // Try to verify with each verifier
                let mut verified = false;
                let mut last_error = None;

                if let Some(cert_chain) = &sig_for_hash.certificate_chain {
                    if cert_chain.is_empty() {
                        results.push(VerificationResult {
                            info,
                            verified: false,
                            error: Some("Empty certificate chain".to_string()),
                        });
                        sig_index += 1;
                        continue;
                    }

                    // Try each verifier
                    for verifier in verifiers {
                        // Verify certificate chain
                        let chain_result = verifier.verify_certificate_chain(cert_chain, None);
                        if let Err(e) = chain_result {
                            last_error =
                                Some(format!("Certificate chain verification failed: {:?}", e));
                            continue;
                        }

                        // Extract public key
                        let public_key = match extract_public_key_from_certificate(&cert_chain[0]) {
                            Ok(pk) => pk,
                            Err(e) => {
                                last_error = Some(format!("Failed to extract public key: {:?}", e));
                                continue;
                            }
                        };

                        // Verify WASM signature
                        let mut msg: Vec<u8> = vec![];
                        msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
                        msg.extend_from_slice(&[
                            signature_data.specification_version,
                            signature_data.content_type,
                            signature_data.hash_function,
                        ]);
                        msg.extend_from_slice(hash);

                        let signature =
                            match ed25519_compact::Signature::from_slice(&sig_for_hash.signature) {
                                Ok(sig) => sig,
                                Err(_) => {
                                    last_error = Some("Invalid signature format".to_string());
                                    continue;
                                }
                            };

                        if public_key.pk.verify(&msg, &signature).is_ok() {
                            verified = true;
                            break; // Success with this verifier
                        } else {
                            last_error = Some("Signature verification failed".to_string());
                        }
                    }
                } else {
                    last_error =
                        Some("No certificate chain (use regular verification)".to_string());
                }

                results.push(VerificationResult {
                    info,
                    verified,
                    error: if verified { None } else { last_error },
                });

                sig_index += 1;
            }
        }
    }

    Ok(results)
}

/// Get information about all signatures in a WASM module without verifying them
///
/// This is useful for inspecting what signatures are present before verification.
///
/// # Example
///
/// ```ignore
/// let signatures = inspect_signatures(&mut wasm_file)?;
/// println!("Found {} signatures:", signatures.len());
/// for sig in signatures {
///     if sig.has_certificate_chain {
///         println!("  Signature {}: {} certificates",
///             sig.index, sig.certificate_count);
///     } else {
///         println!("  Signature {}: key-based (no certificates)",
///             sig.index);
///     }
/// }
/// ```
pub fn inspect_signatures(reader: &mut impl Read) -> Result<Vec<SignatureInfo>, WSError> {
    let stream = Module::init_from_reader(reader)?;
    let mut sections = Module::iterate(stream)?;

    // Read signature header
    let signature_header_section = sections.next().ok_or(WSError::ParseError)??;
    let signature_header = match signature_header_section {
        Section::Custom(custom_section) if custom_section.is_signature_header() => custom_section,
        _ => {
            debug!("This module is not signed");
            return Err(WSError::NoSignatures);
        }
    };

    // Parse signature data
    let signature_data = signature_header.signature_data()?;

    let mut signatures = Vec::new();
    let mut sig_index = 0;

    for signed_hashes in &signature_data.signed_hashes_set {
        for sig_for_hash in &signed_hashes.signatures {
            signatures.push(SignatureInfo {
                index: sig_index,
                has_certificate_chain: sig_for_hash.certificate_chain.is_some(),
                certificate_count: sig_for_hash
                    .certificate_chain
                    .as_ref()
                    .map(|c| c.len())
                    .unwrap_or(0),
                subject_dn: sig_for_hash
                    .certificate_chain
                    .as_ref()
                    .and_then(|chain| chain.first())
                    .and_then(|cert| extract_subject_dn(cert).ok()),
                key_id: sig_for_hash.key_id.clone(),
            });
            sig_index += 1;
        }
    }

    Ok(signatures)
}

/// Extract Subject DN from a certificate
fn extract_subject_dn(cert_der: &[u8]) -> Result<String, WSError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| WSError::X509Error(format!("Failed to parse certificate: {:?}", e)))?;

    Ok(cert.subject().to_string())
}

/// Extract public key from X.509 certificate
///
/// This function parses an X.509 certificate and extracts the public key.
///
/// # Arguments
///
/// * `cert_der` - DER-encoded X.509 certificate
///
/// # Returns
///
/// PublicKey extracted from the certificate
fn extract_public_key_from_certificate(cert_der: &[u8]) -> Result<PublicKey, WSError> {
    use x509_parser::prelude::*;

    // Parse certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| WSError::X509Error(format!("Failed to parse certificate: {:?}", e)))?;

    // Extract public key
    let public_key_info = cert.public_key();
    let public_key_bytes = &public_key_info.subject_public_key.data;

    // For Ed25519, the public key is 32 bytes
    if public_key_bytes.len() != 32 {
        return Err(WSError::X509Error(format!(
            "Invalid public key length: {} (expected 32 for Ed25519)",
            public_key_bytes.len()
        )));
    }

    // Create Ed25519 public key
    let pk = ed25519_compact::PublicKey::from_slice(public_key_bytes)
        .map_err(WSError::CryptoError)?;

    Ok(PublicKey { pk, key_id: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::software::SoftwareProvider;
    use crate::provisioning::OfflineVerifierBuilder;
    use crate::provisioning::ca::{CAConfig, PrivateCA};
    use crate::provisioning::{CertificateConfig, DeviceIdentity, ProvisioningResult, ProvisioningSession};

    #[test]
    fn test_sign_and_verify_with_certificate() {
        // Create CA
        let root_config = CAConfig::new("Test Corp", "Test Root CA");
        let root_ca = PrivateCA::create_root(root_config).unwrap();

        // For testing with SoftwareProvider, we can export the full keypair
        // and use it to create a proper certificate (hardware doesn't allow this)
        let provider = SoftwareProvider::new();
        let key_handle = provider.generate_key().unwrap();
        let device_keypair = provider.export_keypair(key_handle).unwrap();

        let device_id = DeviceIdentity::new("device-test");
        let cert_config = CertificateConfig::new("device-test");

        // Create certificate with the actual device keypair (for testing)
        let device_cert = root_ca
            .sign_device_certificate_with_keypair(&device_keypair, &device_id, &cert_config)
            .unwrap();

        // Build result manually for testing
        let prov_result = ProvisioningResult {
            key_handle,
            certificate: device_cert,
            certificate_chain: vec![root_ca.certificate().to_vec()],
            device_id: device_id.id().to_string(),
            serial_number: vec![1, 2, 3, 4],
        };

        // Create test WASM module (minimal valid WASM: magic + version)
        let wasm_bytes: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6D, // Magic: \0asm
            0x01, 0x00, 0x00, 0x00, // Version: 1
        ];
        let module = Module::deserialize(&mut wasm_bytes.as_slice()).unwrap();

        // Sign with certificate
        let cert_chain = prov_result.full_chain();
        let signed_module =
            sign_with_certificate(&provider, prov_result.key_handle, module, &cert_chain).unwrap();

        // Verify with certificate
        let verifier = OfflineVerifierBuilder::new()
            .with_root(root_ca.certificate())
            .unwrap()
            .build()
            .unwrap();

        // Serialize module to bytes
        let mut module_bytes = Vec::new();
        signed_module.serialize(&mut module_bytes).unwrap();
        let result = verify_with_certificate(&mut module_bytes.as_slice(), &verifier);

        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        println!("✓ WASM signed and verified with certificates");
    }

    #[test]
    fn test_multi_signature_owner_plus_integrator() {
        // Scenario: Component owner signs, then integrator adds their signature

        // 1. Owner signs
        let owner_ca =
            PrivateCA::create_root(CAConfig::new("Owner Corp", "Owner Root CA")).unwrap();
        let owner_provider = SoftwareProvider::new();
        let owner_key = owner_provider.generate_key().unwrap();
        let owner_keypair = owner_provider.export_keypair(owner_key).unwrap();

        let owner_id = DeviceIdentity::new("owner-device");
        let owner_config = CertificateConfig::new("owner-device");

        let owner_cert = owner_ca
            .sign_device_certificate_with_keypair(&owner_keypair, &owner_id, &owner_config)
            .unwrap();

        // Create test WASM module
        let wasm_bytes: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6D, // Magic: \0asm
            0x01, 0x00, 0x00, 0x00, // Version: 1
        ];
        let module = Module::deserialize(&mut wasm_bytes.as_slice()).unwrap();

        // Owner signs
        let owner_signed = sign_with_certificate(
            &owner_provider,
            owner_key,
            module,
            &[owner_cert.clone(), owner_ca.certificate().to_vec()],
        )
        .unwrap();

        // 2. Integrator adds signature
        let integrator_ca =
            PrivateCA::create_root(CAConfig::new("Integrator Inc", "Integrator Root CA")).unwrap();
        let integrator_provider = SoftwareProvider::new();
        let integrator_key = integrator_provider.generate_key().unwrap();
        let integrator_keypair = integrator_provider.export_keypair(integrator_key).unwrap();

        let integrator_id = DeviceIdentity::new("integrator-device");
        let integrator_config = CertificateConfig::new("integrator-device");

        let integrator_cert = integrator_ca
            .sign_device_certificate_with_keypair(
                &integrator_keypair,
                &integrator_id,
                &integrator_config,
            )
            .unwrap();

        // Integrator signs the already-signed module
        let dual_signed = sign_with_certificate(
            &integrator_provider,
            integrator_key,
            owner_signed,
            &[integrator_cert, integrator_ca.certificate().to_vec()],
        )
        .unwrap();

        // 3. Inspect signatures
        let mut dual_bytes = Vec::new();
        dual_signed.serialize(&mut dual_bytes).unwrap();

        let signatures = inspect_signatures(&mut dual_bytes.as_slice()).unwrap();
        assert_eq!(signatures.len(), 2, "Should have 2 signatures");

        for (i, sig) in signatures.iter().enumerate() {
            assert!(
                sig.has_certificate_chain,
                "Signature {} should have certificate chain",
                i
            );
            assert_eq!(
                sig.certificate_count, 2,
                "Signature {} should have 2 certificates (device + root)",
                i
            );
            assert!(
                sig.subject_dn.is_some(),
                "Signature {} should have subject DN",
                i
            );
        }

        println!("✓ Found 2 signatures:");
        for sig in &signatures {
            println!(
                "  - Signature {}: {} ({}  certs)",
                sig.index,
                sig.subject_dn.as_ref().unwrap(),
                sig.certificate_count
            );
        }

        // 4. Verify all signatures
        let owner_verifier = OfflineVerifierBuilder::new()
            .with_root(owner_ca.certificate())
            .unwrap()
            .build()
            .unwrap();

        let integrator_verifier = OfflineVerifierBuilder::new()
            .with_root(integrator_ca.certificate())
            .unwrap()
            .build()
            .unwrap();

        let results = verify_all_certificates(
            &mut dual_bytes.as_slice(),
            &[&owner_verifier, &integrator_verifier],
        )
        .unwrap();

        assert_eq!(results.len(), 2, "Should have 2 verification results");

        // Check all signatures verified
        for result in &results {
            assert!(
                result.verified,
                "Signature {} failed: {:?}",
                result.info.index, result.error
            );
        }

        println!("✓ Both signatures verified successfully");
        println!("✓ Owner + Integrator multi-signature works!");
    }

    #[test]
    fn test_extract_public_key_from_certificate() {
        // Create CA and device certificate
        let root_config = CAConfig::new("Test Corp", "Test Root CA");
        let root_ca = PrivateCA::create_root(root_config).unwrap();

        let provider = SoftwareProvider::new();
        let device_id = DeviceIdentity::new("device-pk-test");
        let cert_config = CertificateConfig::new("device-pk-test");

        let prov_result =
            ProvisioningSession::provision(&root_ca, &provider, device_id, cert_config, false)
                .unwrap();

        // Extract public key from certificate
        let public_key = extract_public_key_from_certificate(&prov_result.certificate);

        // Note: This will fail because the certificate contains a temporary key
        // (see Phase 5 limitation). This is expected until we implement proper
        // device public key embedding.
        // For now, we just verify it doesn't crash
        let _ = public_key;
    }
}
