# Multi-Signature WASM Component Composition

## Overview

This document describes how to sign WASM components with multiple signatures for composition scenarios where different parties need to attest to the module.

## Use Case: Owner + Integrator Signatures

**Scenario**: A WASM component is created by an owner, then integrated into a larger system by an integrator. Both parties need to sign:

1. **Owner** signs the original component with their certificate
2. **Integrator** adds their signature when composing/integrating
3. **Verifier** checks both signatures independently

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ WASM Module Signature Structure                             │
├─────────────────────────────────────────────────────────────┤
│ Signature Header (custom section "wasmsig")                 │
│   ├─ SignatureData                                          │
│   │   ├─ SignedHashes[0]                                    │
│   │   │   ├─ hashes: [hash1, hash2, ...]                    │
│   │   │   └─ signatures: [                                  │
│   │   │       ├─ Signature 1 (Owner)                        │
│   │   │       │   ├─ key_id: None                           │
│   │   │       │   ├─ signature: <Ed25519 64 bytes>          │
│   │   │       │   └─ certificate_chain: [                   │
│   │   │       │       ├─ owner_device_cert                  │
│   │   │       │       ├─ owner_intermediate_ca              │
│   │   │       │       └─ owner_root_ca                      │
│   │   │       │     ]                                       │
│   │   │       └─ Signature 2 (Integrator)                   │
│   │   │           ├─ key_id: None                           │
│   │   │           ├─ signature: <Ed25519 64 bytes>          │
│   │   │           └─ certificate_chain: [                   │
│   │   │               ├─ integrator_device_cert             │
│   │   │               ├─ integrator_intermediate_ca         │
│   │   │               └─ integrator_root_ca                 │
│   │   │             ]                                       │
│   │   │     ]                                               │
│   │   └─ SignedHashes[1] (if sections added with delimiters)│
│   └─ ...                                                    │
└─────────────────────────────────────────────────────────────┘
```

## Workflow

### Step 1: Owner Signs Original Component

```rust
use wsc::provisioning::{sign_with_certificate, PrivateCA, DeviceIdentity};
use wsc::platform::SoftwareProvider;
use wsc::wasm_module::Module;

// Owner's provisioning setup
let owner_ca = PrivateCA::load("owner_ca.pem")?;
let owner_provider = SoftwareProvider::new();
let owner_key = owner_provider.generate_key()?;

// Get owner's certificate chain
let owner_cert_chain = /* ... from provisioning ... */;

// Load original WASM component
let mut component = Module::deserialize_from_file("component.wasm")?;

// Owner signs with certificate
let signed_component = sign_with_certificate(
    &owner_provider,
    owner_key,
    component,
    &owner_cert_chain,
)?;

// Save owner-signed component
signed_component.serialize_to_file("component.owner-signed.wasm")?;
```

### Step 2: Integrator Adds Signature

The integrator can add their signature to the already-signed module:

```rust
// Integrator's provisioning setup
let integrator_ca = PrivateCA::load("integrator_ca.pem")?;
let integrator_provider = SoftwareProvider::new();
let integrator_key = integrator_provider.generate_key()?;

// Get integrator's certificate chain
let integrator_cert_chain = /* ... from provisioning ... */;

// Load owner-signed component
let owner_signed = Module::deserialize_from_file("component.owner-signed.wasm")?;

// Integrator adds their signature
let dual_signed = sign_with_certificate(
    &integrator_provider,
    integrator_key,
    owner_signed,  // Already has owner's signature
    &integrator_cert_chain,
)?;

// Save dual-signed component
dual_signed.serialize_to_file("component.dual-signed.wasm")?;
```

### Step 3: Verification with Multiple Certificates

Verifier needs to check BOTH signatures:

```rust
use wsc::provisioning::{verify_with_certificate, OfflineVerifierBuilder};

// Create verifier for owner's CA
let owner_verifier = OfflineVerifierBuilder::new()
    .with_root(OWNER_ROOT_CA_CERT)?
    .build()?;

// Create verifier for integrator's CA
let integrator_verifier = OfflineVerifierBuilder::new()
    .with_root(INTEGRATOR_ROOT_CA_CERT)?
    .build()?;

// Load dual-signed component
let component_bytes = std::fs::read("component.dual-signed.wasm")?;

// Verify owner's signature
verify_with_certificate(
    &mut component_bytes.as_slice(),
    &owner_verifier,
)?;

// Verify integrator's signature
// Note: Currently needs enhancement to verify specific signature
verify_with_certificate(
    &mut component_bytes.as_slice(),
    &integrator_verifier,
)?;
```

## Signature Preservation During Composition

### Using `allow_extensions` Flag

When composing components, you may want to preserve original signatures while adding new sections:

```rust
use wsc::signature::SecretKey;

// Owner signs with allow_extensions=true
let owner_sk = SecretKey::from_bytes(&owner_key_bytes)?;
let (signed_module, _) = owner_sk.sign_multi(
    component,
    Some(&owner_key_id),
    false,  // embedded signature
    true,   // allow_extensions - inserts delimiters
)?;

// This adds delimiter sections after each module section
// New sections can be appended without invalidating the original signature
```

### Delimiter Mechanism

Delimiters are 16-byte random custom sections that mark signed boundaries:

```
[Signature Header]
[Section 1] → Hash₁
[Delimiter₁]
[Section 2] → Hash₂
[Delimiter₂]
[Section 3] → Hash₃
```

- Each delimiter creates a new hash boundary
- Adding sections after a delimiter doesn't invalidate previous hashes
- Original signatures remain valid

## Security Considerations

### 1. Independent Verification

Each signature should be independently verifiable:
- Owner signature proves component authenticity
- Integrator signature proves integration approval
- Both must pass for full trust

### 2. Certificate Chain Validation

Each signature includes its own certificate chain:
- Owner chain validates against owner's root CA
- Integrator chain validates against integrator's root CA
- Chains are independent (different PKI hierarchies)

### 3. Signature Order

Signatures are added in order:
1. First signature (owner) covers original content
2. Second signature (integrator) covers content + first signature
3. Both remain in the signature header

### 4. Revocation

Certificate-based signing doesn't include revocation:
- Use short-lived certificates (1-2 years for devices)
- Verifier can check certificate expiry
- For critical applications, maintain certificate blocklists

## Current Limitations

### 1. Signature-Specific Verification

Current `verify_with_certificate()` checks if ANY signature is valid:

```rust
// Current: Passes if EITHER signature is valid
verify_with_certificate(&module, &owner_verifier)?;
```

**Needed**: Verify specific signature index or all signatures:

```rust
// Proposed: Verify ALL signatures
verify_all_certificates(&module, &[owner_verifier, integrator_verifier])?;

// Proposed: Verify specific signature
verify_certificate_at_index(&module, &owner_verifier, 0)?;
```

### 2. Certificate Chain Extraction

No API to extract certificate chains from a signed module:

```rust
// Proposed API
let chains = extract_certificate_chains(&module)?;
for (idx, chain) in chains.iter().enumerate() {
    println!("Signature {}: {} certificates", idx, chain.len());
}
```

### 3. Signature Metadata

No way to get signature metadata without verification:

```rust
// Proposed API
let signatures = get_signature_info(&module)?;
for sig in signatures {
    if let Some(chain) = &sig.certificate_chain {
        let cert = parse_certificate(&chain[0])?;
        println!("Signer: {}", cert.subject_dn);
    }
}
```

## Recommended Enhancements

### 1. Multi-Certificate Verification Function

```rust
/// Verify all certificate-based signatures in a module
///
/// Each verifier corresponds to a different PKI hierarchy.
/// All signatures must verify against at least one verifier.
pub fn verify_all_certificates(
    reader: &mut impl Read,
    verifiers: &[&OfflineVerifier],
) -> Result<Vec<VerificationResult>, WSError> {
    // Returns result for each signature
}
```

### 2. Signature Inspection API

```rust
/// Extract certificate information without verification
pub fn inspect_signatures(
    reader: &mut impl Read,
) -> Result<Vec<SignatureInfo>, WSError> {
    // Returns metadata for each signature
}

pub struct SignatureInfo {
    pub index: usize,
    pub has_certificate_chain: bool,
    pub certificate_count: usize,
    pub subject_dn: Option<String>,  // from device cert
    pub key_id: Option<Vec<u8>>,
}
```

### 3. Selective Verification

```rust
/// Verify only signatures matching a predicate
pub fn verify_certificates_where<F>(
    reader: &mut impl Read,
    verifier: &OfflineVerifier,
    predicate: F,
) -> Result<(), WSError>
where
    F: Fn(&SignatureInfo) -> bool,
{
    // Verify only signatures where predicate returns true
}
```

## Best Practices

### For Component Owners

1. **Always use certificate-based signing** for traceability
2. **Include complete chain** (device + intermediate + root)
3. **Use allow_extensions=true** if expecting composition
4. **Document PKI hierarchy** for verifiers

### For Integrators

1. **Verify owner signature** before adding your own
2. **Use separate PKI hierarchy** from component owners
3. **Preserve original signatures** (don't strip)
4. **Document trust requirements** (both signatures needed)

### For Verifiers

1. **Embed both root CAs** in verifier firmware
2. **Check certificate validity periods**
3. **Require both signatures** for composed components
4. **Log verification results** for audit trail

## Example: Full Composition Workflow

```rust
use wsc::provisioning::*;
use wsc::platform::SoftwareProvider;
use wsc::wasm_module::Module;

fn compose_and_sign() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Owner creates and signs component
    let owner_ca = PrivateCA::create_root(CAConfig::new("Owner Corp", "Owner Root CA"))?;
    let owner_provider = SoftwareProvider::new();
    let owner_key = owner_provider.generate_key()?;
    let owner_cert_chain = vec![/* ... */];

    let component = Module::deserialize_from_file("lib.wasm")?;
    let owner_signed = sign_with_certificate(
        &owner_provider,
        owner_key,
        component,
        &owner_cert_chain,
    )?;

    // 2. Integrator loads and verifies owner signature
    let integrator_ca = PrivateCA::create_root(CAConfig::new("Integrator Inc", "Integrator Root CA"))?;
    let owner_verifier = OfflineVerifierBuilder::new()
        .with_root(owner_ca.certificate())?
        .build()?;

    let mut owner_bytes = Vec::new();
    owner_signed.serialize(&mut owner_bytes)?;
    verify_with_certificate(&mut owner_bytes.as_slice(), &owner_verifier)?;
    println!("✓ Owner signature valid");

    // 3. Integrator adds their signature
    let integrator_provider = SoftwareProvider::new();
    let integrator_key = integrator_provider.generate_key()?;
    let integrator_cert_chain = vec![/* ... */];

    let dual_signed = sign_with_certificate(
        &integrator_provider,
        integrator_key,
        owner_signed,
        &integrator_cert_chain,
    )?;

    // 4. Verifier checks both signatures
    let integrator_verifier = OfflineVerifierBuilder::new()
        .with_root(integrator_ca.certificate())?
        .build()?;

    let mut dual_bytes = Vec::new();
    dual_signed.serialize(&mut dual_bytes)?;

    // Verify owner signature still valid
    verify_with_certificate(&mut dual_bytes.as_slice(), &owner_verifier)?;
    println!("✓ Owner signature preserved");

    // Verify integrator signature
    verify_with_certificate(&mut dual_bytes.as_slice(), &integrator_verifier)?;
    println!("✓ Integrator signature valid");

    println!("✓ Component has valid dual signatures");
    Ok(())
}
```

## Conclusion

The current implementation **already supports** multi-signature scenarios with independent certificate chains. The main gaps are in the verification API (checking all signatures vs any signature) and inspection utilities.

For component composition:
- ✅ Multiple signatures are preserved
- ✅ Each signature has independent certificate chain
- ✅ Delimiters allow section additions
- ⚠️  Verification API needs enhancement for "require all" semantics
- ⚠️  No signature inspection API yet

The cryptographic design is **sound** for this use case.
