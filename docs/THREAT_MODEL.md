---
id: DOC-THREAT-MODEL
title: STRIDE Threat Model
type: specification
status: approved
tags: [security, stride, threat-model]
---

# WSC Component Threat Analysis (STRIDE)

This document provides a **component-level** threat analysis of the WebAssembly Signature Component (WSC) using the STRIDE methodology. Each identified threat is cross-referenced to the project's formal threat scenarios, risk assessments, asset inventory, STPA-Sec control structure, and cybersecurity artifacts to provide full traceability from threat through mitigation to verification.

> **Important Clarification**: This is NOT a system-level TARA (Threat Analysis and Risk Assessment). WSC is a cryptographic component that cannot perform TARA in isolation. System integrators must:
> 1. Perform TARA on their ITEM (vehicle ECU, IoT device, etc.)
> 2. Reference this document as evidence for the WSC component
> 3. See `docs/security/INTEGRATION_GUIDANCE.md` for integration help
> 4. See `docs/security/RISK_ASSESSMENT.md` for quantified risk ratings (covering [[RA-001]] through [[RA-018]])

## System Overview

WSC is a WebAssembly module signing and verification toolkit that provides:

1. **Ed25519 Signature Operations** ([[FEAT-1]]) — Sign and verify WASM modules using [[ASSET-001]] and [[ASSET-002]]
2. **Keyless (Ephemeral) Signing** ([[FEAT-2]]) — Sigstore integration via Fulcio/Rekor, consuming [[ASSET-003]] and producing [[ASSET-004]] and [[ASSET-007]]
3. **Multi-Signature Support** ([[FEAT-3]]) — Multiple signers on a single module, managed through [[ASSET-009]]
4. **Certificate Provisioning** ([[FEAT-4]]) — X.509 certificate issuance for devices, anchored by [[ASSET-016]]
5. **Provenance/SBOM Embedding** ([[FEAT-5]]) — SLSA compliance support with audit evidence in [[ASSET-020]]

### Trust Boundaries

The following diagram illustrates the three trust boundaries that structure our threat analysis. Each boundary crossing represents a data flow (see [[DF-1]] through [[DF-10]]) where threats are most likely to materialize.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Build Environment                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ Source Code │───►│  WSC CLI    │───►│ Signed WASM Module  │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│                            │                      │              │
│                   Secret Key (TB1)        Signature Data         │
└─────────────────────────────────────────────────────────────────┘
                             │
        ─────────────────────┼───────────────────────
        TRUST BOUNDARY 1     │  (Key Material)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Sigstore Infrastructure                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Fulcio    │    │   Rekor     │    │   OIDC Provider     │  │
│  │  (Cert CA)  │    │(Trans. Log) │    │  (GitHub/Google)    │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
        ─────────────────────┼───────────────────────
        TRUST BOUNDARY 2     │  (Network/TLS)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Runtime Environment                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │WASM Runtime │◄───│ Verifier    │◄───│  Public Key Store   │  │
│  │ (wasmtime)  │    │   (wsc)     │    │  (Trust Bundle)     │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

Trust Boundary 1 separates the signing environment from external key infrastructure. Data flows crossing this boundary ([[DF-1]], [[DF-2]], [[DF-3]]) carry cryptographic material and must be protected by the security properties defined in [[SP-1]] and [[SP-2]]. Trust Boundary 2 separates the Sigstore infrastructure from the runtime verification environment, where data flows ([[DF-4]], [[DF-5]], [[DF-6]]) must satisfy the integrity and authenticity properties in [[SP-3]] and [[SP-4]].

---

## STRIDE Threat Analysis

### S — Spoofing

#### S1: Key Impersonation

Key impersonation ([[TS-001]]) targets the Ed25519 secret key ([[ASSET-001]]) and, in the keyless flow, the OIDC identity token ([[ASSET-003]]). The attack feasibility is assessed in [[RA-001]], which rates the likelihood as Low given Ed25519's 128-bit security level, but the impact as Critical because a compromised key yields complete trust compromise — any module signed with the stolen key would pass verification.

The STPA-Sec analysis reveals why this threat is structurally dangerous: the signing controller ([[CTRL-1]]) relies on the assumption that the private key is exclusively held by the authorized signer. When that assumption is violated, the unsecure control action [[UCA-9]] manifests — the signing controller issues a valid signature without a legitimate authorization decision. The corresponding attack scenario ([[AS-1]]) traces how an attacker with file-system access to key material can impersonate the signer entirely.

Mitigations are anchored in cybersecurity design [[CD-1]] (cryptographic key protection):

- Key files stored with restricted permissions (0600), enforcing the system constraint [[SC-1]]
- Zeroization of key material on drop, preventing post-use extraction
- HSM/TEE key storage support on the roadmap, addressing [[RR-1]]

The security property [[SP-1]] (key confidentiality) provides the formal guarantee that this threat's residual risk remains Low.

#### S2: Certificate Authority Compromise

Fulcio CA compromise ([[TS-006]]) targets the certificate issuance chain ([[ASSET-004]], [[ASSET-016]]). If the Fulcio CA were compromised, an attacker could obtain certificates binding arbitrary identities, enabling them to sign modules as any identity. The risk assessment [[RA-006]] rates this as Very Low likelihood due to Sigstore's Signed Certificate Timestamp (SCT) monitoring, but High impact.

The STPA control structure analysis is illuminating here: the certificate issuance controller ([[CTRL-4]]) sits outside WSC's trust boundary, meaning WSC must treat it as a partially trusted external dependency. The controlled process [[CP-2]] (certificate validation) must therefore enforce independent checks. The unsecure control action [[UCA-3]] describes what happens when the verification module accepts a certificate without validating its chain against pinned roots — the system constraint [[SC-3]] exists specifically to prevent this.

Mitigations draw on cybersecurity design [[CD-5]] (certificate chain validation):

- Certificate pinning enforced for Fulcio and Rekor endpoints ([[ASSET-010]])
- Rekor transparency log ([[ASSET-007]]) provides an independent audit trail enabling post-hoc detection
- Short-lived certificates (10-minute validity) limit the window of exploitation

The security property [[SP-5]] (certificate integrity) ensures residual risk is Very Low.

#### S3: OIDC Token Theft

OIDC token theft ([[TS-002]]) targets the identity token ([[ASSET-003]]) in CI/CD environments where secrets may leak through environment variables, logs, or process memory. The risk assessment [[RA-002]] rates the likelihood as Medium — CI environments are notoriously leaky — but the impact as Medium because stolen tokens have a limited validity window.

The STPA analysis identifies the data flow from the OIDC provider through the signing controller ([[CTRL-2]]) as a critical path. The unsecure control action [[UCA-1]] arises when the token is stored in a retrievable form after the signing operation completes. The attack scenario [[AS-2]] models a CI pipeline compromise where an attacker extracts the token before it is consumed.

Mitigations are specified in cybersecurity design [[CD-2]] (token lifecycle management):

- Tokens are zeroized immediately after use, satisfying the system constraint [[SC-2]]
- Token lifetime is typically under 10 minutes, bounding the exploitation window
- Rekor provides non-repudiation ([[ASSET-007]]), so even if a token is stolen and used, the resulting signature is logged and attributable

Residual risk is Low when token zeroization is active. The cybersecurity requirement [[CR-2]] mandates this behavior.

### T — Tampering

#### T1: Module Modification After Signing

Post-signing module tampering ([[TS-003]]) targets the signed WASM module ([[ASSET-005]]). This is arguably the most common attack WSC is designed to prevent: an attacker with file-system or network access modifies the module after it has been signed, hoping the altered module will still pass verification. The risk assessment [[RA-003]] rates the likelihood as High (file access is often achievable) but the impact as None because signature verification will deterministically fail.

The STPA control structure reveals why this threat is well-contained: the verification controller ([[CTRL-3]]) computes a fresh hash over all module sections and compares it against the signed digest. The controlled process [[CP-1]] (hash computation) operates over the entire module byte range, leaving no room for undetected modification. The system constraint [[SC-4]] requires that any byte change must invalidate the signature.

Mitigations are grounded in cybersecurity design [[CD-3]] (integrity verification):

- SHA-256 hash of all sections is included in the signature, covering [[ASSET-005]] completely
- Any byte change — even a single bit flip — invalidates the signature, satisfying [[SP-3]] (module integrity)

The security property [[SP-3]] makes the residual risk None. This is a core design invariant verified by [[CV-1]].

#### T2: Signature Section Manipulation

Signature section substitution ([[TS-011]]) targets the signature section itself ([[ASSET-009]]). An attacker might attempt to replace the legitimate signature with one generated under a different key, effectively rebinding the module to a different signer. The risk assessment [[RA-011]] rates the likelihood as Medium but the impact as None because the verification logic binds signatures to specific public keys.

The STPA analysis through controller [[CTRL-6]] (signature validation) and the unsecure control action [[UCA-5]] (accepting a signature without verifying key binding) clarifies why this design choice is essential. The attack scenario [[AS-5]] models a substitution where an attacker replaces the signature section wholesale — the system constraint [[SC-5]] ensures this fails because the key ID embedded in the signature must match the expected public key from [[ASSET-015]].

Mitigations are part of cybersecurity design [[CD-3]]:

- Signature binds cryptographically to a specific public key ([[ASSET-002]])
- Key ID allows explicit key matching, preventing cross-key substitution
- The security property [[SP-6]] (signature binding) ensures verification rejects mismatched signatures

Residual risk is None.

#### T3: Rollback Attack

Rollback attacks ([[TS-012]]) target module version integrity by substituting a newer (patched) module with an older (vulnerable) signed version. The risk assessment [[RA-012]] rates the likelihood as Medium — particularly in OTA update scenarios — and the impact as Medium because vulnerable code would execute with a valid signature.

The STPA analysis highlights the verification controller's ([[CTRL-3]]) limitation: signature verification alone cannot distinguish between a current and a previous version if both carry valid signatures. The unsecure control action [[UCA-6]] describes this gap — the verifier accepts a validly signed module without checking version currency. The system constraint [[SC-6]] requires that verification environments maintain version state to detect rollback.

Mitigations draw on cybersecurity design [[CD-6]] (version integrity):

- Provenance embedding includes version information in the signed payload
- The composition manifest tracks dependencies and their versions
- The air-gapped verifier supports rollback detection by maintaining a monotonic version counter

The residual risk is Low when provenance verification is enabled. This is tracked as requirement [[REQ-5]], and the cybersecurity verification [[CV-4]] confirms the mechanism works.

### R — Repudiation

#### R1: Signer Denies Signing

Signer repudiation ([[TS-013]]) threatens accountability and audit trail integrity ([[ASSET-020]]). A legitimate signer might deny having signed a module to avoid responsibility for its contents. The risk assessment [[RA-013]] rates likelihood as Low — most signers act in good faith — but the impact as Medium because repudiation undermines the entire trust model in compliance-sensitive environments.

The STPA control structure provides the key insight: the Rekor transparency log controller ([[CTRL-5]]) operates as an independent, append-only witness. The controlled process [[CP-3]] (log entry creation) produces a Merkle tree inclusion proof ([[ASSET-007]]) that is computationally infeasible to forge or deny. The unsecure control action [[UCA-7]] would arise only if the signing flow bypassed Rekor submission — the system constraint [[SC-7]] prevents this by requiring Rekor logging for all keyless signatures.

Mitigations are specified in cybersecurity design [[CD-7]] (non-repudiation):

- Rekor transparency log provides an immutable, publicly auditable record
- Certificate chain binds the signature to an OIDC identity ([[ASSET-003]], [[ASSET-004]])
- Merkle tree inclusion proof provides cryptographic evidence of log membership

The security property [[SP-7]] (non-repudiation) reduces residual risk to Very Low.

#### R2: Timestamp Disputes

Timestamp disputes ([[TS-014]]) target temporal integrity — disagreements over when a signing event occurred, which matters for certificate validity windows and revocation timing. The risk assessment [[RA-014]] rates both likelihood and impact as Low, since trusted timestamps are embedded in the signing flow.

The STPA analysis through [[CTRL-5]] (Rekor controller) shows that the timestamp is recorded as part of the transparency log entry, not supplied by the signer. The unsecure control action [[UCA-8]] would occur if the system accepted signer-provided timestamps — the system constraint [[SC-8]] prevents this by requiring externally attested timestamps.

Mitigations are part of cybersecurity design [[CD-7]]:

- Rekor provides a trusted timestamp anchored to the log server's clock
- Signed Certificate Timestamps (SCTs) from Fulcio provide independent temporal evidence
- Together, these create a dual-source timestamp that is extremely difficult to dispute

Residual risk is Very Low.

### I — Information Disclosure

#### I1: Key Material Leakage

Key material leakage ([[TS-001]], [[TS-005]]) targets the Ed25519 secret key ([[ASSET-001]]) and the ECDSA ephemeral key ([[ASSET-008]]). Unlike the spoofing threat (which assumes the attacker already has the key), this threat concerns the pathways by which key material could leak: memory dumps, swap files, log output, or core dumps. The risk assessment [[RA-001]] rates the impact as Critical because leaked keys enable full impersonation.

The STPA analysis through the key management controller ([[CTRL-1]]) identifies multiple loss scenarios. The unsecure control action [[UCA-9]] (key material persists in accessible memory after use) is the primary concern. The attack scenario [[AS-3]] models extraction via `/proc/[pid]/mem` or swap file analysis. The system constraint [[SC-1]] mandates that key material must be zeroized immediately after cryptographic operations complete.

Mitigations are comprehensive, specified in cybersecurity design [[CD-1]]:

- Zeroization on drop using the `zeroize` crate, satisfying [[SC-1]] and verified by [[CV-2]]
- `#![forbid(unsafe_code)]` prevents memory safety bugs that could expose key material
- Secure file permissions (0600) on key files, enforced at write time
- No key material in log output, ensuring [[SP-2]] (key confidentiality in transit and at rest)

The security property [[SP-2]] bounds residual risk to Very Low. The residual risk [[RR-3]] (swap file exposure) remains and is addressed at the OS level.

#### I2: Timing Side Channels

Timing side-channel attacks ([[TS-005]]) attempt to extract cryptographic secrets by measuring the time taken by comparison or arithmetic operations. The risk assessment [[RA-005]] rates the likelihood as Low (requires local access and precise timing instrumentation) but the impact as High because successful exploitation could reveal the secret key.

The STPA analysis identifies the verification controller ([[CTRL-3]]) and signing controller ([[CTRL-1]]) as the relevant control points. The unsecure control action [[UCA-10]] describes a scenario where variable-time comparison leaks information about the expected signature value. The system constraint [[SC-9]] mandates constant-time operations for all security-sensitive comparisons.

Mitigations are specified in cybersecurity design [[CD-4]] (side-channel resistance):

- Constant-time comparison via the `ct_codecs` crate
- The `ed25519-compact` library uses constant-time arithmetic throughout
- The security property [[SP-8]] (side-channel resistance) is verified by [[CV-3]]

Residual risk is Very Low.

#### I3: Identity Disclosure via Certificates

Identity disclosure ([[TS-015]]) concerns the visibility of signer identity information embedded in Fulcio certificates ([[ASSET-004]]). Because certificates are designed to be public and verifiable, the signer's OIDC identity (typically an email or service account) is inherently visible to anyone who inspects the certificate.

This is an **accepted risk by design** — the security property [[SP-7]] (non-repudiation) requires identity binding, and [[CG-5]] (accountability) explicitly calls for signer identity to be verifiable. The risk assessment [[RA-015]] confirms this is N/A from a mitigation perspective: the behavior is intentional and required for the trust model to function.

The STPA analysis confirms that this is not a control failure but a deliberate design choice reflected in [[SC-7]].

### D — Denial of Service

#### D1: Resource Exhaustion

Resource exhaustion ([[TS-008]]) targets system availability through malformed input that triggers excessive memory allocation or CPU consumption. The risk assessment [[RA-008]] rates the likelihood as Medium — crafted inputs are straightforward to construct — and the impact as Medium because exhaustion affects the host process.

The STPA analysis through the parser controller ([[CTRL-7]]) and the controlled process [[CP-4]] (module parsing) reveals the attack surface: the WASM binary format allows variable-length sections with size fields that could specify enormous allocations. The unsecure control action [[UCA-11]] occurs when the parser allocates memory based on untrusted size fields without validation. The system constraint [[SC-10]] mandates bounded resource consumption.

Mitigations are specified in cybersecurity design [[CD-8]] (resource bounding):

- 16 MB allocation limit prevents memory exhaustion from oversized section declarations
- Bounded varint parsing prevents integer overflow attacks in length fields
- Maximum section counts are enforced, preventing combinatorial explosion
- Six fuzz testing targets continuously probe for resource exhaustion bugs, verified by [[CV-5]]

The security property [[SP-4]] (availability) ensures residual risk is Low. The cybersecurity requirement [[CR-8]] mandates these bounds.

#### D2: Infinite Loop / Hang

Infinite loop attacks ([[TS-016]]) target system availability through crafted input that causes the parser to loop indefinitely. The risk assessment [[RA-016]] rates the likelihood as Low — the parsing logic is iterative and bounded — and the impact as Medium.

The STPA analysis through [[CTRL-7]] (parser controller) identifies the unsecure control action [[UCA-11]] (parser does not terminate) as the root concern. The attack scenario [[AS-8]] models a crafted module with circular section references. The system constraint [[SC-10]] requires all parser loops to have explicit termination conditions.

Mitigations are part of cybersecurity design [[CD-8]]:

- Bounded iteration in all parsers — every loop has a maximum iteration count
- No recursion in critical parsing paths, eliminating stack overflow as a hang vector
- Fuzz testing specifically targets hang detection with timeout-based oracles

Residual risk is Very Low, verified by [[CV-5]].

#### D3: Network Denial of Service

Network DoS ([[TS-017]]) targets the Sigstore infrastructure endpoints (Fulcio, Rekor, OIDC providers) that the keyless signing flow depends on. The risk assessment [[RA-017]] rates the likelihood as Low (Sigstore has rate limiting and DDoS protection) and the impact as Medium (keyless signing becomes unavailable, but traditional Ed25519 signing is unaffected).

The STPA control structure analysis through [[CTRL-2]] (keyless signing controller) shows that this is an availability dependency on external services. The unsecure control action [[UCA-12]] describes the scenario where the signing flow blocks indefinitely waiting for an unresponsive external service. The system constraint [[SC-11]] requires timeout and fallback behavior.

Mitigations are specified in cybersecurity design [[CD-9]] (availability resilience):

- Sigstore infrastructure has its own rate limiting and availability protections
- WSC supports fallback to traditional Ed25519 signing when keyless infrastructure is unavailable
- Connection timeouts prevent indefinite blocking

Residual risk is Low.

### E — Elevation of Privilege

#### E1: Code Execution via Parser Bug

Parser-triggered code execution ([[TS-018]]) is the most severe potential threat: a crafted WASM module exploits a parsing bug to achieve arbitrary code execution on the host. The risk assessment [[RA-018]] rates the likelihood as Very Low — Rust's memory safety guarantees and the `#![forbid(unsafe_code)]` policy make this extremely difficult — but the impact as Critical.

The STPA analysis through [[CTRL-7]] (parser controller) and [[CP-4]] (module parsing) identifies this as the highest-consequence failure mode. The attack scenario [[AS-10]] models a buffer overflow in section parsing leading to control-flow hijacking. The system constraint [[SC-10]] requires memory-safe parsing, which Rust provides by default.

Mitigations are layered, specified in cybersecurity design [[CD-8]] and [[CD-1]]:

- `#![forbid(unsafe_code)]` is enforced project-wide, eliminating the primary class of memory corruption vulnerabilities
- Rust's ownership and borrowing system prevents use-after-free and double-free bugs
- Comprehensive fuzz testing with six targets ([[CV-5]]) continuously probes for memory safety violations
- Bounds checking on all reads prevents out-of-bounds access

The security property [[SP-4]] and [[SP-1]] together ensure residual risk is Very Low. The cybersecurity verification [[CV-6]] confirms no unsafe code exists in the codebase.

#### E2: Privilege Escalation via File Permissions

File permission exploitation targets key material ([[ASSET-001]]) through insecure file permissions that allow unauthorized users to read private keys. The risk assessment rates the likelihood as Low and the impact as Critical.

This threat is closely related to [[TS-001]] (key theft) and shares the same STPA analysis. The controller [[CTRL-1]] must ensure that key files are created with restrictive permissions. The unsecure control action [[UCA-9]] applies here as well — if the key file is world-readable, any local user can steal it.

Mitigations are specified in cybersecurity design [[CD-1]]:

- Keys are written with 0600 permissions, enforced at file creation time
- Warnings are emitted when existing key files have insecure permissions
- The cybersecurity requirement [[CR-1]] mandates this behavior

Residual risk is Very Low.

---

## Attack Surface Summary

The attack surface is organized by component, with each surface mapped to the relevant data flows, security properties, and threat scenarios:

- **WASM Parser** — Malformed sections and oversized data cross [[DF-7]] and [[DF-8]]. Protected by [[SP-4]] and [[CD-8]]. Risk: Low. Relevant threats: [[TS-008]], [[TS-016]], [[TS-018]].

- **Signature Verification** — Timing attacks and algorithm weaknesses target [[DF-4]] and [[DF-5]]. Protected by [[SP-8]] and [[CD-4]]. Risk: Very Low. Relevant threats: [[TS-005]], [[TS-011]].

- **Key Management** — File permissions and memory residue expose [[ASSET-001]] across [[DF-1]]. Protected by [[SP-1]], [[SP-2]], and [[CD-1]]. Risk: Low. Relevant threats: [[TS-001]], [[TS-005]].

- **Keyless Signing** — OIDC token handling and TLS across [[DF-2]] and [[DF-3]]. Protected by [[SP-5]] and [[CD-2]]. Risk: Low. Relevant threats: [[TS-002]], [[TS-009]].

- **Certificate Pinning** — MitM during updates targets [[DF-6]]. Protected by [[SP-5]] and [[CD-5]]. Risk: Very Low. Relevant threats: [[TS-006]], [[TS-010]].

- **Provenance/SBOM** — Substitution attacks target [[DF-9]] and [[DF-10]]. Protected by [[SP-3]] and [[CD-6]]. Risk: Low. Relevant threats: [[TS-003]], [[TS-012]].

---

## Security Controls Summary

### Cryptographic Controls ([[CD-1]], [[CD-3]], [[CD-4]])

These controls implement the core security properties [[SP-1]] through [[SP-3]] and [[SP-8]]:

- **Ed25519 signatures** (128-bit security) provide the foundational integrity and authenticity guarantee ([[REQ-1]]). The cryptographic strength satisfies [[CG-1]] (confidentiality of key material) and [[CG-2]] (integrity of signed artifacts).
- **SHA-256 hashing** ensures module integrity across all sections, implementing [[SP-3]].
- **Constant-time operations** via `ct_codecs` and `ed25519-compact` satisfy [[SP-8]] and prevent the timing side-channel threat ([[TS-005]]).
- **Zeroization of sensitive data** using the `zeroize` crate enforces [[SC-1]] and [[SC-2]], verified by [[CV-2]].

### Access Controls ([[CD-1]], [[CD-5]])

These controls enforce the system constraints [[SC-1]], [[SC-3]], and [[SC-5]]:

- **Secure file permissions** (0600) protect [[ASSET-001]] at rest, satisfying [[CR-1]].
- **Key ID matching** prevents signature substitution attacks ([[TS-011]]), enforcing [[SC-5]].
- **Certificate chain validation** verifies the full chain from leaf to root ([[ASSET-016]]), satisfying [[CR-5]].
- **Certificate pinning** for Sigstore endpoints protects against CA compromise ([[TS-006]]) and MitM attacks, using [[ASSET-010]].

### Audit Controls ([[CD-7]])

These controls implement the security property [[SP-7]] (non-repudiation) and satisfy [[CG-5]] (accountability):

- **Rekor transparency log** ([[ASSET-007]]) provides immutable, publicly verifiable records of all keyless signing events.
- **Merkle tree inclusion proofs** provide cryptographic evidence that a specific entry exists in the log.
- **Provenance embedding** links signed modules to their build context, satisfying [[REQ-5]] and supporting [[CG-7]] (supply chain integrity).
- **SBOM generation** provides dependency transparency for compliance with [[CG-8]].

### Availability Controls ([[CD-8]], [[CD-9]])

These controls implement the security property [[SP-4]] (availability) and satisfy [[CG-6]] (resilience):

- **Resource limits** (16 MB) prevent memory exhaustion from crafted inputs, enforcing [[SC-10]].
- **Bounded parsing** ensures all parser loops terminate, preventing [[TS-016]].
- **Fuzz testing** with six targets ([[CV-5]]) continuously validates the parser's robustness.
- **Fallback mechanisms** ensure Ed25519 signing remains available when Sigstore is unreachable, satisfying [[SC-11]].

---

## Compliance Evidence

This STRIDE analysis provides evidence for the following standards. Note that full compliance requires system-level TARA by the integrator. Each mapping references the cybersecurity goals ([[CG-1]] through [[CG-8]]) and requirements ([[CR-1]] through [[CR-11]]) that provide formal traceability.

- **Cryptographic strength** (ISO 21434): Ed25519 (128-bit) and SHA-256 provide component-level evidence for [[CG-1]] and [[CG-2]]. The cybersecurity requirement [[CR-3]] specifies the minimum cryptographic strength, and the design artifact [[DD-1]] documents the algorithm selection rationale.

- **Key management** (IEC 62443): Secure storage and zeroization satisfy [[CR-1]] and [[CR-2]]. The cybersecurity goal [[CG-1]] drives these requirements, and the verification [[CV-2]] confirms implementation correctness.

- **Audit logging** (ISO 27001): Rekor integration satisfies [[CG-5]] and [[CR-6]]. The design artifact [[DD-2]] documents the transparency log integration architecture.

- **Secure development** (SLSA L2+): Provenance and reproducible builds satisfy [[CG-7]] and [[CR-9]]. Build evidence is produced by the CI pipeline and embedded in signed artifacts.

- **Memory safety** (MISRA C++ equivalent): Rust's `#![forbid(unsafe_code)]` satisfies [[CR-10]] and provides design evidence for [[CG-3]] (software integrity). The verification [[CV-6]] confirms no unsafe code in the codebase.

For quantified risk assessment with ISO 21434 Attack Feasibility ratings, see `docs/security/RISK_ASSESSMENT.md`, which covers [[RA-001]] through [[RA-018]].

---

## Residual Risks

The following residual risks have been identified and accepted with documented rationale:

1. **HSM Integration Incomplete** ([[RR-1]]): Software key storage for [[ASSET-001]] is inherently less secure than hardware-backed storage because keys exist in host memory where they are vulnerable to extraction via memory dumps or cold-boot attacks. The cybersecurity requirement [[CR-1]] is only partially satisfied without HSM support.
   - *Mitigation*: HSM support is scaffolded in the architecture ([[DD-3]]) and tracked as a roadmap item. The zeroization controls ([[CD-1]]) reduce the exposure window.

2. **OCSP/CRL Not Implemented** ([[RR-2]]): Certificate revocation checking relies entirely on short certificate validity periods rather than active revocation checking. If a Fulcio certificate is compromised within its 10-minute validity window, there is no mechanism to revoke it before expiration.
   - *Mitigation*: Fulcio certificates have a 10-minute validity window, making the exposure window very small. The cybersecurity goal [[CG-4]] (timely revocation) is partially addressed by this short lifetime.

3. **Swap File Exposure** ([[RR-3]]): Key material in process memory could be paged to disk by the OS swap mechanism, persisting after zeroization. This is outside WSC's control and depends on the host OS configuration.
   - *Mitigation*: System integrators should use locked memory (`mlock`) in production deployments. The integration guidance references this requirement. The system constraint [[SC-1]] is satisfied at the application level; OS-level enforcement is the integrator's responsibility.

4. **OIDC Provider Trust** ([[RR-4]]): The keyless signing flow trusts the OIDC provider (GitHub, Google) to correctly authenticate the signer. A compromised OIDC provider could issue tokens for arbitrary identities.
   - *Mitigation*: OIDC providers are large, well-resourced organizations with strong security practices. The cybersecurity requirement [[CR-7]] specifies minimum OIDC provider security expectations.

5. **Sigstore Availability** ([[RR-5]]): The keyless signing flow depends on the availability of Fulcio, Rekor, and the OIDC provider. If any of these services experience an outage, keyless signing is unavailable.
   - *Mitigation*: Fallback to traditional Ed25519 signing ([[CD-9]]) ensures signing capability is never fully lost. The system constraint [[SC-11]] requires this fallback.

6. **Supply Chain of Dependencies** ([[RR-6]]): WSC depends on third-party Rust crates (`ed25519-compact`, `ct_codecs`, `zeroize`, etc.) whose security is outside WSC's direct control. A compromised dependency could undermine WSC's security guarantees.
   - *Mitigation*: Dependency auditing via `cargo audit`, minimal dependency surface, and SLSA provenance tracking ([[CG-7]]) reduce this risk. The cybersecurity verification [[CV-8]] includes dependency audit in the CI pipeline.

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-04 | WSC Team | Initial STRIDE analysis |
| 1.1 | 2026-01-06 | WSC Team | Clarified component vs system scope, added TARA integration guidance |
| 2.0 | 2026-03-15 | WSC Team | Converted to Rivet format with artifact cross-references, enriched narrative with STPA-Sec and cybersecurity traceability |
