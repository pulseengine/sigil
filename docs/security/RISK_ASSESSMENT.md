---
id: DOC-RISK-ASSESSMENT
title: Risk Assessment (ISO/SAE 21434)
type: specification
status: approved
tags: [security, risk-assessment, iso-21434, attack-feasibility]
---

# WSC Risk Assessment

This document provides quantified risk assessment for WSC using ISO/SAE 21434 Attack Feasibility (AF) methodology and explicit risk treatment decisions. It integrates STPA-Sec (Systems-Theoretic Process Analysis for Security) findings to provide a dual-lens view: traditional TARA identifies threats and rates their risk, while STPA-Sec identifies the underlying control structure failures that enable those threats. Together, they produce a comprehensive, traceable risk picture where every threat has a clear path from asset through analysis to mitigation.

## Document Information

- **Version**: 2.0
- **Date**: 2026-03-15
- **Classification**: Public
- **Review Cycle**: Quarterly
- **Standard Reference**: ISO/SAE 21434 Clauses 15.5-15.9
- **Complementary Analysis**: STPA-Sec control structure analysis

## Scope and Limitations

**Important**: This is a *component-level* risk assessment for WSC as a software library. It is NOT a system-level TARA.

System integrators must:

1. Perform their own TARA on their ITEM (vehicle ECU, IoT gateway, etc.)
2. Reference this assessment as evidence for the WSC component
3. Assess how WSC risks affect their overall system risk profile

## How STPA-Sec Complements TARA

Traditional TARA (as performed in this document) asks: "What can go wrong, how likely is it, and what is the impact?" It produces threat scenarios with attack feasibility ratings and risk levels. This is essential for prioritisation and regulatory compliance.

STPA-Sec asks a different question: "What control structure failures allow unsafe or insecure states?" Rather than enumerating attacks, it identifies hazards (unsafe states), unsafe control actions (UCAs), and the causal scenarios that produce them. This is essential for understanding *why* defences might fail and ensuring mitigations address root causes rather than symptoms.

In this document, each threat scenario includes cross-references to the STPA-Sec analysis, showing:

- Which **hazards** ([[H-1]] through [[H-5]]) the threat could trigger
- Which **unsafe control actions** ([[UCA-1]] through [[UCA-12]]) represent the control structure failure
- Which **attack scenarios** ([[AS-1]] through [[AS-10]]) model the adversarial exploitation path
- How **cybersecurity goals** ([[CG-1]] through [[CG-8]]), **requirements** ([[CR-1]] through [[CR-11]]), and **designs** ([[CD-1]] through [[CD-9]]) close the loop

This dual analysis ensures that mitigations are not merely reactive patches but structurally sound controls that address the underlying system dynamics.

---

## Attack Feasibility Rating Methodology

Per ISO/SAE 21434 Annex H, attack feasibility is calculated using five factors:

### Factor Scoring

| Factor | Description | Points |
|--------|-------------|--------|
| **Elapsed Time** | Time to identify/develop attack | 0 (<=1 day) to 19 (>=6 months) |
| **Specialist Expertise** | Attacker skill level required | 0 (Layman) to 8 (Expert) |
| **Knowledge of Item** | Target information needed | 0 (Public) to 11 (Critical) |
| **Window of Opportunity** | Access conditions | 0 (Unlimited) to 10 (Difficult) |
| **Equipment** | Attack tools required | 0 (Standard) to 9 (Bespoke) |

### AF Rating Thresholds

| Total Points | AF Rating | Interpretation |
|--------------|-----------|----------------|
| 0-9 | High | Attack is feasible for low-skilled attackers |
| 10-13 | Medium | Attack requires moderate skill/resources |
| 14-19 | Low | Attack requires significant skill/resources |
| 20+ | Very Low | Attack is impractical for most adversaries |

---

## Impact Rating Methodology

Per ISO/SAE 21434, impacts are rated on the SFOP scale:

| Category | Negligible | Moderate | Major | Severe |
|----------|------------|----------|-------|--------|
| **S**afety | No injury | Minor injury | Serious injury | Life-threatening |
| **F**inancial | <$1K | $1K-$100K | $100K-$1M | >$1M |
| **O**perational | No disruption | Minor disruption | Significant disruption | Complete failure |
| **P**rivacy | No PII | Limited PII | Bulk PII | Sensitive PII |

---

## Risk Determination Matrix

| AF Rating | Negligible Impact | Moderate Impact | Major Impact | Severe Impact |
|-----------|-------------------|-----------------|--------------|---------------|
| **High** | Low Risk | Medium Risk | High Risk | Critical Risk |
| **Medium** | Low Risk | Medium Risk | High Risk | High Risk |
| **Low** | Negligible Risk | Low Risk | Medium Risk | High Risk |
| **Very Low** | Negligible Risk | Negligible Risk | Low Risk | Medium Risk |

---

## Threat Scenarios and Risk Assessment

### TS-001: Private Key Theft

**Asset**: [[ASSET-001]] (Ed25519 Secret Key) -- the primary signing credential. Compromise of this asset enables an attacker to sign arbitrary WebAssembly modules that will pass verification, making it the highest-value target in the WSC key-based signing flow.

**Attack Goal**: Obtain secret key to sign unauthorized modules via file system access, memory dump, or insider threat.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-001]] (Ed25519 Secret Key)
- **Threat scenario**: [[TS-001]] (Private Key Theft)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- if the attacker signs malicious modules with the stolen key, the verifier has no way to distinguish them from legitimate ones
- **Unsafe control action**: [[UCA-1]] (Signing controller issues signature for unauthorised code) -- because from the system's perspective, the stolen key *is* the authorized signer
- **Attack scenario**: [[AS-1]] (Key material extraction through host compromise) -- models the attacker's path from gaining host access to extracting key material from the file system or process memory
- **Risk assessment**: [[RA-001]]
- **Cybersecurity goals**: [[CG-1]] (Authenticity of WASM modules), [[CG-4]] (Confidentiality of key material)
- **Cybersecurity requirements**: [[CR-1]] (Use approved cryptographic algorithms), [[CR-2]] (Protect cryptographic keys at rest)
- **Cybersecurity designs**: [[CD-1]] (Secure key storage with file permissions), [[CD-2]] (Zeroization of key material on drop), [[CD-3]] (HSM-backed key storage)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 week | 4 | Simple if access is gained |
| Specialist Expertise | Proficient | 4 | Understands file systems, crypto basics |
| Knowledge of Item | Restricted | 7 | Needs to know key location, format |
| Window of Opportunity | Moderate | 4 | Requires system access |
| Equipment | Standard | 0 | Standard file copy tools |
| **Total** | | **19** | |

**AF Rating**: Low (14-19 points)

**Impact Assessment**: The highest-impact category is Major. Safety impact is Moderate (malicious code could cause harm in automotive/industrial contexts). Financial impact is Major (breach of trust, re-signing cost, reputation damage). Operational impact is Major (must revoke key, re-sign all modules, update all verifiers). Privacy impact is Negligible (keys do not contain PII).

**Risk Determination**: AF Low x Impact Major = **Medium Risk** ([[RA-001]])

**Risk Treatment**: **Reduce** -- implement additional controls.

**Controls Applied**:

1. [[CD-1]] File permissions (0600) -- Implemented. Prevents unauthorized file system access to key material.
2. [[CD-2]] Zeroization on drop -- Implemented. Ensures key material is not recoverable from process memory after use.
3. [[CD-3]] HSM support -- Roadmap. When complete, eliminates software key storage entirely, reducing risk to Low.
4. [[CR-1]] Secure key generation -- Implemented. Uses cryptographically secure random number generation.

**STPA-Sec Insight**: The STPA-Sec analysis reveals that [[TS-001]] is fundamentally a loss-of-confidentiality failure in the control structure. The signing controller ([[CC-1]]) assumes exclusive access to key material, but this assumption breaks when the host environment is compromised. [[CD-3]] (HSM) addresses the root cause by removing the key from the software-accessible domain entirely, rather than merely adding protective layers around it. The system constraint [[SC-1]] (key material must never be exposed in plaintext outside a trusted boundary) cannot be fully satisfied with software-only storage.

**Residual Risk**: [[RR-1]] (Key theft via software storage) -- accepted as Low risk while HSM integration is pending. System integrators requiring higher assurance must provide their own HSM backend.

---

### TS-002: OIDC Token Theft (Keyless Signing)

**Asset**: [[ASSET-006]] (OIDC Identity Token) -- a short-lived JWT used for Sigstore authentication. Its ephemeral nature (approximately 10-minute lifetime) severely limits the attack window, but compromise during that window enables signing as the victim's identity.

**Attack Goal**: Steal token to sign as victim's identity, typically via CI environment compromise or log exposure.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-006]] (OIDC Identity Token)
- **Threat scenario**: [[TS-002]] (OIDC Token Theft)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- a stolen token enables signing as the victim identity
- **Unsafe control action**: [[UCA-3]] (Identity binding accepts compromised credential) -- the Fulcio CA cannot distinguish between a legitimate token holder and an attacker who has stolen the token
- **Attack scenario**: [[AS-3]] (CI environment credential exfiltration) -- models token theft from build pipelines where OIDC tokens are injected as environment variables
- **Risk assessment**: [[RA-002]]
- **Cybersecurity goals**: [[CG-1]] (Authenticity), [[CG-3]] (Non-repudiation of signing)
- **Cybersecurity requirements**: [[CR-2]] (Protect credentials), [[CR-5]] (Log security events)
- **Cybersecurity designs**: [[CD-2]] (Zeroization after use), [[CD-5]] (Rekor transparency logging)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 day | 0 | Token expires in approximately 10 minutes |
| Specialist Expertise | Proficient | 4 | CI/CD knowledge needed |
| Knowledge of Item | Sensitive | 11 | Token format, Sigstore flow |
| Window of Opportunity | Difficult | 10 | Only valid during signing |
| Equipment | Standard | 0 | Standard network tools |
| **Total** | | **25** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Moderate. Safety impact is Moderate (signed malicious module could cause harm). Financial impact is Moderate (limited window; Rekor provides audit trail for forensics). Operational impact is Moderate (identity is logged, investigation is possible). Privacy impact is Negligible (token itself is not PII).

**Risk Determination**: AF Very Low x Impact Moderate = **Negligible Risk** ([[RA-002]])

**Risk Treatment**: **Accept** -- risk is already negligible due to inherent design properties.

**Why Accept**: The token lifetime of approximately 10 minutes creates an extremely narrow attack window. Rekor provides an immutable audit trail that makes unauthorized use detectable after the fact. Identity is cryptographically bound to the signature via the Fulcio certificate chain, providing non-repudiation.

**STPA-Sec Insight**: The STPA-Sec analysis shows that the keyless signing flow is inherently more resilient than key-based signing because it eliminates persistent secret material. The control structure enforces temporal constraints (short-lived certificates, [[SC-3]]) and provides detection controls (transparency logging, [[SC-5]]) that compensate for the inability to fully prevent credential theft in CI environments. The combination of prevention (ephemeral tokens) and detection (Rekor) addresses both [[UCA-3]] and [[UCA-7]] (failure to detect unauthorized signing).

---

### TS-003: Module Tampering Post-Signature

**Asset**: [[ASSET-009]] (Signed WASM Module) -- the primary output of the WSC signing process. The entire purpose of WSC is to protect this asset's integrity.

**Attack Goal**: Modify a signed module to inject malicious code via transit interception or storage modification.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-009]] (Signed WASM Module)
- **Threat scenario**: [[TS-003]] (Module Tampering Post-Signature)
- **STPA-Sec hazard**: [[H-2]] (Tampered code accepted as valid) -- this is the core integrity hazard that WSC is designed to prevent
- **Unsafe control action**: [[UCA-4]] (Verification controller accepts modified module) -- would only occur if the signature verification algorithm itself is flawed
- **Attack scenario**: [[AS-4]] (In-transit module substitution) -- models an attacker intercepting and modifying a signed module during distribution
- **Risk assessment**: [[RA-003]]
- **Cybersecurity goals**: [[CG-2]] (Integrity of signed content)
- **Cybersecurity requirements**: [[CR-3]] (Verify software integrity)
- **Cybersecurity designs**: [[CD-4]] (SHA-256 content hashing bound to Ed25519 signature)

**AF Rating**: Not Applicable -- Attack is cryptographically infeasible. Any modification to the module invalidates the Ed25519 signature. The SHA-256 hash covers all module sections, and the attacker cannot forge a valid signature without the private key (128-bit security level).

**Impact Assessment**: None. Verification fails deterministically for tampered modules.

**Risk Determination**: AF N/A x Impact None = **No Risk** ([[RA-003]]). This threat scenario demonstrates that WSC's signature verification is a functioning security control, not a residual risk.

**Risk Treatment**: Not applicable. This is a security control, not a risk.

**STPA-Sec Insight**: The STPA-Sec analysis confirms that the verification control loop is well-designed: the controller ([[CC-2]], verification controller) receives the module and independently recomputes the hash, comparing it against the signature. The feedback path is direct (hash comparison), leaving no room for the control action to diverge from the process state. The system constraint [[SC-2]] (no module shall be accepted without valid signature verification) is enforced by the cryptographic binding itself, not by procedural controls. This is the strongest category of control in STPA terms because the laws of mathematics, not human procedures, enforce the constraint.

---

### TS-004: Trust Bundle Manipulation

**Asset**: [[ASSET-014]] (Airgapped Trust Bundle) -- the offline verification package that contains the set of trusted public keys. In airgapped environments such as automotive ECUs and industrial controllers, this bundle is the sole source of trust. Compromising it means compromising all verification decisions on the device.

**Attack Goal**: Inject a rogue public key to cause the device to accept malicious modules. The attack vector is compromising the provisioning process or substituting the bundle file.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-014]] (Airgapped Trust Bundle)
- **Threat scenario**: [[TS-004]] (Trust Bundle Manipulation)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic), [[H-3]] (Trust anchor compromised)
- **Unsafe control action**: [[UCA-5]] (Trust provisioning controller installs rogue key material) -- this occurs when the provisioning process lacks integrity verification
- **Attack scenario**: [[AS-5]] (Supply chain compromise of trust material during device provisioning) -- models an attacker who gains access to the provisioning pipeline and substitutes or augments the trust bundle
- **Risk assessment**: [[RA-004]]
- **Cybersecurity goals**: [[CG-1]] (Authenticity), [[CG-5]] (Availability of verification in offline contexts)
- **Cybersecurity requirements**: [[CR-3]] (Verify software integrity), [[CR-4]] (Implement defence in depth)
- **Cybersecurity designs**: [[CD-6]] (Signed trust bundles), [[CD-7]] (Certificate pinning for updates)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <=2 weeks | 7 | Bundle has integrity protection |
| Specialist Expertise | Expert | 8 | Cryptographic understanding needed |
| Knowledge of Item | Critical | 11 | Bundle format, provisioning process |
| Window of Opportunity | Moderate | 4 | During device provisioning |
| Equipment | Specialized | 6 | Provisioning environment access |
| **Total** | | **36** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Severe. Safety impact is Severe (complete trust bypass in safety-critical device). Financial impact is Major (fleet-wide compromise potential if provisioning is shared). Operational impact is Severe (all verification decisions on the device become untrustworthy). Privacy impact is Moderate (depends on module purpose).

**Risk Determination**: AF Very Low x Impact Severe = **Medium Risk** ([[RA-004]])

**Risk Treatment**: **Reduce** -- add additional integrity controls at the bundle and provisioning levels.

**Controls Applied**:

1. [[CD-6]] Bundle is signed -- Implemented. The trust bundle itself is cryptographically signed, creating a chicken-and-egg problem for the attacker (they need a trusted key to inject a trusted key).
2. [[CD-7]] Certificate pinning for updates -- Implemented. Prevents man-in-the-middle substitution of bundle updates.
3. [[CR-4]] Secure provisioning guidance -- Documented. Provides integrators with procedures for secure initial provisioning.

**STPA-Sec Insight**: The STPA-Sec analysis reveals that [[TS-004]] targets the *trust establishment* phase, which occurs before the normal control loop is operational. This is a classic STPA finding: the system is most vulnerable during initialization, when the control structure assumptions (e.g., "the trust bundle is authentic") have not yet been verified. The system constraint [[SC-4]] (trust material must be authenticated before use) addresses this, but enforcement depends on the integrator's provisioning process -- WSC can sign the bundle ([[CD-6]]) but cannot control how the bundle reaches the device. This is why the residual risk ([[RR-2]]) is assigned to the integrator.

**Residual Risk**: [[RR-2]] (Trust bundle provisioning integrity) -- the security of the initial provisioning channel is the integrator's responsibility. WSC provides the cryptographic mechanism (signed bundles) but cannot enforce the physical or procedural security of the provisioning environment.

---

### TS-005: Timing Side-Channel Attack

**Asset**: [[ASSET-001]] (Ed25519 Secret Key), [[ASSET-003]] (ECDSA P-256 Ephemeral Key) -- cryptographic key material that could be extracted through statistical analysis of operation timing.

**Attack Goal**: Extract key material via timing analysis by performing repeated signing or verification operations and measuring execution time variations.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-001]], [[ASSET-003]] (Secret Keys)
- **Threat scenario**: [[TS-005]] (Timing Side-Channel Attack)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- if key material is extracted, the attacker can forge signatures
- **Unsafe control action**: [[UCA-6]] (Cryptographic controller leaks key material through observable behaviour) -- a non-constant-time implementation creates an information side channel
- **Attack scenario**: [[AS-6]] (Statistical timing analysis of cryptographic operations) -- models an attacker with repeated access to the signing interface who correlates input patterns with execution timing
- **Risk assessment**: [[RA-005]]
- **Cybersecurity goals**: [[CG-4]] (Confidentiality of key material)
- **Cybersecurity requirements**: [[CR-1]] (Use approved cryptographic algorithms with side-channel resistance)
- **Cybersecurity designs**: [[CD-8]] (Constant-time cryptographic operations)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | >=6 months | 19 | Statistical analysis, noise filtering |
| Specialist Expertise | Expert | 8 | Cryptographic side-channel research |
| Knowledge of Item | Sensitive | 11 | Algorithm internals |
| Window of Opportunity | Easy | 1 | Need repeated access to signing |
| Equipment | Specialized | 6 | High-precision timing equipment |
| **Total** | | **45** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Major. Safety impact is Major (key compromise enables malicious signing). Financial impact is Major (key replacement, re-signing cost across all consumers). Operational impact is Major (trust revocation required across all verifiers). Privacy impact is Negligible (keys do not contain PII).

**Risk Determination**: AF Very Low x Impact Major = **Low Risk** ([[RA-005]])

**Risk Treatment**: **Reduce** -- use constant-time operations throughout.

**Controls Applied**:

1. [[CD-8]] ct_equal() for cryptographic comparisons -- Implemented (PR #26). Ensures that comparison operations do not leak information through timing.
2. [[CD-8]] ed25519-compact uses constant-time operations -- Implemented. The underlying library performs scalar multiplication in constant time.
3. [[CD-8]] p256 crate uses constant-time operations -- Implemented. ECDSA operations use the RustCrypto constant-time backend.

**STPA-Sec Insight**: The STPA-Sec analysis classifies this as a *feedback channel* vulnerability. In the control structure model, the signing controller's internal operations create an observable feedback path (timing) that was not intended as part of the control interface. The system constraint [[SC-6]] (cryptographic operations must not create observable side channels) is enforced at the implementation level through library selection and explicit constant-time primitives. Unlike many threats where the control structure itself is at fault, here the control logic is correct but the *implementation* leaks information. This distinction matters for mitigation: the fix is at the code level (constant-time libraries), not the architecture level.

---

### TS-006: Certificate Authority Compromise (Fulcio)

**Asset**: [[ASSET-007]] (Fulcio Certificate) -- the ephemeral signing certificate issued by the Fulcio CA as part of the Sigstore keyless signing flow. Compromise of Fulcio would enable an attacker to issue certificates for arbitrary identities.

**Attack Goal**: Issue rogue certificates for any identity, enabling signing as any user, via Fulcio infrastructure compromise.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-007]] (Fulcio Certificate)
- **Threat scenario**: [[TS-006]] (Certificate Authority Compromise)
- **STPA-Sec hazard**: [[H-3]] (Trust anchor compromised) -- Fulcio is a root of trust for keyless signing
- **Unsafe control action**: [[UCA-8]] (Certificate issuance controller issues certificate without valid identity proof) -- this occurs when the CA's identity verification is bypassed
- **Attack scenario**: [[AS-7]] (Nation-state compromise of Sigstore infrastructure) -- models a sophisticated attacker with resources to penetrate Sigstore's hardened infrastructure
- **Risk assessment**: [[RA-006]]
- **Cybersecurity goals**: [[CG-1]] (Authenticity), [[CG-3]] (Non-repudiation)
- **Cybersecurity requirements**: [[CR-4]] (Implement defence in depth), [[CR-5]] (Log security events)
- **Cybersecurity designs**: [[CD-7]] (Certificate pinning), [[CD-5]] (Rekor transparency logging), [[CD-9]] (Fallback to key-based signing)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | >=6 months | 19 | Sigstore security hardening |
| Specialist Expertise | Expert | 8 | Infrastructure security expertise |
| Knowledge of Item | Critical | 11 | Fulcio internals |
| Window of Opportunity | Difficult | 10 | Requires Sigstore infrastructure access |
| Equipment | Bespoke | 9 | Nation-state level resources |
| **Total** | | **57** | |

**AF Rating**: Very Low (20+ points -- maximum difficulty)

**Impact Assessment**: The highest-impact category is Severe. Safety impact is Severe (arbitrary signing as any identity). Financial impact is Severe (trust model completely broken for keyless signing). Operational impact is Severe (all keyless signatures become suspect). Privacy impact is Moderate (identity spoofing).

**Risk Determination**: AF Very Low x Impact Severe = **Medium Risk** ([[RA-006]])

**Risk Treatment**: **Transfer** + **Reduce** -- rely on Sigstore's security programme (transfer) while adding local detection and fallback controls (reduce).

**Controls Applied**:

1. [[CD-7]] Certificate pinning for Fulcio -- Implemented. Prevents acceptance of certificates from rogue CAs even if TLS is compromised.
2. [[CD-5]] Rekor transparency log -- Detection control. Any rogue certificate issuance would be logged and detectable through transparency log monitoring.
3. Short-lived certificates (10 min) -- Inherent design. Limits the useful lifetime of any rogue certificate.
4. [[CD-9]] Fallback to key-based signing -- Implemented. If Sigstore trust is questioned, signers can revert to Ed25519 key-based signing which does not depend on Fulcio.

**STPA-Sec Insight**: The STPA-Sec analysis identifies this as a *trust boundary* failure. The WSC control structure depends on Fulcio as an external controller ([[CC-8]]) that is outside WSC's control authority. The system constraint [[SC-7]] (external trust dependencies must have fallback mechanisms) is addressed by [[CD-9]] (key-based fallback). The STPA-Sec finding that WSC cannot enforce constraints on external infrastructure motivated the architectural decision to never make keyless signing the *only* signing mode -- [[FEAT-1]] (Ed25519 signing) and [[FEAT-2]] (keyless signing) are independent features, ensuring that compromise of one does not eliminate the other.

**Residual Risk**: [[RR-3]] (Sigstore infrastructure dependency) -- accepted as Medium Risk, mitigated by the availability of key-based fallback. Integrators in high-assurance environments should prefer key-based signing with HSM-backed keys.

---

### TS-007: Signature Section Stripping

**Asset**: [[ASSET-010]] (Signature Section) -- the custom WASM section containing the Ed25519 signature and metadata.

**Attack Goal**: Remove the signature section from a signed module so that it appears to be an unsigned module, bypassing verification if the consumer does not enforce signature requirements.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-010]] (Signature Section)
- **Threat scenario**: [[TS-007]] (Signature Section Stripping)
- **STPA-Sec hazard**: [[H-4]] (Verification bypassed entirely) -- if the module appears unsigned, verification may not be invoked
- **Unsafe control action**: [[UCA-9]] (Verification controller does not execute because no signature is present) -- this is a control action *omission*, the most common UCA type in STPA
- **Attack scenario**: [[AS-8]] (Module stripping to bypass verification policy) -- models an attacker who removes the signature section and relies on the consumer accepting unsigned modules
- **Risk assessment**: [[RA-007]]
- **Cybersecurity goals**: [[CG-2]] (Integrity of signed content)
- **Cybersecurity requirements**: [[CR-3]] (Verify software integrity), [[CR-7]] (Enforce signature presence policy)
- **Cybersecurity designs**: [[CD-4]] (Signature verification), [[CD-6]] (Trust bundle with enforcement policy)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 day | 0 | Trivial binary manipulation |
| Specialist Expertise | Layman | 0 | WASM section removal is well-documented |
| Knowledge of Item | Public | 0 | WASM custom section format is public |
| Window of Opportunity | Unlimited | 0 | Can be done offline at any time |
| Equipment | Standard | 0 | Standard binary editing tools |
| **Total** | | **0** | |

**AF Rating**: High (0-9 points)

**Impact Assessment**: Impact depends entirely on whether the consumer enforces signature requirements. If the consumer accepts unsigned modules, impact is Severe (complete bypass). If the consumer rejects unsigned modules, impact is None (attack fails). For this assessment, we assume the consumer *should* enforce but *might not*, yielding an impact of Major.

**Risk Determination**: AF High x Impact Major = **High Risk** ([[RA-007]])

**Risk Treatment**: **Reduce** -- provide enforcement mechanisms and clear guidance.

**Controls Applied**:

1. [[CD-6]] Trust bundle includes enforcement policy -- Implemented. The airgapped trust bundle specifies whether unsigned modules are acceptable.
2. [[CR-7]] Documentation of signature enforcement -- Implemented. Integration guidance clearly states that consumers must reject unsigned modules in security-critical contexts.
3. [[CD-4]] Verification API returns clear unsigned status -- Implemented. The verification result distinguishes between "unsigned" and "signature invalid," enabling consumers to enforce policy.

**STPA-Sec Insight**: This is a paradigmatic STPA finding. Traditional threat analysis focuses on attacks that *defeat* controls, but STPA identifies the more insidious case: attacks that *avoid* controls entirely. [[UCA-9]] (verification not performed) is a control action omission -- the control exists but is never invoked. The system constraint [[SC-8]] (all modules must undergo verification before execution) cannot be enforced by WSC alone; it requires the consumer runtime to invoke verification. This is why [[RR-4]] is assigned to the integrator.

**Residual Risk**: [[RR-4]] (Consumer enforcement of signature requirements) -- WSC provides the verification mechanism and policy infrastructure, but cannot force consumers to invoke verification. This is a shared responsibility.

---

### TS-008: Rollback Attack (Module Downgrade)

**Asset**: [[ASSET-009]] (Signed WASM Module) -- specifically, the version integrity of the module.

**Attack Goal**: Substitute a newer signed module with an older signed version that contains known vulnerabilities. Both versions have valid signatures, so the attack exploits the absence of version ordering enforcement.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-009]] (Signed WASM Module)
- **Threat scenario**: [[TS-008]] (Rollback Attack)
- **STPA-Sec hazard**: [[H-5]] (Outdated or revoked module accepted as current)
- **Unsafe control action**: [[UCA-10]] (Verification controller accepts valid-but-outdated module) -- the verification succeeds because the signature is valid, but the module is not the intended version
- **Attack scenario**: [[AS-9]] (Version rollback through module substitution) -- models an attacker who replaces a patched module with a legitimately signed older version
- **Risk assessment**: [[RA-008]]
- **Cybersecurity goals**: [[CG-2]] (Integrity of signed content)
- **Cybersecurity requirements**: [[CR-8]] (Support version ordering and rollback detection)
- **Cybersecurity designs**: [[CD-4]] (Signature verification), [[CD-5]] (Rekor timestamp-based ordering)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 week | 4 | Need access to older signed module |
| Specialist Expertise | Proficient | 4 | Understanding of versioning mechanisms |
| Knowledge of Item | Restricted | 7 | Knowledge of module distribution |
| Window of Opportunity | Moderate | 4 | Need access to distribution channel |
| Equipment | Standard | 0 | Standard file manipulation |
| **Total** | | **19** | |

**AF Rating**: Low (14-19 points)

**Impact Assessment**: The highest-impact category is Major. Safety impact is Major (vulnerable code executed in safety-critical context). Financial impact is Moderate (incident response for known vulnerability). Operational impact is Major (must detect and remediate rollback). Privacy impact is Negligible.

**Risk Determination**: AF Low x Impact Major = **Medium Risk** ([[RA-008]])

**Risk Treatment**: **Reduce** -- provide version ordering mechanisms.

**Controls Applied**:

1. [[CD-5]] Provenance embedding includes version info -- Implemented. SLSA provenance statements include version metadata.
2. Composition manifest tracks dependencies -- Implemented. Multi-module compositions include version information.
3. Airgapped verifier supports rollback detection -- Implemented. The trust bundle can specify minimum version requirements.

**STPA-Sec Insight**: The STPA-Sec analysis reveals that signature verification alone ([[SC-2]]) is necessary but not sufficient for version integrity. The system needs a *temporal ordering* mechanism -- a way to determine that version N+1 supersedes version N. This is a missing control action in the STPA sense: the controller can verify authenticity but cannot verify currency. The Rekor transparency log ([[CD-5]]) provides timestamps that can serve as an ordering mechanism, but only in online contexts. For airgapped environments, the trust bundle's version policy must be used instead.

---

### TS-009: Memory Residue Attack

**Asset**: [[ASSET-001]] (Ed25519 Secret Key) -- key material that may persist in process memory after use.

**Attack Goal**: Recover key material from process memory, swap files, or core dumps after the signing operation has completed.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-001]] (Ed25519 Secret Key)
- **Threat scenario**: [[TS-009]] (Memory Residue Attack)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- recovered key enables malicious signing
- **Unsafe control action**: [[UCA-1]] (Signing controller issues signature for unauthorised code) -- same as TS-001, because the root cause (key compromise) produces the same outcome
- **Attack scenario**: [[AS-1]] (Key material extraction) -- variant path through memory forensics rather than file system access
- **Risk assessment**: [[RA-009]]
- **Cybersecurity goals**: [[CG-4]] (Confidentiality of key material)
- **Cybersecurity requirements**: [[CR-2]] (Protect cryptographic keys)
- **Cybersecurity designs**: [[CD-2]] (Zeroization on drop)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 month | 10 | Memory forensics and analysis |
| Specialist Expertise | Expert | 8 | Memory forensics expertise |
| Knowledge of Item | Sensitive | 11 | Memory layout knowledge |
| Window of Opportunity | Moderate | 4 | Need access to memory dump or swap |
| Equipment | Specialized | 6 | Memory forensics tools |
| **Total** | | **39** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: Same as [[TS-001]] -- Major impact if key material is recovered.

**Risk Determination**: AF Very Low x Impact Major = **Low Risk** ([[RA-009]])

**Risk Treatment**: **Reduce** -- zeroize all sensitive memory.

**Controls Applied**:

1. [[CD-2]] Zeroization on drop via `zeroize` crate -- Implemented. All secret key types implement `ZeroizeOnDrop`.
2. `#![forbid(unsafe_code)]` -- Implemented. Prevents memory bugs that could bypass zeroization.
3. Rust ownership model -- Inherent. Ensures key material has a single owner with deterministic drop.

**STPA-Sec Insight**: This threat is related to [[TS-001]] but exploits a different phase of the key lifecycle. [[TS-001]] targets key material *at rest* (on disk), while [[TS-009]] targets key material *after use* (in memory). The STPA-Sec analysis groups both under the same hazard ([[H-1]]) but different causal scenarios, leading to complementary controls: [[CD-1]] (file permissions) for at-rest protection and [[CD-2]] (zeroization) for in-memory protection. The residual risk ([[RR-1]]) is shared with [[TS-001]].

---

### TS-010: Malformed Module Denial of Service

**Asset**: [[ASSET-008]] (Unsigned WASM Module) -- the input to the signing or verification process.

**Attack Goal**: Cause resource exhaustion or infinite processing by providing a crafted malformed WASM module, rendering the signing or verification service unavailable.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-008]] (Unsigned WASM Module)
- **Threat scenario**: [[TS-010]] (Malformed Module DoS)
- **STPA-Sec hazard**: [[H-4]] (Verification bypassed entirely) -- if the verifier crashes, verification cannot occur
- **Unsafe control action**: [[UCA-11]] (Parser controller fails to bound resource consumption) -- the parser accepts arbitrarily large or deeply nested structures
- **Attack scenario**: [[AS-10]] (Resource exhaustion through crafted input) -- models an attacker who submits a specially crafted WASM module designed to exhaust memory or CPU
- **Risk assessment**: [[RA-010]]
- **Cybersecurity goals**: [[CG-5]] (Availability of verification)
- **Cybersecurity requirements**: [[CR-9]] (Enforce resource limits on input processing)
- **Cybersecurity designs**: [[CD-4]] (Bounded parsing with resource limits)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 day | 0 | Trivial to craft malformed binary |
| Specialist Expertise | Proficient | 4 | WASM binary format knowledge |
| Knowledge of Item | Restricted | 7 | Parser implementation details |
| Window of Opportunity | Easy | 1 | Need to submit module for processing |
| Equipment | Standard | 0 | Standard tools |
| **Total** | | **12** | |

**AF Rating**: Medium (10-13 points)

**Impact Assessment**: The highest-impact category is Moderate. Safety impact is Negligible (no code execution, only service disruption). Financial impact is Negligible (service restart resolves). Operational impact is Moderate (signing/verification temporarily unavailable). Privacy impact is Negligible.

**Risk Determination**: AF Medium x Impact Moderate = **Medium Risk** ([[RA-010]])

**Risk Treatment**: **Reduce** -- enforce strict resource limits.

**Controls Applied**:

1. 16 MB allocation limit -- Implemented. Prevents memory exhaustion.
2. Bounded varint parsing -- Implemented. Prevents infinite loops on malformed length fields.
3. Maximum section counts enforced -- Implemented. Prevents combinatorial explosion.
4. Fuzz testing (6 targets) -- Implemented. Continuously discovers new crash inputs.

**STPA-Sec Insight**: The STPA-Sec analysis classifies this as an *inadequate control algorithm* failure. The parser is a controller that must make decisions about how much resource to allocate based on untrusted input. Without explicit bounds, the parser's control algorithm trusts the input to be well-formed -- a classic STPA violation of the principle that controllers must not trust the process they control. The system constraints [[SC-9]] (input processing must be bounded) and [[SC-10]] (untrusted input must not control resource allocation) are enforced through explicit limits and fuzz testing.

---

### TS-011: Man-in-the-Middle on Sigstore Communication

**Asset**: [[ASSET-015]] (Certificate Pins), [[ASSET-007]] (Fulcio Certificate) -- the TLS channel and certificate validation protecting communication with Sigstore infrastructure.

**Attack Goal**: Intercept and modify communication between WSC and Sigstore services (Fulcio, Rekor) to issue rogue certificates or suppress transparency log entries.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-015]] (Certificate Pins), [[ASSET-007]] (Fulcio Certificate)
- **Threat scenario**: [[TS-011]] (MitM on Sigstore Communication)
- **STPA-Sec hazard**: [[H-3]] (Trust anchor compromised) -- if TLS is subverted, the channel to the trust anchor (Fulcio) is no longer authenticated
- **Unsafe control action**: [[UCA-8]] (Certificate issuance controller issues certificate without valid identity proof) -- from WSC's perspective, a MitM could impersonate Fulcio
- **Attack scenario**: [[AS-7]] (variant: network-level interception rather than infrastructure compromise) -- lower sophistication than full Fulcio compromise but same trust boundary
- **Risk assessment**: [[RA-011]]
- **Cybersecurity goals**: [[CG-1]] (Authenticity), [[CG-6]] (Channel integrity for Sigstore communication)
- **Cybersecurity requirements**: [[CR-4]] (Implement defence in depth), [[CR-10]] (Enforce TLS certificate validation)
- **Cybersecurity designs**: [[CD-7]] (Certificate pinning for Sigstore endpoints)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <=2 weeks | 7 | TLS interception setup |
| Specialist Expertise | Expert | 8 | TLS/PKI expertise |
| Knowledge of Item | Sensitive | 11 | Sigstore API endpoints, pinning implementation |
| Window of Opportunity | Moderate | 4 | Need network position |
| Equipment | Specialized | 6 | TLS interception proxy |
| **Total** | | **36** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Major. Safety impact is Moderate (could enable rogue certificate issuance). Financial impact is Moderate (limited to keyless signing flow). Operational impact is Major (keyless signing trust compromised). Privacy impact is Negligible.

**Risk Determination**: AF Very Low x Impact Major = **Low Risk** ([[RA-011]])

**Risk Treatment**: **Reduce** -- certificate pinning and TLS enforcement.

**Controls Applied**:

1. [[CD-7]] Certificate pinning for Fulcio and Rekor -- Implemented. SHA-256 pins of known Sigstore certificates are checked during TLS handshake.
2. [[CR-10]] TLS certificate validation -- Implemented. Standard TLS validation plus pinning provides defence in depth.
3. [[CD-9]] Fallback to key-based signing -- Implemented. If network trust is uncertain, key-based signing avoids Sigstore entirely.

**STPA-Sec Insight**: This threat targets the communication channel between the WSC controller and the external Sigstore controller. In STPA terms, this is a *feedback path* attack: the attacker corrupts the information flowing from Fulcio back to WSC, causing WSC to accept a rogue certificate as legitimate. Certificate pinning ([[CD-7]]) creates an independent verification path that does not rely solely on the TLS PKI chain, providing the kind of redundant feedback that STPA recommends for critical control actions.

**Residual Risk**: [[RR-3]] (Sigstore infrastructure dependency) -- shared with [[TS-006]]. The ureq HTTP client has a known limitation regarding certificate pinning enforcement (tracked as ureq #1087).

---

### TS-012: Key ID Collision / Confusion

**Asset**: [[ASSET-002]] (Ed25519 Public Key), [[ASSET-019]] (Key ID Mappings) -- the mapping between logical key identifiers and actual key material.

**Attack Goal**: Exploit key ID collisions or ambiguous key resolution to cause verification against the wrong public key, either accepting a malicious module or rejecting a legitimate one.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-002]] (Ed25519 Public Key), [[ASSET-019]] (Key ID Mappings)
- **Threat scenario**: [[TS-012]] (Key ID Collision)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- if the wrong key is selected, a module signed by the attacker could pass verification
- **Unsafe control action**: [[UCA-12]] (Key selection controller resolves ambiguous key ID to wrong key) -- the control algorithm fails to produce a deterministic, correct key selection
- **Attack scenario**: [[AS-2]] (Key confusion through identifier manipulation) -- models an attacker who registers a key with an ID that collides with or shadows an existing trusted key
- **Risk assessment**: [[RA-012]]
- **Cybersecurity goals**: [[CG-1]] (Authenticity)
- **Cybersecurity requirements**: [[CR-11]] (Ensure unique and unambiguous key identification)
- **Cybersecurity designs**: [[CD-1]] (Key management with unique IDs)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 month | 10 | Analysis of key ID generation scheme |
| Specialist Expertise | Proficient | 4 | Cryptographic basics |
| Knowledge of Item | Restricted | 7 | Key ID format and resolution logic |
| Window of Opportunity | Moderate | 4 | Need to provision a colliding key |
| Equipment | Standard | 0 | Standard tools |
| **Total** | | **25** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Major. Safety impact is Major (wrong key selection could accept malicious module). Financial impact is Moderate (key re-provisioning). Operational impact is Major (trust confusion across fleet). Privacy impact is Negligible.

**Risk Determination**: AF Very Low x Impact Major = **Low Risk** ([[RA-012]])

**Risk Treatment**: **Reduce** -- ensure unique key identification.

**Controls Applied**:

1. [[CD-1]] Key IDs derived from public key hash -- Implemented. Key IDs are deterministically derived from the public key material, making accidental collisions cryptographically improbable.
2. [[CR-11]] Explicit key matching in verification -- Implemented. The verifier resolves key IDs unambiguously and fails if multiple keys match.

**STPA-Sec Insight**: This threat exploits the *model* that the verification controller maintains of the trust store. In STPA terms, the controller's process model (which key corresponds to which ID) can become inconsistent with reality. The system constraint [[SC-11]] (key identification must be deterministic and collision-resistant) ensures that the controller's model cannot be corrupted through ID manipulation.

---

### TS-013: Provenance Forgery

**Asset**: [[ASSET-017]] (In-toto Provenance Statement) -- the SLSA provenance attestation embedded in signed modules.

**Attack Goal**: Forge or tamper with provenance metadata to misrepresent the origin, build process, or dependencies of a signed module.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-017]] (In-toto Provenance Statement)
- **Threat scenario**: [[TS-013]] (Provenance Forgery)
- **STPA-Sec hazard**: [[H-2]] (Tampered code accepted as valid) -- provenance misrepresentation is a form of integrity violation
- **Unsafe control action**: [[UCA-4]] (Verification controller accepts module with forged provenance) -- if provenance is not covered by the signature, it can be modified independently
- **Attack scenario**: [[AS-4]] (variant: metadata tampering rather than code tampering) -- exploits the boundary between signed content and metadata
- **Risk assessment**: [[RA-013]]
- **Cybersecurity goals**: [[CG-2]] (Integrity of signed content), [[CG-7]] (Supply chain transparency)
- **Cybersecurity requirements**: [[CR-3]] (Verify software integrity), [[CR-8]] (Support provenance verification)
- **Cybersecurity designs**: [[CD-4]] (Signature covers provenance sections), [[CD-5]] (Rekor transparency logging)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 week | 4 | Provenance format is documented |
| Specialist Expertise | Proficient | 4 | Build system and attestation knowledge |
| Knowledge of Item | Restricted | 7 | Provenance embedding format |
| Window of Opportunity | Moderate | 4 | Need access to module before distribution |
| Equipment | Standard | 0 | Standard tools |
| **Total** | | **19** | |

**AF Rating**: Low (14-19 points)

**Impact Assessment**: The highest-impact category is Major. Safety impact is Moderate (incorrect provenance could hide supply chain compromise). Financial impact is Major (supply chain trust violation). Operational impact is Major (provenance-based policies produce wrong decisions). Privacy impact is Negligible.

**Risk Determination**: AF Low x Impact Major = **Medium Risk** ([[RA-013]])

**Risk Treatment**: **Reduce** -- include provenance in signature scope.

**Controls Applied**:

1. [[CD-4]] Provenance sections included in signature hash -- Implemented. The SHA-256 hash covers all custom sections including provenance, so any modification invalidates the signature.
2. [[CD-5]] Rekor provides independent provenance record -- Implemented. The transparency log stores provenance metadata independently of the module.

---

### TS-014: Rekor Transparency Log Unavailability

**Asset**: [[ASSET-008]] (Rekor Entry UUID) -- the reference to the transparency log entry required for keyless signature verification.

**Attack Goal**: Deny access to Rekor to prevent verification of keyless signatures, either through service disruption or network blocking.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-008]] (Rekor Entry UUID)
- **Threat scenario**: [[TS-014]] (Rekor Unavailability)
- **STPA-Sec hazard**: [[H-4]] (Verification bypassed entirely) -- if Rekor is unavailable, keyless verification may fail or be skipped
- **Unsafe control action**: [[UCA-9]] (Verification controller does not execute due to infrastructure unavailability)
- **Attack scenario**: [[AS-10]] (variant: service denial through network disruption) -- models an attacker who blocks network access to Rekor
- **Risk assessment**: [[RA-014]]
- **Cybersecurity goals**: [[CG-5]] (Availability of verification)
- **Cybersecurity requirements**: [[CR-6]] (Support offline/degraded verification), [[CR-9]] (Handle infrastructure failures gracefully)
- **Cybersecurity designs**: [[CD-9]] (Fallback to key-based verification), [[CD-6]] (Airgapped trust bundles)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 day | 0 | Simple network blocking |
| Specialist Expertise | Proficient | 4 | Network configuration knowledge |
| Knowledge of Item | Public | 0 | Rekor endpoints are public |
| Window of Opportunity | Moderate | 4 | Need network position or DNS control |
| Equipment | Standard | 0 | Firewall rules or DNS manipulation |
| **Total** | | **8** | |

**AF Rating**: High (0-9 points)

**Impact Assessment**: The highest-impact category is Moderate. Safety impact is Negligible (no code execution impact, only verification availability). Financial impact is Negligible (temporary inconvenience). Operational impact is Moderate (keyless verification temporarily unavailable). Privacy impact is Negligible.

**Risk Determination**: AF High x Impact Moderate = **Medium Risk** ([[RA-014]])

**Risk Treatment**: **Reduce** -- provide offline verification alternatives.

**Controls Applied**:

1. [[CD-9]] Fallback to key-based signing and verification -- Implemented. Eliminates Rekor dependency entirely.
2. [[CD-6]] Airgapped trust bundles for offline verification -- Implemented. Designed specifically for environments without network access.
3. [[FEAT-5]] Graceful degradation -- Implemented. WSC reports Rekor unavailability clearly and suggests alternatives.

**STPA-Sec Insight**: This threat highlights a fundamental STPA principle: controllers must not depend on feedback paths that can be severed. The keyless verification controller depends on Rekor as a feedback path for inclusion proof verification. The system constraint [[SC-7]] (external trust dependencies must have fallback mechanisms) directly motivates the airgapped verification design ([[FEAT-4]]) and key-based fallback ([[CD-9]]).

---

### TS-015: WASM Parser Code Execution

**Asset**: [[ASSET-008]] (Unsigned WASM Module), [[ASSET-020]] (System Integrity) -- a crafted module that exploits a parser vulnerability to achieve arbitrary code execution.

**Attack Goal**: Achieve code execution on the host system by providing a specially crafted WASM module that triggers a parser vulnerability (buffer overflow, use-after-free, etc.).

**Traceability Chain**:

- **Asset at risk**: [[ASSET-008]] (Unsigned WASM Module), [[ASSET-020]] (System Integrity)
- **Threat scenario**: [[TS-015]] (WASM Parser Code Execution)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- code execution could bypass all controls
- **Unsafe control action**: [[UCA-11]] (Parser controller fails to validate input bounds) -- a memory safety violation in the parser
- **Attack scenario**: [[AS-10]] (variant: code execution through crafted input) -- the most severe outcome of parser exploitation
- **Risk assessment**: [[RA-015]]
- **Cybersecurity goals**: [[CG-8]] (Parser robustness against adversarial input)
- **Cybersecurity requirements**: [[CR-9]] (Enforce resource limits), [[CR-1]] (Memory-safe implementation)
- **Cybersecurity designs**: [[CD-4]] (Bounded parsing), [[CD-8]] (Rust memory safety guarantees)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | >=6 months | 19 | Rust memory safety makes exploitation extremely difficult |
| Specialist Expertise | Expert | 8 | Rust exploitation expertise |
| Knowledge of Item | Sensitive | 11 | Parser internals |
| Window of Opportunity | Easy | 1 | Need to submit module for parsing |
| Equipment | Specialized | 6 | Fuzzing infrastructure, exploit development |
| **Total** | | **45** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Severe. Safety impact is Severe (arbitrary code execution). Financial impact is Major (full system compromise). Operational impact is Severe (complete system integrity loss). Privacy impact is Major (access to all system data).

**Risk Determination**: AF Very Low x Impact Severe = **Medium Risk** ([[RA-015]])

**Risk Treatment**: **Reduce** -- defence in depth through language safety, coding practices, and continuous testing.

**Controls Applied**:

1. `#![forbid(unsafe_code)]` -- Implemented. Eliminates the most common classes of memory safety vulnerabilities (buffer overflows, use-after-free, double-free).
2. Rust ownership model -- Inherent. Compile-time enforcement of memory safety without runtime overhead.
3. Comprehensive fuzz testing (6 targets) -- Implemented. Continuously discovers edge cases in parser logic.
4. Bounds checking on all reads -- Implemented. All array and slice accesses are bounds-checked.

**STPA-Sec Insight**: The STPA-Sec analysis identifies parser code execution as a *control algorithm* failure where the parser's decision logic is subverted by adversarial input. The Rust language's memory safety guarantees ([[CD-8]]) provide a structural defence: the control algorithm cannot be corrupted through memory manipulation because memory corruption is prevented at the language level. This is an example of using system design (language choice) to eliminate entire classes of control failures, which is the most effective STPA mitigation strategy.

**Residual Risk**: [[RR-5]] (Logic bugs in parser despite memory safety) -- Rust prevents memory corruption but not logic errors. Fuzz testing addresses this residual risk continuously.

---

### TS-016: Supply Chain Attack on WSC Dependencies

**Asset**: [[ASSET-018]] (SBOM/CycloneDX), [[ASSET-020]] (System Integrity) -- the integrity of WSC's own dependency chain.

**Attack Goal**: Compromise a WSC dependency (e.g., ed25519-compact, ureq, serde) to inject malicious code that runs within WSC's trust boundary.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-018]] (SBOM), [[ASSET-020]] (System Integrity)
- **Threat scenario**: [[TS-016]] (Supply Chain Attack on Dependencies)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- compromised dependency runs within WSC's trust boundary
- **Unsafe control action**: [[UCA-1]] (Signing controller issues signature for unauthorised code) -- if the signing logic itself is compromised
- **Attack scenario**: [[AS-5]] (Supply chain compromise) -- variant targeting WSC's own build rather than the modules it signs
- **Risk assessment**: [[RA-016]]
- **Cybersecurity goals**: [[CG-7]] (Supply chain transparency), [[CG-8]] (Build integrity)
- **Cybersecurity requirements**: [[CR-3]] (Verify software integrity), [[CR-8]] (Support provenance verification)
- **Cybersecurity designs**: [[CD-5]] (SLSA provenance), [[CD-4]] (Cargo.lock pinning)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <=2 weeks | 7 | Dependency typosquatting or compromise |
| Specialist Expertise | Expert | 8 | Supply chain attack sophistication |
| Knowledge of Item | Sensitive | 11 | Dependency graph, CI pipeline |
| Window of Opportunity | Moderate | 4 | During build or dependency update |
| Equipment | Specialized | 6 | Build infrastructure access |
| **Total** | | **36** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Severe. Safety impact is Severe (compromised signing tool is worst-case scenario). Financial impact is Severe (all modules signed with compromised version are suspect). Operational impact is Severe (requires full incident response, re-signing). Privacy impact is Moderate (depends on attacker's payload).

**Risk Determination**: AF Very Low x Impact Severe = **Medium Risk** ([[RA-016]])

**Risk Treatment**: **Reduce** -- supply chain hardening.

**Controls Applied**:

1. [[CD-4]] Cargo.lock pins exact dependency versions -- Implemented. Prevents automatic adoption of compromised versions.
2. [[CD-5]] SLSA provenance for WSC builds -- Implemented. Provides verifiable build attestation.
3. Minimal dependency surface -- By design. WSC uses few dependencies, reducing attack surface.
4. `cargo audit` in CI -- Implemented. Checks for known vulnerabilities in dependencies.

**Residual Risk**: [[RR-6]] (Zero-day compromise of a dependency) -- if a dependency is compromised before a vulnerability is known, cargo audit cannot detect it. This is an industry-wide challenge mitigated by dependency minimisation and vigilant monitoring.

---

### TS-017: Privilege Escalation via File Permissions

**Asset**: [[ASSET-001]] (Ed25519 Secret Key), [[ASSET-020]] (System Integrity) -- key material that could be accessed through overly permissive file system settings.

**Attack Goal**: Exploit insecure file permissions on key files to read or modify key material, escalating from a low-privilege user to the ability to sign modules.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-001]] (Ed25519 Secret Key)
- **Threat scenario**: [[TS-017]] (Privilege Escalation via File Permissions)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- key access enables malicious signing
- **Unsafe control action**: [[UCA-1]] (Signing controller issues signature for unauthorised code) -- same outcome as [[TS-001]]
- **Attack scenario**: [[AS-1]] (Key material extraction) -- variant through file permission weakness
- **Risk assessment**: [[RA-017]]
- **Cybersecurity goals**: [[CG-4]] (Confidentiality of key material)
- **Cybersecurity requirements**: [[CR-2]] (Protect cryptographic keys at rest)
- **Cybersecurity designs**: [[CD-1]] (Secure file permissions)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 day | 0 | Trivial if permissions are wrong |
| Specialist Expertise | Layman | 0 | Basic file system knowledge |
| Knowledge of Item | Restricted | 7 | Key file location |
| Window of Opportunity | Easy | 1 | Persistent if permissions are insecure |
| Equipment | Standard | 0 | Standard OS tools |
| **Total** | | **8** | |

**AF Rating**: High (0-9 points)

**Impact Assessment**: The highest-impact category is Major. Same impact profile as [[TS-001]].

**Risk Determination**: AF High x Impact Major = **High Risk** ([[RA-017]]) before controls. After [[CD-1]] is applied, the effective AF increases significantly because the attacker must first escalate to the key owner's privileges.

**Risk Treatment**: **Reduce** -- enforce strict file permissions.

**Controls Applied**:

1. [[CD-1]] Keys written with 0600 permissions -- Implemented. Only the owner can read/write key files.
2. [[CD-1]] Warnings on insecure existing files -- Implemented. WSC warns if it detects key files with overly permissive permissions.
3. Secure key generation creates files with correct permissions from the start -- Implemented.

**STPA-Sec Insight**: This threat demonstrates why STPA-Sec analysis must consider the *initial conditions* of the system, not just steady-state operation. If key files are created with insecure permissions (e.g., by a manual process that bypasses WSC's key generation), the control structure assumption that key material is confidential is violated from the start. [[CD-1]] addresses both the steady state (setting 0600 on new files) and the detection case (warning on existing insecure files).

**Residual Risk**: [[RR-1]] (Key theft via software storage) -- shared with [[TS-001]]. File permissions are an operating system control; WSC sets them correctly but cannot prevent the OS or administrator from changing them.

---

### TS-018: Multi-Signature Policy Bypass

**Asset**: [[ASSET-009]] (Signed WASM Module), [[ASSET-013]] (Public Key Set) -- the multi-signature verification policy and the set of keys used to evaluate it.

**Attack Goal**: Bypass multi-signature requirements by exploiting policy evaluation logic, such as satisfying an N-of-M threshold with fewer than N valid signatures or with signatures from unintended keys.

**Traceability Chain**:

- **Asset at risk**: [[ASSET-009]] (Signed WASM Module), [[ASSET-013]] (Public Key Set)
- **Threat scenario**: [[TS-018]] (Multi-Signature Policy Bypass)
- **STPA-Sec hazard**: [[H-1]] (Unauthorized code accepted as authentic) -- policy bypass enables acceptance of insufficiently authorized modules
- **Unsafe control action**: [[UCA-4]] (Verification controller accepts module that does not meet policy requirements) -- the control algorithm's policy evaluation is flawed
- **Attack scenario**: [[AS-2]] (variant: policy manipulation rather than key confusion) -- the attacker exploits the gap between the intended policy and its implementation
- **Risk assessment**: [[RA-018]]
- **Cybersecurity goals**: [[CG-1]] (Authenticity), [[CG-2]] (Integrity)
- **Cybersecurity requirements**: [[CR-3]] (Verify software integrity), [[CR-11]] (Ensure unambiguous policy evaluation)
- **Cybersecurity designs**: [[CD-4]] (Multi-signature verification logic)

**Attack Feasibility Calculation**:

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 month | 10 | Policy logic analysis |
| Specialist Expertise | Proficient | 4 | Understanding of threshold schemes |
| Knowledge of Item | Restricted | 7 | Multi-signature implementation details |
| Window of Opportunity | Moderate | 4 | Need to submit module with crafted signatures |
| Equipment | Standard | 0 | Standard tools |
| **Total** | | **25** | |

**AF Rating**: Very Low (20+ points)

**Impact Assessment**: The highest-impact category is Major. Safety impact is Major (insufficiently authorized code accepted in safety-critical context). Financial impact is Moderate (trust policy violation). Operational impact is Major (policy integrity compromised). Privacy impact is Negligible.

**Risk Determination**: AF Very Low x Impact Major = **Low Risk** ([[RA-018]])

**Risk Treatment**: **Reduce** -- rigorous policy evaluation implementation and testing.

**Controls Applied**:

1. [[CD-4]] Explicit threshold evaluation -- Implemented. Multi-signature verification counts unique valid signatures and compares against the threshold.
2. Key deduplication -- Implemented. The same key cannot satisfy multiple signature slots in a threshold policy.
3. Test coverage for policy edge cases -- Implemented. Unit tests cover boundary conditions (exactly N signatures, N-1, duplicate keys, etc.).

**STPA-Sec Insight**: Multi-signature policy evaluation is a *control algorithm* that must correctly implement the intended authorization model. The STPA-Sec analysis identifies the risk of *process model inconsistency*: the controller's model of "how many valid signatures exist" could differ from reality if the counting logic has edge cases. The system constraint [[SC-11]] (policy evaluation must be deterministic and unambiguous) is enforced through explicit counting, key deduplication, and comprehensive testing.

---

## Risk Summary

| Threat | AF Rating | Impact | Risk Level | Treatment | Status |
|--------|-----------|--------|------------|-----------|--------|
| [[TS-001]]: Key Theft | Low | Major | Medium | Reduce | Controlled |
| [[TS-002]]: Token Theft | Very Low | Moderate | Negligible | Accept | Accepted |
| [[TS-003]]: Module Tampering | N/A | None | None | N/A | By Design |
| [[TS-004]]: Trust Bundle Manipulation | Very Low | Severe | Medium | Reduce | Controlled |
| [[TS-005]]: Timing Attack | Very Low | Major | Low | Reduce | Controlled |
| [[TS-006]]: Fulcio Compromise | Very Low | Severe | Medium | Transfer+Reduce | Controlled |
| [[TS-007]]: Signature Stripping | High | Major | High | Reduce | Controlled |
| [[TS-008]]: Rollback Attack | Low | Major | Medium | Reduce | Controlled |
| [[TS-009]]: Memory Residue | Very Low | Major | Low | Reduce | Controlled |
| [[TS-010]]: Malformed Module DoS | Medium | Moderate | Medium | Reduce | Controlled |
| [[TS-011]]: MitM on Sigstore | Very Low | Major | Low | Reduce | Controlled |
| [[TS-012]]: Key ID Collision | Very Low | Major | Low | Reduce | Controlled |
| [[TS-013]]: Provenance Forgery | Low | Major | Medium | Reduce | Controlled |
| [[TS-014]]: Rekor Unavailability | High | Moderate | Medium | Reduce | Controlled |
| [[TS-015]]: Parser Code Execution | Very Low | Severe | Medium | Reduce | Controlled |
| [[TS-016]]: Supply Chain Attack | Very Low | Severe | Medium | Reduce | Controlled |
| [[TS-017]]: File Permission Escalation | High | Major | High | Reduce | Controlled |
| [[TS-018]]: Multi-Sig Policy Bypass | Very Low | Major | Low | Reduce | Controlled |

---

## Residual Risks

After applying all controls, the following residual risks remain. Each residual risk is traceable to the threat scenarios and controls that produce it.

### [[RR-1]]: Key Material in Software Storage

- **Source threats**: [[TS-001]] (Key Theft), [[TS-009]] (Memory Residue), [[TS-017]] (File Permission Escalation)
- **Controls applied**: [[CD-1]] (File permissions), [[CD-2]] (Zeroization), [[CD-3]] (HSM -- roadmap)
- **Residual level**: Low
- **Accepted by**: System integrator
- **Review date**: Quarterly
- **Resolution path**: [[CD-3]] (HSM integration) eliminates this residual risk by removing key material from software-accessible storage entirely.

### [[RR-2]]: Trust Bundle Provisioning Integrity

- **Source threats**: [[TS-004]] (Trust Bundle Manipulation)
- **Controls applied**: [[CD-6]] (Signed bundles), [[CD-7]] (Certificate pinning for updates)
- **Residual level**: Low
- **Accepted by**: System integrator
- **Review date**: Quarterly
- **Note**: WSC provides the cryptographic mechanism (signed bundles) but the physical/procedural security of the initial provisioning channel is the integrator's responsibility.

### [[RR-3]]: Sigstore Infrastructure Dependency

- **Source threats**: [[TS-006]] (Fulcio Compromise), [[TS-011]] (MitM on Sigstore), [[TS-014]] (Rekor Unavailability)
- **Controls applied**: [[CD-7]] (Certificate pinning), [[CD-5]] (Rekor logging), [[CD-9]] (Key-based fallback)
- **Residual level**: Medium
- **Accepted by**: System integrator
- **Review date**: Track ureq #1087 for pinning limitation
- **Note**: Integrators in high-assurance environments should prefer key-based signing with HSM-backed keys to avoid Sigstore dependency entirely.

### [[RR-4]]: Consumer Enforcement of Signature Requirements

- **Source threats**: [[TS-007]] (Signature Stripping)
- **Controls applied**: [[CD-6]] (Trust bundle with enforcement policy), [[CR-7]] (Documentation)
- **Residual level**: Medium
- **Accepted by**: System integrator
- **Review date**: Quarterly
- **Note**: WSC provides verification mechanisms and clear API responses for unsigned modules, but cannot force consumers to invoke verification. This is a shared responsibility boundary.

### [[RR-5]]: Logic Bugs in Parser Despite Memory Safety

- **Source threats**: [[TS-015]] (Parser Code Execution), [[TS-010]] (Malformed Module DoS)
- **Controls applied**: `#![forbid(unsafe_code)]`, Rust memory safety, fuzz testing (6 targets)
- **Residual level**: Low
- **Accepted by**: WSC Team
- **Review date**: Continuous (fuzz testing runs continuously in CI)
- **Note**: Rust prevents memory corruption but not logic errors. Fuzz testing provides ongoing assurance against parser logic bugs.

### [[RR-6]]: Zero-Day Dependency Compromise

- **Source threats**: [[TS-016]] (Supply Chain Attack)
- **Controls applied**: Cargo.lock pinning, `cargo audit`, minimal dependency surface, SLSA provenance
- **Residual level**: Low
- **Accepted by**: WSC Team
- **Review date**: On each dependency update
- **Note**: This is an industry-wide challenge. WSC mitigates through dependency minimisation, version pinning, and continuous vulnerability scanning.

**Note**: Residual risk acceptance for RR-1 through RR-4 is the responsibility of the system integrator, not WSC. WSC accepts RR-5 and RR-6 as component-level residual risks managed through continuous testing and monitoring.

---

## STPA-Sec Integration Summary

The following table summarises how each STPA-Sec element connects to the TARA risk assessment, providing a cross-reference for auditors and reviewers.

| STPA-Sec Element | Related Threats | Key Finding |
|------------------|-----------------|-------------|
| [[H-1]] Unauthorized code accepted | [[TS-001]], [[TS-005]], [[TS-009]], [[TS-012]], [[TS-015]], [[TS-016]], [[TS-017]], [[TS-018]] | Most threats ultimately map to this hazard; defence in depth is essential |
| [[H-2]] Tampered code accepted | [[TS-003]], [[TS-013]] | Cryptographic binding ([[CD-4]]) provides structural prevention |
| [[H-3]] Trust anchor compromised | [[TS-004]], [[TS-006]], [[TS-011]] | External trust dependencies require fallback mechanisms ([[SC-7]]) |
| [[H-4]] Verification bypassed | [[TS-007]], [[TS-010]], [[TS-014]] | Control omission (not invoking verification) is as dangerous as control failure |
| [[H-5]] Outdated module accepted | [[TS-008]] | Signature verification alone is insufficient; temporal ordering is needed |
| [[AS-1]] Key extraction | [[TS-001]], [[TS-009]], [[TS-017]] | Multiple extraction paths require multiple controls ([[CD-1]], [[CD-2]], [[CD-3]]) |
| [[AS-5]] Supply chain compromise | [[TS-004]], [[TS-016]] | Trust establishment and build integrity are distinct but related concerns |
| [[AS-10]] Resource exhaustion | [[TS-010]], [[TS-014]], [[TS-015]] | Untrusted input must never control resource allocation ([[SC-9]], [[SC-10]]) |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-06 | WSC Team | Initial risk assessment per ISO 21434 |
| 2.0 | 2026-03-15 | WSC Team | Rivet conversion: added YAML frontmatter, artifact cross-references, STPA-Sec integration, expanded threat scenarios (TS-007 through TS-018), enriched traceability chains, residual risk traceability |
