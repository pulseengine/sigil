---
id: DOC-TARA-COMPLIANCE
title: TARA Compliance Evidence
type: specification
status: approved
tags: [security, tara, iso-21434, iec-62443, compliance]
---

# WSC Security Evidence for TARA

This document provides **component-level security evidence** that system integrators can reference when performing TARA (Threat Analysis and Risk Assessment) on their systems. Every claim is backed by traceable artifact references, enabling auditors to follow the chain from threat scenario through cybersecurity goal, requirement, design decision, and verification evidence.

> **Critical Distinction**: WSC does not "perform TARA" - it provides evidence FOR your TARA.
>
> - **Your responsibility**: Perform TARA on your ITEM (vehicle ECU, IoT device, etc.)
> - **WSC provides**: Component security claims, threat analysis, risk assessment evidence
> - **See also**: `docs/security/INTEGRATION_GUIDANCE.md` for integration help

## Document Information

| Field | Value |
|-------|-------|
| Version | 2.0 |
| Date | 2026-03-15 |
| Standards | ISO/SAE 21434, IEC 62443, SLSA, Common Criteria |
| Status | Approved |
| Scope | Component-level evidence only |

---

## ISO/SAE 21434 (Automotive Cybersecurity)

### Work Products Mapping

WSC provides **component-level evidence** for the following work products. System integrators must create their own system-level work products. Each work product below links to the specific artifacts that constitute its evidence.

**WP-06-01 (Threat Analysis)** is evidenced by the STRIDE Threat Model (THREAT_MODEL.md) which contains a comprehensive STRIDE analysis producing threat scenarios [[TS-001]] through [[TS-018]]. The analysis covers all identified assets [[ASSET-001]] through [[ASSET-022]] and models data flows [[DF-1]] through [[DF-10]] across trust boundaries. STPA hazard analysis identifies hazards [[H-1]] through [[H-11]] with unsafe control actions [[UCA-1]] through [[UCA-12]] and causal scenarios [[CC-1]] through [[CC-12]].

**WP-06-02 (Risk Assessment)** is evidenced by risk assessments [[RA-001]] through [[RA-018]], each using ISO 21434 Attack Feasibility (AF) ratings. Residual risks are documented as [[RR-1]] through [[RR-6]], each with an explicit acceptance rationale and mitigation timeline.

**WP-07-01 (Cybersecurity Goals)** is evidenced by the cybersecurity goals [[CG-1]] through [[CG-8]] defined below, each derived from the threat scenarios in WP-06-01.

**WP-07-02 (Cybersecurity Claims)** is evidenced by this document (this document), which maps goals to requirements ([[CR-1]] through [[CR-11]]), requirements to designs ([[CD-1]] through [[CD-9]]), and designs to verification evidence ([[CV-1]] through [[CV-8]]).

**WP-08-01 (Vulnerability Analysis)** is evidenced by fuzz testing results across 6 fuzz targets, verification activities [[CV-5]] (fuzz testing) and [[CV-6]] (dependency audit), and the security properties [[SP-1]] through [[SP-8]] that are formally verified.

**WP-09-01 (Verification)** is evidenced by verification activities [[CV-1]] through [[CV-8]], including unit tests, integration tests, end-to-end signing workflows, fuzz testing, and memory safety analysis.

**Note**: "Complete" status for component evidence does NOT mean your system TARA is complete.

### Cybersecurity Goals

WSC defines eight cybersecurity goals, each traceable to the threat scenarios that motivate them and the requirements that implement them:

**[[CG-1]] Authenticity of WASM Modules** — Ensures that every WASM module consumed by the system was produced by a known, authorized signer. Motivated by spoofing threats [[TS-001]], [[TS-002]], and [[TS-003]]. Implemented through Ed25519 signatures ([[CD-1]]) and OIDC identity binding ([[CD-4]]). Verified by [[CV-1]] and [[CV-2]].

**[[CG-2]] Integrity of Signed Content** — Ensures that signed WASM modules have not been modified after signing. Motivated by tampering threats [[TS-004]], [[TS-005]], and [[TS-006]]. Implemented through SHA-256 content hashing ([[CD-2]]) with signature binding. Verified by [[CV-1]] and [[CV-3]].

**[[CG-3]] Non-Repudiation of Signing** — Ensures that a signing event can be independently verified and cannot be denied by the signer. Motivated by repudiation threats [[TS-007]], [[TS-008]], and [[TS-009]]. Implemented through Rekor transparency log integration ([[CD-5]]). Verified by [[CV-4]].

**[[CG-4]] Key Confidentiality** — Ensures that private signing keys are protected from unauthorized access throughout their lifecycle. Motivated by information disclosure threats [[TS-010]], [[TS-011]], and [[TS-012]]. Implemented through secure file permissions, memory zeroization ([[CD-3]]), and key lifecycle management. Verified by [[CV-7]].

**[[CG-5]] Verification Availability** — Ensures that signature verification can be performed even without network connectivity. Motivated by denial-of-service threats [[TS-013]] and [[TS-014]]. Implemented through air-gapped verification mode ([[CD-6]]) and embedded trust bundles. Verified by [[CV-2]].

**[[CG-6]] Trust Bundle Resilience** — Ensures that the trust bundle mechanism resists corruption, truncation, and substitution attacks. Motivated by threats [[TS-015]] and [[TS-016]] targeting embedded trust anchors. Implemented through trust bundle integrity verification ([[CD-7]]) and safe controller design with loss constraints [[SC-1]] through [[SC-11]]. Verified by [[CV-3]] and [[CV-8]].

**[[CG-7]] CA Compromise Resilience** — Ensures that compromise of a single certificate authority does not invalidate all existing signatures or enable unbounded forgery. Motivated by threat [[TS-017]] targeting the Fulcio CA. Implemented through short-lived certificates (10-minute window), transparency log anchoring ([[CD-5]]), and certificate pinning ([[CD-8]]). Residual risk documented in [[RR-3]].

**[[CG-8]] Replay and Rollback Protection** — Ensures that previously valid but now-revoked or outdated signatures cannot be replayed to install old, vulnerable modules. Motivated by threat [[TS-018]]. Implemented through timestamp verification ([[CD-9]]) and provenance metadata. Verified by [[CV-4]].

### Cybersecurity Requirements

WSC defines eleven cybersecurity requirements, each satisfying one or more cybersecurity goals and implemented by specific design decisions:

**[[CR-1]] Use Approved Cryptographic Algorithms** — Ed25519 for signatures, SHA-256 for content hashing. Satisfies [[CG-1]] and [[CG-2]]. Implemented by [[CD-1]] and [[CD-2]]. Evidence in `src/signature/`. Verified by [[CV-1]].

**[[CR-2]] Protect Cryptographic Keys** — File permissions (0600), memory zeroization via `zeroize` crate, secure key storage. Satisfies [[CG-4]]. Implemented by [[CD-3]]. Evidence in `secure_file.rs`, `keys.rs`. Verified by [[CV-7]].

**[[CR-3]] Verify Software Integrity Before Execution** — Mandatory signature verification before any module is accepted. Satisfies [[CG-1]] and [[CG-2]]. Implemented by [[CD-1]] and [[CD-6]]. Evidence in `simple.rs`, `multi.rs`. Verified by [[CV-1]] and [[CV-2]].

**[[CR-4]] Implement Defense in Depth** — Multiple independent security layers: cryptographic verification, certificate pinning, input validation, bounded resource allocation. Satisfies [[CG-1]], [[CG-2]], [[CG-6]], and [[CG-7]]. Implemented by [[CD-8]]. Evidence in `cert_pinning.rs`. Verified by [[CV-5]].

**[[CR-5]] Log Security-Relevant Events** — All signing operations are recorded in the Rekor transparency log with tamper-evident properties. Satisfies [[CG-3]]. Implemented by [[CD-5]]. Evidence in `rekor.rs`. Verified by [[CV-4]].

**[[CR-6]] Support Incident Response** — Key revocation procedures, incident response playbook, and forensic evidence preservation. Satisfies [[CG-4]] and [[CG-7]]. Documentation in `INCIDENT_RESPONSE.md`. Augmented by safety actions [[AS-1]] through [[AS-10]].

**[[CR-7]] Enforce Input Validation and Resource Bounds** — All external inputs are validated; WASM module size is bounded to 16 MB; allocations are bounded. Satisfies [[CG-5]] and [[CG-6]]. Implemented by [[CD-7]]. Verified by [[CV-5]] (fuzz testing).

**[[CR-8]] Support Air-Gapped Operation** — Verification must function without any network access, using pre-provisioned trust bundles. Satisfies [[CG-5]]. Implemented by [[CD-6]]. Verified by [[CV-2]].

**[[CR-9]] Incident Response Readiness** — Maintain documented incident response procedures with defined roles, escalation paths, and communication templates. Satisfies [[CG-4]] and [[CG-7]]. Evidence in `INCIDENT_RESPONSE.md`. Residual risks [[RR-4]] and [[RR-5]] address response time constraints.

**[[CR-10]] Structured Audit Log Format** — All security events must be logged in a structured, machine-parseable format suitable for automated compliance monitoring. Satisfies [[CG-3]]. Implemented by [[CD-5]] and [[CD-9]]. See Audit Trail Requirements below.

**[[CR-11]] Vulnerability Disclosure Process** — Maintain a documented vulnerability disclosure and handling process. Satisfies [[CG-7]]. Evidence in `SECURITY.md`. Verified by [[CV-6]] (dependency audit).

---

## IEC 62443 (Industrial Automation Cybersecurity)

### Security Level Capability

**WSC Component Security Level (SL-C) = 2**

WSC is a software component. Its security level capability represents what the component can achieve on its own, independent of the deployment environment:

| SL | Description | WSC Capability | Status |
|----|-------------|----------------|--------|
| SL 1 | Casual/coincidental | Software key storage ([[CD-3]]), basic verification ([[CD-1]]) | **Supported** |
| SL 2 | Intentional, low resources | + Certificate pinning ([[CD-8]]), file permissions, zeroization ([[CD-3]]) | **Supported** |
| SL 3 | Sophisticated attacker | + HSM integration required ([[FEAT-2]]) | **Requires HSM** |
| SL 4 | State-level threat | + TEE, secure boot, anti-tamper | **Not Supported** |

**Important Clarifications:**

- **SL-C (Component)**: What WSC can achieve = **2**
- **SL-T (Target)**: What your system aims for = **Determined by you**
- Achieving SL-T = 3 with WSC requires enabling HSM backend via `platform/` module ([[FEAT-2]], in development)
- SL-T = 4 requires external TEE and secure boot chain beyond WSC's scope

### Foundational Requirements (FR)

#### FR 1: Identification and Authentication Control

**SR 1.1 (Human User Identification)** is implemented by [[CD-4]] (OIDC identity binding), which binds signing operations to an authenticated human identity through Fulcio short-lived certificates. Satisfies [[CR-1]] and supports [[CG-1]]. Threat coverage: [[TS-001]], [[TS-007]].

**SR 1.2 (Software Process Identification)** is implemented through Key ID embedding in signatures ([[CD-1]]), enabling identification of the signing key used for each module. Satisfies [[CR-3]].

**SR 1.3 (Account Management)** is delegated to the OIDC identity provider. WSC does not manage accounts directly; it consumes OIDC tokens as authenticated identity claims. Data flow [[DF-3]] models this trust boundary.

**SR 1.5 (Authenticator Management)** is implemented through documented key lifecycle procedures in `KEY_LIFECYCLE.md`, covering generation, storage, rotation, and destruction. Satisfies [[CR-2]] and [[CR-6]].

**SR 1.7 (Strength of Authentication)** is implemented by [[CD-1]] (Ed25519 providing 128-bit security level), satisfying [[CR-1]]. Risk assessment [[RA-001]] confirms this meets the component's threat model.

#### FR 2: Use Control

**SR 2.1 (Authorization Enforcement)** is implemented through mandatory signature verification ([[CD-1]], [[CD-6]]) before any module is accepted. Only modules signed by authorized keys pass verification. Satisfies [[CR-3]].

**SR 2.4 (Mobile Code)** is directly addressed by WSC's core function: ensuring WASM module integrity through [[CD-1]] and [[CD-2]], with the full traceability chain [[CG-2]] → [[CR-3]] → [[CD-1]] → [[CV-1]].

**SR 2.8 (Auditable Events)** is implemented by [[CD-5]] (Rekor transparency log integration). Every signing operation produces a tamper-evident log entry. Satisfies [[CR-5]] and [[CR-10]].

**SR 2.9 (Audit Storage Capacity)** is provided by the Sigstore public infrastructure (Rekor), which maintains append-only transparency logs. Residual risk [[RR-2]] documents the dependency on external infrastructure availability.

#### FR 3: System Integrity

**SR 3.1 (Communication Integrity)** is implemented by [[CD-8]] (TLS with certificate pinning) for all communications with Fulcio and Rekor. Data flows [[DF-1]] through [[DF-5]] model these channels. Satisfies [[CR-4]].

**SR 3.2 (Protection from Malicious Code)** is the primary function of WSC: signature verification ([[CD-1]], [[CD-6]]) prevents execution of unsigned or tampered modules. The full traceability chain runs [[TS-004]] → [[CG-2]] → [[CR-3]] → [[CD-1]] → [[CV-1]].

**SR 3.4 (Software and Information Integrity)** is implemented by [[CD-2]] (SHA-256 content hashing) and [[CD-1]] (Ed25519 signatures), providing both integrity detection and authenticity. Satisfies [[CR-1]] and [[CR-3]]. Security properties [[SP-1]] through [[SP-4]] formalize these guarantees.

**SR 3.5 (Input Validation)** is implemented through bounded parsing with a 16 MB module size limit ([[CR-7]]), validated by 6 fuzz targets ([[CV-5]]). Safety constraints [[SC-1]] through [[SC-11]] ensure robust input handling.

#### FR 4: Data Confidentiality

**SR 4.1 (Information Confidentiality)** is implemented by [[CD-3]] (memory zeroization using the `zeroize` crate), ensuring key material is erased from memory after use. Satisfies [[CR-2]]. Verified by [[CV-7]].

**SR 4.2 (Information at Rest)** is implemented through secure file permissions (0600) for key storage ([[CD-3]]). Satisfies [[CR-2]]. Residual risk [[RR-1]] documents the limitation of software-only key storage.

**SR 4.3 (Use of Cryptography)** is implemented by [[CD-1]] (Ed25519) and [[CD-2]] (SHA-256), both NIST-approved algorithms. Satisfies [[CR-1]]. Security properties [[SP-1]] and [[SP-2]] formalize the cryptographic guarantees.

#### FR 5: Restricted Data Flow

**SR 5.1 (Network Segmentation)** is not applicable at the application level. WSC operates as a user-space tool and does not manage network topology. System integrators must address this at the system level.

**SR 5.2 (Zone Boundary Protection)** is supported by [[CD-6]] (air-gapped verification mode), which enables WSC to operate entirely within an isolated zone without requiring network connectivity. Satisfies [[CR-8]]. Data flow [[DF-7]] models the air-gapped trust boundary.

#### FR 6: Timely Response to Events

**SR 6.1 (Audit Log Accessibility)** is implemented by [[CD-5]] (Rekor public transparency log), which provides publicly auditable, tamper-evident records of all signing operations. Satisfies [[CR-5]] and [[CR-10]].

**SR 6.2 (Continuous Monitoring)** is supported through transparency log monitoring capabilities. Satisfies [[CR-9]]. Safety actions [[AS-1]] through [[AS-10]] define response procedures for detected anomalies.

#### FR 7: Resource Availability

**SR 7.1 (DoS Protection)** is implemented through resource limits: 16 MB maximum module size, bounded memory allocations ([[CR-7]]). Satisfies [[CG-5]]. Verified by [[CV-5]] (fuzz testing under resource constraints).

**SR 7.2 (Resource Management)** is implemented through bounded allocations and deterministic resource cleanup. Satisfies [[CR-7]]. Security property [[SP-7]] formalizes the resource bound guarantee.

**SR 7.6 (Network and Security Configuration)** is implemented by [[CD-6]] (offline/air-gapped verification), enabling operation without network dependencies. Satisfies [[CR-8]]. Verified by [[CV-2]].

---

## SLSA (Supply Chain Levels for Software Artifacts)

### Level Compliance

WSC provides tooling to help achieve SLSA compliance for WASM artifacts. The relevant requirements and their implementation status:

**SLSA 1 (Provenance Exists)** — WSC embeds provenance metadata in signed modules through `composition/intoto.rs`. This satisfies [[REQ-5]] (provenance embedding) and is implemented by [[CD-9]]. Verified by [[CV-4]]. **Status: Supported.**

**SLSA 2 (Hosted Build, Signed Provenance)** — WSC provides keyless signing via Sigstore ([[CD-4]], [[CD-5]]), producing signed provenance anchored in the Rekor transparency log. The traceability chain runs [[CG-3]] → [[CR-5]] → [[CD-5]] → [[CV-4]]. **Status: Supported.**

**SLSA 3 (Hardened Build)** — Requires reproducible builds. WSC uses Bazel for hermetic builds ([[FEAT-3]]). Full SLSA 3 compliance is on the roadmap. Residual risk [[RR-6]] documents the current gap. **Status: In Progress.**

**SLSA 4 (Hermetic, Reproducible)** — Requires fully hermetic and reproducible build pipeline. Planned as [[FEAT-4]]. **Status: Roadmap.**

### Build Requirements

| Requirement | WSC Implementation | Artifact References |
|-------------|-------------------|---------------------|
| Signed provenance | `composition/intoto.rs` | [[CD-9]], [[CR-5]], [[CV-4]] |
| Timestamp from service | Rekor timestamp | [[CD-5]], [[CG-3]] |
| Version control identity | OIDC identity binding | [[CD-4]], [[CR-1]] |
| Dependencies declared | SBOM embedding | [[REQ-6]], [[FEAT-5]] |

---

## Common Criteria (EAL2+)

For Common Criteria evaluation at EAL2 or above, WSC provides the following mappings from Security Functional Requirements and Security Assurance Requirements to concrete design decisions and verification evidence.

### Security Functional Requirements

**FCS_COP (Cryptographic Operation)** — Implemented by [[CD-1]] (Ed25519 signatures) and [[CD-2]] (SHA-256 hashing). These satisfy [[CR-1]] and are verified by [[CV-1]]. Security properties [[SP-1]] and [[SP-2]] formalize the cryptographic guarantees. Requirements trace: [[REQ-1]], [[REQ-2]].

**FCS_CKM (Cryptographic Key Management)** — Implemented by [[CD-3]] (secure key storage, zeroization, lifecycle management). Satisfies [[CR-2]]. Verified by [[CV-7]]. Key lifecycle is documented in `KEY_LIFECYCLE.md`. Design decision [[DD-1]] justifies the Ed25519 algorithm choice.

**FDP_ITC (Import from Outside TSF)** — Implemented by signature verification ([[CD-1]], [[CD-6]]) which validates all externally-sourced WASM modules before acceptance. Satisfies [[CR-3]]. Data flows [[DF-1]] through [[DF-5]] model the import boundaries. Verified by [[CV-1]] and [[CV-2]].

**FDP_ETC (Export to Outside TSF)** — Implemented by signature embedding, which attaches cryptographic signatures as WASM custom sections. Implemented by [[CD-1]] and [[CD-9]]. Data flows [[DF-6]] through [[DF-10]] model the export paths.

**FIA_UID (User Identification)** — Implemented by [[CD-4]] (OIDC identity binding through Fulcio). The signer's identity is cryptographically bound to the signature via a short-lived certificate. Satisfies [[CR-1]]. Verified by [[CV-4]].

**FPT_FLS (Fail Secure)** — Implemented through `panic=abort` configuration, explicit error handling, and bounded resource allocation ([[CR-7]]). Safety constraints [[SC-1]] through [[SC-11]] ensure that failures do not lead to insecure states. Design decision [[DD-2]] documents the fail-closed verification policy.

### Security Assurance Requirements

**ADV_ARC (Security Architecture)** — Evidenced by the STRIDE Threat Model (THREAT_MODEL.md), which contains the security architecture description, trust boundary analysis, and data flow diagrams ([[DF-1]] through [[DF-10]]). Design decisions [[DD-1]] through [[DD-3]] document architectural choices.

**ADV_FSP (Functional Specification)** — Evidenced by API documentation and requirements [[REQ-1]] through [[REQ-10]], which specify the security-relevant interfaces and their expected behavior.

**ALC_CMC (Configuration Management)** — Evidenced by Git version control with semantic versioning, `Cargo.lock` for dependency pinning, and the CI/CD pipeline. Verified by [[CV-6]] (dependency audit).

**ALC_CMS (CM Scope)** — Evidenced by `Cargo.lock` for reproducible dependency resolution and Bazel build definitions for hermetic builds. Feature [[FEAT-3]] tracks full build reproducibility.

**ATE_COV (Test Coverage)** — Evidenced by verification activities [[CV-1]] through [[CV-8]], including unit tests, integration tests (cargo test), fuzz testing (6 targets), and end-to-end signing workflows. Coverage reports provide quantitative evidence.

**AVA_VAN (Vulnerability Analysis)** — Evidenced by [[CV-5]] (fuzz testing), [[CV-6]] (dependency audit), and the security audit process. Threat scenarios [[TS-001]] through [[TS-018]] constitute the structured vulnerability analysis. Residual risks [[RR-1]] through [[RR-6]] document accepted vulnerabilities.

---

## Known Limitations and Residual Risks

The following limitations represent accepted residual risks, each formally documented with a risk acceptance rationale:

**[[RR-1]] Software-Only Key Storage (No HSM)** — Limits IEC 62443 SL-C to a maximum of 2. Currently mitigated by file permissions (0600) and memory zeroization ([[CD-3]]). Future mitigation: HSM integration in `platform/` module ([[FEAT-2]]). Impact: [[CG-4]] is partially satisfied; hardware-backed key protection is deferred.

**[[RR-2]] Dependency on External Sigstore Infrastructure** — Rekor and Fulcio availability affects keyless signing operations. Currently mitigated by air-gapped verification mode ([[CD-6]]) which eliminates runtime dependency. Impact: [[CG-3]] (non-repudiation) requires Rekor availability for new signing operations.

**[[RR-3]] No OCSP/CRL for Certificate Revocation** — Fulcio issues 10-minute certificates, limiting the revocation window. Currently documented as accepted risk per ISO 21434 minimal impact assessment. Impact: [[CG-7]] (CA compromise resilience) relies on short certificate lifetime rather than active revocation.

**[[RR-4]] ureq Certificate Pinning Limitation** — Certificate pins are defined but only partially enforced due to upstream library limitations. Currently mitigated by defense-in-depth ([[CR-4]]). Future mitigation: tracking upstream ureq issue #1087. Impact: [[CD-8]] provides reduced assurance.

**[[RR-5]] Incident Response Time Constraints** — As an open-source component, incident response times depend on maintainer availability. Documented procedures exist ([[CR-9]]) but SLA guarantees are not provided. Impact: [[CR-6]] response times are best-effort.

**[[RR-6]] Reproducible Builds In Progress** — Full SLSA 3 compliance requires reproducible builds. Bazel hermetic builds are in progress ([[FEAT-3]]). Impact: SLSA Level 3 compliance is deferred to Q3 2026.

### Roadmap

The following features address the residual risks and advance WSC's security posture:

**[[FEAT-1]] Complete TARA Documentation** — Q1 2026. Delivers audit-ready evidence package including this document and all referenced artifacts. Reduces [[RR-5]] by providing comprehensive pre-incident documentation.

**[[FEAT-2]] HSM Integration** — Q2 2026. Enables hardware-backed key storage via `platform/` module, raising SL-C to 3. Eliminates [[RR-1]]. Strengthens [[CG-4]] and [[CR-2]].

**[[FEAT-3]] Reproducible Builds** — Q3 2026. Achieves SLSA 3 compliance through fully hermetic Bazel builds. Eliminates [[RR-6]]. Strengthens supply chain integrity claims.

**[[FEAT-4]] Hermetic Build Pipeline** — Q4 2026. Achieves SLSA 4 compliance. Enables third-party build verification.

**[[FEAT-5]] SBOM and Dependency Transparency** — Ongoing. Embeds Software Bill of Materials in signed artifacts, supporting [[CR-11]] and supply chain transparency requirements.

**Note**: This roadmap is for WSC component improvements. System integrators must maintain their own compliance roadmaps.

---

## Audit Trail Requirements

### What Must Be Logged

For TARA compliance, the following events must be logged per [[CR-5]] and [[CR-10]]. The event categories map to data flows [[DF-1]] through [[DF-10]] and support the non-repudiation goal [[CG-3]]:

1. **Signing Operations** (data flows [[DF-1]], [[DF-2]], [[DF-3]])
   - Timestamp
   - Signer identity (OIDC subject, per [[CD-4]])
   - Module hash (SHA-256, per [[CD-2]])
   - Key ID used (per [[CD-1]])
   - Rekor entry UUID (per [[CD-5]])

2. **Verification Operations** (data flows [[DF-6]], [[DF-7]])
   - Timestamp
   - Module hash
   - Verification result (pass/fail)
   - Public key used
   - Trust bundle version (per [[CD-7]])

3. **Key Management** (per [[CR-2]], [[CD-3]])
   - Key generation (algorithm, key ID)
   - Key import/export (source/destination)
   - Key deletion (secure erasure confirmation)

### Log Format (Structured)

Per [[CR-10]], all security events use a structured JSON format suitable for automated compliance monitoring:

```json
{
  "timestamp": "2026-01-04T12:00:00Z",
  "event": "sign",
  "module_hash": "sha256:abc123...",
  "identity": "user@example.com",
  "key_id": "def456...",
  "rekor_uuid": "108e9186e8c5677a..."
}
```

---

## Certification Checklist

### Pre-Certification

- [ ] Complete threat model review (the STRIDE Threat Model (THREAT_MODEL.md), [[TS-001]]–[[TS-018]])
- [ ] Penetration testing complete ([[CV-5]], [[CV-8]])
- [ ] Fuzz testing coverage >80% ([[CV-5]])
- [ ] Security audit findings resolved ([[CV-6]])
- [ ] Documentation complete (this document, all referenced artifacts)

### Documentation Required

- [x] THREAT_MODEL.md — the STRIDE Threat Model (THREAT_MODEL.md)
- [x] TARA_COMPLIANCE.md — this document
- [x] KEY_LIFECYCLE.md — Key lifecycle per [[CR-2]], [[CD-3]]
- [x] INCIDENT_RESPONSE.md — Incident response per [[CR-6]], [[CR-9]]
- [ ] Security architecture diagram — [[DF-1]]–[[DF-10]], [[DD-1]]–[[DD-3]]
- [ ] Test coverage report — [[CV-1]]–[[CV-8]]

### Technical Requirements

- [x] Constant-time crypto operations — [[CD-1]], [[SP-1]]
- [x] Memory zeroization — [[CD-3]], [[CR-2]], [[CV-7]]
- [x] Overflow checks in release — [[CR-7]], [[SP-7]]
- [x] Certificate pinning — [[CD-8]], [[CR-4]]
- [ ] HSM integration — [[FEAT-2]], [[RR-1]]
- [ ] OCSP stapling — [[RR-3]]

---

## Traceability Summary

The following chains demonstrate end-to-end traceability from threat to verification, as required by ISO/SAE 21434:

| Threat | Goal | Requirement | Design | Verification |
|--------|------|-------------|--------|--------------|
| [[TS-001]]–[[TS-003]] | [[CG-1]] Authenticity | [[CR-1]], [[CR-3]] | [[CD-1]], [[CD-4]] | [[CV-1]], [[CV-2]] |
| [[TS-004]]–[[TS-006]] | [[CG-2]] Integrity | [[CR-1]], [[CR-3]] | [[CD-1]], [[CD-2]] | [[CV-1]], [[CV-3]] |
| [[TS-007]]–[[TS-009]] | [[CG-3]] Non-Repudiation | [[CR-5]], [[CR-10]] | [[CD-5]], [[CD-9]] | [[CV-4]] |
| [[TS-010]]–[[TS-012]] | [[CG-4]] Key Confidentiality | [[CR-2]], [[CR-6]] | [[CD-3]] | [[CV-7]] |
| [[TS-013]]–[[TS-014]] | [[CG-5]] Verification Availability | [[CR-7]], [[CR-8]] | [[CD-6]], [[CD-7]] | [[CV-2]], [[CV-5]] |
| [[TS-015]]–[[TS-016]] | [[CG-6]] Trust Bundle Resilience | [[CR-4]], [[CR-7]] | [[CD-7]], [[CD-8]] | [[CV-3]], [[CV-8]] |
| [[TS-017]] | [[CG-7]] CA Compromise Resilience | [[CR-4]], [[CR-11]] | [[CD-5]], [[CD-8]] | [[CV-4]], [[CV-6]] |
| [[TS-018]] | [[CG-8]] Replay/Rollback Protection | [[CR-3]], [[CR-5]] | [[CD-9]] | [[CV-4]] |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-04 | WSC Team | Initial compliance mapping |
| 1.1 | 2026-01-06 | WSC Team | Clarified component vs system scope, fixed SL claims, added cross-references |
| 2.0 | 2026-03-15 | WSC Team | Rivet conversion: added artifact references throughout, expanded cybersecurity goals (CG-6 through CG-8), expanded requirements (CR-7 through CR-11), added traceability summary, enriched all standard mappings with artifact references, added residual risk identifiers |
