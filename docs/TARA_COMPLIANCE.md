# WSC TARA Compliance Mapping

This document maps WSC security controls to TARA (Threat Analysis and Risk Assessment) requirements for automotive (ISO/SAE 21434) and industrial IoT (IEC 62443) deployments.

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-04 |
| Standards | ISO/SAE 21434, IEC 62443, SLSA |
| Status | Active |

---

## ISO/SAE 21434 (Automotive Cybersecurity)

### Work Products Mapping

| WP ID | Work Product | WSC Artifact | Status |
|-------|--------------|--------------|--------|
| WP-06-01 | Threat Analysis | docs/THREAT_MODEL.md | Complete |
| WP-06-02 | Risk Assessment | THREAT_MODEL.md Risk ratings | Complete |
| WP-07-01 | Cybersecurity Goals | SECURITY.md | Complete |
| WP-07-02 | Cybersecurity Claims | This document | Complete |
| WP-08-01 | Vulnerability Analysis | Fuzz testing, audit | Ongoing |
| WP-09-01 | Cybersecurity Verification | cargo test, fuzz | Complete |

### Cybersecurity Goals

| Goal ID | Goal | Implementation |
|---------|------|----------------|
| CG-01 | Authenticity of WASM modules | Ed25519 signatures |
| CG-02 | Integrity of signed content | SHA-256 hash verification |
| CG-03 | Non-repudiation of signing | Rekor transparency log |
| CG-04 | Confidentiality of keys | Secure storage, zeroization |
| CG-05 | Availability of verification | Offline verification support |

### Cybersecurity Requirements

| Req ID | Requirement | WSC Control | Evidence |
|--------|-------------|-------------|----------|
| CR-01 | Use approved cryptographic algorithms | Ed25519, SHA-256 | src/signature/ |
| CR-02 | Protect cryptographic keys | 0600 permissions, zeroize | secure_file.rs, keys.rs |
| CR-03 | Verify software integrity | Signature verification | simple.rs, multi.rs |
| CR-04 | Implement defense in depth | Multi-layer security | cert_pinning.rs |
| CR-05 | Log security events | Rekor integration | rekor.rs |
| CR-06 | Support incident response | Key revocation docs | INCIDENT_RESPONSE.md |

---

## IEC 62443 (Industrial Automation Cybersecurity)

### Security Level Mapping

WSC supports Security Levels 1-3:

| SL | Description | WSC Capability |
|----|-------------|----------------|
| SL 1 | Casual/coincidental | Software key storage |
| SL 2 | Intentional, low resources | Certificate pinning, file permissions |
| SL 3 | Sophisticated attacker | HSM integration (roadmap), airgapped ops |
| SL 4 | State-level threat | Requires external HSM + secure boot |

### Foundational Requirements (FR)

#### FR 1: Identification and Authentication Control

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 1.1 | Human user identification | OIDC identity binding |
| SR 1.2 | Software process identification | Key ID in signatures |
| SR 1.3 | Account management | N/A (delegated to OIDC) |
| SR 1.5 | Authenticator management | Key lifecycle docs |
| SR 1.7 | Strength of authentication | Ed25519 (128-bit security) |

#### FR 2: Use Control

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 2.1 | Authorization enforcement | Signature verification |
| SR 2.4 | Mobile code | WASM module integrity |
| SR 2.8 | Auditable events | Rekor log entries |
| SR 2.9 | Audit storage capacity | Sigstore infrastructure |

#### FR 3: System Integrity

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 3.1 | Communication integrity | TLS + cert pinning |
| SR 3.2 | Protection from malicious code | Signature verification |
| SR 3.4 | Software/info integrity | SHA-256 + Ed25519 |
| SR 3.5 | Input validation | Bounded parsing, fuzz testing |

#### FR 4: Data Confidentiality

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 4.1 | Information confidentiality | Key zeroization |
| SR 4.2 | Information at rest | Secure file permissions |
| SR 4.3 | Use of cryptography | Ed25519, SHA-256 |

#### FR 5: Restricted Data Flow

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 5.1 | Network segmentation | N/A (application level) |
| SR 5.2 | Zone boundary protection | Airgapped mode support |

#### FR 6: Timely Response to Events

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 6.1 | Audit log accessibility | Rekor public log |
| SR 6.2 | Continuous monitoring | Transparency log monitoring |

#### FR 7: Resource Availability

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 7.1 | DoS protection | Resource limits (16 MB) |
| SR 7.2 | Resource management | Bounded allocations |
| SR 7.6 | Network/security config | Offline verification |

---

## SLSA (Supply Chain Levels for Software Artifacts)

### Level Compliance

| Level | Requirement | WSC Status |
|-------|-------------|------------|
| SLSA 1 | Provenance exists | Provenance embedding |
| SLSA 2 | Hosted build, signed provenance | Keyless signing + Rekor |
| SLSA 3 | Hardened build | Reproducible builds (roadmap) |
| SLSA 4 | Hermetic, reproducible | Full hermetic (roadmap) |

### Build Requirements

| Requirement | WSC Implementation |
|-------------|-------------------|
| Signed provenance | composition/intoto.rs |
| Timestamp from service | Rekor timestamp |
| Version control identity | OIDC identity binding |
| Dependencies declared | SBOM embedding |

---

## Common Criteria (EAL2+)

For Common Criteria evaluation at EAL2 or above:

### Security Functional Requirements

| SFR Class | SFR | WSC Control |
|-----------|-----|-------------|
| FCS_COP | Cryptographic operation | Ed25519, SHA-256 |
| FCS_CKM | Cryptographic key management | Key generation, zeroization |
| FDP_ITC | Import from outside TSF | Signature verification |
| FDP_ETC | Export to outside TSF | Signature embedding |
| FIA_UID | User identification | OIDC identity |
| FPT_FLS | Fail secure | panic=abort, error handling |

### Security Assurance Requirements

| SAR | Requirement | WSC Evidence |
|-----|-------------|--------------|
| ADV_ARC | Security architecture | THREAT_MODEL.md |
| ADV_FSP | Functional specification | API documentation |
| ALC_CMC | Configuration management | Git, semantic versioning |
| ALC_CMS | CM scope | Cargo.lock, reproducible |
| ATE_COV | Test coverage | cargo test, fuzz |
| AVA_VAN | Vulnerability analysis | Security audit, fuzz |

---

## Compliance Gaps and Roadmap

### Current Gaps

| Gap | Standard | Impact | Mitigation Plan |
|-----|----------|--------|-----------------|
| HSM integration incomplete | IEC 62443 SL3+ | Medium | Platform module scaffolded |
| OCSP/CRL not implemented | ISO 21434 | Low | Fulcio short-lived certs |
| Reproducible builds | SLSA 3 | Low | Bazel build in progress |
| Formal verification | EAL4+ | Medium | Not planned |

### Compliance Roadmap

| Quarter | Milestone | Standards |
|---------|-----------|-----------|
| Q1 2026 | Certificate pinning GA | All |
| Q2 2026 | HSM integration | IEC 62443 SL3 |
| Q3 2026 | Reproducible builds | SLSA 3 |
| Q4 2026 | Security certification prep | ISO 21434 |

---

## Audit Trail Requirements

### What Must Be Logged

For TARA compliance, the following events should be logged:

1. **Signing Operations**
   - Timestamp
   - Signer identity (OIDC subject)
   - Module hash
   - Key ID used
   - Rekor entry UUID

2. **Verification Operations**
   - Timestamp
   - Module hash
   - Verification result
   - Public key used

3. **Key Management**
   - Key generation
   - Key import/export
   - Key deletion

### Log Format (Structured)

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

- [ ] Complete threat model review
- [ ] Penetration testing complete
- [ ] Fuzz testing coverage >80%
- [ ] Security audit findings resolved
- [ ] Documentation complete

### Documentation Required

- [x] THREAT_MODEL.md
- [x] TARA_COMPLIANCE.md
- [x] KEY_LIFECYCLE.md
- [x] INCIDENT_RESPONSE.md
- [ ] Security architecture diagram
- [ ] Test coverage report

### Technical Requirements

- [x] Constant-time crypto operations
- [x] Memory zeroization
- [x] Overflow checks in release
- [x] Certificate pinning
- [ ] HSM integration
- [ ] OCSP stapling

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-04 | WSC Team | Initial compliance mapping |
