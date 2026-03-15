---
id: DOC-INTEGRATION-GUIDANCE
title: TARA Integration Guidance for System Integrators
type: guidance
status: approved
tags: [security, integration, tara, system-integrators]
---

# WSC Integration Guidance for TARA Compliance

This document helps system integrators incorporate WSC into their TARA (Threat Analysis and Risk Assessment) processes for ISO/SAE 21434 (automotive) and IEC 62443 (industrial) compliance.

| Field | Value |
|-------|-------|
| Version | 2.0 |
| Date | 2026-01-06 |
| Classification | Public |
| Audience | System integrators, security architects |

---

## Understanding WSC's Role

### What WSC Provides

WSC is a **cryptographic signing and verification component**. It provides:

| Capability | Description | Artifact References |
|------------|-------------|---------------------|
| Module Integrity | Ed25519 signatures ensure WASM modules haven't been tampered with | [[CG-1]] [[CG-2]] [[CR-1]] [[CR-3]] |
| Identity Binding | Keyless signing binds signatures to OIDC identities | [[CG-3]] [[CR-5]] [[CR-7]] |
| Transparency | Rekor log provides immutable audit trail | [[CG-4]] [[CR-5]] [[CR-8]] |
| Offline Verification | Airgapped mode for disconnected devices | [[CG-5]] [[CR-6]] [[CD-5]] |
| Provenance | SLSA-compliant supply chain attestation | [[CG-6]] [[CR-10]] [[CR-11]] |
| Confidentiality of Keys | Secure storage with zeroization and permission controls | [[CG-7]] [[CR-2]] [[CR-4]] |
| Defense in Depth | Certificate pinning, constant-time operations, bounded parsing | [[CG-8]] [[CR-9]] |
| Approved Cryptography | Ed25519 (128-bit), SHA-256, ECDSA P-256 | [[CR-1]] [[SP-1]] [[SP-2]] |

These capabilities map to cybersecurity goals [[CG-1]] through [[CG-8]] and cybersecurity requirements [[CR-1]] through [[CR-11]] defined in the WSC security evidence package.

### What WSC Does NOT Provide

WSC is a **component**, not a complete security solution. The following are outside WSC's scope and represent residual risks or integration responsibilities:

| Not Provided | Your Responsibility | Residual Risk / Limitation Reference |
|--------------|---------------------|--------------------------------------|
| System-level TARA | You perform TARA on your ITEM | [[RR-1]] -- WSC provides component-level evidence only |
| Secure boot | Integrate WSC into your boot chain | [[RR-2]] -- Hardware root of trust is your responsibility |
| Runtime protection | Use WASM runtime sandboxing | [[RR-3]] -- WSC verifies before execution, not during |
| HSM integration | Enable via `platform/` module when available | [[RR-4]] -- Software-only keys limit SL-C to 2 |
| Network security | Configure TLS, firewall rules | [[RR-5]] -- WSC pins certificates but does not manage network policy |
| OCSP/CRL revocation | Rely on short-lived Fulcio certs or manage CRL externally | [[RR-6]] -- No certificate revocation checking in WSC |

---

## Integration Workflow

### Step 1: Identify Your ITEM

Per ISO/SAE 21434, your ITEM is the vehicle system or component being assessed.

**Examples:**
- Vehicle OTA Update ECU
- Industrial PLC firmware loader
- IoT gateway update service
- Container orchestration node

**Document in your TARA:**
```
Item: [Your System Name]
+-- Component: WSC (WebAssembly Signature Component)
    +-- Function: Module signing and verification
    +-- Assets: Reference [[ASSET-001]] through [[ASSET-022]]
    +-- Controls: Reference [[CTRL-1]] through [[CTRL-7]]
```

### Step 2: Map WSC to Your Architecture

Identify where WSC sits in your trust boundaries. The diagram below shows the three primary zones and how data flows ([[DF-1]] through [[DF-10]]) traverse them:

```
+-------------------------------------------------------------+
|                    YOUR SYSTEM ITEM                          |
|  +----------------------------------------------------------+
|  |                   Build/CI Pipeline                       |
|  |  +-------------+    +-------------+                       |
|  |  | Source Code |---->| WSC Sign    |----> Signed Module   |
|  |  +-------------+    +-------------+                       |
|  |                          |                                |
|  |        [[DF-1]] Module ingestion                          |
|  |        [[DF-2]] Signing request                           |
|  |        [[DF-3]] Signed artifact output                    |
|  +----------------------------------------------------------+
|           --------------- Trust Boundary 1 ---------------   |
|  +----------------------------------------------------------+
|  |                   Distribution                            |
|  |  +-------------+    +-------------+                       |
|  |  | Module Repo |<---| CDN/Update  |                       |
|  |  +-------------+    +-------------+                       |
|  |                                                           |
|  |        [[DF-4]] Artifact publication                      |
|  |        [[DF-5]] Distribution channel                      |
|  +----------------------------------------------------------+
|           --------------- Trust Boundary 2 ---------------   |
|  +----------------------------------------------------------+
|  |                   Target Device                           |
|  |  +-------------+    +-------------+    +-------------+    |
|  |  | WSC Verify  |---->| WASM Runtime|---->| Application |   |
|  |  +-------------+    +-------------+    +-------------+    |
|  |                                                           |
|  |        [[DF-6]] Verification request                      |
|  |        [[DF-7]] Trust bundle lookup                       |
|  |        [[DF-8]] Verification result                       |
|  +----------------------------------------------------------+
+-------------------------------------------------------------+
```

**Controller mappings for each zone:**

| Zone | Controllers | Data Flows |
|------|------------|------------|
| Build/CI Pipeline | [[CTRL-1]] Signing authority, [[CTRL-2]] Identity provider | [[DF-1]] [[DF-2]] [[DF-3]] |
| Distribution | [[CTRL-3]] Artifact repository, [[CTRL-4]] Transparency log | [[DF-4]] [[DF-5]] [[DF-9]] |
| Target Device | [[CTRL-5]] Verification engine, [[CTRL-6]] Trust store, [[CTRL-7]] Runtime gatekeeper | [[DF-6]] [[DF-7]] [[DF-8]] [[DF-10]] |

### Step 3: Reference WSC Evidence

Include WSC documentation as evidence in your TARA work products. Each work product maps to specific WSC artifacts:

| Your Work Product | WSC Evidence to Reference | Key Artifacts |
|-------------------|---------------------------|---------------|
| Asset Identification | `docs/security/ASSET_INVENTORY.md` | [[ASSET-001]] through [[ASSET-022]] |
| Threat Scenarios | `docs/THREAT_MODEL.md` (STRIDE analysis) | [[TS-001]] through [[TS-018]] |
| Risk Assessment | `docs/security/RISK_ASSESSMENT.md` | [[RA-001]] through [[RA-018]], [[RR-1]] through [[RR-6]] |
| Cybersecurity Goals | `docs/TARA_COMPLIANCE.md` | [[CG-1]] through [[CG-8]] |
| Cybersecurity Requirements | `docs/TARA_COMPLIANCE.md` | [[CR-1]] through [[CR-11]] |
| Cybersecurity Designs | Security architecture docs | [[CD-1]] through [[CD-9]] |
| Security Properties | Cryptographic specifications | [[SP-1]] through [[SP-8]] |
| Key Management | `docs/KEY_LIFECYCLE.md` | [[ASSET-001]], [[ASSET-003]], [[SP-1]], [[SP-2]] |
| Incident Response | `docs/INCIDENT_RESPONSE.md` | [[CR-9]] |
| STPA Control Structure | Architecture diagrams | [[CTRL-1]] through [[CTRL-7]], [[SC-1]] through [[SC-11]] |
| Safety Constraints | Constraint analysis | [[CC-1]] through [[CC-12]], [[CP-1]] through [[CP-4]] |
| Verification Evidence | Test results, fuzz coverage | [[CV-1]] through [[CV-8]] |

**Example TARA Entry:**
```
Threat: T-42 - Unsigned firmware injection
Asset: ECU Firmware Module (maps to [[ASSET-008]])
Attack Vector: Compromise update channel, inject malicious module
Control: WSC signature verification ([[CTRL-5]], [[CD-3]])
Evidence: WSC RISK_ASSESSMENT.md [[TS-003]] (Module Tampering), [[RA-003]]
Risk Treatment: [[RR-1]] residual risk accepted at system level
Residual Risk: Low (WSC cryptographically prevents tampering)
```

### Step 4: Configure Security Level

WSC supports IEC 62443 Security Levels 1-2 natively, with SL3 requiring HSM:

| Your Target SL | WSC Configuration | Additional Requirements | Design References |
|----------------|-------------------|------------------------|-------------------|
| SL 1 | Default configuration | None | [[CD-1]] Basic signing/verification |
| SL 2 | Enable cert pinning, secure file permissions | Verify 0600 on key files | [[CD-2]] Hardened configuration, [[SP-3]] [[SP-4]] |
| SL 3 | Enable HSM backend | Configure `platform/` module, HSM hardware | [[CD-6]] HSM integration, [[CC-5]] Hardware key constraint |
| SL 4 | Not supported by WSC alone | External TEE, secure boot chain | [[RR-2]] Secure boot is integrator responsibility |

**Design artifacts for each security level:**

- **SL 1**: [[CD-1]] standard cryptographic operations, [[CR-1]] approved algorithms, [[CR-3]] integrity verification
- **SL 2**: All of SL 1 plus [[CD-2]] certificate pinning, [[CD-3]] secure file permissions, [[CD-4]] memory zeroization, [[SP-5]] constant-time comparisons
- **SL 3**: All of SL 2 plus [[CD-6]] HSM key storage (roadmap), [[CD-7]] hardware-bound operations. Constrained by [[CC-5]] requiring hardware key protection and [[CC-6]] requiring secure enclave operations
- **SL 4**: Requires [[CD-8]] TEE integration and [[CD-9]] secure boot chain, both outside WSC scope

**SL 3 Configuration Example:**
```rust
// Future: When HSM integration is complete
use wsc::platform::HsmBackend;

let hsm = HsmBackend::tpm2()?;
let sk = hsm.load_key("wsc-signing-key")?;
let signed = sk.sign(module, Some(&key_id))?;
```

### Step 5: Include in Incident Response

Your incident response plan should include WSC-specific scenarios. All incident scenarios map to cybersecurity requirement [[CR-9]] (incident response capability):

| Scenario | Your Actions | Reference | Related Artifacts |
|----------|--------------|-----------|-------------------|
| Signing key compromise | See WSC INC-1 procedure | `INCIDENT_RESPONSE.md` | [[CR-9]], [[TS-001]], [[RA-001]], [[CTRL-1]] |
| Malicious signed module | Identify signer, revoke key | `INCIDENT_RESPONSE.md` | [[CR-9]], [[TS-003]], [[RA-003]], [[CTRL-5]] |
| Sigstore outage | Switch to key-based signing | `INCIDENT_RESPONSE.md` | [[CR-9]], [[TS-006]], [[RA-006]], [[CD-5]] |
| WSC vulnerability (CVE) | Update WSC, verify modules | `INCIDENT_RESPONSE.md` | [[CR-9]], [[RR-6]], [[CV-7]] |

---

## Security Level Capability Statement

### Official Claim

**WSC Component Security Level (SL-C) = 2**

WSC provides security controls sufficient for IEC 62443 Security Level 2. The following security properties ([[SP-1]] through [[SP-8]]) underpin this claim:

| Security Property | Description | Artifact |
|-------------------|-------------|----------|
| Approved algorithms | Ed25519 (128-bit), SHA-256 | [[SP-1]] |
| Elliptic curve cryptography | ECDSA P-256 for Sigstore | [[SP-2]] |
| Secure file permissions | 0600 for secret keys | [[SP-3]] |
| Memory zeroization | Key material cleared on drop | [[SP-4]] |
| Constant-time operations | Prevents timing side channels | [[SP-5]] |
| Certificate pinning | Sigstore endpoint verification | [[SP-6]] |
| Bounded resource usage | 16 MB allocation limits | [[SP-7]] |
| Input validation | Fuzz-tested parsers | [[SP-8]] |

### SL 3 Path

Achieving SL-3 with WSC requires additional controls beyond the current component capability. These are tracked as cybersecurity design items:

1. **HSM Integration** ([[CD-6]], in development)
   - Hardware-protected key storage
   - Key operations in secure enclave
   - Resolves [[RR-4]] (software-only key limitation)

2. **Secure Boot Chain** ([[CD-8]], your responsibility)
   - Verified WSC binary loading
   - Attestation of runtime environment
   - Resolves [[RR-2]] (no hardware root of trust)

3. **Additional Hardening** ([[CD-9]], your responsibility)
   - Locked memory for sensitive operations
   - Anti-tamper monitoring
   - Addresses [[CC-11]] (physical tamper resistance) and [[CC-12]] (runtime integrity monitoring)

---

## TARA Work Product Templates

### Template: Asset Entry for WSC Keys

Use this template to add WSC assets to your system-level asset inventory. Reference the WSC asset inventory ([[ASSET-001]] through [[ASSET-022]]) for the complete set.

```markdown
## Asset: WSC Signing Key

| Property | Value |
|----------|-------|
| Asset ID | CRYPTO-001 |
| Type | Ed25519 Secret Key |
| WSC Reference | [[ASSET-001]] (Ed25519 Secret Key) |
| Owner | [Your Team] |
| Location | Build server, `/secure/keys/wsc-sign.sec` |
| Confidentiality | Critical |
| Integrity | Critical |
| Availability | High |
| Protection | File permissions (0600) [[SP-3]], zeroization [[SP-4]] |
| Backup | [Your backup procedure] |
| Threat Scenarios | [[TS-001]] (Key Theft), [[TS-005]] (Timing Attack) |
| Risk Assessment | [[RA-001]], [[RA-005]] |
```

### Template: Threat Scenario Using WSC

Use this template to incorporate WSC threats into your system-level TARA. Reference [[TS-001]] through [[TS-018]] for all component-level threats.

```markdown
## Threat: TS-042 - Update Channel Compromise

| Field | Value |
|-------|-------|
| Threat ID | TS-042 |
| Asset | WASM Application Module |
| WSC Assets | [[ASSET-008]] (Signed Module), [[ASSET-009]] (Signature Section) |
| Attack Goal | Execute malicious code on target device |
| Attack Vector | MitM on update channel, inject modified module |

### Attack Path
1. Attacker gains position on network path
2. Intercepts legitimate module download
3. Modifies module to include malicious code
4. Delivers modified module to target

### Controls
| Control | Type | Effectiveness | WSC Artifact |
|---------|------|---------------|--------------|
| TLS for download | Preventive | High (but not if CA compromised) | [[SP-6]] |
| **WSC Signature Verification** | Detective/Preventive | **Critical** | [[CTRL-5]], [[CD-3]], [[CR-3]] |
| Runtime sandboxing | Mitigating | Medium | [[RR-3]] (outside WSC scope) |

### Residual Risk Assessment
With WSC verification: **Negligible**
- Modified module fails SHA-256 hash verification ([[SP-1]])
- Attack is cryptographically infeasible
- Reference: WSC [[TS-003]] (Module Tampering), [[RA-003]]
```

### Template: Cybersecurity Requirement

Use this template to flow WSC cybersecurity requirements ([[CR-1]] through [[CR-11]]) into your system requirements.

```markdown
## Requirement: REQ-SEC-015 - Module Integrity Verification

| Field | Value |
|-------|-------|
| Requirement ID | REQ-SEC-015 |
| Title | WASM Module Signature Verification |
| Priority | Critical |
| Standard | ISO/SAE 21434 CR-03 |
| WSC Requirement | [[CR-3]] (Verify software integrity) |
| WSC Design | [[CD-3]] (Signature verification design) |

### Description
All WASM modules loaded by the system MUST be verified against
a trusted signature before execution.

### Implementation
- Use WSC `PublicKey::verify()` before module instantiation
- Reject modules with invalid or missing signatures
- Log verification results to audit trail
- References: [[CTRL-5]], [[DF-6]], [[DF-8]]

### Verification Method
- Unit tests for signature verification -- [[CV-1]]
- Integration test with tampered modules -- [[CV-2]]
- Fuzz testing of verification path -- [[CV-3]]

### Evidence
- WSC library test suite passing -- [[CV-1]] through [[CV-4]]
- Integration test results -- [[CV-5]]
- Fuzz testing coverage report -- [[CV-6]]
```

---

## Common Integration Patterns

### Pattern 1: Build-Time Signing

```
+------------+    +------------+    +------------+
|   Build    |---->| WSC Sign   |---->|  Publish   |
|   System   |    | (keyless)  |    |  Artifact  |
+------------+    +------------+    +------------+
                        |
                        v
                  +------------+
                  |   Rekor    | (Transparency Log)
                  +------------+
```

**Use Case**: CI/CD pipeline with GitHub Actions, GitLab CI
**WSC Mode**: Keyless signing with OIDC
**Benefit**: No long-lived keys to manage

**Relevant artifacts:**
- Controllers: [[CTRL-1]] (Signing authority), [[CTRL-2]] (Identity provider)
- Data flows: [[DF-1]] (Module ingestion), [[DF-2]] (Signing request), [[DF-3]] (Signed artifact output), [[DF-9]] (Transparency log entry)
- Designs: [[CD-1]] (Standard signing), [[CD-4]] (Memory zeroization for ephemeral keys)
- Safety constraints: [[SC-1]] (Only authorized identities may sign), [[SC-2]] (Ephemeral keys must not persist)

### Pattern 2: Airgapped Device Verification

```
+------------+         +------------+         +------------+
| Provision  |--------->| Trust      |--------->|  Device    |
|  Station   |         | Bundle     |         | (offline)  |
+------------+         +------------+         +------------+
                                                    |
                                              +-----+-----+
                                              | WSC       |
                                              | Airgapped |
                                              | Verify    |
                                              +-----------+
```

**Use Case**: Automotive ECU, industrial PLC, embedded IoT
**WSC Mode**: Airgapped verification with pre-provisioned trust bundle
**Benefit**: No network required at runtime

**Relevant artifacts:**
- Controllers: [[CTRL-5]] (Verification engine), [[CTRL-6]] (Trust store), [[CTRL-7]] (Runtime gatekeeper)
- Data flows: [[DF-6]] (Verification request), [[DF-7]] (Trust bundle lookup), [[DF-8]] (Verification result), [[DF-10]] (Trust bundle provisioning)
- Designs: [[CD-5]] (Airgapped verification design), [[CD-3]] (Signature verification)
- Safety constraints: [[SC-5]] (Device must not execute unverified modules), [[SC-6]] (Trust bundle integrity must be verified before use), [[SC-7]] (Verification must succeed without network access)
- Control process: [[CP-3]] (Offline verification process)

### Pattern 3: Multi-Stage Supply Chain

```
+----------+    +----------+    +----------+    +----------+
| Vendor A |---->| Vendor B |---->| OEM      |---->| Device   |
|  Sign    |    |  Sign    |    |  Sign    |    | Verify   |
+----------+    +----------+    +----------+    +----------+
     |               |               |
     v               v               v
+------------------------------------------------------------+
|                    Multi-Signature Chain                    |
|           (All signatures verified at device)              |
+------------------------------------------------------------+
```

**Use Case**: Automotive supply chain, tiered manufacturing
**WSC Mode**: Multi-signature with composition tracking
**Benefit**: Full provenance from source to deployment

**Relevant artifacts:**
- Controllers: [[CTRL-1]] (Signing authority -- multiple instances), [[CTRL-5]] (Verification engine -- validates chain)
- Data flows: [[DF-1]] through [[DF-3]] (repeated at each stage), [[DF-4]] (Inter-vendor handoff), [[DF-5]] (Distribution)
- Designs: [[CD-7]] (Multi-signature composition), [[CD-3]] (Signature verification)
- Safety constraints: [[SC-8]] (All signers in chain must be verified), [[SC-9]] (Composition manifest must be tamper-evident)
- Control process: [[CP-4]] (Multi-party signing process)
- Causal scenarios: [[CC-7]] (Missing signature in chain), [[CC-8]] (Unauthorized signer in chain)

---

## Checklist: WSC Integration for TARA

### Pre-Integration

- [ ] Identify your ITEM and scope -- reference [[CTRL-1]] through [[CTRL-7]] for WSC control structure
- [ ] Map WSC to your architecture diagram -- use data flows [[DF-1]] through [[DF-10]]
- [ ] Determine required Security Level (SL-T) -- see [[CD-1]] through [[CD-9]] for design options
- [ ] Review WSC security documentation -- start with [[CG-1]] through [[CG-8]] for goals

### Asset Inventory

- [ ] Add WSC assets to your asset inventory -- reference [[ASSET-001]] through [[ASSET-022]]
- [ ] Assign CIA ratings for your context -- WSC ratings in asset inventory are component-level baselines
- [ ] Document key storage locations -- see [[ASSET-001]] (secret key), [[ASSET-002]] (public key), [[SP-3]] (file permissions)

### Threat Analysis

- [ ] Reference WSC STRIDE analysis -- threat scenarios [[TS-001]] through [[TS-018]]
- [ ] Map WSC threats to your threat scenarios -- use [[RA-001]] through [[RA-018]] for attack feasibility
- [ ] Identify any additional threats from integration -- check [[SC-1]] through [[SC-11]] for safety constraint gaps
- [ ] Review causal scenarios -- [[CC-1]] through [[CC-12]] for how controls can fail

### Risk Assessment

- [ ] Reference WSC AF ratings -- [[RA-001]] through [[RA-018]] with ISO 21434 methodology
- [ ] Assess impact in YOUR system context -- WSC impact ratings are component-level only
- [ ] Document risk treatment decisions -- reference [[RR-1]] through [[RR-6]] for known residual risks
- [ ] Assign residual risk acceptance -- integrator responsibility per [[RR-1]]

### Implementation

- [ ] Configure WSC for your Security Level -- [[CD-1]] (SL1), [[CD-2]] (SL2), [[CD-6]] (SL3)
- [ ] Integrate verification into runtime -- [[CTRL-5]], [[DF-6]], [[DF-8]]
- [ ] Set up key management procedures -- [[ASSET-001]], [[SP-3]], [[SP-4]]
- [ ] Configure audit logging -- [[CR-5]], [[CR-8]]

### Verification

- [ ] Test signature verification path -- [[CV-1]] (unit tests), [[CV-2]] (tampered module tests)
- [ ] Test rejection of unsigned/invalid modules -- [[CV-3]] (negative tests), [[CV-4]] (boundary tests)
- [ ] Verify key rotation procedure -- [[CV-5]] (key lifecycle tests)
- [ ] Conduct penetration testing -- [[CV-6]] (fuzz testing), [[CV-7]] (security testing)
- [ ] Validate cybersecurity designs -- [[CV-8]] (design verification)

### Incident Response

- [ ] Include WSC scenarios in IR plan -- [[CR-9]] (incident response requirement)
- [ ] Test key compromise procedure -- INC-1 in `INCIDENT_RESPONSE.md`, references [[TS-001]], [[RA-001]]
- [ ] Establish communication channels -- see emergency contacts in `INCIDENT_RESPONSE.md`
- [ ] Document Sigstore fallback procedure -- [[CD-5]], [[TS-006]]

---

## Frequently Asked Questions

### Q: Can I claim my system is "TARA compliant" because I use WSC?

**No.** WSC provides component-level security evidence. TARA is performed on your ITEM (vehicle, ECU, system). You must perform your own TARA and reference WSC evidence as supporting documentation. Specifically:

- WSC cybersecurity goals ([[CG-1]] through [[CG-8]]) are **component goals** -- they feed into your system goals
- WSC risk assessments ([[RA-001]] through [[RA-018]]) rate **component risks** -- you must assess system-level impact
- WSC residual risks ([[RR-1]] through [[RR-6]]) require **your acceptance** -- the integrator owns residual risk decisions

### Q: What Security Level can I claim with WSC?

WSC component security level is SL-C = 2 (supported by [[SP-1]] through [[SP-8]]). Your system security level (SL-T) depends on:
- All components meeting the target SL
- System-level security architecture (your own cybersecurity design artifacts)
- Operational security procedures
- For SL-3: WSC requires HSM integration ([[CD-6]]), resolving [[RR-4]]

### Q: Do I need Sigstore for ISO 21434 compliance?

No. Key-based signing is sufficient (see [[CD-1]]). Keyless signing adds:
- Non-repudiation via Rekor transparency log ([[CG-4]], [[CR-5]])
- Identity binding without key management ([[CG-3]], [[CR-7]])
- Useful for CI/CD environments ([[CP-1]])

### Q: How do I handle WSC updates in a certified system?

1. Evaluate the update for security impact -- check against [[TS-001]] through [[TS-018]]
2. Regression test verification functionality -- run [[CV-1]] through [[CV-8]]
3. Update your TARA if risk profile changes -- reassess [[RA-001]] through [[RA-018]]
4. Document the change in your configuration management
5. If the update addresses a CVE, follow [[CR-9]] (incident response) procedures

### Q: Which artifacts should I reference in my own TARA documentation?

At minimum, reference these WSC artifacts in your system TARA:

| Your TARA Section | Minimum WSC Artifact References |
|-------------------|---------------------------------|
| Asset identification | [[ASSET-001]], [[ASSET-008]], [[ASSET-014]] |
| Threat scenarios | [[TS-001]], [[TS-003]], [[TS-004]] (plus any relevant to your context) |
| Risk treatment | [[RA-001]], [[RA-003]], [[RA-004]], [[RR-1]] through [[RR-6]] |
| Security goals | [[CG-1]] through [[CG-8]] |
| Security requirements | [[CR-1]], [[CR-2]], [[CR-3]], [[CR-9]] |
| Verification | [[CV-1]] through [[CV-8]] |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-06 | WSC Team | Initial integration guidance |
| 2.0 | 2026-01-06 | WSC Team | Converted to Rivet format with artifact references |
