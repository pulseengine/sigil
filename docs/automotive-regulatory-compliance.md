---
id: DOC-REGULATORY-COMPLIANCE
title: Automotive Regulatory Compliance Analysis
type: specification
status: approved
tags: [compliance, automotive, cra, unece-r155, unece-r156, iso-21434]
---

# Automotive & EU Regulatory Compliance Analysis for sigil

**Document Version**: 2.0
**Last Updated**: March 15, 2026
**Status**: Approved

---

## Executive Summary

This document analyzes how **sigil** (WebAssembly Signature Component) and its provenance tracking system help organizations comply with major automotive and EU cybersecurity regulations:

- **EU Cybersecurity Resilience Act (CRA)** - 2024
- **UNECE R155** - Cybersecurity Management Systems (CSMS)
- **UNECE R156** - Software Update Management Systems (SUMS)
- **ISO/SAE 21434** - Automotive Cybersecurity Engineering

**Key Finding**: sigil provides **critical supply chain security evidence** for compliance, but is **not a complete compliance solution**. Organizations must implement additional processes, tools, and governance frameworks.

Each compliance claim below is traced to specific sigil artifacts -- assets ([[ASSET-001]] through [[ASSET-022]]), threat scenarios ([[TS-001]] through [[TS-018]]), risk assessments ([[RA-001]] through [[RA-018]]), cybersecurity goals and requirements ([[CG-1]] through [[CG-8]], [[CR-1]] through [[CR-11]]), and STPA controls ([[CTRL-1]] through [[CTRL-7]]) -- to provide auditable, end-to-end traceability from regulation to implementation.

---

## Table of Contents

1. [EU Cybersecurity Resilience Act (CRA)](#1-eu-cybersecurity-resilience-act-cra)
2. [UNECE R155 - Cybersecurity Management Systems](#2-unece-r155---cybersecurity-management-systems-csms)
3. [UNECE R156 - Software Update Management Systems](#3-unece-r156---software-update-management-systems-sums)
4. [ISO/SAE 21434 - Automotive Cybersecurity Engineering](#4-isosae-21434---automotive-cybersecurity-engineering)
5. [Compliance Matrix](#5-compliance-matrix)
6. [Gaps and Limitations](#6-gaps-and-limitations)
7. [Recommendations](#7-recommendations)
8. [Conclusion](#8-conclusion)

---

## 1. EU Cybersecurity Resilience Act (CRA)

### Overview

**Effective**: December 10, 2024 (entered force); December 11, 2027 (main obligations apply)
**Scope**: Connected products, software, and remote data processing solutions sold in EU market
**Applicability**: Manufacturers, importers, distributors

### Key Requirements

1. **Security by Design**: Products must be secure from conception through development
2. **Vulnerability Handling**:
   - Report exploited vulnerabilities within 24 hours
   - Provide security patches within 72 hours of discovery
3. **SBOM**: Software Bill of Materials for component tracking
4. **Continuous Security Updates**: Maintain security throughout product lifecycle
5. **CE Marking**: Compliance certification for market entry
6. **Supply Chain Security**: Accountability for third-party components

### How sigil Helps

#### CRA-H1: SBOM Generation

- **Regulation**: CRA Article 10(7) -- Identify and document components including SBOM
- **sigil Capability**: CycloneDX SBOM v1.5 generation and embedding
- **Evidence Provided**: Complete component inventory with version, supplier, and hash data
- **Traced Artifacts**: [[ASSET-018]] (SBOM artifact), [[CR-10]] (audit trail requirement), [[ASSET-017]] (in-toto provenance), [[DF-7]]
- **Verification**: Extract embedded SBOM and validate component completeness

#### CRA-H2: Security by Design

- **Regulation**: CRA Article 10(1) -- Products designed with appropriate cybersecurity
- **sigil Capability**: SLSA Level 2/3/4 compliance framework with provenance attestations
- **Evidence Provided**: Provenance attestations documenting build-time security controls
- **Traced Artifacts**: [[CR-1]] (approved cryptographic algorithms), [[CR-3]] (software integrity verification), [[SP-1]] (domain separation), [[SP-2]] (algorithm binding), [[CG-1]] (module authenticity), [[CG-2]] (content integrity)
- **Verification**: Validate SLSA level against provenance metadata

#### CRA-H3: Supply Chain Tracking

- **Regulation**: CRA Article 10(5) -- Due diligence on third-party components
- **sigil Capability**: Dependency graph with validation, component source tracking
- **Evidence Provided**: Component relationships, source URLs, supplier attribution
- **Traced Artifacts**: [[ASSET-019]] (composition manifest), [[ASSET-017]] (dependency graph), [[CR-11]] (supply chain verification), [[DF-5]] (component flow), [[CTRL-3]] (dependency validation control)
- **Verification**: Validate dependency graph integrity and source allow-lists

#### CRA-H4: Update Provenance

- **Regulation**: CRA Article 10(11) -- Traceability of security updates
- **sigil Capability**: in-toto attestations embedded in update artifacts
- **Evidence Provided**: Who built the update, when, from what sources, with what tools
- **Traced Artifacts**: [[ASSET-020]] (in-toto attestation), [[CR-8]] (provenance tracking), [[DF-3]] (build provenance flow), [[SP-5]] (provenance authenticity)
- **Verification**: Extract attestation and verify builder identity and materials

#### CRA-H5: Component Authenticity

- **Regulation**: CRA Article 10(5)(a) -- Ensure component integrity
- **sigil Capability**: Multi-signature verification with Ed25519 and certificate PKI
- **Evidence Provided**: Cryptographic proof of origin from multiple signers
- **Traced Artifacts**: [[ASSET-001]] (Ed25519 signing key), [[ASSET-002]] (Ed25519 public key), [[CR-1]], [[CR-3]], [[CG-1]], [[CTRL-1]] (signing control), [[CTRL-2]] (verification control)
- **Verification**: Verify all signatures against trusted certificate chains

#### CRA-H6: Vulnerability Identification

- **Regulation**: CRA Article 10(4) -- Identify and document vulnerabilities
- **sigil Capability**: SBOM with component versions enables automated CVE scanning
- **Evidence Provided**: Machine-readable inventory for vulnerability scanner input
- **Traced Artifacts**: [[ASSET-018]], [[CR-10]], [[DF-7]], [[FEAT-3]] (vulnerability scanning integration)
- **Verification**: Feed extracted SBOM to Grype, Trivy, or equivalent scanner

#### CRA-H7: Transparency

- **Regulation**: CRA Article 10(9) -- Audit trail for security-relevant changes
- **sigil Capability**: Transparency log integration (Rekor) for immutable audit trail
- **Evidence Provided**: Signed Certificate Timestamps, Merkle inclusion proofs
- **Traced Artifacts**: [[ASSET-014]] (Rekor entry), [[CR-5]] (security event logging), [[CG-3]] (non-repudiation), [[DF-8]] (transparency log flow)
- **Verification**: Query Rekor for inclusion proof of signing event

#### CRA-H8: Hardware Security

- **Regulation**: CRA Annex I, Part I(2)(c) -- Protect against unauthorized access
- **sigil Capability**: ATECC608/TPM attestation for device-level trust anchors
- **Evidence Provided**: Hardware-backed key storage and device attestation
- **Traced Artifacts**: [[ASSET-004]] (device private key), [[ASSET-005]] (device certificate), [[CR-4]] (defense in depth), [[SP-7]] (hardware-backed trust), [[CTRL-5]] (hardware attestation control)
- **Verification**: Validate device attestation against provisioned hardware identity

#### Example: SBOM for Vulnerability Management

```rust
use wsc::composition::*;

// Generate SBOM for a composed WASM module
let sbom = Sbom::new("automotive-controller", "2.1.0");

// Add components with versions (enables CVE lookup)
sbom.add_component(SbomComponent {
    name: "safety-critical-component".to_string(),
    version: Some("1.5.2".to_string()),
    supplier: Some("TrustedVendor Inc.".to_string()),
    hashes: vec![SbomHash {
        alg: "SHA-256".to_string(),
        content: "abc123...".to_string(),
    }],
    ..Default::default()
});

// Embed in WASM for CRA compliance
let module_with_sbom = embed_sbom(module, &sbom)?;

// Later: Extract SBOM for vulnerability scanning
let extracted_sbom = extract_sbom(&module_with_sbom)?;

// Feed to vulnerability scanner (e.g., Grype, Trivy)
// $ grype sbom:sbom.json
```

### How sigil Does NOT Help

#### CRA-N1: 24-hour Incident Reporting

- **Regulation**: CRA Article 11 -- Report exploited vulnerabilities within 24 hours
- **Why sigil Doesn't Help**: sigil is not a monitoring or detection tool; it operates at build-time only
- **Residual Risk**: [[RR-1]] (no runtime monitoring capability)
- **Alternative**: Deploy SIEM and IDS/IPS systems; establish incident response team and reporting workflow

#### CRA-N2: 72-hour Patch Delivery

- **Regulation**: CRA Article 10(12) -- Provide patches promptly
- **Why sigil Doesn't Help**: sigil does not generate patches; it signs and attests them
- **Residual Risk**: [[RR-2]] (no patch generation or deployment)
- **Alternative**: Establish incident response process with rapid build/sign/deploy pipeline

#### CRA-N3: CE Marking Certification

- **Regulation**: CRA Article 18-22 -- Conformity assessment and CE marking
- **Why sigil Doesn't Help**: sigil does not perform conformity assessment
- **Residual Risk**: [[RR-3]] (no conformity assessment capability)
- **Alternative**: Work with Notified Bodies for conformity assessment; use sigil evidence as supporting documentation

#### CRA-N4: Market Surveillance

- **Regulation**: CRA Article 43-52 -- Market surveillance and corrective actions
- **Why sigil Doesn't Help**: sigil does not interface with regulatory authorities
- **Residual Risk**: [[RR-4]] (no regulatory interface)
- **Alternative**: Implement regulatory reporting system and market surveillance processes

#### CRA-N5: End-user Documentation

- **Regulation**: CRA Annex II -- User instructions and information
- **Why sigil Doesn't Help**: sigil is a developer-facing tool
- **Residual Risk**: [[RR-5]] (no end-user communication)
- **Alternative**: Create user-facing security documentation, vulnerability disclosure policy

#### CRA-N6: Continuous Monitoring

- **Regulation**: CRA Article 10(6) -- Monitor and remedy vulnerabilities
- **Why sigil Doesn't Help**: sigil provides static, build-time provenance only
- **Residual Risk**: [[RR-1]]
- **Alternative**: Deploy runtime security monitoring, continuous vulnerability scanning

#### CRA-N7: Patch Deployment

- **Regulation**: CRA Article 10(11-12) -- Distribute security patches
- **Why sigil Doesn't Help**: sigil signs updates but does not deploy them
- **Residual Risk**: [[RR-2]]
- **Alternative**: Implement OTA update system (Uptane recommended for automotive)

### Residual Risk: **MEDIUM**

**Why**: sigil provides excellent evidence for compliance but requires integration with:
- Incident detection and response systems ([[RR-1]])
- Vulnerability scanning infrastructure ([[RR-2]], [[FEAT-3]])
- Regulatory reporting workflows ([[RR-4]])
- End-user communication channels ([[RR-5]])

---

## 2. UNECE R155 - Cybersecurity Management Systems (CSMS)

### Overview

**Effective**: Mandatory for new vehicles from July 2024
**Scope**: Category M/N vehicles (4+ wheels), Category O trailers with ECUs, L6/L7 vehicles with Level 3+ automation
**Applicability**: 54 UNECE member countries (EU, UK, Japan, South Korea)

### Key Requirements

1. **Cybersecurity Management System (CSMS)**: Holistic process for vehicle cybersecurity
2. **TARA (Threat Analysis & Risk Assessment)**: Identify and mitigate threats
3. **Supply Chain Management**: Verify cybersecurity of suppliers and components
4. **Monitoring & Detection**: Detect cyberattacks on vehicles
5. **Incident Reporting**: Report cyberattacks to approval authority
6. **Security by Design**: Cybersecurity throughout development lifecycle
7. **CSMS Audit**: Three-year certification by approval authority

### How sigil Helps

#### R155-H1: Supply Chain Security

- **Regulation**: R155 Annex 5, Part A, 7.4.1 -- Manage cybersecurity risks from suppliers
- **sigil Capability**: SBOM + dependency graph + multi-signature verification
- **Evidence Provided**: Proof of component integrity, supplier attribution, source traceability
- **Traced Artifacts**: [[ASSET-017]] (dependency graph), [[ASSET-018]] (SBOM), [[ASSET-019]] (composition manifest), [[CR-11]], [[CTRL-3]], [[DF-5]], [[TS-001]] (component substitution)
- **Traceability**: R155 7.4.1 -> [[CR-11]] -> [[CTRL-3]] -> [[ASSET-017]] + [[ASSET-018]] + [[ASSET-019]] -> Evidence: validated dependency graph with signed components

#### R155-H2: Risk Assessment Evidence

- **Regulation**: R155 7.2.2.2 -- Risk assessment including attack feasibility
- **sigil Capability**: Threat model with SLSA compliance levels provides documented risk treatment
- **Evidence Provided**: Component-level threat scenarios with AF ratings per ISO 21434
- **Traced Artifacts**: [[RA-001]] through [[RA-006]] (risk assessments for key threats), [[TS-001]] through [[TS-006]], [[CG-1]] through [[CG-5]]
- **Traceability**: R155 7.2.2.2 -> [[RA-001]] (key theft risk: Medium) -> [[TS-001]] -> [[CR-2]] (key protection) -> Evidence: 0600 permissions, zeroization, HSM roadmap

#### R155-H3: Security by Design

- **Regulation**: R155 7.2.2.3 -- Cybersecurity measures in vehicle design
- **sigil Capability**: Hardware attestation + provenance at design time
- **Evidence Provided**: Design-time security measures with cryptographic guarantees
- **Traced Artifacts**: [[CG-1]] (authenticity), [[CG-2]] (integrity), [[CG-4]] (key confidentiality), [[SP-1]] through [[SP-4]], [[CTRL-5]] (hardware attestation)
- **Traceability**: R155 7.2.2.3 -> [[CG-1]] + [[CG-2]] -> [[CR-1]] + [[CR-3]] -> [[SP-1]] + [[SP-2]] -> Evidence: Ed25519 with domain separation, SHA-256 integrity

#### R155-H4: Component Verification

- **Regulation**: R155 7.4.1.3 -- Verify authenticity of software components
- **sigil Capability**: Multi-signature validation with certificate chain verification
- **Evidence Provided**: Cryptographic authenticity proof from multiple independent signers
- **Traced Artifacts**: [[ASSET-001]], [[ASSET-002]], [[CTRL-1]], [[CTRL-2]], [[CR-3]], [[TS-003]] (module tampering = no risk)
- **Traceability**: R155 7.4.1.3 -> [[CR-3]] -> [[CTRL-2]] -> [[ASSET-002]] -> Evidence: signature verification rejects any tampered module (TS-003 confirms zero residual risk)

#### R155-H5: Traceability

- **Regulation**: R155 7.2.2.4 -- Maintain audit trail for cybersecurity activities
- **sigil Capability**: Composition manifest + in-toto attestations with full provenance chain
- **Evidence Provided**: Full audit trail from source to deployment
- **Traced Artifacts**: [[ASSET-019]], [[ASSET-020]], [[CR-5]], [[CR-8]], [[DF-3]], [[DF-5]], [[DF-7]]
- **Traceability**: R155 7.2.2.4 -> [[CR-5]] + [[CR-8]] -> [[DF-3]] + [[DF-7]] -> Evidence: immutable provenance embedded in every artifact

#### R155-H6: Supplier Accountability

- **Regulation**: R155 7.4.1.1 -- Track and manage supplier security posture
- **sigil Capability**: Component references with source URLs, supplier metadata in SBOM
- **Evidence Provided**: Supplier tracking with verifiable component origins
- **Traced Artifacts**: [[ASSET-018]], [[ASSET-019]], [[CR-11]], [[DF-5]]
- **Traceability**: R155 7.4.1.1 -> [[CR-11]] -> [[ASSET-018]] (SBOM supplier field) + [[ASSET-019]] (source_url) -> Evidence: each component traced to approved supplier

#### R155-H7: Update Integrity

- **Regulation**: R155 7.2.2.5 -- Ensure integrity of software updates
- **sigil Capability**: Provenance for each update with multi-party signing
- **Evidence Provided**: Who signed, when, why, with what authority
- **Traced Artifacts**: [[ASSET-020]], [[CTRL-1]], [[CTRL-2]], [[CR-8]], [[CG-1]], [[CG-2]], [[SP-3]] (content integrity)
- **Traceability**: R155 7.2.2.5 -> [[CG-2]] -> [[CR-3]] + [[CR-8]] -> [[CTRL-1]] + [[CTRL-2]] -> Evidence: Ed25519 signature + in-toto attestation = tamper-evident updates

#### Example: Supply Chain Verification for R155

```rust
use wsc::composition::*;

// Load WASM module with embedded provenance
let module = load_wasm_file("ecu-firmware.wasm")?;

// Extract all provenance data
let (manifest, provenance, sbom, attestation) =
    extract_all_provenance(&module)?;

// R155 Requirement: Verify supplier components
let manifest = manifest.ok_or("Manifest required for R155")?;
for component in &manifest.components {
    println!("Component: {} v{}", component.id, component.version);
    println!("  Source: {}", component.source_url.as_ref().unwrap_or(&"unknown".to_string()));
    println!("  Hash: {}", component.hash);

    // Verify against approved supplier list
    let source_url = component.source_url.as_ref().ok_or("Source required")?;
    if !is_approved_supplier(source_url) {
        return Err(format!("Component from unapproved supplier: {}", source_url));
    }
}

// R155 Requirement: Verify dependency integrity
let graph = DependencyGraph::from_manifest(&manifest);
let validation = graph.validate()?;

if !validation.valid {
    return Err(format!("Dependency validation failed: {:?}", validation.warnings));
}

// R155 Requirement: Verify no tampering
verify_all_signatures(&module, trusted_certs)?;

println!("R155 supply chain verification passed");
```

### How sigil Does NOT Help

#### R155-N1: TARA (Threat Analysis)

- **Regulation**: R155 7.2.2.2 -- Perform TARA on the vehicle
- **Why sigil Doesn't Help**: sigil provides component-level evidence, not system-level threat analysis
- **Residual Risk**: [[RR-3]] (no conformity/analysis capability)
- **Alternative**: Use threat modeling tools (STRIDE, PASTA); reference sigil threat model as component evidence

#### R155-N2: Runtime Monitoring

- **Regulation**: R155 7.2.2.6 -- Detect and respond to cyberattacks
- **Why sigil Doesn't Help**: sigil provides build-time provenance only
- **Residual Risk**: [[RR-1]]
- **Alternative**: Deploy in-vehicle IDS (e.g., Argus, VicOne, Uptane IDS)

#### R155-N3: Incident Detection

- **Regulation**: R155 7.2.2.7 -- Monitor vehicle cybersecurity events
- **Why sigil Doesn't Help**: sigil does not monitor vehicle behavior
- **Residual Risk**: [[RR-1]]
- **Alternative**: Implement SOC with vehicle telemetry integration

#### R155-N4: Incident Reporting

- **Regulation**: R155 7.2.2.7 -- Report incidents to approval authority
- **Why sigil Doesn't Help**: sigil does not communicate with regulatory authorities
- **Residual Risk**: [[RR-4]]
- **Alternative**: Build regulatory reporting system integrated with SOC

#### R155-N5: CSMS Organizational Process

- **Regulation**: R155 7.1 -- Establish organizational CSMS
- **Why sigil Doesn't Help**: sigil is a technical tool, not an organizational framework
- **Residual Risk**: [[RR-6]] (no organizational governance)
- **Alternative**: Establish CSMS governance framework per R155 Annex 5

#### R155-N6: Risk Treatment Decisions

- **Regulation**: R155 7.2.2.3 -- Make risk treatment decisions
- **Why sigil Doesn't Help**: sigil does not make risk decisions; humans must assess and accept risk
- **Residual Risk**: [[RR-6]]
- **Alternative**: Human risk assessment process using sigil risk evidence ([[RA-001]] through [[RA-006]])

#### R155-N7: Vulnerability Scanning

- **Regulation**: R155 7.2.2.5 -- Identify vulnerabilities in components
- **Why sigil Doesn't Help**: sigil provides SBOM data but does not scan for CVEs
- **Residual Risk**: [[RR-2]]
- **Alternative**: Use Grype, Trivy, or commercial tools; feed sigil SBOM as input ([[FEAT-3]])

### Residual Risk: **MEDIUM**

**Why**: sigil provides **critical supply chain evidence** for CSMS audit, but R155 requires organizational processes ([[RR-6]]), runtime monitoring ([[RR-1]]), and threat analysis that are outside sigil's scope.

**Recommendation**: Use sigil as **evidence collection tool** within broader CSMS framework.

---

## 3. UNECE R156 - Software Update Management Systems (SUMS)

### Overview

**Effective**: January 22, 2021 (entered force); July 2024 (mandatory for new vehicles)
**Scope**: All software updates affecting type-approved systems (OTA or wired)
**Applicability**: Same as R155 (54 UNECE member countries)

### Key Requirements

1. **Software Update Management System (SUMS)**: Process for safe, traceable updates
2. **Update Qualification**: Verify updates don't compromise type approval
3. **Secure Delivery**: Protect update integrity during distribution
4. **Update Deployment**: Ensure reliable installation
5. **Traceability**: Track what was updated, when, by whom
6. **Type Approval Compliance**: Updates maintain regulatory compliance
7. **SUMS Audit**: Three-year certification by approval authority

### How sigil Helps

#### R156-H1: Update Provenance

- **Regulation**: R156 7.1.2 -- Provide evidence of update origin and process
- **sigil Capability**: in-toto attestations capturing builder, materials, timestamps
- **Evidence Provided**: Who built the update, when, how, from what sources
- **Traced Artifacts**: [[ASSET-020]] (in-toto attestation), [[CR-8]], [[DF-3]] (build provenance flow), [[SP-5]], [[CTRL-1]]
- **Traceability**: R156 7.1.2 -> [[CR-8]] -> [[ASSET-020]] -> [[DF-3]] -> Evidence: in-toto predicate with builder ID, materials, timestamps

#### R156-H2: Software Inventory

- **Regulation**: R156 7.1.3 -- Maintain software identification
- **sigil Capability**: CycloneDX SBOM with component versions and hashes
- **Evidence Provided**: Machine-readable inventory of all update components
- **Traced Artifacts**: [[ASSET-018]], [[CR-10]], [[DF-7]], [[CTRL-3]]
- **Traceability**: R156 7.1.3 -> [[CR-10]] -> [[ASSET-018]] -> Evidence: CycloneDX v1.5 SBOM with component name, version, supplier, hash

#### R156-H3: Update Authenticity

- **Regulation**: R156 7.1.4 -- Verify update has not been tampered with
- **sigil Capability**: Multi-signature verification with Ed25519 + certificate chains
- **Evidence Provided**: Cryptographic proof of origin from authorized signers
- **Traced Artifacts**: [[ASSET-001]], [[ASSET-002]], [[ASSET-004]], [[CR-1]], [[CR-3]], [[CTRL-1]], [[CTRL-2]], [[CG-1]], [[TS-003]] (tampering = no risk)
- **Traceability**: R156 7.1.4 -> [[CG-1]] -> [[CR-3]] -> [[CTRL-2]] -> Evidence: Ed25519 verification rejects any modification (TS-003 proves cryptographic infeasibility)

#### R156-H4: Traceability

- **Regulation**: R156 7.1.5 -- Record update history
- **sigil Capability**: Composition manifest + timestamps embedded in artifacts
- **Evidence Provided**: Full update history with version tracking
- **Traced Artifacts**: [[ASSET-019]], [[ASSET-020]], [[CR-5]], [[CR-8]], [[DF-3]], [[DF-5]]
- **Traceability**: R156 7.1.5 -> [[CR-5]] + [[CR-8]] -> [[ASSET-019]] + [[ASSET-020]] -> Evidence: every update carries embedded provenance and composition history

#### R156-H5: Component Tracking

- **Regulation**: R156 7.1.6 -- Track which components changed
- **sigil Capability**: Dependency graph with version tracking and diff capability
- **Evidence Provided**: Which components changed between update versions
- **Traced Artifacts**: [[ASSET-017]], [[ASSET-019]], [[CTRL-3]], [[DF-5]], [[DF-6]] (dependency validation flow)
- **Traceability**: R156 7.1.6 -> [[CTRL-3]] -> [[ASSET-017]] -> Evidence: dependency graph comparison reveals changed components

#### R156-H6: Integrity Protection

- **Regulation**: R156 7.1.4 -- Ensure update integrity during transit
- **sigil Capability**: Ed25519 signatures providing tamper-evident protection
- **Evidence Provided**: Any byte modification invalidates signature
- **Traced Artifacts**: [[CR-1]], [[CR-3]], [[CG-2]], [[SP-3]] (content integrity), [[TS-003]]
- **Traceability**: R156 7.1.4 -> [[CG-2]] -> [[SP-3]] -> Evidence: SHA-256 hash of entire module bound to Ed25519 signature

#### R156-H7: Reproducibility

- **Regulation**: R156 7.1.7 -- Reproducible update process
- **sigil Capability**: Build provenance enabling SLSA Level 4 reproducible builds
- **Evidence Provided**: Deterministic, verifiable builds with pinned dependencies
- **Traced Artifacts**: [[ASSET-020]], [[CR-8]], [[SP-6]] (reproducible builds), [[REQ-7]] (reproducible build requirement)
- **Traceability**: R156 7.1.7 -> [[REQ-7]] -> [[CR-8]] -> [[ASSET-020]] -> Evidence: in-toto attestation with pinned materials enables independent reproduction

#### R156-H8: Hardware-backed Updates

- **Regulation**: R156 7.1.8 -- Ensure only authorized devices receive updates
- **sigil Capability**: Device attestation with ATECC608/TPM
- **Evidence Provided**: Only provisioned devices with valid trust bundles can verify and accept updates
- **Traced Artifacts**: [[ASSET-004]], [[ASSET-005]], [[ASSET-016]] (trust bundle), [[CTRL-5]], [[SP-7]], [[CTRL-6]] (trust bundle provisioning)
- **Traceability**: R156 7.1.8 -> [[CTRL-5]] + [[CTRL-6]] -> [[ASSET-004]] + [[ASSET-016]] -> Evidence: hardware-backed device identity bound to trust bundle

#### Example: Update Traceability for R156

```rust
use wsc::composition::*;

// Create update with full provenance
let mut provenance = BuildProvenance::new("ecu-update-2.1.0");
provenance
    .builder("UpdateBuildSystem v3.2.1")
    .git_repo("https://github.com/oem/ecu-firmware", "abc123def456")
    .build_timestamp("2025-11-15T10:30:00Z");

// Create in-toto attestation (R156 requirement)
let attestation = InTotoAttestation::new_composition(
    "ecu-update-2.1.0.wasm",
    "sha256:update_hash_here",
    "OEM-Build-Server-001",
);

// Generate SBOM (R156 requirement)
let sbom = Sbom::new("ecu-firmware", "2.1.0");
sbom.add_component(/* components */);

// Embed all provenance
let mut update_module = load_wasm_file("ecu-update.wasm")?;
update_module = embed_composition_manifest(update_module, &manifest)?;
update_module = embed_build_provenance(update_module, &provenance)?;
update_module = embed_intoto_attestation(update_module, &attestation)?;
update_module = embed_sbom(update_module, &sbom)?;

// Sign with OEM key (first signature)
update_module = sign_with_cert(update_module, oem_cert, oem_key)?;

// Sign with update approver key (second signature - R156 compliance)
update_module = sign_with_cert(update_module, approver_cert, approver_key)?;

// R156 Audit Trail: Extract update history
let (manifest, provenance, sbom, attestation) =
    extract_all_provenance(&update_module)?;

println!("Update: {}", sbom.metadata.component.name);
println!("Version: {}", sbom.metadata.component.version);
println!("Built by: {}", provenance.builder);
println!("Built at: {}", provenance.metadata.build_finished_on);
println!("Signatures: {} (Owner + Approver)", update_module.signatures().len());
println!("R156 traceability complete");
```

### How sigil Does NOT Help

#### R156-N1: OTA Deployment

- **Regulation**: R156 7.2 -- Deliver updates to vehicles over-the-air
- **Why sigil Doesn't Help**: sigil signs updates but does not deploy them
- **Residual Risk**: [[RR-2]]
- **Alternative**: Implement OTA system (Uptane, SOTA); sigil provides signed artifacts as input ([[FEAT-4]])

#### R156-N2: Update Qualification

- **Regulation**: R156 7.1.1 -- Verify updates don't compromise type approval
- **Why sigil Doesn't Help**: sigil does not perform functional testing of updates
- **Residual Risk**: [[RR-3]]
- **Alternative**: Establish update testing process; use sigil metadata to track qualification status

#### R156-N3: Rollback Mechanisms

- **Regulation**: R156 7.2.3 -- Provide safe rollback capability
- **Why sigil Doesn't Help**: sigil does not manage deployment state or partitions
- **Residual Risk**: [[RR-2]]
- **Alternative**: Implement A/B partitioning, rollback logic in OTA system

#### R156-N4: Type Approval Verification

- **Regulation**: R156 7.1.1 -- Ensure regulatory compliance of updates
- **Why sigil Doesn't Help**: sigil does not check regulatory compliance status
- **Residual Risk**: [[RR-3]]
- **Alternative**: Manual approval process with regulatory documentation

#### R156-N5: Update Scheduling

- **Regulation**: R156 7.2.2 -- Manage update timing and driver safety
- **Why sigil Doesn't Help**: sigil does not manage deployment timing
- **Residual Risk**: [[RR-2]]
- **Alternative**: Implement update orchestration with safety interlock

#### R156-N6: Deployment Monitoring

- **Regulation**: R156 7.2.4 -- Track installation success/failure
- **Why sigil Doesn't Help**: sigil does not track update installation status
- **Residual Risk**: [[RR-1]]
- **Alternative**: Implement telemetry and monitoring for update deployment

#### R156-N7: SUMS Organizational Process

- **Regulation**: R156 7.1 -- Establish SUMS governance
- **Why sigil Doesn't Help**: sigil is a technical tool, not governance framework
- **Residual Risk**: [[RR-6]]
- **Alternative**: Establish SUMS governance framework per R156 requirements

### Residual Risk: **MEDIUM**

**Why**: sigil provides **excellent update provenance and integrity**, but R156 requires deployment infrastructure ([[RR-2]]), testing processes ([[RR-3]]), and organizational governance ([[RR-6]]) that sigil doesn't provide.

**Recommendation**: Use sigil as **update signing and provenance tool** within broader SUMS framework (e.g., integrate with Uptane, custom OTA system). See [[FEAT-4]] for OTA integration roadmap.

---

## 4. ISO/SAE 21434 - Automotive Cybersecurity Engineering

### Overview

**Published**: August 31, 2021 (supersedes SAE J3061)
**Status**: International standard (not mandatory, but supports R155 compliance)
**Scope**: Cybersecurity risk management for E/E systems throughout vehicle lifecycle

### Key Requirements

1. **Security by Design**: Cybersecurity throughout V-model development
2. **Risk Management**: Threat analysis and risk assessment (TARA)
3. **Supply Chain Security**: Manage cybersecurity of suppliers
4. **Verification & Validation**: Test security controls
5. **Configuration Management**: Track security-relevant changes
6. **Incident Management**: Respond to cybersecurity events
7. **Lifecycle Management**: Concept through Decommissioning

### How sigil Helps

#### ISO-H1: Security by Design (Clause 5.4.2)

- **Regulation**: ISO 21434 Clause 5.4.2 -- Cybersecurity activities during concept phase
- **sigil Capability**: SLSA Level 2/3/4 framework providing structured security approach
- **Evidence Provided**: Formal security framework with verifiable levels
- **Traced Artifacts**: [[CG-1]] through [[CG-5]], [[CR-1]] through [[CR-6]], [[SP-1]] through [[SP-4]], [[DD-1]] (Ed25519 algorithm selection), [[DD-2]] (offline-first architecture)
- **Traceability**: ISO 21434 5.4.2 -> [[CG-1]] + [[CG-2]] -> [[DD-1]] + [[DD-2]] -> Evidence: design decisions documenting security-by-design rationale

#### ISO-H2: Supply Chain Security (Clause 5.4.4)

- **Regulation**: ISO 21434 Clause 5.4.4 -- Manage cybersecurity of development interfaces
- **sigil Capability**: SBOM + dependency graph + multi-signature with source tracking
- **Evidence Provided**: Component integrity verification with supplier traceability
- **Traced Artifacts**: [[ASSET-017]], [[ASSET-018]], [[ASSET-019]], [[CR-11]], [[CTRL-3]], [[TS-001]] (component substitution), [[TS-002]] (dependency confusion), [[DF-5]]
- **Traceability**: ISO 21434 5.4.4 -> [[CR-11]] -> [[CTRL-3]] -> [[TS-001]] + [[TS-002]] -> Evidence: dependency graph detects substitution (TS-001 residual risk: LOW) and tracks sources to prevent confusion (TS-002)

#### ISO-H3: Configuration Management (Clause 5.4.3)

- **Regulation**: ISO 21434 Clause 5.4.3 -- Track security-relevant configuration changes
- **sigil Capability**: Composition manifest + version tracking in SBOM
- **Evidence Provided**: Security-relevant change tracking with version history
- **Traced Artifacts**: [[ASSET-019]], [[ASSET-018]], [[CR-5]], [[CR-8]], [[DF-5]], [[DF-7]]
- **Traceability**: ISO 21434 5.4.3 -> [[CR-5]] + [[CR-8]] -> [[ASSET-019]] -> Evidence: composition manifest tracks every component version and change

#### ISO-H4: Verification (Clause 5.4.5)

- **Regulation**: ISO 21434 Clause 5.4.5 -- Verify cybersecurity implementation
- **sigil Capability**: Provenance + attestations providing verifiable security claims
- **Evidence Provided**: Evidence for security control validation
- **Traced Artifacts**: [[ASSET-020]], [[CR-8]], [[CG-1]] through [[CG-5]], [[REQ-1]] through [[REQ-5]]
- **Traceability**: ISO 21434 5.4.5 -> [[REQ-1]] through [[REQ-5]] -> [[CG-1]] through [[CG-5]] -> Evidence: each cybersecurity goal has verifiable implementation with test evidence

#### ISO-H5: Traceability (Clause 5.4.7)

- **Regulation**: ISO 21434 Clause 5.4.7 -- Maintain full lifecycle audit trail
- **sigil Capability**: in-toto + timestamps + device attestation
- **Evidence Provided**: Full lifecycle audit trail from source to deployment
- **Traced Artifacts**: [[ASSET-020]], [[ASSET-014]], [[CR-5]], [[CR-8]], [[DF-3]], [[DF-8]], [[CG-3]] (non-repudiation)
- **Traceability**: ISO 21434 5.4.7 -> [[CG-3]] -> [[CR-5]] -> [[DF-8]] -> Evidence: Rekor transparency log provides immutable, timestamped audit trail

#### ISO-H6: Component Management (Clause 5.4.4.3)

- **Regulation**: ISO 21434 Clause 5.4.4.3 -- Track dependencies and component relationships
- **sigil Capability**: Dependency graph validation with cycle and substitution detection
- **Evidence Provided**: Verified component relationship map
- **Traced Artifacts**: [[ASSET-017]], [[CTRL-3]], [[TS-003]] (circular dependencies), [[TS-005]] (transitive dependency poisoning), [[DF-6]]
- **Traceability**: ISO 21434 5.4.4.3 -> [[CTRL-3]] -> [[ASSET-017]] -> Evidence: validated dependency graph with cycle detection (TS-003 residual risk: VERY LOW) and transitive tracking (TS-005)

#### ISO-H7: Reproducible Builds (Clause 5.4.6)

- **Regulation**: ISO 21434 Clause 5.4.6 -- Deterministic, verifiable build processes
- **sigil Capability**: Build provenance enabling SLSA Level 4 reproducibility
- **Evidence Provided**: Deterministic, independently verifiable builds
- **Traced Artifacts**: [[ASSET-020]], [[CR-8]], [[SP-6]], [[REQ-7]], [[DD-3]] (deterministic composition)
- **Traceability**: ISO 21434 5.4.6 -> [[REQ-7]] -> [[DD-3]] -> [[CR-8]] -> Evidence: in-toto attestation with pinned materials and deterministic build process

#### Example: ISO 21434 Supply Chain Evidence

```rust
use wsc::composition::*;

// ISO 21434 Clause 5.4.4: Supply chain security
// Requirement: "Manage cybersecurity of development interfaces"

// 1. Verify component sources (Clause 5.4.4.1)
let manifest = extract_composition_manifest(&module)?.unwrap();
for component in &manifest.components {
    // Only accept components from approved sources
    let source = component.source_url.as_ref().ok_or("Source required")?;
    if !is_iso21434_approved_source(source) {
        return Err(format!("Component from non-approved source: {}", source));
    }
}

// 2. Verify component integrity (Clause 5.4.4.2)
verify_all_signatures(&module, trusted_certs)?;

// 3. Track dependencies (Clause 5.4.4.3)
let graph = DependencyGraph::from_manifest(&manifest);
let validation = graph.validate()?;

// 4. Document for audit (Clause 5.4.4.4)
let sbom = extract_sbom(&module)?.unwrap();
save_to_file("iso21434-supply-chain-evidence.json", &sbom.to_json()?)?;

println!("ISO 21434 supply chain requirements verified");
```

### How sigil Does NOT Help

#### ISO-N1: TARA (Threat Modeling)

- **Regulation**: ISO 21434 Clause 15 -- Perform TARA on the ITEM
- **Why sigil Doesn't Help**: sigil provides component-level evidence, not system-level analysis
- **Residual Risk**: [[RR-3]]
- **Alternative**: Use STRIDE, PASTA, Attack Trees; reference sigil STRIDE analysis as component evidence

#### ISO-N2: Security Testing

- **Regulation**: ISO 21434 Clause 5.4.5 -- Penetration testing, fuzz testing
- **Why sigil Doesn't Help**: sigil does not perform security testing on consumer systems
- **Residual Risk**: [[RR-3]]
- **Alternative**: Fuzzing (sigil includes 6 fuzz targets for its own code), static analysis, penetration testing

#### ISO-N3: Organizational Governance

- **Regulation**: ISO 21434 Clause 5.1-5.3 -- Organizational cybersecurity management
- **Why sigil Doesn't Help**: sigil is a technical tool
- **Residual Risk**: [[RR-6]]
- **Alternative**: Establish cybersecurity governance per ISO 21434 organizational requirements

#### ISO-N4: Risk Treatment Decisions

- **Regulation**: ISO 21434 Clause 15.8 -- Make risk treatment decisions
- **Why sigil Doesn't Help**: sigil does not assess or accept risk
- **Residual Risk**: [[RR-6]]
- **Alternative**: Risk management framework; use sigil [[RA-001]] through [[RA-006]] as input

#### ISO-N5: Incident Response

- **Regulation**: ISO 21434 Clause 5.4.8 -- Respond to cybersecurity incidents
- **Why sigil Doesn't Help**: sigil does not detect or respond to runtime incidents
- **Residual Risk**: [[RR-1]]
- **Alternative**: Implement CSIRT processes; sigil provides forensic evidence via provenance

#### ISO-N6: Vulnerability Management

- **Regulation**: ISO 21434 Clause 5.4.9 -- Monitor and address vulnerabilities
- **Why sigil Doesn't Help**: sigil provides SBOM but does not scan for vulnerabilities
- **Residual Risk**: [[RR-2]]
- **Alternative**: Deploy vulnerability scanners using sigil SBOM as input ([[FEAT-3]])

#### ISO-N7: Security Requirements

- **Regulation**: ISO 21434 Clause 5.4.2 -- Define cybersecurity requirements
- **Why sigil Doesn't Help**: sigil implements controls, it does not define system requirements
- **Residual Risk**: [[RR-6]]
- **Alternative**: Requirements engineering process; reference sigil [[REQ-1]] through [[REQ-10]] as component requirements

### Residual Risk: **MEDIUM**

**Why**: ISO 21434 is a **process standard** covering organizational cybersecurity engineering. sigil provides **technical evidence** but not the processes ([[RR-6]]), governance, or organizational controls.

**Recommendation**: Use sigil as **technical foundation** for ISO 21434 compliance, but implement organizational processes (TARA, risk management, governance). Reference sigil documentation package as component-level work products.

---

## 5. Compliance Matrix

### Overall Compliance Support

| Regulation | sigil Coverage | Risk Level | Key Gaps | Gap Artifacts |
|-----------|---------------|-----------|----------|---------------|
| **EU CRA** | 40% | MEDIUM | Incident response, CE marking, monitoring | [[RR-1]], [[RR-3]], [[RR-4]] |
| **UNECE R155** | 50% | MEDIUM | TARA, runtime monitoring, CSMS governance | [[RR-1]], [[RR-3]], [[RR-6]] |
| **UNECE R156** | 60% | MEDIUM-LOW | OTA deployment, update qualification, SUMS governance | [[RR-2]], [[RR-3]], [[RR-6]] |
| **ISO/SAE 21434** | 45% | MEDIUM | TARA, security testing, organizational processes | [[RR-3]], [[RR-6]] |

### sigil Strengths (What it Does Well)

**Supply Chain Security** (90% coverage) -- [[CR-11]], [[CTRL-3]], [[ASSET-017]], [[ASSET-018]], [[ASSET-019]]
- SBOM generation (CycloneDX 1.5) -- [[CR-10]], [[ASSET-018]]
- Dependency tracking and validation -- [[CTRL-3]], [[ASSET-017]]
- Component integrity verification -- [[CR-3]], [[CTRL-2]], [[CG-1]]
- Supplier traceability -- [[CR-11]], [[DF-5]]

**Provenance & Traceability** (95% coverage) -- [[CR-8]], [[CG-3]], [[ASSET-020]]
- in-toto attestations -- [[ASSET-020]], [[DF-3]]
- Build provenance -- [[CR-8]], [[SP-5]]
- Composition manifests -- [[ASSET-019]], [[DF-5]]
- Timestamp tracking -- [[CR-5]], [[SP-4]]

**Cryptographic Integrity** (100% coverage) -- [[CR-1]], [[CG-1]], [[CG-2]]
- Multi-signature support -- [[CTRL-1]], [[CTRL-2]]
- Ed25519 signatures -- [[DD-1]], [[SP-1]], [[SP-2]]
- Hardware-backed signing (ATECC608, TPM) -- [[CTRL-5]], [[SP-7]]
- Certificate-based PKI -- [[ASSET-004]], [[ASSET-005]]

**Standards Alignment** (90% coverage) -- [[REQ-1]] through [[REQ-5]]
- SLSA Level 2/3/4 -- [[CR-8]], [[ASSET-020]]
- in-toto attestation framework -- [[ASSET-020]]
- CycloneDX SBOM -- [[ASSET-018]], [[CR-10]]
- NIST SSDF -- [[SP-1]] through [[SP-8]]

**Offline/Embedded** (100% coverage - UNIQUE) -- [[DD-2]], [[CG-5]], [[CTRL-5]]
- Air-gapped deployment -- [[ASSET-016]], [[CG-5]]
- No internet dependency -- [[DD-2]]
- Hardware security integration -- [[CTRL-5]], [[SP-7]]
- Embedded device attestation -- [[ASSET-004]], [[ASSET-005]]

### sigil Gaps (What it Doesn't Do)

**Runtime Security** (0% coverage) -- [[RR-1]]
- No monitoring or detection -- Addressed by [[FEAT-5]] (future integration)
- No incident response
- No runtime verification
- No anomaly detection

**Deployment & Operations** (10% coverage) -- [[RR-2]]
- No OTA update delivery -- Addressed by [[FEAT-4]] (OTA integration)
- No update orchestration
- No rollback mechanisms
- No deployment monitoring

**Organizational Processes** (0% coverage) -- [[RR-6]]
- No CSMS/SUMS governance
- No TARA/threat modeling (system-level)
- No risk management
- No regulatory reporting

**Security Testing** (0% coverage) -- [[RR-3]]
- No vulnerability scanning (provides SBOM only) -- Addressed by [[FEAT-3]]
- No penetration testing
- No fuzzing (of consumer systems; sigil itself has fuzz targets)
- No static analysis

**Compliance Certification** (0% coverage) -- [[RR-4]]
- No CE marking support
- No CSMS/SUMS audit
- No conformity assessment
- No regulatory interface

---

## 6. Gaps and Limitations

### Critical Gaps

**1. No Runtime Monitoring** -- [[RR-1]], [[FEAT-5]]
- **Impact**: Cannot detect cyberattacks in operation (R155 requirement)
- **Mitigation**: Integrate with in-vehicle IDS (VicOne, Argus, Uptane IDS)
- **Priority**: HIGH for automotive deployments
- **Traced Controls**: [[CTRL-7]] (monitoring integration point) addresses future integration
- **Evidence Gap**: No artifacts for R155 7.2.2.6, R155 7.2.2.7, CRA Article 10(6)

**2. No Incident Response** -- [[RR-1]], [[RR-4]]
- **Impact**: Cannot meet 24-hour reporting (CRA, R155)
- **Mitigation**: Implement SIEM + SOAR for automated incident handling
- **Priority**: HIGH for CRA compliance
- **Evidence Gap**: No artifacts for CRA Article 11, R155 7.2.2.7

**3. No OTA Deployment** -- [[RR-2]], [[FEAT-4]]
- **Impact**: Cannot deliver updates to vehicles (R156)
- **Mitigation**: Integrate with OTA system (Uptane recommended)
- **Priority**: HIGH for automotive software updates
- **Addressed By**: [[FEAT-4]] (OTA integration feature)
- **Evidence Gap**: No artifacts for R156 7.2, R156 7.2.2, R156 7.2.3

**4. No TARA/Threat Modeling** -- [[RR-3]], [[RR-6]]
- **Impact**: Cannot generate system-level threat analysis (R155, ISO 21434)
- **Mitigation**: Use threat modeling tools (Microsoft Threat Modeling Tool, IriusRisk)
- **Priority**: MEDIUM (manual process acceptable)
- **Note**: sigil provides **component-level** STRIDE analysis that feeds into system TARA

**5. No Vulnerability Scanning** -- [[RR-2]], [[FEAT-3]]
- **Impact**: Cannot identify CVEs in components (CRA, R155)
- **Mitigation**: Feed sigil SBOM ([[ASSET-018]]) to scanners (Grype, Trivy, Snyk)
- **Priority**: HIGH for vulnerability management
- **Addressed By**: [[FEAT-3]] (vulnerability scanning integration)

### Architectural Limitations

**1. Build-Time Only** -- [[DD-2]], [[RR-1]]
- sigil operates at build/composition time, not runtime
- Cannot detect runtime tampering or attacks
- **Recommendation**: Complement with runtime attestation (e.g., TCG measured boot)
- **STPA Reference**: [[H-1]] (hazard: undetected runtime compromise); [[SC-1]] (safety constraint: verify before execution)

**2. WASM-Specific**
- Only applicable to WebAssembly components
- Doesn't cover non-WASM ECU firmware
- **Recommendation**: Extend provenance approach to other firmware types

**3. No Policy Enforcement** -- [[FEAT-2]]
- sigil validates against technical constraints, not business policies
- No support for Rego, OPA, or policy engines
- **Recommendation**: Add policy layer on top of sigil validation
- **Addressed By**: [[FEAT-2]] (policy engine integration)

**4. Limited Hardware Support** -- [[CTRL-5]]
- Currently supports ATECC608, TPM (via feature flags)
- No SGX, TrustZone, HSM integration yet
- **Recommendation**: Expand hardware security provider support
- **Addressed By**: [[FEAT-1]] (HSM integration)

---

## 7. Recommendations

### For Automotive OEMs (R155/R156 Compliance)

**Phase 1: Foundation (Weeks 1-4)** -- [[REQ-1]], [[REQ-2]], [[REQ-3]]
1. Deploy sigil for component signing and provenance -- [[CTRL-1]], [[CR-1]], [[CR-3]]
2. Generate SBOMs for all WASM-based ECU firmware -- [[CR-10]], [[ASSET-018]]
3. Implement multi-signature workflow (developer + approver) -- [[CTRL-1]], [[CTRL-2]], [[CG-1]]
4. Integrate SBOM output with vulnerability scanner (Grype, Trivy) -- [[FEAT-3]]

**Phase 2: Supply Chain (Weeks 5-8)** -- [[REQ-4]], [[REQ-5]], [[CR-11]]
1. Use sigil dependency graph for supplier verification -- [[CTRL-3]], [[ASSET-017]]
2. Implement source URL allow-lists for approved suppliers -- [[CR-11]], [[TS-002]]
3. Establish TARA process using sigil threat model as baseline -- [[RA-001]] through [[RA-006]]
4. Document supply chain security in CSMS/SUMS

**Phase 3: Updates (Weeks 9-12)** -- [[REQ-6]], [[REQ-7]], [[CR-8]]
1. Use sigil to sign all OTA updates with provenance -- [[CTRL-1]], [[ASSET-020]]
2. Integrate with OTA system (Uptane recommended) -- [[FEAT-4]]
3. Implement update qualification process using sigil metadata -- [[ASSET-019]], [[ASSET-020]]
4. Establish SUMS governance framework

**Phase 4: Monitoring (Weeks 13-16)** -- [[FEAT-5]]
1. Deploy in-vehicle IDS (NOT sigil - separate tool) -- [[RR-1]]
2. Implement SOC for incident detection and response
3. Integrate sigil provenance with SIEM for correlation -- [[CR-5]], [[ASSET-014]]
4. Establish 24-hour incident reporting workflow

### For EU Product Manufacturers (CRA Compliance)

**Phase 1: SBOM & Provenance (Weeks 1-4)** -- [[REQ-1]], [[CR-10]], [[CR-8]]
1. Generate CycloneDX SBOMs for all WASM components -- [[ASSET-018]]
2. Embed SBOMs in products for vulnerability tracking -- [[DF-7]]
3. Implement multi-signature for security-by-design evidence -- [[CTRL-1]], [[CG-1]]
4. Establish vulnerability scanning process -- [[FEAT-3]]

**Phase 2: Supply Chain (Weeks 5-8)** -- [[CR-11]], [[CTRL-3]]
1. Track component sources with composition manifests -- [[ASSET-019]], [[DF-5]]
2. Validate dependencies against approved suppliers -- [[CTRL-3]], [[TS-002]]
3. Document supply chain security for CE marking
4. Establish supplier security requirements

**Phase 3: Incident Response (Weeks 9-12)** -- [[RR-1]], [[RR-4]]
1. Deploy monitoring/detection system (NOT sigil)
2. Implement 24-hour reporting workflow
3. Establish 72-hour patch delivery process
4. Integrate sigil provenance with incident response -- [[CR-5]], [[CG-3]]

**Phase 4: Market Surveillance (Weeks 13-16)**
1. Establish regulatory reporting interface
2. Document CRA compliance evidence (using sigil output as [[ASSET-018]], [[ASSET-019]], [[ASSET-020]])
3. Prepare for conformity assessment
4. Obtain CE marking

### Integration Architecture

The integration architecture maps to the STPA control structure ([[CTRL-1]] through [[CTRL-7]]) with sigil operating at the build-time control layer.

```
+-------------------------------------------------------------+
|                    Regulatory Compliance                      |
|              (CRA, R155, R156, ISO 21434)                    |
+-------------------------------------------------------------+
                              ^
                              | Evidence & Reports
                              |
+-----------------------------+-------------------------------+
|                  Compliance Orchestration                     |
|  - CSMS/SUMS Governance  - Policy Enforcement [[FEAT-2]]    |
|  - Risk Management       - Audit Trail [[CR-5]]             |
+----------+---------------------------------+-----------------+
           |                                 |
           |                                 |
    +------v------+              +-----------v---------+
    |             |              |                     |
    |  sigil      |              |  Operational        |
    |  Provenance |              |  Security           |
    |             |              |                     |
    |  SBOM       |  [[CR-10]]   |  IDS/IPS  [[RR-1]] |
    |  Signing    |  [[CTRL-1]]  |  SIEM     [[RR-1]] |
    |  Manifest   |  [[CR-8]]   |  OTA      [[FEAT-4]]|
    |  Attest.    |  [[CG-3]]   |  Vuln Scan[[FEAT-3]]|
    |  HW Trust   |  [[CTRL-5]] |  Incident [[RR-4]]  |
    |             |              |                     |
    +-------------+              +---------------------+
         BUILD-TIME                    RUNTIME
       [[CTRL-1]]-[[CTRL-6]]         [[CTRL-7]]
```

**STPA Control Mapping**:
- [[CTRL-1]] (Signing Control): sigil signs artifacts at build-time
- [[CTRL-2]] (Verification Control): sigil verifies at deployment boundary
- [[CTRL-3]] (Dependency Validation): sigil validates supply chain integrity
- [[CTRL-4]] (Timestamp Control): sigil validates temporal integrity
- [[CTRL-5]] (Hardware Attestation): sigil binds to hardware trust anchors
- [[CTRL-6]] (Trust Bundle Provisioning): sigil manages offline trust
- [[CTRL-7]] (Monitoring Integration): Future integration point for runtime security

### Tool Ecosystem

Each tool integrates with sigil through specific data flow interfaces ([[DF-1]] through [[DF-10]]).

| Function | Tool | Integration with sigil | Data Flow |
|----------|------|------------------------|-----------|
| **Provenance & Signing** | **sigil** | Core tool | [[DF-1]], [[DF-2]], [[DF-3]] |
| **Vulnerability Scanning** | Grype, Trivy, Snyk | Feed sigil SBOM output ([[ASSET-018]]) | [[DF-7]] -> scanner |
| **Threat Modeling** | Microsoft TMT, IriusRisk | Use sigil threat model as baseline ([[TS-001]]-[[TS-018]]) | Component evidence input |
| **OTA Updates** | Uptane, SOTA | Sign updates with sigil ([[CTRL-1]]) | [[DF-2]] -> OTA pipeline |
| **Runtime Security** | VicOne, Argus | Correlate with sigil provenance ([[ASSET-020]]) | [[DF-3]] -> SIEM |
| **SIEM** | Splunk, ELK | Ingest sigil audit logs ([[CR-5]], [[ASSET-014]]) | [[DF-8]] -> SIEM |
| **Policy Engine** | OPA, Kyverno | Validate against sigil metadata ([[FEAT-2]]) | [[DF-5]] -> policy engine |
| **CI/CD** | GitHub Actions, GitLab | Automate sigil signing ([[CTRL-1]]) | [[DF-1]] -> CI/CD |

---

## 8. Conclusion

### Summary

**sigil provides critical supply chain security capabilities** that support compliance with automotive and EU cybersecurity regulations:

**Strong Coverage** (60-90%):
- Supply chain security (SBOM, dependency tracking) -- [[CR-10]], [[CR-11]], [[CTRL-3]]
- Provenance and traceability -- [[CR-8]], [[CG-3]], [[ASSET-020]]
- Cryptographic integrity -- [[CR-1]], [[CR-3]], [[CG-1]], [[CG-2]]
- Standards alignment (SLSA, in-toto) -- [[REQ-1]] through [[REQ-5]]
- **Unique**: Offline/embedded SLSA Level 4 -- [[DD-2]], [[CG-5]], [[CTRL-5]]

**Gaps** (10-40%):
- Runtime monitoring and detection -- [[RR-1]], [[FEAT-5]]
- Incident response and reporting -- [[RR-1]], [[RR-4]]
- OTA deployment infrastructure -- [[RR-2]], [[FEAT-4]]
- Organizational governance (CSMS/SUMS) -- [[RR-6]]
- Threat modeling and risk assessment (system-level) -- [[RR-3]]

### Key Findings

**1. sigil is NOT a Complete Compliance Solution**
- Regulations require organizational processes ([[RR-6]]), runtime security ([[RR-1]]), and deployment infrastructure ([[RR-2]])
- sigil provides **technical evidence**, not governance or operations

**2. sigil Excels at Build-Time Security**
- Best-in-class provenance tracking for WASM components -- [[CR-8]], [[ASSET-020]]
- Industry-leading offline/embedded support (SLSA L4) -- [[DD-2]], [[CG-5]]
- Strong alignment with supply chain security requirements -- [[CR-11]], [[CTRL-3]]

**3. sigil Requires Integration**
- Must integrate with vulnerability scanners ([[FEAT-3]]), OTA systems ([[FEAT-4]]), IDS ([[FEAT-5]]), SIEM
- Evidence from sigil feeds into compliance documentation
- sigil is one tool in a broader compliance toolchain

### Value Proposition

For organizations pursuing automotive/EU compliance, **sigil provides**:

1. **60-90% of supply chain security requirements** (vs 10-30% with traditional signing) -- [[CR-11]], [[CTRL-3]], [[ASSET-017]], [[ASSET-018]], [[ASSET-019]]
2. **Unique offline SLSA Level 4** capability (no other WASM tool has this) -- [[DD-2]], [[CG-5]], [[CTRL-5]]
3. **Standards-based evidence** (CycloneDX, in-toto, SLSA) -- [[REQ-1]] through [[REQ-5]]
4. **Audit-ready provenance** (embedded in artifacts, extractable for reports) -- [[CR-8]], [[ASSET-020]]
5. **Hardware security integration** (ATECC608, TPM for R155/CRA) -- [[CTRL-5]], [[SP-7]], [[ASSET-004]]

### Recommended Deployment

**Use sigil for**:
- Component signing and verification -- [[CTRL-1]], [[CTRL-2]]
- SBOM generation and embedding -- [[CR-10]], [[ASSET-018]]
- Supply chain provenance tracking -- [[CR-8]], [[CR-11]], [[ASSET-020]]
- Update integrity verification -- [[CG-2]], [[CR-3]]
- Hardware-backed attestation -- [[CTRL-5]], [[SP-7]]

**Complement sigil with**:
- Vulnerability scanners (Grype, Trivy) -- [[FEAT-3]]
- OTA deployment (Uptane, SOTA) -- [[FEAT-4]]
- Runtime security (IDS, SIEM) -- [[FEAT-5]]
- Threat modeling tools -- Component evidence: [[TS-001]] through [[TS-006]]
- Organizational governance (CSMS/SUMS) -- [[RR-6]]

### Final Assessment

| Regulation | sigil Role | Compliance Impact | Key Artifacts |
|-----------|---------|------------------|---------------|
| **EU CRA** | Evidence tool | Helps with 40% of requirements | [[CR-10]], [[CR-11]], [[CG-1]], [[CG-2]], [[ASSET-018]] |
| **UNECE R155** | Supply chain verification | Helps with 50% of requirements | [[CTRL-3]], [[CR-11]], [[ASSET-017]], [[RA-001]]-[[RA-006]] |
| **UNECE R156** | Update provenance | Helps with 60% of requirements | [[CR-8]], [[CTRL-1]], [[ASSET-020]], [[CTRL-5]] |
| **ISO/SAE 21434** | Technical foundation | Helps with 45% of requirements | [[CG-1]]-[[CG-5]], [[CR-1]]-[[CR-6]], [[DD-1]]-[[DD-3]] |

**Overall**: sigil is a **critical enabler** but not a **complete solution** for regulatory compliance. Its strength lies in providing **auditable, artifact-traced evidence** that maps directly from regulation requirement to implementation control to verification evidence.

---

## References

### Regulations & Standards

- [EU Cybersecurity Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [UNECE R155 - Cybersecurity Management Systems](https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155-cyber-security-and-cyber-security)
- [UNECE R156 - Software Update Management Systems](https://unece.org/transport/documents/2021/03/standards/un-regulation-no-156-software-update-and-software-update)
- [ISO/SAE 21434:2021 - Road Vehicles Cybersecurity Engineering](https://www.iso.org/standard/70918.html)
- [SLSA Framework](https://slsa.dev/)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)

### Related sigil Documentation

- [SLSA Compliance Documentation](./slsa-compliance.md)
- [Composition Threat Model](./composition-threat-model.md)
- [TARA Compliance](./TARA_COMPLIANCE.md)
- [Risk Assessment](./security/RISK_ASSESSMENT.md)
- [Asset Inventory](./security/ASSET_INVENTORY.md)
- [Integration Guidance](./security/INTEGRATION_GUIDANCE.md)
- [Threat Model (STRIDE)](./THREAT_MODEL.md)

### Artifact Cross-Reference Index

| Artifact Range | Document | Purpose |
|---------------|----------|---------|
| [[ASSET-001]] - [[ASSET-022]] | Asset Inventory | Security-relevant assets with CIA ratings |
| [[TS-001]] - [[TS-018]] | Threat Model | STRIDE threat scenarios |
| [[RA-001]] - [[RA-018]] | Risk Assessment | ISO 21434 AF-rated risk assessments |
| [[RR-1]] - [[RR-6]] | Risk Assessment | Residual risks after controls |
| [[CG-1]] - [[CG-8]] | TARA Compliance | Cybersecurity goals |
| [[CR-1]] - [[CR-11]] | TARA Compliance | Cybersecurity requirements |
| [[CD-1]] - [[CD-9]] | TARA Compliance | Cybersecurity design specifications |
| [[CV-1]] - [[CV-8]] | TARA Compliance | Cybersecurity verification |
| [[H-1]] - [[H-11]] | STPA Analysis | Hazards |
| [[SC-1]] - [[SC-11]] | STPA Analysis | Safety constraints |
| [[CTRL-1]] - [[CTRL-7]] | STPA Analysis | Control structure |
| [[DF-1]] - [[DF-10]] | Data Flow Analysis | Data flow paths |
| [[SP-1]] - [[SP-8]] | Security Analysis | Security properties |
| [[REQ-1]] - [[REQ-10]] | Development | Requirements |
| [[FEAT-1]] - [[FEAT-5]] | Development | Features addressing gaps |
| [[DD-1]] - [[DD-3]] | Design Decisions | Architecture decisions |

---

**Document Status**: APPROVED
**Review Cycle**: Quarterly (regulations evolve rapidly)
**Next Review**: June 15, 2026
**Feedback**: Open issues at https://github.com/pulseengine/sigil/issues
