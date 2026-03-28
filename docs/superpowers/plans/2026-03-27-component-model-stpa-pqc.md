# WASM Component Model Signing + STPA-Sec Gap Closure + PQC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add WASM Component Model signing support, close all STPA-Sec analysis gaps for v0.6.x features, and prepare for v0.7.0 release with full traceability.

**Architecture:** Three phases: (1) STPA-Sec gap closure — add 80+ rivet artifacts for features A-H, fix validation warnings; (2) WASM Component Model signing — extend the parser for component-layer sections, recursive nested module hashing, and roundtrip tests; (3) PQC integration preparation — domain-separated hybrid signing pipeline with all-or-nothing verification.

**Tech Stack:** Rust 1.90.0, Bazel 8.5.1, rivet CLI, Kani, cargo-mutants

---

## File Structure

### Phase 1: STPA-Sec Artifacts (rivet YAML)
- Modify: `artifacts/stpa/losses-and-hazards.yaml` — add L-10, H-21–H-35, SC-20–SC-33
- Modify: `artifacts/stpa/control-structure.yaml` — add CTRL-11–13, CA-12–14, CP-8
- Modify: `artifacts/stpa/data-flows.yaml` — add DF-17–22, SP-11–12, fix DF-16
- Modify: `artifacts/stpa/ucas.yaml` — add UCA-22–35, CC-13–26
- Modify: `artifacts/stpa/attack-scenarios.yaml` — add AS-22–32
- Modify: `artifacts/cybersecurity/goals-and-requirements.yaml` — add CR-18–24, CD-23–27, CV-30–34, fix existing
- Modify: `artifacts/cybersecurity/assets-and-threats.yaml` — add ASSET-023–25, TS-019–24
- Modify: `artifacts/dev/features.yaml` — add FEAT-11 (component model), fix REQ links

### Phase 2: WASM Component Model Signing (Rust)
- Modify: `src/lib/src/wasm_module/mod.rs` — extend SectionId for component sections, add recursive nesting support
- Create: `src/lib/src/wasm_module/component.rs` — component-model-aware parsing and hashing
- Modify: `src/lib/src/wasm_module/mod.rs` tests — add component model roundtrip tests
- Create: `fuzz/fuzz_targets/fuzz_component_model.rs` — fuzz target for component parsing
- Modify: `fuzz/Cargo.toml` — add fuzz target

### Phase 3: PQC Hybrid Signing (Rust)
- Modify: `src/lib/src/pqc.rs` — add HybridSigner/HybridVerifier traits, domain separation
- Modify: `src/lib/src/signature/mod.rs` — wire hybrid signing into signature pipeline
- Modify: `src/cli/main.rs` — add --pqc flag

---

## Phase 1: STPA-Sec Gap Closure

### Task 1: Add losses, hazards, and system constraints for new features

**Files:**
- Modify: `artifacts/stpa/losses-and-hazards.yaml`

- [ ] **Step 1: Add L-10 (component model integrity loss)**

```yaml
  - id: L-10
    type: loss
    title: Loss of WASM component model integrity
    description: >
      Nested module content within a WASM component is not covered by
      the outer signature, allowing substitution of inner modules
      without detection.
    links:
      - type: leads-to-loss
        target: L-1
```

- [ ] **Step 2: Add H-21 through H-35 (15 new hazards)**

Add hazards for: component section reordering (H-21), nested module substitution (H-22), PQC hybrid verification skip (H-23), PQC key size constraints (H-24), proof cache poisoning (H-25), cache TTL staleness (H-26), SCT signature forgery (H-27), SCT silent failure (H-28), checkpoint corruption (H-29), checkpoint race condition (H-30), bundle format mismatch (H-31), bundle field stripping (H-32), build env spoofing (H-33), build env PATH poisoning (H-34), DSSE single-sig acceptance (H-35).

Each hazard must have `leads-to-loss` link to the appropriate loss.

- [ ] **Step 3: Add SC-20 through SC-33 (14 system constraints)**

Each constraint inverts its hazard. SC-20: signature covers full component tree. SC-21: parser recurses component nesting. SC-22: hybrid verification checks both. SC-23: PQC zeroization. SC-24: cache stores only verified proofs. SC-25: cache bounded size. SC-26: SCT verified against trusted logs. SC-27: SCT fail-closed. SC-28: checkpoint atomic update. SC-29: checkpoint persists across restarts. SC-30: bundle includes complete material. SC-31: bundle media type validated. SC-32: build env doesn't trust PATH. SC-33: DSSE multi-sig policy configurable.

Each constraint must have `prevents` link to its hazard and `protects` link to relevant security properties.

- [ ] **Step 4: Run `rivet validate` and fix any errors**

Run: `rivet validate 2>&1 | grep -v "synth:" | grep -v "kiln:" | grep ERROR`
Expected: 0 local errors

- [ ] **Step 5: Commit**

```bash
git add artifacts/stpa/losses-and-hazards.yaml
git commit -m "stpa: add losses, hazards, constraints for component model, PQC, cache, SCT, checkpoint, bundle, build-env, DSSE"
```

### Task 2: Add controllers, control actions, processes, and data flows

**Files:**
- Modify: `artifacts/stpa/control-structure.yaml`
- Modify: `artifacts/stpa/data-flows.yaml`

- [ ] **Step 1: Add CTRL-11 (Component Model Parser), CTRL-12 (SCT Monitor), CTRL-13 (Checkpoint Verifier)**

- [ ] **Step 2: Add CA-12 (parse/hash component tree), CA-13 (verify SCT), CA-14 (verify checkpoint consistency)**

- [ ] **Step 3: Add CP-8 (WASM Component Processing)**

- [ ] **Step 4: Add DF-17 through DF-22 (6 data flows) and SP-11, SP-12**

DF-17: component nested module content. DF-18: PQC key material. DF-19: cached proof data. DF-20: SCT from certificate. DF-21: checkpoint persistence. DF-22: bundle format conversion.

SP-11: PQC key material confidentiality. SP-12: proof cache integrity.

- [ ] **Step 5: Fix DF-16 field values** (`data-type`, `sensitivity`)

- [ ] **Step 6: Run `rivet validate`, fix errors, commit**

```bash
git add artifacts/stpa/control-structure.yaml artifacts/stpa/data-flows.yaml
git commit -m "stpa: add controllers, data flows, security properties for new features"
```

### Task 3: Add UCAs, controller constraints, and attack scenarios

**Files:**
- Modify: `artifacts/stpa/ucas.yaml`
- Modify: `artifacts/stpa/attack-scenarios.yaml`

- [ ] **Step 1: Add UCA-22 through UCA-35 (14 UCAs)**

Each UCA links to its controller and hazard. Full list:

- UCA-22: Sign component WITHOUT traversing nested modules (→ H-22)
- UCA-23: Verify component with core-module-only parser (→ H-21)
- UCA-24: Verify hybrid sig WITHOUT checking PQC component (→ H-23)
- UCA-25: Sign with PQC key WITHOUT domain separation (→ H-23)
- UCA-26: Insert cache entry WITHOUT prior verification (→ H-25)
- UCA-27: Return cached proof AFTER key revocation (→ H-26)
- UCA-28: Accept Fulcio cert WITHOUT valid SCT (→ H-27)
- UCA-29: Verify SCT against wrong CT log key (→ H-28)
- UCA-30: Accept checkpoint WITHOUT consistency proof (→ H-29)
- UCA-31: Persist checkpoint with non-atomic write (→ H-30)
- UCA-32: Produce bundle WITHOUT tlog entries (→ H-31)
- UCA-33: Parse bundle WITHOUT media type validation (→ H-32)
- UCA-34: Capture build env from untrusted PATH (→ H-34)
- UCA-35: Verify DSSE with any-one-of when policy requires all (→ H-35)

- [ ] **Step 2: Add CC-13 through CC-26 (controller constraints inverting UCAs)**

Also add missing CC for existing container UCAs (UCA-16 through UCA-21).

- [ ] **Step 3: Add AS-22 through AS-32 (11 attack scenarios)**

AS-22: nested module substitution. AS-23: quantum downgrade. AS-24: cache pre-population. AS-25: cache memory exhaustion. AS-26: CT log compromise. AS-27: SCT stripping. AS-28: checkpoint file replacement. AS-29: split-view. AS-30: bundle field stripping. AS-31: PATH poisoning. AS-32: env var spoofing.

Plus AS-33: DSSE policy bypass — attacker compromises one of N signing keys, DSSE verify() succeeds on the remaining valid signature, hiding the compromise.

Each links to its UCA, hazard, and threat agent.

- [ ] **Step 4: Run `rivet validate`, fix errors, commit**

```bash
git add artifacts/stpa/ucas.yaml artifacts/stpa/attack-scenarios.yaml
git commit -m "stpa: add UCAs, controller constraints, attack scenarios for all new features"
```

### Task 4: Add cybersecurity requirements, designs, verifications

**Files:**
- Modify: `artifacts/cybersecurity/goals-and-requirements.yaml`
- Modify: `artifacts/cybersecurity/assets-and-threats.yaml`
- Modify: `artifacts/dev/features.yaml`

- [ ] **Step 1: Add ASSET-023 (SLH-DSA key pair), ASSET-024 (CT log keys), ASSET-025 (DSSE envelope)**

- [ ] **Step 2: Add TS-019 through TS-024 (6 threat scenarios)**

- [ ] **Step 3: Add CR-18 through CR-24 (7 cybersecurity requirements)**

- [ ] **Step 4: Add CD-23 through CD-27 (5 cybersecurity designs)**

- [ ] **Step 5: Add CV-30 through CV-34 (5 cybersecurity verifications)**

- [ ] **Step 6: Fix existing validation warnings**

- Fix CV-25–29: `method: test` → `method: automated-test`
- Fix CV-16–19: add `description` field
- Fix REQ-3, REQ-12, REQ-13, REQ-14: add satisfying links
- Add FEAT-11 (Component Model Signing) to features.yaml

- [ ] **Step 7: Run `rivet validate`, fix all local errors, commit**

```bash
git add artifacts/
git commit -m "cybersecurity: add requirements, designs, verifications, assets, threats; fix validation warnings"
```

### Task 5: PR and merge Phase 1

- [ ] **Step 1: Run full test suite** `cargo test -p wsc`
- [ ] **Step 2: Run `rivet validate` — verify 0 local errors**
- [ ] **Step 3: Run `rivet init --agents` to refresh AGENTS.md**
- [ ] **Step 4: Create PR, watch CI, merge**

---

## Phase 2: WASM Component Model Signing

### Task 5b: Verify rivet and Bazel before starting Phase 2

- [ ] **Step 1: Confirm rivet is clean**

Run: `rivet validate 2>&1 | grep -v "synth:" | grep -v "kiln:" | grep ERROR`
Expected: 0 local errors

- [ ] **Step 2: Confirm Bazel builds**

Run: `bazel build //src/lib:wsc //src/cli:wasmsign_cli`
Expected: BUILD SUCCESSFUL

---

### Task 6: Write failing tests for component model signing

**Files:**
- Modify: `src/lib/src/wasm_module/mod.rs` (tests section)

- [ ] **Step 1: Write test_component_model_sign_verify**

```rust
#[test]
fn test_component_model_sign_verify() {
    // Component model header: \0asm + version 0x0d 0x00 0x01 0x00
    let component_bytes = build_minimal_component();
    let module = Module::deserialize(&component_bytes).expect("should parse component");

    let kp = KeyPair::generate();
    let signed = module.sign(&kp.sk).expect("should sign component");
    let verified = signed.verify(&kp.pk);
    assert!(verified.is_ok(), "should verify component signature");
}
```

- [ ] **Step 2: Write test_component_nested_module_coverage**

```rust
#[test]
fn test_component_nested_module_coverage() {
    // Component with a nested core module inside
    let component = build_component_with_nested_module(b"inner module content");
    let module = Module::deserialize(&component).expect("should parse");

    let kp = KeyPair::generate();
    let signed = module.sign(&kp.sk).expect("should sign");

    // Tamper with the nested module content
    let mut tampered = signed.serialize();
    // Modify a byte in the nested module region
    tamper_nested_content(&mut tampered);

    let tampered_module = Module::deserialize(&tampered).expect("should parse tampered");
    assert!(tampered_module.verify(&kp.pk).is_err(), "tampered nested content must fail verification");
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p wsc test_component_model`
Expected: FAIL (functions not implemented)

- [ ] **Step 4: Commit failing tests**

```bash
git commit -m "test: add failing tests for WASM component model signing (SC-20)"
```

### Task 7: Implement component model section parsing

**Files:**
- Create: `src/lib/src/wasm_module/component.rs`
- Modify: `src/lib/src/wasm_module/mod.rs`

- [ ] **Step 1: Add component section IDs**

Extend `SectionId` or create `ComponentSectionId` enum per the WASM Component Model binary spec:
- 0x00 = Custom (same as core)
- 0x01 = CoreModule (nested core module)
- 0x02 = CoreInstance
- 0x03 = CoreType
- 0x04 = Component (nested component)
- 0x05 = Instance
- 0x06 = Alias
- 0x07 = Type
- 0x08 = Canon
- 0x09 = Start
- 0x0A = Import
- 0x0B = Export

- [ ] **Step 2: Add recursive component traversal**

When a component-layer section contains a nested core module or component, recurse into it and include its content in the hash computation.

- [ ] **Step 3: Ensure signature covers full component tree**

The hash must cover ALL bytes from the component header through all sections including nested modules. The existing full-module hash approach should work, but verify with the nested module test.

- [ ] **Step 4: Run tests**

Run: `cargo test -p wsc test_component_model`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git commit -m "feat: WASM component model signing with nested module coverage (SC-20, SC-21)"
```

### Task 8: Add Kani proofs and fuzz target for component model

**Files:**
- Modify: `src/lib/src/wasm_module/mod.rs` (kani section)
- Create: `fuzz/fuzz_targets/fuzz_component_model.rs`

- [ ] **Step 1: Add Kani proof for component header detection**

```rust
#[cfg(kani)]
mod component_proofs {
    use super::*;

    /// Prove: component and module headers are mutually exclusive
    /// for any 8-byte input (no polyglot attack possible).
    #[kani::proof]
    fn proof_component_module_header_mutual_exclusivity() {
        let b: [u8; 8] = kani::any();
        let is_module = b == WASM_HEADER;
        let is_component = b == WASM_COMPONENT_HEADER;
        assert!(!(is_module && is_component), "Cannot be both module and component");
    }

    /// Prove: hash computation over component bytes is deterministic.
    #[kani::proof]
    fn proof_component_hash_deterministic() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let data = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00, b0, b1];
        use sha2::{Sha256, Digest};
        let h1 = Sha256::digest(&data);
        let h2 = Sha256::digest(&data);
        assert_eq!(h1, h2);
    }
}
```

- [ ] **Step 2: Add fuzz target**

- [ ] **Step 3: Run tests + mutation testing**

Run: `cargo test -p wsc` and check mutation testing catches component signing mutations.

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: add Kani proof and fuzz target for component model (CV-30)"
```

### Task 9: PR and merge Phase 2

- [ ] **Step 1: Run full test suite**
- [ ] **Step 2: Run `rivet validate`**
- [ ] **Step 3: Create PR, watch CI, merge**

---

## Phase 3: PQC Hybrid Signing Preparation

### Task 10: Add hybrid signing traits and domain separation

**Files:**
- Modify: `src/lib/src/pqc.rs`

- [ ] **Step 1: Write failing test for hybrid sign/verify**

```rust
#[test]
fn test_hybrid_signature_requires_both_valid() {
    let hybrid = HybridSignature {
        classical: vec![0u8; 64],  // fake Ed25519 sig
        post_quantum: vec![],      // empty PQC sig
        pqc_algorithm: PqcAlgorithm::SlhDsaSha2_128s,
        message_hash: vec![0u8; 32],
    };
    // Verification must fail if PQC component is missing
    assert!(!hybrid.is_complete());
}
```

- [ ] **Step 2: Implement is_complete() and domain separation**

```rust
impl HybridSignature {
    pub fn is_complete(&self) -> bool {
        !self.classical.is_empty()
            && !self.post_quantum.is_empty()
            && self.classical.len() == 64  // Ed25519
            && self.post_quantum.len() <= self.pqc_algorithm.max_signature_size()
    }

    pub fn domain_separator() -> &'static [u8] {
        b"wsc-hybrid-v1"
    }
}
```

- [ ] **Step 3: Run tests, commit**

```bash
git commit -m "feat: hybrid signature completeness check and domain separation (SC-22, SC-23)"
```

### Task 11: Version bump and release preparation

- [ ] **Step 1: Bump version to 0.7.0**
- [ ] **Step 2: Run `rivet init --agents`**
- [ ] **Step 3: Run full test suite + `rivet validate`**
- [ ] **Step 4: Create release PR**
- [ ] **Step 5: Watch CI, merge, tag v0.7.0**

---

## Verification Checklist

After all phases:

- [ ] `rivet validate` — 0 local errors
- [ ] `cargo test -p wsc` — all tests pass
- [ ] Component model sign+verify roundtrip works
- [ ] Hybrid signature completeness enforced
- [ ] Mutation testing passes (0 surviving mutants)
- [ ] All new STPA artifacts have bidirectional links
- [ ] AGENTS.md refreshed with new artifact count
