<div align="center">

# Sigil

<sup>Supply chain security for WebAssembly</sup>

&nbsp;

![Rust](https://img.shields.io/badge/Rust-CE422B?style=flat-square&logo=rust&logoColor=white&labelColor=1a1b27)
![Sigstore](https://img.shields.io/badge/Sigstore-keyless_signing-654FF0?style=flat-square&labelColor=1a1b27)
![SLSA](https://img.shields.io/badge/SLSA-L4_provenance-00C853?style=flat-square&labelColor=1a1b27)
![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square&labelColor=1a1b27)

&nbsp;

<h6>
  <a href="https://github.com/pulseengine/meld">Meld</a>
  &middot;
  <a href="https://github.com/pulseengine/loom">Loom</a>
  &middot;
  <a href="https://github.com/pulseengine/synth">Synth</a>
  &middot;
  <a href="https://github.com/pulseengine/kiln">Kiln</a>
  &middot;
  <a href="https://github.com/pulseengine/sigil">Sigil</a>
</h6>

</div>

&nbsp;

Meld fuses. Loom weaves. Synth transpiles. Kiln fires. Sigil seals.

The cryptographic backbone of the PulseEngine pipeline. Sigil signs WebAssembly modules with embedded signatures that can be verified completely offline — perfect for embedded systems, edge devices, and air-gapped environments. Every pipeline stage (fusion, optimization, transpilation) creates a signed transformation attestation recording what changed, which tool version ran, and cryptographic hashes of inputs and outputs.

Built on the [WebAssembly modules signatures proposal](https://github.com/wasm-signatures/design) and extended with Sigstore keyless signing, SLSA policy enforcement, and hardware security via TPM 2.0. All signatures are embedded directly in WebAssembly modules — no external registry required.

## Quick Start

```bash
# Install from source
cargo install wsc-cli

# Or build from source
git clone https://github.com/pulseengine/sigil.git
cd sigil
cargo build --release
```

### Keyless Signing (Sigstore)

```bash
# Sign in GitHub Actions (or any OIDC-enabled CI)
sigil sign --keyless -i module.wasm -o signed.wasm

# Verify offline — no network required
sigil verify --keyless -i signed.wasm

# With identity constraints
sigil verify --keyless -i signed.wasm \
  --cert-identity "user@example.com" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

### Traditional Key-Based Signing

```bash
# Generate key pair
sigil keygen -k secret.key -K public.key

# Sign
sigil sign -k secret.key -i module.wasm -o signed.wasm

# Verify
sigil verify -K public.key -i signed.wasm
```

## Features

- **Offline-First Verification** — Embedded signatures survive distribution; no network required at runtime
- **Keyless Signing** — Full Sigstore/Fulcio/Rekor integration with OIDC authentication (GitHub Actions, Google Cloud, GitLab CI)
- **Keyless Verification** — Verify Sigstore signatures offline with certificate chain and SET validation
- **Enhanced Rekor Verification** — Checkpoint-based verification with security hardening
- **Bazel Integration** — Full BUILD and MODULE.bazel support for hermetic builds
- **WIT Component Model** — Both library and CLI WebAssembly component builds
- **OpenSSH Key Support** — Works with Ed25519 SSH keys
- **GitHub Integration** — Verify using a GitHub user's SSH public keys
- **Multiple Signatures** — Compact representation for multi-signer workflows

### Offline Verification vs Registry Signatures

| Scenario | Cosign/OCI | Sigil |
|----------|------------|-------|
| IoT device with intermittent WiFi | Needs connectivity | Verify offline |
| Industrial controller | Requires registry access | Signature embedded |
| Edge CDN node | Registry latency | Local verification |
| Air-gapped network | Cannot verify | Works offline |

## Additional Operations

```bash
# Inspect a module
sigil show -i module.wasm

# Detach signature
sigil detach -i signed.wasm -o unsigned.wasm -S signature.bin

# Attach signature
sigil attach -i unsigned.wasm -o signed.wasm -S signature.bin

# Partial verification (specific custom sections)
sigil verify -K public.key -i signed.wasm --split "custom_section_regex"
```

## Formal Verification

> [!NOTE]
> **Cross-cutting verification** &mdash; Rocq mechanized proofs, Kani bounded model checking, Z3 SMT verification, and Verus Rust verification are used across the PulseEngine toolchain. Sigil attestation chains bind it all together.

## Documentation

- [Checkpoint Implementation](docs/checkpoint_implementation.md)
- [Security Audit](docs/checkpoint_security_audit.md)
- [Checkpoint Format](docs/rekor_checkpoint_format.md)
- [Security Model](SECURITY.md)
- [Keyless Signing](docs/keyless.md)
- [Testing Guide](docs/testing.md)

## Acknowledgments

Based on [wasmsign2](https://github.com/wasm-signatures/wasmsign2) by Frank Denis. MIT License &mdash; original wasmsign2 Copyright (c) 2024 Frank Denis.

## License

MIT License &mdash; see [LICENSE](LICENSE).

---

<div align="center">

<sub>Part of <a href="https://github.com/pulseengine">PulseEngine</a> &mdash; formally verified WebAssembly toolchain for safety-critical systems</sub>

</div>
