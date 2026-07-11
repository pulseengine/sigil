# Embedded on-target trust chain (#187) — plan & coordination drafts

Status: **planning**. Tracks sigil #187, kiln #415 / `AD-WCMC-001`.
Rivet: `FEAT-12` → `REQ-15` (no_std verify-core, v0.10.0), `REQ-16` (signed
reject-at-load, v0.11.0), `DD-8` (secure-boot verify profile).

## The pipeline (a secure-boot path)

```
meld → scry (sound bounds) → kiln.resource_limits (embed) → sigil signs
     → embedded verify (no_std, offline, key-based) → reject-at-load → run
```

`reject-at-load` is the **boot-admission gate**: a module whose signed bounds
exceed the provisioned RAM/stack budget is refused on the bench, not trapped
mid-mission. The gate is only trustworthy if the target *trusts* the bound —
hence on-target signature verification.

## What already exists (so we build less than the issue assumes)

- **Key-based verify** (ask #3): `wsc-verify-core` already has the non-keyless
  Ed25519 public-key path (`signature/{multi,simple,keys}.rs`). std today.
- **The bounds format** (ask #2): kiln's `ResourceLimitsSection`
  (`kiln.resource_limits` v1) is already `no_std`/`BoundedMap`-bounded
  (`max_memory_usage`, `max_call_depth` [ASIL-D-required], `max_fuel_per_step`,
  `qualification_hash`, …). sigil signs the **whole module minus the sig
  section**, so this section is already covered by the signature. No new
  manifest format — reuse kiln's.
- **HW-crypto proposal**: sigil's `wsc:crypto` `hardware-signing` WIT
  (handle-based, key material stays in the secure element; ed25519/ecdsa;
  security-levels software→hardware-certified). gale would implement it.

## Spike result (2026-07-11) — ask #1 de-risked

`ed25519-compact` + `ct-codecs` (both `default-features = false`) build for
`thumbv7em-none-eabi` in `no_std` and expose the public-key verify API. So the
dependency wall is clear; ask #1 reduces to sigil's own std→no_std refactor:
feature-gate file-IO (`std::fs`/`os::unix`/`env::temp_dir`/`Path`, ~30 uses),
swap `std::io::Read`/`Cursor` (~18) for a slice reader, `alloc` collections +
`core::fmt`. Ship a `thumbv7em` staticlib mirroring kiln-async.

## Crypto strategy: HW-preferred, SW-fallback (DD-8)

- **HW where possible**: gale's `wsc:crypto` implementation (accelerated Ed25519
  verify / secure key storage) when the BSP provides it.
- **SW fallback**: `ed25519-compact` software verify. Verify uses **only public
  keys** — no secret material — so the SW fallback is *correctness-complete*
  without a secure element. HW buys speed (Cortex-M Ed25519 verify is costly)
  and key-storage assurance, not correctness.

## Release mapping

| Release | Scope |
|---|---|
| sigil **v0.10.0** | `no_std` carve of verify-core behind a default `std` feature; `thumbv7em-none-eabi` staticlib in CI; key-based verify reachable no_std (`REQ-15`). |
| sigil **v0.11.0** | require-signed-`kiln.resource_limits` + reject-at-load contract; integration test against kiln's loader (`REQ-16`). |

---

## DRAFT — comment for kiln #415 / AD-WCMC-001 (review before posting)

> sigil-side plan for the on-target trust chain is in sigil#187 (rivet FEAT-12).
> Key points for the loader integration:
> - **We reuse `kiln.resource_limits` verbatim** — no new manifest format. sigil's
>   whole-module signature already covers the section (only the sig custom
>   section is stripped before hashing), so the bounds are signed as-is.
> - **Integration point**: `resource_limits_loader` /
>   `extract_resource_limits_from_binary` should call sigil's (no_std) verify
>   **before** trusting the section. Proposed contract — the loader rejects if:
>   (a) the module signature is invalid, OR (b) the `kiln.resource_limits`
>   section is absent, OR (c) the signed bounds exceed the provisioned
>   RAM/stack budget.
> - **Pipeline ordering** matters: `cargo-kiln embed_limits` must run **before**
>   sigil signs, so the bounds are inside the signed hash. Can we confirm
>   `embed_limits` is a pre-sign build step?
> - sigil ships a `thumbv7em-none-eabi` staticlib (v0.10.0) for you to link,
>   mirroring kiln-async's no_std staticlib.

## DRAFT — issue/question for gale (review before posting; gale not checked out locally)

> For the gale/gust embedded secure-boot path (sigil#187, kiln#415), sigil needs
> to verify module signatures **on-target, offline, key-based**. Questions:
> 1. **HW-accelerated Ed25519 verify?** Does the BSP expose a crypto accelerator
>    for Ed25519 *verify* (public-key; no secret material)? If so we'd bind it
>    through sigil's `wsc:crypto` interface (extended with a `hardware-verify`
>    counterpart to the existing `hardware-signing`). If not, the software
>    `ed25519-compact` path is correctness-complete — HW is a perf/assurance
>    upgrade, not required.
> 2. **Trust-anchor provisioning**: where do the embedded verification **public
>    keys** live (gale secure storage / a provisioned key region)? The verifier
>    needs the trust anchor at load time.
> 3. **OS/BSP surface**: what `no_std` environment does the `thumbv7em` staticlib
>    link against (allocator present? which `core`/`alloc` assumptions)?
