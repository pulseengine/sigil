//! Criterion benchmarks for sigil's signature-verification hot paths.
//!
//! sigil is on the supply-chain hot path: every signature verification must
//! complete within a build-time budget. These benchmarks capture per-path
//! latency baselines so silent crypto-path regressions surface as criterion
//! diffs rather than mysteriously slow CI runs.
//!
//! Implements issue #89 (acceptance criteria sans the SLH-DSA path, which
//! is deferred to issue #46, and sans the CI integration, which is deferred
//! to a follow-up PR).
//!
//! # Traceability (rivet artifacts in `artifacts/cybersecurity/goals-and-requirements.yaml`)
//!
//! | bench group              | requirement                                              |
//! |--------------------------|----------------------------------------------------------|
//! | `ed25519_verify`         | CR-1  Use Approved Cryptographic Algorithms (Ed25519)    |
//! |                          | CR-3  Verify Software Integrity                          |
//! |                          | RFC 8032 (Ed25519) timing budget                         |
//! | `dsse_parse_and_verify`  | CR-3  Verify Software Integrity                          |
//! |                          | CR-8  Bound Resource Consumption (parser budget)         |
//! | `merkle_validation`      | CR-3  Verify Software Integrity                          |
//! |                          | CR-5  Log Security Events via Transparency Log (RFC 6962)|
//! |                          | CR-8  Bound Resource Consumption                         |
//! | `cert_chain_validation`  | CR-7  Enforce Certificate Pinning for Sigstore           |
//! |                          | CR-8  Bound Resource Consumption (MAX_CHAIN_DEPTH = 8)   |
//!
//! The SLH-DSA bench (FIPS 205) is intentionally omitted — see issue #46.
//!
//! # Running
//!
//! ```text
//! cargo bench -p wsc --bench verification_benchmarks                 # full run
//! cargo bench -p wsc --bench verification_benchmarks -- --quick      # smoke
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use wsc::dsse::{payload_types, DsseEnvelope, Ed25519DsseSigner, Ed25519DsseVerifier};
use wsc::keyless::merkle::{compute_leaf_hash, compute_node_hash, verify_inclusion_proof};
use wsc::keyless::{KeylessSignature, RekorEntry, MAX_CHAIN_DEPTH};

// ─────────────────────────────────────────────────────────────────────────
// Group 1: Ed25519 signature verify (CR-1, CR-3 / RFC 8032)
// ─────────────────────────────────────────────────────────────────────────

fn bench_ed25519_verify(c: &mut Criterion) {
    // Set up the input *once* — outside the inner loop.
    let kp = ed25519_compact::KeyPair::generate();
    let message: Vec<u8> = b"sigil-bench-fixed-payload-for-ed25519-verify".to_vec();
    let signature = kp.sk.sign(&message, None);

    let mut group = c.benchmark_group("ed25519_verify");
    group.throughput(Throughput::Elements(1));
    group.bench_function("verify_64B_message", |b| {
        b.iter(|| {
            // black_box on the inputs so the compiler can't constant-fold the verify.
            let res = kp
                .pk
                .verify(black_box(&message[..]), black_box(&signature));
            black_box(res.is_ok())
        });
    });
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────
// Group 2: DSSE envelope parse + verify (CR-3, CR-8)
// ─────────────────────────────────────────────────────────────────────────

fn bench_dsse_parse_and_verify(c: &mut Criterion) {
    // Construct a small envelope *once*; bench parses-then-verifies it.
    let kp = ed25519_compact::KeyPair::generate();
    let signer = Ed25519DsseSigner::new(kp.sk.clone(), Some("bench-key".to_string()));
    let verifier = Ed25519DsseVerifier::new(kp.pk);

    let payload = b"{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[]}";
    let envelope =
        DsseEnvelope::sign(payload, payload_types::IN_TOTO, &signer).expect("sign envelope");
    let envelope_json = envelope.to_json().expect("serialize envelope");

    let mut group = c.benchmark_group("dsse_parse_and_verify");
    group.throughput(Throughput::Elements(1));
    group.bench_function("from_json_then_verify", |b| {
        b.iter(|| {
            let parsed =
                DsseEnvelope::from_json(black_box(&envelope_json)).expect("parse envelope");
            let payload = parsed.verify(&verifier).expect("verify envelope");
            black_box(payload)
        });
    });
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────
// Group 3: Merkle tree validation, parameterised by leaf count (CR-3, CR-5, CR-8)
// ─────────────────────────────────────────────────────────────────────────

/// Build a complete-binary Merkle tree over `leaf_count` synthetic leaves and
/// return `(root, leaf_hashes, audit_path_for_leaf_0)` — enough to feed
/// `verify_inclusion_proof` for leaf 0 in a benchmark loop.
///
/// Implementation note: we use the *same* leaf/node hash primitives the
/// production verifier consumes, so the audit path is guaranteed valid.
/// We only support `leaf_count` that is a power of two to keep the fixture
/// construction trivial — that's fine for benchmarks (we just want a
/// realistic verify-side cost, not to exercise the odd-tree-size logic).
fn build_merkle_fixture(leaf_count: usize) -> ([u8; 32], [u8; 32], Vec<[u8; 32]>) {
    assert!(leaf_count.is_power_of_two() && leaf_count >= 1);

    // Compute leaf hashes for synthetic leaves.
    let mut level: Vec<[u8; 32]> = (0..leaf_count)
        .map(|i| {
            let leaf = format!("sigil-bench-leaf-{i}");
            compute_leaf_hash(leaf.as_bytes())
        })
        .collect();

    let leaf0_hash = level[0];

    // Walk up the tree, collecting the sibling at each level along the
    // path from leaf 0 to the root. For leaf 0 the sibling is always
    // the right-hand neighbour at index 1, then the right subtree root, etc.
    let mut audit_path: Vec<[u8; 32]> = Vec::new();
    while level.len() > 1 {
        // Sibling of leaf 0 at this level is level[1] (always the right
        // child of the leftmost pair).
        audit_path.push(level[1]);

        // Reduce level pairwise.
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(compute_node_hash(&pair[0], &pair[1]));
        }
        level = next;
    }

    let root = level[0];
    (root, leaf0_hash, audit_path)
}

fn bench_merkle_validation(c: &mut Criterion) {
    let leaf_counts: &[usize] = &[8, 64, 512, 4096];

    let mut group = c.benchmark_group("merkle_validation");
    for &n in leaf_counts {
        // Set up the fixture *once* per parameter — not in the inner loop.
        let (root, leaf_hash, audit_path) = build_merkle_fixture(n);
        let tree_size = n as u64;

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let res = verify_inclusion_proof(
                    black_box(0),
                    black_box(tree_size),
                    black_box(&leaf_hash),
                    black_box(&audit_path),
                    black_box(&root),
                );
                black_box(res.is_ok())
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────
// Group 4: Cert-chain parse + length-bound validation (CR-7, CR-8 / MAX_CHAIN_DEPTH=8)
// ─────────────────────────────────────────────────────────────────────────
//
// We bench the *parse + length-check* portion of cert-chain validation:
//   KeylessSignature::from_bytes  →  cert_chain.len() check against MAX_CHAIN_DEPTH
//
// The full WebPKI verification path (verify_cert_chain) requires real Fulcio
// roots and integrated_time fixtures, which would dominate the measurement
// with I/O setup rather than per-cert validation cost. The parse+bound check
// is the actual hot path on the inbound side (audit PR #98 added this
// MAX_CHAIN_DEPTH=8 guard precisely so that adversarial deep chains are
// rejected *before* the heavy WebPKI work begins).

fn make_keyless_signature(chain_len: usize) -> KeylessSignature {
    // Plausible-shaped PEMs — the parser only validates UTF-8 + length-prefix
    // framing at this layer, not the X.509 contents.
    let cert_chain: Vec<String> = (0..chain_len)
        .map(|i| {
            format!(
                "-----BEGIN CERTIFICATE-----\nbench-cert-{i:03}-padding-padding-padding-padding\n-----END CERTIFICATE-----"
            )
        })
        .collect();

    let rekor_entry = RekorEntry {
        uuid: "bench-uuid".to_string(),
        log_index: 1,
        body: "eyJiZW5jaCI6dHJ1ZX0=".to_string(),
        log_id: "bench-log-id".to_string(),
        inclusion_proof: vec![1, 2, 3, 4],
        signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
        integrated_time: "2025-01-01T00:00:00Z".to_string(),
    };

    KeylessSignature::new(
        vec![0u8; 64],     // Ed25519-sized signature placeholder
        cert_chain,
        rekor_entry,
        vec![0xab; 32],    // SHA-256-sized module hash placeholder
    )
}

fn bench_cert_chain_validation(c: &mut Criterion) {
    // Parameter set matches MAX_CHAIN_DEPTH = 8 (audit PR #98).
    let chain_lens: &[usize] = &[1, 2, 4, 8];

    let mut group = c.benchmark_group("cert_chain_validation");
    for &len in chain_lens {
        assert!(
            len <= MAX_CHAIN_DEPTH,
            "bench parameter must respect MAX_CHAIN_DEPTH bound"
        );

        // Build a serialized KeylessSignature once per parameter.
        let sig = make_keyless_signature(len);
        let bytes = sig.to_bytes().expect("serialize KeylessSignature");

        group.throughput(Throughput::Elements(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &len, |b, _| {
            b.iter(|| {
                // Parse the embedded signature blob (this is the real
                // entry point a verifier hits before WebPKI runs).
                let parsed = KeylessSignature::from_bytes(black_box(&bytes))
                    .expect("parse KeylessSignature");
                // Length-bound check matches the MAX_CHAIN_DEPTH guard that
                // runs at the start of verify_cert_chain (audit PR #98).
                let ok = parsed.cert_chain.len() <= MAX_CHAIN_DEPTH;
                black_box(ok)
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_ed25519_verify,
    bench_dsse_parse_and_verify,
    bench_merkle_validation,
    bench_cert_chain_validation,
);
criterion_main!(benches);
