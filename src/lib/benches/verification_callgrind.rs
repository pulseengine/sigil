//! Deterministic cost benchmarks for sigil's signature-verification paths.
//!
//! `verification_benchmarks.rs` measures wall time with criterion. On shared
//! CI runners wall time varies by a factor of ~3 between identical runs, so it
//! cannot gate a pull request. This file measures the same paths under
//! Valgrind via gungraun: Callgrind instruction counts (≈0.1 % run-to-run
//! spread) and DHAT heap allocations (exact). `.github/workflows/benchmarks.yml`
//! runs it for the PR head and for the base commit on the same runner, and
//! `scripts/perf-verdict.py` compares the two:
//!
//! - heap blocks or bytes up by more than the tolerance (default 2 %) on any
//!   benchmark fails the check;
//! - instructions up by more than 3 % are reported, not failed;
//! - wall time stays report-only (the criterion sanity run).
//!
//! Every fixture is deterministic (fixed seeds, fixed inputs) so the base and
//! head runs measure the same work. Each benchmark function is the Callgrind
//! and DHAT entry point: setup runs outside the measurement. All paths are
//! single-threaded; Valgrind serialises threads, so a threaded path would
//! measure the scheduler. Linux only.
//!
//! Running (needs valgrind and `gungraun-runner` at the same version as the
//! `gungraun` dev-dependency):
//!
//! ```text
//! cargo bench -p wsc --bench verification_callgrind
//! ```

use std::hint::black_box;
use std::io::Cursor;

use gungraun::{library_benchmark, library_benchmark_group, main, Dhat, LibraryBenchmarkConfig};

use wsc::dsse::{payload_types, DsseEnvelope, Ed25519DsseSigner, Ed25519DsseVerifier};
use wsc::keyless::merkle::{compute_leaf_hash, compute_node_hash, verify_inclusion_proof};
use wsc::keyless::{KeylessSignature, RekorEntry, MAX_CHAIN_DEPTH};
use wsc::{Module, PublicKey, SecretKey};

fn fixed_keypair() -> ed25519_compact::KeyPair {
    ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x5a; 32]))
}

// ── wasm module signature verify (the `wsc verify` path) ───────────────────

fn setup_signed_module() -> (PublicKey, Vec<u8>) {
    let wat = format!(
        r#"(module
             (memory 1)
             (func (export "answer") (result i32) i32.const 42)
             (data (i32.const 0) "{}"))"#,
        "sigil-bench-data-".repeat(256)
    );
    let raw = wat::parse_str(wat).expect("assemble fixture module");
    let module = Module::deserialize(&mut Cursor::new(raw)).expect("parse fixture module");
    let kp = fixed_keypair();
    let sk = SecretKey { sk: kp.sk };
    let signed = sk.sign(module, None).expect("sign fixture module");
    let mut bytes = Vec::new();
    signed.serialize(&mut bytes).expect("serialize signed module");
    (PublicKey { pk: kp.pk, key_id: None }, bytes)
}

#[library_benchmark]
#[bench::embedded_signature(setup = setup_signed_module)]
fn wasm_module_verify(fixture: (PublicKey, Vec<u8>)) -> bool {
    let (pk, bytes) = fixture;
    black_box(pk.verify(&mut Cursor::new(black_box(&bytes[..])), None).is_ok())
}

// ── Ed25519 verify (CR-1, CR-3) ────────────────────────────────────────────

fn setup_ed25519() -> (ed25519_compact::PublicKey, Vec<u8>, ed25519_compact::Signature) {
    let kp = fixed_keypair();
    let message = b"sigil-bench-fixed-payload-for-ed25519-verify".to_vec();
    let signature = kp.sk.sign(&message, None);
    (kp.pk, message, signature)
}

#[library_benchmark]
#[bench::message_44b(setup = setup_ed25519)]
fn ed25519_verify(
    fixture: (ed25519_compact::PublicKey, Vec<u8>, ed25519_compact::Signature),
) -> bool {
    let (pk, message, signature) = fixture;
    black_box(pk.verify(black_box(&message[..]), black_box(&signature)).is_ok())
}

// ── DSSE envelope parse + verify (CR-3, CR-8) ──────────────────────────────

fn setup_dsse() -> (Ed25519DsseVerifier, String) {
    let kp = fixed_keypair();
    let signer = Ed25519DsseSigner::new(kp.sk.clone(), Some("bench-key".to_string()));
    let payload = b"{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[]}";
    let envelope =
        DsseEnvelope::sign(payload, payload_types::IN_TOTO, &signer).expect("sign envelope");
    let json = envelope.to_json().expect("serialize envelope");
    (Ed25519DsseVerifier::new(kp.pk), json)
}

#[library_benchmark]
#[bench::in_toto_statement(setup = setup_dsse)]
fn dsse_parse_and_verify(fixture: (Ed25519DsseVerifier, String)) -> bool {
    let (verifier, json) = fixture;
    let parsed = DsseEnvelope::from_json(black_box(&json)).expect("parse envelope");
    black_box(parsed.verify(&verifier).is_ok())
}

// ── RFC 6962 Merkle inclusion proof (CR-3, CR-5, CR-8) ─────────────────────

/// Complete binary tree over `leaf_count` synthetic leaves; returns the
/// inclusion proof for leaf 0. Same hash primitives as the verifier.
fn setup_merkle(leaf_count: usize) -> (u64, [u8; 32], Vec<[u8; 32]>, [u8; 32]) {
    assert!(leaf_count.is_power_of_two());
    let mut level: Vec<[u8; 32]> = (0..leaf_count)
        .map(|i| compute_leaf_hash(format!("sigil-bench-leaf-{i}").as_bytes()))
        .collect();
    let leaf = level[0];
    let mut path = Vec::new();
    while level.len() > 1 {
        path.push(level[1]);
        level = level
            .chunks(2)
            .map(|p| compute_node_hash(&p[0], &p[1]))
            .collect();
    }
    (leaf_count as u64, leaf, path, level[0])
}

#[library_benchmark]
#[benches::leaves(args = [8, 4096], setup = setup_merkle)]
fn merkle_inclusion_verify(fixture: (u64, [u8; 32], Vec<[u8; 32]>, [u8; 32])) -> bool {
    let (tree_size, leaf, path, root) = fixture;
    black_box(verify_inclusion_proof(0, black_box(tree_size), &leaf, &path, &root).is_ok())
}

// ── Keyless signature parse + chain-depth bound (CR-7, CR-8) ───────────────

fn setup_keyless(chain_len: usize) -> Vec<u8> {
    let cert_chain = (0..chain_len)
        .map(|i| {
            format!(
                "-----BEGIN CERTIFICATE-----\nbench-cert-{i:03}-padding-padding-padding\n-----END CERTIFICATE-----"
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
    KeylessSignature::new(vec![0u8; 64], cert_chain, rekor_entry, vec![0xab; 32])
        .to_bytes()
        .expect("serialize KeylessSignature")
}

#[library_benchmark]
#[benches::chain(args = [1, MAX_CHAIN_DEPTH], setup = setup_keyless)]
fn keyless_signature_parse(bytes: Vec<u8>) -> bool {
    let parsed = KeylessSignature::from_bytes(black_box(&bytes)).expect("parse KeylessSignature");
    black_box(parsed.cert_chain.len() <= MAX_CHAIN_DEPTH)
}

library_benchmark_group!(
    name = verification,
    benchmarks = [
        wasm_module_verify,
        ed25519_verify,
        dsse_parse_and_verify,
        merkle_inclusion_verify,
        keyless_signature_parse
    ]
);

main!(
    config = LibraryBenchmarkConfig::default().tool(Dhat::default());
    library_benchmark_groups = verification
);
