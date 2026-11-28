//! `wsc verify-chain` binds the attested output hash at the command level
//! (REQ-39, #395). The library check has unit tests; these run the binary, so
//! removing the call in the command handler, or moving it behind the
//! `--policy` / `--report-only` branches, fails a test.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A minimal module: one `() -> ()` type, one function, one body (`end`).
const MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section
    0x03, 0x02, 0x01, 0x00, // function section
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: one body, `end`
];

fn wsc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wsc"))
}

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wsc-verify-chain-cli-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write MODULE as input and output, then `wsc attest` embeds the attestation
/// into the output. Returns the attested output path.
fn attested(dir: &Path) -> PathBuf {
    let input = dir.join("in.wasm");
    let output = dir.join("out.wasm");
    std::fs::write(&input, MODULE).unwrap();
    std::fs::write(&output, MODULE).unwrap();
    let st = wsc()
        .args(["attest", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .args(["--tool-name", "loom", "--tool-version", "1.0.0", "--type", "optimization"])
        .output()
        .unwrap();
    assert!(st.status.success(), "attest failed: {}", String::from_utf8_lossy(&st.stderr));
    output
}

/// Copy `src` with the function body's `end` (0x0b) changed to `nop` (0x01):
/// a change in the code section, before the attestation section.
fn tampered(src: &Path, dir: &Path) -> PathBuf {
    let mut bytes = std::fs::read(src).unwrap();
    let at = bytes
        .windows(3)
        .position(|w| w == [0x02, 0x00, 0x0b])
        .expect("code body present")
        + 2;
    bytes[at] = 0x01;
    let out = dir.join("tampered.wasm");
    std::fs::write(&out, bytes).unwrap();
    out
}

fn verify_chain(module: &Path, extra: &[&str]) -> (bool, String) {
    let out = wsc().args(["verify-chain", "-i"]).arg(module).args(extra).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn policy() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/policies/development.toml")
        .to_string_lossy()
        .into_owned()
}

// rivet: verifies REQ-39
#[test]
fn unmodified_attested_module_passes() {
    let dir = workdir("ok");
    let (ok, text) = verify_chain(&attested(&dir), &[]);
    assert!(ok, "an unmodified attested module must verify: {text}");
}

// rivet: verifies REQ-39
#[test]
fn modified_module_fails_in_every_mode() {
    let dir = workdir("tampered");
    let bad = tampered(&attested(&dir), &dir);
    let policy = policy();
    let modes: [&[&str]; 5] = [
        &[],
        &["--report-only"],
        &["--strict"],
        &["--policy", &policy],
        &["--policy", &policy, "--report-only"],
    ];
    for mode in modes {
        let (ok, text) = verify_chain(&bad, mode);
        assert!(!ok, "verify-chain {mode:?} accepted a module changed after attestation: {text}");
        assert!(
            text.contains("does not match the module"),
            "verify-chain {mode:?} failed, but not on the hash binding: {text}"
        );
    }
}

/// A module fused by meld 0.72.0, the first release whose output.hash covers
/// every byte except the attestation section (meld#701, option A of #396).
/// Source and regeneration steps: fixtures/meld-0.72.0-fused.input.wat.
const MELD_0_72_FUSED: &[u8] = include_bytes!("fixtures/meld-0.72.0-fused.wasm");

/// Write MELD_0_72_FUSED with one bit flipped at `at`, or unchanged for None.
fn meld_fixture(dir: &Path, name: &str, at: Option<usize>) -> PathBuf {
    let mut bytes = MELD_0_72_FUSED.to_vec();
    if let Some(at) = at {
        bytes[at] ^= 1;
    }
    let out = dir.join(name);
    std::fs::write(&out, bytes).unwrap();
    out
}

/// Offset of the first byte after `needle` in the fixture.
fn after(needle: &[u8]) -> usize {
    MELD_0_72_FUSED
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present in the meld fixture")
        + needle.len()
}

// rivet: verifies REQ-39
// rivet: verifies REQ-43
#[test]
fn meld_0_72_fused_module_verifies() {
    let dir = workdir("meld-ok");
    let (ok, text) = verify_chain(&meld_fixture(&dir, "fused.wasm", None), &[]);
    assert!(ok, "meld 0.72.0's unmodified fused module must verify: {text}");
}

// rivet: verifies REQ-39
// rivet: verifies REQ-43
#[test]
fn meld_0_72_component_provenance_byte_flip_is_rejected() {
    // meld 0.69.0 left component-provenance out of output.hash; 0.72.0 covers
    // it. One bit flipped in its payload must break the binding.
    let dir = workdir("meld-prov");
    let at = after(b"component-provenance") + 4;
    let (ok, text) = verify_chain(&meld_fixture(&dir, "prov.wasm", Some(at)), &[]);
    assert!(!ok, "a component-provenance byte flip was accepted: {text}");
    assert!(text.contains("does not match the module"), "failed, but not on the hash binding: {text}");
}

// rivet: verifies REQ-39
// rivet: verifies REQ-43
#[test]
fn meld_0_72_code_byte_flip_is_rejected() {
    // The fused body of `add`: local.get 0, local.get 1, i32.add (0x6a), end.
    // 0x6a -> 0x6b (i32.sub) keeps the module valid.
    let dir = workdir("meld-code");
    let at = after(&[0x20, 0x00, 0x20, 0x01]);
    assert_eq!(MELD_0_72_FUSED[at], 0x6a);
    let (ok, text) = verify_chain(&meld_fixture(&dir, "code.wasm", Some(at)), &[]);
    assert!(!ok, "a code byte flip was accepted: {text}");
    assert!(text.contains("does not match the module"), "failed, but not on the hash binding: {text}");
}

// rivet: verifies REQ-43
#[test]
fn meld_0_72_unsigned_attestation_rejected_when_signatures_required() {
    // meld's attestation is unsigned, so the hash binding cannot cover the
    // attestation itself: an edit inside it is caught only by requiring
    // attestation signatures.
    let dir = workdir("meld-unsigned");
    let at = after(b"\"imports_resolved\":");
    for (name, flip) in [("fused.wasm", None), ("att.wasm", Some(at))] {
        let (ok, text) =
            verify_chain(&meld_fixture(&dir, name, flip), &["--require-attestation-signatures"]);
        assert!(!ok, "{name}: an unsigned meld attestation passed --require-attestation-signatures: {text}");
        assert!(text.contains("unsigned"), "{name}: failed, but not on the missing signature: {text}");
    }
}
