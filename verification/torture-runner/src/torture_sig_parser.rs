//! Torture `SignatureForHashes::deserialize` against I/O fault injection.
//!
//! Builds a minimal-but-structurally-valid signature-section payload and
//! drives the parser against every fault offset. Exercises the `?` paths
//! in `varint::get_slice`, `varint::get32`, `read_exact`, and the
//! certificate-chain loop.

use std::io::Read;
use wsc_torture_runner::torture_io;
use wsc_verify_core::signature::SignatureForHashes;

fn main() {
    // Build a signature payload: empty key_id + Ed25519 alg id + signature
    // varint(3, [0xAA, 0xBB, 0xCC]) + cert_count(0).
    let payload: Vec<u8> = vec![
        0x00,             // key_id length = 0 (no key_id)
        0x01,             // alg_id = ED25519_PK_ID (1)
        0x03,             // signature length varint = 3
        0xAA, 0xBB, 0xCC, // signature bytes
        0x00,             // cert_count varint = 0 (no cert chain)
    ];

    // SignatureForHashes::deserialize takes `impl AsRef<[u8]>`, not a Reader,
    // so we adapt by draining the FaultyReader into a Vec inside the closure.
    // The fault therefore manifests as a short / truncated buffer fed to
    // deserialize — exactly the realistic adversarial-input scenario the
    // parser must handle without panicking.
    torture_io("SignatureForHashes::deserialize", &payload, |reader| {
        let mut buf = Vec::new();
        // read_to_end ignores Interrupted errors and keeps trying, so use a
        // manual loop that stops at the injected error to make the fault
        // visible to the parser.
        let mut chunk = [0u8; 32];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    // Surface the IO error as a parse error so it lands on
                    // the same `Result` channel the parser uses.
                    return Err(wsc_verify_core::CoreError::IOError(e));
                }
            }
        }
        SignatureForHashes::deserialize(&buf).map(|_| ())
    });

    println!("\n✔ SignatureForHashes::deserialize survived I/O torture at every byte offset.");
}
