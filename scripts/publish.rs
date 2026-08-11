//! Helper script to publish wsc crates to crates.io
//!
//! * `./publish verify` - verify crates can be published to crates.io
//! * `./publish publish` - actually publish crates to crates.io

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

// List of crates to publish in dependency order.
// wsc-verify-core and wsc-attestation MUST precede wsc (wsc depends on both);
// wsc-cli depends on wsc. wsc-component/wsc-crypto are not deps of any published
// crate, so they are intentionally not published.
const CRATES_TO_PUBLISH: &[&str] = &["wsc-verify-core", "wsc-attestation", "wsc-dsse", "wsc", "wsc-cli"];

struct Workspace {
    version: String,
}

struct Crate {
    manifest: PathBuf,
    name: String,
    version: String,
    publish: bool,
}

fn main() {
    let mut crates = Vec::new();

    // Read workspace version from root Cargo.toml
    let ws_version = std::fs::read_to_string("./Cargo.toml")
        .expect("failed to read workspace Cargo.toml")
        .lines()
        .find(|line| line.trim().starts_with("version ="))
        .expect("failed to find workspace version")
        .split('=')
        .nth(1)
        .expect("failed to parse workspace version")
        .trim()
        .trim_matches('"')
        .to_string();

    let ws = Workspace {
        version: ws_version,
    };

    // Add verify-core crate first (leaf: wsc depends on it, no internal deps)
    let verify_core_crate = read_crate(Some(&ws), "./src/verify-core/Cargo.toml".as_ref());
    crates.push(verify_core_crate);

    // Add attestation crate (leaf: wsc depends on it too)
    let attestation_crate = read_crate(Some(&ws), "./src/attestation/Cargo.toml".as_ref());
    crates.push(attestation_crate);

    // Add DSSE crate (leaf: wsc depends on it; must precede wsc)
    let dsse_crate = read_crate(Some(&ws), "./src/dsse/Cargo.toml".as_ref());
    crates.push(dsse_crate);

    // Add main library crate
    let lib_crate = read_crate(Some(&ws), "./src/lib/Cargo.toml".as_ref());
    crates.push(lib_crate);

    // Add CLI crate
    let cli_crate = read_crate(Some(&ws), "./src/cli/Cargo.toml".as_ref());
    crates.push(cli_crate);

    match &env::args().nth(1).expect("must have one argument")[..] {
        "publish" => {
            // Publish with retries for rate limiting/index propagation
            for _ in 0..10 {
                crates.retain(|krate| !publish(krate));

                if crates.is_empty() {
                    break;
                }

                println!(
                    "{} crates failed to publish, waiting to retry",
                    crates.len(),
                );
                thread::sleep(Duration::from_secs(40));
            }

            assert!(crates.is_empty(), "failed to publish all crates");

            println!("");
            println!("===================================================================");
            println!("");
            println!("Don't forget to push a git tag for this release!");
            println!("");
            println!("    $ git tag vX.Y.Z");
            println!("    $ git push origin vX.Y.Z");
        }

        "verify" => {
            verify(&crates);
        }

        s => panic!("unknown command: {}", s),
    }
}

fn read_crate(ws: Option<&Workspace>, manifest: &Path) -> Crate {
    let mut name = None;
    let mut version = None;
    let mut publish = true;

    let content = fs::read_to_string(manifest).expect("failed to read Cargo.toml");

    for line in content.lines() {
        let line = line.trim();

        // Parse name
        if name.is_none() && line.starts_with("name =") {
            if let Some(value) = line.split('=').nth(1) {
                let value = value.trim().trim_matches('"');
                name = Some(value.to_string());
            }
        }

        // Parse version
        if version.is_none() && line.starts_with("version =") {
            if let Some(value) = line.split('=').nth(1) {
                let value = value.trim();
                if value.starts_with('"') && value.ends_with('"') {
                    version = Some(value.trim_matches('"').to_string());
                }
            }
        } else if version.is_none() && line.trim() == "version.workspace = true" {
            if let Some(ws) = ws {
                version = Some(ws.version.clone());
            }
        }

        if line.starts_with("publish = false") {
            publish = false;
        }
    }

    let name = name.expect("failed to find crate name");
    let version = version.expect("failed to find crate version");

    Crate {
        manifest: manifest.to_path_buf(),
        name,
        version,
        publish,
    }
}

fn publish(krate: &Crate) -> bool {
    if !CRATES_TO_PUBLISH.iter().any(|s| *s == krate.name) {
        return true;
    }

    // Fail-safe: skip if this EXACT version is already on crates.io. Query the
    // version endpoint directly (crates.io requires a User-Agent — a bare curl
    // gets 403, which is why the old newest_version check silently missed and
    // then hard-failed on re-publish). e.g. wsc-verify-core 0.10.0 is already up.
    if already_published(&krate.name, &krate.version) {
        println!(
            "skip {}@{}: already published on crates.io",
            krate.name, krate.version,
        );
        return true;
    }

    let output = Command::new("cargo")
        .arg("publish")
        .current_dir(krate.manifest.parent().unwrap())
        .arg("--no-verify")
        .output()
        .expect("failed to run cargo");

    // Preserve cargo's own output in the CI log regardless of outcome.
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        println!("✅ Successfully published {}@{}", krate.name, krate.version);
        return true;
    }

    // Belt-and-suspenders fail-safe: if the upload failed *because* this version
    // already exists (a race with the pre-check, or a prior partial run), that is
    // not an error — treat it as a successful skip so the release stays green.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("already exists") || stderr.contains("already uploaded") {
        println!(
            "skip {}@{}: already published (detected at upload)",
            krate.name, krate.version,
        );
        return true;
    }

    println!("FAIL: failed to publish `{}`: {}", krate.name, output.status);
    false
}

// True only when this exact name@version is confirmed present on crates.io.
// On any uncertainty (network error, non-200) returns false so the publish path
// (and its own already-exists fail-safe) decides — we never skip on a maybe.
fn already_published(name: &str, version: &str) -> bool {
    let output = Command::new("curl")
        .arg("-sS")
        .arg("-H")
        .arg("User-Agent: sigil-release (github.com/pulseengine/sigil)")
        .arg(&format!("https://crates.io/api/v1/crates/{}/{}", name, version))
        .output()
        .expect("failed to invoke `curl`");

    if !output.status.success() {
        return false;
    }

    let body = String::from_utf8_lossy(&output.stdout);
    // The version endpoint returns {"version":{"num":"X.Y.Z",...}} when present,
    // or an {"errors":[...]} object when the version does not exist.
    body.contains(&format!("\"num\":\"{}\"", version)) && !body.contains("\"errors\"")
}

// Verify the current tree is publish-able to crates.io
fn verify(crates: &[Crate]) {
    // Clean up any existing vendor directory
    let _ = fs::remove_dir_all("vendor");

    // Vendor dependencies for offline verification
    let vendor = Command::new("cargo")
        .arg("vendor")
        .stderr(Stdio::inherit())
        .output()
        .unwrap();

    if !vendor.status.success() {
        println!("Warning: cargo vendor failed, proceeding anyway");
    }

    for krate in crates {
        if !krate.publish {
            continue;
        }
        verify_crate(&krate);
    }
}

fn verify_crate(krate: &Crate) {
    let mut cmd = Command::new("cargo");
    cmd.arg("package")
        .arg("--allow-dirty")
        .arg("--manifest-path")
        .arg(&krate.manifest)
        .env("CARGO_TARGET_DIR", "./target");

    let status = cmd.status().unwrap();
    assert!(status.success(), "failed to verify {:?}", &krate.manifest);

    println!("✅ Verified {} can be packaged", krate.name);
}
