//! Build environment attestation for SLSA provenance.
//!
//! Captures build environment metadata (toolchain versions, Bazel config,
//! Nix flake hash, platform info) and integrates it with SLSA provenance
//! as internal parameters. Addresses Ferrocene RUSTC_CSTR_0030 for
//! tool version verification.
//!
//! # Example
//!
//! ```ignore
//! use wsc::build_env::BuildEnvironment;
//!
//! let env = BuildEnvironment::capture();
//! println!("Rust: {}", env.rustc_version.as_deref().unwrap_or("unknown"));
//!
//! // Embed in SLSA provenance
//! let params = env.to_slsa_internal_params();
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::Command;

/// Build environment metadata captured at build/sign time.
///
/// Embedded as `internalParameters.buildEnvironment` in SLSA provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildEnvironment {
    /// Rust compiler version (output of `rustc --version`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustc_version: Option<String>,

    /// Cargo version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_version: Option<String>,

    /// Bazel version (from .bazelversion or `bazel --version`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bazel_version: Option<String>,

    /// Nix flake lock hash (SHA-256 of flake.lock for reproducibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nix_flake_lock_hash: Option<String>,

    /// Whether the build was run inside a Nix shell
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nix_build: Option<bool>,

    /// wasm-tools version (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_tools_version: Option<String>,

    /// Host platform (e.g., "aarch64-macos")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_platform: Option<String>,

    /// OS version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// Additional tool versions (key: tool name, value: version string)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub additional_tools: HashMap<String, String>,

    /// Capture timestamp (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
}

/// Resolve a command to its absolute path for logging (SC-35).
///
/// Uses `which`-style PATH lookup to determine which binary will actually
/// be executed. Returns None if the command is not found.
fn resolve_command_path(cmd: &str) -> Option<std::path::PathBuf> {
    // Check for explicit override env var first (e.g., WSC_RUSTC_PATH)
    let env_key = format!("WSC_{}_PATH", cmd.to_uppercase().replace('-', "_"));
    if let Ok(explicit_path) = std::env::var(&env_key) {
        let path = std::path::PathBuf::from(explicit_path);
        if path.exists() {
            return Some(path);
        }
        log::warn!(
            "{} set to {:?} but file does not exist — falling back to PATH",
            env_key,
            path
        );
    }

    // Fall back to PATH resolution
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(cmd);
            if full.is_file() {
                Some(full)
            } else {
                None
            }
        })
    })
}

/// Run a command and return trimmed stdout, or None on any failure.
///
/// SECURITY (SC-35 / H-37): Logs the resolved absolute path of the binary
/// to provide visibility into which tool is actually executed. Operators can
/// override tool paths via WSC_<TOOL>_PATH environment variables.
fn capture_command_output(cmd: &str, args: &[&str]) -> Option<String> {
    // SC-35: Resolve and log the actual binary path
    let resolved = resolve_command_path(cmd);
    if let Some(ref path) = resolved {
        log::debug!("Build env capture: {} resolved to {:?}", cmd, path);
    } else {
        log::debug!("Build env capture: {} not found in PATH", cmd);
    }

    let binary = resolved
        .as_ref()
        .map(|p| p.as_os_str())
        .unwrap_or_else(|| std::ffi::OsStr::new(cmd));

    Command::new(binary)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Find and read `.bazelversion` by walking up from the current directory.
fn read_bazel_version_file() -> Option<String> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".bazelversion");
        if candidate.is_file() {
            return std::fs::read_to_string(candidate)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Compute SHA-256 hash of `flake.lock` if it exists.
fn hash_flake_lock() -> Option<String> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join("flake.lock");
        if candidate.is_file() {
            let bytes = std::fs::read(candidate).ok()?;
            let hash = Sha256::digest(&bytes);
            return Some(hex::encode(hash));
        }
        if !dir.pop() {
            return None;
        }
    }
}

impl BuildEnvironment {
    /// Auto-detect build environment by probing tools and files.
    ///
    /// Runs external commands (`rustc`, `cargo`, `bazel`, `wasm-tools`)
    /// and reads configuration files (`.bazelversion`, `flake.lock`).
    /// Never fails — missing tools produce `None` fields.
    pub fn capture() -> Self {
        let rustc_version = capture_command_output("rustc", &["--version"]);
        let cargo_version = capture_command_output("cargo", &["--version"]);

        let bazel_version = read_bazel_version_file().or_else(|| {
            capture_command_output("bazel", &["--version"])
                .and_then(|s| s.strip_prefix("bazel ").map(|v| v.to_string()))
        });

        let nix_flake_lock_hash = hash_flake_lock();

        let nix_build = if std::env::var("IN_NIX_SHELL").is_ok()
            || std::env::var("NIX_BUILD_TOP").is_ok()
        {
            Some(true)
        } else {
            None
        };

        let wasm_tools_version = capture_command_output("wasm-tools", &["--version"]);

        let host_platform = Some(format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS));

        let os_version = capture_command_output("uname", &["-sr"])
            .or_else(|| std::env::var("OS").ok());

        let captured_at = Some(chrono::Utc::now().to_rfc3339());

        Self {
            rustc_version,
            cargo_version,
            bazel_version,
            nix_flake_lock_hash,
            nix_build,
            wasm_tools_version,
            host_platform,
            os_version,
            additional_tools: HashMap::new(),
            captured_at,
        }
    }

    /// Read build environment from `WSC_*` environment variables.
    ///
    /// Falls back to `capture()` for any variables that are not set.
    /// Useful in CI where tool paths may not be on `$PATH` but versions
    /// are known.
    ///
    /// Recognized variables:
    /// - `WSC_RUSTC_VERSION`
    /// - `WSC_CARGO_VERSION`
    /// - `WSC_BAZEL_VERSION`
    /// - `WSC_NIX_FLAKE_LOCK_HASH`
    /// - `WSC_WASM_TOOLS_VERSION`
    pub fn from_env_vars() -> Self {
        let mut env = Self::capture();

        if let Ok(v) = std::env::var("WSC_RUSTC_VERSION") {
            env.rustc_version = Some(v);
        }
        if let Ok(v) = std::env::var("WSC_CARGO_VERSION") {
            env.cargo_version = Some(v);
        }
        if let Ok(v) = std::env::var("WSC_BAZEL_VERSION") {
            env.bazel_version = Some(v);
        }
        if let Ok(v) = std::env::var("WSC_NIX_FLAKE_LOCK_HASH") {
            env.nix_flake_lock_hash = Some(v);
        }
        if let Ok(v) = std::env::var("WSC_WASM_TOOLS_VERSION") {
            env.wasm_tools_version = Some(v);
        }

        env
    }

    /// Convert to SLSA provenance `internalParameters` JSON value.
    ///
    /// Returns a JSON object suitable for embedding in
    /// `BuildDefinition.internalParameters.buildEnvironment`.
    pub fn to_slsa_internal_params(&self) -> serde_json::Value {
        serde_json::json!({
            "buildEnvironment": self
        })
    }

    /// Add a custom tool version entry.
    pub fn with_tool(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.additional_tools.insert(name.into(), version.into());
        self
    }

    /// Whether the build environment is reproducible (Nix flake lock pinned).
    pub fn is_reproducible(&self) -> bool {
        self.nix_flake_lock_hash.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture() {
        let env = BuildEnvironment::capture();
        // rustc should be available in any Rust dev environment
        assert!(env.rustc_version.is_some());
        assert!(env.cargo_version.is_some());
        assert!(env.host_platform.is_some());
        assert!(env.captured_at.is_some());
    }

    #[test]
    fn test_from_env_vars_structure() {
        // We can't safely set env vars in edition 2024 (set_var is unsafe),
        // so verify the method works by checking it returns a valid struct
        // with at least the auto-detected fields.
        let env = BuildEnvironment::from_env_vars();
        // Should still detect rustc even without WSC_ vars set
        assert!(env.rustc_version.is_some());
        assert!(env.host_platform.is_some());
    }

    #[test]
    fn test_to_slsa_internal_params() {
        let env = BuildEnvironment {
            rustc_version: Some("rustc 1.90.0".to_string()),
            cargo_version: Some("cargo 1.90.0".to_string()),
            bazel_version: Some("8.5.1".to_string()),
            nix_flake_lock_hash: Some("abc123".to_string()),
            nix_build: Some(true),
            wasm_tools_version: None,
            host_platform: Some("aarch64-macos".to_string()),
            os_version: None,
            additional_tools: HashMap::new(),
            captured_at: Some("2026-03-18T00:00:00Z".to_string()),
        };

        let params = env.to_slsa_internal_params();
        let be = &params["buildEnvironment"];
        assert_eq!(be["rustcVersion"], "rustc 1.90.0");
        assert_eq!(be["bazelVersion"], "8.5.1");
        assert_eq!(be["nixFlakeLockHash"], "abc123");
        assert_eq!(be["nixBuild"], true);
        assert_eq!(be["hostPlatform"], "aarch64-macos");
        // None fields should not be present
        assert!(be.get("wasmToolsVersion").is_none());
        assert!(be.get("osVersion").is_none());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let env = BuildEnvironment::capture();
        let json = serde_json::to_string_pretty(&env).unwrap();
        let parsed: BuildEnvironment = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.rustc_version, env.rustc_version);
        assert_eq!(parsed.cargo_version, env.cargo_version);
        assert_eq!(parsed.host_platform, env.host_platform);
    }

    #[test]
    fn test_with_tool() {
        let env = BuildEnvironment::capture()
            .with_tool("protoc", "3.21.0")
            .with_tool("z3", "4.12.0");

        assert_eq!(
            env.additional_tools.get("protoc"),
            Some(&"3.21.0".to_string())
        );
        assert_eq!(
            env.additional_tools.get("z3"),
            Some(&"4.12.0".to_string())
        );
    }

    #[test]
    fn test_is_reproducible() {
        let mut env = BuildEnvironment::capture();

        // If flake.lock exists in the project, it may already be reproducible.
        // Test both states explicitly.
        env.nix_flake_lock_hash = None;
        assert!(!env.is_reproducible());

        env.nix_flake_lock_hash = Some("abc123".to_string());
        assert!(env.is_reproducible());
    }

    #[test]
    fn test_skip_none_fields() {
        let env = BuildEnvironment {
            rustc_version: Some("rustc 1.90.0".to_string()),
            cargo_version: None,
            bazel_version: None,
            nix_flake_lock_hash: None,
            nix_build: None,
            wasm_tools_version: None,
            host_platform: None,
            os_version: None,
            additional_tools: HashMap::new(),
            captured_at: None,
        };

        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("rustcVersion"));
        assert!(!json.contains("cargoVersion"));
        assert!(!json.contains("bazelVersion"));
        assert!(!json.contains("nixFlakeLockHash"));
        assert!(!json.contains("additionalTools"));
        assert!(!json.contains("capturedAt"));
    }

    #[test]
    fn test_capture_command_output_missing_tool() {
        let result = capture_command_output("this-tool-definitely-does-not-exist-xyz", &["--version"]);
        assert!(result.is_none());
    }

    #[test]
    fn test_bazel_version_from_file() {
        // This test depends on .bazelversion being present in the project
        // Just verify it doesn't panic
        let _ = read_bazel_version_file();
    }
}
