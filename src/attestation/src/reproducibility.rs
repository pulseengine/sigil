//! Reproducibility tracking for SLSA L4 compliance
//!
//! This module provides data structures for capturing everything needed to
//! reproduce a build, following SLSA L4 requirements:
//!
//! - **Build environment**: Compiler version, target, features, flags
//! - **Material manifest**: All dependencies with exact versions and hashes
//! - **Builder identity**: CI/CD platform detection
//!
//! # Example
//!
//! ```rust
//! use wsc_attestation::reproducibility::*;
//!
//! // Capture build environment (typically done in build.rs or at build time)
//! let env = BuildEnvironment::builder()
//!     .rustc_version("1.75.0")
//!     .target("wasm32-wasip2")
//!     .add_feature("signing")
//!     .build();
//!
//! // Create a dependency pin
//! let dep = DependencyPin::new("serde", "1.0.195", "crates.io")
//!     .with_hash("sha256:abc123...");
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete build environment capture for reproducibility
///
/// Captures all information about the build machine and configuration
/// that could affect the resulting artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildEnvironment {
    /// Rust compiler version (e.g., "1.75.0")
    pub rustc_version: String,

    /// Rust toolchain identifier (e.g., "stable-x86_64-unknown-linux-gnu")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,

    /// Cargo version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_version: Option<String>,

    /// Target triple (e.g., "wasm32-wasip2", "x86_64-unknown-linux-gnu")
    pub target: String,

    /// Optimization level (0, 1, 2, 3, "s", "z")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt_level: Option<String>,

    /// LTO mode ("off", "thin", "fat")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lto: Option<String>,

    /// Codegen units
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codegen_units: Option<u32>,

    /// Cargo features enabled
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,

    /// RUSTFLAGS environment variable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustflags: Option<String>,

    /// CI/CD builder identity (if detected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<BuilderIdentity>,

    /// Build timestamp (ISO 8601)
    pub build_timestamp: String,

    /// Host OS and architecture (e.g., "linux-x86_64", "macos-aarch64")
    pub build_host: String,

    /// Additional environment variables that affect the build
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra_env: HashMap<String, String>,
}

impl BuildEnvironment {
    /// Create a new builder for BuildEnvironment
    pub fn builder() -> BuildEnvironmentBuilder {
        BuildEnvironmentBuilder::new()
    }

    /// Attempt to detect the current build environment automatically
    ///
    /// This captures what can be detected at runtime. For accurate
    /// build-time capture, use the builder pattern with explicit values
    /// from build.rs or CI environment.
    pub fn detect() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let host = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

        Self {
            rustc_version: option_env!("RUSTC_VERSION")
                .unwrap_or("unknown")
                .to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN").ok(),
            cargo_version: option_env!("CARGO_PKG_VERSION").map(|v| v.to_string()),
            target: std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string()),
            opt_level: std::env::var("OPT_LEVEL").ok(),
            lto: std::env::var("LTO").ok(),
            codegen_units: std::env::var("CODEGEN_UNITS")
                .ok()
                .and_then(|s| s.parse().ok()),
            features: Vec::new(),
            rustflags: std::env::var("RUSTFLAGS").ok(),
            builder: BuilderIdentity::detect(),
            build_timestamp: now,
            build_host: host,
            extra_env: HashMap::new(),
        }
    }
}

/// Builder for creating BuildEnvironment
pub struct BuildEnvironmentBuilder {
    rustc_version: Option<String>,
    toolchain: Option<String>,
    cargo_version: Option<String>,
    target: Option<String>,
    opt_level: Option<String>,
    lto: Option<String>,
    codegen_units: Option<u32>,
    features: Vec<String>,
    rustflags: Option<String>,
    builder: Option<BuilderIdentity>,
    extra_env: HashMap<String, String>,
}

impl BuildEnvironmentBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            rustc_version: None,
            toolchain: None,
            cargo_version: None,
            target: None,
            opt_level: None,
            lto: None,
            codegen_units: None,
            features: Vec::new(),
            rustflags: None,
            builder: None,
            extra_env: HashMap::new(),
        }
    }

    /// Set rustc version
    pub fn rustc_version(mut self, version: impl Into<String>) -> Self {
        self.rustc_version = Some(version.into());
        self
    }

    /// Set toolchain identifier
    pub fn toolchain(mut self, toolchain: impl Into<String>) -> Self {
        self.toolchain = Some(toolchain.into());
        self
    }

    /// Set cargo version
    pub fn cargo_version(mut self, version: impl Into<String>) -> Self {
        self.cargo_version = Some(version.into());
        self
    }

    /// Set target triple
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Set optimization level
    pub fn opt_level(mut self, level: impl Into<String>) -> Self {
        self.opt_level = Some(level.into());
        self
    }

    /// Set LTO mode
    pub fn lto(mut self, lto: impl Into<String>) -> Self {
        self.lto = Some(lto.into());
        self
    }

    /// Set codegen units
    pub fn codegen_units(mut self, units: u32) -> Self {
        self.codegen_units = Some(units);
        self
    }

    /// Add a cargo feature
    pub fn add_feature(mut self, feature: impl Into<String>) -> Self {
        self.features.push(feature.into());
        self
    }

    /// Set all features at once
    pub fn features(mut self, features: Vec<String>) -> Self {
        self.features = features;
        self
    }

    /// Set RUSTFLAGS
    pub fn rustflags(mut self, flags: impl Into<String>) -> Self {
        self.rustflags = Some(flags.into());
        self
    }

    /// Set builder identity
    pub fn builder(mut self, builder: BuilderIdentity) -> Self {
        self.builder = Some(builder);
        self
    }

    /// Add an extra environment variable
    pub fn add_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.insert(key.into(), value.into());
        self
    }

    /// Build the BuildEnvironment
    pub fn build(self) -> BuildEnvironment {
        let now = chrono::Utc::now().to_rfc3339();
        let host = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

        BuildEnvironment {
            rustc_version: self.rustc_version.unwrap_or_else(|| "unknown".to_string()),
            toolchain: self.toolchain,
            cargo_version: self.cargo_version,
            target: self.target.unwrap_or_else(|| "unknown".to_string()),
            opt_level: self.opt_level,
            lto: self.lto,
            codegen_units: self.codegen_units,
            features: self.features,
            rustflags: self.rustflags,
            builder: self.builder.or_else(BuilderIdentity::detect),
            build_timestamp: now,
            build_host: host,
            extra_env: self.extra_env,
        }
    }
}

impl Default for BuildEnvironmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// CI/CD builder identity for attribution
///
/// Identifies the build system that produced the artifact,
/// enabling trust decisions based on builder identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuilderIdentity {
    /// Builder type (e.g., "github-actions", "gitlab-ci", "local")
    pub builder_type: String,

    /// Builder ID (typically a URI)
    pub builder_id: String,

    /// Workflow or pipeline name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,

    /// Job or step name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,

    /// Run ID (unique execution identifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,

    /// Run number (monotonic counter)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_number: Option<String>,

    /// Repository (for CI systems)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,

    /// Git ref (branch, tag, or PR ref)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,

    /// Commit SHA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

impl BuilderIdentity {
    /// Create a new builder identity
    pub fn new(builder_type: impl Into<String>, builder_id: impl Into<String>) -> Self {
        Self {
            builder_type: builder_type.into(),
            builder_id: builder_id.into(),
            workflow: None,
            job: None,
            run_id: None,
            run_number: None,
            repository: None,
            ref_name: None,
            commit_sha: None,
        }
    }

    /// Create a local development builder identity
    pub fn local() -> Self {
        Self::new("local", "https://wsc.dev/local-builder/v1")
    }

    /// Attempt to detect CI/CD environment automatically
    pub fn detect() -> Option<Self> {
        // GitHub Actions
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            let repo = std::env::var("GITHUB_REPOSITORY").unwrap_or_default();
            let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_default();

            return Some(Self {
                builder_type: "github-actions".to_string(),
                builder_id: format!(
                    "https://github.com/{}/actions/runs/{}",
                    repo, run_id
                ),
                workflow: std::env::var("GITHUB_WORKFLOW").ok(),
                job: std::env::var("GITHUB_JOB").ok(),
                run_id: Some(run_id),
                run_number: std::env::var("GITHUB_RUN_NUMBER").ok(),
                repository: Some(repo),
                ref_name: std::env::var("GITHUB_REF_NAME").ok(),
                commit_sha: std::env::var("GITHUB_SHA").ok(),
            });
        }

        // GitLab CI
        if std::env::var("GITLAB_CI").is_ok() {
            return Some(Self {
                builder_type: "gitlab-ci".to_string(),
                builder_id: std::env::var("CI_JOB_URL").unwrap_or_default(),
                workflow: std::env::var("CI_PIPELINE_NAME").ok(),
                job: std::env::var("CI_JOB_NAME").ok(),
                run_id: std::env::var("CI_JOB_ID").ok(),
                run_number: std::env::var("CI_PIPELINE_IID").ok(),
                repository: std::env::var("CI_PROJECT_PATH").ok(),
                ref_name: std::env::var("CI_COMMIT_REF_NAME").ok(),
                commit_sha: std::env::var("CI_COMMIT_SHA").ok(),
            });
        }

        // CircleCI
        if std::env::var("CIRCLECI").is_ok() {
            return Some(Self {
                builder_type: "circleci".to_string(),
                builder_id: std::env::var("CIRCLE_BUILD_URL").unwrap_or_default(),
                workflow: std::env::var("CIRCLE_WORKFLOW_ID").ok(),
                job: std::env::var("CIRCLE_JOB").ok(),
                run_id: std::env::var("CIRCLE_BUILD_NUM").ok(),
                run_number: std::env::var("CIRCLE_BUILD_NUM").ok(),
                repository: std::env::var("CIRCLE_PROJECT_REPONAME").ok(),
                ref_name: std::env::var("CIRCLE_BRANCH")
                    .ok()
                    .or_else(|| std::env::var("CIRCLE_TAG").ok()),
                commit_sha: std::env::var("CIRCLE_SHA1").ok(),
            });
        }

        // Azure Pipelines
        if std::env::var("TF_BUILD").is_ok() {
            return Some(Self {
                builder_type: "azure-pipelines".to_string(),
                builder_id: std::env::var("BUILD_BUILDURI").unwrap_or_default(),
                workflow: std::env::var("BUILD_DEFINITIONNAME").ok(),
                job: std::env::var("AGENT_JOBNAME").ok(),
                run_id: std::env::var("BUILD_BUILDID").ok(),
                run_number: std::env::var("BUILD_BUILDNUMBER").ok(),
                repository: std::env::var("BUILD_REPOSITORY_NAME").ok(),
                ref_name: std::env::var("BUILD_SOURCEBRANCHNAME").ok(),
                commit_sha: std::env::var("BUILD_SOURCEVERSION").ok(),
            });
        }

        // Jenkins
        if std::env::var("JENKINS_URL").is_ok() {
            return Some(Self {
                builder_type: "jenkins".to_string(),
                builder_id: std::env::var("BUILD_URL").unwrap_or_default(),
                workflow: std::env::var("JOB_NAME").ok(),
                job: std::env::var("JOB_BASE_NAME").ok(),
                run_id: std::env::var("BUILD_ID").ok(),
                run_number: std::env::var("BUILD_NUMBER").ok(),
                repository: None,
                ref_name: std::env::var("GIT_BRANCH").ok(),
                commit_sha: std::env::var("GIT_COMMIT").ok(),
            });
        }

        // Not detected - return None (caller can use local identity if desired)
        None
    }

    /// Set workflow name
    pub fn with_workflow(mut self, workflow: impl Into<String>) -> Self {
        self.workflow = Some(workflow.into());
        self
    }

    /// Set job name
    pub fn with_job(mut self, job: impl Into<String>) -> Self {
        self.job = Some(job.into());
        self
    }

    /// Set run ID
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    /// Set repository
    pub fn with_repository(mut self, repo: impl Into<String>) -> Self {
        self.repository = Some(repo.into());
        self
    }

    /// Set commit SHA
    pub fn with_commit_sha(mut self, sha: impl Into<String>) -> Self {
        self.commit_sha = Some(sha.into());
        self
    }
}

/// Complete material manifest - all inputs to a build
///
/// For SLSA L4, all materials must be pinned with cryptographic hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialManifest {
    /// Hash of Cargo.lock file contents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_lock_hash: Option<String>,

    /// All resolved dependencies with exact versions and hashes
    pub dependencies: Vec<DependencyPin>,

    /// Hash of source code (git tree hash or computed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<String>,

    /// Git commit SHA (if building from git)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,

    /// Git tree hash (more stable than commit, identifies content)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_tree: Option<String>,

    /// Build script outputs that affect the build
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub build_script_outputs: Vec<String>,

    /// Additional files that affect the build
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_files: Vec<FilePin>,
}

impl MaterialManifest {
    /// Create a new empty manifest
    pub fn new() -> Self {
        Self {
            cargo_lock_hash: None,
            dependencies: Vec::new(),
            source_hash: None,
            git_commit: None,
            git_tree: None,
            build_script_outputs: Vec::new(),
            additional_files: Vec::new(),
        }
    }

    /// Create a manifest builder
    pub fn builder() -> MaterialManifestBuilder {
        MaterialManifestBuilder::new()
    }

    /// Add a dependency pin
    pub fn add_dependency(&mut self, dep: DependencyPin) {
        self.dependencies.push(dep);
    }

    /// Count dependencies
    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }

    /// Check if all dependencies have hashes
    pub fn all_dependencies_pinned(&self) -> bool {
        self.dependencies.iter().all(|d| d.hash.is_some())
    }
}

impl Default for MaterialManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for MaterialManifest
pub struct MaterialManifestBuilder {
    cargo_lock_hash: Option<String>,
    dependencies: Vec<DependencyPin>,
    source_hash: Option<String>,
    git_commit: Option<String>,
    git_tree: Option<String>,
    build_script_outputs: Vec<String>,
    additional_files: Vec<FilePin>,
}

impl MaterialManifestBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            cargo_lock_hash: None,
            dependencies: Vec::new(),
            source_hash: None,
            git_commit: None,
            git_tree: None,
            build_script_outputs: Vec::new(),
            additional_files: Vec::new(),
        }
    }

    /// Set Cargo.lock hash
    pub fn cargo_lock_hash(mut self, hash: impl Into<String>) -> Self {
        self.cargo_lock_hash = Some(hash.into());
        self
    }

    /// Add a dependency
    pub fn add_dependency(mut self, dep: DependencyPin) -> Self {
        self.dependencies.push(dep);
        self
    }

    /// Set source hash
    pub fn source_hash(mut self, hash: impl Into<String>) -> Self {
        self.source_hash = Some(hash.into());
        self
    }

    /// Set git commit
    pub fn git_commit(mut self, commit: impl Into<String>) -> Self {
        self.git_commit = Some(commit.into());
        self
    }

    /// Set git tree hash
    pub fn git_tree(mut self, tree: impl Into<String>) -> Self {
        self.git_tree = Some(tree.into());
        self
    }

    /// Add build script output
    pub fn add_build_script_output(mut self, output: impl Into<String>) -> Self {
        self.build_script_outputs.push(output.into());
        self
    }

    /// Add additional file
    pub fn add_file(mut self, file: FilePin) -> Self {
        self.additional_files.push(file);
        self
    }

    /// Build the manifest
    pub fn build(self) -> MaterialManifest {
        MaterialManifest {
            cargo_lock_hash: self.cargo_lock_hash,
            dependencies: self.dependencies,
            source_hash: self.source_hash,
            git_commit: self.git_commit,
            git_tree: self.git_tree,
            build_script_outputs: self.build_script_outputs,
            additional_files: self.additional_files,
        }
    }
}

impl Default for MaterialManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Pinned dependency with cryptographic hash
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyPin {
    /// Package name
    pub name: String,

    /// Exact version
    pub version: String,

    /// Source (e.g., "crates.io", "git", "path")
    pub source: String,

    /// SHA-256 hash of crate contents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,

    /// Registry URL (for crates.io packages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,

    /// Git URL (for git dependencies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_url: Option<String>,

    /// Git revision (commit, tag, or branch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_rev: Option<String>,

    /// Path (for path dependencies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl DependencyPin {
    /// Create a new dependency pin
    pub fn new(name: impl Into<String>, version: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            source: source.into(),
            hash: None,
            registry: None,
            git_url: None,
            git_rev: None,
            path: None,
        }
    }

    /// Create a crates.io dependency
    pub fn crates_io(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(name, version, "crates.io")
            .with_registry("https://crates.io")
    }

    /// Create a git dependency
    pub fn git(
        name: impl Into<String>,
        version: impl Into<String>,
        url: impl Into<String>,
        rev: impl Into<String>,
    ) -> Self {
        let mut dep = Self::new(name, version, "git");
        dep.git_url = Some(url.into());
        dep.git_rev = Some(rev.into());
        dep
    }

    /// Create a path dependency
    pub fn path(name: impl Into<String>, version: impl Into<String>, path: impl Into<String>) -> Self {
        let mut dep = Self::new(name, version, "path");
        dep.path = Some(path.into());
        dep
    }

    /// Set hash
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.hash = Some(hash.into());
        self
    }

    /// Set registry
    pub fn with_registry(mut self, registry: impl Into<String>) -> Self {
        self.registry = Some(registry.into());
        self
    }
}

/// Pinned file with hash
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePin {
    /// File path (relative to project root)
    pub path: String,

    /// SHA-256 hash of file contents
    pub hash: String,

    /// File size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

impl FilePin {
    /// Create a new file pin
    pub fn new(path: impl Into<String>, hash: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            hash: hash.into(),
            size: None,
        }
    }

    /// Set file size
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
}

/// Reproducibility verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReproducibilityVerification {
    /// Whether the build is reproducible
    pub is_reproducible: bool,

    /// Environment where rebuild was performed
    pub verification_environment: BuildEnvironment,

    /// Hash of rebuilt artifact
    pub rebuilt_hash: String,

    /// Hash of original artifact
    pub original_hash: String,

    /// Timestamp of verification (ISO 8601)
    pub verified_at: String,

    /// Differences found (if not reproducible)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub differences: Vec<String>,
}

impl ReproducibilityVerification {
    /// Create a successful verification
    pub fn success(
        env: BuildEnvironment,
        original_hash: impl Into<String>,
    ) -> Self {
        let hash = original_hash.into();
        Self {
            is_reproducible: true,
            verification_environment: env,
            rebuilt_hash: hash.clone(),
            original_hash: hash,
            verified_at: chrono::Utc::now().to_rfc3339(),
            differences: Vec::new(),
        }
    }

    /// Create a failed verification
    pub fn failure(
        env: BuildEnvironment,
        original_hash: impl Into<String>,
        rebuilt_hash: impl Into<String>,
        differences: Vec<String>,
    ) -> Self {
        Self {
            is_reproducible: false,
            verification_environment: env,
            rebuilt_hash: rebuilt_hash.into(),
            original_hash: original_hash.into(),
            verified_at: chrono::Utc::now().to_rfc3339(),
            differences,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_environment_builder() {
        let env = BuildEnvironment::builder()
            .rustc_version("1.75.0")
            .target("wasm32-wasip2")
            .opt_level("3")
            .add_feature("signing")
            .add_feature("async")
            .build();

        assert_eq!(env.rustc_version, "1.75.0");
        assert_eq!(env.target, "wasm32-wasip2");
        assert_eq!(env.opt_level, Some("3".to_string()));
        assert_eq!(env.features, vec!["signing", "async"]);
    }

    #[test]
    fn test_builder_identity_github_detection() {
        // Can't easily test actual detection without setting env vars
        // but we can test the struct creation
        let builder = BuilderIdentity::new("github-actions", "https://github.com/org/repo/actions/runs/123")
            .with_workflow("CI")
            .with_job("build")
            .with_run_id("123")
            .with_repository("org/repo")
            .with_commit_sha("abc123");

        assert_eq!(builder.builder_type, "github-actions");
        assert_eq!(builder.workflow, Some("CI".to_string()));
        assert_eq!(builder.commit_sha, Some("abc123".to_string()));
    }

    #[test]
    fn test_dependency_pin() {
        let dep = DependencyPin::crates_io("serde", "1.0.195")
            .with_hash("sha256:abc123");

        assert_eq!(dep.name, "serde");
        assert_eq!(dep.version, "1.0.195");
        assert_eq!(dep.source, "crates.io");
        assert_eq!(dep.hash, Some("sha256:abc123".to_string()));
        assert_eq!(dep.registry, Some("https://crates.io".to_string()));
    }

    #[test]
    fn test_material_manifest_builder() {
        let manifest = MaterialManifest::builder()
            .cargo_lock_hash("sha256:lockfile123")
            .git_commit("abc123def456")
            .add_dependency(DependencyPin::crates_io("serde", "1.0"))
            .add_dependency(DependencyPin::crates_io("tokio", "1.0"))
            .build();

        assert_eq!(manifest.cargo_lock_hash, Some("sha256:lockfile123".to_string()));
        assert_eq!(manifest.git_commit, Some("abc123def456".to_string()));
        assert_eq!(manifest.dependency_count(), 2);
    }

    #[test]
    fn test_all_dependencies_pinned() {
        let mut manifest = MaterialManifest::new();
        manifest.add_dependency(DependencyPin::crates_io("a", "1.0").with_hash("hash1"));
        manifest.add_dependency(DependencyPin::crates_io("b", "2.0").with_hash("hash2"));

        assert!(manifest.all_dependencies_pinned());

        manifest.add_dependency(DependencyPin::crates_io("c", "3.0")); // No hash
        assert!(!manifest.all_dependencies_pinned());
    }

    #[test]
    fn test_reproducibility_verification_success() {
        let env = BuildEnvironment::builder()
            .rustc_version("1.75.0")
            .target("wasm32-wasip2")
            .build();

        let verification = ReproducibilityVerification::success(env, "sha256:artifact123");

        assert!(verification.is_reproducible);
        assert_eq!(verification.original_hash, verification.rebuilt_hash);
        assert!(verification.differences.is_empty());
    }

    #[test]
    fn test_reproducibility_verification_failure() {
        let env = BuildEnvironment::builder()
            .rustc_version("1.75.0")
            .target("wasm32-wasip2")
            .build();

        let verification = ReproducibilityVerification::failure(
            env,
            "sha256:original",
            "sha256:rebuilt",
            vec!["Timestamp differs".to_string()],
        );

        assert!(!verification.is_reproducible);
        assert_ne!(verification.original_hash, verification.rebuilt_hash);
        assert_eq!(verification.differences.len(), 1);
    }

    #[test]
    fn test_json_serialization() {
        let env = BuildEnvironment::builder()
            .rustc_version("1.75.0")
            .target("wasm32-wasip2")
            .add_feature("test")
            .build();

        let json = serde_json::to_string_pretty(&env).unwrap();
        assert!(json.contains("rustcVersion"));
        assert!(json.contains("1.75.0"));
        assert!(json.contains("wasm32-wasip2"));

        // Roundtrip
        let parsed: BuildEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rustc_version, "1.75.0");
    }
}
