//! SLSA v1.0 Provenance predicate implementation
//!
//! Implements the SLSA Provenance predicate format.
//! See: https://slsa.dev/spec/v1.0/provenance
//!
//! SLSA Provenance describes how an artifact was built, including:
//! - Build inputs (external parameters, dependencies)
//! - Build platform (builder identity)
//! - Build metadata (timestamps, invocation ID)
//!
//! # Example
//!
//! ```ignore
//! use wsc::slsa::{Provenance, BuildDefinition, RunDetails, Builder};
//!
//! let provenance = Provenance {
//!     build_definition: BuildDefinition {
//!         build_type: "https://wsc.dev/WasmBuild/v1".to_string(),
//!         external_parameters: json!({"target": "wasm32-wasip2"}),
//!         internal_parameters: None,
//!         resolved_dependencies: vec![],
//!     },
//!     run_details: RunDetails {
//!         builder: Builder { id: "https://github.com/actions/runner".to_string(), .. },
//!         metadata: Some(BuildMetadata { invocation_id: Some("..."), .. }),
//!         byproducts: None,
//!     },
//! };
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::intoto::ResourceDescriptor;

/// SLSA Provenance v1.0 predicate type
pub const PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// SLSA Provenance v1.0 predicate
///
/// The top-level structure for SLSA provenance attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    /// Describes the build's inputs
    pub build_definition: BuildDefinition,

    /// Describes the build execution
    pub run_details: RunDetails,
}

impl Provenance {
    /// Create a new provenance with minimal required fields
    pub fn new(
        build_type: impl Into<String>,
        builder_id: impl Into<String>,
        external_parameters: serde_json::Value,
    ) -> Self {
        Self {
            build_definition: BuildDefinition {
                build_type: build_type.into(),
                external_parameters,
                internal_parameters: None,
                resolved_dependencies: vec![],
            },
            run_details: RunDetails {
                builder: Builder::new(builder_id),
                metadata: None,
                byproducts: None,
            },
        }
    }

    /// Create provenance for a WASM build
    pub fn wasm_build(
        target: &str,
        builder_id: impl Into<String>,
        dependencies: Vec<ResourceDescriptor>,
    ) -> Self {
        Self {
            build_definition: BuildDefinition {
                build_type: "https://wsc.dev/WasmBuild/v1".to_string(),
                external_parameters: serde_json::json!({
                    "target": target,
                }),
                internal_parameters: None,
                resolved_dependencies: dependencies,
            },
            run_details: RunDetails {
                builder: Builder::new(builder_id),
                metadata: Some(BuildMetadata::now()),
                byproducts: None,
            },
        }
    }

    /// Create provenance for a transformation (optimization, composition, etc.)
    pub fn transformation(
        transformation_type: &str,
        tool_name: &str,
        tool_version: &str,
        inputs: Vec<ResourceDescriptor>,
    ) -> Self {
        Self {
            build_definition: BuildDefinition {
                build_type: format!("https://wsc.dev/Transformation/{}/v1", transformation_type),
                external_parameters: serde_json::json!({
                    "tool": {
                        "name": tool_name,
                        "version": tool_version,
                    }
                }),
                internal_parameters: None,
                resolved_dependencies: inputs,
            },
            run_details: RunDetails {
                builder: Builder::new(format!("https://wsc.dev/tools/{}", tool_name)),
                metadata: Some(BuildMetadata::now()),
                byproducts: None,
            },
        }
    }

    /// Add a resolved dependency
    pub fn add_dependency(&mut self, dep: ResourceDescriptor) {
        self.build_definition.resolved_dependencies.push(dep);
    }

    /// Set internal parameters
    pub fn with_internal_parameters(mut self, params: serde_json::Value) -> Self {
        self.build_definition.internal_parameters = Some(params);
        self
    }

    /// Set build metadata
    pub fn with_metadata(mut self, metadata: BuildMetadata) -> Self {
        self.run_details.metadata = Some(metadata);
        self
    }

    /// Add byproducts
    pub fn with_byproducts(mut self, byproducts: Vec<ResourceDescriptor>) -> Self {
        self.run_details.byproducts = Some(byproducts);
        self
    }
}

/// Build definition - describes the build's inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDefinition {
    /// URI identifying the build type/template
    pub build_type: String,

    /// User-controlled build inputs (must be verified)
    pub external_parameters: serde_json::Value,

    /// Platform-controlled build settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_parameters: Option<serde_json::Value>,

    /// Artifacts fetched during the build
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

/// Run details - describes the build execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetails {
    /// The trusted build platform
    pub builder: Builder,

    /// Build execution metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BuildMetadata>,

    /// Additional artifacts produced (logs, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byproducts: Option<Vec<ResourceDescriptor>>,
}

/// Builder identity
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Builder {
    /// URI identifying the builder
    pub id: String,

    /// Builder version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<HashMap<String, String>>,

    /// Dependencies of the builder itself
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_dependencies: Option<Vec<ResourceDescriptor>>,
}

impl Builder {
    /// Create a new builder with just an ID
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: None,
            builder_dependencies: None,
        }
    }

    /// Create a GitHub Actions builder
    pub fn github_actions() -> Self {
        Self {
            id: "https://github.com/actions/runner".to_string(),
            version: None,
            builder_dependencies: None,
        }
    }

    /// Create a local development builder
    pub fn local() -> Self {
        Self {
            id: "https://wsc.dev/local-builder/v1".to_string(),
            version: None,
            builder_dependencies: None,
        }
    }

    /// Set builder version
    pub fn with_version(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.version
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value.into());
        self
    }
}

/// Build execution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildMetadata {
    /// Unique identifier for this build invocation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,

    /// Timestamp when the build started
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_on: Option<String>,

    /// Timestamp when the build finished
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_on: Option<String>,
}

impl BuildMetadata {
    /// Create empty metadata
    pub fn new() -> Self {
        Self {
            invocation_id: None,
            started_on: None,
            finished_on: None,
        }
    }

    /// Create metadata with current timestamp
    pub fn now() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            invocation_id: Some(uuid::Uuid::new_v4().to_string()),
            started_on: Some(now.clone()),
            finished_on: Some(now),
        }
    }

    /// Set invocation ID
    pub fn with_invocation_id(mut self, id: impl Into<String>) -> Self {
        self.invocation_id = Some(id.into());
        self
    }

    /// Set start timestamp
    pub fn with_started_on(mut self, ts: impl Into<String>) -> Self {
        self.started_on = Some(ts.into());
        self
    }

    /// Set finish timestamp
    pub fn with_finished_on(mut self, ts: impl Into<String>) -> Self {
        self.finished_on = Some(ts.into());
        self
    }
}

impl Default for BuildMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// SLSA verification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlsaLevel {
    /// No SLSA requirements
    #[serde(rename = "SLSA_BUILD_LEVEL_0")]
    L0 = 0,

    /// Provenance exists
    #[serde(rename = "SLSA_BUILD_LEVEL_1")]
    L1 = 1,

    /// Hosted build platform, signed provenance
    #[serde(rename = "SLSA_BUILD_LEVEL_2")]
    L2 = 2,

    /// Hardened build platform
    #[serde(rename = "SLSA_BUILD_LEVEL_3")]
    L3 = 3,
}

impl SlsaLevel {
    /// Get level as numeric value
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Create from numeric value
    pub fn from_u8(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::L0),
            1 => Some(Self::L1),
            2 => Some(Self::L2),
            3 => Some(Self::L3),
            _ => None,
        }
    }

    /// Display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::L0 => "SLSA Build L0",
            Self::L1 => "SLSA Build L1",
            Self::L2 => "SLSA Build L2",
            Self::L3 => "SLSA Build L3",
        }
    }
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Common build types
pub mod build_types {
    /// Generic WASM build
    pub const WASM_BUILD: &str = "https://wsc.dev/WasmBuild/v1";

    /// Cargo (Rust) build
    pub const CARGO_BUILD: &str = "https://wsc.dev/CargoBuild/v1";

    /// Bazel build
    pub const BAZEL_BUILD: &str = "https://wsc.dev/BazelBuild/v1";

    /// WASM optimization transformation
    pub const WASM_OPTIMIZATION: &str = "https://wsc.dev/Transformation/optimization/v1";

    /// WASM composition transformation
    pub const WASM_COMPOSITION: &str = "https://wsc.dev/Transformation/composition/v1";

    /// Generic transformation
    pub const TRANSFORMATION: &str = "https://wsc.dev/Transformation/v1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_provenance() {
        let prov = Provenance::new(
            build_types::WASM_BUILD,
            "https://github.com/actions/runner",
            serde_json::json!({"target": "wasm32-wasip2"}),
        );

        assert_eq!(prov.build_definition.build_type, build_types::WASM_BUILD);
        assert!(prov.build_definition.resolved_dependencies.is_empty());
    }

    #[test]
    fn test_wasm_build_provenance() {
        let deps = vec![
            ResourceDescriptor::new("pkg:cargo/serde@1.0", "abc123"),
        ];

        let prov = Provenance::wasm_build(
            "wasm32-wasip2",
            Builder::github_actions().id,
            deps,
        );

        assert!(prov.build_definition.build_type.contains("WasmBuild"));
        assert_eq!(prov.build_definition.resolved_dependencies.len(), 1);
        assert!(prov.run_details.metadata.is_some());
    }

    #[test]
    fn test_transformation_provenance() {
        let inputs = vec![
            ResourceDescriptor::from_name("input.wasm", "deadbeef"),
        ];

        let prov = Provenance::transformation(
            "optimization",
            "loom",
            "0.1.0",
            inputs,
        );

        assert!(prov.build_definition.build_type.contains("Transformation"));
        assert!(prov.build_definition.build_type.contains("optimization"));
        assert!(prov.run_details.builder.id.contains("loom"));
    }

    #[test]
    fn test_provenance_serialization() {
        let prov = Provenance::new(
            "https://example.com/build/v1",
            "https://example.com/builder",
            serde_json::json!({"key": "value"}),
        );

        let json = serde_json::to_string_pretty(&prov).unwrap();

        assert!(json.contains("buildDefinition"));
        assert!(json.contains("runDetails"));
        assert!(json.contains("externalParameters"));
        assert!(json.contains("builder"));

        // Roundtrip
        let parsed: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.build_definition.build_type, prov.build_definition.build_type);
    }

    #[test]
    fn test_builder_variants() {
        let gh = Builder::github_actions();
        assert!(gh.id.contains("github"));

        let local = Builder::local();
        assert!(local.id.contains("local"));

        let custom = Builder::new("https://my-builder.com")
            .with_version("runner", "2.0");
        assert_eq!(custom.version.as_ref().unwrap().get("runner"), Some(&"2.0".to_string()));
    }

    #[test]
    fn test_build_metadata() {
        let meta = BuildMetadata::now();

        assert!(meta.invocation_id.is_some());
        assert!(meta.started_on.is_some());
        assert!(meta.finished_on.is_some());
    }

    #[test]
    fn test_slsa_levels() {
        assert!(SlsaLevel::L3 > SlsaLevel::L2);
        assert!(SlsaLevel::L2 > SlsaLevel::L1);
        assert!(SlsaLevel::L1 > SlsaLevel::L0);

        assert_eq!(SlsaLevel::L2.as_u8(), 2);
        assert_eq!(SlsaLevel::from_u8(3), Some(SlsaLevel::L3));
        assert_eq!(SlsaLevel::from_u8(99), None);
    }

    #[test]
    fn test_add_dependency() {
        let mut prov = Provenance::new(
            "https://example.com/build",
            "https://builder.com",
            serde_json::json!({}),
        );

        assert!(prov.build_definition.resolved_dependencies.is_empty());

        prov.add_dependency(ResourceDescriptor::new("pkg:npm/lodash@4.0", "abc"));
        prov.add_dependency(ResourceDescriptor::new("pkg:npm/react@18.0", "def"));

        assert_eq!(prov.build_definition.resolved_dependencies.len(), 2);
    }

    #[test]
    fn test_fluent_api() {
        let prov = Provenance::new("https://build", "https://builder", serde_json::json!({}))
            .with_internal_parameters(serde_json::json!({"opt_level": 3}))
            .with_metadata(BuildMetadata::new().with_invocation_id("inv-123"))
            .with_byproducts(vec![ResourceDescriptor::from_name("build.log", "logsha")]);

        assert!(prov.build_definition.internal_parameters.is_some());
        assert_eq!(
            prov.run_details.metadata.as_ref().unwrap().invocation_id,
            Some("inv-123".to_string())
        );
        assert_eq!(prov.run_details.byproducts.as_ref().unwrap().len(), 1);
    }
}
