//! Rego policy language support via Regorus.
//!
//! This module provides optional Rego policy evaluation for power users who
//! need more expressive policies than TOML allows. It uses Regorus, Microsoft's
//! fast Rust implementation of the Open Policy Agent (OPA) Rego language.
//!
//! # Feature Flag
//!
//! This module requires the `rego` feature:
//!
//! ```toml
//! [dependencies]
//! wsc = { version = "0.5", features = ["rego"] }
//! ```
//!
//! # Example Rego Policy
//!
//! ```rego
//! package wsc.policy
//!
//! # Deny if SLSA level is below minimum
//! default allow := false
//!
//! allow {
//!     input.slsa_level >= data.config.minimum_slsa_level
//!     valid_signatures
//!     trusted_tool
//! }
//!
//! valid_signatures {
//!     input.attestation.signature.algorithm != "unsigned"
//! }
//!
//! trusted_tool {
//!     tool := input.attestation.tool.name
//!     data.trusted_tools[tool]
//! }
//!
//! # Violations for reporting
//! violations[msg] {
//!     input.slsa_level < data.config.minimum_slsa_level
//!     msg := sprintf("SLSA level %d below minimum %d", [input.slsa_level, data.config.minimum_slsa_level])
//! }
//!
//! violations[msg] {
//!     input.attestation.signature.algorithm == "unsigned"
//!     msg := "Attestation is not signed"
//! }
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use wsc::policy::rego::{RegoEngine, RegoInput};
//! use wsc::composition::TransformationAttestation;
//!
//! let mut engine = RegoEngine::new()?;
//! engine.add_policy_file("policy.rego")?;
//! engine.set_data_file("trusted_tools.json")?;
//!
//! let input = RegoInput::from_attestation(&attestation, slsa_level);
//! let result = engine.evaluate(&input)?;
//!
//! if result.allowed {
//!     println!("Policy passed");
//! } else {
//!     for violation in &result.violations {
//!         eprintln!("Violation: {}", violation);
//!     }
//! }
//! ```

use crate::error::WSError;
use serde::{Deserialize, Serialize};
use wsc_attestation::TransformationAttestation;

/// Rego policy evaluation engine.
///
/// Wraps Regorus to provide a simple interface for evaluating WSC
/// attestations against Rego policies.
pub struct RegoEngine {
    engine: regorus::Engine,
    policy_loaded: bool,
}

/// Input data for Rego policy evaluation.
///
/// This structure is serialized to JSON and passed to the Rego engine
/// as the `input` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegoInput {
    /// The transformation attestation being evaluated
    pub attestation: serde_json::Value,
    /// Detected SLSA level (0-4)
    pub slsa_level: u8,
    /// Current timestamp (ISO 8601)
    pub current_time: String,
    /// Optional additional context
    #[serde(default)]
    pub context: serde_json::Value,
}

/// Result of Rego policy evaluation.
#[derive(Debug, Clone, Default)]
pub struct RegoResult {
    /// Whether the policy allows the attestation
    pub allowed: bool,
    /// List of policy violations (from `violations` rule)
    pub violations: Vec<String>,
    /// List of warnings (from `warnings` rule)
    pub warnings: Vec<String>,
    /// Raw result value for advanced use
    pub raw: Option<serde_json::Value>,
}

/// Error type for Rego operations.
#[derive(Debug, Clone)]
pub enum RegoError {
    /// Failed to parse Rego policy
    ParseError(String),
    /// Failed to evaluate policy
    EvalError(String),
    /// Failed to serialize/deserialize data
    SerdeError(String),
    /// Failed to read file
    IoError(String),
    /// Policy not loaded
    NoPolicyLoaded,
}

impl std::fmt::Display for RegoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegoError::ParseError(msg) => write!(f, "Rego parse error: {}", msg),
            RegoError::EvalError(msg) => write!(f, "Rego evaluation error: {}", msg),
            RegoError::SerdeError(msg) => write!(f, "Rego serialization error: {}", msg),
            RegoError::IoError(msg) => write!(f, "Rego I/O error: {}", msg),
            RegoError::NoPolicyLoaded => write!(f, "No Rego policy loaded"),
        }
    }
}

impl std::error::Error for RegoError {}

impl From<RegoError> for WSError {
    fn from(e: RegoError) -> Self {
        WSError::InternalError(e.to_string())
    }
}

impl RegoEngine {
    /// Create a new Rego evaluation engine.
    pub fn new() -> Result<Self, RegoError> {
        let engine = regorus::Engine::new();
        Ok(Self {
            engine,
            policy_loaded: false,
        })
    }

    /// Add a Rego policy from a string.
    ///
    /// # Arguments
    ///
    /// * `name` - Policy name (used for error messages)
    /// * `policy` - Rego policy source code
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// engine.add_policy("main", r#"
    /// package wsc.policy
    /// default allow := false
    /// allow { input.slsa_level >= 2 }
    /// "#)?;
    /// ```
    pub fn add_policy(&mut self, name: &str, policy: &str) -> Result<(), RegoError> {
        self.engine
            .add_policy(name.to_string(), policy.to_string())
            .map_err(|e| RegoError::ParseError(e.to_string()))?;
        self.policy_loaded = true;
        Ok(())
    }

    /// Load a Rego policy from a file.
    pub fn add_policy_file(&mut self, path: &str) -> Result<(), RegoError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RegoError::IoError(format!("{}: {}", path, e)))?;
        self.add_policy(path, &content)
    }

    /// Set static data (the `data` document in Rego).
    ///
    /// This is typically used for trusted tools, configuration, etc.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// engine.set_data(serde_json::json!({
    ///     "config": {
    ///         "minimum_slsa_level": 2
    ///     },
    ///     "trusted_tools": {
    ///         "loom": true,
    ///         "wac": true
    ///     }
    /// }))?;
    /// ```
    pub fn set_data(&mut self, data: serde_json::Value) -> Result<(), RegoError> {
        let regorus_value = json_to_regorus(&data)?;
        self.engine
            .add_data(regorus_value)
            .map_err(|e| RegoError::EvalError(e.to_string()))?;
        Ok(())
    }

    /// Load data from a JSON file.
    pub fn set_data_file(&mut self, path: &str) -> Result<(), RegoError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RegoError::IoError(format!("{}: {}", path, e)))?;
        let data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| RegoError::SerdeError(e.to_string()))?;
        self.set_data(data)
    }

    /// Evaluate the policy against the given input.
    ///
    /// This evaluates the standard WSC policy rules:
    /// - `data.wsc.policy.allow` - main allow/deny decision
    /// - `data.wsc.policy.violations` - list of violation messages
    /// - `data.wsc.policy.warnings` - list of warning messages
    pub fn evaluate(&mut self, input: &RegoInput) -> Result<RegoResult, RegoError> {
        if !self.policy_loaded {
            return Err(RegoError::NoPolicyLoaded);
        }

        // Set input
        let input_json = serde_json::to_value(input)
            .map_err(|e| RegoError::SerdeError(e.to_string()))?;
        let input_regorus = json_to_regorus(&input_json)?;
        self.engine.set_input(input_regorus);

        let mut result = RegoResult::default();

        // Evaluate allow rule
        match self.engine.eval_rule("data.wsc.policy.allow".to_string()) {
            Ok(value) => {
                result.allowed = regorus_to_bool(&value);
                result.raw = Some(regorus_to_json(&value)?);
            }
            Err(_) => {
                // Try alternative package path
                match self.engine.eval_rule("data.policy.allow".to_string()) {
                    Ok(value) => {
                        result.allowed = regorus_to_bool(&value);
                        result.raw = Some(regorus_to_json(&value)?);
                    }
                    Err(_) => {
                        // No allow rule found - default to false
                        result.allowed = false;
                    }
                }
            }
        }

        // Evaluate violations rule
        if let Ok(value) = self.engine.eval_rule("data.wsc.policy.violations".to_string()) {
            result.violations = regorus_to_string_set(&value);
        } else if let Ok(value) = self.engine.eval_rule("data.policy.violations".to_string()) {
            result.violations = regorus_to_string_set(&value);
        }

        // Evaluate warnings rule
        if let Ok(value) = self.engine.eval_rule("data.wsc.policy.warnings".to_string()) {
            result.warnings = regorus_to_string_set(&value);
        } else if let Ok(value) = self.engine.eval_rule("data.policy.warnings".to_string()) {
            result.warnings = regorus_to_string_set(&value);
        }

        Ok(result)
    }

    /// Evaluate a custom rule and return the result.
    ///
    /// # Arguments
    ///
    /// * `rule` - Full rule path (e.g., "data.mypackage.myrule")
    pub fn eval_rule(&mut self, rule: &str) -> Result<serde_json::Value, RegoError> {
        if !self.policy_loaded {
            return Err(RegoError::NoPolicyLoaded);
        }

        let value = self
            .engine
            .eval_rule(rule.to_string())
            .map_err(|e| RegoError::EvalError(e.to_string()))?;
        regorus_to_json(&value)
    }
}

impl Default for RegoEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create Rego engine")
    }
}

impl RegoInput {
    /// Create input from a TransformationAttestation.
    ///
    /// # Arguments
    ///
    /// * `attestation` - The attestation to evaluate
    /// * `slsa_level` - Detected SLSA level (0-4)
    pub fn from_attestation(attestation: &TransformationAttestation, slsa_level: u8) -> Self {
        let attestation_json = serde_json::to_value(attestation)
            .unwrap_or(serde_json::Value::Null);

        Self {
            attestation: attestation_json,
            slsa_level,
            current_time: chrono::Utc::now().to_rfc3339(),
            context: serde_json::Value::Null,
        }
    }

    /// Add additional context to the input.
    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = context;
        self
    }
}

// ============================================================================
// Regorus Value Conversion Helpers
// ============================================================================

/// Convert serde_json::Value to regorus::Value
fn json_to_regorus(json: &serde_json::Value) -> Result<regorus::Value, RegoError> {
    match json {
        serde_json::Value::Null => Ok(regorus::Value::Null),
        serde_json::Value::Bool(b) => Ok(regorus::Value::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                // Use from_i64 for integers
                Ok(regorus::Value::from(i))
            } else if let Some(f) = n.as_f64() {
                // Use from_f64 for floats
                Ok(regorus::Value::from(f))
            } else {
                Err(RegoError::SerdeError("Invalid number".to_string()))
            }
        }
        serde_json::Value::String(s) => Ok(regorus::Value::String(s.clone().into())),
        serde_json::Value::Array(arr) => {
            let values: Result<Vec<_>, _> = arr.iter().map(json_to_regorus).collect();
            Ok(regorus::Value::from(values?))
        }
        serde_json::Value::Object(obj) => {
            let mut map = regorus::Value::new_object();
            for (k, v) in obj {
                let key = regorus::Value::String(k.clone().into());
                let value = json_to_regorus(v)?;
                if let Ok(obj_map) = map.as_object_mut() {
                    obj_map.insert(key, value);
                } else {
                    return Err(RegoError::SerdeError("Failed to create object".to_string()));
                }
            }
            Ok(map)
        }
    }
}

/// Convert regorus::Value to serde_json::Value
fn regorus_to_json(value: &regorus::Value) -> Result<serde_json::Value, RegoError> {
    match value {
        regorus::Value::Null | regorus::Value::Undefined => Ok(serde_json::Value::Null),
        regorus::Value::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        regorus::Value::String(s) => Ok(serde_json::Value::String(s.to_string())),
        regorus::Value::Number(n) => {
            // regorus Number can be i64 or f64
            if let Some(f) = n.as_f64() {
                let json_num = serde_json::Number::from_f64(f)
                    .ok_or_else(|| RegoError::SerdeError("Invalid number conversion".to_string()))?;
                Ok(serde_json::Value::Number(json_num))
            } else if let Some(i) = n.as_i64() {
                Ok(serde_json::Value::Number(i.into()))
            } else {
                Err(RegoError::SerdeError("Invalid number".to_string()))
            }
        }
        regorus::Value::Array(arr) => {
            let values: Result<Vec<_>, _> = arr.iter().map(regorus_to_json).collect();
            Ok(serde_json::Value::Array(values?))
        }
        regorus::Value::Set(set) => {
            let values: Result<Vec<_>, _> = set.iter().map(regorus_to_json).collect();
            Ok(serde_json::Value::Array(values?))
        }
        regorus::Value::Object(obj) => {
            let mut map = serde_json::Map::new();
            for (k, v) in obj.iter() {
                let key = match k {
                    regorus::Value::String(s) => s.to_string(),
                    _ => k.to_string(),
                };
                map.insert(key, regorus_to_json(v)?);
            }
            Ok(serde_json::Value::Object(map))
        }
    }
}

/// Extract boolean from regorus::Value
fn regorus_to_bool(value: &regorus::Value) -> bool {
    match value {
        regorus::Value::Bool(b) => *b,
        regorus::Value::Set(s) if s.len() == 1 => {
            // Single-element set containing bool
            s.iter().next().map(regorus_to_bool).unwrap_or(false)
        }
        _ => false,
    }
}

/// Extract string set from regorus::Value (for violations/warnings)
fn regorus_to_string_set(value: &regorus::Value) -> Vec<String> {
    match value {
        regorus::Value::Set(set) => {
            set.iter()
                .filter_map(|v| match v {
                    regorus::Value::String(s) => Some(s.to_string()),
                    _ => Some(v.to_string()),
                })
                .collect()
        }
        regorus::Value::Array(arr) => {
            arr.iter()
                .filter_map(|v| match v {
                    regorus::Value::String(s) => Some(s.to_string()),
                    _ => Some(v.to_string()),
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = RegoEngine::new();
        assert!(engine.is_ok());
    }

    #[test]
    fn test_simple_policy() {
        let mut engine = RegoEngine::new().unwrap();

        let policy = r#"
            package wsc.policy

            default allow := false

            allow {
                input.slsa_level >= 2
            }

            violations[msg] {
                input.slsa_level < 2
                msg := sprintf("SLSA level %d is below minimum 2", [input.slsa_level])
            }
        "#;

        engine.add_policy("test.rego", policy).unwrap();

        // Test with SLSA L3 - should pass
        let input = RegoInput {
            attestation: serde_json::json!({}),
            slsa_level: 3,
            current_time: "2025-01-01T00:00:00Z".to_string(),
            context: serde_json::Value::Null,
        };

        let result = engine.evaluate(&input).unwrap();
        assert!(result.allowed);
        assert!(result.violations.is_empty());

        // Test with SLSA L1 - should fail
        let input = RegoInput {
            attestation: serde_json::json!({}),
            slsa_level: 1,
            current_time: "2025-01-01T00:00:00Z".to_string(),
            context: serde_json::Value::Null,
        };

        let result = engine.evaluate(&input).unwrap();
        assert!(!result.allowed);
        assert!(!result.violations.is_empty());
    }

    #[test]
    fn test_policy_with_data() {
        let mut engine = RegoEngine::new().unwrap();

        let policy = r#"
            package wsc.policy

            default allow := false

            allow {
                input.attestation.tool.name == tool_name
                data.trusted_tools[tool_name]
            }
        "#;

        engine.add_policy("test.rego", policy).unwrap();
        engine.set_data(serde_json::json!({
            "trusted_tools": {
                "loom": true,
                "wac": true
            }
        })).unwrap();

        // Test with trusted tool
        let input = RegoInput {
            attestation: serde_json::json!({
                "tool": { "name": "loom" }
            }),
            slsa_level: 2,
            current_time: "2025-01-01T00:00:00Z".to_string(),
            context: serde_json::Value::Null,
        };

        let result = engine.evaluate(&input).unwrap();
        assert!(result.allowed);

        // Test with untrusted tool
        let input = RegoInput {
            attestation: serde_json::json!({
                "tool": { "name": "malicious-tool" }
            }),
            slsa_level: 2,
            current_time: "2025-01-01T00:00:00Z".to_string(),
            context: serde_json::Value::Null,
        };

        let result = engine.evaluate(&input).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn test_no_policy_loaded() {
        let mut engine = RegoEngine::new().unwrap();
        let input = RegoInput {
            attestation: serde_json::json!({}),
            slsa_level: 2,
            current_time: "2025-01-01T00:00:00Z".to_string(),
            context: serde_json::Value::Null,
        };

        let result = engine.evaluate(&input);
        assert!(matches!(result, Err(RegoError::NoPolicyLoaded)));
    }

    #[test]
    fn test_json_conversion() {
        let json = serde_json::json!({
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": true,
            "null": null,
            "array": [1, 2, 3],
            "object": { "nested": "value" }
        });

        let regorus = json_to_regorus(&json).unwrap();
        let back = regorus_to_json(&regorus).unwrap();

        // Numbers might lose precision, but structure should match
        assert_eq!(back["string"], json["string"]);
        assert_eq!(back["bool"], json["bool"]);
        assert!(back["null"].is_null());
    }
}
