//! Unified error types for Roxy proxy.
//!
//! Errors propagate upward through layers:
//! - Lower layers define specific errors (ParseError, ConfigError)
//! - Proxy layer converts errors → HTTP status codes

use thiserror::Error;

/// Configuration loading and parsing errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadFile(#[source] std::io::Error),

    #[error("Failed to parse YAML: {0}")]
    ParseYaml(#[from] serde_yaml::Error),

    #[error("Invalid configuration: {0}")]
    Invalid(String),

    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Rule DSL parsing errors.
/// Each variant includes the rule name for easy identification in multi-rule configs.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Rule '{rule_name}': unexpected input at position {position} — expected {expected}, got '{actual}'")]
    UnexpectedToken {
        rule_name: String,
        position: usize,
        expected: String,
        actual: String,
    },

    #[error("Rule '{rule_name}': empty expression")]
    EmptyExpression { rule_name: String },

    #[error("Rule '{rule_name}': invalid glob pattern '{pattern}' — {reason}")]
    InvalidGlob {
        rule_name: String,
        pattern: String,
        reason: String,
    },

    #[error("Rule '{rule_name}': unknown HTTP method '{method}'")]
    InvalidMethod {
        rule_name: String,
        method: String,
    },

    #[error("Rule '{rule_name}': invalid action combination — {detail}")]
    InvalidActionCombination {
        rule_name: String,
        detail: String,
    },

    #[error("Rule '{rule_name}': {detail}")]
    InvalidValue {
        rule_name: String,
        detail: String,
    },

    #[error("Rule '{rule_name}': {detail}")]
    Other {
        rule_name: String,
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_messages() {
        let err = ParseError::InvalidGlob {
            rule_name: "block-internal".to_string(),
            pattern: "[invalid".to_string(),
            reason: "unclosed character class".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("block-internal"));
        assert!(msg.contains("[invalid"));
    }

    #[test]
    fn test_invalid_method_message() {
        let err = ParseError::InvalidMethod {
            rule_name: "my-rule".to_string(),
            method: "FOOBAR".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my-rule"));
        assert!(msg.contains("FOOBAR"));
    }

    #[test]
    fn test_invalid_action_combo_message() {
        let err = ParseError::InvalidActionCombination {
            rule_name: "test".to_string(),
            detail: "cannot combine 'block' with 'credit'".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("cannot combine"));
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::Invalid("test".to_string());
        assert!(err.to_string().contains("Invalid configuration"));
    }
}
