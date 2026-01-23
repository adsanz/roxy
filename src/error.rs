//! Unified error types for Roxy proxy.
//!
//! Errors propagate upward through layers:
//! - Lower layers define specific errors (ParseError, ConfigError)
//! - Domain layer adds semantic meaning (RuleError)
//! - Proxy layer converts RoxyError → HTTP status codes

use thiserror::Error;

/// Top-level error type for Roxy.
/// Used at module boundaries and in the proxy layer.
/// 
/// NOTE: Currently handlers return Hudsucker errors directly.
/// This type is designed for future unified error handling.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum RoxyError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Rule error: {0}")]
    Rule(#[from] RuleError),

    #[error("Rate limit error: {0}")]
    RateLimit(#[from] RateLimitError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

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
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Unexpected token at position {position}: expected {expected}, got '{actual}'")]
    UnexpectedToken {
        position: usize,
        expected: String,
        actual: String,
    },

    #[error("Empty expression")]
    EmptyExpression,

    #[error("Parse error: {0}")]
    Nom(String),
}

/// Rule evaluation errors (semantic, not syntax).
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum RuleError {
    #[error("Request blocked by rule: {rule_name}")]
    Blocked { rule_name: String },
}

/// Rate limiting errors.
#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Failed to extract rate limit key: {0}")]
    KeyExtraction(String),
}

#[allow(dead_code)]
impl RoxyError {
    /// Convert error to HTTP status code for response.
    /// This is the single point where errors become HTTP semantics.
    pub fn status_code(&self) -> u16 {
        match self {
            RoxyError::Config(_) => 500,
            RoxyError::Rule(RuleError::Blocked { .. }) => 403,
            RoxyError::RateLimit(_) => 429,
            RoxyError::Io(_) => 502,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_rule_returns_403() {
        let err = RoxyError::Rule(RuleError::Blocked {
            rule_name: "test-rule".to_string(),
        });
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn test_rate_limit_returns_429() {
        let err = RoxyError::RateLimit(RateLimitError::KeyExtraction("test".to_string()));
        assert_eq!(err.status_code(), 429);
    }

    #[test]
    fn test_config_error_returns_500() {
        let err = RoxyError::Config(ConfigError::Invalid("test".to_string()));
        assert_eq!(err.status_code(), 500);
    }
}
