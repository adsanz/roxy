//! Configuration types for Roxy proxy.
//!
//! All types are pure data structures with serde derives.
//! No business logic belongs here.

use serde::Deserialize;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::ConfigError;

/// Root configuration structure.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Address to listen on (e.g., "0.0.0.0:8080")
    pub listen: String,

    /// TLS configuration for MITM
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Access control rules
    #[serde(default)]
    pub rules: Vec<RuleConfig>,

    /// Header manipulation rules
    #[serde(default)]
    pub headers: Vec<HeaderMangleConfig>,

    /// Global rate limit settings
    #[serde(default)]
    pub rate_limit: Option<GlobalRateLimitConfig>,
}

/// TLS/MITM configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Path to CA certificate file
    pub ca_cert: PathBuf,

    /// Path to CA private key file
    pub ca_key: PathBuf,

    /// Certificate cache size (default: 1000)
    #[serde(default = "default_cert_cache_size")]
    pub cert_cache_size: usize,
}

fn default_cert_cache_size() -> usize {
    1000
}

/// A single access control rule.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Unique name for the rule (used in logs and header mangle refs)
    pub name: String,

    /// Rule DSL expression (e.g., 'host("*.internal") && !header("X-Auth") = block')
    pub rule: String,
}

/// Header manipulation configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderMangleConfig {
    /// Rule names that trigger this header modification
    pub rules: Vec<String>,

    /// Headers to add
    #[serde(default)]
    pub add: Vec<HeaderAddConfig>,

    /// Header names to remove
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Header to add.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderAddConfig {
    /// Header name
    pub name: String,

    /// Header value
    pub value: String,
}

/// Global rate limit configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GlobalRateLimitConfig {
    /// Cleanup interval in seconds for expired entries
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_cleanup_interval() -> u64 {
    60
}

impl ProxyConfig {
    /// Load configuration from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        contents.parse()
    }

    /// Validate configuration consistency.
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate listen address format
        if self.listen.is_empty() {
            return Err(ConfigError::MissingField("listen".to_string()));
        }

        // Validate rule names are unique
        let mut seen_names = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.name.is_empty() {
                return Err(ConfigError::Invalid(
                    "Rule name cannot be empty".to_string(),
                ));
            }
            if !seen_names.insert(&rule.name) {
                return Err(ConfigError::Invalid(format!(
                    "Duplicate rule name: {}",
                    rule.name
                )));
            }
        }

        // Validate header mangle rule references exist
        for header_config in &self.headers {
            for rule_ref in &header_config.rules {
                if !seen_names.contains(rule_ref) {
                    return Err(ConfigError::Invalid(format!(
                        "Header config references unknown rule: {}",
                        rule_ref
                    )));
                }
            }
        }

        Ok(())
    }
}

impl FromStr for ProxyConfig {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: ProxyConfig = serde_yaml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
listen: "0.0.0.0:8080"
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080");
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_parse_full_config() {
        let yaml = r#"
listen: "0.0.0.0:8080"
tls:
  ca_cert: "/path/to/ca.crt"
  ca_key: "/path/to/ca.key"
rules:
  - name: "block-internal"
    rule: 'host("*.internal") = block'
  - name: "add-headers"
    rule: 'host("api.*") = mangle'
headers:
  - rules: ["add-headers"]
    add:
      - name: "X-Proxy"
        value: "roxy"
    remove:
      - "X-Internal"
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.headers.len(), 1);
        assert!(config.tls.is_some());
    }

    #[test]
    fn test_duplicate_rule_names_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "my-rule"
    rule: 'host("a.com") = block'
  - name: "my-rule"
    rule: 'host("b.com") = block'
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Duplicate rule name")
        );
    }

    #[test]
    fn test_invalid_header_rule_ref_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "my-rule"
    rule: 'host("a.com") = block'
headers:
  - rules: ["nonexistent-rule"]
    add:
      - name: "X-Test"
        value: "test"
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown rule"));
    }
}
