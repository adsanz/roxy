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

    /// Connection pool settings
    #[serde(default)]
    pub pool: Option<PoolConfig>,

    /// Throttle settings for rate_limit and credit rules (soft/hard limits)
    #[serde(default)]
    pub throttle: Vec<ThrottleConfig>,

    /// Credit system settings
    #[serde(default)]
    pub credits: Vec<CreditConfig>,
}

/// Connection pool configuration.
///
/// Controls how many idle connections the proxy keeps to upstream servers.
/// Limiting pool size prevents unbounded memory growth and mitigates DoS attacks.
#[derive(Debug, Clone, Deserialize)]
pub struct PoolConfig {
    /// Maximum idle connections per host (default: 10)
    #[serde(default = "default_pool_max_idle_per_host")]
    pub max_idle_per_host: usize,

    /// Idle connection timeout in seconds (default: 30)
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: default_pool_max_idle_per_host(),
            idle_timeout_secs: default_pool_idle_timeout_secs(),
        }
    }
}

fn default_pool_max_idle_per_host() -> usize {
    10
}

fn default_pool_idle_timeout_secs() -> u64 {
    30
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

/// Throttle configuration for rate_limit or credit rules.
///
/// Adds progressive delay (soft limit) before the hard limit kicks in.
/// The hard limit is the value defined in the DSL (e.g., 100/s for rate_limit).
#[derive(Debug, Clone, Deserialize)]
pub struct ThrottleConfig {
    /// Rule name this throttle config applies to
    pub rule: String,

    /// Request count at which progressive delay starts.
    /// Delay increases linearly from 0ms at soft_limit to max_delay_ms at hard limit.
    pub soft_limit: u64,

    /// Maximum delay in milliseconds applied when approaching the hard limit (default: 2000)
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,
}

fn default_max_delay_ms() -> u64 {
    2000
}

/// Credit system configuration for credit rules.
///
/// Credits are a fixed budget that resets on a schedule (daily/weekly/monthly).
/// Unlike rate_limit (sliding window), credits are a simple decrementing counter.
#[derive(Debug, Clone, Deserialize)]
pub struct CreditConfig {
    /// Rule name this credit config applies to
    pub rule: String,

    /// Request count at which progressive delay starts (optional)
    pub soft_limit: Option<u64>,

    /// Maximum delay in milliseconds applied when approaching the hard limit (default: 2000)
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,

    /// Reset schedule in format: "daily@HH:MM", "weekly@Day-HH:MM", "monthly@DD-HH:MM"
    /// Times are in UTC.
    pub reset_schedule: String,

    /// Custom message returned when credits are exhausted.
    /// Use {reset_time} to interpolate the next reset datetime.
    #[serde(default = "default_credit_message")]
    pub message: String,
}

fn default_credit_message() -> String {
    "Request credit exhausted until {reset_time}".to_string()
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

        // Validate throttle config references exist
        for throttle in &self.throttle {
            if !seen_names.contains(&throttle.rule) {
                return Err(ConfigError::Invalid(format!(
                    "Throttle config references unknown rule: {}",
                    throttle.rule
                )));
            }
        }

        // Validate credit config references and reset_schedule format
        for credit in &self.credits {
            if !seen_names.contains(&credit.rule) {
                return Err(ConfigError::Invalid(format!(
                    "Credit config references unknown rule: {}",
                    credit.rule
                )));
            }
            // Validate reset_schedule by attempting to parse it
            if let Err(e) = crate::ratelimit::ResetSchedule::parse(&credit.reset_schedule) {
                return Err(ConfigError::Invalid(format!(
                    "Credit '{}' has invalid reset_schedule: {}",
                    credit.rule, e
                )));
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

    #[test]
    fn test_throttle_config_valid() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-rate"
    rule: 'host("api.*") = rate_limit(100/s, header(X-Key))'
throttle:
  - rule: "api-rate"
    soft_limit: 80
    max_delay_ms: 1500
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert_eq!(config.throttle.len(), 1);
        assert_eq!(config.throttle[0].soft_limit, 80);
        assert_eq!(config.throttle[0].max_delay_ms, 1500);
    }

    #[test]
    fn test_throttle_invalid_rule_ref_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "my-rule"
    rule: 'host("a.com") = block'
throttle:
  - rule: "nonexistent"
    soft_limit: 50
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown rule"));
    }

    #[test]
    fn test_credit_config_valid() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-credit"
    rule: 'host("api.*") = credit(1000/d, header(X-Key))'
credits:
  - rule: "api-credit"
    soft_limit: 800
    reset_schedule: "daily@00:00"
    message: "Credits exhausted until {reset_time}"
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert_eq!(config.credits.len(), 1);
        assert_eq!(config.credits[0].soft_limit, Some(800));
    }

    #[test]
    fn test_credit_invalid_schedule_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-credit"
    rule: 'host("api.*") = credit(1000/d, header(X-Key))'
credits:
  - rule: "api-credit"
    reset_schedule: "hourly@00:00"
    message: "out of credits"
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown period"));
    }

    #[test]
    fn test_credit_invalid_rule_ref_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "my-rule"
    rule: 'host("a.com") = block'
credits:
  - rule: "nonexistent"
    reset_schedule: "daily@12:00"
    message: "out"
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown rule"));
    }

    #[test]
    fn test_credit_weekly_schedule_valid() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-credit"
    rule: 'host("api.*") = credit(5000/w, header(X-Key))'
credits:
  - rule: "api-credit"
    reset_schedule: "weekly@Mon-09:00"
    message: "out"
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert_eq!(config.credits[0].reset_schedule, "weekly@Mon-09:00");
    }

    #[test]
    fn test_credit_monthly_schedule_valid() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-credit"
    rule: 'host("api.*") = credit(50000/M, header(X-Key))'
credits:
  - rule: "api-credit"
    reset_schedule: "monthly@01-00:00"
    message: "out"
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert_eq!(config.credits[0].reset_schedule, "monthly@01-00:00");
    }
}
