//! Configuration types for Roxy proxy.
//!
//! All types are pure data structures with serde derives.
//! No business logic belongs here.

use serde::Deserialize;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::ConfigError;

/// Maximum allowed value for max_delay_ms in throttle/credit configs.
/// Caps how long a request can be held sleeping, limiting connection exhaustion.
const MAX_THROTTLE_DELAY_MS: u64 = 60_000;

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

    /// Inbound server timeout settings (HTTP/1 header read, HTTP/2 keep-alive, etc.).
    /// NOT hot-reloadable: server timeouts are baked into the listener at startup;
    /// changes require a restart.
    #[serde(default)]
    pub server_timeouts: Option<ServerTimeoutConfig>,

    /// Optional runtime metrics. Periodically logs tokio's `num_alive_tasks`
    /// alongside the inbound connection count, useful for confirming that
    /// connection leak fixes are taking effect.
    /// NOT hot-reloadable: spawned at startup.
    #[serde(default)]
    pub runtime_metrics: Option<RuntimeMetricsConfig>,

    /// Throttle settings for rate_limit and credit rules (soft/hard limits)
    #[serde(default)]
    pub throttle: Vec<ThrottleConfig>,

    /// Credit system settings
    #[serde(default)]
    pub credits: Vec<CreditConfig>,

    /// Hot reload check interval in seconds (default: 5, 0 = disabled).
    /// When enabled, the proxy periodically checks for config file changes
    /// and reloads rules, headers, and throttle config without restarting.
    /// Credit and rate limit state is preserved across reloads.
    #[serde(default = "default_reload_interval_secs")]
    pub reload_interval_secs: u64,

    /// Skip TLS certificate verification for upstream servers (default: false).
    /// When true, the proxy accepts any upstream certificate including self-signed.
    /// WARNING: This disables all upstream TLS security. Use only in trusted networks.
    #[serde(default)]
    pub unsafe_skip_verify: bool,

    /// Kernel-level TCP keep-alive settings applied to the listening socket
    /// (inherited by every accepted client connection on Linux). Tuning these
    /// is the only OS-level lever for detecting dead peers when the application
    /// protocol is silent. Note: it does NOT bound the lifetime of a healthy
    /// idle connection because live peers ACK the probes — see
    /// `docs/hudsucker-gaps.md` Gap #5.
    /// NOT hot-reloadable: socket options are set at startup.
    #[serde(default)]
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,
}

fn default_reload_interval_secs() -> u64 {
    5
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

    /// HTTP/2 keep-alive PING interval in seconds (default: 20, 0 = disabled).
    /// Detects dead upstream peers on pooled h2 connections. Without this,
    /// pooled h2 connections to silently-dead upstreams accumulate until
    /// idle_timeout_secs elapses (which only triggers when truly idle).
    #[serde(default = "default_http2_keep_alive_interval_secs")]
    pub http2_keep_alive_interval_secs: u64,

    /// HTTP/2 keep-alive PING timeout in seconds (default: 10).
    /// If a PING is not ACK'd within this window, the connection is closed.
    #[serde(default = "default_http2_keep_alive_timeout_secs")]
    pub http2_keep_alive_timeout_secs: u64,

    /// Send HTTP/2 keep-alive PINGs even on idle connections (default: true).
    #[serde(default = "default_http2_keep_alive_while_idle")]
    pub http2_keep_alive_while_idle: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: default_pool_max_idle_per_host(),
            idle_timeout_secs: default_pool_idle_timeout_secs(),
            http2_keep_alive_interval_secs: default_http2_keep_alive_interval_secs(),
            http2_keep_alive_timeout_secs: default_http2_keep_alive_timeout_secs(),
            http2_keep_alive_while_idle: default_http2_keep_alive_while_idle(),
        }
    }
}

fn default_pool_max_idle_per_host() -> usize {
    10
}

fn default_pool_idle_timeout_secs() -> u64 {
    30
}

fn default_http2_keep_alive_interval_secs() -> u64 {
    20
}

fn default_http2_keep_alive_timeout_secs() -> u64 {
    10
}

fn default_http2_keep_alive_while_idle() -> bool {
    true
}

/// Inbound server timeout configuration.
///
/// Mitigates connection leaks where clients keep sockets open without
/// completing protocol exchanges. NOT hot-reloadable — changes require restart.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerTimeoutConfig {
    /// HTTP/1 header-read timeout in seconds (default: 15, 0 = disabled).
    /// Kills slow-loris connections that open a socket and send headers
    /// extremely slowly or never.
    #[serde(default = "default_http1_header_read_timeout_secs")]
    pub http1_header_read_timeout_secs: u64,

    /// HTTP/2 server-side keep-alive PING interval in seconds (default: 20, 0 = disabled).
    /// Detects dead h2 clients whose TCP socket is still established but whose
    /// HTTP/2 peer no longer ACKs PINGs. Healthy idle peers will ACK forever;
    /// use `max_connection_age_secs` to bound that echo-chamber case.
    #[serde(default = "default_server_http2_keep_alive_interval_secs")]
    pub http2_keep_alive_interval_secs: u64,

    /// HTTP/2 server-side keep-alive PING timeout in seconds (default: 10).
    /// Only meaningful when `http2_keep_alive_interval_secs > 0`. Must be
    /// strictly less than the interval.
    #[serde(default = "default_http2_keep_alive_timeout_secs")]
    pub http2_keep_alive_timeout_secs: u64,

    /// HTTP/2 maximum concurrent streams per connection (default: 256, 0 = unbounded).
    /// Bounds memory amplification when a single connection multiplexes many streams.
    #[serde(default = "default_http2_max_concurrent_streams")]
    pub http2_max_concurrent_streams: u32,

    /// Hard maximum age for each inbound accepted connection in seconds
    /// (default: 1800, 0 = disabled). Enforced by Roxy's vendored hudsucker
    /// proxy path. When reached, roxy starts hyper graceful shutdown, then
    /// force-closes after `max_connection_age_grace_secs` if the peer has not
    /// drained. This bounds healthy idle h2 connections that ACK all PINGs.
    #[serde(default = "default_max_connection_age_secs")]
    pub max_connection_age_secs: u64,

    /// Grace window after max connection age before force-close (default: 30).
    /// Must be > 0 when max_connection_age_secs > 0.
    #[serde(default = "default_max_connection_age_grace_secs")]
    pub max_connection_age_grace_secs: u64,

    /// Timeout for reading the first bytes after CONNECT upgrade (default: 15,
    /// 0 = disabled). Closes clients that send CONNECT then never send the TLS
    /// ClientHello / tunnel payload.
    #[serde(default = "default_connect_initial_read_timeout_secs")]
    pub connect_initial_read_timeout_secs: u64,

    /// Timeout for the MITM TLS server handshake after CONNECT (default: 15,
    /// 0 = disabled). Closes partial ClientHello / stalled TLS handshakes.
    #[serde(default = "default_tls_handshake_timeout_secs")]
    pub tls_handshake_timeout_secs: u64,
}

impl Default for ServerTimeoutConfig {
    fn default() -> Self {
        Self {
            http1_header_read_timeout_secs: default_http1_header_read_timeout_secs(),
            http2_keep_alive_interval_secs: default_server_http2_keep_alive_interval_secs(),
            http2_keep_alive_timeout_secs: default_http2_keep_alive_timeout_secs(),
            http2_max_concurrent_streams: default_http2_max_concurrent_streams(),
            max_connection_age_secs: default_max_connection_age_secs(),
            max_connection_age_grace_secs: default_max_connection_age_grace_secs(),
            connect_initial_read_timeout_secs: default_connect_initial_read_timeout_secs(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout_secs(),
        }
    }
}

fn default_http1_header_read_timeout_secs() -> u64 {
    15
}

fn default_server_http2_keep_alive_interval_secs() -> u64 {
    20
}

fn default_http2_max_concurrent_streams() -> u32 {
    256
}

fn default_max_connection_age_secs() -> u64 {
    30 * 60
}

fn default_max_connection_age_grace_secs() -> u64 {
    30
}

fn default_connect_initial_read_timeout_secs() -> u64 {
    15
}

fn default_tls_handshake_timeout_secs() -> u64 {
    15
}

/// Kernel TCP keep-alive configuration for the listening socket.
///
/// All time values are in seconds. Applied via `socket2::TcpKeepalive` on the
/// bind socket; Linux inherits these onto every accepted connection.
///
/// Defaults (`time_secs=60`, `interval_secs=30`, `retries=4`) give roughly
/// `60 + 4*30 = 180s` worst-case dead-peer detection — gentle enough to avoid
/// the constant 15s/15s control-plane chatter the previous hardcoded values
/// produced, while still detecting truly dead peers within ~3 minutes.
#[derive(Debug, Clone, Deserialize)]
pub struct TcpKeepaliveConfig {
    /// Enable SO_KEEPALIVE on the listening socket (default: true).
    #[serde(default = "default_tcp_keepalive_enabled")]
    pub enabled: bool,

    /// Idle seconds before the first keep-alive probe is sent (default: 60).
    /// Maps to `TCP_KEEPIDLE`. Must be > 0 when `enabled = true`.
    #[serde(default = "default_tcp_keepalive_time_secs")]
    pub time_secs: u64,

    /// Seconds between successive keep-alive probes (default: 30).
    /// Maps to `TCP_KEEPINTVL`. Must be > 0 when `enabled = true`.
    #[serde(default = "default_tcp_keepalive_interval_secs")]
    pub interval_secs: u64,

    /// Number of unacknowledged probes before declaring the peer dead
    /// (default: 4, Linux-only — maps to `TCP_KEEPCNT`). On non-Linux this
    /// field is parsed but ignored.
    #[serde(default = "default_tcp_keepalive_retries")]
    pub retries: u32,
}

impl Default for TcpKeepaliveConfig {
    fn default() -> Self {
        Self {
            enabled: default_tcp_keepalive_enabled(),
            time_secs: default_tcp_keepalive_time_secs(),
            interval_secs: default_tcp_keepalive_interval_secs(),
            retries: default_tcp_keepalive_retries(),
        }
    }
}

fn default_tcp_keepalive_enabled() -> bool {
    true
}
fn default_tcp_keepalive_time_secs() -> u64 {
    60
}
fn default_tcp_keepalive_interval_secs() -> u64 {
    30
}
fn default_tcp_keepalive_retries() -> u32 {
    4
}

/// Optional runtime metrics configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeMetricsConfig {
    /// Interval in seconds between metric log emissions (0 = disabled).
    #[serde(default)]
    pub interval_secs: u64,
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
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleConfig {
    /// Unique name for the rule (used in logs and header mangle refs)
    pub name: String,

    /// Rule DSL expression (e.g., 'host("*.internal") && !header("X-Auth") = block')
    pub rule: String,

    /// Optional per-rule log level for user-facing `proxy`-target events
    /// (`forward`, `block`, `rate_limited`, `credit_exhausted`).
    /// Allowed values (case-insensitive): `trace`, `debug`, `info`, `warn`, `error`, `off`.
    /// Defaults to `info` when omitted.
    /// Does NOT affect internal `debug!(target: "rules", ...)` traces for `pass`/`mangle`.
    #[serde(default)]
    pub log_level: Option<String>,
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
        // Validate listen address is a valid SocketAddr
        if self.listen.is_empty() {
            return Err(ConfigError::MissingField("listen".to_string()));
        }
        self.listen.parse::<std::net::SocketAddr>().map_err(|e| {
            ConfigError::Invalid(format!("Invalid listen address '{}': {}", self.listen, e))
        })?;

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
            if let Some(ref lvl) = rule.log_level
                && !matches!(
                    lvl.to_ascii_lowercase().as_str(),
                    "trace" | "debug" | "info" | "warn" | "error" | "off"
                )
            {
                return Err(ConfigError::Invalid(format!(
                    "Rule '{}': invalid log_level '{}' (expected one of: trace, debug, info, warn, error, off)",
                    rule.name, lvl
                )));
            }
        }

        // Validate header mangle rule references exist and header names/values are valid HTTP
        for header_config in &self.headers {
            for rule_ref in &header_config.rules {
                if !seen_names.contains(rule_ref) {
                    return Err(ConfigError::Invalid(format!(
                        "Header config references unknown rule: {}",
                        rule_ref
                    )));
                }
            }
            for add in &header_config.add {
                add.name.parse::<http::HeaderName>().map_err(|e| {
                    ConfigError::Invalid(format!("Invalid header name '{}': {}", add.name, e))
                })?;
                add.value.parse::<http::HeaderValue>().map_err(|e| {
                    ConfigError::Invalid(format!("Invalid header value for '{}': {}", add.name, e))
                })?;
            }
            for remove_name in &header_config.remove {
                remove_name.parse::<http::HeaderName>().map_err(|e| {
                    ConfigError::Invalid(format!(
                        "Invalid header name to remove '{}': {}",
                        remove_name, e
                    ))
                })?;
            }
        }

        // Validate throttle config references exist, uniqueness, and max_delay_ms cap
        let mut seen_throttle_rules = std::collections::HashSet::new();
        for throttle in &self.throttle {
            if !seen_names.contains(&throttle.rule) {
                return Err(ConfigError::Invalid(format!(
                    "Throttle config references unknown rule: {}",
                    throttle.rule
                )));
            }
            if !seen_throttle_rules.insert(&throttle.rule) {
                return Err(ConfigError::Invalid(format!(
                    "Duplicate throttle config for rule: {}",
                    throttle.rule
                )));
            }
            if throttle.max_delay_ms > MAX_THROTTLE_DELAY_MS {
                return Err(ConfigError::Invalid(format!(
                    "Throttle '{}': max_delay_ms ({}) exceeds maximum allowed value ({}ms) you can rebuild with MAX_THROTTLE_DELAY_MS set higher if you need longer delays",
                    throttle.rule, throttle.max_delay_ms, MAX_THROTTLE_DELAY_MS
                )));
            }
        }

        // Validate connection/timeout configs to reject poisoned settings.
        if let Some(st) = &self.server_timeouts {
            if st.http2_keep_alive_interval_secs > 0
                && st.http2_keep_alive_timeout_secs >= st.http2_keep_alive_interval_secs
            {
                return Err(ConfigError::Invalid(format!(
                    "server_timeouts.http2_keep_alive_timeout_secs ({}) must be strictly less than http2_keep_alive_interval_secs ({})",
                    st.http2_keep_alive_timeout_secs, st.http2_keep_alive_interval_secs
                )));
            }
            if st.http2_keep_alive_interval_secs > 0 && st.http2_keep_alive_timeout_secs == 0 {
                return Err(ConfigError::Invalid(
                    "server_timeouts.http2_keep_alive_timeout_secs must be > 0 when http2_keep_alive_interval_secs > 0"
                        .to_string(),
                ));
            }
            if st.max_connection_age_secs > 0 && st.max_connection_age_grace_secs == 0 {
                return Err(ConfigError::Invalid(
                    "server_timeouts.max_connection_age_grace_secs must be > 0 when max_connection_age_secs > 0"
                        .to_string(),
                ));
            }
            if st.max_connection_age_secs > 0
                && st.max_connection_age_grace_secs >= st.max_connection_age_secs
            {
                return Err(ConfigError::Invalid(format!(
                    "server_timeouts.max_connection_age_grace_secs ({}) must be less than max_connection_age_secs ({})",
                    st.max_connection_age_grace_secs, st.max_connection_age_secs
                )));
            }
            if st.http2_keep_alive_interval_secs > 0 && st.max_connection_age_secs == 0 {
                tracing::warn!(
                    target: "proxy",
                    interval_secs = st.http2_keep_alive_interval_secs,
                    "server_timeouts.http2_keep_alive_interval_secs > 0 while max_connection_age_secs = 0: \
                     healthy idle h2 clients can ACK PINGs forever and hold sockets open indefinitely. \
                     Set max_connection_age_secs to bound connection lifetime."
                );
            }
        }
        if let Some(p) = &self.pool {
            if p.http2_keep_alive_interval_secs > 0
                && p.http2_keep_alive_timeout_secs >= p.http2_keep_alive_interval_secs
            {
                return Err(ConfigError::Invalid(format!(
                    "pool.http2_keep_alive_timeout_secs ({}) must be strictly less than http2_keep_alive_interval_secs ({})",
                    p.http2_keep_alive_timeout_secs, p.http2_keep_alive_interval_secs
                )));
            }
            if p.http2_keep_alive_interval_secs > 0 && p.http2_keep_alive_timeout_secs == 0 {
                return Err(ConfigError::Invalid(
                    "pool.http2_keep_alive_timeout_secs must be > 0 when http2_keep_alive_interval_secs > 0"
                        .to_string(),
                ));
            }
        }
        if let Some(k) = &self.tcp_keepalive
            && k.enabled
        {
            if k.time_secs == 0 {
                return Err(ConfigError::Invalid(
                    "tcp_keepalive.time_secs must be > 0 when enabled = true (set enabled: false to disable SO_KEEPALIVE)"
                        .to_string(),
                ));
            }
            if k.interval_secs == 0 {
                return Err(ConfigError::Invalid(
                    "tcp_keepalive.interval_secs must be > 0 when enabled = true".to_string(),
                ));
            }
        }

        // Validate credit config references, uniqueness, reset_schedule format, and max_delay_ms cap
        let mut seen_credit_rules = std::collections::HashSet::new();
        for credit in &self.credits {
            if !seen_names.contains(&credit.rule) {
                return Err(ConfigError::Invalid(format!(
                    "Credit config references unknown rule: {}",
                    credit.rule
                )));
            }
            if !seen_credit_rules.insert(&credit.rule) {
                return Err(ConfigError::Invalid(format!(
                    "Duplicate credit config for rule: {}",
                    credit.rule
                )));
            }
            if credit.max_delay_ms > MAX_THROTTLE_DELAY_MS {
                return Err(ConfigError::Invalid(format!(
                    "Credit '{}': max_delay_ms ({}) exceeds maximum allowed value ({}ms); you can rebuild with MAX_THROTTLE_DELAY_MS set higher if you need longer delays",
                    credit.rule, credit.max_delay_ms, MAX_THROTTLE_DELAY_MS
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
        let config: ProxyConfig = serde_yml::from_str(s)?;
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
    fn test_server_h2_keep_alive_default_enabled_with_max_age() {
        // h2 PING remains enabled for dead-peer detection; max age bounds echo chambers.
        let st = ServerTimeoutConfig::default();
        assert!(
            st.http2_keep_alive_interval_secs > 0,
            "inbound h2 keep-alive should default ON to detect dead h2 peers"
        );
        assert!(
            st.max_connection_age_secs > 0,
            "max connection age must default ON to bound healthy idle h2 peers"
        );
    }

    #[test]
    fn test_pool_h2_keep_alive_default_enabled() {
        // Pool/outbound stays enabled — pooled connections to dead upstreams need detection.
        let p = PoolConfig::default();
        assert!(
            p.http2_keep_alive_interval_secs > 0,
            "pool h2 keep-alive must default ON to evict dead upstream connections"
        );
    }

    #[test]
    fn test_validate_rejects_h2_timeout_ge_interval_server() {
        let yaml = r#"
listen: "0.0.0.0:8080"
server_timeouts:
  http2_keep_alive_interval_secs: 10
  http2_keep_alive_timeout_secs: 10
"#;
        let err = ProxyConfig::from_str(yaml).unwrap_err().to_string();
        assert!(err.contains("strictly less"), "got: {err}");
    }

    #[test]
    fn test_validate_rejects_h2_timeout_ge_interval_pool() {
        let yaml = r#"
listen: "0.0.0.0:8080"
pool:
  http2_keep_alive_interval_secs: 5
  http2_keep_alive_timeout_secs: 5
"#;
        let err = ProxyConfig::from_str(yaml).unwrap_err().to_string();
        assert!(err.contains("strictly less"), "got: {err}");
    }

    #[test]
    fn test_validate_rejects_tcp_keepalive_zero_time() {
        let yaml = r#"
listen: "0.0.0.0:8080"
tcp_keepalive:
  enabled: true
  time_secs: 0
  interval_secs: 30
"#;
        let err = ProxyConfig::from_str(yaml).unwrap_err().to_string();
        assert!(err.contains("time_secs must be > 0"), "got: {err}");
    }

    #[test]
    fn test_validate_rejects_max_age_grace_ge_age() {
        let yaml = r#"
listen: "0.0.0.0:8080"
server_timeouts:
    max_connection_age_secs: 30
    max_connection_age_grace_secs: 30
"#;
        let err = ProxyConfig::from_str(yaml).unwrap_err().to_string();
        assert!(
            err.contains("must be less than max_connection_age_secs"),
            "got: {err}"
        );
    }

    #[test]
    fn test_validate_allows_tcp_keepalive_disabled_with_zero_time() {
        let yaml = r#"
listen: "0.0.0.0:8080"
tcp_keepalive:
  enabled: false
  time_secs: 0
  interval_secs: 0
"#;
        ProxyConfig::from_str(yaml).expect("disabled keepalive should bypass zero checks");
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

    #[test]
    fn test_invalid_listen_address_rejected() {
        let yaml = r#"
listen: "not-a-socket-addr"
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid listen address")
        );
    }

    #[test]
    fn test_duplicate_throttle_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-rate"
    rule: 'host("api.*") = rate_limit(100/s, header(X-Key))'
throttle:
  - rule: "api-rate"
    soft_limit: 80
  - rule: "api-rate"
    soft_limit: 90
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Duplicate throttle")
        );
    }

    #[test]
    fn test_duplicate_credit_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-credit"
    rule: 'host("api.*") = credit(1000/d, header(X-Key))'
credits:
  - rule: "api-credit"
    reset_schedule: "daily@00:00"
    message: "out"
  - rule: "api-credit"
    reset_schedule: "daily@12:00"
    message: "out again"
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate credit"));
    }

    #[test]
    fn test_invalid_header_name_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "my-rule"
    rule: 'host("a.com") = mangle'
headers:
  - rules: ["my-rule"]
    add:
      - name: "Invalid Header!"
        value: "test"
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid header name")
        );
    }

    #[test]
    fn test_invalid_remove_header_name_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "my-rule"
    rule: 'host("a.com") = mangle'
headers:
  - rules: ["my-rule"]
    remove:
      - "Invalid Header!"
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid header name to remove")
        );
    }

    #[test]
    fn test_throttle_max_delay_capped() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "api-rate"
    rule: 'host("api.*") = rate_limit(100/s, header(X-Key))'
throttle:
  - rule: "api-rate"
    soft_limit: 80
    max_delay_ms: 999999
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    // === Coverage: PoolConfig::default() ===

    #[test]
    fn test_pool_config_default() {
        let pool = PoolConfig::default();
        assert_eq!(pool.max_idle_per_host, 10);
        assert_eq!(pool.idle_timeout_secs, 30);
    }

    // === Coverage: empty listen address ===

    #[test]
    fn test_empty_listen_rejected() {
        let yaml = r#"
listen: ""
rules: []
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("listen"));
    }

    // === Coverage: empty rule name ===

    #[test]
    fn test_empty_rule_name_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: ""
    rule: 'host("*") = block'
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    // === Coverage: from_file with nonexistent path ===

    #[test]
    fn test_from_file_nonexistent() {
        let result = ProxyConfig::from_file(std::path::Path::new("/nonexistent/config.yaml"));
        assert!(result.is_err());
    }

    // === Coverage: invalid header value in mangle add ===

    #[test]
    fn test_invalid_header_value_in_mangle_add() {
        let yaml = "listen: \"0.0.0.0:8080\"\nrules:\n  - name: \"my-rule\"\n    rule: 'host(\"*\") = mangle'\nheaders:\n  - rules: [\"my-rule\"]\n    add:\n      - name: \"X-Bad\"\n        value: \"invalid\\x00value\"\n";
        let result = ProxyConfig::from_str(yaml);
        // serde_yml may reject the null byte during parsing, or validation will catch it
        assert!(result.is_err());
    }

    // === Coverage: credit max_delay_ms exceeded ===

    #[test]
    fn test_credit_max_delay_ms_exceeded() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "credit-rule"
    rule: 'host("*") = credit(1000/d, ip)'
credits:
  - rule: "credit-rule"
    reset_schedule: "daily@00:00"
    max_delay_ms: 999999
"#;
        let result = ProxyConfig::from_str(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    // === Coverage: default_credit_message ===

    #[test]
    fn test_default_credit_message_value() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "credit-rule"
    rule: 'host("*") = credit(1000/d, ip)'
credits:
  - rule: "credit-rule"
    reset_schedule: "daily@00:00"
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert!(config.credits[0].message.contains("reset_time"));
    }

    #[test]
    fn test_rule_log_level_omitted_defaults_to_none() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "block-rule"
    rule: 'host("*.internal") = block'
"#;
        let config = ProxyConfig::from_str(yaml).unwrap();
        assert!(config.rules[0].log_level.is_none());
    }

    #[test]
    fn test_rule_log_level_valid_values_accepted() {
        for level in [
            "trace", "debug", "info", "warn", "error", "off", "OFF", "Debug",
        ] {
            let yaml = format!(
                r#"
listen: "0.0.0.0:8080"
rules:
  - name: "r"
    rule: 'host("*") = pass'
    log_level: "{level}"
"#
            );
            let config = ProxyConfig::from_str(&yaml)
                .unwrap_or_else(|e| panic!("expected log_level '{level}' to be accepted, got {e}"));
            assert_eq!(config.rules[0].log_level.as_deref(), Some(level));
        }
    }

    #[test]
    fn test_rule_log_level_invalid_value_rejected() {
        let yaml = r#"
listen: "0.0.0.0:8080"
rules:
  - name: "r"
    rule: 'host("*") = pass'
    log_level: "verbose"
"#;
        let err = ProxyConfig::from_str(yaml).unwrap_err().to_string();
        assert!(err.contains("invalid log_level"), "unexpected error: {err}");
        assert!(err.contains("verbose"), "unexpected error: {err}");
    }
}
