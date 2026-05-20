//! Shared helpers for benchmark suites.
#![allow(dead_code)]

use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Method;
use std::net::IpAddr;

use roxy::config::RuleConfig;
use roxy::rules::{EvalContext, RuleIndex};

/// Rule complexity levels
#[derive(Debug, Clone, Copy)]
pub enum Complexity {
    /// Single matcher: `host("example.com") = pass`
    Simple,
    /// 2-3 matchers with AND/OR: `host("*.api") && method(GET) = pass`
    Medium,
    /// 4+ matchers with nesting, NOT, ternary
    Complex,
}

/// Generate a rule with specified complexity
pub fn generate_rule(index: usize, complexity: Complexity) -> RuleConfig {
    let (name, rule) = match complexity {
        Complexity::Simple => match index % 4 {
            0 => (
                format!("simple-host-{}", index),
                format!(r#"host("service-{}.example.com") = pass"#, index),
            ),
            1 => (
                format!("simple-path-{}", index),
                format!(r#"path("/api/v{}/resource") = pass"#, index % 10),
            ),
            2 => (
                format!("simple-method-{}", index),
                format!(
                    r#"method({}) = pass"#,
                    ["GET", "POST", "PUT", "DELETE"][index % 4]
                ),
            ),
            _ => (
                format!("simple-header-{}", index),
                format!(r#"header("X-Request-Id-{}") = pass"#, index),
            ),
        },
        Complexity::Medium => match index % 3 {
            0 => (
                format!("medium-auth-{}", index),
                format!(
                    r#"host("api-{}.example.com") && !header("Authorization") = block : pass"#,
                    index % 100
                ),
            ),
            1 => (
                format!("medium-method-path-{}", index),
                format!(
                    r#"method(GET) && path("/users/{}/profile") = pass"#,
                    index
                ),
            ),
            _ => (
                format!("medium-or-{}", index),
                format!(
                    r#"host("service-{}.internal") || host("service-{}.local") = block"#,
                    index, index
                ),
            ),
        },
        Complexity::Complex => match index % 4 {
            0 => (
                format!("complex-nested-{}", index),
                format!(
                    r#"(host("*.api-{}.com") || host("*.cdn-{}.net")) && method(GET) && !header("X-Block") = pass"#,
                    index % 50,
                    index % 50
                ),
            ),
            1 => (
                format!("complex-ratelimit-{}", index),
                format!(
                    r#"host("api-{}.example.com") && path("/v1/*") = rate_limit(100/s, header(X-Customer-Id))"#,
                    index % 100
                ),
            ),
            2 => (
                format!("complex-mangle-{}", index),
                format!(
                    r#"host("backend-{}.internal") && !header("X-Forwarded-For") && method(POST) = mangle"#,
                    index % 50
                ),
            ),
            _ => (
                format!("complex-multi-{}", index),
                format!(
                    r#"(host("*.example.com") && path("/api/*")) || (host("*.test.com") && header("X-Test-{}:enabled")) = pass"#,
                    index
                ),
            ),
        },
    };

    RuleConfig {
        name,
        rule,
        ..Default::default()
    }
}

/// Generate a batch of rules with specified count and complexity
pub fn generate_rules(count: usize, complexity: Complexity) -> Vec<RuleConfig> {
    (0..count).map(|i| generate_rule(i, complexity)).collect()
}

/// Create a RuleIndex from generated rules
pub fn build_rule_index(rules: &[RuleConfig]) -> RuleIndex {
    RuleIndex::from_config(rules).expect("Failed to parse generated rules")
}

/// Create a test evaluation context
pub fn create_eval_context<'a>(
    host: &'a str,
    path: &'a str,
    method: &'a Method,
    headers: &'a HeaderMap,
) -> EvalContext<'a> {
    EvalContext {
        host,
        path,
        method,
        headers,
        client_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100))),
    }
}

/// Build a HeaderMap with common auth + customer headers
pub fn headers_with_auth() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_static("Bearer token123"),
    );
    h.insert(
        HeaderName::from_static("x-customer-id"),
        HeaderValue::from_static("cust-42"),
    );
    h.insert(
        HeaderName::from_static("x-request-id-5"),
        HeaderValue::from_static("req-123"),
    );
    h
}

/// Build a HeaderMap without auth
pub fn headers_without_auth() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("x-customer-id"),
        HeaderValue::from_static("cust-42"),
    );
    h
}
