//! Key extraction for rate limiting.
//!
//! Extracts values from requests to build rate limit keys.
//! Supports composite keys from multiple extractors.
//! Missing components use placeholders to prevent bypass.

use crate::rules::ast::{EvalContext, KeyExpr, KeyExtractor};

/// Placeholder used when a key component is unavailable.
const MISSING_PLACEHOLDER: &str = "__no_value__";

/// Extract a rate limit key from the request context.
/// Missing components use a placeholder instead of failing,
/// so rate limiting is never bypassed by omitting headers.
pub fn extract_key(key_expr: &KeyExpr, ctx: &EvalContext) -> String {
    match key_expr {
        KeyExpr::Single(extractor) => extract_single(extractor, ctx),
        KeyExpr::Composite(extractors) => {
            let parts: Vec<String> = extractors.iter().map(|e| extract_single(e, ctx)).collect();
            parts.join(":")
        }
    }
}

/// Extract the IP-only key for baseline enforcement.
/// Returns the client IP or a placeholder if unavailable.
pub fn extract_ip_key(rule_name: &str, ctx: &EvalContext) -> String {
    let ip = ctx.client_ip.unwrap_or(MISSING_PLACEHOLDER);
    format!("__ip_baseline__:{}:{}", rule_name, ip)
}

/// Extract a single key component.
/// Returns a placeholder for missing values instead of failing.
fn extract_single(extractor: &KeyExtractor, ctx: &EvalContext) -> String {
    match extractor {
        KeyExtractor::Host(_pattern) => ctx.host.to_string(),
        KeyExtractor::Path(_pattern) => ctx.path.to_string(),
        KeyExtractor::Header(name) => ctx
            .headers
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_else(|| MISSING_PLACEHOLDER.to_string()),
        KeyExtractor::ClientIp => ctx
            .client_ip
            .map(|s| s.to_string())
            .unwrap_or_else(|| MISSING_PLACEHOLDER.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use std::collections::HashMap;

    fn make_ctx<'a>(
        host: &'a str,
        path: &'a str,
        headers: &'a HashMap<String, String>,
        client_ip: Option<&'a str>,
    ) -> EvalContext<'a> {
        EvalContext {
            host,
            path,
            method: Method::GET,
            headers,
            client_ip,
        }
    }

    #[test]
    fn test_extract_host() {
        let headers = HashMap::new();
        let ctx = make_ctx("api.example.com", "/", &headers, None);

        let key = extract_key(&KeyExpr::Single(KeyExtractor::Host(None)), &ctx);
        assert_eq!(key, "api.example.com");
    }

    #[test]
    fn test_extract_path() {
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/api/v1/users", &headers, None);

        let key = extract_key(&KeyExpr::Single(KeyExtractor::Path(None)), &ctx);
        assert_eq!(key, "/api/v1/users");
    }

    #[test]
    fn test_extract_header() {
        let mut headers = HashMap::new();
        headers.insert("x-customer-id".to_string(), "customer-123".to_string());
        let ctx = make_ctx("example.com", "/", &headers, None);

        let key = extract_key(
            &KeyExpr::Single(KeyExtractor::Header("X-Customer-Id".to_string())),
            &ctx,
        );
        assert_eq!(key, "customer-123");
    }

    #[test]
    fn test_extract_header_missing_uses_placeholder() {
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/", &headers, None);

        let key = extract_key(
            &KeyExpr::Single(KeyExtractor::Header("X-Customer-Id".to_string())),
            &ctx,
        );
        assert_eq!(key, "__no_value__");
    }

    #[test]
    fn test_extract_client_ip() {
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/", &headers, Some("192.168.1.100"));

        let key = extract_key(&KeyExpr::Single(KeyExtractor::ClientIp), &ctx);
        assert_eq!(key, "192.168.1.100");
    }

    #[test]
    fn test_extract_composite_key() {
        let mut headers = HashMap::new();
        headers.insert("x-customer-id".to_string(), "cust-42".to_string());
        let ctx = make_ctx("api.example.com", "/v1/orders", &headers, None);

        let key_expr = KeyExpr::Composite(vec![
            KeyExtractor::Header("X-Customer-Id".to_string()),
            KeyExtractor::Path(None),
            KeyExtractor::Host(None),
        ]);

        let key = extract_key(&key_expr, &ctx);
        assert_eq!(key, "cust-42:/v1/orders:api.example.com");
    }

    #[test]
    fn test_composite_key_graceful_with_missing_header() {
        let headers = HashMap::new(); // Missing header
        let ctx = make_ctx("api.example.com", "/v1/orders", &headers, None);

        let key_expr = KeyExpr::Composite(vec![
            KeyExtractor::Header("X-Customer-Id".to_string()),
            KeyExtractor::Host(None),
        ]);

        // Should succeed with placeholder instead of failing
        let key = extract_key(&key_expr, &ctx);
        assert_eq!(key, "__no_value__:api.example.com");
    }

    #[test]
    fn test_extract_ip_key() {
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/", &headers, Some("10.0.0.1"));

        let key = extract_ip_key("my-rule", &ctx);
        assert_eq!(key, "__ip_baseline__:my-rule:10.0.0.1");
    }
}
