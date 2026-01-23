//! Key extraction for rate limiting.
//!
//! Extracts values from requests to build rate limit keys.
//! Supports composite keys from multiple extractors.

use crate::error::RateLimitError;
use crate::rules::ast::{EvalContext, KeyExpr, KeyExtractor};

/// Extract a rate limit key from the request context.
pub fn extract_key(key_expr: &KeyExpr, ctx: &EvalContext) -> Result<String, RateLimitError> {
    match key_expr {
        KeyExpr::Single(extractor) => extract_single(extractor, ctx),
        KeyExpr::Composite(extractors) => {
            let parts: Result<Vec<String>, _> =
                extractors.iter().map(|e| extract_single(e, ctx)).collect();
            Ok(parts?.join(":"))
        }
    }
}

/// Extract a single key component.
fn extract_single(extractor: &KeyExtractor, ctx: &EvalContext) -> Result<String, RateLimitError> {
    match extractor {
        KeyExtractor::Host(pattern) => {
            if pattern.is_none() {
                // Full host
                Ok(ctx.host.to_string())
            } else {
                // TODO: Pattern capture (for now, just return full host)
                Ok(ctx.host.to_string())
            }
        }
        KeyExtractor::Path(pattern) => {
            if pattern.is_none() {
                // Full path
                Ok(ctx.path.to_string())
            } else {
                // TODO: Pattern capture (for now, just return full path)
                Ok(ctx.path.to_string())
            }
        }
        KeyExtractor::Header(name) => ctx
            .headers
            .get(&name.to_lowercase())
            .cloned()
            .ok_or_else(|| RateLimitError::KeyExtraction(format!("Header '{}' not found", name))),
        KeyExtractor::ClientIp => ctx
            .client_ip
            .map(|s| s.to_string())
            .ok_or_else(|| RateLimitError::KeyExtraction("Client IP not available".to_string())),
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

        let key = extract_key(&KeyExpr::Single(KeyExtractor::Host(None)), &ctx).unwrap();
        assert_eq!(key, "api.example.com");
    }

    #[test]
    fn test_extract_path() {
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/api/v1/users", &headers, None);

        let key = extract_key(&KeyExpr::Single(KeyExtractor::Path(None)), &ctx).unwrap();
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
        )
        .unwrap();
        assert_eq!(key, "customer-123");
    }

    #[test]
    fn test_extract_header_missing() {
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/", &headers, None);

        let result = extract_key(
            &KeyExpr::Single(KeyExtractor::Header("X-Customer-Id".to_string())),
            &ctx,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_client_ip() {
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/", &headers, Some("192.168.1.100"));

        let key = extract_key(&KeyExpr::Single(KeyExtractor::ClientIp), &ctx).unwrap();
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

        let key = extract_key(&key_expr, &ctx).unwrap();
        assert_eq!(key, "cust-42:/v1/orders:api.example.com");
    }

    #[test]
    fn test_composite_key_fails_if_any_missing() {
        let headers = HashMap::new(); // Missing header
        let ctx = make_ctx("api.example.com", "/v1/orders", &headers, None);

        let key_expr = KeyExpr::Composite(vec![
            KeyExtractor::Header("X-Customer-Id".to_string()),
            KeyExtractor::Host(None),
        ]);

        let result = extract_key(&key_expr, &ctx);
        assert!(result.is_err());
    }
}
