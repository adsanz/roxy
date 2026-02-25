//! Key extraction for rate limiting.
//!
//! Extracts values from requests to build rate limit keys.
//! Supports composite keys from multiple extractors.
//! Missing components use placeholders to prevent bypass.

use std::borrow::Cow;
use std::fmt::Write;

use crate::rules::ast::{EvalContext, KeyExpr, KeyExtractor};
use crate::util::StackString;

/// Placeholder used when a key component is unavailable.
const MISSING_PLACEHOLDER: &str = "__no_value__";

/// Extract a rate limit key from the request context.
/// Missing components use a placeholder instead of failing,
/// so rate limiting is never bypassed by omitting headers.
///
/// Returns `Cow<str>`: borrowed for single Host/Path/Header keys (zero alloc),
/// owned only for ClientIp or Composite keys.
pub fn extract_key<'a>(key_expr: &KeyExpr, ctx: &'a EvalContext<'a>) -> Cow<'a, str> {
    match key_expr {
        KeyExpr::Single(extractor) => extract_single(extractor, ctx),
        KeyExpr::Composite(extractors) => {
            // Write directly into a single String instead of Vec<String> + join
            let mut key = String::with_capacity(64);
            for (i, e) in extractors.iter().enumerate() {
                if i > 0 {
                    key.push(':');
                }
                let _ = write!(key, "{}", extract_single(e, ctx));
            }
            Cow::Owned(key)
        }
    }
}

/// IP baseline key capacity.
/// `__ip_baseline__:` (16) + rule_name (≤48) + `:` (1) + IPv6 (≤45) = 110 max.
/// 128 bytes covers all realistic cases without heap allocation.
const IP_KEY_CAP: usize = 128;

/// Extract the IP-only key for baseline enforcement.
/// Returns a stack-allocated `StackString` — zero heap allocation.
///
/// Falls back to heap `String` only if the formatted key exceeds 128 bytes
/// (e.g., extremely long rule names), which should never happen in practice.
pub fn extract_ip_key(rule_name: &str, ctx: &EvalContext) -> IpKey {
    let mut key = StackString::<IP_KEY_CAP>::new();
    let ok = key.push_str("__ip_baseline__:").is_ok()
        && key.push_str(rule_name).is_ok()
        && key.push_ascii(':').is_ok()
        && match ctx.client_ip {
            Some(ip) => write!(key, "{}", ip).is_ok(),
            None => key.push_str(MISSING_PLACEHOLDER).is_ok(),
        };

    if ok {
        IpKey {
            inner: IpKeyInner::Stack(key),
        }
    } else {
        // Fallback: very long rule name — allocate on heap
        let mut s = String::with_capacity(16 + rule_name.len() + 46);
        s.push_str("__ip_baseline__:");
        s.push_str(rule_name);
        s.push(':');
        match ctx.client_ip {
            Some(ip) => {
                let _ = write!(s, "{}", ip);
            }
            None => s.push_str(MISSING_PLACEHOLDER),
        }
        IpKey {
            inner: IpKeyInner::Heap(s),
        }
    }
}

/// IP baseline key that is stack-allocated in the common case.
/// Opaque type — access contents via [`IpKey::as_str()`].
pub struct IpKey {
    inner: IpKeyInner,
}

enum IpKeyInner {
    Stack(StackString<IP_KEY_CAP>),
    Heap(String),
}

impl IpKey {
    /// Borrow the key as `&str` for DashMap lookup.
    #[inline]
    pub fn as_str(&self) -> &str {
        match &self.inner {
            IpKeyInner::Stack(s) => s.as_str(),
            IpKeyInner::Heap(s) => s.as_str(),
        }
    }
}

/// Extract a single key component.
/// Returns a `Cow<str>` to avoid allocating for Host/Path (already borrowed).
fn extract_single<'a>(extractor: &KeyExtractor, ctx: &'a EvalContext<'a>) -> Cow<'a, str> {
    match extractor {
        KeyExtractor::Host => Cow::Borrowed(ctx.host),
        KeyExtractor::Path => Cow::Borrowed(ctx.path),
        KeyExtractor::Header(header_name, _) => ctx
            .headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(Cow::Borrowed)
            .unwrap_or(Cow::Borrowed(MISSING_PLACEHOLDER)),
        KeyExtractor::ClientIp => ctx
            .client_ip
            .map(|ip| Cow::Owned(ip.to_string()))
            .unwrap_or(Cow::Borrowed(MISSING_PLACEHOLDER)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use http::header::{HeaderMap, HeaderName, HeaderValue};
    use std::net::IpAddr;

    fn make_ctx<'a>(
        host: &'a str,
        path: &'a str,
        headers: &'a HeaderMap,
        client_ip: Option<IpAddr>,
    ) -> EvalContext<'a> {
        EvalContext {
            host,
            path,
            method: &Method::GET,
            headers,
            client_ip,
        }
    }

    #[test]
    fn test_extract_host() {
        let headers = HeaderMap::new();
        let ctx = make_ctx("api.example.com", "/", &headers, None);

        let key = extract_key(&KeyExpr::Single(KeyExtractor::Host), &ctx);
        assert_eq!(key, "api.example.com");
    }

    #[test]
    fn test_extract_path() {
        let headers = HeaderMap::new();
        let ctx = make_ctx("example.com", "/api/v1/users", &headers, None);

        let key = extract_key(&KeyExpr::Single(KeyExtractor::Path), &ctx);
        assert_eq!(key, "/api/v1/users");
    }

    #[test]
    fn test_extract_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-customer-id"),
            HeaderValue::from_static("customer-123"),
        );
        let ctx = make_ctx("example.com", "/", &headers, None);

        let key = extract_key(
            &KeyExpr::Single(KeyExtractor::Header(
                HeaderName::from_static("x-customer-id"),
                "x-customer-id".to_string(),
            )),
            &ctx,
        );
        assert_eq!(key, "customer-123");
    }

    #[test]
    fn test_extract_header_missing_uses_placeholder() {
        let headers = HeaderMap::new();
        let ctx = make_ctx("example.com", "/", &headers, None);

        let key = extract_key(
            &KeyExpr::Single(KeyExtractor::Header(
                HeaderName::from_static("x-customer-id"),
                "x-customer-id".to_string(),
            )),
            &ctx,
        );
        assert_eq!(key, "__no_value__");
    }

    #[test]
    fn test_extract_client_ip() {
        let headers = HeaderMap::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let ctx = make_ctx("example.com", "/", &headers, Some(ip));

        let key = extract_key(&KeyExpr::Single(KeyExtractor::ClientIp), &ctx);
        assert_eq!(key, "192.168.1.100");
    }

    #[test]
    fn test_extract_composite_key() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-customer-id"),
            HeaderValue::from_static("cust-42"),
        );
        let ctx = make_ctx("api.example.com", "/v1/orders", &headers, None);

        let key_expr = KeyExpr::Composite(vec![
            KeyExtractor::Header(
                HeaderName::from_static("x-customer-id"),
                "x-customer-id".to_string(),
            ),
            KeyExtractor::Path,
            KeyExtractor::Host,
        ]);

        let key = extract_key(&key_expr, &ctx);
        assert_eq!(key, "cust-42:/v1/orders:api.example.com");
    }

    #[test]
    fn test_composite_key_graceful_with_missing_header() {
        let headers = HeaderMap::new(); // Missing header
        let ctx = make_ctx("api.example.com", "/v1/orders", &headers, None);

        let key_expr = KeyExpr::Composite(vec![
            KeyExtractor::Header(
                HeaderName::from_static("x-customer-id"),
                "x-customer-id".to_string(),
            ),
            KeyExtractor::Host,
        ]);

        // Should succeed with placeholder instead of failing
        let key = extract_key(&key_expr, &ctx);
        assert_eq!(key, "__no_value__:api.example.com");
    }

    #[test]
    fn test_extract_ip_key() {
        let headers = HeaderMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ctx = make_ctx("example.com", "/", &headers, Some(ip));

        let key = extract_ip_key("my-rule", &ctx);
        assert_eq!(key.as_str(), "__ip_baseline__:my-rule:10.0.0.1");
    }

    #[test]
    fn test_extract_ip_key_no_ip() {
        let headers = HeaderMap::new();
        let ctx = make_ctx("example.com", "/", &headers, None);

        let key = extract_ip_key("my-rule", &ctx);
        assert_eq!(key.as_str(), "__ip_baseline__:my-rule:__no_value__");
    }

    #[test]
    fn test_extract_ip_key_heap_fallback() {
        let headers = HeaderMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ctx = make_ctx("example.com", "/", &headers, Some(ip));

        // Use a rule name long enough to exceed the 128-byte stack buffer
        let long_name = "a".repeat(120);
        let key = extract_ip_key(&long_name, &ctx);
        let expected = format!("__ip_baseline__:{}:10.0.0.1", long_name);
        assert_eq!(key.as_str(), expected);
    }

    #[test]
    fn test_extract_client_ip_missing() {
        let headers = HeaderMap::new();
        let ctx = make_ctx("example.com", "/", &headers, None);

        let key = extract_key(&KeyExpr::Single(KeyExtractor::ClientIp), &ctx);
        assert_eq!(key, "__no_value__");
    }
}
