//! Hudsucker HttpHandler implementation.
//!
//! Implements the request processing pipeline:
//! handle_request → [rules evaluation] → [rate limiting] → [header mangle] → forward

use http::Method;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{Request, Response, StatusCode},
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::config::HeaderMangleConfig;
use crate::error::RateLimitError;
use crate::ratelimit::{RateLimitResult, RateLimiter};
use crate::rules::{EvalContext, KeyExpr, RuleIndex, RuleResult, extract_key};

/// Roxy HTTP handler implementing Hudsucker's HttpHandler trait.
#[derive(Clone)]
pub struct RoxyHandler {
    /// Compiled rule index
    rules: Arc<RuleIndex>,

    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,

    /// Header mangle configurations keyed by rule name
    header_configs: Arc<HashMap<String, Vec<HeaderMangleConfig>>>,
}

impl RoxyHandler {
    /// Create a new handler with the given configuration.
    pub fn new(
        rules: Arc<RuleIndex>,
        rate_limiter: Arc<RateLimiter>,
        header_configs: Vec<HeaderMangleConfig>,
    ) -> Self {
        // Index header configs by rule name for fast lookup
        let mut configs_by_rule: HashMap<String, Vec<HeaderMangleConfig>> = HashMap::new();
        for config in header_configs {
            for rule_name in &config.rules {
                configs_by_rule
                    .entry(rule_name.clone())
                    .or_default()
                    .push(config.clone());
            }
        }

        Self {
            rules,
            rate_limiter,
            header_configs: Arc::new(configs_by_rule),
        }
    }

    /// Extract request info into evaluation context.
    fn build_eval_context<'a>(
        host: &'a str,
        path: &'a str,
        method: Method,
        headers: &'a HashMap<String, String>,
        client_ip: Option<&'a str>,
    ) -> EvalContext<'a> {
        EvalContext {
            host,
            path,
            method,
            headers,
            client_ip,
        }
    }

    /// Extract headers from request into a HashMap.
    fn extract_headers<T>(req: &Request<T>) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        for (name, value) in req.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }
        headers
    }

    /// Parse host and path from request.
    fn parse_request_info<T>(req: &Request<T>) -> (String, String) {
        let uri = req.uri();

        // Get host from URI authority or Host header
        let host = uri
            .authority()
            .map(|a| a.host().to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h).to_string())
            })
            .unwrap_or_else(|| "localhost".to_string());

        let path = uri.path().to_string();

        (host, path)
    }

    /// Check rate limit for a request.
    fn check_rate_limit(
        &self,
        key_expr: &KeyExpr,
        requests: u64,
        window_secs: u64,
        ctx: &EvalContext,
    ) -> Result<RateLimitResult, RateLimitError> {
        let key = extract_key(key_expr, ctx)?;
        Ok(self.rate_limiter.check(&key, requests, window_secs))
    }

    /// Create an error response.
    fn error_response(status: StatusCode, message: &str) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("Content-Type", "text/plain")
            .header("Content-Length", message.len())
            .body(Body::from(message.to_string()))
            .unwrap()
    }

    /// Create a rate limit response with Retry-After header.
    fn rate_limit_response(retry_after_secs: u64) -> Response<Body> {
        let message = "Rate limit exceeded";
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Content-Type", "text/plain")
            .header("Content-Length", message.len())
            .header("Retry-After", retry_after_secs.to_string())
            .body(Body::from(message.to_string()))
            .unwrap()
    }
}

impl HttpHandler for RoxyHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let method = req.method().clone();
        let (host, path) = Self::parse_request_info(&req);
        let headers = Self::extract_headers(&req);

        // Get client IP
        let client_ip = ctx.client_addr.ip().to_string();

        // Build evaluation context
        let eval_ctx =
            Self::build_eval_context(&host, &path, method.clone(), &headers, Some(&client_ip));

        // Evaluate rules
        let result = self.rules.evaluate(&eval_ctx);
        let mangle_rules = self.rules.evaluate_mangle_rules(&eval_ctx);

        // Process rule result
        match result {
            RuleResult::NoMatch => {
                debug!(target: "rules", "No rules matched");
            }
            RuleResult::Block { rule_name } => {
                info!(target: "proxy", rule = %rule_name, action = "block", status = 403);
                return Self::error_response(StatusCode::FORBIDDEN, "Forbidden by proxy rule")
                    .into();
            }
            RuleResult::Pass { rule_name } => {
                debug!(target: "rules", rule = %rule_name, action = "pass");
            }
            RuleResult::Mangle { rule_name } => {
                debug!(target: "rules", rule = %rule_name, action = "mangle");
                // Mangle rules collected separately below
            }
            RuleResult::RateLimit {
                rule_name,
                requests,
                window_secs,
                key_expr,
            } => {
                match self.check_rate_limit(&key_expr, requests, window_secs, &eval_ctx) {
                    Ok(RateLimitResult::Allowed { remaining }) => {
                        debug!(target: "ratelimit", rule = %rule_name, remaining = remaining);
                    }
                    Ok(RateLimitResult::Limited { retry_after_secs }) => {
                        warn!(target: "ratelimit", rule = %rule_name, action = "limited");
                        return Self::rate_limit_response(retry_after_secs).into();
                    }
                    Err(e) => {
                        warn!(target: "ratelimit", error = %e, "Rate limit key extraction failed");
                        // Continue without rate limiting if key extraction fails
                    }
                }
            }
        }

        // Apply header modifications for matched mangle rules
        let (mut parts, body) = req.into_parts();

        for rule_name in &mangle_rules {
            if let Some(configs) = self.header_configs.get(rule_name) {
                for config in configs {
                    // Add headers
                    for header_add in &config.add {
                        if let Ok(name) = header_add.name.parse::<http::HeaderName>()
                            && let Ok(value) = header_add.value.parse::<http::HeaderValue>()
                        {
                            parts.headers.insert(name, value);
                            debug!(
                                target: "proxy",
                                rule = %rule_name,
                                header = %header_add.name,
                                value = %header_add.value,
                                "Added header"
                            );
                        }
                    }

                    // Remove headers
                    for header_name in &config.remove {
                        if let Ok(name) = header_name.parse::<http::HeaderName>() {
                            parts.headers.remove(name);
                            debug!(
                                target: "proxy",
                                rule = %rule_name,
                                header = %header_name,
                                "Removed header"
                            );
                        }
                    }
                }
            }
        }

        // Log the forwarded request
        info!(
            target: "proxy",
            method = %method,
            host = %host,
            path = %path,
            action = "forward"
        );

        // Reconstruct request and forward
        Request::from_parts(parts, body).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // Pass through responses unchanged for now
        // Future: could add response filtering/modification here
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratelimit::RateLimiter;
    use crate::rules::RuleIndex;
    use std::time::Duration;

    #[test]
    fn test_parse_request_info() {
        let req = Request::builder()
            .uri("http://example.com/path/to/resource")
            .body(())
            .unwrap();

        let (host, path) = RoxyHandler::parse_request_info(&req);
        assert_eq!(host, "example.com");
        assert_eq!(path, "/path/to/resource");
    }

    #[test]
    fn test_parse_request_info_with_host_header() {
        let req = Request::builder()
            .uri("/api/endpoint")
            .header("host", "api.example.com:8080")
            .body(())
            .unwrap();

        let (host, path) = RoxyHandler::parse_request_info(&req);
        assert_eq!(host, "api.example.com");
        assert_eq!(path, "/api/endpoint");
    }

    #[test]
    fn test_extract_headers() {
        let req = Request::builder()
            .uri("http://example.com/")
            .header("X-Custom", "value")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();

        let headers = RoxyHandler::extract_headers(&req);
        assert_eq!(headers.get("x-custom"), Some(&"value".to_string()));
        assert_eq!(
            headers.get("content-type"),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn test_error_response() {
        let resp = RoxyHandler::error_response(StatusCode::FORBIDDEN, "Forbidden");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_rate_limit_response() {
        let resp = RoxyHandler::rate_limit_response(60);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "60");
    }

    #[test]
    fn test_handler_creation() {
        let rules = Arc::new(RuleIndex::new());
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_secs(60)));
        let handler = RoxyHandler::new(rules, rate_limiter, vec![]);

        assert!(handler.header_configs.is_empty());
    }
}
