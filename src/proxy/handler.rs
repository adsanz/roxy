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
use tracing::{debug, info};

use crate::config::{HeaderMangleConfig, ThrottleConfig};
use crate::ratelimit::{CreditManager, CreditResult, RateLimitResult, RateLimiter};
use crate::rules::{EvalContext, KeyExpr, RuleIndex, RuleResult, extract_ip_key, extract_key};

/// Roxy HTTP handler implementing Hudsucker's HttpHandler trait.
#[derive(Clone)]
pub struct RoxyHandler {
    /// Compiled rule index
    rules: Arc<RuleIndex>,

    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,

    /// Credit manager
    credit_manager: Arc<CreditManager>,

    /// Header mangle configurations keyed by rule name
    header_configs: Arc<HashMap<String, Vec<HeaderMangleConfig>>>,

    /// Throttle configs indexed by rule name
    throttle_configs: Arc<HashMap<String, ThrottleConfig>>,
}

impl RoxyHandler {
    /// Create a new handler with the given configuration.
    pub fn new(
        rules: Arc<RuleIndex>,
        rate_limiter: Arc<RateLimiter>,
        credit_manager: Arc<CreditManager>,
        header_configs: Vec<HeaderMangleConfig>,
        throttle_configs: Vec<ThrottleConfig>,
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

        // Index throttle configs by rule name
        let throttle_by_rule: HashMap<String, ThrottleConfig> = throttle_configs
            .into_iter()
            .map(|c| (c.rule.clone(), c))
            .collect();

        Self {
            rules,
            rate_limiter,
            credit_manager,
            header_configs: Arc::new(configs_by_rule),
            throttle_configs: Arc::new(throttle_by_rule),
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
            } else {
                // Header contains non-ASCII bytes, use lossy conversion
                let v = String::from_utf8_lossy(value.as_bytes()).to_string();
                debug!(target: "proxy", header = %name, "Header contains non-UTF8 bytes, using lossy conversion");
                headers.insert(name.as_str().to_lowercase(), v);
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
    ) -> RateLimitResult {
        let key = extract_key(key_expr, ctx);
        self.rate_limiter.check(&key, requests, window_secs)
    }

    /// IP baseline rate limit check.
    /// Enforces the same rate limit by IP alone when keys contain user-controlled
    /// header extractors. Prevents bypass by varying header values.
    fn check_ip_baseline(
        &self,
        rule_name: &str,
        key_expr: &KeyExpr,
        requests: u64,
        window_secs: u64,
        ctx: &EvalContext,
    ) -> Option<RateLimitResult> {
        if !key_expr.has_header_extractor() {
            return None; // No user-controlled components, no need for baseline
        }
        let ip_key = extract_ip_key(rule_name, ctx);
        Some(self.rate_limiter.check(&ip_key, requests, window_secs))
    }

    /// Create an error response.
    fn error_response(status: StatusCode, message: &str) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("Content-Type", "text/plain")
            .header("Content-Length", message.len())
            .body(Body::from(message.to_string()))
            .unwrap_or_else(|_| Response::new(Body::from("Internal proxy error")))
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
            .unwrap_or_else(|_| Response::new(Body::from("Rate limit exceeded")))
    }

    /// Create a credit exhaustion response with custom message.
    fn credit_exhausted_response(retry_after_secs: u64, message: &str) -> Response<Body> {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Content-Type", "text/plain")
            .header("Content-Length", message.len())
            .header("Retry-After", retry_after_secs.to_string())
            .body(Body::from(message.to_string()))
            .unwrap_or_else(|_| Response::new(Body::from("Credit exhausted")))
    }

    /// Compute progressive delay for rate limiting when a throttle config exists.
    /// Returns delay in ms if request count exceeds soft_limit.
    fn compute_throttle_delay(
        &self,
        rule_name: &str,
        remaining: u64,
        max_requests: u64,
    ) -> Option<u64> {
        let throttle = self.throttle_configs.get(rule_name)?;
        let used = max_requests.saturating_sub(remaining);
        if used <= throttle.soft_limit {
            return None;
        }
        let range = max_requests.saturating_sub(throttle.soft_limit);
        let over = used.saturating_sub(throttle.soft_limit);
        let delay_ms = if range > 0 {
            (over as f64 / range as f64 * throttle.max_delay_ms as f64) as u64
        } else {
            throttle.max_delay_ms
        };
        Some(delay_ms)
    }
}

impl HttpHandler for RoxyHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let method = req.method().clone();
        let (host, path) = Self::parse_request_info(&req);
        let headers = Self::extract_headers(&req);

        // Get client IP
        let client_ip = ctx.client_addr.ip().to_string();

        // For CONNECT requests (HTTPS tunnel establishment), skip rule evaluation.
        // Rules will be evaluated on the actual HTTP request inside the tunnel.
        // This allows path-based rules to work correctly for HTTPS traffic.
        if method == Method::CONNECT {
            debug!(
                target: "proxy",
                method = %method,
                host = %host,
                action = "tunnel",
                "Establishing HTTPS tunnel (rule evaluation will happen on inner request)"
            );
            return req.into();
        }

        debug!(
            target: "proxy",
            method = %method,
            host = %host,
            path = %path,
            "Processing request"
        );

        // Build evaluation context
        let eval_ctx =
            Self::build_eval_context(&host, &path, method.clone(), &headers, Some(&client_ip));

        // Evaluate rules
        let result = self.rules.evaluate(&eval_ctx);
        let mut mangle_rules = self.rules.evaluate_mangle_rules(&eval_ctx);

        debug!(target: "rules", ?result, "Rule evaluation result");

        // Process rule result - collect info for single log at forward time
        let mut matched_rule: Option<String> = None;
        let mut matched_headers: HashMap<String, String> = HashMap::new();

        match result {
            RuleResult::NoMatch => {
                debug!(target: "rules", "No rules matched");
            }
            RuleResult::Block {
                rule_name,
                logged_headers,
            } => {
                info!(
                    target: "proxy",
                    method = %method,
                    host = %host,
                    path = %path,
                    rule = %rule_name,
                    action = "block",
                    status = 403,
                    headers = ?logged_headers
                );
                return Self::error_response(StatusCode::FORBIDDEN, "Not Allowed").into();
            }
            RuleResult::Pass {
                rule_name,
                logged_headers,
            } => {
                debug!(target: "rules", rule = %rule_name, action = "pass");
                matched_rule = Some(rule_name);
                matched_headers = logged_headers;
            }
            RuleResult::Mangle {
                rule_name,
                logged_headers,
            } => {
                debug!(target: "rules", rule = %rule_name, action = "mangle");
                matched_rule = Some(rule_name);
                matched_headers = logged_headers;
            }
            RuleResult::RateLimit {
                rule_name,
                requests,
                window_secs,
                key_expr,
                mangle,
                logged_headers,
            } => {
                // IP baseline check: prevent bypass by varying header values
                if let Some(RateLimitResult::Limited { retry_after_secs }) =
                    self.check_ip_baseline(&rule_name, &key_expr, requests, window_secs, &eval_ctx)
                {
                    info!(
                        target: "proxy",
                        method = %method,
                        host = %host,
                        path = %path,
                        rule = %rule_name,
                        action = "rate_limited",
                        reason = "ip_baseline",
                        status = 429,
                        headers = ?logged_headers
                    );
                    return Self::rate_limit_response(retry_after_secs).into();
                }

                // Per-key rate limit check
                match self.check_rate_limit(&key_expr, requests, window_secs, &eval_ctx) {
                    RateLimitResult::Allowed { remaining } => {
                        if let Some(delay_ms) =
                            self.compute_throttle_delay(&rule_name, remaining, requests)
                        {
                            debug!(target: "ratelimit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        } else {
                            debug!(target: "ratelimit", rule = %rule_name, remaining);
                        }
                        if mangle {
                            mangle_rules.push(rule_name.clone());
                        }
                        matched_rule = Some(rule_name);
                        matched_headers = logged_headers;
                    }
                    RateLimitResult::Limited { retry_after_secs } => {
                        info!(
                            target: "proxy",
                            method = %method,
                            host = %host,
                            path = %path,
                            rule = %rule_name,
                            action = "rate_limited",
                            status = 429,
                            headers = ?logged_headers
                        );
                        return Self::rate_limit_response(retry_after_secs).into();
                    }
                }
            }
            RuleResult::Credit {
                rule_name,
                credits: _,
                period: _,
                key_expr,
                mangle,
                logged_headers,
            } => {
                let key = extract_key(&key_expr, &eval_ctx);
                let result = self.credit_manager.check(&rule_name, &key);
                match result {
                    CreditResult::Allowed { remaining } => {
                        debug!(target: "credit", rule = %rule_name, remaining);
                        if mangle {
                            mangle_rules.push(rule_name.clone());
                        }
                        matched_rule = Some(rule_name);
                        matched_headers = logged_headers;
                    }
                    CreditResult::Throttled {
                        remaining,
                        delay_ms,
                    } => {
                        debug!(target: "credit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        if mangle {
                            mangle_rules.push(rule_name.clone());
                        }
                        matched_rule = Some(rule_name);
                        matched_headers = logged_headers;
                    }
                    CreditResult::Exhausted {
                        retry_after_secs,
                        reset_time,
                    } => {
                        let message = self
                            .credit_manager
                            .format_exhaustion_message(&rule_name, &reset_time);
                        info!(
                            target: "proxy",
                            method = %method,
                            host = %host,
                            path = %path,
                            rule = %rule_name,
                            action = "credit_exhausted",
                            status = 429,
                            reset_time = %reset_time,
                            headers = ?logged_headers
                        );
                        return Self::credit_exhausted_response(retry_after_secs, &message).into();
                    }
                }
            }
            RuleResult::RateLimitCredit {
                rule_name,
                requests,
                window_secs,
                rate_key_expr,
                credits: _,
                period: _,
                credit_key_expr,
                mangle,
                logged_headers,
            } => {
                // Step 0: IP baseline check (prevents header-flooding bypass)
                if let Some(RateLimitResult::Limited { retry_after_secs }) = self.check_ip_baseline(
                    &rule_name,
                    &rate_key_expr,
                    requests,
                    window_secs,
                    &eval_ctx,
                ) {
                    info!(
                        target: "proxy",
                        method = %method,
                        host = %host,
                        path = %path,
                        rule = %rule_name,
                        action = "rate_limited",
                        reason = "ip_baseline",
                        status = 429,
                        headers = ?logged_headers
                    );
                    return Self::rate_limit_response(retry_after_secs).into();
                }

                // Step 1: Per-key rate limit check (burst protection)
                match self.check_rate_limit(&rate_key_expr, requests, window_secs, &eval_ctx) {
                    RateLimitResult::Limited { retry_after_secs } => {
                        info!(
                            target: "proxy",
                            method = %method,
                            host = %host,
                            path = %path,
                            rule = %rule_name,
                            action = "rate_limited",
                            status = 429,
                            headers = ?logged_headers
                        );
                        return Self::rate_limit_response(retry_after_secs).into();
                    }
                    RateLimitResult::Allowed { remaining } => {
                        // Step 2: Credit check (budget enforcement)
                        let credit_key = extract_key(&credit_key_expr, &eval_ctx);
                        let credit_result = self.credit_manager.check(&rule_name, &credit_key);
                        match credit_result {
                            CreditResult::Exhausted {
                                retry_after_secs,
                                reset_time,
                            } => {
                                let message = self
                                    .credit_manager
                                    .format_exhaustion_message(&rule_name, &reset_time);
                                info!(
                                    target: "proxy",
                                    method = %method,
                                    host = %host,
                                    path = %path,
                                    rule = %rule_name,
                                    action = "credit_exhausted",
                                    status = 429,
                                    reset_time = %reset_time,
                                    headers = ?logged_headers
                                );
                                return Self::credit_exhausted_response(retry_after_secs, &message)
                                    .into();
                            }
                            CreditResult::Throttled {
                                remaining: _,
                                delay_ms: credit_delay,
                            } => {
                                let rl_delay = self
                                    .compute_throttle_delay(&rule_name, remaining, requests)
                                    .unwrap_or(0);
                                let max_delay = credit_delay.max(rl_delay);
                                debug!(target: "proxy", rule = %rule_name, credit_delay, rl_delay, max_delay, "Composite throttle");
                                tokio::time::sleep(std::time::Duration::from_millis(max_delay))
                                    .await;
                                if mangle {
                                    mangle_rules.push(rule_name.clone());
                                }
                                matched_rule = Some(rule_name);
                                matched_headers = logged_headers;
                            }
                            CreditResult::Allowed { remaining: _ } => {
                                if let Some(delay_ms) =
                                    self.compute_throttle_delay(&rule_name, remaining, requests)
                                {
                                    debug!(target: "ratelimit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms))
                                        .await;
                                }
                                if mangle {
                                    mangle_rules.push(rule_name.clone());
                                }
                                matched_rule = Some(rule_name);
                                matched_headers = logged_headers;
                            }
                        }
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

        // Log the forwarded request (single info log per request)
        match (&matched_rule, matched_headers.is_empty()) {
            (Some(rule), true) => {
                info!(
                    target: "proxy",
                    method = %method,
                    host = %host,
                    path = %path,
                    rule = %rule,
                    action = "forward"
                );
            }
            (Some(rule), false) => {
                info!(
                    target: "proxy",
                    method = %method,
                    host = %host,
                    path = %path,
                    rule = %rule,
                    action = "forward",
                    headers = ?matched_headers
                );
            }
            (None, _) => {
                info!(
                    target: "proxy",
                    method = %method,
                    host = %host,
                    path = %path,
                    action = "forward"
                );
            }
        }

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
        let credit_manager = Arc::new(CreditManager::new());
        let handler = RoxyHandler::new(rules, rate_limiter, credit_manager, vec![], vec![]);

        assert!(handler.header_configs.is_empty());
        assert!(handler.throttle_configs.is_empty());
    }
}
