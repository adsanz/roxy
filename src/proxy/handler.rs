//! Hudsucker HttpHandler implementation.
//!
//! Implements the request processing pipeline:
//! handle_request → [rules evaluation] → [rate limiting] → [header mangle] → forward

use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{Request, Response, StatusCode},
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::config::{HeaderMangleConfig, ThrottleConfig};
use crate::ratelimit::{CreditManager, CreditResult, RateLimitResult, RateLimiter};
use crate::rules::{
    Action, EvalContext, KeyExpr, LoggedHeaders, RuleIndex, RuleMatch, extract_ip_key, extract_key,
};

/// Pre-parsed header to add (parsed once at startup, not per-request).
#[derive(Clone, Debug)]
struct ParsedHeaderAdd {
    name: http::HeaderName,
    value: http::HeaderValue,
}

/// Pre-parsed header to remove (parsed once at startup, not per-request).
#[derive(Clone, Debug)]
struct ParsedHeaderRemove {
    name: http::HeaderName,
}

/// Pre-parsed header mangle config (no per-request `.parse()` calls).
#[derive(Clone, Debug)]
struct ParsedMangleConfig {
    add: Vec<ParsedHeaderAdd>,
    remove: Vec<ParsedHeaderRemove>,
}

/// Roxy HTTP handler implementing Hudsucker's HttpHandler trait.
#[derive(Clone)]
pub struct RoxyHandler {
    /// Compiled rule index
    rules: Arc<RuleIndex>,

    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,

    /// Credit manager
    credit_manager: Arc<CreditManager>,

    /// Header mangle configurations keyed by rule name (pre-parsed at startup)
    header_configs: Arc<HashMap<String, Vec<ParsedMangleConfig>>>,

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
        // Index header configs by rule name and pre-parse header names/values
        let mut configs_by_rule: HashMap<String, Vec<ParsedMangleConfig>> = HashMap::new();
        for config in header_configs {
            let parsed = ParsedMangleConfig {
                add: config
                    .add
                    .iter()
                    .filter_map(|h| {
                        let name = h.name.parse::<http::HeaderName>().ok()?;
                        let value = h.value.parse::<http::HeaderValue>().ok()?;
                        Some(ParsedHeaderAdd { name, value })
                    })
                    .collect(),
                remove: config
                    .remove
                    .iter()
                    .filter_map(|h| {
                        let name = h.parse::<http::HeaderName>().ok()?;
                        Some(ParsedHeaderRemove { name })
                    })
                    .collect(),
            };
            for rule_name in &config.rules {
                configs_by_rule
                    .entry(rule_name.clone())
                    .or_default()
                    .push(parsed.clone());
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

    /// Parse host and path from request.
    /// Host is returned as `Cow<str>`: borrowed when available from URI authority
    /// (zero-alloc), owned only when extracted from Host header (port stripping).
    fn parse_request_info<T>(req: &Request<T>) -> (Cow<'_, str>, &str) {
        let uri = req.uri();

        // Get host: prefer URI authority (borrowed), fall back to Host header (may allocate for port strip)
        let host: Cow<'_, str> = if let Some(authority) = uri.authority() {
            Cow::Borrowed(authority.host())
        } else if let Some(h) = req.headers().get("host").and_then(|h| h.to_str().ok()) {
            if let Some(host_part) = h.split(':').next()
                && host_part != h
            {
                // Host header has port — need to allocate the stripped version
                Cow::Owned(host_part.to_string())
            } else {
                Cow::Borrowed(h)
            }
        } else {
            Cow::Borrowed("localhost")
        };

        let path = uri.path();

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
        Some(self.rate_limiter.check(ip_key.as_str(), requests, window_secs))
    }

    /// Build an HTTP error/rejection response.
    ///
    /// If `retry_after` is `Some`, a `Retry-After` header is added (for 429s).
    fn build_response(
        status: StatusCode,
        message: &str,
        retry_after: Option<u64>,
    ) -> Response<Body> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", "text/plain")
            .header("Content-Length", message.len());
        if let Some(secs) = retry_after {
            builder = builder.header("Retry-After", secs.to_string());
        }
        builder
            .body(Body::from(message.to_string()))
            .unwrap_or_else(|_| Response::new(Body::from("Internal proxy error")))
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

        // Get client IP as IpAddr (no formatting unless needed)
        let client_ip = ctx.client_addr.ip();

        // For CONNECT requests (HTTPS tunnel establishment), skip rule evaluation.
        // Rules will be evaluated on the actual HTTP request inside the tunnel.
        // This allows path-based rules to work correctly for HTTPS traffic.
        if method == http::Method::CONNECT {
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

        // Build evaluation context — pass headers by reference, no copy
        let eval_ctx = EvalContext {
            host: &host,
            path,
            method: &method,
            headers: req.headers(),
            client_ip: Some(client_ip),
        };

        // Evaluate rules
        let result = self.rules.evaluate(&eval_ctx);
        let mut mangle_rules = self.rules.evaluate_mangle_rules(&eval_ctx);

        debug!(target: "rules", ?result, "Rule evaluation result");

        // Process rule result - collect info for single log at forward time
        let mut matched_rule: Option<&str> = None;
        let mut matched_headers = LoggedHeaders::default();

        if let Some(rule_match) = result {
            let RuleMatch {
                rule_name,
                logged_headers,
                action,
            } = rule_match;

            match action {
                Action::Block => {
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
                    return Self::build_response(StatusCode::FORBIDDEN, "Not Allowed", None).into();
                }
                Action::Pass => {
                    debug!(target: "rules", rule = %rule_name, action = "pass");
                    matched_rule = Some(rule_name);
                    matched_headers = logged_headers;
                }
                Action::Mangle => {
                    debug!(target: "rules", rule = %rule_name, action = "mangle");
                    matched_rule = Some(rule_name);
                    matched_headers = logged_headers;
                }
                Action::RateLimit {
                    requests,
                    window_secs,
                    key_expr,
                    mangle,
                } => {
                    // IP baseline check: prevent bypass by varying header values
                    if let Some(RateLimitResult::Limited { retry_after_secs }) = self
                        .check_ip_baseline(rule_name, key_expr, *requests, *window_secs, &eval_ctx)
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
                        return Self::build_response(
                            StatusCode::TOO_MANY_REQUESTS,
                            "Rate limit exceeded",
                            Some(retry_after_secs),
                        )
                        .into();
                    }

                    // Per-key rate limit check
                    match self.check_rate_limit(key_expr, *requests, *window_secs, &eval_ctx) {
                        RateLimitResult::Allowed { remaining } => {
                            if let Some(delay_ms) =
                                self.compute_throttle_delay(rule_name, remaining, *requests)
                            {
                                debug!(target: "ratelimit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                                tokio::time::sleep(std::time::Duration::from_millis(delay_ms))
                                    .await;
                            } else {
                                debug!(target: "ratelimit", rule = %rule_name, remaining);
                            }
                            if *mangle {
                                mangle_rules.push_name(rule_name);
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
                            return Self::build_response(
                                StatusCode::TOO_MANY_REQUESTS,
                                "Rate limit exceeded",
                                Some(retry_after_secs),
                            )
                            .into();
                        }
                    }
                }
                Action::Credit {
                    key_expr, mangle, ..
                } => {
                    let key = extract_key(key_expr, &eval_ctx);
                    let credit_result = self.credit_manager.check(rule_name, &key);
                    match credit_result {
                        CreditResult::Allowed { remaining } => {
                            debug!(target: "credit", rule = %rule_name, remaining);
                            if *mangle {
                                mangle_rules.push_name(rule_name);
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
                            if *mangle {
                                mangle_rules.push_name(rule_name);
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
                                .format_exhaustion_message(rule_name, &reset_time);
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
                            return Self::build_response(
                                StatusCode::TOO_MANY_REQUESTS,
                                &message,
                                Some(retry_after_secs),
                            )
                            .into();
                        }
                    }
                }
                Action::RateLimitCredit {
                    requests,
                    window_secs,
                    rate_key_expr,
                    credit_key_expr,
                    mangle,
                    ..
                } => {
                    // Step 0: IP baseline check (prevents header-flooding bypass)
                    if let Some(RateLimitResult::Limited { retry_after_secs }) = self
                        .check_ip_baseline(
                            rule_name,
                            rate_key_expr,
                            *requests,
                            *window_secs,
                            &eval_ctx,
                        )
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
                        return Self::build_response(
                            StatusCode::TOO_MANY_REQUESTS,
                            "Rate limit exceeded",
                            Some(retry_after_secs),
                        )
                        .into();
                    }

                    // Step 1: Per-key rate limit check (burst protection)
                    match self.check_rate_limit(rate_key_expr, *requests, *window_secs, &eval_ctx) {
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
                            return Self::build_response(
                                StatusCode::TOO_MANY_REQUESTS,
                                "Rate limit exceeded",
                                Some(retry_after_secs),
                            )
                            .into();
                        }
                        RateLimitResult::Allowed { remaining } => {
                            // Step 2: Credit check (budget enforcement)
                            let credit_key = extract_key(credit_key_expr, &eval_ctx);
                            let credit_result = self.credit_manager.check(rule_name, &credit_key);
                            match credit_result {
                                CreditResult::Exhausted {
                                    retry_after_secs,
                                    reset_time,
                                } => {
                                    let message = self
                                        .credit_manager
                                        .format_exhaustion_message(rule_name, &reset_time);
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
                                    return Self::build_response(
                                        StatusCode::TOO_MANY_REQUESTS,
                                        &message,
                                        Some(retry_after_secs),
                                    )
                                    .into();
                                }
                                CreditResult::Throttled {
                                    remaining: _,
                                    delay_ms: credit_delay,
                                } => {
                                    let rl_delay = self
                                        .compute_throttle_delay(rule_name, remaining, *requests)
                                        .unwrap_or(0);
                                    let max_delay = credit_delay.max(rl_delay);
                                    debug!(target: "proxy", rule = %rule_name, credit_delay, rl_delay, max_delay, "Composite throttle");
                                    tokio::time::sleep(std::time::Duration::from_millis(max_delay))
                                        .await;
                                    if *mangle {
                                        mangle_rules.push_name(rule_name);
                                    }
                                    matched_rule = Some(rule_name);
                                    matched_headers = logged_headers;
                                }
                                CreditResult::Allowed { remaining: _ } => {
                                    if let Some(delay_ms) =
                                        self.compute_throttle_delay(rule_name, remaining, *requests)
                                    {
                                        debug!(target: "ratelimit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                                        tokio::time::sleep(std::time::Duration::from_millis(
                                            delay_ms,
                                        ))
                                        .await;
                                    }
                                    if *mangle {
                                        mangle_rules.push_name(rule_name);
                                    }
                                    matched_rule = Some(rule_name);
                                    matched_headers = logged_headers;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            debug!(target: "rules", "No rules matched");
        }

        // Log the forwarded request before destructuring (host/path borrow from req)
        if matched_headers.is_empty() {
            info!(
                target: "proxy",
                method = %method,
                host = %host,
                path = %path,
                rule = ?matched_rule,
                action = "forward",
            );
        } else {
            info!(
                target: "proxy",
                method = %method,
                host = %host,
                path = %path,
                rule = ?matched_rule,
                action = "forward",
                headers = ?matched_headers
            );
        }

        // Apply header modifications for matched mangle rules
        let (mut parts, body) = req.into_parts();

        for rule_name in mangle_rules.iter() {
            if let Some(configs) = self.header_configs.get(rule_name) {
                for config in configs {
                    // Add headers (pre-parsed at startup, just clone name/value)
                    for header_add in &config.add {
                        parts
                            .headers
                            .insert(header_add.name.clone(), header_add.value.clone());
                        debug!(
                            target: "proxy",
                            rule = %rule_name,
                            header = %header_add.name,
                            "Added header"
                        );
                    }

                    // Remove headers (pre-parsed at startup)
                    for header_rm in &config.remove {
                        parts.headers.remove(&header_rm.name);
                        debug!(
                            target: "proxy",
                            rule = %rule_name,
                            header = %header_rm.name,
                            "Removed header"
                        );
                    }
                }
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
        assert_eq!(host.as_ref(), "example.com");
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
        assert_eq!(host.as_ref(), "api.example.com");
        assert_eq!(path, "/api/endpoint");
    }

    #[test]
    fn test_build_response_error() {
        let resp = RoxyHandler::build_response(StatusCode::FORBIDDEN, "Forbidden", None);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get("retry-after").is_none());
    }

    #[test]
    fn test_build_response_rate_limit() {
        let resp = RoxyHandler::build_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
            Some(60),
        );
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
