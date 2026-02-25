//! Hudsucker HttpHandler implementation.
//!
//! Implements the request processing pipeline:
//! handle_request → [rules evaluation] → [rate limiting] → [header mangle] → forward

use arc_swap::ArcSwap;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{Request, Response, StatusCode},
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};

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

/// Rate limit metadata to inject as X-RateLimit-* response headers.
#[derive(Clone, Debug, Default)]
struct RateLimitHeaders {
    /// Maximum requests allowed in the window
    limit: u64,
    /// Remaining requests in the current window
    remaining: u64,
    /// Seconds until the window resets
    reset_after_secs: u64,
}

/// Credit system metadata to inject as X-Credit-* response headers.
/// Separate from RateLimitHeaders to avoid collision when both systems apply.
#[derive(Clone, Debug, Default)]
struct CreditHeaders {
    /// Total credit budget
    limit: u64,
    /// Remaining credits
    remaining: u64,
    /// Seconds until credits reset
    reset_after_secs: u64,
}

/// Pre-parsed header mangle config (no per-request `.parse()` calls).
#[derive(Clone, Debug)]
struct ParsedMangleConfig {
    add: Vec<ParsedHeaderAdd>,
    remove: Vec<ParsedHeaderRemove>,
}

/// Hot-reloadable configuration bundle.
///
/// Bundles rules, header configs, and throttle configs into a single unit
/// that can be atomically swapped via `ArcSwap` without restarting the proxy.
/// Rate limiter and credit manager state is preserved across reloads.
pub struct SharedConfig {
    /// Compiled rule index
    pub(crate) rules: RuleIndex,
    /// Header mangle configurations keyed by rule name (pre-parsed)
    header_configs: HashMap<String, Vec<ParsedMangleConfig>>,
    /// Throttle configs indexed by rule name
    throttle_configs: HashMap<String, ThrottleConfig>,
}

impl SharedConfig {
    /// Build a new shared config from raw configuration.
    ///
    /// Pre-parses header names/values at construction time so the hot path
    /// only clones pre-validated `HeaderName`/`HeaderValue` values.
    pub fn new(
        rules: RuleIndex,
        header_configs: Vec<HeaderMangleConfig>,
        throttle_configs: Vec<ThrottleConfig>,
    ) -> Self {
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

        let throttle_by_rule: HashMap<String, ThrottleConfig> = throttle_configs
            .into_iter()
            .map(|c| (c.rule.clone(), c))
            .collect();

        Self {
            rules,
            header_configs: configs_by_rule,
            throttle_configs: throttle_by_rule,
        }
    }
}

/// Roxy HTTP handler implementing Hudsucker's HttpHandler trait.
#[derive(Clone)]
pub struct RoxyHandler {
    /// Hot-reloadable config (rules + headers + throttle).
    /// `ArcSwap::load()` is a single atomic load (~2ns on x86_64).
    config: Arc<ArcSwap<SharedConfig>>,

    /// Rate limiter (stateful — preserved across reloads)
    rate_limiter: Arc<RateLimiter>,

    /// Credit manager (stateful — preserved across reloads)
    credit_manager: Arc<CreditManager>,

    /// Per-request rate limit info to inject into the response.
    /// Set during handle_request, consumed by handle_response.
    pending_ratelimit_headers: Option<RateLimitHeaders>,

    /// Per-request credit info to inject into the response.
    /// Set during handle_request, consumed by handle_response.
    pending_credit_headers: Option<CreditHeaders>,
}

impl RoxyHandler {
    /// Create a new handler with the given configuration.
    ///
    /// Takes a shared config wrapped in `ArcSwap` for lock-free hot reload.
    /// Rate limiter and credit manager are stateful and preserved across reloads.
    pub fn new(
        config: Arc<ArcSwap<SharedConfig>>,
        rate_limiter: Arc<RateLimiter>,
        credit_manager: Arc<CreditManager>,
    ) -> Self {
        Self {
            config,
            rate_limiter,
            credit_manager,
            pending_ratelimit_headers: None,
            pending_credit_headers: None,
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
        Some(
            self.rate_limiter
                .check(ip_key.as_str(), requests, window_secs),
        )
    }

    /// Build an HTTP error/rejection response.
    ///
    /// If `retry_after` is `Some`, a `Retry-After` header is added (for 429s).
    /// If `rl_headers` is `Some`, X-RateLimit-* headers are injected.
    /// If `credit_headers` is `Some`, X-Credit-* headers are injected.
    fn build_response(
        status: StatusCode,
        message: &str,
        retry_after: Option<u64>,
        rl_headers: Option<&RateLimitHeaders>,
        credit_headers: Option<&CreditHeaders>,
    ) -> Response<Body> {
        let mut builder = Response::builder()
            .status(status)
            .header("Content-Type", "text/plain")
            .header("Content-Length", message.len());
        if let Some(secs) = retry_after {
            builder = builder.header("Retry-After", secs.to_string());
        }
        if let Some(rl) = rl_headers {
            builder = builder
                .header("X-RateLimit-Limit", rl.limit)
                .header("X-RateLimit-Remaining", rl.remaining)
                .header("X-RateLimit-Reset", rl.reset_after_secs);
        }
        if let Some(cr) = credit_headers {
            builder = builder
                .header("X-Credit-Limit", cr.limit)
                .header("X-Credit-Remaining", cr.remaining)
                .header("X-Credit-Reset", cr.reset_after_secs);
        }
        builder
            .body(Body::from(message.to_string()))
            .unwrap_or_else(|_| Response::new(Body::from("Internal proxy error")))
    }

    /// Compute progressive delay for rate limiting when a throttle config exists.
    /// Returns delay in ms if request count exceeds soft_limit.
    fn compute_throttle_delay(
        cfg: &SharedConfig,
        rule_name: &str,
        remaining: u64,
        max_requests: u64,
    ) -> Option<u64> {
        let throttle = cfg.throttle_configs.get(rule_name)?;
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
        // Load config snapshot once per request (single atomic load, ~2ns).
        // All rule evaluation and mangle lookups use this snapshot, ensuring
        // a consistent view even if config is swapped mid-request.
        let cfg = self.config.load();

        let method = req.method().clone();
        let (host, path) = Self::parse_request_info(&req);

        // Get client IP as IpAddr (no formatting unless needed)
        let client_ip = ctx.client_addr.ip();

        // Health endpoint: respond directly when the request targets the proxy
        // itself (origin-form URI with no authority), not when proxied through.
        if req.uri().authority().is_none() && path == "/healthz" {
            return Self::build_response(StatusCode::OK, "ok", None, None, None).into();
        }

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
        let result = cfg.rules.evaluate(&eval_ctx);
        let mut mangle_rules = cfg.rules.evaluate_mangle_rules(&eval_ctx);

        debug!(target: "rules", ?result, "Rule evaluation result");

        // Process rule result - collect info for single log at forward time
        let mut matched_rule: &str = "";
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
                    return Self::build_response(
                        StatusCode::FORBIDDEN,
                        "Not Allowed",
                        None,
                        None,
                        None,
                    )
                    .into();
                }
                Action::Pass => {
                    debug!(target: "rules", rule = %rule_name, action = "pass");
                    matched_rule = rule_name;
                    matched_headers = logged_headers;
                }
                Action::Mangle => {
                    debug!(target: "rules", rule = %rule_name, action = "mangle");
                    matched_rule = rule_name;
                    matched_headers = logged_headers;
                }
                Action::RateLimit {
                    requests,
                    window_secs,
                    key_expr,
                    mangle,
                } => {
                    // IP baseline check: prevent bypass by varying header values
                    if let Some(RateLimitResult::Limited {
                        retry_after_secs,
                        limit,
                    }) = self.check_ip_baseline(
                        rule_name,
                        key_expr,
                        *requests,
                        *window_secs,
                        &eval_ctx,
                    ) {
                        let rl = RateLimitHeaders {
                            limit,
                            remaining: 0,
                            reset_after_secs: retry_after_secs,
                        };
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
                            Some(&rl),
                            None,
                        )
                        .into();
                    }

                    // Per-key rate limit check
                    match self.check_rate_limit(key_expr, *requests, *window_secs, &eval_ctx) {
                        RateLimitResult::Allowed {
                            remaining,
                            limit,
                            reset_after_secs,
                        } => {
                            if let Some(delay_ms) =
                                Self::compute_throttle_delay(&cfg, rule_name, remaining, *requests)
                            {
                                debug!(target: "ratelimit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                                tokio::time::sleep(std::time::Duration::from_millis(delay_ms))
                                    .await;
                            } else {
                                debug!(target: "ratelimit", rule = %rule_name, remaining);
                            }
                            self.pending_ratelimit_headers = Some(RateLimitHeaders {
                                limit,
                                remaining,
                                reset_after_secs,
                            });
                            if *mangle {
                                mangle_rules.push_name(rule_name);
                            }
                            matched_rule = rule_name;
                            matched_headers = logged_headers;
                        }
                        RateLimitResult::Limited {
                            retry_after_secs,
                            limit,
                        } => {
                            let rl = RateLimitHeaders {
                                limit,
                                remaining: 0,
                                reset_after_secs: retry_after_secs,
                            };
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
                                Some(&rl),
                                None,
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
                        CreditResult::Allowed {
                            remaining,
                            limit,
                            reset_after_secs,
                        } => {
                            debug!(target: "credit", rule = %rule_name, remaining);
                            self.pending_credit_headers = Some(CreditHeaders {
                                limit,
                                remaining,
                                reset_after_secs,
                            });
                            if *mangle {
                                mangle_rules.push_name(rule_name);
                            }
                            matched_rule = rule_name;
                            matched_headers = logged_headers;
                        }
                        CreditResult::Throttled {
                            remaining,
                            delay_ms,
                            limit,
                            reset_after_secs,
                        } => {
                            debug!(target: "credit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            self.pending_credit_headers = Some(CreditHeaders {
                                limit,
                                remaining,
                                reset_after_secs,
                            });
                            if *mangle {
                                mangle_rules.push_name(rule_name);
                            }
                            matched_rule = rule_name;
                            matched_headers = logged_headers;
                        }
                        CreditResult::Exhausted {
                            retry_after_secs,
                            reset_time,
                            limit,
                            reset_after_secs,
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
                            let exhausted_headers = CreditHeaders {
                                limit,
                                remaining: 0,
                                reset_after_secs,
                            };
                            return Self::build_response(
                                StatusCode::TOO_MANY_REQUESTS,
                                &message,
                                Some(retry_after_secs),
                                None,
                                Some(&exhausted_headers),
                            )
                            .into();
                        }
                        CreditResult::NotConfigured => {
                            error!(
                                target: "proxy",
                                rule = %rule_name,
                                "Credit rule not configured in credit manager — check config.credits"
                            );
                            if *mangle {
                                mangle_rules.push_name(rule_name);
                            }
                            matched_rule = rule_name;
                            matched_headers = logged_headers;
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
                    if let Some(RateLimitResult::Limited {
                        retry_after_secs,
                        limit,
                    }) = self.check_ip_baseline(
                        rule_name,
                        rate_key_expr,
                        *requests,
                        *window_secs,
                        &eval_ctx,
                    ) {
                        let rl = RateLimitHeaders {
                            limit,
                            remaining: 0,
                            reset_after_secs: retry_after_secs,
                        };
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
                            Some(&rl),
                            None,
                        )
                        .into();
                    }

                    // Step 1: Per-key rate limit check (burst protection)
                    match self.check_rate_limit(rate_key_expr, *requests, *window_secs, &eval_ctx) {
                        RateLimitResult::Limited {
                            retry_after_secs,
                            limit,
                        } => {
                            let rl = RateLimitHeaders {
                                limit,
                                remaining: 0,
                                reset_after_secs: retry_after_secs,
                            };
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
                                Some(&rl),
                                None,
                            )
                            .into();
                        }
                        RateLimitResult::Allowed {
                            remaining,
                            limit,
                            reset_after_secs,
                        } => {
                            // Store rate limit headers (separate from credit)
                            self.pending_ratelimit_headers = Some(RateLimitHeaders {
                                limit,
                                remaining,
                                reset_after_secs,
                            });

                            // Step 2: Credit check (budget enforcement)
                            let credit_key = extract_key(credit_key_expr, &eval_ctx);
                            let credit_result = self.credit_manager.check(rule_name, &credit_key);
                            match credit_result {
                                CreditResult::Exhausted {
                                    retry_after_secs,
                                    reset_time,
                                    limit: credit_limit,
                                    reset_after_secs: credit_reset,
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
                                    let exhausted_headers = CreditHeaders {
                                        limit: credit_limit,
                                        remaining: 0,
                                        reset_after_secs: credit_reset,
                                    };
                                    return Self::build_response(
                                        StatusCode::TOO_MANY_REQUESTS,
                                        &message,
                                        Some(retry_after_secs),
                                        self.pending_ratelimit_headers.as_ref(),
                                        Some(&exhausted_headers),
                                    )
                                    .into();
                                }
                                CreditResult::Throttled {
                                    remaining: credit_remaining,
                                    delay_ms: credit_delay,
                                    limit: credit_limit,
                                    reset_after_secs: credit_reset,
                                } => {
                                    // Store credit headers separately from rate limit
                                    self.pending_credit_headers = Some(CreditHeaders {
                                        limit: credit_limit,
                                        remaining: credit_remaining,
                                        reset_after_secs: credit_reset,
                                    });
                                    let rl_delay = Self::compute_throttle_delay(
                                        &cfg, rule_name, remaining, *requests,
                                    )
                                    .unwrap_or(0);
                                    let max_delay = credit_delay.max(rl_delay);
                                    debug!(target: "proxy", rule = %rule_name, credit_delay, rl_delay, max_delay, "Composite throttle");
                                    tokio::time::sleep(std::time::Duration::from_millis(max_delay))
                                        .await;
                                    if *mangle {
                                        mangle_rules.push_name(rule_name);
                                    }
                                    matched_rule = rule_name;
                                    matched_headers = logged_headers;
                                }
                                CreditResult::Allowed {
                                    remaining: credit_remaining,
                                    limit: credit_limit,
                                    reset_after_secs: credit_reset,
                                } => {
                                    // Store credit headers separately from rate limit
                                    self.pending_credit_headers = Some(CreditHeaders {
                                        limit: credit_limit,
                                        remaining: credit_remaining,
                                        reset_after_secs: credit_reset,
                                    });
                                    if let Some(delay_ms) = Self::compute_throttle_delay(
                                        &cfg, rule_name, remaining, *requests,
                                    ) {
                                        debug!(target: "ratelimit", rule = %rule_name, remaining, delay_ms, "Throttling (soft limit)");
                                        tokio::time::sleep(std::time::Duration::from_millis(
                                            delay_ms,
                                        ))
                                        .await;
                                    }
                                    if *mangle {
                                        mangle_rules.push_name(rule_name);
                                    }
                                    matched_rule = rule_name;
                                    matched_headers = logged_headers;
                                }
                                CreditResult::NotConfigured => {
                                    error!(
                                        target: "proxy",
                                        rule = %rule_name,
                                        "Credit rule not configured in credit manager — check config.credits"
                                    );
                                    if *mangle {
                                        mangle_rules.push_name(rule_name);
                                    }
                                    matched_rule = rule_name;
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
        if matched_rule.is_empty() {
            info!(
                target: "proxy",
                method = %method,
                host = %host,
                path = %path,
                action = "forward",
            );
        } else if matched_headers.is_empty() {
            info!(
                target: "proxy",
                method = %method,
                host = %host,
                path = %path,
                rule = %matched_rule,
                action = "forward",
            );
        } else {
            info!(
                target: "proxy",
                method = %method,
                host = %host,
                path = %path,
                rule = %matched_rule,
                action = "forward",
                headers = ?matched_headers
            );
        }

        // Apply header modifications for matched mangle rules
        let (mut parts, body) = req.into_parts();

        for rule_name in mangle_rules.iter() {
            if let Some(configs) = cfg.header_configs.get(rule_name) {
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
        let has_rl = self.pending_ratelimit_headers.is_some();
        let has_credit = self.pending_credit_headers.is_some();

        if !has_rl && !has_credit {
            return res;
        }

        let (mut parts, body) = res.into_parts();

        // Inject X-RateLimit-* headers (sliding window burst limiter)
        if let Some(rl) = self.pending_ratelimit_headers.take() {
            parts.headers.insert("X-RateLimit-Limit", rl.limit.into());
            parts
                .headers
                .insert("X-RateLimit-Remaining", rl.remaining.into());
            parts
                .headers
                .insert("X-RateLimit-Reset", rl.reset_after_secs.into());
        }

        // Inject X-Credit-* headers (budget/quota system)
        if let Some(cr) = self.pending_credit_headers.take() {
            parts.headers.insert("X-Credit-Limit", cr.limit.into());
            parts
                .headers
                .insert("X-Credit-Remaining", cr.remaining.into());
            parts
                .headers
                .insert("X-Credit-Reset", cr.reset_after_secs.into());
        }

        Response::from_parts(parts, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HeaderAddConfig, HeaderMangleConfig, RuleConfig, ThrottleConfig};
    use crate::ratelimit::RateLimiter;
    use crate::rules::RuleIndex;
    use std::time::Duration;

    /// Construct an HttpContext for testing.
    /// HttpContext is #[non_exhaustive] in hudsucker, so it cannot be constructed
    /// normally from outside that crate. We use MaybeUninit to write the single
    /// public field.
    fn make_http_ctx(addr: std::net::SocketAddr) -> HttpContext {
        unsafe {
            let mut ctx = std::mem::MaybeUninit::<HttpContext>::uninit();
            let ptr = ctx.as_mut_ptr();
            std::ptr::addr_of_mut!((*ptr).client_addr).write(addr);
            ctx.assume_init()
        }
    }

    fn test_addr() -> std::net::SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    fn make_handler_with_rules(rule_configs: Vec<RuleConfig>) -> RoxyHandler {
        let index = RuleIndex::from_config(&rule_configs).expect("rules should parse");
        make_handler(index, vec![], vec![])
    }

    /// Build a handler from a RuleIndex with optional header/throttle configs.
    fn make_handler(
        index: RuleIndex,
        header_configs: Vec<HeaderMangleConfig>,
        throttle_configs: Vec<ThrottleConfig>,
    ) -> RoxyHandler {
        let shared = SharedConfig::new(index, header_configs, throttle_configs);
        let config = Arc::new(ArcSwap::from_pointee(shared));
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_secs(60)));
        let credit_manager = Arc::new(CreditManager::new());
        RoxyHandler::new(config, rate_limiter, credit_manager)
    }

    /// Build a handler with a custom credit manager (for pre-registered credit rules).
    fn make_handler_with_credits(
        index: RuleIndex,
        credit_manager: Arc<CreditManager>,
        header_configs: Vec<HeaderMangleConfig>,
        throttle_configs: Vec<ThrottleConfig>,
    ) -> RoxyHandler {
        let shared = SharedConfig::new(index, header_configs, throttle_configs);
        let config = Arc::new(ArcSwap::from_pointee(shared));
        let rate_limiter = Arc::new(RateLimiter::new(Duration::from_secs(60)));
        RoxyHandler::new(config, rate_limiter, credit_manager)
    }

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
        let resp =
            RoxyHandler::build_response(StatusCode::FORBIDDEN, "Forbidden", None, None, None);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get("retry-after").is_none());
    }

    #[test]
    fn test_build_response_rate_limit() {
        let rl = RateLimitHeaders {
            limit: 100,
            remaining: 0,
            reset_after_secs: 60,
        };
        let resp = RoxyHandler::build_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
            Some(60),
            Some(&rl),
            None,
        );
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "60");
        assert_eq!(resp.headers().get("X-RateLimit-Limit").unwrap(), "100");
        assert_eq!(resp.headers().get("X-RateLimit-Remaining").unwrap(), "0");
        assert_eq!(resp.headers().get("X-RateLimit-Reset").unwrap(), "60");
    }

    #[test]
    fn test_handler_creation() {
        let handler = make_handler(RuleIndex::new(), vec![], vec![]);

        let cfg = handler.config.load();
        assert!(cfg.header_configs.is_empty());
        assert!(cfg.throttle_configs.is_empty());
        assert!(handler.pending_ratelimit_headers.is_none());
        assert!(handler.pending_credit_headers.is_none());
    }

    #[test]
    fn test_build_response_no_rl_headers() {
        let resp = RoxyHandler::build_response(StatusCode::OK, "ok", None, None, None);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("X-RateLimit-Limit").is_none());
        assert!(resp.headers().get("X-RateLimit-Remaining").is_none());
        assert!(resp.headers().get("X-RateLimit-Reset").is_none());
    }

    #[test]
    fn test_parse_request_info_no_host() {
        let req = Request::builder().uri("/path").body(()).unwrap();
        let (host, path) = RoxyHandler::parse_request_info(&req);
        assert_eq!(host.as_ref(), "localhost");
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_request_info_host_no_port() {
        let req = Request::builder()
            .uri("/path")
            .header("host", "example.com")
            .body(())
            .unwrap();
        let (host, path) = RoxyHandler::parse_request_info(&req);
        assert_eq!(host.as_ref(), "example.com");
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_compute_throttle_delay_no_config() {
        let handler = make_handler(RuleIndex::new(), vec![], vec![]);
        let cfg = handler.config.load();
        assert!(RoxyHandler::compute_throttle_delay(&cfg, "nonexistent", 50, 100).is_none());
    }

    #[test]
    fn test_compute_throttle_delay_under_soft_limit() {
        use crate::config::ThrottleConfig;
        let throttle = vec![ThrottleConfig {
            rule: "test-rule".to_string(),
            soft_limit: 50,
            max_delay_ms: 1000,
        }];
        let handler = make_handler(RuleIndex::new(), vec![], throttle);
        let cfg = handler.config.load();
        // 60 remaining out of 100 means 40 used, under soft_limit of 50
        assert!(RoxyHandler::compute_throttle_delay(&cfg, "test-rule", 60, 100).is_none());
    }

    #[test]
    fn test_compute_throttle_delay_over_soft_limit() {
        use crate::config::ThrottleConfig;
        let throttle = vec![ThrottleConfig {
            rule: "test-rule".to_string(),
            soft_limit: 50,
            max_delay_ms: 1000,
        }];
        let handler = make_handler(RuleIndex::new(), vec![], throttle);
        let cfg = handler.config.load();
        // 25 remaining out of 100 means 75 used, 25 over soft_limit of 50
        let delay = RoxyHandler::compute_throttle_delay(&cfg, "test-rule", 25, 100).unwrap();
        assert_eq!(delay, 500); // 25/50 * 1000 = 500
    }

    // === Coverage: handler creation with header configs ===

    #[test]
    fn test_handler_with_header_configs() {
        use crate::config::{HeaderAddConfig, HeaderMangleConfig};

        let header_configs = vec![HeaderMangleConfig {
            rules: vec!["rule-a".to_string(), "rule-b".to_string()],
            add: vec![HeaderAddConfig {
                name: "X-Added".to_string(),
                value: "true".to_string(),
            }],
            remove: vec!["X-Internal".to_string()],
        }];

        let handler = make_handler(RuleIndex::new(), header_configs, vec![]);

        let cfg = handler.config.load();
        // Both rule names should be indexed
        assert!(cfg.header_configs.contains_key("rule-a"));
        assert!(cfg.header_configs.contains_key("rule-b"));

        // Verify parsed configs
        let configs_a = cfg.header_configs.get("rule-a").unwrap();
        assert_eq!(configs_a.len(), 1);
        assert_eq!(configs_a[0].add.len(), 1);
        assert_eq!(configs_a[0].remove.len(), 1);
    }

    #[test]
    fn test_handler_with_throttle_configs() {
        use crate::config::ThrottleConfig;

        let throttle = vec![ThrottleConfig {
            rule: "rate-rule".to_string(),
            soft_limit: 80,
            max_delay_ms: 2000,
        }];

        let handler = make_handler(RuleIndex::new(), vec![], throttle);
        let cfg = handler.config.load();
        assert!(cfg.throttle_configs.contains_key("rate-rule"));
    }

    #[test]
    fn test_compute_throttle_delay_at_exact_soft_limit() {
        use crate::config::ThrottleConfig;
        let throttle = vec![ThrottleConfig {
            rule: "test-rule".to_string(),
            soft_limit: 50,
            max_delay_ms: 1000,
        }];
        let handler = make_handler(RuleIndex::new(), vec![], throttle);
        let cfg = handler.config.load();
        // 50 remaining out of 100 means 50 used, exactly at soft_limit
        assert!(RoxyHandler::compute_throttle_delay(&cfg, "test-rule", 50, 100).is_none());
    }

    #[test]
    fn test_compute_throttle_delay_zero_range() {
        use crate::config::ThrottleConfig;
        let throttle = vec![ThrottleConfig {
            rule: "test-rule".to_string(),
            soft_limit: 99,
            max_delay_ms: 500,
        }];
        let handler = make_handler(RuleIndex::new(), vec![], throttle);
        let cfg = handler.config.load();
        // max_requests = 100, soft_limit = 99 → range = 1
        // remaining = 0 → used = 100, over = 100 - 99 = 1
        // delay = 1/1 * 500 = 500
        let delay = RoxyHandler::compute_throttle_delay(&cfg, "test-rule", 0, 100).unwrap();
        assert_eq!(delay, 500);
    }

    // === Async handler tests (exercising handle_request pipeline) ===

    #[tokio::test]
    async fn test_handle_request_healthz() {
        let mut handler = make_handler_with_rules(vec![]);
        let http_ctx = make_http_ctx(test_addr());
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
            }
            _ => panic!("Expected direct response for /healthz"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_connect_passthrough() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "block-all".to_string(),
            rule: r#"host("*") = block"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());
        let req = Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.method(), http::Method::CONNECT);
            }
            _ => panic!("CONNECT should be passed through without rule evaluation"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_block_rule() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "block-internal".to_string(),
            rule: r#"host("*.internal") = block"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());
        let req = Request::builder()
            .uri("http://secret.internal/api")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected 403 response for blocked host"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_pass_rule() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "allow-api".to_string(),
            rule: r#"host("api.*") = pass"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());
        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.uri().path(), "/data");
            }
            _ => panic!("Expected request to be forwarded"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_no_rules_match() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "only-internal".to_string(),
            rule: r#"host("*.internal") = block"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());
        let req = Request::builder()
            .uri("http://public.com/page")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.uri().host(), Some("public.com"));
            }
            _ => panic!("Expected request to be forwarded (no rules matched)"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_ternary_else_block() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "require-auth".to_string(),
            rule: r#"header("X-Auth") = pass : block"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());

        // Without X-Auth header → should block (else action)
        let req = Request::builder()
            .uri("http://example.com/api")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected 403 when header missing"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_ternary_pass_with_header() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "require-auth".to_string(),
            rule: r#"header("X-Auth") = pass : block"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());

        // With X-Auth header → should pass
        let req = Request::builder()
            .uri("http://example.com/api")
            .header("X-Auth", "token")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(_) => {} // forwarded, good
            _ => panic!("Expected request to be forwarded when header present"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_rate_limit_allows() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "rate-api".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, ip)"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());
        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(_) => {
                assert!(handler.pending_ratelimit_headers.is_some());
            }
            _ => panic!("Expected request to be forwarded (rate limit allows)"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_rate_limit_exhausted() {
        let rules = vec![RuleConfig {
            name: "rate-api".to_string(),
            rule: r#"host("api.*") = rate_limit(2/s, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let mut handler = make_handler(index, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exhaust the rate limit
        for _ in 0..3 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        // This one should be rate limited
        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                assert!(resp.headers().get("retry-after").is_some());
                assert!(resp.headers().get("X-RateLimit-Limit").is_some());
            }
            _ => panic!("Expected 429 response after rate limit exhausted"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_mangle_adds_headers() {
        let rules = vec![RuleConfig {
            name: "mangle-rule".to_string(),
            rule: r#"host("api.*") = mangle"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let header_configs = vec![HeaderMangleConfig {
            rules: vec!["mangle-rule".to_string()],
            add: vec![HeaderAddConfig {
                name: "X-Proxy-Processed".to_string(),
                value: "true".to_string(),
            }],
            remove: vec!["X-Internal".to_string()],
        }];
        let mut handler = make_handler(index, header_configs, vec![]);
        let http_ctx = make_http_ctx(test_addr());

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .header("X-Internal", "secret")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.headers().get("X-Proxy-Processed").unwrap(), "true");
                assert!(
                    r.headers().get("X-Internal").is_none(),
                    "X-Internal should be removed"
                );
            }
            _ => panic!("Expected request to be forwarded with modified headers"),
        }
    }

    #[tokio::test]
    async fn test_handle_response_injects_ratelimit_headers() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "rate-api".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, ip)"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());

        // First, handle a request to set pending_ratelimit_headers
        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        handler.handle_request(&http_ctx, req).await;

        // Now handle the response — should inject X-RateLimit-* headers
        let resp = Response::builder().status(200).body(Body::empty()).unwrap();
        let result = handler.handle_response(&http_ctx, resp).await;
        assert!(result.headers().get("X-RateLimit-Limit").is_some());
        assert!(result.headers().get("X-RateLimit-Remaining").is_some());
        assert!(result.headers().get("X-RateLimit-Reset").is_some());
    }

    #[tokio::test]
    async fn test_handle_response_no_ratelimit_headers() {
        let mut handler = make_handler_with_rules(vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // No rate limit was applied, so no headers should be injected
        let resp = Response::builder().status(200).body(Body::empty()).unwrap();
        let result = handler.handle_response(&http_ctx, resp).await;
        assert!(result.headers().get("X-RateLimit-Limit").is_none());
    }

    #[tokio::test]
    async fn test_handle_request_rate_limit_with_header_key() {
        let mut handler = make_handler_with_rules(vec![RuleConfig {
            name: "rate-by-header".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, header(X-Customer-Id))"#.to_string(),
        }]);
        let http_ctx = make_http_ctx(test_addr());

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .header("X-Customer-Id", "customer-1")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(_) => {
                // IP baseline check + per-key check both passed
                assert!(handler.pending_ratelimit_headers.is_some());
            }
            _ => panic!("Expected request to be forwarded"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_credit_allows() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "credit-rule".to_string(),
            rule: r#"host("api.*") = credit(1000/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "credit-rule".to_string(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(_) => {
                assert!(handler.pending_credit_headers.is_some());
            }
            _ => panic!("Expected request to be forwarded (credit allows)"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_credit_exhausted() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "credit-rule".to_string(),
            rule: r#"host("api.*") = credit(2/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "credit-rule".to_string(),
            CreditRuleConfig {
                budget: 2,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "Credits exhausted until {reset_time}".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exhaust credits
        for _ in 0..3 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        // This should be rejected
        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected 429 response when credits exhausted"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_rate_limit_with_mangle() {
        let rules = vec![RuleConfig {
            name: "rl-mangle".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, ip) + mangle"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let header_configs = vec![HeaderMangleConfig {
            rules: vec!["rl-mangle".to_string()],
            add: vec![HeaderAddConfig {
                name: "X-Rate-Limited".to_string(),
                value: "attached".to_string(),
            }],
            remove: vec![],
        }];
        let mut handler = make_handler(index, header_configs, vec![]);
        let http_ctx = make_http_ctx(test_addr());

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.headers().get("X-Rate-Limited").unwrap(), "attached");
            }
            _ => panic!("Expected forwarded request with mangle headers"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_composite_rate_limit_credit() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "composite-rule".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, ip) + credit(1000/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "composite-rule".to_string(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(_) => {
                assert!(handler.pending_ratelimit_headers.is_some());
                assert!(handler.pending_credit_headers.is_some());
            }
            _ => panic!("Expected forwarded request (composite allows)"),
        }
    }

    // === Coverage: IP baseline exhaustion for rate_limit with header key ===

    #[tokio::test]
    async fn test_handle_request_rate_limit_ip_baseline_exhausted() {
        let rules = vec![RuleConfig {
            name: "rl-header".to_string(),
            rule: r#"host("api.*") = rate_limit(2/s, header(X-Id))"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let mut handler = make_handler(index, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exhaust IP baseline (limit=2/s) by varying header values
        for i in 0..3 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .header("X-Id", format!("user-{i}"))
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .header("X-Id", "user-new")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected 429 from IP baseline"),
        }
    }

    // === Coverage: rate_limit allowed + throttle (soft limit exceeded) ===

    #[tokio::test]
    async fn test_handle_request_rate_limit_throttled() {
        let rules = vec![RuleConfig {
            name: "rl-throttle".to_string(),
            rule: r#"host("api.*") = rate_limit(10/s, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let throttle = vec![ThrottleConfig {
            rule: "rl-throttle".to_string(),
            soft_limit: 2,
            max_delay_ms: 10, // small to keep test fast
        }];
        let mut handler = make_handler(index, vec![], throttle);
        let http_ctx = make_http_ctx(test_addr());

        // Send 5 requests to exceed soft_limit of 2
        for _ in 0..5 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        // Should still be allowed (throttled, not rejected)
        assert!(handler.pending_ratelimit_headers.is_some());
    }

    // === Coverage: credit allowed with mangle ===

    #[tokio::test]
    async fn test_handle_request_credit_allowed_with_mangle() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "credit-mangle".to_string(),
            rule: r#"host("api.*") = credit(1000/d, ip) + mangle"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "credit-mangle".to_string(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let header_configs = vec![HeaderMangleConfig {
            rules: vec!["credit-mangle".to_string()],
            add: vec![HeaderAddConfig {
                name: "X-Credit".to_string(),
                value: "ok".to_string(),
            }],
            remove: vec![],
        }];
        let mut handler = make_handler_with_credits(index, credit_manager, header_configs, vec![]);
        let http_ctx = make_http_ctx(test_addr());

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.headers().get("X-Credit").unwrap(), "ok");
            }
            _ => panic!("Expected forwarded request with mangle header"),
        }
    }

    // === Coverage: credit throttled (soft limit exceeded) ===

    #[tokio::test]
    async fn test_handle_request_credit_throttled() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "credit-throttle".to_string(),
            rule: r#"host("api.*") = credit(10/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "credit-throttle".to_string(),
            CreditRuleConfig {
                budget: 10,
                soft_limit: Some(2),
                max_delay_ms: 10, // small to keep test fast
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Send 5 requests — first 2 under soft_limit, next 3 throttled
        for _ in 0..5 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        assert!(handler.pending_credit_headers.is_some());
    }

    // === Coverage: credit throttled with mangle ===

    #[tokio::test]
    async fn test_handle_request_credit_throttled_with_mangle() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "credit-thr-m".to_string(),
            rule: r#"host("api.*") = credit(10/d, ip) + mangle"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "credit-thr-m".to_string(),
            CreditRuleConfig {
                budget: 10,
                soft_limit: Some(2),
                max_delay_ms: 10,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let header_configs = vec![HeaderMangleConfig {
            rules: vec!["credit-thr-m".to_string()],
            add: vec![HeaderAddConfig {
                name: "X-Throttled".to_string(),
                value: "yes".to_string(),
            }],
            remove: vec![],
        }];
        let mut handler = make_handler_with_credits(index, credit_manager, header_configs, vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exceed soft_limit
        for _ in 0..5 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.headers().get("X-Throttled").unwrap(), "yes");
            }
            _ => panic!("Expected forwarded request with mangle header"),
        }
    }

    // === Coverage: RateLimitCredit — IP baseline exhausted ===

    #[tokio::test]
    async fn test_handle_request_rlc_ip_baseline_exhausted() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "rlc-ip".to_string(),
            rule: r#"host("api.*") = rate_limit(2/s, header(X-Id)) + credit(1000/d, ip)"#
                .to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "rlc-ip".to_string(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exhaust IP baseline (2/s) by varying header values
        for i in 0..3 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .header("X-Id", format!("user-{i}"))
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .header("X-Id", "user-new")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected 429 from RLC IP baseline"),
        }
    }

    // === Coverage: RateLimitCredit — per-key rate limit exhausted ===

    #[tokio::test]
    async fn test_handle_request_rlc_rate_limited() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "rlc-rl".to_string(),
            rule: r#"host("api.*") = rate_limit(2/s, ip) + credit(1000/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "rlc-rl".to_string(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exhaust per-key rate limit (2/s by ip)
        for _ in 0..3 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected 429 from RLC per-key rate limit"),
        }
    }

    // === Coverage: RateLimitCredit — credit exhausted after rate limit passes ===

    #[tokio::test]
    async fn test_handle_request_rlc_credit_exhausted() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "rlc-cx".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, ip) + credit(2/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "rlc-cx".to_string(),
            CreditRuleConfig {
                budget: 2,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "Credits exhausted until {reset_time}".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exhaust credits (budget=2)
        for _ in 0..3 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }
            _ => panic!("Expected 429 from RLC credit exhausted"),
        }
    }

    // === Coverage: RateLimitCredit — credit throttled (composite throttle) ===

    #[tokio::test]
    async fn test_handle_request_rlc_credit_throttled() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "rlc-ct".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, ip) + credit(10/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "rlc-ct".to_string(),
            CreditRuleConfig {
                budget: 10,
                soft_limit: Some(2),
                max_delay_ms: 10,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exceed credit soft_limit of 2
        for _ in 0..5 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        // Should still be allowed (throttled, not exhausted)
        assert!(handler.pending_ratelimit_headers.is_some());
        assert!(handler.pending_credit_headers.is_some());
    }

    // === Coverage: RateLimitCredit — credit throttled with mangle ===

    #[tokio::test]
    async fn test_handle_request_rlc_credit_throttled_with_mangle() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "rlc-ctm".to_string(),
            rule: r#"host("api.*") = rate_limit(100/s, ip) + credit(10/d, ip) + mangle"#
                .to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "rlc-ctm".to_string(),
            CreditRuleConfig {
                budget: 10,
                soft_limit: Some(2),
                max_delay_ms: 10,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let header_configs = vec![HeaderMangleConfig {
            rules: vec!["rlc-ctm".to_string()],
            add: vec![HeaderAddConfig {
                name: "X-Composite".to_string(),
                value: "yes".to_string(),
            }],
            remove: vec![],
        }];
        let mut handler = make_handler_with_credits(index, credit_manager, header_configs, vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exceed credit soft_limit
        for _ in 0..5 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.headers().get("X-Composite").unwrap(), "yes");
            }
            _ => panic!("Expected forwarded request with mangle header"),
        }
    }

    // === Coverage: RateLimitCredit — credit allowed + RL throttle ===

    #[tokio::test]
    async fn test_handle_request_rlc_credit_allowed_rl_throttled() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "rlc-art".to_string(),
            rule: r#"host("api.*") = rate_limit(10/s, ip) + credit(1000/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "rlc-art".to_string(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let throttle = vec![ThrottleConfig {
            rule: "rlc-art".to_string(),
            soft_limit: 2,
            max_delay_ms: 10, // small to keep test fast
        }];
        let mut handler = make_handler_with_credits(index, credit_manager, vec![], throttle);
        let http_ctx = make_http_ctx(test_addr());

        // Send 5 requests to exceed RL soft_limit of 2
        for _ in 0..5 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        // Credit ok, RL throttled
        assert!(handler.pending_ratelimit_headers.is_some());
        assert!(handler.pending_credit_headers.is_some());
    }

    // === Coverage: RateLimitCredit — credit allowed + RL throttle + mangle ===

    #[tokio::test]
    async fn test_handle_request_rlc_credit_allowed_rl_throttled_mangle() {
        use crate::ratelimit::CreditRuleConfig;
        use crate::ratelimit::ResetSchedule;

        let rules = vec![RuleConfig {
            name: "rlc-artm".to_string(),
            rule: r#"host("api.*") = rate_limit(10/s, ip) + credit(1000/d, ip) + mangle"#
                .to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let credit_manager = Arc::new(CreditManager::new());
        credit_manager.register_rule(
            "rlc-artm".to_string(),
            CreditRuleConfig {
                budget: 1000,
                soft_limit: None,
                max_delay_ms: 0,
                schedule: ResetSchedule::Daily { hour: 0, minute: 0 },
                message: "exhausted".to_string(),
            },
        );
        let throttle = vec![ThrottleConfig {
            rule: "rlc-artm".to_string(),
            soft_limit: 2,
            max_delay_ms: 10,
        }];
        let header_configs = vec![HeaderMangleConfig {
            rules: vec!["rlc-artm".to_string()],
            add: vec![HeaderAddConfig {
                name: "X-RLC".to_string(),
                value: "throttled".to_string(),
            }],
            remove: vec![],
        }];
        let mut handler =
            make_handler_with_credits(index, credit_manager, header_configs, throttle);
        let http_ctx = make_http_ctx(test_addr());

        // Exceed RL soft_limit
        for _ in 0..5 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Request(r) => {
                assert_eq!(r.headers().get("X-RLC").unwrap(), "throttled");
            }
            _ => panic!("Expected forwarded request with mangle header"),
        }
    }

    // === Coverage: rate_limit per-key Limited (not IP baseline) ===

    #[tokio::test]
    async fn test_handle_request_rate_limit_per_key_limited() {
        let rules = vec![RuleConfig {
            name: "rl-pk".to_string(),
            rule: r#"host("api.*") = rate_limit(2/s, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let mut handler = make_handler(index, vec![], vec![]);
        let http_ctx = make_http_ctx(test_addr());

        // Exhaust per-key limit (2/s by ip, no header extractor → no IP baseline)
        for _ in 0..3 {
            let req = Request::builder()
                .uri("http://api.example.com/data")
                .body(Body::empty())
                .unwrap();
            handler.handle_request(&http_ctx, req).await;
        }

        let req = Request::builder()
            .uri("http://api.example.com/data")
            .body(Body::empty())
            .unwrap();
        let result = handler.handle_request(&http_ctx, req).await;
        match result {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                assert!(resp.headers().get("X-RateLimit-Limit").is_some());
            }
            _ => panic!("Expected 429 from per-key rate limit"),
        }
    }
}
