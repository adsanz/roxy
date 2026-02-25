//! Method-indexed rule engine for efficient evaluation.
//!
//! Rules are indexed by HTTP method for O(1) lookup of relevant rules.
//! Rules without a method filter go in the `None` bucket and are always checked.

use http::Method;
use std::collections::HashMap;
use std::fmt;

use crate::config::RuleConfig;
use crate::error::ParseError;
use crate::rules::ast::*;
use crate::rules::parser::parse_rule;

/// Maximum number of mangle rule matches stored on the stack.
const MAX_MANGLE_MATCHES: usize = 4;

/// Result of rule evaluation: the matched action plus metadata.
///
/// Wraps `Action` with the rule name and any logged headers, avoiding
/// duplication of those fields across every action variant.
/// `None` means no rules matched.
///
/// Borrows from the `RuleIndex` (`'idx`) and request headers (`'req`) separately
/// to avoid per-request allocation while allowing the request to be consumed
/// before mangle-rule iteration.
#[derive(Debug)]
pub struct RuleMatch<'idx, 'req> {
    /// Name of the rule that matched (borrowed from RuleIndex)
    pub rule_name: &'idx str,
    /// Headers to log (existence-only checks with their values).
    /// Borrows key from CompiledRule.logged_header_names and value from request HeaderMap.
    /// Zero heap allocation — no HashMap or String cloning.
    pub logged_headers: LoggedHeaders<'req>,
    /// The action to take (borrowed from RuleIndex)
    pub action: &'idx Action,
}

/// Zero-allocation container for logged header key-value pairs.
///
/// Stores up to `MAX_LOGGED_HEADERS` pairs on the stack. Borrows both
/// keys (from CompiledRule) and values (from request HeaderMap).
/// Rules referencing more headers than this cap will have truncated logging.
const MAX_LOGGED_HEADERS: usize = 8;

pub struct LoggedHeaders<'a> {
    entries: [Option<(&'a str, &'a str)>; MAX_LOGGED_HEADERS],
    count: usize,
}

impl<'a> LoggedHeaders<'a> {
    fn new() -> Self {
        Self {
            entries: [None; MAX_LOGGED_HEADERS],
            count: 0,
        }
    }

    fn push(&mut self, key: &'a str, value: &'a str) {
        if self.count < MAX_LOGGED_HEADERS {
            self.entries[self.count] = Some((key, value));
            self.count += 1;
        }
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the number of logged headers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Look up a header value by name (for testing/logging).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
    }

    /// Iterate over logged header pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries[..self.count].iter().filter_map(|e| *e)
    }
}

impl fmt::Debug for LoggedHeaders<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (k, v) in self.iter() {
            map.entry(&k, &v);
        }
        map.finish()
    }
}

impl Default for LoggedHeaders<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Stack-allocated collection of matched mangle rule names.
///
/// Avoids `Vec<String>` heap allocation for the common case of 0-4 mangle matches.
/// Falls back to a heap `Vec` if more than `MAX_MANGLE_MATCHES` rules match.
#[derive(Debug)]
pub struct MangleMatches<'a> {
    stack: [Option<&'a str>; MAX_MANGLE_MATCHES],
    count: usize,
    overflow: Option<Vec<&'a str>>,
}

impl<'a> MangleMatches<'a> {
    fn new() -> Self {
        Self {
            stack: [None; MAX_MANGLE_MATCHES],
            count: 0,
            overflow: None,
        }
    }

    fn push(&mut self, name: &'a str) {
        if self.count < MAX_MANGLE_MATCHES {
            self.stack[self.count] = Some(name);
        } else {
            // Spill to heap on overflow
            let overflow = self.overflow.get_or_insert_with(Vec::new);
            overflow.push(name);
        }
        self.count += 1;
    }

    /// Add an extra name (used when a rate-limit/credit rule also has mangle=true).
    pub fn push_name(&mut self, name: &'a str) {
        self.push(name);
    }

    /// Iterate over all matched mangle rule names.
    pub fn iter(&self) -> impl Iterator<Item = &str> + use<'_> {
        let stack_count = self.count.min(MAX_MANGLE_MATCHES);
        let stack_iter = self.stack[..stack_count].iter().filter_map(|o| *o);
        let overflow_iter = self.overflow.as_deref().unwrap_or(&[]).iter().copied();
        stack_iter.chain(overflow_iter)
    }
}

/// Rule engine that preserves config order for first-match-wins semantics.
///
/// Rules are stored in config order and optionally indexed by method for
/// fast filtering. The evaluation respects the original order in the config file.
pub struct RuleIndex {
    /// All rules in config order, with their original index
    rules: Vec<CompiledRule>,

    /// Method index: maps method -> indices into `rules` vec (for fast filtering)
    /// Rules without a method filter are in the `None` bucket.
    method_index: HashMap<Option<Method>, Vec<usize>>,

    /// Pre-merged sorted indices per method.
    /// Each entry contains the union of method-specific + wildcard (None) indices,
    /// already sorted by config order. Eliminates per-request Vec allocation + sort.
    merged_index: HashMap<Option<Method>, Vec<usize>>,
}

impl RuleIndex {
    /// Create a new empty rule index.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            method_index: HashMap::new(),
            merged_index: HashMap::new(),
        }
    }

    /// Build rule index from configuration.
    /// Rules are evaluated in the order they appear in the config (first-match-wins).
    /// Collects all parse errors and returns them together (fail-fast aggregation).
    pub fn from_config(rules: &[RuleConfig]) -> Result<Self, Vec<ParseError>> {
        let mut index = Self::new();
        let mut errors = Vec::new();

        for rule_config in rules {
            match parse_rule(&rule_config.name, &rule_config.rule) {
                Ok(compiled) => index.add_rule(compiled),
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            index.rebuild_merged_index();
            Ok(index)
        } else {
            Err(errors)
        }
    }

    /// Add a compiled rule to the index.
    pub fn add_rule(&mut self, rule: CompiledRule) {
        let idx = self.rules.len();
        let method_key = rule.indexed_method.clone();

        self.rules.push(rule);
        self.method_index.entry(method_key).or_default().push(idx);
        // Note: rebuild_merged_index() must be called after all rules are added
        // when using add_rule directly. from_config handles this automatically.
    }

    /// Rebuild the pre-merged index for all methods.
    /// Must be called after all `add_rule()` calls when building manually.
    pub fn rebuild_merged_index(&mut self) {
        self.merged_index.clear();
        let wildcard = self.method_index.get(&None).cloned().unwrap_or_default();

        // Build merged index for each specific method
        for (method, indices) in &self.method_index {
            if method.is_some() {
                let mut merged: Vec<usize> =
                    indices.iter().chain(wildcard.iter()).copied().collect();
                merged.sort_unstable();
                merged.dedup();
                self.merged_index.insert(method.clone(), merged);
            }
        }

        // The wildcard-only bucket (for methods not in method_index)
        if !wildcard.is_empty() {
            self.merged_index.insert(None, wildcard);
        }
    }

    /// Get total number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Extract credit budgets from parsed rules.
    /// Returns Vec of (rule_name, budget) for all credit and composite rules.
    pub fn credit_budgets(&self) -> Vec<(String, u64)> {
        self.rules
            .iter()
            .filter_map(|rule| match &rule.action {
                Action::Credit { credits, .. } => Some((rule.name.clone(), *credits)),
                Action::RateLimitCredit { credits, .. } => Some((rule.name.clone(), *credits)),
                _ => None,
            })
            .collect()
    }

    /// Check for unreachable rules and log warnings.
    ///
    /// A ternary rule (one with an `else_action`) always fires — it handles both
    /// match and no-match cases. Any rule evaluated after a ternary rule in the
    /// same method bucket is unreachable.
    pub fn warn_unreachable(&self) {
        use tracing::warn;

        // Check each method bucket independently
        for (method, indices) in &self.method_index {
            let mut seen_catchall: Option<&str> = None;

            for &idx in indices {
                let rule = &self.rules[idx];

                if let Some(catchall_name) = seen_catchall {
                    let method_label = method
                        .as_ref()
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| "ANY".to_string());
                    warn!(
                        target: "rules",
                        rule = %rule.name,
                        shadowed_by = %catchall_name,
                        method = %method_label,
                        "Rule is unreachable — ternary rule '{}' always matches first",
                        catchall_name
                    );
                    continue;
                }

                // A ternary rule always takes an action (match → action, no-match → else_action)
                if rule.else_action.is_some() {
                    seen_catchall = Some(&rule.name);
                }
            }
        }
    }

    /// Check for rules with duplicate conditions and log warnings.
    ///
    /// When two rules share the same condition expression, only the first one
    /// can ever fire (first-match-wins). This is almost always a config mistake.
    pub fn warn_duplicate_conditions(&self) {
        use std::collections::HashMap as StdHashMap;
        use tracing::warn;

        // Map: canonical condition signature → first rule name that used it
        let mut seen: StdHashMap<String, &str> = StdHashMap::new();

        for rule in &self.rules {
            let sig = rule.condition.condition_signature();
            if let Some(first_name) = seen.get(&sig) {
                warn!(
                    target: "rules",
                    rule = %rule.name,
                    duplicate_of = %first_name,
                    condition = %sig,
                    "Rule has the same condition as '{}' — only the first rule will ever match",
                    first_name
                );
            } else {
                seen.insert(sig, &rule.name);
            }
        }
    }

    /// Evaluate rules against the request context.
    ///
    /// Rules are evaluated in **config order** (first-match-wins).
    /// Only rules that could potentially match the request method are checked.
    /// Returns `None` if no rules matched.
    pub fn evaluate<'idx, 'req>(
        &'idx self,
        ctx: &'req EvalContext<'req>,
    ) -> Option<RuleMatch<'idx, 'req>>
    where
        'idx: 'req,
    {
        // Use pre-merged index: try method-specific first, fall back to wildcard-only
        let indices = self
            .merged_index
            .get(&Some(ctx.method.clone()))
            .or_else(|| self.merged_index.get(&None));

        let indices = match indices {
            Some(v) => v.as_slice(),
            None => return None,
        };

        // Evaluate in config order
        for &idx in indices {
            let rule = &self.rules[idx];
            let matched = rule.condition.evaluate(ctx);

            let action = if matched {
                Some(&rule.action)
            } else {
                rule.else_action.as_ref()
            };

            if let Some(action) = action {
                let logged_headers = self.collect_logged_headers(rule, ctx);
                return Some(RuleMatch {
                    rule_name: &rule.name,
                    logged_headers,
                    action,
                });
            }
        }

        None
    }

    /// Collect header values for all headers referenced in the rule.
    /// Includes both existence-only and value-match headers (for logging).
    /// Uses pre-computed (HeaderName, String) pairs from `CompiledRule` for
    /// zero-alloc HeaderMap lookups. Returns stack-allocated LoggedHeaders.
    fn collect_logged_headers<'req>(
        &self,
        rule: &'req CompiledRule,
        ctx: &'req EvalContext<'req>,
    ) -> LoggedHeaders<'req> {
        let mut logged = LoggedHeaders::new();
        for (header_name, name_str) in &rule.logged_header_names {
            if let Some(value) = ctx.headers.get(header_name)
                && let Ok(v) = value.to_str()
            {
                logged.push(name_str.as_str(), v);
            }
        }
        logged
    }

    /// Evaluate and collect all mangle rules that match.
    /// Unlike `evaluate`, this doesn't short-circuit on first match.
    /// Returns a stack-allocated `MangleMatches` (avoids `Vec<String>` heap alloc).
    pub fn evaluate_mangle_rules<'a>(&'a self, ctx: &EvalContext) -> MangleMatches<'a> {
        let mut matched = MangleMatches::new();

        // Use pre-merged index
        let indices = self
            .merged_index
            .get(&Some(ctx.method.clone()))
            .or_else(|| self.merged_index.get(&None));

        let indices = match indices {
            Some(v) => v.as_slice(),
            None => return matched,
        };

        for &idx in indices {
            let rule = &self.rules[idx];
            if rule.condition.evaluate(ctx) && matches!(rule.action, Action::Mangle) {
                matched.push(&rule.name);
            }
        }

        matched
    }
}

impl Default for RuleIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderMap, HeaderName, HeaderValue};

    fn make_ctx<'a>(
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
            client_ip: None,
        }
    }

    #[test]
    fn test_empty_index_returns_no_match() {
        let mut index = RuleIndex::new();
        index.rebuild_merged_index();
        let headers = HeaderMap::new();
        let ctx = make_ctx("example.com", "/", &Method::GET, &headers);

        assert!(index.evaluate(&ctx).is_none());
    }

    #[test]
    fn test_method_indexed_lookup() {
        let mut index = RuleIndex::new();

        // Add GET-specific rule
        let rule = parse_rule("get-only", r#"method(GET) && host("*.com") = pass"#).unwrap();
        index.add_rule(rule);

        // Add POST-specific rule
        let rule = parse_rule("post-only", r#"method(POST) && host("*.com") = block"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();

        // GET request should match get-only rule
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "get-only");
        assert!(matches!(r.action, Action::Pass));

        // POST request should match post-only rule
        let ctx = make_ctx("test.com", "/", &Method::POST, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "post-only");
        assert!(matches!(r.action, Action::Block));

        // DELETE request should not match
        let ctx = make_ctx("test.com", "/", &Method::DELETE, &headers);
        assert!(index.evaluate(&ctx).is_none());
    }

    #[test]
    fn test_wildcard_rules_always_checked() {
        let mut index = RuleIndex::new();

        // Add a rule without method filter (goes to wildcard bucket)
        let rule = parse_rule("all-methods", r#"host("blocked.com") = block"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();

        // Should match for any method
        for method in [Method::GET, Method::POST, Method::DELETE, Method::PUT] {
            let ctx = make_ctx("blocked.com", "/", &method, &headers);
            let r = index.evaluate(&ctx).unwrap();
            assert_eq!(r.rule_name, "all-methods");
            assert!(matches!(r.action, Action::Block));
        }
    }

    #[test]
    fn test_first_match_wins() {
        let mut index = RuleIndex::new();

        // First rule blocks
        let rule = parse_rule("first", r#"host("*.com") = block"#).unwrap();
        index.add_rule(rule);

        // Second rule passes (should never be reached)
        let rule = parse_rule("second", r#"host("test.com") = pass"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "first");
        assert!(matches!(r.action, Action::Block));
    }

    #[test]
    fn test_ternary_else_action() {
        let mut index = RuleIndex::new();

        let rule = parse_rule("ternary", r#"header("X-Auth") = pass : block"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        // With header: should pass
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-auth"),
            HeaderValue::from_static("token"),
        );
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);
        assert!(matches!(index.evaluate(&ctx).unwrap().action, Action::Pass));

        // Without header: should block
        let headers = HeaderMap::new();
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);
        assert!(matches!(
            index.evaluate(&ctx).unwrap().action,
            Action::Block
        ));
    }

    #[test]
    fn test_config_order_preserved() {
        // This test verifies that rules are evaluated in config order,
        // even when mixing method-specific and wildcard rules.
        let rules = vec![
            RuleConfig {
                name: "allow-health".to_string(),
                rule: r#"path("/health") = pass"#.to_string(),
            },
            RuleConfig {
                name: "allow-payment".to_string(),
                rule: r#"method(POST) && path("/payment") = pass"#.to_string(),
            },
            RuleConfig {
                name: "block-all".to_string(),
                rule: r#"host("*") = block"#.to_string(),
            },
        ];

        let index = RuleIndex::from_config(&rules).unwrap();
        let headers = HeaderMap::new();

        // Health check should pass (rule 1)
        let ctx = make_ctx("api.example.com", "/health", &Method::GET, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "allow-health");
        assert!(matches!(r.action, Action::Pass));

        // Payment should pass (rule 2)
        let ctx = make_ctx("api.example.com", "/payment", &Method::POST, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "allow-payment");
        assert!(matches!(r.action, Action::Pass));

        // Everything else should be blocked (rule 3)
        let ctx = make_ctx("api.example.com", "/users", &Method::GET, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "block-all");
        assert!(matches!(r.action, Action::Block));
    }

    #[test]
    fn test_evaluate_mangle_rules() {
        let mut index = RuleIndex::new();

        let rule = parse_rule("mangle1", r#"host("api.*") = mangle"#).unwrap();
        index.add_rule(rule);

        let rule = parse_rule("mangle2", r#"path("/v1/*") = mangle"#).unwrap();
        index.add_rule(rule);

        let rule = parse_rule("block", r#"host("blocked.com") = block"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();
        let ctx = make_ctx("api.example.com", "/v1/users", &Method::GET, &headers);

        let matched = index.evaluate_mangle_rules(&ctx);
        let names: Vec<&str> = matched.iter().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"mangle1"));
        assert!(names.contains(&"mangle2"));
    }

    #[test]
    fn test_from_config() {
        let configs = vec![
            RuleConfig {
                name: "rule1".to_string(),
                rule: r#"host("*.internal") = block"#.to_string(),
            },
            RuleConfig {
                name: "rule2".to_string(),
                rule: r#"method(GET) = pass"#.to_string(),
            },
        ];

        let index = RuleIndex::from_config(&configs).unwrap();
        assert_eq!(index.rule_count(), 2);
    }

    #[test]
    fn test_from_config_collects_all_errors() {
        let configs = vec![
            RuleConfig {
                name: "good-rule".to_string(),
                rule: r#"host("*.com") = block"#.to_string(),
            },
            RuleConfig {
                name: "bad-rule-1".to_string(),
                rule: "".to_string(), // empty expression
            },
            RuleConfig {
                name: "bad-rule-2".to_string(),
                rule: r#"host("[invalid") = block"#.to_string(), // bad glob
            },
        ];

        let result = RuleIndex::from_config(&configs);
        assert!(result.is_err(), "Should have failed with parse errors");
        let errors = match result {
            Err(e) => e,
            Ok(_) => panic!("Expected errors"),
        };
        assert_eq!(
            errors.len(),
            2,
            "Should collect both errors, got: {:?}",
            errors
        );

        // Verify each error has the right rule name
        let names: Vec<_> = errors.iter().map(|e| e.to_string()).collect();
        assert!(names.iter().any(|m| m.contains("bad-rule-1")));
        assert!(names.iter().any(|m| m.contains("bad-rule-2")));
    }

    #[test]
    fn test_duplicate_conditions_detected() {
        // Two rules with identical conditions but different actions
        let configs = vec![
            RuleConfig {
                name: "rule-a".to_string(),
                rule: r#"host("api.*") && path("/v1/*") = block"#.to_string(),
            },
            RuleConfig {
                name: "rule-b".to_string(),
                rule: r#"host("api.*") && path("/v1/*") = pass"#.to_string(),
            },
            RuleConfig {
                name: "rule-c".to_string(),
                rule: r#"host("other.*") = block"#.to_string(),
            },
        ];

        let index = RuleIndex::from_config(&configs).unwrap();

        // Verify signatures match for the duplicate pair
        let sigs: Vec<String> = index
            .rules
            .iter()
            .map(|r| r.condition.condition_signature())
            .collect();

        assert_eq!(
            sigs[0], sigs[1],
            "rule-a and rule-b should have the same signature"
        );
        assert_ne!(sigs[0], sigs[2], "rule-a and rule-c should differ");

        // warn_duplicate_conditions should not panic
        index.warn_duplicate_conditions();
    }

    #[test]
    fn test_logged_headers_populated() {
        let mut index = RuleIndex::new();

        // Rule with existence-only header check
        let rule = parse_rule("check-auth", r#"header("X-Customer-Id") = pass"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        // Request with the header present
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-customer-id"),
            HeaderValue::from_static("cust-12345"),
        );
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "check-auth");
        assert!(matches!(r.action, Action::Pass));
        assert_eq!(r.logged_headers.get("x-customer-id"), Some("cust-12345"));
    }

    #[test]
    fn test_logged_headers_multiple() {
        let mut index = RuleIndex::new();

        // Rule with multiple existence-only header checks
        let rule = parse_rule(
            "multi-header",
            r#"header("X-Auth") && header("X-Request-Id") = pass"#,
        )
        .unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-auth"),
            HeaderValue::from_static("bearer-token"),
        );
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("req-abc-123"),
        );
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert!(matches!(r.action, Action::Pass));
        assert_eq!(r.logged_headers.len(), 2);
        assert_eq!(r.logged_headers.get("x-auth"), Some("bearer-token"));
        assert_eq!(r.logged_headers.get("x-request-id"), Some("req-abc-123"));
    }

    #[test]
    fn test_logged_headers_includes_value_match() {
        let mut index = RuleIndex::new();

        // Rule with value match — now also logged
        let rule = parse_rule("value-match", r#"header("X-Auth:secret") = pass"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-auth"),
            HeaderValue::from_static("secret"),
        );
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert!(matches!(r.action, Action::Pass));
        assert_eq!(
            r.logged_headers.get("x-auth"),
            Some("secret"),
            "Value-match headers should now be logged"
        );
    }

    #[test]
    fn test_logged_headers_on_else_action() {
        let mut index = RuleIndex::new();

        // Ternary rule: header exists = pass, else block
        let rule = parse_rule("ternary-log", r#"header("X-Auth") = pass : block"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        // Without header - triggers else action, but headers still extracted from rule
        let headers = HeaderMap::new();
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert!(matches!(r.action, Action::Block));
        // Header not present, so logged_headers should be empty
        assert!(r.logged_headers.is_empty());
    }

    #[test]
    fn test_composite_rate_limit_credit_result() {
        let mut index = RuleIndex::new();

        let rule = parse_rule(
            "api-protected",
            r#"host("api.*") = rate_limit(100/s, header(X-Id)) + credit(1000/d, header(X-Id))"#,
        )
        .unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-id"),
            HeaderValue::from_static("cust-123"),
        );
        let ctx = make_ctx("api.example.com", "/v1/data", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "api-protected");
        assert!(
            matches!(r.action, Action::RateLimitCredit { requests, credits, .. }
                if *requests == 100 && *credits == 1000),
            "Expected RateLimitCredit action, got {:?}",
            r.action
        );
    }

    #[test]
    fn test_credit_budgets_includes_composite() {
        let mut index = RuleIndex::new();

        let rule = parse_rule("credit-only", r#"host("a.*") = credit(500/d, ip)"#).unwrap();
        index.add_rule(rule);

        let rule = parse_rule(
            "composite",
            r#"host("b.*") = rate_limit(10/s, ip) + credit(2000/w, ip)"#,
        )
        .unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let budgets = index.credit_budgets();
        assert_eq!(budgets.len(), 2);
        assert!(
            budgets
                .iter()
                .any(|(name, budget)| name == "credit-only" && *budget == 500)
        );
        assert!(
            budgets
                .iter()
                .any(|(name, budget)| name == "composite" && *budget == 2000)
        );
    }

    #[test]
    fn test_rate_limit_with_mangle_result() {
        let mut index = RuleIndex::new();

        let rule = parse_rule(
            "rl-mangle",
            r#"host("api.*") = rate_limit(100/s, ip) + mangle"#,
        )
        .unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "rl-mangle");
        assert!(
            matches!(r.action, Action::RateLimit { mangle, .. } if *mangle),
            "Expected RateLimit with mangle=true, got {:?}",
            r.action
        );
    }

    #[test]
    fn test_credit_with_mangle_result() {
        let mut index = RuleIndex::new();

        let rule = parse_rule(
            "credit-mangle",
            r#"host("api.*") = credit(1000/d, ip) + mangle"#,
        )
        .unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "credit-mangle");
        assert!(
            matches!(r.action, Action::Credit { mangle, .. } if *mangle),
            "Expected Credit with mangle=true, got {:?}",
            r.action
        );
    }

    #[test]
    fn test_rate_limit_credit_mangle_result() {
        let mut index = RuleIndex::new();

        let rule = parse_rule(
            "combo-mangle",
            r#"host("api.*") = rate_limit(100/s, ip) + credit(1000/d, ip) + mangle"#,
        )
        .unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "combo-mangle");
        assert!(
            matches!(r.action, Action::RateLimitCredit { mangle, .. } if *mangle),
            "Expected RateLimitCredit with mangle=true, got {:?}",
            r.action
        );
    }

    #[test]
    fn test_rate_limit_without_mangle_result() {
        let mut index = RuleIndex::new();

        let rule = parse_rule("rl-only", r#"host("api.*") = rate_limit(100/s, ip)"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", &Method::GET, &headers);

        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "rl-only");
        assert!(
            matches!(r.action, Action::RateLimit { mangle, .. } if !*mangle),
            "Expected RateLimit with mangle=false, got {:?}",
            r.action
        );
    }

    #[test]
    fn test_method_and_path_rule_before_catchall() {
        // Exact scenario from user: method(GET) && path("/health") before host("*") = block
        let rules = vec![
            RuleConfig {
                name: "allow-healthcheck".to_string(),
                rule: r#"path("/health") && method(GET) = pass"#.to_string(),
            },
            RuleConfig {
                name: "block-all".to_string(),
                rule: r#"host("*") = block"#.to_string(),
            },
        ];

        let index = RuleIndex::from_config(&rules).unwrap();
        let headers = HeaderMap::new();

        // GET /health should pass (rule 1)
        let ctx = make_ctx("example.com", "/health", &Method::GET, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "allow-healthcheck");
        assert!(matches!(r.action, Action::Pass));

        // POST /health should be blocked (rule 1 requires GET)
        let ctx = make_ctx("example.com", "/health", &Method::POST, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "block-all");
        assert!(matches!(r.action, Action::Block));

        // GET /other should be blocked
        let ctx = make_ctx("example.com", "/other", &Method::GET, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "block-all");
        assert!(matches!(r.action, Action::Block));
    }

    // === Coverage: LoggedHeaders Debug + Default ===

    #[test]
    fn test_logged_headers_debug_format() {
        let mut logged = LoggedHeaders::new();
        logged.push("x-auth", "token123");
        logged.push("x-trace", "abc");
        let debug = format!("{:?}", logged);
        assert!(
            debug.contains("x-auth"),
            "Debug should contain header name: {}",
            debug
        );
        assert!(
            debug.contains("token123"),
            "Debug should contain header value: {}",
            debug
        );
    }

    #[test]
    fn test_logged_headers_default_impl() {
        let logged = LoggedHeaders::default();
        assert_eq!(logged.iter().count(), 0);
    }

    // === Coverage: MangleMatches overflow + push_name ===

    #[test]
    fn test_mangle_matches_overflow_to_heap() {
        let mut matches = MangleMatches::new();
        let names_storage: Vec<String> = (0..MAX_MANGLE_MATCHES)
            .map(|i| format!("rule-{}", i))
            .collect();
        // Fill the stack slots (MAX_MANGLE_MATCHES = 4)
        for name in &names_storage {
            matches.push_name(name);
        }
        // Push beyond stack capacity → should spill to heap
        matches.push_name("overflow-rule-1");
        matches.push_name("overflow-rule-2");

        let names: Vec<&str> = matches.iter().collect();
        assert_eq!(names.len(), MAX_MANGLE_MATCHES + 2);
        assert_eq!(names[MAX_MANGLE_MATCHES], "overflow-rule-1");
        assert_eq!(names[MAX_MANGLE_MATCHES + 1], "overflow-rule-2");
    }

    // === Coverage: RuleIndex::default() ===

    #[test]
    fn test_rule_index_default() {
        let index = RuleIndex::default();
        assert_eq!(index.rule_count(), 0);
    }

    // === Coverage: warn_unreachable ===

    #[test]
    fn test_warn_unreachable_after_ternary() {
        let rules = vec![
            RuleConfig {
                name: "ternary".to_string(),
                rule: r#"header("X-Auth") = pass : block"#.to_string(),
            },
            RuleConfig {
                name: "unreachable".to_string(),
                rule: r#"host("*") = block"#.to_string(),
            },
        ];
        let index = RuleIndex::from_config(&rules).unwrap();
        // Should log a warning for unreachable rule — we just exercise the code path
        index.warn_unreachable();
    }

    #[test]
    fn test_warn_unreachable_method_bucket() {
        // Ternary in a method-specific bucket
        let rules = vec![
            RuleConfig {
                name: "get-ternary".to_string(),
                rule: r#"method(GET) && header("X-Auth") = pass : block"#.to_string(),
            },
            RuleConfig {
                name: "get-after".to_string(),
                rule: r#"method(GET) && host("*") = pass"#.to_string(),
            },
        ];
        let index = RuleIndex::from_config(&rules).unwrap();
        index.warn_unreachable();
    }

    // === Coverage: evaluate with logged headers resolving values ===

    #[test]
    fn test_evaluate_logged_headers_with_values() {
        let mut index = RuleIndex::new();
        // Rule with existence-only header check → logged headers should capture values
        let rule = parse_rule("log-hdr", r#"header("X-Request-Id") = pass"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("req-abc-123"),
        );
        let ctx = make_ctx("example.com", "/", &Method::GET, &headers);
        let r = index.evaluate(&ctx).unwrap();
        assert_eq!(r.rule_name, "log-hdr");
        assert_eq!(r.logged_headers.get("x-request-id"), Some("req-abc-123"));
    }

    // === Coverage: evaluate_mangle_rules with method-specific rules ===

    #[test]
    fn test_evaluate_mangle_rules_method_specific() {
        let mut index = RuleIndex::new();
        let rule = parse_rule("mangle-get", r#"method(GET) && host("*.com") = mangle"#).unwrap();
        index.add_rule(rule);
        let rule = parse_rule("mangle-any", r#"host("*.org") = mangle"#).unwrap();
        index.add_rule(rule);
        index.rebuild_merged_index();

        let headers = HeaderMap::new();
        let ctx = make_ctx("test.com", "/", &Method::GET, &headers);
        let matched = index.evaluate_mangle_rules(&ctx);
        let names: Vec<&str> = matched.iter().collect();
        assert_eq!(names, vec!["mangle-get"]);
    }

    // === Coverage: credit_budgets with RateLimitCredit ===

    #[test]
    fn test_credit_budgets_from_composite() {
        let rules = vec![RuleConfig {
            name: "composite".to_string(),
            rule: r#"host("*") = rate_limit(100/s, ip) + credit(5000/d, ip)"#.to_string(),
        }];
        let index = RuleIndex::from_config(&rules).unwrap();
        let budgets = index.credit_budgets();
        assert_eq!(budgets.len(), 1);
        assert_eq!(budgets[0].0, "composite");
        assert_eq!(budgets[0].1, 5000);
    }
}
