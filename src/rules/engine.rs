//! Method-indexed rule engine for efficient evaluation.
//!
//! Rules are indexed by HTTP method for O(1) lookup of relevant rules.
//! Rules without a method filter go in the `None` bucket and are always checked.

use http::Method;
use std::collections::HashMap;

use crate::config::RuleConfig;
use crate::error::ParseError;
use crate::rules::ast::*;
use crate::rules::parser::parse_rule;

/// Result of rule evaluation.
#[derive(Debug, Clone)]
pub enum RuleResult {
    /// No rules matched, continue processing
    NoMatch,

    /// Request should be blocked
    Block {
        rule_name: String,
        /// Headers to log (existence-only checks with their values)
        logged_headers: HashMap<String, String>,
    },

    /// Request is allowed (stop further rule evaluation)
    Pass {
        rule_name: String,
        /// Headers to log (existence-only checks with their values)
        logged_headers: HashMap<String, String>,
    },

    /// Request should have headers mangled
    Mangle {
        rule_name: String,
        /// Headers to log (existence-only checks with their values)
        logged_headers: HashMap<String, String>,
    },

    /// Request should be rate limited
    RateLimit {
        rule_name: String,
        requests: u64,
        window_secs: u64,
        key_expr: KeyExpr,
        /// Also apply header mangling for this rule
        mangle: bool,
        /// Headers to log (existence-only checks with their values)
        logged_headers: HashMap<String, String>,
    },

    /// Request should be credit-checked
    Credit {
        rule_name: String,
        credits: u64,
        period: CreditPeriod,
        key_expr: KeyExpr,
        /// Also apply header mangling for this rule
        mangle: bool,
        /// Headers to log (existence-only checks with their values)
        logged_headers: HashMap<String, String>,
    },

    /// Request should be both rate-limited (burst) and credit-checked (budget)
    RateLimitCredit {
        rule_name: String,
        requests: u64,
        window_secs: u64,
        rate_key_expr: KeyExpr,
        credits: u64,
        period: CreditPeriod,
        credit_key_expr: KeyExpr,
        /// Also apply header mangling for this rule
        mangle: bool,
        /// Headers to log (existence-only checks with their values)
        logged_headers: HashMap<String, String>,
    },
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
}

impl RuleIndex {
    /// Create a new empty rule index.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            method_index: HashMap::new(),
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
    pub fn evaluate(&self, ctx: &EvalContext) -> RuleResult {
        // Collect indices of rules to check:
        // - Rules specific to this method
        // - Wildcard rules (no method filter)
        let method_indices = self.method_index.get(&Some(ctx.method.clone()));
        let wildcard_indices = self.method_index.get(&None);

        // Merge indices and sort to preserve config order
        let mut indices: Vec<usize> = method_indices
            .into_iter()
            .flatten()
            .chain(wildcard_indices.into_iter().flatten())
            .copied()
            .collect();
        indices.sort_unstable();

        // Evaluate in config order
        for idx in indices {
            let rule = &self.rules[idx];
            let matched = rule.condition.evaluate(ctx);

            if matched {
                let logged_headers = self.collect_logged_headers(rule, ctx);
                return self.action_to_result(&rule.name, &rule.action, logged_headers);
            } else if let Some(else_action) = &rule.else_action {
                let logged_headers = self.collect_logged_headers(rule, ctx);
                return self.action_to_result(&rule.name, else_action, logged_headers);
            }
        }

        RuleResult::NoMatch
    }

    /// Collect header values for headers that are existence-only checks in the rule.
    fn collect_logged_headers(
        &self,
        rule: &CompiledRule,
        ctx: &EvalContext,
    ) -> HashMap<String, String> {
        let header_names = rule.extract_logged_headers();
        let mut logged = HashMap::new();

        for name in header_names {
            let name_lower = name.to_lowercase();
            if let Some(value) = ctx.headers.get(&name_lower) {
                logged.insert(name, value.clone());
            }
        }

        logged
    }

    /// Evaluate and collect all mangle rules that match.
    /// Unlike `evaluate`, this doesn't short-circuit on first match.
    pub fn evaluate_mangle_rules(&self, ctx: &EvalContext) -> Vec<String> {
        let mut matched_rules = Vec::new();

        let method_indices = self.method_index.get(&Some(ctx.method.clone()));
        let wildcard_indices = self.method_index.get(&None);

        let mut indices: Vec<usize> = method_indices
            .into_iter()
            .flatten()
            .chain(wildcard_indices.into_iter().flatten())
            .copied()
            .collect();
        indices.sort_unstable();

        for idx in indices {
            let rule = &self.rules[idx];
            if rule.condition.evaluate(ctx) && matches!(rule.action, Action::Mangle) {
                matched_rules.push(rule.name.clone());
            }
        }

        matched_rules
    }

    fn action_to_result(
        &self,
        rule_name: &str,
        action: &Action,
        logged_headers: HashMap<String, String>,
    ) -> RuleResult {
        match action {
            Action::Block => RuleResult::Block {
                rule_name: rule_name.to_string(),
                logged_headers,
            },
            Action::Pass => RuleResult::Pass {
                rule_name: rule_name.to_string(),
                logged_headers,
            },
            Action::Mangle => RuleResult::Mangle {
                rule_name: rule_name.to_string(),
                logged_headers,
            },
            Action::RateLimit {
                requests,
                window_secs,
                key_expr,
                mangle,
            } => RuleResult::RateLimit {
                rule_name: rule_name.to_string(),
                requests: *requests,
                window_secs: *window_secs,
                key_expr: key_expr.clone(),
                mangle: *mangle,
                logged_headers,
            },
            Action::Credit {
                credits,
                period,
                key_expr,
                mangle,
            } => RuleResult::Credit {
                rule_name: rule_name.to_string(),
                credits: *credits,
                period: *period,
                key_expr: key_expr.clone(),
                mangle: *mangle,
                logged_headers,
            },
            Action::RateLimitCredit {
                requests,
                window_secs,
                rate_key_expr,
                credits,
                period,
                credit_key_expr,
                mangle,
            } => RuleResult::RateLimitCredit {
                rule_name: rule_name.to_string(),
                requests: *requests,
                window_secs: *window_secs,
                rate_key_expr: rate_key_expr.clone(),
                credits: *credits,
                period: *period,
                credit_key_expr: credit_key_expr.clone(),
                mangle: *mangle,
                logged_headers,
            },
        }
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
    use std::collections::HashMap;

    fn make_ctx<'a>(
        host: &'a str,
        path: &'a str,
        method: Method,
        headers: &'a HashMap<String, String>,
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
        let index = RuleIndex::new();
        let headers = HashMap::new();
        let ctx = make_ctx("example.com", "/", Method::GET, &headers);

        assert!(matches!(index.evaluate(&ctx), RuleResult::NoMatch));
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

        let headers = HashMap::new();

        // GET request should match get-only rule
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);
        assert!(matches!(
            index.evaluate(&ctx),
            RuleResult::Pass { rule_name, .. } if rule_name == "get-only"
        ));

        // POST request should match post-only rule
        let ctx = make_ctx("test.com", "/", Method::POST, &headers);
        assert!(matches!(
            index.evaluate(&ctx),
            RuleResult::Block { rule_name, .. } if rule_name == "post-only"
        ));

        // DELETE request should not match
        let ctx = make_ctx("test.com", "/", Method::DELETE, &headers);
        assert!(matches!(index.evaluate(&ctx), RuleResult::NoMatch));
    }

    #[test]
    fn test_wildcard_rules_always_checked() {
        let mut index = RuleIndex::new();

        // Add a rule without method filter (goes to wildcard bucket)
        let rule = parse_rule("all-methods", r#"host("blocked.com") = block"#).unwrap();
        index.add_rule(rule);

        let headers = HashMap::new();

        // Should match for any method
        for method in [Method::GET, Method::POST, Method::DELETE, Method::PUT] {
            let ctx = make_ctx("blocked.com", "/", method, &headers);
            assert!(matches!(
                index.evaluate(&ctx),
                RuleResult::Block { rule_name, .. } if rule_name == "all-methods"
            ));
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

        let headers = HashMap::new();
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);

        assert!(matches!(
            index.evaluate(&ctx),
            RuleResult::Block { rule_name, .. } if rule_name == "first"
        ));
    }

    #[test]
    fn test_ternary_else_action() {
        let mut index = RuleIndex::new();

        let rule = parse_rule("ternary", r#"header("X-Auth") = pass : block"#).unwrap();
        index.add_rule(rule);

        // With header: should pass
        let mut headers = HashMap::new();
        headers.insert("x-auth".to_string(), "token".to_string());
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);
        assert!(matches!(index.evaluate(&ctx), RuleResult::Pass { .. }));

        // Without header: should block
        let headers = HashMap::new();
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);
        assert!(matches!(index.evaluate(&ctx), RuleResult::Block { .. }));
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
        let headers = HashMap::new();

        // Health check should pass (rule 1)
        let ctx = make_ctx("api.example.com", "/health", Method::GET, &headers);
        assert!(matches!(
            index.evaluate(&ctx),
            RuleResult::Pass { rule_name, .. } if rule_name == "allow-health"
        ));

        // Payment should pass (rule 2)
        let ctx = make_ctx("api.example.com", "/payment", Method::POST, &headers);
        assert!(matches!(
            index.evaluate(&ctx),
            RuleResult::Pass { rule_name, .. } if rule_name == "allow-payment"
        ));

        // Everything else should be blocked (rule 3)
        let ctx = make_ctx("api.example.com", "/users", Method::GET, &headers);
        assert!(matches!(
            index.evaluate(&ctx),
            RuleResult::Block { rule_name, .. } if rule_name == "block-all"
        ));
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

        let headers = HashMap::new();
        let ctx = make_ctx("api.example.com", "/v1/users", Method::GET, &headers);

        let matched = index.evaluate_mangle_rules(&ctx);
        assert_eq!(matched.len(), 2);
        assert!(matched.contains(&"mangle1".to_string()));
        assert!(matched.contains(&"mangle2".to_string()));
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

        // Request with the header present
        let mut headers = HashMap::new();
        headers.insert("x-customer-id".to_string(), "cust-12345".to_string());
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        match result {
            RuleResult::Pass {
                rule_name,
                logged_headers,
            } => {
                assert_eq!(rule_name, "check-auth");
                assert_eq!(
                    logged_headers.get("X-Customer-Id"),
                    Some(&"cust-12345".to_string())
                );
            }
            _ => panic!("Expected Pass result"),
        }
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

        let mut headers = HashMap::new();
        headers.insert("x-auth".to_string(), "bearer-token".to_string());
        headers.insert("x-request-id".to_string(), "req-abc-123".to_string());
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        match result {
            RuleResult::Pass { logged_headers, .. } => {
                assert_eq!(logged_headers.len(), 2);
                assert_eq!(
                    logged_headers.get("X-Auth"),
                    Some(&"bearer-token".to_string())
                );
                assert_eq!(
                    logged_headers.get("X-Request-Id"),
                    Some(&"req-abc-123".to_string())
                );
            }
            _ => panic!("Expected Pass result"),
        }
    }

    #[test]
    fn test_logged_headers_empty_when_no_existence_checks() {
        let mut index = RuleIndex::new();

        // Rule with value match (not existence-only)
        let rule = parse_rule("value-match", r#"header("X-Auth:secret") = pass"#).unwrap();
        index.add_rule(rule);

        let mut headers = HashMap::new();
        headers.insert("x-auth".to_string(), "secret".to_string());
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        match result {
            RuleResult::Pass { logged_headers, .. } => {
                assert!(
                    logged_headers.is_empty(),
                    "Value matches should not be logged"
                );
            }
            _ => panic!("Expected Pass result"),
        }
    }

    #[test]
    fn test_logged_headers_on_else_action() {
        let mut index = RuleIndex::new();

        // Ternary rule: header exists = pass, else block
        let rule = parse_rule("ternary-log", r#"header("X-Auth") = pass : block"#).unwrap();
        index.add_rule(rule);

        // Without header - triggers else action, but headers still extracted from rule
        let headers = HashMap::new();
        let ctx = make_ctx("test.com", "/", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        match result {
            RuleResult::Block { logged_headers, .. } => {
                // Header not present, so logged_headers should be empty
                assert!(logged_headers.is_empty());
            }
            _ => panic!("Expected Block result"),
        }
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

        let mut headers = HashMap::new();
        headers.insert("x-id".to_string(), "cust-123".to_string());
        let ctx = make_ctx("api.example.com", "/v1/data", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::RateLimitCredit { rule_name, requests, credits, .. }
                if rule_name == "api-protected" && *requests == 100 && *credits == 1000),
            "Expected RateLimitCredit result, got {:?}",
            result
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

        let headers = HashMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::RateLimit { rule_name, mangle, .. }
                if rule_name == "rl-mangle" && *mangle),
            "Expected RateLimit with mangle=true, got {:?}",
            result
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

        let headers = HashMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::Credit { rule_name, mangle, .. }
                if rule_name == "credit-mangle" && *mangle),
            "Expected Credit with mangle=true, got {:?}",
            result
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

        let headers = HashMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::RateLimitCredit { rule_name, mangle, .. }
                if rule_name == "combo-mangle" && *mangle),
            "Expected RateLimitCredit with mangle=true, got {:?}",
            result
        );
    }

    #[test]
    fn test_rate_limit_without_mangle_result() {
        let mut index = RuleIndex::new();

        let rule = parse_rule("rl-only", r#"host("api.*") = rate_limit(100/s, ip)"#).unwrap();
        index.add_rule(rule);

        let headers = HashMap::new();
        let ctx = make_ctx("api.example.com", "/v1/data", Method::GET, &headers);

        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::RateLimit { rule_name, mangle, .. }
                if rule_name == "rl-only" && !*mangle),
            "Expected RateLimit with mangle=false, got {:?}",
            result
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
        let headers = HashMap::new();

        // GET /health should pass (rule 1)
        let ctx = make_ctx("example.com", "/health", Method::GET, &headers);
        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::Pass { rule_name, .. } if rule_name == "allow-healthcheck"),
            "Expected Pass from allow-healthcheck, got {:?}",
            result
        );

        // POST /health should be blocked (rule 1 requires GET)
        let ctx = make_ctx("example.com", "/health", Method::POST, &headers);
        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::Block { rule_name, .. } if rule_name == "block-all"),
            "Expected Block from block-all, got {:?}",
            result
        );

        // GET /other should be blocked
        let ctx = make_ctx("example.com", "/other", Method::GET, &headers);
        let result = index.evaluate(&ctx);
        assert!(
            matches!(&result, RuleResult::Block { rule_name, .. } if rule_name == "block-all"),
            "Expected Block from block-all, got {:?}",
            result
        );
    }
}
