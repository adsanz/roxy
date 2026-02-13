//! AST types for the rule DSL.
//!
//! Represents parsed rule expressions and actions.

use globset::GlobMatcher;
use http::Method;

/// A compiled rule ready for evaluation.
#[derive(Debug)]
pub struct CompiledRule {
    /// Rule name (for logging and header mangle references)
    pub name: String,

    /// The condition expression
    pub condition: Expr,

    /// Action to take when condition matches
    pub action: Action,

    /// Optional else action (for ternary rules)
    pub else_action: Option<Action>,

    /// Extracted method for indexing (if rule has simple method check)
    pub indexed_method: Option<Method>,
}

/// Expression AST node.
#[derive(Debug)]
pub enum Expr {
    /// Match request host against glob pattern
    Host(GlobMatcher),

    /// Match request path against glob pattern
    Path(GlobMatcher),

    /// Match HTTP method
    Method(Method),

    /// Check header exists, optionally with value match
    /// header("X-Auth") - exists check
    /// header("X-Auth:value") - value match
    /// header("X-Auth~regex") - regex match (future)
    Header {
        name: String,
        value: Option<HeaderMatch>,
    },

    /// Logical NOT
    Not(Box<Expr>),

    /// Logical AND (short-circuit)
    And(Box<Expr>, Box<Expr>),

    /// Logical OR (short-circuit)
    Or(Box<Expr>, Box<Expr>),
}

/// Header value matching type.
#[derive(Debug, Clone)]
pub enum HeaderMatch {
    /// Exact value match
    Exact(String),
    /// Glob pattern match
    Glob(GlobMatcher),
}

/// Action to take when a rule matches.
#[derive(Debug, Clone)]
pub enum Action {
    /// Block the request (return 403)
    Block,

    /// Allow the request (stop rule evaluation)
    Pass,

    /// Apply header mangling (matched rule name used for lookup)
    Mangle,

    /// Rate limit with specified parameters
    RateLimit {
        /// Requests per window
        requests: u64,
        /// Window duration in seconds
        window_secs: u64,
        /// Key extractor expression
        key_expr: KeyExpr,
        /// Also apply header mangling for this rule
        mangle: bool,
    },

    /// Credit-based rate limiting with fixed budget and scheduled reset
    Credit {
        /// Total credits per period
        credits: u64,
        /// Reset period
        period: CreditPeriod,
        /// Key extractor expression
        key_expr: KeyExpr,
        /// Also apply header mangling for this rule
        mangle: bool,
    },

    /// Composite: rate limit (burst) + credit (budget) on the same rule
    RateLimitCredit {
        /// Rate limit: requests per window
        requests: u64,
        /// Rate limit: window duration in seconds
        window_secs: u64,
        /// Rate limit: key extractor
        rate_key_expr: KeyExpr,
        /// Credit: total credits per period
        credits: u64,
        /// Credit: reset period
        period: CreditPeriod,
        /// Credit: key extractor
        credit_key_expr: KeyExpr,
        /// Also apply header mangling for this rule
        mangle: bool,
    },
}

/// Credit reset period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditPeriod {
    /// Daily reset
    Day,
    /// Weekly reset
    Week,
    /// Monthly reset
    Month,
}

/// Key extraction expression for rate limiting.
#[derive(Debug, Clone)]
pub enum KeyExpr {
    /// Single extractor
    Single(KeyExtractor),

    /// Composite key (concatenated extractors)
    Composite(Vec<KeyExtractor>),
}

impl KeyExpr {
    /// Check if this key expression contains any Header extractors.
    /// Header-based keys are user-controlled and require IP baseline enforcement.
    pub fn has_header_extractor(&self) -> bool {
        match self {
            KeyExpr::Single(e) => matches!(e, KeyExtractor::Header(_)),
            KeyExpr::Composite(extractors) => extractors
                .iter()
                .any(|e| matches!(e, KeyExtractor::Header(_))),
        }
    }
}

/// Individual key extractor.
#[derive(Debug, Clone)]
pub enum KeyExtractor {
    /// Extract from host
    Host(Option<String>), // None = full host, Some = glob capture

    /// Extract from header value
    Header(String),

    /// Extract from path
    Path(Option<String>), // None = full path, Some = glob capture

    /// Client IP address
    ClientIp,
}

impl CompiledRule {
    /// Create a new compiled rule.
    pub fn new(name: String, condition: Expr, action: Action, else_action: Option<Action>) -> Self {
        let indexed_method = Self::extract_indexed_method(&condition);
        Self {
            name,
            condition,
            action,
            else_action,
            indexed_method,
        }
    }

    /// Extract method for indexing if the rule has a simple method check.
    /// Only extracts if method is at the top level or in a top-level AND.
    fn extract_indexed_method(expr: &Expr) -> Option<Method> {
        match expr {
            Expr::Method(m) => Some(m.clone()),
            Expr::And(left, _) => {
                // Check if left side is a method check
                if let Expr::Method(m) = left.as_ref() {
                    return Some(m.clone());
                }
                None
            }
            _ => None,
        }
    }

    /// Extract header names that are existence-only checks (no value matcher).
    /// These headers will be logged when the rule matches.
    pub fn extract_logged_headers(&self) -> Vec<String> {
        self.condition.collect_existence_headers()
    }
}

impl Expr {
    /// Collect header names that are existence-only checks (value is None).
    /// Recursively traverses the expression tree.
    pub fn collect_existence_headers(&self) -> Vec<String> {
        let mut headers = Vec::new();
        self.collect_existence_headers_recursive(&mut headers);
        headers
    }

    fn collect_existence_headers_recursive(&self, headers: &mut Vec<String>) {
        match self {
            Expr::Header { name, value: None } => {
                // Only collect headers that are existence checks (no value matcher)
                headers.push(name.clone());
            }
            Expr::Not(inner) => {
                inner.collect_existence_headers_recursive(headers);
            }
            Expr::And(left, right) | Expr::Or(left, right) => {
                left.collect_existence_headers_recursive(headers);
                right.collect_existence_headers_recursive(headers);
            }
            // Host, Path, Method, Header with value don't contribute
            _ => {}
        }
    }

    /// Produce a canonical string representation of this expression.
    /// Used for detecting duplicate conditions across rules.
    pub fn condition_signature(&self) -> String {
        match self {
            Expr::Host(glob) => format!("host(\"{}\")", glob.glob().glob()),
            Expr::Path(glob) => format!("path(\"{}\")", glob.glob().glob()),
            Expr::Method(m) => format!("method({})", m),
            Expr::Header { name, value } => match value {
                None => format!("header(\"{}\")", name),
                Some(HeaderMatch::Exact(v)) => format!("header(\"{}:{}\")", name, v),
                Some(HeaderMatch::Glob(g)) => {
                    format!("header(\"{}~{}\")", name, g.glob().glob())
                }
            },
            Expr::Not(inner) => format!("!{}", inner.condition_signature()),
            Expr::And(left, right) => format!(
                "({} && {})",
                left.condition_signature(),
                right.condition_signature()
            ),
            Expr::Or(left, right) => format!(
                "({} || {})",
                left.condition_signature(),
                right.condition_signature()
            ),
        }
    }

    /// Evaluate expression against request data.
    pub fn evaluate(&self, ctx: &EvalContext) -> bool {
        match self {
            Expr::Host(glob) => glob.is_match(ctx.host),
            Expr::Path(glob) => glob.is_match(ctx.path),
            Expr::Method(m) => ctx.method == m,
            Expr::Header { name, value } => {
                if let Some(header_value) = ctx.headers.get(name.to_lowercase().as_str()) {
                    match value {
                        None => true, // Just existence check
                        Some(HeaderMatch::Exact(expected)) => header_value == expected,
                        Some(HeaderMatch::Glob(glob)) => glob.is_match(header_value),
                    }
                } else {
                    false
                }
            }
            Expr::Not(inner) => !inner.evaluate(ctx),
            Expr::And(left, right) => {
                // Short-circuit: if left is false, don't evaluate right
                left.evaluate(ctx) && right.evaluate(ctx)
            }
            Expr::Or(left, right) => {
                // Short-circuit: if left is true, don't evaluate right
                left.evaluate(ctx) || right.evaluate(ctx)
            }
        }
    }
}

/// Context for rule evaluation containing request data.
#[derive(Debug)]
pub struct EvalContext<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub method: Method,
    pub headers: &'a std::collections::HashMap<String, String>,
    pub client_ip: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use globset::Glob;
    use std::collections::HashMap;

    fn make_glob(pattern: &str) -> GlobMatcher {
        Glob::new(pattern).unwrap().compile_matcher()
    }

    #[test]
    fn test_host_match() {
        let expr = Expr::Host(make_glob("*.example.com"));
        let headers = HashMap::new();
        let ctx = EvalContext {
            host: "api.example.com",
            path: "/",
            method: Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));

        let ctx2 = EvalContext {
            host: "other.com",
            path: "/",
            method: Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(!expr.evaluate(&ctx2));
    }

    #[test]
    fn test_and_short_circuit() {
        let expr = Expr::And(
            Box::new(Expr::Host(make_glob("never.match"))),
            Box::new(Expr::Path(make_glob("*"))), // This shouldn't be evaluated
        );
        let headers = HashMap::new();
        let ctx = EvalContext {
            host: "other.com",
            path: "/test",
            method: Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(!expr.evaluate(&ctx));
    }

    #[test]
    fn test_or_short_circuit() {
        let expr = Expr::Or(
            Box::new(Expr::Host(make_glob("*.com"))),
            Box::new(Expr::Path(make_glob("never"))), // This shouldn't be evaluated
        );
        let headers = HashMap::new();
        let ctx = EvalContext {
            host: "test.com",
            path: "/test",
            method: Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_header_existence() {
        let expr = Expr::Header {
            name: "X-Auth".to_string(),
            value: None,
        };
        let mut headers = HashMap::new();
        headers.insert("x-auth".to_string(), "token123".to_string());

        let ctx = EvalContext {
            host: "test.com",
            path: "/",
            method: Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_header_value_match() {
        let expr = Expr::Header {
            name: "X-Auth".to_string(),
            value: Some(HeaderMatch::Exact("secret".to_string())),
        };
        let mut headers = HashMap::new();
        headers.insert("x-auth".to_string(), "secret".to_string());

        let ctx = EvalContext {
            host: "test.com",
            path: "/",
            method: Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_not_expression() {
        let expr = Expr::Not(Box::new(Expr::Header {
            name: "X-Auth".to_string(),
            value: None,
        }));
        let headers = HashMap::new(); // No headers

        let ctx = EvalContext {
            host: "test.com",
            path: "/",
            method: Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx)); // !false = true
    }

    #[test]
    fn test_collect_existence_headers_simple() {
        // Single existence check
        let expr = Expr::Header {
            name: "X-Auth".to_string(),
            value: None,
        };
        let headers = expr.collect_existence_headers();
        assert_eq!(headers, vec!["X-Auth".to_string()]);
    }

    #[test]
    fn test_collect_existence_headers_with_value_ignored() {
        // Header with value match should NOT be collected
        let expr = Expr::Header {
            name: "X-Auth".to_string(),
            value: Some(HeaderMatch::Exact("secret".to_string())),
        };
        let headers = expr.collect_existence_headers();
        assert!(headers.is_empty());
    }

    #[test]
    fn test_collect_existence_headers_and_expr() {
        // AND with two existence checks
        let expr = Expr::And(
            Box::new(Expr::Header {
                name: "X-Auth".to_string(),
                value: None,
            }),
            Box::new(Expr::Header {
                name: "X-Customer-Id".to_string(),
                value: None,
            }),
        );
        let headers = expr.collect_existence_headers();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&"X-Auth".to_string()));
        assert!(headers.contains(&"X-Customer-Id".to_string()));
    }

    #[test]
    fn test_collect_existence_headers_mixed() {
        // Mix of existence check and value match - only existence collected
        let expr = Expr::And(
            Box::new(Expr::Header {
                name: "X-Auth".to_string(),
                value: Some(HeaderMatch::Exact("token".to_string())),
            }),
            Box::new(Expr::Header {
                name: "X-Request-Id".to_string(),
                value: None,
            }),
        );
        let headers = expr.collect_existence_headers();
        assert_eq!(headers, vec!["X-Request-Id".to_string()]);
    }

    #[test]
    fn test_collect_existence_headers_nested() {
        // Nested: (host && header) || !header
        let expr = Expr::Or(
            Box::new(Expr::And(
                Box::new(Expr::Host(make_glob("*.com"))),
                Box::new(Expr::Header {
                    name: "X-First".to_string(),
                    value: None,
                }),
            )),
            Box::new(Expr::Not(Box::new(Expr::Header {
                name: "X-Second".to_string(),
                value: None,
            }))),
        );
        let headers = expr.collect_existence_headers();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&"X-First".to_string()));
        assert!(headers.contains(&"X-Second".to_string()));
    }

    #[test]
    fn test_collect_existence_headers_no_headers() {
        // Expression with no header checks
        let expr = Expr::And(
            Box::new(Expr::Host(make_glob("*.com"))),
            Box::new(Expr::Path(make_glob("/api/*"))),
        );
        let headers = expr.collect_existence_headers();
        assert!(headers.is_empty());
    }

    #[test]
    fn test_method_indexing_extraction() {
        // Simple method check
        let rule = CompiledRule::new(
            "test".to_string(),
            Expr::Method(Method::GET),
            Action::Pass,
            None,
        );
        assert_eq!(rule.indexed_method, Some(Method::GET));

        // Method in AND
        let rule2 = CompiledRule::new(
            "test2".to_string(),
            Expr::And(
                Box::new(Expr::Method(Method::POST)),
                Box::new(Expr::Host(make_glob("*"))),
            ),
            Action::Pass,
            None,
        );
        assert_eq!(rule2.indexed_method, Some(Method::POST));

        // No method at top level
        let rule3 = CompiledRule::new(
            "test3".to_string(),
            Expr::Host(make_glob("*")),
            Action::Pass,
            None,
        );
        assert_eq!(rule3.indexed_method, None);
    }

    #[test]
    fn test_condition_signature_simple() {
        let expr = Expr::Host(make_glob("*.example.com"));
        assert_eq!(expr.condition_signature(), r#"host("*.example.com")"#);
    }

    #[test]
    fn test_condition_signature_and_or() {
        let expr = Expr::And(
            Box::new(Expr::Host(make_glob("*.com"))),
            Box::new(Expr::Or(
                Box::new(Expr::Method(Method::GET)),
                Box::new(Expr::Method(Method::POST)),
            )),
        );
        let sig = expr.condition_signature();
        assert_eq!(sig, r#"(host("*.com") && (method(GET) || method(POST)))"#);
    }

    #[test]
    fn test_condition_signature_not() {
        let expr = Expr::Not(Box::new(Expr::Header {
            name: "X-Auth".to_string(),
            value: None,
        }));
        assert_eq!(expr.condition_signature(), r#"!header("X-Auth")"#);
    }

    #[test]
    fn test_identical_conditions_same_signature() {
        let a = Expr::And(
            Box::new(Expr::Host(make_glob("api.*"))),
            Box::new(Expr::Path(make_glob("/v1/*"))),
        );
        let b = Expr::And(
            Box::new(Expr::Host(make_glob("api.*"))),
            Box::new(Expr::Path(make_glob("/v1/*"))),
        );
        assert_eq!(a.condition_signature(), b.condition_signature());
    }

    #[test]
    fn test_different_conditions_different_signature() {
        let a = Expr::Host(make_glob("api.*"));
        let b = Expr::Host(make_glob("web.*"));
        assert_ne!(a.condition_signature(), b.condition_signature());
    }
}
