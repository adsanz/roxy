//! AST types for the rule DSL.
//!
//! Represents parsed rule expressions and actions.

use globset::GlobMatcher;
use http::Method;
use http::header::{HeaderMap, HeaderName};
use std::net::IpAddr;

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

    /// Pre-computed header names referenced in the rule expression (for logging).
    /// Includes both existence checks (`header("X-Auth")`) and value-match
    /// checks (`header("X-Type", "internal")`).
    /// Stores (HeaderName, String) pairs: HeaderName for zero-alloc lookup,
    /// String for the key in the logged headers HashMap.
    /// Computed once at rule compile time to avoid per-request AST traversal.
    pub logged_header_names: Vec<(HeaderName, String)>,
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
        /// Original (lowercased) name string — used for logging and key extraction
        name: String,
        /// Pre-computed HeaderName for zero-alloc HeaderMap lookups.
        /// Avoids per-evaluation `HeaderName::from_bytes()` heap allocation.
        header_name: HeaderName,
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
            KeyExpr::Single(e) => matches!(e, KeyExtractor::Header(..)),
            KeyExpr::Composite(extractors) => extractors
                .iter()
                .any(|e| matches!(e, KeyExtractor::Header(..))),
        }
    }
}

/// Individual key extractor.
#[derive(Debug, Clone)]
pub enum KeyExtractor {
    /// Extract from host (full value)
    Host,

    /// Extract from header value.
    /// Stores pre-computed HeaderName for zero-alloc HeaderMap lookups
    /// alongside the original String for key formatting.
    Header(HeaderName, String),

    /// Extract from path (full value)
    Path,

    /// Client IP address
    ClientIp,
}

impl CompiledRule {
    /// Create a new compiled rule.
    pub fn new(name: String, condition: Expr, action: Action, else_action: Option<Action>) -> Self {
        let indexed_method = Self::extract_indexed_method(&condition);
        // Pre-compute (HeaderName, String) pairs for logging.
        // HeaderName enables zero-alloc HeaderMap lookups, String is the logged key.
        let logged_header_names: Vec<(HeaderName, String)> = condition
            .collect_referenced_headers()
            .into_iter()
            .filter_map(|h| {
                let lower = h.to_lowercase();
                HeaderName::from_bytes(lower.as_bytes())
                    .ok()
                    .map(|hn| (hn, lower))
            })
            .collect();
        Self {
            name,
            condition,
            action,
            else_action,
            indexed_method,
            logged_header_names,
        }
    }

    /// Extract method for indexing if the rule has a simple method check.
    /// Only extracts if method is at the top level or in a top-level AND.
    fn extract_indexed_method(expr: &Expr) -> Option<Method> {
        match expr {
            Expr::Method(m) => Some(m.clone()),
            Expr::And(left, right) => {
                // Check both sides of top-level AND for a method check
                if let Expr::Method(m) = left.as_ref() {
                    return Some(m.clone());
                }
                if let Expr::Method(m) = right.as_ref() {
                    return Some(m.clone());
                }
                None
            }
            _ => None,
        }
    }
}

impl Expr {
    /// Collect all header names referenced in the expression tree.
    /// Includes both existence-only checks and value-match checks.
    /// Used for logging header values at match time.
    pub fn collect_referenced_headers(&self) -> Vec<String> {
        let mut headers = Vec::new();
        self.collect_referenced_headers_recursive(&mut headers);
        headers
    }

    fn collect_referenced_headers_recursive(&self, headers: &mut Vec<String>) {
        match self {
            Expr::Header { name, .. } => {
                headers.push(name.clone());
            }
            Expr::Not(inner) => {
                inner.collect_referenced_headers_recursive(headers);
            }
            Expr::And(left, right) | Expr::Or(left, right) => {
                left.collect_referenced_headers_recursive(headers);
                right.collect_referenced_headers_recursive(headers);
            }
            // Host, Path, Method don't contribute headers
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
            Expr::Header { name, value, .. } => match value {
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
            Expr::Header {
                header_name, value, ..
            } => {
                // Use pre-computed HeaderName for zero-alloc HeaderMap lookup.
                // HeaderMap::get(&HeaderName) does a direct hash probe without
                // the temporary BytesMut allocation that get(&str) requires.
                if let Some(header_value) = ctx.headers.get(header_name) {
                    let header_str = header_value.to_str().unwrap_or("");
                    match value {
                        None => true, // Just existence check
                        Some(HeaderMatch::Exact(expected)) => header_str == expected,
                        Some(HeaderMatch::Glob(glob)) => glob.is_match(header_str),
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
    pub method: &'a Method,
    pub headers: &'a HeaderMap,
    pub client_ip: Option<IpAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use globset::Glob;
    use http::header::{HeaderMap, HeaderName, HeaderValue};

    fn make_glob(pattern: &str) -> GlobMatcher {
        Glob::new(pattern).unwrap().compile_matcher()
    }

    #[test]
    fn test_host_match() {
        let expr = Expr::Host(make_glob("*.example.com"));
        let headers = HeaderMap::new();
        let ctx = EvalContext {
            host: "api.example.com",
            path: "/",
            method: &Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));

        let ctx2 = EvalContext {
            host: "other.com",
            path: "/",
            method: &Method::GET,
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
        let headers = HeaderMap::new();
        let ctx = EvalContext {
            host: "other.com",
            path: "/test",
            method: &Method::GET,
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
        let headers = HeaderMap::new();
        let ctx = EvalContext {
            host: "test.com",
            path: "/test",
            method: &Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_header_existence() {
        let expr = Expr::Header {
            name: "x-auth".to_string(),
            header_name: HeaderName::from_static("x-auth"),
            value: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-auth"),
            HeaderValue::from_static("token123"),
        );

        let ctx = EvalContext {
            host: "test.com",
            path: "/",
            method: &Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_header_value_match() {
        let expr = Expr::Header {
            name: "x-auth".to_string(),
            header_name: HeaderName::from_static("x-auth"),
            value: Some(HeaderMatch::Exact("secret".to_string())),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-auth"),
            HeaderValue::from_static("secret"),
        );

        let ctx = EvalContext {
            host: "test.com",
            path: "/",
            method: &Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_not_expression() {
        let expr = Expr::Not(Box::new(Expr::Header {
            name: "x-auth".to_string(),
            header_name: HeaderName::from_static("x-auth"),
            value: None,
        }));
        let headers = HeaderMap::new(); // No headers

        let ctx = EvalContext {
            host: "test.com",
            path: "/",
            method: &Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx)); // !false = true
    }

    #[test]
    fn test_collect_referenced_headers_simple() {
        // Single existence check
        let expr = Expr::Header {
            name: "x-auth".to_string(),
            header_name: HeaderName::from_static("x-auth"),
            value: None,
        };
        let headers = expr.collect_referenced_headers();
        assert_eq!(headers, vec!["x-auth".to_string()]);
    }

    #[test]
    fn test_collect_referenced_headers_value_match_included() {
        // Header with value match IS now collected (for logging)
        let expr = Expr::Header {
            name: "x-auth".to_string(),
            header_name: HeaderName::from_static("x-auth"),
            value: Some(HeaderMatch::Exact("secret".to_string())),
        };
        let headers = expr.collect_referenced_headers();
        assert_eq!(headers, vec!["x-auth".to_string()]);
    }

    #[test]
    fn test_collect_referenced_headers_and_expr() {
        // AND with two existence checks
        let expr = Expr::And(
            Box::new(Expr::Header {
                name: "x-auth".to_string(),
                header_name: HeaderName::from_static("x-auth"),
                value: None,
            }),
            Box::new(Expr::Header {
                name: "x-customer-id".to_string(),
                header_name: HeaderName::from_static("x-customer-id"),
                value: None,
            }),
        );
        let headers = expr.collect_referenced_headers();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&"x-auth".to_string()));
        assert!(headers.contains(&"x-customer-id".to_string()));
    }

    #[test]
    fn test_collect_referenced_headers_mixed() {
        // Mix of existence check and value match — both collected now
        let expr = Expr::And(
            Box::new(Expr::Header {
                name: "x-auth".to_string(),
                header_name: HeaderName::from_static("x-auth"),
                value: Some(HeaderMatch::Exact("token".to_string())),
            }),
            Box::new(Expr::Header {
                name: "x-request-id".to_string(),
                header_name: HeaderName::from_static("x-request-id"),
                value: None,
            }),
        );
        let headers = expr.collect_referenced_headers();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&"x-auth".to_string()));
        assert!(headers.contains(&"x-request-id".to_string()));
    }

    #[test]
    fn test_collect_referenced_headers_nested() {
        // Nested: (host && header) || !header
        let expr = Expr::Or(
            Box::new(Expr::And(
                Box::new(Expr::Host(make_glob("*.com"))),
                Box::new(Expr::Header {
                    name: "x-first".to_string(),
                    header_name: HeaderName::from_static("x-first"),
                    value: None,
                }),
            )),
            Box::new(Expr::Not(Box::new(Expr::Header {
                name: "x-second".to_string(),
                header_name: HeaderName::from_static("x-second"),
                value: None,
            }))),
        );
        let headers = expr.collect_referenced_headers();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&"x-first".to_string()));
        assert!(headers.contains(&"x-second".to_string()));
    }

    #[test]
    fn test_collect_referenced_headers_no_headers() {
        // Expression with no header checks
        let expr = Expr::And(
            Box::new(Expr::Host(make_glob("*.com"))),
            Box::new(Expr::Path(make_glob("/api/*"))),
        );
        let headers = expr.collect_referenced_headers();
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
    fn test_method_indexing_right_side_of_and() {
        // Method on right side of AND should also be extracted
        let rule = CompiledRule::new(
            "test-right".to_string(),
            Expr::And(
                Box::new(Expr::Host(make_glob("api.*"))),
                Box::new(Expr::Method(Method::DELETE)),
            ),
            Action::Block,
            None,
        );
        assert_eq!(rule.indexed_method, Some(Method::DELETE));
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
            name: "x-auth".to_string(),
            header_name: HeaderName::from_static("x-auth"),
            value: None,
        }));
        assert_eq!(expr.condition_signature(), r#"!header("x-auth")"#);
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

    // === Coverage: KeyExpr::has_header_extractor ===

    #[test]
    fn test_key_expr_single_header_has_header() {
        let expr = KeyExpr::Single(KeyExtractor::Header(
            HeaderName::from_static("x-key"),
            "x-key".to_string(),
        ));
        assert!(expr.has_header_extractor());
    }

    #[test]
    fn test_key_expr_single_host_no_header() {
        let expr = KeyExpr::Single(KeyExtractor::Host);
        assert!(!expr.has_header_extractor());
    }

    #[test]
    fn test_key_expr_single_ip_no_header() {
        let expr = KeyExpr::Single(KeyExtractor::ClientIp);
        assert!(!expr.has_header_extractor());
    }

    #[test]
    fn test_key_expr_composite_with_header() {
        let expr = KeyExpr::Composite(vec![
            KeyExtractor::Host,
            KeyExtractor::Header(HeaderName::from_static("x-key"), "x-key".to_string()),
            KeyExtractor::Path,
        ]);
        assert!(expr.has_header_extractor());
    }

    #[test]
    fn test_key_expr_composite_without_header() {
        let expr = KeyExpr::Composite(vec![
            KeyExtractor::Host,
            KeyExtractor::Path,
            KeyExtractor::ClientIp,
        ]);
        assert!(!expr.has_header_extractor());
    }

    // === Coverage: condition_signature Header with Glob ===

    #[test]
    fn test_condition_signature_header_glob() {
        let glob = globset::Glob::new("val*").unwrap().compile_matcher();
        let expr = Expr::Header {
            name: "x-custom".to_string(),
            header_name: HeaderName::from_static("x-custom"),
            value: Some(HeaderMatch::Glob(glob)),
        };
        let sig = expr.condition_signature();
        assert_eq!(sig, r#"header("x-custom~val*")"#);
    }

    // === Coverage: evaluate Header with Glob ===

    #[test]
    fn test_evaluate_header_glob_match() {
        let glob = globset::Glob::new("bearer*").unwrap().compile_matcher();
        let expr = Expr::Header {
            name: "authorization".to_string(),
            header_name: HeaderName::from_static("authorization"),
            value: Some(HeaderMatch::Glob(glob)),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("bearer-token-123"),
        );
        let ctx = EvalContext {
            host: "example.com",
            path: "/",
            method: &Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(expr.evaluate(&ctx));
    }

    #[test]
    fn test_evaluate_header_glob_no_match() {
        let glob = globset::Glob::new("bearer*").unwrap().compile_matcher();
        let expr = Expr::Header {
            name: "authorization".to_string(),
            header_name: HeaderName::from_static("authorization"),
            value: Some(HeaderMatch::Glob(glob)),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("basic-something"),
        );
        let ctx = EvalContext {
            host: "example.com",
            path: "/",
            method: &Method::GET,
            headers: &headers,
            client_ip: None,
        };
        assert!(!expr.evaluate(&ctx));
    }
}
