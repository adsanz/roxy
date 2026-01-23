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
    },
}

/// Key extraction expression for rate limiting.
#[derive(Debug, Clone)]
pub enum KeyExpr {
    /// Single extractor
    Single(KeyExtractor),

    /// Composite key (concatenated extractors)
    Composite(Vec<KeyExtractor>),
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
}

impl Expr {
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
}
