//! Rule DSL parser using nom combinators.
//!
//! Parses expressions like:
//!   host("*.example.com") && !header("X-Auth") = block
//!   method(GET) || method(POST) = pass
//!   host("api.*") = rate_limit(100/s, header(X-Customer-Id))

use globset::Glob;
use http::Method;
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_until, take_while1},
    character::complete::{char, digit1, multispace0, one_of},
    combinator::{map, map_res, opt, value},
    sequence::{delimited, preceded},
};

use crate::error::ParseError;
use crate::rules::ast::*;

/// Custom nom error that carries a descriptive message for later conversion
/// to a rich `ParseError` at the `parse_rule()` boundary.
#[derive(Debug)]
struct RuleParseError<'a> {
    input: &'a str,
    kind: RuleParseErrorKind,
}

#[derive(Debug)]
enum RuleParseErrorKind {
    /// Invalid glob pattern with the pattern string and the reason
    InvalidGlob { pattern: String, reason: String },
    /// Invalid HTTP method with the method string
    InvalidMethod { method: String },
    /// Invalid action combination with a description
    InvalidActionCombination { detail: String },
    /// Invalid value (e.g. rate_limit(0/s, ...))
    InvalidValue { detail: String },
    /// Generic nom error (fallback)
    Nom(#[allow(dead_code)] nom::error::ErrorKind),
}

impl<'a> nom::error::ParseError<&'a str> for RuleParseError<'a> {
    fn from_error_kind(input: &'a str, kind: nom::error::ErrorKind) -> Self {
        Self {
            input,
            kind: RuleParseErrorKind::Nom(kind),
        }
    }

    fn append(_input: &'a str, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a, E> nom::error::FromExternalError<&'a str, E> for RuleParseError<'a> {
    fn from_external_error(input: &'a str, kind: nom::error::ErrorKind, _e: E) -> Self {
        Self {
            input,
            kind: RuleParseErrorKind::Nom(kind),
        }
    }
}

/// Internal IResult type using our custom error
type RResult<'a, O> = IResult<&'a str, O, RuleParseError<'a>>;

/// Parse a complete rule string into a CompiledRule.
pub fn parse_rule(name: &str, input: &str) -> Result<CompiledRule, ParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ParseError::EmptyExpression {
            rule_name: name.to_string(),
        });
    }

    match parse_rule_internal(input) {
        Ok((remaining, (condition, action, else_action))) => {
            if !remaining.trim().is_empty() {
                return Err(ParseError::UnexpectedToken {
                    rule_name: name.to_string(),
                    position: input.len() - remaining.len(),
                    expected: "end of input".to_string(),
                    actual: remaining.to_string(),
                });
            }
            Ok(CompiledRule::new(
                name.to_string(),
                condition,
                action,
                else_action,
            ))
        }
        Err(nom::Err::Failure(e) | nom::Err::Error(e)) => {
            match e.kind {
                RuleParseErrorKind::InvalidGlob { pattern, reason } => {
                    Err(ParseError::InvalidGlob {
                        rule_name: name.to_string(),
                        pattern,
                        reason,
                    })
                }
                RuleParseErrorKind::InvalidMethod { method } => Err(ParseError::InvalidMethod {
                    rule_name: name.to_string(),
                    method,
                }),
                RuleParseErrorKind::InvalidActionCombination { detail } => {
                    Err(ParseError::InvalidActionCombination {
                        rule_name: name.to_string(),
                        detail,
                    })
                }
                RuleParseErrorKind::InvalidValue { detail } => Err(ParseError::InvalidValue {
                    rule_name: name.to_string(),
                    detail,
                }),
                RuleParseErrorKind::Nom(_) => {
                    // Derive a human-readable message from remaining input context
                    let position = input.len() - e.input.len();
                    let actual = if e.input.len() > 30 {
                        format!("{}...", &e.input[..30])
                    } else {
                        e.input.to_string()
                    };
                    Err(ParseError::UnexpectedToken {
                        rule_name: name.to_string(),
                        position,
                        expected: "valid expression or action".to_string(),
                        actual,
                    })
                }
            }
        }
        Err(nom::Err::Incomplete(_)) => Err(ParseError::Other {
            rule_name: name.to_string(),
            detail: "incomplete input".to_string(),
        }),
    }
}

/// Internal parser for rule: condition = action [: else_action]
fn parse_rule_internal(input: &str) -> RResult<'_, (Expr, Action, Option<Action>)> {
    let (input, condition) = parse_expr(input)?;
    let (input, _) = ws(char('='))(input)?;
    let (input, action) = parse_action(input)?;
    let (input, else_action) = opt(preceded(ws(char(':')), parse_action))(input)?;
    Ok((input, (condition, action, else_action)))
}

/// Parse an expression (handles OR at lowest precedence)
fn parse_expr(input: &str) -> RResult<'_, Expr> {
    parse_or_expr(input)
}

/// Parse OR expression: and_expr (|| and_expr)*
fn parse_or_expr(input: &str) -> RResult<'_, Expr> {
    let (input, first) = parse_and_expr(input)?;
    let (input, rest) = nom::multi::many0(preceded(ws(tag("||")), parse_and_expr))(input)?;

    Ok((
        input,
        rest.into_iter()
            .fold(first, |acc, expr| Expr::Or(Box::new(acc), Box::new(expr))),
    ))
}

/// Parse AND expression: unary_expr (&& unary_expr)*
fn parse_and_expr(input: &str) -> RResult<'_, Expr> {
    let (input, first) = parse_unary_expr(input)?;
    let (input, rest) = nom::multi::many0(preceded(ws(tag("&&")), parse_unary_expr))(input)?;

    Ok((
        input,
        rest.into_iter()
            .fold(first, |acc, expr| Expr::And(Box::new(acc), Box::new(expr))),
    ))
}

/// Parse unary expression: !primary | primary
fn parse_unary_expr(input: &str) -> RResult<'_, Expr> {
    alt((
        map(preceded(ws(char('!')), parse_unary_expr), |e| {
            Expr::Not(Box::new(e))
        }),
        parse_primary_expr,
    ))(input)
}

/// Parse primary expression: (expr) | function_call
fn parse_primary_expr(input: &str) -> RResult<'_, Expr> {
    alt((
        delimited(ws(char('(')), parse_expr, ws(char(')'))),
        parse_function_call,
    ))(input)
}

/// Parse function call: host(...) | path(...) | method(...) | header(...)
fn parse_function_call(input: &str) -> RResult<'_, Expr> {
    alt((parse_host, parse_path, parse_method, parse_header))(input)
}

/// Parse host("pattern")
fn parse_host(input: &str) -> RResult<'_, Expr> {
    let (input, _) = ws(tag_no_case("host"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_string_arg, ws(char(')')))(input)?;

    let glob = Glob::new(&pattern)
        .map_err(|e| {
            nom::Err::Failure(RuleParseError {
                input,
                kind: RuleParseErrorKind::InvalidGlob {
                    pattern: pattern.clone(),
                    reason: e.to_string(),
                },
            })
        })?
        .compile_matcher();

    Ok((input, Expr::Host(glob)))
}

/// Parse path("pattern")
fn parse_path(input: &str) -> RResult<'_, Expr> {
    let (input, _) = ws(tag_no_case("path"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_string_arg, ws(char(')')))(input)?;

    let glob = Glob::new(&pattern)
        .map_err(|e| {
            nom::Err::Failure(RuleParseError {
                input,
                kind: RuleParseErrorKind::InvalidGlob {
                    pattern: pattern.clone(),
                    reason: e.to_string(),
                },
            })
        })?
        .compile_matcher();

    Ok((input, Expr::Path(glob)))
}

/// Parse method(GET|POST|...)
fn parse_method(input: &str) -> RResult<'_, Expr> {
    let (input, _) = ws(tag_no_case("method"))(input)?;
    let (input, method_str) = delimited(
        ws(char('(')),
        take_while1(|c: char| c.is_ascii_alphabetic()),
        ws(char(')')),
    )(input)?;

    let method = Method::from_bytes(method_str.to_uppercase().as_bytes()).map_err(|_| {
        nom::Err::Failure(RuleParseError {
            input,
            kind: RuleParseErrorKind::InvalidMethod {
                method: method_str.to_string(),
            },
        })
    })?;

    Ok((input, Expr::Method(method)))
}

/// Parse header("Name") or header("Name:value") or header("Name~pattern")
fn parse_header(input: &str) -> RResult<'_, Expr> {
    let (input, _) = ws(tag_no_case("header"))(input)?;
    let (input, arg) = delimited(ws(char('(')), parse_string_arg, ws(char(')')))(input)?;

    // Check for value match (Name:value) or glob match (Name~pattern)
    let (name, value) = if let Some(pos) = arg.find(':') {
        let (n, v) = arg.split_at(pos);
        (n.to_string(), Some(HeaderMatch::Exact(v[1..].to_string())))
    } else if let Some(pos) = arg.find('~') {
        let (n, v) = arg.split_at(pos);
        let glob = Glob::new(&v[1..])
            .map_err(|e| {
                nom::Err::Failure(RuleParseError {
                    input,
                    kind: RuleParseErrorKind::InvalidGlob {
                        pattern: v[1..].to_string(),
                        reason: e.to_string(),
                    },
                })
            })?
            .compile_matcher();
        (n.to_string(), Some(HeaderMatch::Glob(glob)))
    } else {
        (arg, None)
    };

    Ok((input, Expr::Header { name, value }))
}

/// Parse action: single action or composite (action + action)
fn parse_action(input: &str) -> RResult<'_, Action> {
    let (remaining, first) = parse_single_action(input)?;

    // Try to parse additional actions after '+'
    // The '+' for composite actions is at the top level (outside parens),
    // so it doesn't conflict with '+' inside key expressions.
    let (remaining, second) = opt(preceded(ws(char('+')), parse_single_action))(remaining)?;

    match second {
        Some(second_action) => {
            // Try to parse an optional third action
            let (remaining, third) = opt(preceded(ws(char('+')), parse_single_action))(remaining)?;
            combine_actions(first, second_action, third, remaining)
        }
        None => Ok((remaining, first)),
    }
}

/// Combine two or three actions into a composite.
/// Supported combinations:
///   - rate_limit + credit (or reverse) → RateLimitCredit
///   - rate_limit + mangle (or reverse) → RateLimit { mangle: true }
///   - credit + mangle (or reverse) → Credit { mangle: true }
///   - rate_limit + credit + mangle (any order) → RateLimitCredit { mangle: true }
fn combine_actions<'a>(
    a: Action,
    b: Action,
    c: Option<Action>,
    input: &'a str,
) -> RResult<'a, Action> {
    // Collect actions into categorized slots
    let actions: Vec<Action> = match c {
        Some(third) => vec![a, b, third],
        None => vec![a, b],
    };

    let mut rate_limit: Option<(u64, u64, KeyExpr)> = None;
    let mut credit: Option<(u64, CreditPeriod, KeyExpr)> = None;
    let mut has_mangle = false;

    for action in &actions {
        match action {
            Action::RateLimit {
                requests,
                window_secs,
                key_expr,
                ..
            } => {
                if rate_limit.is_some() {
                    return Err(nom::Err::Failure(RuleParseError {
                        input,
                        kind: RuleParseErrorKind::InvalidActionCombination {
                            detail: "duplicate 'rate_limit' in composite action".to_string(),
                        },
                    }));
                }
                rate_limit = Some((*requests, *window_secs, key_expr.clone()));
            }
            Action::Credit {
                credits,
                period,
                key_expr,
                ..
            } => {
                if credit.is_some() {
                    return Err(nom::Err::Failure(RuleParseError {
                        input,
                        kind: RuleParseErrorKind::InvalidActionCombination {
                            detail: "duplicate 'credit' in composite action".to_string(),
                        },
                    }));
                }
                credit = Some((*credits, *period, key_expr.clone()));
            }
            Action::Mangle => {
                if has_mangle {
                    return Err(nom::Err::Failure(RuleParseError {
                        input,
                        kind: RuleParseErrorKind::InvalidActionCombination {
                            detail: "duplicate 'mangle' in composite action".to_string(),
                        },
                    }));
                }
                has_mangle = true;
            }
            other => {
                let action_name = match other {
                    Action::Block => "block",
                    Action::Pass => "pass",
                    _ => "unknown",
                };
                return Err(nom::Err::Failure(RuleParseError {
                    input,
                    kind: RuleParseErrorKind::InvalidActionCombination {
                        detail: format!(
                            "cannot combine '{}' with other actions — only rate_limit, credit, and mangle can be combined",
                            action_name
                        ),
                    },
                }));
            }
        }
    }

    match (rate_limit, credit, has_mangle) {
        // rate_limit + credit (+ optional mangle)
        (
            Some((requests, window_secs, rate_key_expr)),
            Some((credits, period, credit_key_expr)),
            mangle,
        ) => Ok((
            input,
            Action::RateLimitCredit {
                requests,
                window_secs,
                rate_key_expr,
                credits,
                period,
                credit_key_expr,
                mangle,
            },
        )),
        // rate_limit + mangle
        (Some((requests, window_secs, key_expr)), None, true) => Ok((
            input,
            Action::RateLimit {
                requests,
                window_secs,
                key_expr,
                mangle: true,
            },
        )),
        // credit + mangle
        (None, Some((credits, period, key_expr)), true) => Ok((
            input,
            Action::Credit {
                credits,
                period,
                key_expr,
                mangle: true,
            },
        )),
        // Any other combo is invalid
        _ => Err(nom::Err::Failure(RuleParseError {
            input,
            kind: RuleParseErrorKind::InvalidActionCombination {
                detail: "unsupported action combination".to_string(),
            },
        })),
    }
}

/// Parse a single action: block | pass | mangle | rate_limit(...) | credit(...)
fn parse_single_action(input: &str) -> RResult<'_, Action> {
    alt((
        value(Action::Block, ws(tag_no_case("block"))),
        value(Action::Pass, ws(tag_no_case("pass"))),
        value(Action::Mangle, ws(tag_no_case("mangle"))),
        parse_rate_limit_action,
        parse_credit_action,
    ))(input)
}

/// Parse rate_limit(100/s, key_expr)
fn parse_rate_limit_action(input: &str) -> RResult<'_, Action> {
    let (input, _) = ws(tag_no_case("rate_limit"))(input)?;
    let (input, _) = ws(char('('))(input)?;

    // Parse rate: 100/s or 100/m or 100/h
    let (input, requests) = map_res(digit1, |s: &str| s.parse::<u64>())(input)?;
    let (input, _) = char('/')(input)?;
    let (input, unit) = one_of("smh")(input)?;

    if requests == 0 {
        return Err(nom::Err::Failure(RuleParseError {
            input,
            kind: RuleParseErrorKind::InvalidValue {
                detail: "rate_limit requests must be > 0".to_string(),
            },
        }));
    }

    let window_secs = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        _ => unreachable!(),
    };

    // Parse key expression
    let (input, _) = ws(char(','))(input)?;
    let (input, key_expr) = parse_key_expr(input)?;
    let (input, _) = ws(char(')'))(input)?;

    Ok((
        input,
        Action::RateLimit {
            requests,
            window_secs,
            key_expr,
            mangle: false,
        },
    ))
}

/// Parse credit(1000/d, key_expr)
fn parse_credit_action(input: &str) -> RResult<'_, Action> {
    let (input, _) = ws(tag_no_case("credit"))(input)?;
    let (input, _) = ws(char('('))(input)?;

    // Parse credits: 1000/d or 1000/w or 1000/M
    let (input, credits) = map_res(digit1, |s: &str| s.parse::<u64>())(input)?;
    let (input, _) = char('/')(input)?;
    let (input, period_char) = one_of("dwM")(input)?;

    if credits == 0 {
        return Err(nom::Err::Failure(RuleParseError {
            input,
            kind: RuleParseErrorKind::InvalidValue {
                detail: "credit budget must be > 0".to_string(),
            },
        }));
    }

    let period = match period_char {
        'd' => CreditPeriod::Day,
        'w' => CreditPeriod::Week,
        'M' => CreditPeriod::Month,
        _ => unreachable!(),
    };

    // Parse key expression
    let (input, _) = ws(char(','))(input)?;
    let (input, key_expr) = parse_key_expr(input)?;
    let (input, _) = ws(char(')'))(input)?;

    Ok((
        input,
        Action::Credit {
            credits,
            period,
            key_expr,
            mangle: false,
        },
    ))
}

/// Parse key expression: extractor or extractor + extractor + ...
fn parse_key_expr(input: &str) -> RResult<'_, KeyExpr> {
    let (input, first) = parse_key_extractor(input)?;
    let (input, rest) = nom::multi::many0(preceded(ws(char('+')), parse_key_extractor))(input)?;

    if rest.is_empty() {
        Ok((input, KeyExpr::Single(first)))
    } else {
        let mut extractors = vec![first];
        extractors.extend(rest);
        Ok((input, KeyExpr::Composite(extractors)))
    }
}

/// Parse single key extractor: host(*) | header(Name) | path(*) | ip
fn parse_key_extractor(input: &str) -> RResult<'_, KeyExtractor> {
    alt((
        parse_key_host,
        parse_key_header,
        parse_key_path,
        value(KeyExtractor::ClientIp, ws(tag_no_case("ip"))),
    ))(input)
}

/// Parse host key extractor
fn parse_key_host(input: &str) -> RResult<'_, KeyExtractor> {
    let (input, _) = ws(tag_no_case("host"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_key_pattern, ws(char(')')))(input)?;
    Ok((input, KeyExtractor::Host(pattern)))
}

/// Parse header key extractor
fn parse_key_header(input: &str) -> RResult<'_, KeyExtractor> {
    let (input, _) = ws(tag_no_case("header"))(input)?;
    let (input, name) = delimited(ws(char('(')), parse_identifier, ws(char(')')))(input)?;
    Ok((input, KeyExtractor::Header(name.to_string())))
}

/// Parse path key extractor
fn parse_key_path(input: &str) -> RResult<'_, KeyExtractor> {
    let (input, _) = ws(tag_no_case("path"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_key_pattern, ws(char(')')))(input)?;
    Ok((input, KeyExtractor::Path(pattern)))
}

/// Parse key pattern: * (full value) or a specific pattern
fn parse_key_pattern(input: &str) -> RResult<'_, Option<String>> {
    alt((value(None, ws(char('*'))), map(parse_string_arg, Some)))(input)
}

/// Parse a string argument (quoted or unquoted)
fn parse_string_arg(input: &str) -> RResult<'_, String> {
    alt((
        // Double-quoted string
        map(
            delimited(char('"'), take_until("\""), char('"')),
            |s: &str| s.to_string(),
        ),
        // Single-quoted string
        map(
            delimited(char('\''), take_until("'"), char('\'')),
            |s: &str| s.to_string(),
        ),
        // Unquoted identifier-like
        map(parse_identifier, |s| s.to_string()),
    ))(input)
}

/// Parse an identifier (alphanumeric, -, _, ., *, /)
fn parse_identifier(input: &str) -> RResult<'_, &str> {
    take_while1(|c: char| c.is_alphanumeric() || "-_.*/?".contains(c))(input)
}

/// Wrap a parser to consume surrounding whitespace
fn ws<'a, F, O>(inner: F) -> impl FnMut(&'a str) -> RResult<'a, O>
where
    F: FnMut(&'a str) -> RResult<'a, O>,
{
    delimited(multispace0, inner, multispace0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_block() {
        let rule = parse_rule("test", r#"host("*.internal") = block"#).unwrap();
        assert_eq!(rule.name, "test");
        assert!(matches!(rule.action, Action::Block));
    }

    #[test]
    fn test_parse_method_pass() {
        let rule = parse_rule("test", "method(GET) = pass").unwrap();
        assert!(matches!(rule.action, Action::Pass));
        assert_eq!(rule.indexed_method, Some(Method::GET));
    }

    #[test]
    fn test_parse_and_expression() {
        let rule = parse_rule("test", r#"host("api.*") && !header("X-Auth") = block"#).unwrap();
        assert!(matches!(rule.condition, Expr::And(_, _)));
    }

    #[test]
    fn test_parse_or_expression() {
        let rule = parse_rule("test", "method(GET) || method(POST) = pass").unwrap();
        assert!(matches!(rule.condition, Expr::Or(_, _)));
    }

    #[test]
    fn test_parse_ternary() {
        let rule = parse_rule("test", r#"header("X-Auth") = pass : block"#).unwrap();
        assert!(matches!(rule.action, Action::Pass));
        assert!(matches!(rule.else_action, Some(Action::Block)));
    }

    #[test]
    fn test_parse_rate_limit() {
        let rule = parse_rule(
            "test",
            r#"host("api.*") = rate_limit(100/s, header(X-Customer-Id))"#,
        )
        .unwrap();
        if let Action::RateLimit {
            requests,
            window_secs,
            key_expr,
            mangle,
        } = rule.action
        {
            assert_eq!(requests, 100);
            assert_eq!(window_secs, 1);
            assert!(matches!(key_expr, KeyExpr::Single(KeyExtractor::Header(_))));
            assert!(!mangle);
        } else {
            panic!("Expected RateLimit action");
        }
    }

    #[test]
    fn test_parse_composite_key() {
        let rule = parse_rule(
            "test",
            r#"path("/api/*") = rate_limit(50/m, header(X-Customer-Id) + path(*) + host(*))"#,
        )
        .unwrap();
        if let Action::RateLimit { key_expr, .. } = rule.action {
            if let KeyExpr::Composite(extractors) = key_expr {
                assert_eq!(extractors.len(), 3);
            } else {
                panic!("Expected Composite key");
            }
        } else {
            panic!("Expected RateLimit action");
        }
    }

    #[test]
    fn test_parse_header_with_value() {
        let rule = parse_rule("test", r#"header("X-Auth:secret") = pass"#).unwrap();
        if let Expr::Header { name, value } = &rule.condition {
            assert_eq!(name, "X-Auth");
            assert!(matches!(value, Some(HeaderMatch::Exact(v)) if v == "secret"));
        } else {
            panic!("Expected Header expression");
        }
    }

    #[test]
    fn test_parse_nested_groups() {
        let rule = parse_rule(
            "test",
            r#"(method(GET) || method(POST)) && host("api.*") = pass"#,
        )
        .unwrap();
        assert!(matches!(rule.condition, Expr::And(_, _)));
    }

    #[test]
    fn test_parse_mangle_action() {
        let rule = parse_rule("test", r#"host("backend.*") = mangle"#).unwrap();
        assert!(matches!(rule.action, Action::Mangle));
    }

    #[test]
    fn test_empty_expression_error() {
        let result = parse_rule("test", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_case_insensitive_keywords() {
        let rule = parse_rule("test", r#"HOST("*.com") && METHOD(get) = BLOCK"#).unwrap();
        assert!(matches!(rule.action, Action::Block));
    }

    #[test]
    fn test_parse_credit_daily() {
        let rule = parse_rule(
            "test",
            r#"host("api.*") = credit(1000/d, header(X-Customer-Id))"#,
        )
        .unwrap();
        if let Action::Credit {
            credits,
            period,
            key_expr,
            mangle,
        } = rule.action
        {
            assert_eq!(credits, 1000);
            assert_eq!(period, CreditPeriod::Day);
            assert!(matches!(key_expr, KeyExpr::Single(KeyExtractor::Header(_))));
            assert!(!mangle);
        } else {
            panic!("Expected Credit action, got {:?}", rule.action);
        }
    }

    #[test]
    fn test_parse_credit_weekly() {
        let rule = parse_rule(
            "test",
            r#"path("/api/*") = credit(5000/w, header(X-Api-Key))"#,
        )
        .unwrap();
        if let Action::Credit {
            credits, period, ..
        } = rule.action
        {
            assert_eq!(credits, 5000);
            assert_eq!(period, CreditPeriod::Week);
        } else {
            panic!("Expected Credit action");
        }
    }

    #[test]
    fn test_parse_credit_monthly() {
        let rule = parse_rule("test", r#"host("*") = credit(50000/M, header(X-Tenant))"#).unwrap();
        if let Action::Credit {
            credits, period, ..
        } = rule.action
        {
            assert_eq!(credits, 50000);
            assert_eq!(period, CreditPeriod::Month);
        } else {
            panic!("Expected Credit action");
        }
    }

    #[test]
    fn test_parse_credit_composite_key() {
        let rule = parse_rule(
            "test",
            r#"path("/api/*") = credit(1000/d, header(X-Customer-Id) + path(*))"#,
        )
        .unwrap();
        if let Action::Credit { key_expr, .. } = rule.action {
            if let KeyExpr::Composite(extractors) = key_expr {
                assert_eq!(extractors.len(), 2);
            } else {
                panic!("Expected Composite key");
            }
        } else {
            panic!("Expected Credit action");
        }
    }

    #[test]
    fn test_parse_rate_limit_plus_credit() {
        let rule = parse_rule(
            "test",
            r#"host("api.*") = rate_limit(100/s, header(X-Id)) + credit(1000/d, header(X-Id))"#,
        )
        .unwrap();
        if let Action::RateLimitCredit {
            requests,
            window_secs,
            rate_key_expr,
            credits,
            period,
            credit_key_expr,
            mangle,
        } = rule.action
        {
            assert_eq!(requests, 100);
            assert_eq!(window_secs, 1);
            assert_eq!(credits, 1000);
            assert_eq!(period, CreditPeriod::Day);
            assert!(matches!(
                rate_key_expr,
                KeyExpr::Single(KeyExtractor::Header(_))
            ));
            assert!(matches!(
                credit_key_expr,
                KeyExpr::Single(KeyExtractor::Header(_))
            ));
            assert!(!mangle);
        } else {
            panic!("Expected RateLimitCredit action, got {:?}", rule.action);
        }
    }

    #[test]
    fn test_parse_credit_plus_rate_limit() {
        // Reverse order: credit first, then rate_limit
        let rule = parse_rule(
            "test",
            r#"host("api.*") = credit(500/w, header(X-Key)) + rate_limit(50/m, ip)"#,
        )
        .unwrap();
        if let Action::RateLimitCredit {
            requests,
            window_secs,
            credits,
            period,
            ..
        } = rule.action
        {
            assert_eq!(requests, 50);
            assert_eq!(window_secs, 60);
            assert_eq!(credits, 500);
            assert_eq!(period, CreditPeriod::Week);
        } else {
            panic!("Expected RateLimitCredit action, got {:?}", rule.action);
        }
    }

    #[test]
    fn test_parse_composite_with_composite_keys() {
        let rule = parse_rule(
            "test",
            r#"path("/v3/*") = rate_limit(100/s, header(X-Id) + ip) + credit(5000/M, header(X-Id))"#,
        )
        .unwrap();
        if let Action::RateLimitCredit {
            rate_key_expr,
            credit_key_expr,
            ..
        } = rule.action
        {
            assert!(matches!(rate_key_expr, KeyExpr::Composite(_)));
            assert!(matches!(
                credit_key_expr,
                KeyExpr::Single(KeyExtractor::Header(_))
            ));
        } else {
            panic!("Expected RateLimitCredit action, got {:?}", rule.action);
        }
    }

    #[test]
    fn test_parse_invalid_composite_block_plus_credit() {
        // block + credit is not valid
        let result = parse_rule(
            "test",
            r#"host("api.*") = block + credit(1000/d, header(X-Id))"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rate_limit_plus_mangle() {
        let rule = parse_rule(
            "test",
            r#"host("api.*") = rate_limit(50/s, header(X-Id)) + mangle"#,
        )
        .unwrap();
        if let Action::RateLimit {
            requests,
            window_secs,
            key_expr,
            mangle,
        } = rule.action
        {
            assert_eq!(requests, 50);
            assert_eq!(window_secs, 1);
            assert!(matches!(key_expr, KeyExpr::Single(KeyExtractor::Header(_))));
            assert!(mangle);
        } else {
            panic!(
                "Expected RateLimit action with mangle, got {:?}",
                rule.action
            );
        }
    }

    #[test]
    fn test_parse_mangle_plus_rate_limit() {
        // Reverse order: mangle first
        let rule = parse_rule("test", r#"host("api.*") = mangle + rate_limit(50/s, ip)"#).unwrap();
        if let Action::RateLimit {
            requests,
            window_secs,
            mangle,
            ..
        } = rule.action
        {
            assert_eq!(requests, 50);
            assert_eq!(window_secs, 1);
            assert!(mangle);
        } else {
            panic!(
                "Expected RateLimit action with mangle, got {:?}",
                rule.action
            );
        }
    }

    #[test]
    fn test_parse_credit_plus_mangle() {
        let rule = parse_rule(
            "test",
            r#"host("api.*") = credit(1000/d, header(X-Id)) + mangle"#,
        )
        .unwrap();
        if let Action::Credit {
            credits,
            period,
            mangle,
            ..
        } = rule.action
        {
            assert_eq!(credits, 1000);
            assert_eq!(period, CreditPeriod::Day);
            assert!(mangle);
        } else {
            panic!("Expected Credit action with mangle, got {:?}", rule.action);
        }
    }

    #[test]
    fn test_parse_mangle_plus_credit() {
        // Reverse order: mangle first
        let rule = parse_rule("test", r#"host("api.*") = mangle + credit(500/w, ip)"#).unwrap();
        if let Action::Credit {
            credits,
            period,
            mangle,
            ..
        } = rule.action
        {
            assert_eq!(credits, 500);
            assert_eq!(period, CreditPeriod::Week);
            assert!(mangle);
        } else {
            panic!("Expected Credit action with mangle, got {:?}", rule.action);
        }
    }

    #[test]
    fn test_parse_rate_limit_credit_mangle() {
        // Three-way composite
        let rule = parse_rule(
            "test",
            r#"host("api.*") = rate_limit(100/s, header(X-Id)) + credit(1000/d, header(X-Id)) + mangle"#,
        )
        .unwrap();
        if let Action::RateLimitCredit {
            requests,
            credits,
            mangle,
            ..
        } = rule.action
        {
            assert_eq!(requests, 100);
            assert_eq!(credits, 1000);
            assert!(mangle);
        } else {
            panic!(
                "Expected RateLimitCredit action with mangle, got {:?}",
                rule.action
            );
        }
    }

    #[test]
    fn test_parse_mangle_rate_limit_credit() {
        // Three-way composite, mangle first
        let rule = parse_rule(
            "test",
            r#"host("api.*") = mangle + rate_limit(50/m, ip) + credit(500/w, ip)"#,
        )
        .unwrap();
        if let Action::RateLimitCredit {
            requests,
            window_secs,
            credits,
            period,
            mangle,
            ..
        } = rule.action
        {
            assert_eq!(requests, 50);
            assert_eq!(window_secs, 60);
            assert_eq!(credits, 500);
            assert_eq!(period, CreditPeriod::Week);
            assert!(mangle);
        } else {
            panic!(
                "Expected RateLimitCredit action with mangle, got {:?}",
                rule.action
            );
        }
    }

    #[test]
    fn test_parse_invalid_block_plus_mangle() {
        // block + mangle is not valid
        let result = parse_rule("test", r#"host("api.*") = block + mangle"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_pass_plus_mangle() {
        // pass + mangle is not valid
        let result = parse_rule("test", r#"host("api.*") = pass + mangle"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_duplicate_mangle() {
        // mangle + mangle is not valid
        let result = parse_rule("test", r#"host("api.*") = mangle + mangle"#);
        assert!(result.is_err());
    }

    // === New tests for enriched error messages ===

    #[test]
    fn test_error_includes_rule_name() {
        let result = parse_rule("my-fancy-rule", "");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("my-fancy-rule"),
            "Error should contain rule name: {}",
            msg
        );
    }

    #[test]
    fn test_empty_expression_error_variant() {
        let result = parse_rule("empty-rule", "   ");
        match result {
            Err(ParseError::EmptyExpression { rule_name }) => {
                assert_eq!(rule_name, "empty-rule");
            }
            other => panic!("Expected EmptyExpression, got {:?}", other),
        }
    }

    #[test]
    fn test_unexpected_token_includes_position() {
        let result = parse_rule("trailing", r#"host("*.com") = block EXTRA"#);
        match result {
            Err(ParseError::UnexpectedToken {
                rule_name,
                position,
                ..
            }) => {
                assert_eq!(rule_name, "trailing");
                assert!(position > 0);
            }
            other => panic!("Expected UnexpectedToken, got {:?}", other),
        }
    }

    #[test]
    fn test_zero_rate_limit_rejected() {
        let result = parse_rule("zero-rate", r#"host("*") = rate_limit(0/s, ip)"#);
        match result {
            Err(ParseError::InvalidValue { rule_name, detail }) => {
                assert_eq!(rule_name, "zero-rate");
                assert!(
                    detail.contains("rate_limit"),
                    "Detail should mention rate_limit: {}",
                    detail
                );
            }
            other => panic!("Expected InvalidValue, got {:?}", other),
        }
    }

    #[test]
    fn test_zero_credit_rejected() {
        let result = parse_rule("zero-credit", r#"host("*") = credit(0/d, ip)"#);
        match result {
            Err(ParseError::InvalidValue { rule_name, detail }) => {
                assert_eq!(rule_name, "zero-credit");
                assert!(
                    detail.contains("credit"),
                    "Detail should mention credit: {}",
                    detail
                );
            }
            other => panic!("Expected InvalidValue, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_glob_error() {
        let result = parse_rule("bad-glob", r#"host("[invalid") = block"#);
        match result {
            Err(ParseError::InvalidGlob {
                rule_name, pattern, ..
            }) => {
                assert_eq!(rule_name, "bad-glob");
                assert_eq!(pattern, "[invalid");
            }
            other => panic!("Expected InvalidGlob, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_action_combo_error() {
        let result = parse_rule("bad-combo", r#"host("*") = block + credit(100/d, ip)"#);
        match result {
            Err(ParseError::InvalidActionCombination { rule_name, detail }) => {
                assert_eq!(rule_name, "bad-combo");
                assert!(
                    detail.contains("block"),
                    "Detail should mention 'block': {}",
                    detail
                );
            }
            other => panic!("Expected InvalidActionCombination, got {:?}", other),
        }
    }

    #[test]
    fn test_duplicate_rate_limit_combo_error() {
        let result = parse_rule(
            "dup-rl",
            r#"host("*") = rate_limit(10/s, ip) + rate_limit(20/s, ip)"#,
        );
        match result {
            Err(ParseError::InvalidActionCombination { rule_name, detail }) => {
                assert_eq!(rule_name, "dup-rl");
                assert!(
                    detail.contains("duplicate"),
                    "Detail should mention duplicate: {}",
                    detail
                );
            }
            other => panic!("Expected InvalidActionCombination, got {:?}", other),
        }
    }
}
