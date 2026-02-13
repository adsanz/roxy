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

/// Parse a complete rule string into a CompiledRule.
pub fn parse_rule(name: &str, input: &str) -> Result<CompiledRule, ParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ParseError::EmptyExpression);
    }

    match parse_rule_internal(input) {
        Ok((remaining, (condition, action, else_action))) => {
            if !remaining.trim().is_empty() {
                return Err(ParseError::UnexpectedToken {
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
        Err(e) => Err(ParseError::Nom(format!("{:?}", e))),
    }
}

/// Internal parser for rule: condition = action [: else_action]
fn parse_rule_internal(input: &str) -> IResult<&str, (Expr, Action, Option<Action>)> {
    let (input, condition) = parse_expr(input)?;
    let (input, _) = ws(char('='))(input)?;
    let (input, action) = parse_action(input)?;
    let (input, else_action) = opt(preceded(ws(char(':')), parse_action))(input)?;
    Ok((input, (condition, action, else_action)))
}

/// Parse an expression (handles OR at lowest precedence)
fn parse_expr(input: &str) -> IResult<&str, Expr> {
    parse_or_expr(input)
}

/// Parse OR expression: and_expr (|| and_expr)*
fn parse_or_expr(input: &str) -> IResult<&str, Expr> {
    let (input, first) = parse_and_expr(input)?;
    let (input, rest) = nom::multi::many0(preceded(ws(tag("||")), parse_and_expr))(input)?;

    Ok((
        input,
        rest.into_iter()
            .fold(first, |acc, expr| Expr::Or(Box::new(acc), Box::new(expr))),
    ))
}

/// Parse AND expression: unary_expr (&& unary_expr)*
fn parse_and_expr(input: &str) -> IResult<&str, Expr> {
    let (input, first) = parse_unary_expr(input)?;
    let (input, rest) = nom::multi::many0(preceded(ws(tag("&&")), parse_unary_expr))(input)?;

    Ok((
        input,
        rest.into_iter()
            .fold(first, |acc, expr| Expr::And(Box::new(acc), Box::new(expr))),
    ))
}

/// Parse unary expression: !primary | primary
fn parse_unary_expr(input: &str) -> IResult<&str, Expr> {
    alt((
        map(preceded(ws(char('!')), parse_unary_expr), |e| {
            Expr::Not(Box::new(e))
        }),
        parse_primary_expr,
    ))(input)
}

/// Parse primary expression: (expr) | function_call
fn parse_primary_expr(input: &str) -> IResult<&str, Expr> {
    alt((
        delimited(ws(char('(')), parse_expr, ws(char(')'))),
        parse_function_call,
    ))(input)
}

/// Parse function call: host(...) | path(...) | method(...) | header(...)
fn parse_function_call(input: &str) -> IResult<&str, Expr> {
    alt((parse_host, parse_path, parse_method, parse_header))(input)
}

/// Parse host("pattern")
fn parse_host(input: &str) -> IResult<&str, Expr> {
    let (input, _) = ws(tag_no_case("host"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_string_arg, ws(char(')')))(input)?;

    let glob = Glob::new(&pattern)
        .map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))?
        .compile_matcher();

    Ok((input, Expr::Host(glob)))
}

/// Parse path("pattern")
fn parse_path(input: &str) -> IResult<&str, Expr> {
    let (input, _) = ws(tag_no_case("path"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_string_arg, ws(char(')')))(input)?;

    let glob = Glob::new(&pattern)
        .map_err(|_| nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))?
        .compile_matcher();

    Ok((input, Expr::Path(glob)))
}

/// Parse method(GET|POST|...)
fn parse_method(input: &str) -> IResult<&str, Expr> {
    let (input, _) = ws(tag_no_case("method"))(input)?;
    let (input, method_str) = delimited(
        ws(char('(')),
        take_while1(|c: char| c.is_ascii_alphabetic()),
        ws(char(')')),
    )(input)?;

    let method = Method::from_bytes(method_str.to_uppercase().as_bytes()).map_err(|_| {
        nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag))
    })?;

    Ok((input, Expr::Method(method)))
}

/// Parse header("Name") or header("Name:value") or header("Name~pattern")
fn parse_header(input: &str) -> IResult<&str, Expr> {
    let (input, _) = ws(tag_no_case("header"))(input)?;
    let (input, arg) = delimited(ws(char('(')), parse_string_arg, ws(char(')')))(input)?;

    // Check for value match (Name:value) or glob match (Name~pattern)
    let (name, value) = if let Some(pos) = arg.find(':') {
        let (n, v) = arg.split_at(pos);
        (n.to_string(), Some(HeaderMatch::Exact(v[1..].to_string())))
    } else if let Some(pos) = arg.find('~') {
        let (n, v) = arg.split_at(pos);
        let glob = Glob::new(&v[1..])
            .map_err(|_| {
                nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag))
            })?
            .compile_matcher();
        (n.to_string(), Some(HeaderMatch::Glob(glob)))
    } else {
        (arg, None)
    };

    Ok((input, Expr::Header { name, value }))
}

/// Parse action: single action or composite (action + action)
fn parse_action(input: &str) -> IResult<&str, Action> {
    let (remaining, first) = parse_single_action(input)?;

    // Try to parse a second action after '+'
    // The '+' for composite actions is at the top level (outside parens),
    // so it doesn't conflict with '+' inside key expressions.
    let (remaining, second) = opt(preceded(ws(char('+')), parse_single_action))(remaining)?;

    match second {
        Some(second_action) => combine_actions(first, second_action, remaining),
        None => Ok((remaining, first)),
    }
}

/// Combine two actions into a RateLimitCredit composite.
/// Only rate_limit + credit (in either order) is supported.
fn combine_actions<'a>(a: Action, b: Action, input: &'a str) -> IResult<&'a str, Action> {
    match (a, b) {
        (
            Action::RateLimit {
                requests,
                window_secs,
                key_expr,
            },
            Action::Credit {
                credits,
                period,
                key_expr: credit_key_expr,
            },
        ) => Ok((
            input,
            Action::RateLimitCredit {
                requests,
                window_secs,
                rate_key_expr: key_expr,
                credits,
                period,
                credit_key_expr,
            },
        )),
        (
            Action::Credit {
                credits,
                period,
                key_expr: credit_key_expr,
            },
            Action::RateLimit {
                requests,
                window_secs,
                key_expr,
            },
        ) => Ok((
            input,
            Action::RateLimitCredit {
                requests,
                window_secs,
                rate_key_expr: key_expr,
                credits,
                period,
                credit_key_expr,
            },
        )),
        _ => Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

/// Parse a single action: block | pass | mangle | rate_limit(...) | credit(...)
fn parse_single_action(input: &str) -> IResult<&str, Action> {
    alt((
        value(Action::Block, ws(tag_no_case("block"))),
        value(Action::Pass, ws(tag_no_case("pass"))),
        value(Action::Mangle, ws(tag_no_case("mangle"))),
        parse_rate_limit_action,
        parse_credit_action,
    ))(input)
}

/// Parse rate_limit(100/s, key_expr)
fn parse_rate_limit_action(input: &str) -> IResult<&str, Action> {
    let (input, _) = ws(tag_no_case("rate_limit"))(input)?;
    let (input, _) = ws(char('('))(input)?;

    // Parse rate: 100/s or 100/m or 100/h
    let (input, requests) = map_res(digit1, |s: &str| s.parse::<u64>())(input)?;
    let (input, _) = char('/')(input)?;
    let (input, unit) = one_of("smh")(input)?;

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
        },
    ))
}

/// Parse credit(1000/d, key_expr)
fn parse_credit_action(input: &str) -> IResult<&str, Action> {
    let (input, _) = ws(tag_no_case("credit"))(input)?;
    let (input, _) = ws(char('('))(input)?;

    // Parse credits: 1000/d or 1000/w or 1000/M
    let (input, credits) = map_res(digit1, |s: &str| s.parse::<u64>())(input)?;
    let (input, _) = char('/')(input)?;
    let (input, period_char) = one_of("dwM")(input)?;

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
        },
    ))
}

/// Parse key expression: extractor or extractor + extractor + ...
fn parse_key_expr(input: &str) -> IResult<&str, KeyExpr> {
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
fn parse_key_extractor(input: &str) -> IResult<&str, KeyExtractor> {
    alt((
        parse_key_host,
        parse_key_header,
        parse_key_path,
        value(KeyExtractor::ClientIp, ws(tag_no_case("ip"))),
    ))(input)
}

/// Parse host key extractor
fn parse_key_host(input: &str) -> IResult<&str, KeyExtractor> {
    let (input, _) = ws(tag_no_case("host"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_key_pattern, ws(char(')')))(input)?;
    Ok((input, KeyExtractor::Host(pattern)))
}

/// Parse header key extractor
fn parse_key_header(input: &str) -> IResult<&str, KeyExtractor> {
    let (input, _) = ws(tag_no_case("header"))(input)?;
    let (input, name) = delimited(ws(char('(')), parse_identifier, ws(char(')')))(input)?;
    Ok((input, KeyExtractor::Header(name.to_string())))
}

/// Parse path key extractor
fn parse_key_path(input: &str) -> IResult<&str, KeyExtractor> {
    let (input, _) = ws(tag_no_case("path"))(input)?;
    let (input, pattern) = delimited(ws(char('(')), parse_key_pattern, ws(char(')')))(input)?;
    Ok((input, KeyExtractor::Path(pattern)))
}

/// Parse key pattern: * (full value) or a specific pattern
fn parse_key_pattern(input: &str) -> IResult<&str, Option<String>> {
    alt((value(None, ws(char('*'))), map(parse_string_arg, Some)))(input)
}

/// Parse a string argument (quoted or unquoted)
fn parse_string_arg(input: &str) -> IResult<&str, String> {
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
fn parse_identifier(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_alphanumeric() || "-_.*/?".contains(c))(input)
}

/// Wrap a parser to consume surrounding whitespace
fn ws<'a, F, O>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
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
        } = rule.action
        {
            assert_eq!(requests, 100);
            assert_eq!(window_secs, 1);
            assert!(matches!(key_expr, KeyExpr::Single(KeyExtractor::Header(_))));
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
        } = rule.action
        {
            assert_eq!(credits, 1000);
            assert_eq!(period, CreditPeriod::Day);
            assert!(matches!(key_expr, KeyExpr::Single(KeyExtractor::Header(_))));
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
}
