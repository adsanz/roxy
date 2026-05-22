//! Full request pipeline benchmarks.
//!
//! Measures end-to-end throughput of the request processing path:
//! parsing → rule evaluation → rate limiting → key extraction.
//! Tests the hot path that every proxied request traverses.

mod common;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::Method;
use std::net::IpAddr;
use std::time::Duration;

use roxy::config::RuleConfig;
use roxy::ratelimit::RateLimiter;
use roxy::rules::{extract_key, EvalContext};

use common::{build_rule_index, create_eval_context, headers_with_auth, headers_without_auth};

/// Benchmark the full evaluate → rate-limit check pipeline.
fn bench_request_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_pipeline");

    // Realistic rule set mixing pass, block, rate_limit, mangle
    let rules: Vec<RuleConfig> = vec![
        RuleConfig {
            name: "block-internal".into(),
            rule: r#"host("*.internal") || host("10.*") = block"#.into(),
            ..Default::default()
        },
        RuleConfig {
            name: "allow-health".into(),
            rule: r#"path("/health") && method(GET) = pass"#.into(),
            ..Default::default()
        },
        RuleConfig {
            name: "require-auth".into(),
            rule: r#"host("api.*") && !header("Authorization") = block : pass"#.into(),
            ..Default::default()
        },
        RuleConfig {
            name: "rate-limit-api".into(),
            rule: r#"host("api.*") && path("/v1/*") = rate_limit(100/s, header(X-Customer-Id))"#
                .into(),
            ..Default::default()
        },
        RuleConfig {
            name: "rate-limit-composite".into(),
            rule: r#"path("/api/*") = rate_limit(50/s, header(X-Customer-Id) + path(*) + host(*))"#
                .into(),
            ..Default::default()
        },
        RuleConfig {
            name: "mangle-backend".into(),
            rule: r#"host("backend.*") = mangle"#.into(),
            ..Default::default()
        },
    ];

    let index = build_rule_index(&rules);
    let limiter = RateLimiter::new(Duration::from_secs(60));
    let headers = headers_with_auth();
    let empty_headers = headers_without_auth();

    // Scenario 1: request that matches rate_limit rule (hot path)
    let ctx_rate_limited =
        create_eval_context("api.example.com", "/v1/users", &Method::GET, &headers);
    group.bench_function("rate_limit_match", |b| {
        b.iter(|| {
            let result = index.evaluate(&ctx_rate_limited);
            if let Some(m) = result {
                if let roxy::rules::Action::RateLimit {
                    requests,
                    window_secs,
                    key_expr,
                    ..
                } = m.action
                {
                    let key = extract_key(key_expr, &ctx_rate_limited);
                    black_box(limiter.check(&key, *requests, *window_secs));
                }
            }
        });
    });

    // Scenario 2: request that matches pass (ternary else branch)
    let ctx_pass = create_eval_context("api.example.com", "/dashboard", &Method::GET, &headers);
    group.bench_function("pass_ternary", |b| {
        b.iter(|| black_box(index.evaluate(&ctx_pass)));
    });

    // Scenario 3: request that matches block (early exit)
    let ctx_block = create_eval_context("db.internal", "/admin", &Method::POST, &empty_headers);
    group.bench_function("block_early_exit", |b| {
        b.iter(|| black_box(index.evaluate(&ctx_block)));
    });

    // Scenario 4: request that matches no rules
    let ctx_miss =
        create_eval_context("unknown.example.org", "/random", &Method::OPTIONS, &empty_headers);
    group.bench_function("no_match", |b| {
        b.iter(|| black_box(index.evaluate(&ctx_miss)));
    });

    // Scenario 5: mangle evaluation
    let ctx_mangle =
        create_eval_context("backend.example.com", "/rpc", &Method::POST, &headers);
    group.bench_function("mangle_collect", |b| {
        b.iter(|| black_box(index.evaluate_mangle_rules(&ctx_mangle)));
    });

    group.finish();
}

/// Benchmark rate limiter under contention patterns.
fn bench_rate_limiter_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter_patterns");
    let limiter = RateLimiter::new(Duration::from_secs(60));

    // High-frequency single key (simulates single customer burst)
    group.bench_function("burst_single_key", |b| {
        b.iter(|| black_box(limiter.check("customer-burst", 10000, 1)));
    });

    // Rotating through 100 keys (simulates many customers)
    group.throughput(Throughput::Elements(100));
    group.bench_function("rotating_100_keys", |b| {
        let keys: Vec<String> = (0..100).map(|i| format!("customer-{}", i)).collect();
        b.iter(|| {
            for key in &keys {
                black_box(limiter.check(key, 100, 1));
            }
        });
    });

    // Key extraction cost (composite key formatting)
    group.bench_function("composite_key_format", |b| {
        b.iter(|| {
            let mut s = String::with_capacity(64);
            s.push_str("cust-42");
            s.push(':');
            s.push_str("/api/v1/users/123/profile");
            s.push(':');
            s.push_str("api.example.com");
            black_box(s);
        });
    });

    group.finish();
}

/// Benchmark diverse request throughput against a large rule set.
fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_throughput");

    // Build a 200-rule mixed rule set
    let mut rules: Vec<RuleConfig> = Vec::with_capacity(200);
    for i in 0..50 {
        rules.push(RuleConfig {
            name: format!("host-block-{}", i),
            rule: format!(r#"host("blocked-{}.example.com") = block"#, i),
            ..Default::default()
        });
    }
    for i in 0..50 {
        rules.push(RuleConfig {
            name: format!("api-rl-{}", i),
            rule: format!(
                r#"host("api-{}.example.com") && path("/v1/*") = rate_limit(100/s, header(X-Customer-Id))"#,
                i
            ),
            ..Default::default()
        });
    }
    for i in 0..50 {
        rules.push(RuleConfig {
            name: format!("auth-check-{}", i),
            rule: format!(
                r#"host("svc-{}.internal") && !header("Authorization") = block : pass"#,
                i
            ),
            ..Default::default()
        });
    }
    for i in 0..50 {
        rules.push(RuleConfig {
            name: format!("mangle-{}", i),
            rule: format!(r#"host("backend-{}.internal") = mangle"#, i),
            ..Default::default()
        });
    }

    let index = build_rule_index(&rules);
    let limiter = RateLimiter::new(Duration::from_secs(60));

    // Pre-generate 1000 diverse requests
    let request_count = 1000;
    let methods = [Method::GET, Method::POST, Method::PUT, Method::DELETE];
    let domains = [
        "api-5.example.com",
        "svc-10.internal",
        "backend-3.internal",
        "unknown.org",
        "blocked-7.example.com",
    ];

    let requests: Vec<(String, String, Method, HeaderMap)> = (0..request_count)
        .map(|i| {
            let host = domains[i % domains.len()].to_string();
            let path = format!("/v1/users/{}", i);
            let method = methods[i % methods.len()].clone();
            let mut headers = HeaderMap::new();
            if i % 2 == 0 {
                headers.insert(
                    HeaderName::from_static("authorization"),
                    HeaderValue::from_static("Bearer tok"),
                );
            }
            headers.insert(
                HeaderName::from_static("x-customer-id"),
                HeaderValue::from_str(&format!("cust-{}", i % 50)).unwrap(),
            );
            (host, path, method, headers)
        })
        .collect();

    group.throughput(Throughput::Elements(request_count as u64));
    group.bench_function("mixed_200_rules_1k_requests", |b| {
        b.iter(|| {
            for (host, path, method, headers) in &requests {
                let ctx = EvalContext {
                    host,
                    path,
                    method,
                    headers,
                    client_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
                };
                let result = index.evaluate(&ctx);
                if let Some(ref m) = result {
                    if let roxy::rules::Action::RateLimit {
                        requests: max_req,
                        window_secs,
                        key_expr,
                        ..
                    } = m.action
                    {
                        let key = extract_key(key_expr, &ctx);
                        black_box(limiter.check(&key, *max_req, *window_secs));
                    }
                }
                black_box(result);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_request_pipeline,
    bench_rate_limiter_patterns,
    bench_throughput,
);
criterion_main!(benches);
