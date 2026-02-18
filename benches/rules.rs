//! Comprehensive benchmarks for the rule engine.
//!
//! Measures throughput (rules/sec) with configurable:
//! - Number of rules
//! - Rule complexity (simple, medium, complex)

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use http::Method;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use std::net::IpAddr;

// Import from the crate
use roxy::rules::{EvalContext, RuleIndex};
use roxy::config::RuleConfig;

/// Rule complexity levels
#[derive(Debug, Clone, Copy)]
enum Complexity {
    /// Single matcher: `host("example.com") = pass`
    Simple,
    /// 2-3 matchers with AND/OR: `host("*.api") && method(GET) = pass`
    Medium,
    /// 4+ matchers with nesting, NOT, ternary: `(host("*") && !header("X-Block")) || method(POST) = block : pass`
    Complex,
}

/// Generate a rule with specified complexity
fn generate_rule(index: usize, complexity: Complexity) -> RuleConfig {
    let (name, rule) = match complexity {
        Complexity::Simple => {
            // Rotate through different simple patterns
            match index % 4 {
                0 => (
                    format!("simple-host-{}", index),
                    format!(r#"host("service-{}.example.com") = pass"#, index),
                ),
                1 => (
                    format!("simple-path-{}", index),
                    format!(r#"path("/api/v{}/resource") = pass"#, index % 10),
                ),
                2 => (
                    format!("simple-method-{}", index),
                    format!(r#"method({}) = pass"#, ["GET", "POST", "PUT", "DELETE"][index % 4]),
                ),
                _ => (
                    format!("simple-header-{}", index),
                    format!(r#"header("X-Request-Id-{}") = pass"#, index),
                ),
            }
        }
        Complexity::Medium => {
            match index % 3 {
                0 => (
                    format!("medium-auth-{}", index),
                    format!(
                        r#"host("api-{}.example.com") && !header("Authorization") = block : pass"#,
                        index % 100
                    ),
                ),
                1 => (
                    format!("medium-method-path-{}", index),
                    format!(
                        r#"method(GET) && path("/users/{}/profile") = pass"#,
                        index
                    ),
                ),
                _ => (
                    format!("medium-or-{}", index),
                    format!(
                        r#"host("service-{}.internal") || host("service-{}.local") = block"#,
                        index, index
                    ),
                ),
            }
        }
        Complexity::Complex => {
            match index % 4 {
                0 => (
                    format!("complex-nested-{}", index),
                    format!(
                        r#"(host("*.api-{}.com") || host("*.cdn-{}.net")) && method(GET) && !header("X-Block") = pass"#,
                        index % 50, index % 50
                    ),
                ),
                1 => (
                    format!("complex-ratelimit-{}", index),
                    format!(
                        r#"host("api-{}.example.com") && path("/v1/*") = rate_limit(100/s, header(X-Customer-Id))"#,
                        index % 100
                    ),
                ),
                2 => (
                    format!("complex-mangle-{}", index),
                    format!(
                        r#"host("backend-{}.internal") && !header("X-Forwarded-For") && method(POST) = mangle"#,
                        index % 50
                    ),
                ),
                _ => (
                    format!("complex-multi-{}", index),
                    format!(
                        r#"(host("*.example.com") && path("/api/*")) || (host("*.test.com") && header("X-Test-{}:enabled")) = pass"#,
                        index
                    ),
                ),
            }
        }
    };

    RuleConfig { name, rule }
}

/// Generate a batch of rules with specified count and complexity
fn generate_rules(count: usize, complexity: Complexity) -> Vec<RuleConfig> {
    (0..count).map(|i| generate_rule(i, complexity)).collect()
}

/// Create a RuleIndex from generated rules
fn build_rule_index(rules: &[RuleConfig]) -> RuleIndex {
    RuleIndex::from_config(rules).expect("Failed to parse generated rules")
}

/// Create a test evaluation context
fn create_eval_context<'a>(
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
        client_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100))),
    }
}

/// Benchmark rule parsing throughput
fn bench_rule_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_parsing");
    
    for complexity in [Complexity::Simple, Complexity::Medium, Complexity::Complex] {
        for count in [10, 100, 500] {
            let rules = generate_rules(count, complexity);
            
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("{:?}", complexity), count),
                &rules,
                |b, rules| {
                    b.iter(|| {
                        black_box(RuleIndex::from_config(rules).unwrap())
                    });
                },
            );
        }
    }
    
    group.finish();
}

/// Benchmark rule evaluation throughput
fn bench_rule_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_evaluation");
    
    // Test contexts that exercise different code paths
    let mut headers_with_auth = HeaderMap::new();
    headers_with_auth.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_static("Bearer token123"),
    );
    headers_with_auth.insert(
        HeaderName::from_static("x-customer-id"),
        HeaderValue::from_static("cust-42"),
    );
    headers_with_auth.insert(
        HeaderName::from_static("x-request-id-5"),
        HeaderValue::from_static("req-123"),
    );
    
    let mut headers_without_auth = HeaderMap::new();
    headers_without_auth.insert(
        HeaderName::from_static("x-customer-id"),
        HeaderValue::from_static("cust-42"),
    );
    
    // Test scenarios
    let scenarios: Vec<(&str, &str, &str, Method, &HeaderMap)> = vec![
        ("match_early", "service-0.example.com", "/api/v1/resource", Method::GET, &headers_with_auth),
        ("match_middle", "api-50.example.com", "/users/50/profile", Method::GET, &headers_with_auth),
        ("match_late", "service-99.internal", "/health", Method::GET, &headers_without_auth),
        ("no_match", "unknown.domain.org", "/random/path", Method::OPTIONS, &headers_without_auth),
    ];

    for complexity in [Complexity::Simple, Complexity::Medium, Complexity::Complex] {
        for count in [10, 100, 500, 1000] {
            let rules = generate_rules(count, complexity);
            let index = build_rule_index(&rules);
            
            for (scenario_name, host, path, method, headers) in &scenarios {
                let ctx = create_eval_context(host, path, method, headers);
                
                group.throughput(Throughput::Elements(1));
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("{:?}/{}/{}", complexity, count, scenario_name),
                        count,
                    ),
                    &(&index, &ctx),
                    |b, (index, ctx)| {
                        b.iter(|| {
                            black_box(index.evaluate(ctx))
                        });
                    },
                );
            }
        }
    }
    
    group.finish();
}

/// Benchmark bulk evaluation (many requests against same rules)
fn bench_bulk_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_evaluation");
    
    // Pre-generate diverse request contexts
    let request_count = 1000;
    let mut requests: Vec<(String, String, Method, HeaderMap)> = Vec::new();
    
    let methods = [Method::GET, Method::POST, Method::PUT, Method::DELETE];
    let domains = ["example.com", "api.internal", "cdn.test.net", "backend.local"];
    
    for i in 0..request_count {
        let host = format!("service-{}.{}", i % 100, domains[i % domains.len()]);
        let path = format!("/api/v{}/users/{}/action", (i % 3) + 1, i);
        let method = methods[i % methods.len()].clone();
        
        let mut headers = HeaderMap::new();
        if i % 3 == 0 {
            headers.insert(
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(&format!("Bearer token-{}", i)).unwrap(),
            );
        }
        headers.insert(
            HeaderName::from_static("x-customer-id"),
            HeaderValue::from_str(&format!("cust-{}", i % 1000)).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_str(&format!("req-{}", i)).unwrap(),
        );
        
        requests.push((host, path, method, headers));
    }

    for complexity in [Complexity::Simple, Complexity::Medium, Complexity::Complex] {
        for rule_count in [50, 200, 500] {
            let rules = generate_rules(rule_count, complexity);
            let index = build_rule_index(&rules);
            
            group.throughput(Throughput::Elements(request_count as u64));
            group.bench_with_input(
                BenchmarkId::new(
                    format!("{:?}_rules_{}", complexity, rule_count),
                    request_count,
                ),
                &(&index, &requests),
                |b, (index, requests)| {
                    b.iter(|| {
                        for (host, path, method, headers) in requests.iter() {
                            let ctx = EvalContext {
                                host,
                                path,
                                method,
                                headers,
                                client_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
                            };
                            black_box(index.evaluate(&ctx));
                        }
                    });
                },
            );
        }
    }
    
    group.finish();
}

/// Benchmark mangle rule collection
fn bench_mangle_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mangle_evaluation");
    
    // Generate rules with some mangle actions
    let rules: Vec<RuleConfig> = (0..100)
        .map(|i| {
            if i % 5 == 0 {
                // Every 5th rule is a mangle rule
                RuleConfig {
                    name: format!("mangle-{}", i),
                    rule: format!(r#"host("backend-{}.internal") = mangle"#, i),
                }
            } else {
                generate_rule(i, Complexity::Medium)
            }
        })
        .collect();
    
    let index = build_rule_index(&rules);
    
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-customer-id"),
        HeaderValue::from_static("cust-42"),
    );
    
    // Context that matches mangle rules
    let ctx_match = create_eval_context("backend-5.internal", "/api/data", &Method::POST, &headers);
    
    // Context that doesn't match
    let ctx_nomatch = create_eval_context("api.example.com", "/users", &Method::GET, &headers);
    
    group.bench_function("mangle_match", |b| {
        b.iter(|| {
            black_box(index.evaluate_mangle_rules(&ctx_match))
        });
    });
    
    group.bench_function("mangle_no_match", |b| {
        b.iter(|| {
            black_box(index.evaluate_mangle_rules(&ctx_nomatch))
        });
    });
    
    group.finish();
}

/// Benchmark rate limiter throughput
fn bench_rate_limiter(c: &mut Criterion) {
    use roxy::ratelimit::RateLimiter;
    use std::time::Duration;
    
    let mut group = c.benchmark_group("rate_limiter");
    
    let limiter = RateLimiter::new(Duration::from_secs(60));
    
    // Single key, high frequency
    group.bench_function("single_key", |b| {
        b.iter(|| {
            black_box(limiter.check("customer-42", 10000, 1))
        });
    });
    
    // Many different keys
    group.throughput(Throughput::Elements(1000));
    group.bench_function("many_keys", |b| {
        b.iter(|| {
            for i in 0..1000 {
                black_box(limiter.check(&format!("customer-{}", i), 100, 1));
            }
        });
    });
    
    // Composite key generation
    group.bench_function("composite_key_gen", |b| {
        let customer_id = "cust-42";
        let path = "/api/v1/users/123/profile";
        let host = "api.example.com";
        
        b.iter(|| {
            black_box(format!("{}:{}:{}", customer_id, path, host))
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_rule_parsing,
    bench_rule_evaluation,
    bench_bulk_evaluation,
    bench_mangle_evaluation,
    bench_rate_limiter,
);
criterion_main!(benches);
