# Roxy - Copilot Instructions

## Project Overview

Uses Rust 2024 edition.

Roxy is a high-performance forward HTTP/S proxy with MITM TLS support, built on Hudsucker. It combines ACL filtering, header mangling, rate limiting, and TLS inspection with a custom rule DSL.

## Architecture

**Pattern**: Layered MITM Proxy with Pipeline Processing

```
Request → [TLS Intercept] → [Parse] → [ACL] → [RateLimit] → [Mangle] → [Forward] → Response
```

### Module Structure

| Module | Responsibility | Key Types |
|--------|----------------|-----------|
| `config/` | YAML config parsing, no logic | `ProxyConfig`, `RuleConfig` |
| `rules/` | DSL parsing (`nom`) + method-indexed evaluation | `Expr`, `Action`, `RuleIndex` |
| `ratelimit/` | In-memory sliding window, `DashMap` storage | `RateLimiter`, `SlidingWindow` |
| `proxy/` | Hudsucker `HttpHandler` trait implementation | `RoxyHandler` |
| `error.rs` | Unified error types with layer-appropriate abstraction | `RoxyError` |

### Error Handling

Errors propagate upward through layers. Each layer defines its own error type:
- Lower layers: `ParseError`, `ConfigError` (what failed)
- Domain layer: `RuleError` (semantic meaning)
- Proxy layer: Converts `RoxyError` → HTTP status codes (policy)

Use `thiserror` for error definitions. Never panic in request path.

## Rule DSL

**Matchers**: `host()`, `header()`, `path()`, `method()`
**Operators**: `&&`, `||`, `!`, `()` for grouping

### Rule Examples

```yaml
rules:
  # Block: deny request, return 403
  - name: "block-internal"
    rule: 'host("*.internal") || host("10.*") = block'

  # Pass: allow request (stop rule evaluation)
  - name: "allow-healthcheck"
    rule: 'path("/health") && method(GET) = pass'

  # Conditional with else: block if no auth header, otherwise pass
  - name: "require-auth"
    rule: 'host("api.example.com") && !header("X-Auth") = block : pass'

  # Rate limit: 100 req/s keyed by customer header
  - name: "rate-limit-api"
    rule: 'host("api.*") && path("/v1/*") = rate_limit(100/s, header(X-Customer-Id))'

  # Rate limit with composite key (concatenates values)
  - name: "rate-limit-composite"
    rule: 'path("/api/*") = rate_limit(50/s, header(X-Customer-Id) + path(*) + host(*))'

  # Header mangle: triggers header modification defined in `headers` section
  - name: "add-trace-header"
    rule: 'host("backend.*") = mangle'
```

### Header Mangling Config

```yaml
headers:
  - rules: ["add-trace-header"]  # Apply when these rules match
    add:
      - name: "X-Proxy-Processed"
        value: "true"
    remove:
      - "X-Internal-Only"
```

## Key Dependencies

- `hudsucker` - MITM HTTP/S proxy framework with TLS interception
- `nom` - Zero-copy DSL parser (not CEL/regex for performance)
- `globset` - Pre-compiled glob patterns
- `dashmap` - Concurrent rate limit storage
- `serde`, `serde_yaml` - Configuration
- `tracing`, `tracing-subscriber` - Structured JSON logging

## Logging

Use `tracing` crate with JSON output. Keep `info` level minimal:

```rust
// INFO: Only log forwarded requests and actions taken
info!(target: "proxy", method = %req.method, host = %host, action = "forward");
info!(target: "proxy", rule = %rule_name, action = "block", status = 403);

// DEBUG: Rule evaluation details, TLS handshakes, cache hits
debug!(target: "rules", rule = %name, matched = true);

// WARN/ERROR: Failures that need attention
warn!(target: "ratelimit", rule = %rule_name, action = "limited");
error!(target: "proxy", error = %e, "Proxy error");
```

## Testing & Benchmarks

```bash
# Unit tests
cargo test

# Benchmarks (rule parsing, evaluation, rate limiter)
cargo bench
```

**Test patterns**:
- `src/rules/parser.rs` - Test each DSL construct in isolation
- `src/rules/engine.rs` - Test rule matching with mock requests
- `src/ratelimit/` - Test sliding window edge cases, concurrent access

## Conventions

- **Visibility**: Use `pub(crate)` for internal APIs; only expose what `main.rs` needs
- **Globs**: Pre-compile to `GlobMatcher` at config load, not per-request
- **Rule indexing**: Index by `Option<Method>` for O(1) method lookup; rules without method filter go in `None` bucket
- **TLS**: Hudsucker handles MITM with `RcgenAuthority` - provide CA cert/key in config for persistent CA

## Build & Run

```bash
# Generate CA certificates (for MITM - optional)
./scripts/generate-ca.sh

# Build
cargo build --release

# Run with config
./target/release/roxy --config config.yaml

# Run with ephemeral CA (no tls config needed)
./target/release/roxy --config config.yaml
```

## File Patterns

- Config structs: `src/config/types.rs`
- Parser combinators: `src/rules/parser.rs`
- Hudsucker hooks: `src/proxy/handler.rs` (`handle_request`, `handle_response`)
