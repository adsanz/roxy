# Roxy - Copilot Instructions

## Project Overview

Uses Rust 2024 edition.

Roxy is a high-performance forward HTTP/S proxy with MITM TLS support, built on Hudsucker. It combines ACL filtering, header mangling, rate limiting, and TLS inspection with a custom rule DSL.

Roxy uses Hudsucker's public handler/body/certificate-authority traits, but owns a vendored copy of Hudsucker 0.24.0's proxy control path in `src/proxy/bounded.rs`. That vendored path is intentional: it lets Roxy enforce connection deadlines that Hudsucker and Hyper do not expose publicly.

## Architecture

**Pattern**: Layered MITM Proxy with Pipeline Processing

```
[Accept + Deadlines] → [TLS Intercept] → [Parse] → [ACL] → [RateLimit] → [Mangle] → [Forward] → Response
```

### Module Structure

| Module | Responsibility | Key Types |
|--------|----------------|-----------|
| `config/` | YAML config parsing, no logic | `ProxyConfig`, `RuleConfig` |
| `rules/` | DSL parsing (`nom`) + method-indexed evaluation | `Expr`, `Action`, `RuleIndex` |
| `ratelimit/` | In-memory sliding window, `DashMap` storage | `RateLimiter`, `SlidingWindow` |
| `proxy/handler.rs` | Hudsucker `HttpHandler` trait implementation | `RoxyHandler` |
| `proxy/bounded.rs` | Vendored Hudsucker 0.24.0 proxy control path + Roxy deadlines | `RoxyProxy`, `ConnectionLifecycle` |
| `proxy/authority.rs` | Custom CA authority with full certificate chain support | `RoxyAuthority` |
| `proxy/tls.rs` | Upstream TLS connector helpers | `NoVerifier` |
| `error.rs` | Unified error types with layer-appropriate abstraction | `RoxyError` |

### Error Handling

Errors propagate upward through layers. Each layer defines its own error type:
- Lower layers: `ParseError`, `ConfigError` (what failed)
- Domain layer: `RuleError` (semantic meaning)
- Proxy layer: Converts `RoxyError` → HTTP status codes (policy)

Use `thiserror` for error definitions. Never panic in request path.

## Connection Lifecycle

The production stability contract is split across protocol keep-alive and hard lifetime bounds:

- HTTP/2 PING keep-alive detects dead h2 peers. It does **not** bound healthy idle peers, because healthy clients ACK PINGs forever.
- `server_timeouts.max_connection_age_secs` bounds healthy idle clients and MITM streams. Default: `1800` seconds.
- `server_timeouts.max_connection_age_grace_secs` gives hyper a graceful-drain window before force-close. Default: `30` seconds.
- `server_timeouts.connect_initial_read_timeout_secs` closes CONNECT clients that never send tunnel/TLS bytes. Default: `15` seconds.
- `server_timeouts.tls_handshake_timeout_secs` closes stalled MITM TLS handshakes. Default: `15` seconds.
- `tcp_keepalive` is kernel dead-peer detection for accepted sockets. Defaults: enabled, `time_secs=60`, `interval_secs=30`, `retries=4`.

Do not disable inbound h2 PING as a leak fix. If long-lived healthy h2 sockets accumulate, adjust or validate max-age behavior instead.

`server_timeouts` and `tcp_keepalive` are startup-only settings. They are not hot-reloadable because they are baked into the listener/server builders.

### Vendored Hudsucker Boundary

`src/proxy/bounded.rs` is a compatibility copy of Hudsucker 0.24.0 internals. Keep edits minimal and focused. When upgrading Hudsucker, audit this file against upstream before changing behavior.

Known sharp edges:

- Hudsucker's `InternalProxy` and `Rewind` are private, so Roxy carries local equivalents.
- `HttpContext` is `#[non_exhaustive]` and has no public constructor; `make_http_context` uses a small unsafe shim for the 0.24.0 layout.
- WebSocket forwarding is implemented locally because Hudsucker's no-op/default websocket internals are not publicly constructible.
- Hyper's HTTP/2 server builder has keep-alive and stream caps, but no `max_connection_age`, `max_idle_time`, or `max_requests_per_connection` knob.

Do not patch vendored code by changing Hudsucker itself unless the project explicitly decides to fork or upstream a change.

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

- `hudsucker` - MITM HTTP/S proxy traits, body types, CA traits, and framework pieces
- `hyper`, `hyper-util`, `http` - HTTP client/server runtime used directly by the vendored proxy path
- `tokio`, `tokio-graceful` - async runtime and graceful task shutdown
- `rustls`, `hyper-rustls`, `tokio-rustls` - upstream TLS and MITM TLS handshake handling
- `hyper-tungstenite` - WebSocket upgrade detection/forwarding in the vendored proxy path
- `socket2` - listener-level TCP keepalive configuration
- `nom` - Zero-copy DSL parser (not CEL/regex for performance)
- `globset` - Pre-compiled glob patterns
- `dashmap` - Concurrent rate limit storage
- `arc-swap` - Lock-free config hot reload
- `moka` - Async certificate cache
- `serde`, `serde_yml` - Configuration
- `tikv-jemallocator` - Global allocator on non-MSVC targets to reduce RSS retention
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
warn!(target: "proxy", client_addr = %client_addr, "MITM stream exceeded max-age grace; force closing");
error!(target: "proxy", error = %e, "Proxy error");
```

## Testing & Benchmarks

```bash
# Unit tests
cargo test

# Release tests for production-like optimization paths
cargo test --release

# Build before local e2e runs; tests do not necessarily refresh target/release/roxy
cargo build --release

# Benchmarks (rule parsing, evaluation, rate limiter)
cargo bench
```

**Test patterns**:
- `src/rules/parser.rs` - Test each DSL construct in isolation
- `src/rules/engine.rs` - Test rule matching with mock requests
- `src/ratelimit/` - Test sliding window edge cases, concurrent access
- `src/config/types.rs` - Test validation for timeout, keep-alive, TCP keepalive, throttle, and credit config
- `src/proxy/bounded.rs` - Test vendored helper behavior where possible; use e2e checks for connection lifetime behavior

## Conventions

- **Visibility**: Use `pub(crate)` for internal APIs; only expose what `main.rs` needs
- **Globs**: Pre-compile to `GlobMatcher` at config load, not per-request
- **Rule indexing**: Index by `Option<Method>` for O(1) method lookup; rules without method filter go in `None` bucket
- **Timeout validation**: Reject poisoned configs early: h2 timeout must be > 0 and less than interval; max-age grace must be > 0 and less than max age; TCP keepalive time/interval must be > 0 when enabled
- **TLS**: Roxy uses `RoxyAuthority` for MITM certificates. Provide CA cert/key in config for persistent CA; otherwise the app can use an ephemeral CA path
- **Vendored proxy path**: Keep `src/proxy/bounded.rs` close to Hudsucker 0.24.0. Prefer documenting upstream gaps in `docs/hudsucker-gaps.md` over scattering workaround rationale.

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
- Vendored proxy runtime: `src/proxy/bounded.rs`
- Hudsucker gap rationale: `docs/hudsucker-gaps.md`
- Memory/socket tuning: `docs/memory-tuning.md`
