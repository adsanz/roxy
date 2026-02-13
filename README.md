# Roxy

[![Docker Hub](https://img.shields.io/docker/v/adsanz/roxy?label=Docker%20Hub)](https://hub.docker.com/r/adsanz/roxy)

High-performance forward HTTP/S proxy with MITM TLS support, built on [Hudsucker](https://github.com/omjadas/hudsucker).

Roxy combines ACL filtering, header mangling, rate limiting, and TLS inspection with a custom rule DSL—designed for scenarios where you need to inspect and control HTTPS traffic (e.g., blocking requests missing required headers).

## Features

- **MITM TLS Interception** - Inspect and modify HTTPS traffic transparently
- **Rule DSL** - Expressive domain-specific language for traffic filtering
- **Rate Limiting** - Sliding window rate limiter with soft/hard limits and progressive throttling
- **Credit System** - Fixed-budget rate limiting with scheduled resets (daily/weekly/monthly)
- **Header Mangling** - Add/remove headers based on rule matches
- **Method-Indexed Rules** - O(1) rule lookup by HTTP method
- **Memory-Conscious** - Configurable caches and connection pools for constrained environments

## Installation

### Docker (Recommended)

```bash
docker pull adsanz/roxy:latest
```

### From Source

```bash
cargo build --release
```

## Usage

### Docker

```bash
# Run with a config file
docker run -v $(pwd)/config.yaml:/etc/roxy/config.yaml -p 8080:8080 adsanz/roxy:latest

# With TLS certificates for MITM
docker run \
  -v $(pwd)/config.yaml:/etc/roxy/config.yaml:ro \
  -v $(pwd)/certs:/etc/roxy/certs:ro \
  -p 8080:8080 \
  adsanz/roxy:latest
```

### Docker Compose

```yaml
services:
  roxy:
    image: adsanz/roxy:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/roxy/config.yaml:ro
      # - ./certs:/etc/roxy/certs:ro  # For MITM TLS
    restart: unless-stopped
```

### Binary

```bash
# Run with a config file
./target/release/roxy --config config.yaml

# The proxy will start on the configured listen address (default: 127.0.0.1:8080)
```

### TLS Certificates

Roxy can operate in two modes:

1. **Ephemeral CA** (default) - Generates a temporary CA certificate on startup. Useful for testing.

2. **Persistent CA** - Provide your own CA certificate and key in the config. Required for production use where clients need to trust the CA.

Generate CA certificates:

```bash
# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=Roxy Proxy CA/O=Roxy/C=US"
```

## Configuration

Roxy uses YAML configuration files. Here's a complete example:

```yaml
# Bind address
listen: "0.0.0.0:8080"

# Connection pool settings. See tunning below
pool:
  max_idle_per_host: 50
  idle_timeout_secs: 120

rate_limit:
  cleanup_interval_secs: 60

rules:
  # 1. Health check - always pass (simple)
  - name: "allow-health"
    rule: 'path("/health") = pass'

  # 2. Block internal paths (simple)
  - name: "block-internal"
    rule: 'path("/internal/*") = block'

  # 3. Require auth for admin endpoints (block if no auth, otherwise fall through)
  - name: "require-admin-auth"
    rule: 'path("/admin/*") && !header("Authorization") = block'

  # 4. Rate limit API by customer header — tight limit to trigger 429s
  - name: "rate-limit-api"
    rule: 'path("/api/*") && header("X-Customer-Id") = rate_limit(5/s, header(X-Customer-Id))'

  # 5. Credit-only rule — small budget to trigger exhaustion quickly
  - name: "credit-only"
    rule: 'path("/credits/*") && header("X-Customer-Id") = credit(10/d, header(X-Customer-Id))'

  # 6. Composite rate_limit + credit — exercises the full pipeline
  - name: "combo-rl-credit"
    rule: 'path("/combo/*") && header("X-Customer-Id") = rate_limit(3/s, ip + header(X-Customer-Id)) + credit(15/d, header(X-Customer-Id))'

  # 7. Rate limit by composite key (complex)
  - name: "rate-limit-composite"
    rule: 'path("/v2/*") = rate_limit(10/s, header(X-Customer-Id) + host(*))'

  # 8. Mangle backend requests
  - name: "mangle-backend"
    rule: 'host("backend.*") && method(GET) = mangle'

  # 9. Default allow (catch-all)
  - name: "allow-all"
    rule: 'host("*") = pass'

# Header modifications
headers:
  - rules: ["rate-limit-api", "combo-rl-credit"]
    add:
      - name: "X-Proxy-Processed"
        value: "true"
      - name: "X-Load-Test"
        value: "true"
    remove:
      - "X-Customer-Id"

# Throttle: progressive delay before hard limit
throttle:
  - rule: "rate-limit-api"
    soft_limit: 3
    max_delay_ms: 1000

  - rule: "combo-rl-credit"
    soft_limit: 2
    max_delay_ms: 1500

# Credit system configuration
credits:
  - rule: "credit-only"
    soft_limit: 7
    max_delay_ms: 2000
    reset_schedule: "daily@00:00"
    message: "Credit exhausted. Resets at {reset_time}."

  - rule: "combo-rl-credit"
    soft_limit: 10
    max_delay_ms: 3000
    reset_schedule: "daily@00:00"
    message: "API budget exhausted. Resets at {reset_time}."

```

### Rule Evaluation Order

**Rules are evaluated in the exact order they appear in the config file (first-match-wins).**

This is critical for writing correct rules. The proxy stops evaluating rules as soon as one matches and returns an action. To implement allow-list patterns:

```yaml
rules:
  # 1. Specific allows FIRST
  - name: "allow-health"
    rule: 'path("/health") = pass'

  - name: "allow-payment"
    rule: 'path("/payment") = pass'

  # 2. Catch-all block LAST
  - name: "block-all"
    rule: 'host("*") = block'
```

With this config:
- `GET /health` → matches rule 1 → **pass** (stops here)
- `POST /payment` → matches rule 2 → **pass** (stops here)  
- `GET /anything-else` → matches rule 3 → **block**

⚠️ **Common mistake**: Putting the catch-all block first would block everything!

### Rule DSL

**Matchers:**
| Matcher | Description | Example |
|---------|-------------|---------|
| `host("pattern")` | Match request host | `host("*.example.com")` |
| `path("pattern")` | Match request path | `path("/api/v1/*")` |
| `method(M)` | Match HTTP method | `method(GET)`, `method(POST)` |
| `header("name")` | Check header exists | `header("Authorization")` |
| `header("name:value")` | Match header value | `header("X-Version:v2")` |

**Operators:**
| Operator | Description | Example |
|----------|-------------|---------|
| `&&` | Logical AND | `host("*") && method(GET)` |
| `\|\|` | Logical OR | `path("/a") \|\| path("/b")` |
| `!` | Logical NOT | `!header("X-Auth")` |
| `()` | Grouping | `(host("a") \|\| host("b")) && method(POST)` |

**Actions:**
| Action | Description |
|--------|-------------|
| `pass` | Allow request, stop rule evaluation |
| `block` | Deny request with 403 Forbidden |
| `mangle` | Allow request, trigger header modifications |
| `rate_limit(N/unit, key)` | Sliding window rate limiting (units: `s`, `m`, `h`) |
| `credit(N/period, key)` | Credit-based rate limiting (periods: `d`, `w`, `M`) |
| `rate_limit(...) + credit(...)` | Composite: burst protection + budget enforcement |

**Ternary syntax:** `condition = action_if_true : action_if_false`

### Rate Limit Keys

Rate limit keys determine how requests are grouped for both `rate_limit` and `credit` actions:

```yaml
# Single key - limit by header value
rate_limit(100/s, header(X-Customer-Id))

# Composite key - limit by combination
rate_limit(50/s, header(X-Customer-Id) + path(*) + host(*))

# Credit-based limiting with same key syntax
credit(1000/d, header(X-Customer-Id))

# Available key sources: header(Name), path(*), host(*), ip
```

### Soft Limits & Progressive Throttling

Both `rate_limit` and `credit` rules support a soft limit that applies progressive delay before the hard limit rejects requests outright. This is configured in the YAML `throttle:` (for rate_limit) or `credits:` (for credit) sections.

The delay ramps linearly from **0 ms** at the soft limit to **max_delay_ms** at the hard limit:

```
Delay = (used - soft_limit) / (hard_limit - soft_limit) × max_delay_ms
```

```yaml
# Throttle config for a rate_limit rule
throttle:
  - rule: "api-rate-limit"     # References a rule with rate_limit() action
    soft_limit: 80              # Start delaying at 80 req/s (hard limit is 100)
    max_delay_ms: 2000          # Max 2s delay when approaching the hard limit
```

Without throttle config, rate_limit rules: allow under the limit, reject (429) over it.

### Composite Actions

Since rules use first-match-wins, you can't have separate `rate_limit` and `credit` rules on the same host/path. Use the `+` operator to combine them into a single rule:

```yaml
rules:
  - name: "api-protected"
    rule: 'host("api.*") && path("/v3/*") = rate_limit(50/s, header(X-Customer-Id)) + credit(5000/d, header(X-Customer-Id))'
```

**Semantics:**
1. Rate limit is checked first (burst/spam protection)
2. If rate limit passes, credit is checked (budget enforcement)
3. Both must pass for the request to proceed
4. If both have soft limits configured, the **maximum** delay from either system applies

The order (`rate_limit + credit` or `credit + rate_limit`) doesn't matter — rate limit is always evaluated first.

Throttle and credit configs reference the same rule name:

```yaml
throttle:
  - rule: "api-protected"
    soft_limit: 40
    max_delay_ms: 1500

credits:
  - rule: "api-protected"
    soft_limit: 4000
    max_delay_ms: 2000
    reset_schedule: "daily@00:00"
    message: "API budget exhausted. Resets at {reset_time}."
```

### Credit System

Credits are a fixed budget that resets on a schedule—unlike rate_limit's sliding window. Use credits for subscription-style quotas (e.g., 1000 API calls per day).

**DSL syntax:** `credit(N/period, key)` where period is `d` (daily), `w` (weekly), or `M` (monthly).

**Config:**

```yaml
rules:
  - name: "api-credits"
    rule: 'host("api.*") && path("/v2/*") = credit(1000/d, header(X-Customer-Id))'

credits:
  - rule: "api-credits"
    soft_limit: 800                # Optional: start progressive delay at 800/1000
    max_delay_ms: 2000             # Max delay in ms
    reset_schedule: "daily@00:00"  # Reset at midnight UTC
    message: "API credit exhausted. Resets at {reset_time}."
```

**Reset schedule formats** (times are UTC):

| Format | Example | Description |
|--------|---------|-------------|
| `daily@HH:MM` | `daily@00:00` | Every day at midnight |
| `weekly@Day-HH:MM` | `weekly@Mon-09:00` | Every Monday at 9 AM |
| `monthly@DD-HH:MM` | `monthly@01-00:00` | 1st of each month at midnight |

When credits are exhausted, the proxy returns **429 Too Many Requests** with a `Retry-After` header and the configured message (with `{reset_time}` interpolated to the next reset datetime).

## Memory Tuning

Roxy is designed to run in memory-constrained environments. The main memory consumers are the certificate cache, connection pool, and rate limit/credit storage.

### Certificate Cache

MITM-generated certificates are cached to avoid regeneration on every request. Each cached certificate (including TLS `ServerConfig`) uses ~25 KB.

```yaml
tls:
  ca_cert: "/path/to/ca.crt"
  ca_key: "/path/to/ca.key"
  cert_cache_size: 1000    # Max cached certificates (default: 1000 ≈ 25 MB)
```

| Scenario | `cert_cache_size` | Approx. Memory |
|----------|-------------------|-----------------|
| Low-memory / few hosts | 100 | ~2.5 MB |
| General use | 500-1000 | ~12-25 MB |
| High-traffic, many unique hosts | 2000-5000 | ~50-125 MB |

Cached entries have a 24-hour TTL and are evicted automatically. TLS session caches are disabled on generated configs to prevent per-host memory accumulation.

### Rate Limit & Credit Storage

Rate limit and credit counters are stored in-memory with `DashMap`. Expired entries are cleaned up periodically (configurable via `cleanup_interval_secs`, default 60s). Credit buckets unused for 48 hours are automatically removed.

```yaml
rate_limit:
  cleanup_interval_secs: 60   # How often to prune expired entries
```

## Connection Pool Tuning

Roxy maintains a pool of keep-alive connections to upstream servers. By default, the pool is bounded to prevent unbounded memory growth and mitigate DoS attacks.

### Configuration

```yaml
pool:
  max_idle_per_host: 10     # Maximum idle connections per upstream host (default: 10)
  idle_timeout_secs: 30     # Seconds before idle connections are closed (default: 30)
```

### Why Limit the Pool?

Without limits, an attacker could force memory exhaustion by making requests through the proxy to many unique hosts. Each connection consumes memory for:
- TCP socket buffers
- TLS session state
- HTTP/2 stream tables and HPACK compression state

Limiting the pool caps memory usage at `max_idle_per_host × number_of_hosts × ~50KB`.

### Tuning Guidelines

| Scenario | `max_idle_per_host` | `idle_timeout_secs` |
|----------|---------------------|---------------------|
| Few backends, high traffic | 50-100 | 60-120 |
| Many backends, low traffic | 5-10 | 15-30 |
| Untrusted clients (public proxy) | 5-10 | 15-30 |
| Internal service mesh | 20-50 | 60 |

**Trade-offs:**
- **Lower limits** = more connection churn, slightly higher latency (TLS handshake overhead)
- **Higher limits** = lower latency, higher memory usage, larger DoS attack surface

## Architecture

```
Request → [TLS Intercept] → [Parse] → [ACL] → [RateLimit] → [Mangle] → [Forward] → Response
```

### Module Structure

| Module | Responsibility | Key Types |
|--------|----------------|-----------|
| `config/` | YAML config parsing | `ProxyConfig`, `RuleConfig` |
| `rules/` | DSL parsing (nom) + method-indexed evaluation | `Expr`, `Action`, `RuleIndex` |
| `ratelimit/` | Sliding window + credit-based rate limiting | `RateLimiter`, `CreditManager` |
| `proxy/` | Hudsucker `HttpHandler` implementation | `RoxyHandler` |
| `error.rs` | Unified error types | `RoxyError` |

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| [hudsucker](https://crates.io/crates/hudsucker) | MITM HTTP/S proxy framework with TLS interception |
| [nom](https://crates.io/crates/nom) | Zero-copy parser combinators for the rule DSL |
| [globset](https://crates.io/crates/globset) | Pre-compiled glob pattern matching |
| [dashmap](https://crates.io/crates/dashmap) | Concurrent hashmap for rate limit storage |
| [chrono](https://crates.io/crates/chrono) | Date/time handling for credit resets |
| [tokio](https://crates.io/crates/tokio) | Async runtime |
| [tracing](https://crates.io/crates/tracing) | Structured logging |

### Design Decisions

1. **Method-Indexed Rules** - Rules are indexed by `Option<Method>` for O(1) lookup. Rules without a method matcher go in the `None` bucket and are always evaluated.

2. **Pre-compiled Globs** - Glob patterns are compiled to `GlobMatcher` at config load time, not per-request.

3. **Sliding Window Rate Limiting** - Uses a time-bucketed sliding window algorithm stored in `DashMap` for lock-free concurrent access.

4. **Credit System** - Fixed-budget counters with wall-clock-aligned resets via `chrono`. Separate from the sliding window limiter; shares the same key extraction logic.

5. **Error Layering** - Each layer defines its own error type. Lower layers report what failed; upper layers decide HTTP status codes.

## Testing

Run the test suite:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test rules::parser
cargo test ratelimit
```

### Test Coverage

- **Parser tests** (`src/rules/parser.rs`) - DSL syntax parsing
- **AST tests** (`src/rules/ast.rs`) - Expression evaluation logic
- **Engine tests** (`src/rules/engine.rs`) - Rule matching with mock requests
- **Rate limiter tests** (`src/ratelimit/limiter.rs`) - Sliding window edge cases
- **Credit system tests** (`src/ratelimit/credit.rs`) - Budget, throttling, resets, cleanup
- **Config tests** (`src/config/types.rs`) - YAML parsing and validation
- **Handler tests** (`src/proxy/handler.rs`) - Request processing

## Benchmarks

Benchmarks measure rule parsing and evaluation throughput across different complexity levels and rule counts.

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark group
cargo bench -- "rule_parsing"
cargo bench -- "rule_evaluation"
cargo bench -- "bulk_evaluation"
cargo bench -- "rate_limiter"

# Run benchmarks for specific complexity
cargo bench -- "Complex"
cargo bench -- "rule_evaluation/Medium"

# Run with specific rule count
cargo bench -- "/500"
```

### Benchmark Groups

| Group | Description |
|-------|-------------|
| `rule_parsing` | Time to parse rules from config into `RuleIndex` |
| `rule_evaluation` | Single request evaluation against rule set |
| `bulk_evaluation` | 1000 diverse requests against rule set |
| `mangle_evaluation` | Collecting mangle rules for header modification |
| `rate_limiter` | Rate limiter check throughput |

### Complexity Levels

- **Simple** - Single matcher: `host("example.com") = pass`
- **Medium** - 2-3 matchers with operators: `host("*.api") && method(GET) = pass`
- **Complex** - 4+ matchers with nesting, NOT, ternary: `(host("*") && !header("X-Block")) || method(POST) = block : pass`

### Example Output

```
rule_parsing/Simple/100   time: [5.5 ms]  thrpt: [18.0 Kelem/s]
rule_parsing/Complex/100  time: [12.3 ms] thrpt: [8.1 Kelem/s]

rule_evaluation/Simple/1000/match_early    time: [245 ns]
rule_evaluation/Complex/1000/no_match      time: [1.2 µs]

bulk_evaluation/Medium_rules_200           thrpt: [1.8 Melem/s]
```

## Logging

Roxy uses structured JSON logging via `tracing`. Set log level with `RUST_LOG`:

```bash
# Info level (default) - forwarded requests and actions
RUST_LOG=info ./target/release/roxy --config config.yaml

# Debug level - rule evaluation details
RUST_LOG=debug ./target/release/roxy --config config.yaml

# Trace specific modules
RUST_LOG=roxy::rules=debug,roxy::proxy=info ./target/release/roxy --config config.yaml
```

### Smart Header Logging

When a rule uses **existence-only header checks** (e.g., `header("X-Customer-Id")` without a value), Roxy automatically logs the actual header value when the rule matches. This is useful for observability without cluttering logs when headers aren't relevant to the rule.

**Example rule:**
```yaml
rules:
  - name: "track-customer"
    rule: 'header("X-Customer-Id") && path("/api/*") = pass'
```

**Log output:**
```json
{"method":"GET","host":"api.example.com","path":"/api/users","rule":"track-customer","action":"forward","headers":{"X-Customer-Id":"cust-12345"}}
```

**What gets logged:**
- `header("X-Name")` - existence check → **value is logged**
- `header("X-Name:value")` - value match → **not logged** (value is already in the rule)
- Multiple headers in a rule → all existence-only headers are logged

This only adds overhead when headers are actually checked, and the values appear in the single `forward` log line.

## License

MIT
