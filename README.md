# Roxy

[![Docker Hub](https://img.shields.io/docker/v/adsanz/roxy?label=Docker%20Hub)](https://hub.docker.com/r/adsanz/roxy)

High-performance forward HTTP/S proxy with MITM TLS support, built on [Hudsucker](https://github.com/omjadas/hudsucker).

Roxy combines ACL filtering, header mangling, rate limiting, and TLS inspection with a custom rule DSL—designed for scenarios where you need to inspect and control HTTPS traffic (e.g., blocking requests missing required headers).

## Features

- **MITM TLS Interception** - Inspect and modify HTTPS traffic transparently
- **Rule DSL** - Expressive domain-specific language for traffic filtering
- **Rate Limiting** - Sliding window rate limiter with flexible key extraction
- **Header Mangling** - Add/remove headers based on rule matches
- **Method-Indexed Rules** - O(1) rule lookup by HTTP method

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
# Proxy server settings
listen: "0.0.0.0:8080"

# TLS settings (optional - uses ephemeral CA if omitted)
tls:
  ca_cert: "/path/to/ca.crt"
  ca_key: "/path/to/ca.key"

# Rule definitions (evaluated in order - first match wins!)
rules:
  # Allow health checks without further processing
  - name: "allow-healthcheck"
    rule: 'path("/health") && method(GET) = pass'

  # Allow payment endpoint
  - name: "allow-payment"
    rule: 'method(POST) && path("/payment") = pass'

  # Require authentication header for API requests
  - name: "require-auth"
    rule: 'host("api.example.com") && !header("X-Auth-Token") = block : pass'

  # Rate limit API requests by customer ID
  - name: "rate-limit-api"
    rule: 'host("api.*") && path("/v1/*") = rate_limit(100/s, header(X-Customer-Id))'

  # Mark requests for header modification
  - name: "add-trace-headers"
    rule: 'host("backend.*") = mangle'

  # Block everything else (catch-all - MUST be last!)
  - name: "block-all"
    rule: 'host("*") = block'

# Header modification rules
headers:
  - rules: ["add-trace-headers"]  # Apply when these rules trigger mangle action
    add:
      - name: "X-Proxy-Processed"
        value: "true"
      - name: "X-Forwarded-By"
        value: "roxy"
    remove:
      - "X-Internal-Only"
      - "X-Debug-Info"
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
| `rate_limit(N/s, key)` | Apply rate limiting |

**Ternary syntax:** `condition = action_if_true : action_if_false`

### Rate Limit Keys

Rate limit keys determine how requests are grouped:

```yaml
# Single key - limit by header value
rate_limit(100/s, header(X-Customer-Id))

# Composite key - limit by combination
rate_limit(50/s, header(X-Customer-Id) + path(*) + host(*))

# Available key sources: header(Name), path(*), host(*), client_ip(*)
```

## Architecture

```
Request → [TLS Intercept] → [Parse] → [ACL] → [RateLimit] → [Mangle] → [Forward] → Response
```

### Module Structure

| Module | Responsibility | Key Types |
|--------|----------------|-----------|
| `config/` | YAML config parsing | `ProxyConfig`, `RuleConfig` |
| `rules/` | DSL parsing (nom) + method-indexed evaluation | `Expr`, `Action`, `RuleIndex` |
| `ratelimit/` | Sliding window rate limiting | `RateLimiter`, `SlidingWindow` |
| `proxy/` | Hudsucker `HttpHandler` implementation | `RoxyHandler` |
| `error.rs` | Unified error types | `RoxyError` |

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| [hudsucker](https://crates.io/crates/hudsucker) | MITM HTTP/S proxy framework with TLS interception |
| [nom](https://crates.io/crates/nom) | Zero-copy parser combinators for the rule DSL |
| [globset](https://crates.io/crates/globset) | Pre-compiled glob pattern matching |
| [dashmap](https://crates.io/crates/dashmap) | Concurrent hashmap for rate limit storage |
| [tokio](https://crates.io/crates/tokio) | Async runtime |
| [tracing](https://crates.io/crates/tracing) | Structured logging |

### Design Decisions

1. **Method-Indexed Rules** - Rules are indexed by `Option<Method>` for O(1) lookup. Rules without a method matcher go in the `None` bucket and are always evaluated.

2. **Pre-compiled Globs** - Glob patterns are compiled to `GlobMatcher` at config load time, not per-request.

3. **Sliding Window Rate Limiting** - Uses a time-bucketed sliding window algorithm stored in `DashMap` for lock-free concurrent access.

4. **Error Layering** - Each layer defines its own error type. Lower layers report what failed; upper layers decide HTTP status codes.

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

## License

MIT
