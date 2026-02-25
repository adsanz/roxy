
# Roxy

![](./logo.svg)

[![Docker Hub](https://img.shields.io/docker/v/adsanz/roxy?label=Docker%20Hub)](https://hub.docker.com/r/adsanz/roxy)

High-performance forward HTTP/S proxy with MITM TLS support, built on [Hudsucker](https://github.com/omjadas/hudsucker).

Roxy combines ACL filtering, header mangling, rate limiting, and TLS inspection with a custom rule DSL—designed for scenarios where you need to inspect and control HTTPS traffic (e.g., blocking requests missing required headers).

## Features

- **MITM TLS Interception** — Inspect and modify HTTPS traffic transparently
- **Rule DSL** — Expressive domain-specific language for traffic filtering ([docs](docs/rules.md))
- **Rate Limiting** — Sliding window rate limiter with soft/hard limits and progressive throttling ([docs](docs/rate-limiting.md))
- **Credit System** — Fixed-budget rate limiting with scheduled resets ([docs](docs/rate-limiting.md))
- **Header Mangling** — Add/remove headers based on rule matches
- **Header Logging** — Headers referenced in rules are automatically logged with their values (up to 8 per rule, zero-allocation, configurable via `MAX_LOGGED_HEADERS`)
- **Hot Reload** — Automatic config reload without restart, preserving rate limit and credit state
- **Method-Indexed Rules** — O(1) rule lookup by HTTP method
- **Memory-Conscious** — jemalloc allocator, configurable caches and pools ([docs](docs/memory-tuning.md))

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
./target/release/roxy --config config.yaml
# Proxy starts on the configured listen address (default: 127.0.0.1:8080)
```

### TLS Certificates

Roxy can operate in two modes:

1. **Ephemeral CA** (default) — Generates a temporary CA on startup. Useful for testing.
2. **Persistent CA** — Provide your own CA cert and key in the config.

```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=Roxy Proxy CA/O=Roxy/C=US"
```

## Configuration

Roxy uses YAML configuration files. See [config.example.yaml](config.example.yaml) for a complete example.

```yaml
listen: "0.0.0.0:8080"

pool:
  max_idle_per_host: 50
  idle_timeout_secs: 120

rules:
  - name: "allow-health"
    rule: 'path("/health") = pass'

  - name: "require-auth"
    rule: 'path("/admin/*") && !header("Authorization") = block'

  - name: "rate-limit-api"
    rule: 'path("/api/*") = rate_limit(100/s, header(X-Customer-Id))'

  - name: "allow-all"
    rule: 'host("*") = pass'
```

Rules are evaluated **first-match-wins** in config order. For the full rule DSL syntax, matchers, operators, actions, and composite rules, see the [Rule DSL docs](docs/rules.md).

For rate limiting, credit system, throttling, and reset schedules, see [Rate Limiting docs](docs/rate-limiting.md).

For memory tuning (jemalloc, cert cache, connection pool), see [Memory Tuning docs](docs/memory-tuning.md).

## Hot Reload

Roxy automatically detects config file changes and reloads rules, headers, and throttle settings without restarting the proxy. Rate limit counters and credit budgets are **preserved** across reloads.

```yaml
# Check for config changes every 5 seconds (default)
reload_interval_secs: 5

# Disable hot reload
reload_interval_secs: 0
```

**What reloads:** rules, header mangle config, throttle config, credit rule budgets.

**What is preserved:** rate limit sliding windows, credit usage counters, TLS certificates, connection pools.

**Delta-aware budget changes:**

- **Rate limits** — When you change e.g. `rate_limit(10/s)` → `rate_limit(15/s)`, existing sliding window counters are kept and the new limit applies immediately on the next request. No traffic spike from a counter reset.
- **Credits** — When you change e.g. `credit(100/d)` → `credit(200/d)`, the current usage is preserved and the extra capacity is available right away. A client that used 60 of 100 credits now has 140 remaining instead of being reset to 200.
- **Decreases** work the same way: lowering a rate limit or credit budget takes effect instantly. Clients already over the new limit will be rejected until counters naturally expire or reset.

If a new config fails to parse or contains invalid rules, the current config remains active and an error is logged.

## Architecture

```
Request → [TLS Intercept] → [Parse] → [ACL] → [RateLimit / Credit / Throttle] → [Mangle] → [Forward] → Response
```

| Module | Responsibility |
|--------|----------------|
| `config/types.rs` | YAML config parsing and validation |
| `config/reload.rs` | Periodic config file watcher, delta-aware hot reload |
| `rules/parser.rs` | DSL parsing (nom) |
| `rules/ast.rs` | Expression types and evaluation |
| `rules/engine.rs` | Method-indexed rule matching |
| `rules/key.rs` | Key extraction for rate limiting (IP, header, composite) |
| `ratelimit/limiter.rs` | Sliding window rate limiting (DashMap) |
| `ratelimit/credit.rs` | Credit-based rate limiting with scheduled resets |
| `proxy/handler.rs` | Hudsucker `HttpHandler` — request/response pipeline |
| `proxy/authority.rs` | Custom CA with full certificate chain for MITM |
| `error.rs` | Unified error types |
| `util.rs` | Stack-allocated string utilities (zero-alloc key formatting) |

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| [hudsucker](https://crates.io/crates/hudsucker) | MITM HTTP/S proxy framework |
| [nom](https://crates.io/crates/nom) | Zero-copy parser combinators for the rule DSL |
| [globset](https://crates.io/crates/globset) | Pre-compiled glob pattern matching |
| [dashmap](https://crates.io/crates/dashmap) | Concurrent hashmap for rate limit storage |
| [arc-swap](https://crates.io/crates/arc-swap) | Lock-free atomic config swap for hot reload |
| [tikv-jemallocator](https://crates.io/crates/tikv-jemallocator) | jemalloc global allocator |
| [tokio](https://crates.io/crates/tokio) | Async runtime |
| [tracing](https://crates.io/crates/tracing) | Structured logging |

## Testing

```bash
cargo test                    # Run all tests
cargo test -- --nocapture     # With output
cargo test rules::parser      # Specific module
cargo test ratelimit
```

### Test Coverage

Coverage is measured with [cargo-tarpaulin](https://github.com/xd009642/tarpaulin) (LLVM engine, library code only):

```bash
cargo tarpaulin --config tarpaulin.toml --lib   # Run coverage
```

| Module | Coverage | Scope |
|--------|----------|-------|
| `src/proxy/handler.rs` | 99% | Full request pipeline, throttling, composites |
| `src/config/types.rs` | 98% | YAML parsing and validation |
| `src/rules/ast.rs` | 98% | Expression evaluation logic |
| `src/rules/engine.rs` | 94% | Rule matching, mangle collection, warnings |
| `src/rules/key.rs` | 93% | Key extraction (IP, header, composite) |
| `src/ratelimit/limiter.rs` | 100% | Sliding window, rotation, cleanup |
| `src/ratelimit/credit.rs` | 90% | Budget, throttling, resets, cleanup |
| `src/rules/parser.rs` | 80% | DSL syntax parsing |
| **Overall** | **91%** | Library code (excludes `main.rs`) |

## Benchmarks

Two benchmark suites using [Criterion](https://crates.io/crates/criterion):

```bash
cargo bench                              # All benchmarks
cargo bench --bench rules                # Rule engine benchmarks
cargo bench --bench request              # Request pipeline benchmarks
cargo bench -- "rule_parsing"            # Specific group
cargo bench -- "rule_evaluation"
cargo bench -- "Complex"                 # By complexity
cargo bench -- "/500"                    # By rule count
```

### `rules` bench — Rule engine isolation

| Group | Description |
|-------|-------------|
| `rule_parsing` | Parse rules from config into `RuleIndex` (by complexity × count) |
| `rule_evaluation` | Single request evaluation (by complexity × count × match position) |
| `bulk_evaluation` | 1000 diverse requests against rule set |
| `mangle_evaluation` | Collecting mangle rules for header modification |
| `rate_limiter` | Single key, many keys, composite key generation |

### `request` bench — Full pipeline

| Group | Description |
|-------|-------------|
| `request_pipeline` | End-to-end evaluate → rate-limit for 5 scenarios |
| `rate_limiter_patterns` | Burst single key, rotating 100 keys, composite key formatting |
| `request_throughput` | 1000 mixed requests against 200 rules with rate limiting |

## Logging

```bash
RUST_LOG=info ./target/release/roxy --config config.yaml
RUST_LOG=debug ./target/release/roxy --config config.yaml
RUST_LOG=roxy::rules=debug,roxy::proxy=info ./target/release/roxy --config config.yaml
```

## Live Stats

A bundled bash script parses roxy's JSON log output in real time and displays a refreshing dashboard with traffic statistics.

```bash
docker logs -f <container> 2>&1 | ./scripts/live-stats.sh
```

Tracks:
- **Paths** — Top 20 paths by hit count
- **Rules** — Requests per matched rule
- **Rate limited** — Requests rejected with 429 (rate limit)
- **Credit exhausted** — Requests rejected with 429 (credit budget)
- **Errors** — Grouped by level and message type

![Live Stats](docs/live-stats.png)

> Requires `jq`. Install with `apt install jq` or `brew install jq`.

## Documentation

| Topic | Link |
|-------|------|
| Rule DSL syntax, matchers, operators, actions | [docs/rules.md](docs/rules.md) |
| Rate limiting, credits, throttling | [docs/rate-limiting.md](docs/rate-limiting.md) |
| Memory tuning, jemalloc, connection pool | [docs/memory-tuning.md](docs/memory-tuning.md) |

## License

MIT
