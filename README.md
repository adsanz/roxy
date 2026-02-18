
# Roxy

![](./logo.png)

[![Docker Hub](https://img.shields.io/docker/v/adsanz/roxy?label=Docker%20Hub)](https://hub.docker.com/r/adsanz/roxy)

High-performance forward HTTP/S proxy with MITM TLS support, built on [Hudsucker](https://github.com/omjadas/hudsucker).

Roxy combines ACL filtering, header mangling, rate limiting, and TLS inspection with a custom rule DSL—designed for scenarios where you need to inspect and control HTTPS traffic (e.g., blocking requests missing required headers).

## Features

- **MITM TLS Interception** — Inspect and modify HTTPS traffic transparently
- **Rule DSL** — Expressive domain-specific language for traffic filtering ([docs](docs/rules.md))
- **Rate Limiting** — Sliding window rate limiter with soft/hard limits and progressive throttling ([docs](docs/rate-limiting.md))
- **Credit System** — Fixed-budget rate limiting with scheduled resets ([docs](docs/rate-limiting.md))
- **Header Mangling** — Add/remove headers based on rule matches
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

## Architecture

```
Request → [TLS Intercept] → [Parse] → [ACL] → [RateLimit] → [Mangle] → [Forward] → Response
```

| Module | Responsibility |
|--------|----------------|
| `config/` | YAML config parsing |
| `rules/` | DSL parsing (nom) + method-indexed evaluation |
| `ratelimit/` | Sliding window + credit-based rate limiting |
| `proxy/` | Hudsucker `HttpHandler` implementation |
| `error.rs` | Unified error types |

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| [hudsucker](https://crates.io/crates/hudsucker) | MITM HTTP/S proxy framework |
| [nom](https://crates.io/crates/nom) | Zero-copy parser combinators for the rule DSL |
| [globset](https://crates.io/crates/globset) | Pre-compiled glob pattern matching |
| [dashmap](https://crates.io/crates/dashmap) | Concurrent hashmap for rate limit storage |
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

| Module | Scope |
|--------|-------|
| `src/rules/parser.rs` | DSL syntax parsing |
| `src/rules/ast.rs` | Expression evaluation logic |
| `src/rules/engine.rs` | Rule matching with mock requests |
| `src/ratelimit/limiter.rs` | Sliding window edge cases |
| `src/ratelimit/credit.rs` | Budget, throttling, resets, cleanup |
| `src/config/types.rs` | YAML parsing and validation |
| `src/proxy/handler.rs` | Request processing |

## Benchmarks

```bash
cargo bench                        # All benchmarks
cargo bench -- "rule_parsing"      # Specific group
cargo bench -- "rule_evaluation"
cargo bench -- "rate_limiter"
cargo bench -- "Complex"           # By complexity
cargo bench -- "/500"              # By rule count
```

| Group | Description |
|-------|-------------|
| `rule_parsing` | Parse rules from config into `RuleIndex` |
| `rule_evaluation` | Single request evaluation against rule set |
| `bulk_evaluation` | 1000 diverse requests against rule set |
| `mangle_evaluation` | Collecting mangle rules for header modification |
| `rate_limiter` | Rate limiter check throughput |

## Logging

```bash
RUST_LOG=info ./target/release/roxy --config config.yaml
RUST_LOG=debug ./target/release/roxy --config config.yaml
RUST_LOG=roxy::rules=debug,roxy::proxy=info ./target/release/roxy --config config.yaml
```

## Documentation

| Topic | Link |
|-------|------|
| Rule DSL syntax, matchers, operators, actions | [docs/rules.md](docs/rules.md) |
| Rate limiting, credits, throttling | [docs/rate-limiting.md](docs/rate-limiting.md) |
| Memory tuning, jemalloc, connection pool | [docs/memory-tuning.md](docs/memory-tuning.md) |

## License

MIT
