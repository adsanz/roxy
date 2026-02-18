# Memory Tuning

Roxy is designed to run in memory-constrained environments. The main memory consumers are the global allocator, certificate cache, connection pool, and rate limit/credit storage.

## Global Allocator (jemalloc)

Roxy uses [jemalloc](https://github.com/jemalloc/jemalloc) as its global allocator on Linux (non-MSVC targets). This replaces glibc's default `ptmalloc2`, which suffers from heap fragmentation under proxy workloads — RSS grows in a staircase pattern and is never returned to the OS.

jemalloc actively defragments and returns unused pages, keeping RSS proportional to actual usage.

### Aggressive Memory Return

For memory-constrained environments, you can make jemalloc more aggressive about returning memory to the OS by setting the `MALLOC_CONF` environment variable:

```bash
MALLOC_CONF="background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000" ./target/release/roxy --config config.yaml
```

| Option | Default | Recommended | Effect |
|--------|---------|-------------|--------|
| `background_thread` | `false` | `true` | Dedicated thread for page purging instead of piggybacking on allocation calls |
| `dirty_decay_ms` | `10000` | `1000` | Return dirty pages to OS after 1s instead of 10s |
| `muzzy_decay_ms` | `10000` | `1000` | Return muzzy pages to OS after 1s instead of 10s |

With default settings, memory settles to ~40-45MB after load. With the aggressive decay settings above, it drops to ~15-17MB post-load. The trade-off is slightly more CPU spent on page management during high-throughput bursts.

For Docker deployments:

```yaml
services:
  roxy:
    image: adsanz/roxy:latest
    environment:
      - MALLOC_CONF=background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/roxy/config.yaml:ro
```

## Certificate Cache

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

## Connection Pool

Roxy maintains a pool of keep-alive connections to upstream servers. The pool is bounded to prevent unbounded memory growth and mitigate DoS attacks.

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

## Rate Limit & Credit Storage

Rate limit and credit counters are stored in-memory with `DashMap`. Expired entries are cleaned up periodically to free memory — this is independent of credit resets (which happen inline on the first request after a window expires). Credit buckets are only removed after their credit window has ended **and** 48 hours of inactivity, so weekly/monthly budgets are never lost mid-window.

```yaml
rate_limit:
  cleanup_interval_secs: 60   # How often to prune expired entries (default: 60s)
```

## Zero-Allocation Hot Path

After warmup (all unique keys seen once), the per-request hot path allocates zero bytes on the heap:

- **Rule evaluation** — borrows from request and compiled rule index; uses stack-allocated arrays for logged headers and mangle matches.
- **Rate limit keys** — single-extractor keys (host, path, header) return borrowed `Cow::Borrowed`; only composite keys allocate.
- **IP baseline keys** — formatted into a 128-byte stack buffer (`StackString`).
- **Credit bucket keys** — formatted on the stack for `DashMap` lookups; only allocated on first sight of a new key.
- **DashMap lookups** — two-phase pattern: `get_mut(&str)` fast path (zero alloc), `entry(String)` slow path only for new keys.
