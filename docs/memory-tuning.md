# Memory Tuning

Roxy is designed to run in memory-constrained environments. The main memory consumers are the global allocator, certificate cache, connection pool, and rate limit/credit storage.

## Global Allocator (jemalloc)

Roxy uses [jemalloc](https://github.com/jemalloc/jemalloc) as its global allocator on Linux (non-MSVC targets). This replaces glibc's default `ptmalloc2`, which suffers from heap fragmentation under proxy workloads — RSS grows in a staircase pattern and is never returned to the OS.

jemalloc actively defragments and returns unused pages, keeping RSS proportional to actual usage.

### Aggressive Memory Return

For memory-constrained environments, you can make jemalloc more aggressive about returning memory to the OS by setting the `_RJEM_MALLOC_CONF` environment variable:

```bash
_RJEM_MALLOC_CONF="background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000" ./target/release/roxy --config config.yaml
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
      - _RJEM_MALLOC_CONF=background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000
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
  max_idle_per_host: 10                # Maximum idle connections per upstream host (default: 10)
  idle_timeout_secs: 30                # Seconds before idle connections are closed (default: 30)
  # HTTP/2 client keep-alive (PING dead pooled h2 connections)
  http2_keep_alive_interval_secs: 20   # 0 = disabled (default: 20)
  http2_keep_alive_timeout_secs: 10    # default: 10
  http2_keep_alive_while_idle: true    # default: true
```

### HTTP/2 Pool Keep-Alive

Without HTTP/2 keep-alive PINGs, a pooled h2 connection to a silently-dead upstream (e.g., upstream OOM-killed, NAT timeout, mid-network blackhole) accumulates until `idle_timeout_secs` fires — and that timer only triggers when the connection is *truly idle*, which a stuck h2 socket with leaked streams is not. The result is a slow but persistent leak of pool slots + tokio tasks.

Enabling client-side h2 keep-alive (defaults above) makes hyper send PING frames; if no ACK arrives within `http2_keep_alive_timeout_secs`, the connection is evicted from the pool immediately.

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

## Inbound Server Timeouts

Roxy configures the inbound `hyper-util` server with explicit timeouts. Without these (the upstream Hudsucker default), inbound sockets from misbehaving or dead clients accumulate indefinitely, leading to a slow but steady RSS / file-descriptor leak.

```yaml
server_timeouts:
  http1_header_read_timeout_secs: 15    # default: 15, 0 = disabled
  http2_keep_alive_interval_secs: 20    # default: 20, 0 = disabled
  http2_keep_alive_timeout_secs: 10     # default: 10
  http2_max_concurrent_streams: 256     # default: 256, 0 = unbounded
```

**Not hot-reloadable.** These values are baked into the listener at startup; changes require restarting the proxy.

| Knob | Purpose |
|------|---------|
| `http1_header_read_timeout_secs` | Kills slow-loris clients that open a socket but never finish sending headers. |
| `http2_keep_alive_interval_secs` | Server-side PING interval. Detects dead clients whose TCP socket is gone but never closed. |
| `http2_keep_alive_timeout_secs` | If no PING ACK in this window, send GOAWAY and close. |
| `http2_max_concurrent_streams` | Bounds per-connection multiplexing fan-out — protects against an attacker opening one h2 socket and allocating thousands of streams. |

### Known Gaps (Hudsucker)

The `CONNECT` initial-read, TLS handshake, and non-intercept tunnel paths cannot be timed out from Roxy's side — see [hudsucker-gaps.md](./hudsucker-gaps.md) for details and operational mitigations (kernel TCP keepalive tuning is recommended).

## Runtime Metrics

Roxy exposes an opt-in runtime metrics task that periodically logs tokio's live task count alongside worker count. This is the simplest way to verify connection-leak fixes are taking effect.

```yaml
runtime_metrics:
  interval_secs: 30   # 0 or omitted = disabled
```

Log output (under `target: "runtime"`):

```json
{"target":"runtime","num_alive_tasks":42,"num_workers":4,"message":"runtime metrics"}
```

Correlate `num_alive_tasks` with `ss -tan | grep ESTAB | wc -l` to confirm sockets and tasks are released together. A widening gap = leak.

**Not hot-reloadable.** The metrics task is spawned at startup.

### Why `num_alive_tasks` doesn't drop back to baseline (HTTPS upstreams)

If you watch `num_alive_tasks` while proxying to HTTPS sites (Google, Cloudflare, GitHub, etc.), you'll see it climb when traffic hits and then **stay elevated** — even after the requests are done and `pool_idle_timeout_secs` has elapsed. **This is normal, not a leak.**

#### What's happening, in plain terms

Roxy keeps a small pool of "warm" connections to each upstream so the next request to the same site is fast (no TCP/TLS handshake). For modern HTTP/2 sites, each warm connection is kept alive by a couple of background tasks. Those tasks stick around as long as the connection is in the pool.

So the rule of thumb is:

> **More distinct upstream hosts you've talked to recently → more warm connections → more background tasks.**

The count is **bounded**: it can never exceed `max_idle_per_host × number_of_distinct_hosts`. It won't grow forever.

#### How to choose your settings

Pick the row that matches your workload:

| Your workload | Recommended `max_idle_per_host` | Why |
|---|---|---|
| Many requests to the **same few** upstreams (e.g. an API gateway) | `32` (default) | Reuse warm connections → faster responses |
| Mixed traffic, want a middle ground | `2` – `4` | Some reuse, smaller task footprint |
| Want the **lowest** memory / task count and don't care about handshake overhead | `0` | Disables the pool entirely; tasks return to baseline immediately |

Example for a low-footprint setup:

```yaml
pool:
  max_idle_per_host: 2
  idle_timeout_secs: 5
```

#### Tips (technical detail)

- Each pooled HTTP/2 connection costs roughly **2 tokio tasks** (the h2 driver + the frame pump). Formula: `num_alive_tasks ≈ baseline + 2 × distinct_h2_hosts_in_pool`.
- `pool_idle_timeout_secs` is honored for HTTP/1.1 idle connections but **does not promptly reap idle HTTP/2 connections** in `hyper-util` 0.1. Only evicting the pool entry (e.g. `max_idle_per_host: 0`, or pressure from new hosts) drops the tasks.
- Setting `http2_keep_alive_while_idle: false` does **not** make h2 pool entries expire faster. Leave it `true` so dead connections are detected before the next request fails.
- The `timer:(keepalive,...)` you see in `ss -tonp` is the **kernel's** TCP SO_KEEPALIVE, which is independent from hyper's HTTP/2 PING keep-alive. Both can be active on the same socket.
- Measured with 3 distinct HTTPS hosts, `pool_idle_timeout_secs=5`, 30 s idle:

  | Pool config | Tasks after burst | After 30 s idle | Outbound ESTAB |
  |---|---|---|---|
  | `max_idle_per_host=32`, `while_idle=true` | 4 → 10 | stays 10 | 2 |
  | `max_idle_per_host=32`, `while_idle=false`, `interval=0` | 4 → 10 | stays 10 | 3 |
  | `max_idle_per_host=0` (pool off) | stays 4 | stays 4 | 0 |

