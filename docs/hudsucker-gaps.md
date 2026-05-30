# Hudsucker — Known Gaps & Workarounds

This document tracks limitations in the upstream [`hudsucker`](https://crates.io/crates/hudsucker) crate (0.24.0 at time of writing) and the Roxy-side mitigations for them.

Roxy now vendors the small hudsucker proxy control path in `src/proxy/bounded.rs`, similar in spirit to the `RoxyAuthority` port. That lets Roxy enforce deadlines that hudsucker does not expose publicly, while still using hudsucker's public `HttpHandler`, `Body`, and certificate authority traits.

---

## 1. CONNECT tunnel: no read timeout on initial bytes

**Where:** `hudsucker/src/proxy/internal.rs` — the function that handles `CONNECT` requests reads bytes from the client to peek for a TLS ClientHello before deciding whether to MITM or blind-tunnel. The first `upgraded.read(&mut buffer)` call has no timeout.

**Symptom:** A malicious or broken client can send `CONNECT example.com:443` followed by zero bytes. The connection sits in `read()` forever, holding a socket + a tokio task. Many such clients = socket and task accumulation = RSS growth.

**Roxy mitigation:** `server_timeouts.connect_initial_read_timeout_secs` wraps the vendored `upgraded.read(...)`. Default: 15s.

**Upstream fix sketch:** Wrap the peek read in `tokio::time::timeout(Duration::from_secs(15), ...)`; on elapse, drop the connection. Should be configurable via builder.

---

## 2. TLS handshake: no timeout

**Where:** `hudsucker/src/proxy/internal.rs` — `TlsAcceptor::accept(stream).await` after MITM decision. Standard `tokio-rustls` `accept` has no timeout.

**Symptom:** Client opens `CONNECT`, sends a partial ClientHello, then stalls. The TLS handshake future parks waiting for more bytes forever. Same accumulation pattern as #1.

**Roxy mitigation:** `server_timeouts.tls_handshake_timeout_secs` wraps the vendored `TlsAcceptor::accept(...)`. Default: 15s.

**Upstream fix sketch:** Wrap `accept` in `tokio::time::timeout(...)`.

---

## 3. Non-intercepted tunnel: unbounded `copy_bidirectional`

**Where:** When Hudsucker decides to *not* MITM a `CONNECT` (e.g., non-TLS upgrade), it calls `tokio::io::copy_bidirectional(...)` between client and upstream sockets. No idle-timeout wrapper.

**Symptom:** Long-lived tunnels (websockets, gRPC over CONNECT, custom protocols) consume a socket and task for as long as both endpoints stay TCP-alive, even if both peers have been silent for hours. If clients leak sockets without `FIN`, the tunnel is held until the OS-level TCP keepalive triggers (default ~2 hours on Linux).

**Roxy mitigation:** `server_timeouts.max_connection_age_secs` bounds the entire vendored CONNECT task, including raw `copy_bidirectional(...)`. This is a max-age cap, not a byte-level idle timer. Default: 1800s plus 30s grace.

**Upstream fix sketch:** Add a configurable max-idle wrapper around `copy_bidirectional` that polls each direction's last-activity timestamp and aborts after N seconds of mutual silence.

---

## 4. No connection-count / handshake-failure metrics surface

**Where:** Hudsucker emits log events for handshake errors but does not expose any counter / gauge that Roxy can wire into its own metrics.

**Symptom:** Operators cannot directly observe "how many CONNECTs are mid-handshake right now" — only kernel-level `ss -tan` counts.

**Workaround:** Roxy exposes `runtime_metrics.interval_secs` which periodically logs tokio's `num_alive_tasks` — a strong correlated proxy for in-flight connections.

**Upstream fix sketch:** Provide a `metrics::Recorder`-style hook on `ProxyBuilder`.

---

## 5. Inbound HTTP/2 keep-alive echo chamber (no `max_connection_age` in hyper server)

**Where:** Not hudsucker per se — this is a `hyper::server::conn::http2::Builder` limitation that hudsucker inherits. Hyper's HTTP/2 server exposes `keep_alive_interval`, `keep_alive_timeout`, `max_concurrent_streams`, and various window-size knobs, but **no `max_connection_age`, `max_idle_time`, or `max_requests_per_connection`** equivalent to what e.g. Envoy or Nginx provide.

**Symptom:** When `server_timeouts.http2_keep_alive_interval_secs > 0`, roxy sends an h2 PING frame to every connected client every N seconds. A healthy-but-idle client (browsers, well-behaved API consumers) instantly ACKs the PING. Combined with kernel-level `SO_KEEPALIVE` (also ACKed by the peer kernel), the connection is "alive" by every metric available to the proxy — but the application above never closes it because hyper has no built-in idle/age cap. Result: in long-running deployments with many distinct clients, idle h2 connections accumulate indefinitely. Observed in production: ~1500 ESTABLISHED sockets after 2 days, with `ss -ton` showing `data_segs_in:4, lastsnd: 2.78 days, app_limited` — i.e. handshake + a few bytes, then nothing but PING/ACK traffic for days.

**Why this looks worse than #1–#3:** unlike CONNECT/TLS stalls, these connections are *correctly* established and *correctly* idle by the protocol's design. There is no slow-loris attacker; there is no broken peer. The proxy itself is keeping them alive.

**Why Roxy can't fully fix it:** Bounding h2 connection age cleanly requires either:

1. A hyper-side `max_connection_age` knob (doesn't exist), or
2. Intercepting accepted `TcpStream`s before they're handed to hyper and wrapping each in a per-connection deadline. Hudsucker's `Proxy::start()` owns the accept loop and its `InternalProxy` service is `pub(crate)`, so Roxy vendors the 0.24.0 control path in `src/proxy/bounded.rs`.

**Mitigations applied in roxy:**

- `server_timeouts.http2_keep_alive_interval_secs` remains enabled by default (**20s**) to detect truly dead h2 peers.
- `server_timeouts.max_connection_age_secs` defaults to **1800s**. On expiry, Roxy asks hyper to gracefully drain the outer accepted connection and the inner MITM `serve_stream(...)`; after `max_connection_age_grace_secs` (default 30s), the task is force-dropped.
- `tcp_keepalive.{time_secs, interval_secs, retries}` defaults relaxed to **`60s / 30s / 4`** (was hardcoded `15s / 15s / default-9`). The kernel still detects truly dead peers within ~3 min but doesn't generate constant control-plane chatter that masks idleness.
- `ProxyConfig::validate()` emits a `WARN` only when inbound h2 PING is enabled **and** `max_connection_age_secs = 0`, because that combination can recreate the echo chamber.
- `ProxyConfig::validate()` rejects nonsensical timeout combinations (`keep_alive_timeout >= keep_alive_interval`, max-age grace >= max-age, `tcp_keepalive.{time,interval}_secs == 0` when enabled).

**Residual risk:** `max_connection_age_secs` is an age cap, not request-aware policy. Very long streaming responses, WebSockets, or CONNECT tunnels can be asked to drain when they hit the cap and force-closed after the grace window. Increase the age or disable it (`0`) for deployments that intentionally require multi-hour single connections; keep external L4 limits if doing so.

**Upstream fix sketch (hyper):**

```rust
hyper::server::conn::http2::Builder::new()
    .max_connection_age(Duration::from_secs(3600))  // proposed
    .max_connection_age_grace(Duration::from_secs(30));
```

**Upstream fix sketch (hudsucker):** expose a `Proxy::on_accept(impl Fn(TcpStream) -> impl Future)` hook or accept an `impl Stream<Item = TcpStream>` listener so callers can wrap each connection with their own deadline future.

---

## Summary of Roxy's defensive posture

| Gap | Roxy mitigation | Residual risk |
|-----|-----------------|---------------|
| #1 CONNECT slow-loris | Vendored `connect_initial_read_timeout_secs` | None when enabled |
| #2 TLS handshake stall | Vendored `tls_handshake_timeout_secs` | None when enabled |
| #3 Long-lived tunnel | Vendored `max_connection_age_secs` + TCP keepalive | Age cap, not byte-level idle timeout |
| #4 Metrics surface | `runtime_metrics` task logging tokio alive task count | Cannot distinguish task types; coarse signal only |
| #5 Inbound h2 echo chamber | Vendored `max_connection_age_secs` + h2 PING retained for dead-peer detection | Very long streams may need a larger cap |

For HTTP/1 and HTTP/2 protocol-level timeouts (header-read, h2 PING keep-alive, max concurrent streams, max connection age) Roxy is fully patched — see `server_timeouts:` and `pool:` in `config.example.yaml`.

---

## Suggested upstream issue / PR

A consolidated upstream issue could group the three timeout gaps (#1, #2, #3) under one `ProxyBuilder::with_connect_timeouts(...)` API exposing:

- `connect_initial_read_timeout: Option<Duration>`
- `tls_handshake_timeout: Option<Duration>`
- `tunnel_idle_timeout: Option<Duration>`

with sensible defaults (15s / 10s / 300s) when omitted.
