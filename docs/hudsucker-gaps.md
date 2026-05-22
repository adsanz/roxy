# Hudsucker — Known Gaps & Workarounds

This document tracks limitations in the upstream [`hudsucker`](https://crates.io/crates/hudsucker) crate (0.24.x at time of writing) that cannot be fully fixed inside Roxy and require either a workaround or an upstream patch.

Roxy mitigates as much as possible from its side (see [memory-tuning.md](./memory-tuning.md)), but the issues below live inside Hudsucker's `proxy/internal.rs` and can only be eliminated by patching the dependency.

---

## 1. CONNECT tunnel: no read timeout on initial bytes

**Where:** `hudsucker/src/proxy/internal.rs` — the function that handles `CONNECT` requests reads bytes from the client to peek for a TLS ClientHello before deciding whether to MITM or blind-tunnel. The first `upgraded.read(&mut buffer)` call has no timeout.

**Symptom:** A malicious or broken client can send `CONNECT example.com:443` followed by zero bytes. The connection sits in `read()` forever, holding a socket + a tokio task. Many such clients = socket and task accumulation = RSS growth.

**Why Roxy can't fix it:** The read happens inside Hudsucker's `serve_connection` path, before any code Roxy controls runs. Roxy's inbound `ServerBuilder.http1().header_read_timeout(...)` does not apply to the CONNECT-upgraded socket.

**Workaround (operational):**

- Front the proxy with a connection-aware L4 load balancer / `iptables` rule that enforces an idle timeout on established TCP connections (e.g., `conntrack` timeouts, AWS NLB idle timeout).
- Monitor with the `runtime_metrics` config in Roxy to detect leaks early.

**Upstream fix sketch:** Wrap the peek read in `tokio::time::timeout(Duration::from_secs(15), ...)`; on elapse, drop the connection. Should be configurable via builder.

---

## 2. TLS handshake: no timeout

**Where:** `hudsucker/src/proxy/internal.rs` — `TlsAcceptor::accept(stream).await` after MITM decision. Standard `tokio-rustls` `accept` has no timeout.

**Symptom:** Client opens `CONNECT`, sends a partial ClientHello, then stalls. The TLS handshake future parks waiting for more bytes forever. Same accumulation pattern as #1.

**Why Roxy can't fix it:** Same reason — the `accept` call lives inside Hudsucker.

**Workaround:** Same operational mitigations as #1.

**Upstream fix sketch:** Wrap `accept` in `tokio::time::timeout(...)`.

---

## 3. Non-intercepted tunnel: unbounded `copy_bidirectional`

**Where:** When Hudsucker decides to *not* MITM a `CONNECT` (e.g., non-TLS upgrade), it calls `tokio::io::copy_bidirectional(...)` between client and upstream sockets. No idle-timeout wrapper.

**Symptom:** Long-lived tunnels (websockets, gRPC over CONNECT, custom protocols) consume a socket and task for as long as both endpoints stay TCP-alive, even if both peers have been silent for hours. If clients leak sockets without `FIN`, the tunnel is held until the OS-level TCP keepalive triggers (default ~2 hours on Linux).

**Why Roxy can't fix it:** The tunnel does not flow through Roxy's `HttpHandler` after the CONNECT decision.

**Workaround:**

- Tune kernel TCP keepalive: `sysctl -w net.ipv4.tcp_keepalive_time=300 net.ipv4.tcp_keepalive_intvl=30 net.ipv4.tcp_keepalive_probes=5`.
- Set socket-level `SO_KEEPALIVE` via systemd or wrapper if Hudsucker doesn't.

**Upstream fix sketch:** Add a configurable max-idle wrapper around `copy_bidirectional` that polls each direction's last-activity timestamp and aborts after N seconds of mutual silence.

---

## 4. No connection-count / handshake-failure metrics surface

**Where:** Hudsucker emits log events for handshake errors but does not expose any counter / gauge that Roxy can wire into its own metrics.

**Symptom:** Operators cannot directly observe "how many CONNECTs are mid-handshake right now" — only kernel-level `ss -tan` counts.

**Workaround:** Roxy exposes `runtime_metrics.interval_secs` which periodically logs tokio's `num_alive_tasks` — a strong correlated proxy for in-flight connections.

**Upstream fix sketch:** Provide a `metrics::Recorder`-style hook on `ProxyBuilder`.

---

## Summary of Roxy's defensive posture

| Gap | Roxy mitigation | Residual risk |
|-----|-----------------|---------------|
| #1 CONNECT slow-loris | Kernel TCP keepalive + `runtime_metrics` for observability | Sockets can still leak briefly until kernel detects dead peer |
| #2 TLS handshake stall | Same as #1 | Same as #1 |
| #3 Long-lived tunnel | Kernel TCP keepalive | Tunnel held until TCP keepalive triggers |
| #4 Metrics surface | `runtime_metrics` task logging tokio alive task count | Cannot distinguish task types; coarse signal only |

For HTTP/1 and HTTP/2 protocol-level timeouts (header-read, h2 PING keep-alive, max concurrent streams) Roxy is fully patched — see `server_timeouts:` and `pool:` in `config.example.yaml`.

---

## Suggested upstream issue / PR

A consolidated upstream issue could group the three timeout gaps (#1, #2, #3) under one `ProxyBuilder::with_connect_timeouts(...)` API exposing:

- `connect_initial_read_timeout: Option<Duration>`
- `tls_handshake_timeout: Option<Duration>`
- `tunnel_idle_timeout: Option<Duration>`

with sensible defaults (15s / 10s / 300s) when omitted.
