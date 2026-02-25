# Rate Limiting & Credit System

Roxy provides two complementary rate limiting mechanisms that can be used independently or combined.

## Sliding Window Rate Limiter

Uses a time-bucketed sliding window algorithm for smooth rate limiting. Stored in-memory with `DashMap` for lock-free concurrent access.

```yaml
rules:
  - name: "rate-limit-api"
    rule: 'path("/api/*") = rate_limit(100/s, header(X-Customer-Id))'
```

**Units:** `s` (per second), `m` (per minute), `h` (per hour)

When the limit is exceeded, the proxy returns **429 Too Many Requests** with a `Retry-After` header.

### IP Baseline Protection

When a rate limit key uses header-based extractors (e.g., `header(X-Customer-Id)`), Roxy automatically enforces an IP-based baseline rate limit to prevent bypass by varying header values. This is transparent and requires no configuration.

## Credit System

Credits are a fixed budget that resets on a schedule — unlike rate_limit's sliding window. Use credits for subscription-style quotas (e.g., 1000 API calls per day).

**DSL syntax:** `credit(N/period, key)` where period is `d` (daily), `w` (weekly), or `M` (monthly).

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

### Reset Schedule Formats

All times are UTC.

| Format | Example | Description |
|--------|---------|-------------|
| `daily@HH:MM` | `daily@00:00` | Every day at midnight |
| `weekly@Day-HH:MM` | `weekly@Mon-09:00` | Every Monday at 9 AM |
| `monthly@DD-HH:MM` | `monthly@01-00:00` | 1st of each month at midnight |

When credits are exhausted, the proxy returns **429 Too Many Requests** with a `Retry-After` header and the configured message (with `{reset_time}` interpolated to the next reset datetime).

## Soft Limits & Progressive Throttling

Both `rate_limit` and `credit` rules support a soft limit that applies progressive delay before the hard limit rejects requests outright.

The delay ramps linearly from **0 ms** at the soft limit to **max_delay_ms** at the hard limit:

```
Delay = (used - soft_limit) / (hard_limit - soft_limit) × max_delay_ms
```

### Throttle Config (for rate_limit)

```yaml
throttle:
  - rule: "api-rate-limit"     # References a rule with rate_limit() action
    soft_limit: 80              # Start delaying at 80 req/s (hard limit is 100)
    max_delay_ms: 2000          # Max 2s delay when approaching the hard limit
```

Without throttle config, rate_limit rules simply allow under the limit and reject (429) over it.

### Credit Soft Limit

```yaml
credits:
  - rule: "api-credits"
    soft_limit: 800             # Start delaying at 800/1000
    max_delay_ms: 2000
    reset_schedule: "daily@00:00"
    message: "Credit exhausted. Resets at {reset_time}."
```

### Composite Throttling

When using `rate_limit(...) + credit(...)` with both soft limits configured, the **maximum** delay from either system applies:

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

## Storage & Cleanup

Rate limit and credit counters are stored in-memory with `DashMap`.

**Credit reset vs memory cleanup** — these are separate mechanisms:
- **Reset** (budget refill): happens automatically on the first request after the credit window expires. The bucket's `used` counter goes back to 0 and a new window starts. This is the schedule configured in `reset_schedule`.
- **Memory cleanup**: periodically removes entries from the map to free memory. This only affects entries that are no longer needed — it never interferes with active credit windows.

```yaml
rate_limit:
  cleanup_interval_secs: 60   # How often to prune expired entries (default: 60s)
```

**Cleanup rules:**
- Rate limit entries unused for 2 windows are removed.
- Credit buckets are removed only after their credit window has ended **and** 48 hours of inactivity. A weekly bucket is never removed mid-window, even if the user is silent for days.
- If a cleaned-up user makes a new request, a fresh bucket is created with `used: 0` — the same state as a reset.
- Both maps call `shrink_to_fit()` after cleanup to release hash table capacity.

## Response Headers

Roxy injects standard rate limit headers into forwarded responses so clients can track their quota usage. Rate limit and credit headers are separate to avoid collisions when both systems apply to the same request.

### Rate Limit Headers (`X-RateLimit-*`)

Injected when a `rate_limit()` rule matches:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in the window |
| `X-RateLimit-Remaining` | Remaining requests in the current window |
| `X-RateLimit-Reset` | Seconds until the window resets |

### Credit Headers (`X-Credit-*`)

Injected when a `credit()` rule matches:

| Header | Description |
|--------|-------------|
| `X-Credit-Limit` | Total credit budget for the period |
| `X-Credit-Remaining` | Remaining credits in the current period |
| `X-Credit-Reset` | Seconds until credits reset |

### Composite Rules

When using `rate_limit(...) + credit(...)`, **both** header sets are injected into the response. Clients can distinguish between burst rate limiting and budget quota by checking the appropriate header prefix.

### Rejection Responses (429)

When a request is rejected (hard limit exceeded), the relevant headers are included in the 429 response body along with a `Retry-After` header. For composite rules where credit is exhausted, both `X-RateLimit-*` and `X-Credit-*` headers are included.
