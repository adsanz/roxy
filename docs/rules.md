# Rule DSL

Roxy uses a custom domain-specific language for traffic filtering. Rules are defined in the `rules:` section of the YAML config and evaluated in order (first-match-wins).

## Rule Evaluation Order

**Rules are evaluated in the exact order they appear in the config file.**

The proxy stops evaluating rules as soon as one matches and returns an action. To implement allow-list patterns:

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

> **Common mistake**: Putting the catch-all block first would block everything!

## Matchers

| Matcher | Description | Example |
|---------|-------------|---------|
| `host("pattern")` | Match request host | `host("*.example.com")` |
| `path("pattern")` | Match request path | `path("/api/v1/*")` |
| `method(M)` | Match HTTP method | `method(GET)`, `method(POST)` |
| `header("name")` | Check header exists | `header("Authorization")` |
| `header("name:value")` | Match header value | `header("X-Version:v2")` |

## Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `&&` | Logical AND | `host("*") && method(GET)` |
| `\|\|` | Logical OR | `path("/a") \|\| path("/b")` |
| `!` | Logical NOT | `!header("X-Auth")` |
| `()` | Grouping | `(host("a") \|\| host("b")) && method(POST)` |

## Actions

| Action | Description |
|--------|-------------|
| `pass` | Allow request, stop rule evaluation |
| `block` | Deny request with 403 Forbidden |
| `mangle` | Allow request, trigger header modifications |
| `rate_limit(N/unit, key)` | Sliding window rate limiting (units: `s`, `m`, `h`) |
| `credit(N/period, key)` | Credit-based rate limiting (periods: `d`, `w`, `M`) |
| `rate_limit(...) + credit(...)` | Composite: burst protection + budget enforcement |
| `rate_limit(...) + mangle` | Rate limit + header mangling |
| `credit(...) + mangle` | Credit check + header mangling |
| `rate_limit(...) + credit(...) + mangle` | Full composite: burst + budget + header mangling |

### Ternary Syntax

Use `condition = action_if_true : action_if_false` for conditional logic:

```yaml
- name: "require-auth"
  rule: 'host("api.example.com") && !header("X-Auth") = block : pass'
```

## Rate Limit Keys

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

## Composite Actions

Since rules use first-match-wins, you can't have separate `rate_limit` and `credit` rules on the same host/path. Use the `+` operator to combine them into a single rule.

The composable actions are `rate_limit`, `credit`, and `mangle`. The `+` operator supports 2 or 3 terms in any order:

```yaml
rules:
  # Rate limit + credit (burst + budget)
  - name: "api-protected"
    rule: 'host("api.*") && path("/v3/*") = rate_limit(50/s, header(X-Customer-Id)) + credit(5000/d, header(X-Customer-Id))'

  # Rate limit + mangle (rate limit + header modification)
  - name: "api-mangled"
    rule: 'host("api.*") = rate_limit(100/s, ip) + mangle'

  # Credit + mangle (budget + header modification)
  - name: "budget-mangled"
    rule: 'host("api.*") = credit(1000/d, header(X-Id)) + mangle'

  # All three: rate limit + credit + mangle
  - name: "full-composite"
    rule: 'host("api.*") = rate_limit(50/s, ip) + credit(5000/d, header(X-Id)) + mangle'
```

**Semantics:**
1. Rate limit is checked first (burst/spam protection)
2. If rate limit passes, credit is checked (budget enforcement)
3. Both must pass for the request to proceed
4. If both have soft limits configured, the **maximum** delay from either system applies
5. If `mangle` is included, header modifications are applied on success (not on 429 rejections)

The order of terms doesn't matter — rate limit is always evaluated before credit, and mangle is applied last.

`block`, `pass`, and `mangle` (standalone) cannot be combined with other actions via `+`.

## Header Mangling

Headers are added/removed when a mangle rule matches. Configure in the `headers:` section:

```yaml
headers:
  - rules: ["rate-limit-api", "combo-rl-credit"]
    add:
      - name: "X-Proxy-Processed"
        value: "true"
    remove:
      - "X-Customer-Id"
```

## Header Logging

When a rule matches, Roxy automatically logs the actual values of **all headers referenced in the rule expression** — both existence checks and value-match checks.

- `header("X-Customer-Id")` — existence check → **value is logged**
- `header("X-Name:value")` — value match → **value is logged**
- Multiple headers in a rule → all referenced headers are logged (up to 8 per rule; extras are silently omitted)

```json
{"method":"GET","host":"api.example.com","path":"/api/users","rule":"track-customer","action":"forward","headers":{"X-Customer-Id":"cust-12345","X-Version":"v2"}}
```
