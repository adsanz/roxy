#!/usr/bin/env bash
#
# Roxy Load Test Script
# Tests all rule types: pass, block, rate_limit, credit, rate_limit+credit.
#
# Phases:
#   1. VERIFY  — Sequential checks that each rule type works correctly.
#                Exits immediately if any verification fails.
#   2. LOAD    — Concurrent traffic using a built-in local echo server
#                so results aren't skewed by upstream instability.
#
# The script starts its own HTTP echo server on TARGET_PORT so it doesn't
# depend on external services (httpbin.org would return 5xx under load).
#
# Includes hang-detection: any request >HANG_TIMEOUT aborts the test.
#
# Prerequisites:
#   - curl, python3
#   - Roxy running with loadtest/config.yaml
#
# Usage:
#   ./loadtest/run.sh [duration_seconds] [concurrency]
#

set -euo pipefail

# Configuration
PROXY_HOST="${PROXY_HOST:-127.0.0.1:8080}"
TARGET_PORT="${TARGET_PORT:-19876}"       # Local echo server port
TARGET_HOST="127.0.0.1:${TARGET_PORT}"
DURATION="${1:-60}"
CONCURRENCY="${2:-20}"
HANG_TIMEOUT=15

# Stats / temp
STATS_DIR=$(mktemp -d)
HANG_FLAG="$STATS_DIR/_hang_detected"
ECHO_PID=""

cleanup() {
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null || true
    rm -rf "$STATS_DIR"
}
trap cleanup EXIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; }

# ──────────────────────────────────────────────────
# Local echo server (Python one-liner)
# Returns 200 with a tiny body for every request.
# ──────────────────────────────────────────────────
start_echo_server() {
    log "Starting local echo server on :${TARGET_PORT}..."
    python3 -c "
import http.server, socketserver, threading

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.end_headers()
        self.wfile.write(b'ok')
    do_POST = do_GET
    do_PUT  = do_GET
    do_HEAD = do_GET
    def log_message(self, *a): pass   # silence logs

socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(('0.0.0.0', ${TARGET_PORT}), H) as s:
    s.serve_forever()
" &
    ECHO_PID=$!
    sleep 0.5

    if ! kill -0 "$ECHO_PID" 2>/dev/null; then
        error "Failed to start echo server on :${TARGET_PORT}"
        exit 1
    fi
    success "Echo server running (PID $ECHO_PID)"
}

# Helper: single curl through proxy, returns "http_code"
proxy_curl() {
    local url="$1"; shift
    curl --proxy "http://$PROXY_HOST" -s -o /dev/null \
         -w "%{http_code}" --max-time 10 "$@" "$url" 2>/dev/null || echo "000"
}

# ──────────────────────────────────────────────────
# Phase 1: VERIFY each rule type
# ──────────────────────────────────────────────────

# Fire N parallel requests, collect status codes into a temp file.
# Usage: burst_curl <count> <url> [extra curl args...]
burst_curl() {
    local count=$1; shift
    local url="$1"; shift
    local burst_dir
    burst_dir=$(mktemp -d "$STATS_DIR/burst.XXXXXX")

    for i in $(seq 1 "$count"); do
        (
            code=$(curl --proxy "http://$PROXY_HOST" -s -o /dev/null \
                        -w "%{http_code}" --max-time 10 "$@" "$url" 2>/dev/null || echo "000")
            echo "$code" > "$burst_dir/$i"
        ) &
    done
    wait

    # Print all collected codes to stdout (one per line)
    cat "$burst_dir"/* 2>/dev/null
    rm -rf "$burst_dir"
}

verify_rules() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  PHASE 1 — RULE VERIFICATION"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""

    local failures=0

    # --- pass (health) ---
    local code
    code=$(proxy_curl "http://${TARGET_HOST}/health")
    if [[ "$code" == "200" ]]; then
        success "pass  rule  → 200 (path /health)"
    else
        error   "pass  rule  → $code (expected 200, path /health)"
        ((failures++))
    fi

    # --- block ---
    code=$(proxy_curl "http://${TARGET_HOST}/internal/secret")
    if [[ "$code" == "403" ]]; then
        success "block rule  → 403 (path /internal/*)"
    else
        error   "block rule  → $code (expected 403, path /internal/*)"
        ((failures++))
    fi

    # --- ternary (no auth → block) ---
    code=$(proxy_curl "http://${TARGET_HOST}/admin/dashboard")
    if [[ "$code" == "403" ]]; then
        success "ternary     → 403 (admin, no auth)"
    else
        error   "ternary     → $code (expected 403, admin no auth)"
        ((failures++))
    fi

    # --- ternary (with auth → pass) ---
    code=$(proxy_curl "http://${TARGET_HOST}/admin/dashboard" -H "Authorization: Bearer tok")
    if [[ "$code" == "200" ]]; then
        success "ternary     → 200 (admin, with auth)"
    else
        error   "ternary     → $code (expected 200, admin with auth)"
        ((failures++))
    fi

    # --- rate_limit: fire 20 parallel requests (limit=5/s), expect some 429 ---
    # Requests are parallel so throttle delays don't prevent exceeding the limit.
    log "Verifying rate_limit (5/s, customer=verify-rl) — 20 parallel requests..."
    local got_429=0
    local total_burst=20
    local codes
    codes=$(burst_curl "$total_burst" "http://${TARGET_HOST}/api/test" -H "X-Customer-Id: verify-rl")
    got_429=$(echo "$codes" | grep -c "^429$" || true)
    if [[ $got_429 -gt 0 ]]; then
        success "rate_limit  → got $got_429 x 429 out of $total_burst requests"
    else
        error   "rate_limit  → 0 x 429 out of $total_burst requests (expected some)"
        ((failures++))
    fi

    # --- credit: fire 20 parallel requests (budget=10/d), expect some 429 ---
    log "Verifying credit (10/d, customer=verify-cr) — 20 parallel requests..."
    got_429=0
    total_burst=20
    codes=$(burst_curl "$total_burst" "http://${TARGET_HOST}/credits/check" -H "X-Customer-Id: verify-cr")
    got_429=$(echo "$codes" | grep -c "^429$" || true)
    if [[ $got_429 -gt 0 ]]; then
        success "credit      → got $got_429 x 429 out of $total_burst requests"
    else
        error   "credit      → 0 x 429 out of $total_burst requests (expected some)"
        ((failures++))
    fi

    # --- combo (rate_limit + credit): fire 15 parallel (limit=3/s + 15/d) ---
    log "Verifying combo rl+credit (3/s + 15/d, customer=verify-co) — 15 parallel requests..."
    got_429=0
    total_burst=15
    codes=$(burst_curl "$total_burst" "http://${TARGET_HOST}/combo/action" -H "X-Customer-Id: verify-co")
    got_429=$(echo "$codes" | grep -c "^429$" || true)
    if [[ $got_429 -gt 0 ]]; then
        success "combo rl+cr → got $got_429 x 429 out of $total_burst requests"
    else
        error   "combo rl+cr → 0 x 429 out of $total_burst requests (expected some)"
        ((failures++))
    fi

    echo ""
    if [[ $failures -gt 0 ]]; then
        error "$failures verification(s) failed — aborting load test."
        error "Make sure the proxy is running with:  cargo run --release -- -c loadtest/config.yaml"
        exit 1
    fi
    success "All rule verifications passed"
}

# ──────────────────────────────────────────────────
# Phase 2: LOAD TEST (concurrent)
# ──────────────────────────────────────────────────

# Worker function — runs in background
worker() {
    local worker_id=$1
    local end_time=$2
    local stats_file="$STATS_DIR/worker_$worker_id"

    # Targets (redefined inside subshell)
    # Format: URL|METHOD|LABEL|EXTRA_HEADERS
    local targets=(
        # pass
        "http://${TARGET_HOST}/health|GET|health|"
        "http://${TARGET_HOST}/anything|GET|catch-all|"

        # block
        "http://${TARGET_HOST}/internal/secret|GET|block-internal|"
        "http://${TARGET_HOST}/admin/users|GET|block-admin|"

        # ternary pass
        "http://${TARGET_HOST}/admin/ok|GET|admin-auth|Authorization:Bearer tok"

        # rate_limit (5/s per customer)
        "http://${TARGET_HOST}/api/widgets|GET|rl-cust-a|X-Customer-Id:load-A"
        "http://${TARGET_HOST}/api/widgets|GET|rl-cust-b|X-Customer-Id:load-B"
        "http://${TARGET_HOST}/api/data|GET|rl-cust-c|X-Customer-Id:load-C"

        # credit-only (10/day per customer)
        "http://${TARGET_HOST}/credits/balance|GET|cr-cust-a|X-Customer-Id:load-A"
        "http://${TARGET_HOST}/credits/balance|GET|cr-cust-b|X-Customer-Id:load-B"

        # combo rate_limit + credit (3/s + 15/day)
        "http://${TARGET_HOST}/combo/action|GET|combo-a|X-Customer-Id:load-A"
        "http://${TARGET_HOST}/combo/action|GET|combo-b|X-Customer-Id:load-B"
        "http://${TARGET_HOST}/combo/action|POST|combo-post|X-Customer-Id:load-A"

        # composite rate limit key (10/s)
        "http://${TARGET_HOST}/v2/resources|GET|rl-comp|X-Customer-Id:load-A"
    )
    local num_targets=${#targets[@]}

    local requests=0
    local ok_2xx=0
    local ok_3xx=0
    local blocked_403=0
    local limited_429=0
    local other_fail=0
    local total_time=0

    while [[ $(date +%s) -lt $end_time ]]; do
        [[ -f "$HANG_FLAG" ]] && break

        local target="${targets[$((RANDOM % num_targets))]}"
        IFS='|' read -r url method name extra_headers <<< "$target"

        local curl_args=(
            --proxy "http://$PROXY_HOST"
            -s -o /dev/null
            -w "%{http_code},%{time_total}"
            --max-time "$HANG_TIMEOUT"
            -X "$method"
        )

        if [[ -n "$extra_headers" ]]; then
            # Split only on the FIRST colon (handles "Authorization:Bearer tok")
            local hname="${extra_headers%%:*}"
            local hvalue="${extra_headers#*:}"
            curl_args+=(-H "$hname: $hvalue")
        fi
        curl_args+=("$url")

        local result
        result=$(curl "${curl_args[@]}" 2>/dev/null) || result="000,0"

        IFS=',' read -r status_code time_taken <<< "$result"

        ((requests++)) || true

        if [[ "$status_code" == "000" ]]; then
            echo "worker=$worker_id target=$name url=$url" > "$HANG_FLAG"
            break
        fi

        case "$status_code" in
            2??) ((ok_2xx++))      || true ;;
            3??) ((ok_3xx++))      || true ;;
            403) ((blocked_403++)) || true ;;
            429) ((limited_429++)) || true ;;
            *)   ((other_fail++))  || true ;;
        esac

        total_time=$(awk "BEGIN {printf \"%.0f\", $total_time + $time_taken * 1000}" 2>/dev/null || echo "$total_time")
    done

    echo "$requests,$ok_2xx,$ok_3xx,$blocked_403,$limited_429,$other_fail,$total_time" > "$stats_file"
}

# Aggregate and display stats
show_stats() {
    local total_requests=0
    local total_2xx=0
    local total_3xx=0
    local total_403=0
    local total_429=0
    local total_other=0
    local total_time=0

    for stats_file in "$STATS_DIR"/worker_*; do
        if [[ -f "$stats_file" ]]; then
            IFS=',' read -r req s2 s3 s403 s429 sother time < "$stats_file"
            total_requests=$((total_requests + req))
            total_2xx=$((total_2xx + s2))
            total_3xx=$((total_3xx + s3))
            total_403=$((total_403 + s403))
            total_429=$((total_429 + s429))
            total_other=$((total_other + sother))
            total_time=$(awk "BEGIN {printf \"%.0f\", $total_time + $time}")
        fi
    done

    local rps=0
    local avg_latency="N/A"

    if [[ $DURATION -gt 0 ]]; then
        rps=$((total_requests / DURATION))
    fi

    if [[ $total_requests -gt 0 ]]; then
        avg_latency=$(awk "BEGIN {printf \"%.2f\", $total_time / $total_requests}")
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  RESULTS"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    printf "  %-25s %s\n" "Duration:" "${DURATION}s"
    printf "  %-25s %s\n" "Concurrency:" "$CONCURRENCY workers"
    printf "  %-25s %s\n" "Total Requests:" "$total_requests"
    printf "  %-25s ${GREEN}%s${NC}\n" "Success (2xx):" "$total_2xx"
    printf "  %-25s ${GREEN}%s${NC}\n" "Redirect (3xx):" "$total_3xx"
    printf "  %-25s ${YELLOW}%s${NC}\n" "Blocked (403):" "$total_403"
    printf "  %-25s ${YELLOW}%s${NC}\n" "Rate/Credit limited (429):" "$total_429"
    printf "  %-25s ${RED}%s${NC}\n" "Other errors:" "$total_other"
    printf "  %-25s ${CYAN}%s${NC}\n" "Requests/sec:" "$rps"
    printf "  %-25s %s ms\n" "Avg Latency:" "$avg_latency"
    echo ""

    if [[ $total_429 -eq 0 && $total_requests -gt 20 ]]; then
        warn "Zero 429 responses — rate limiting / credit enforcement may not be working!"
    fi

    if [[ $total_other -gt $((total_requests / 3)) ]]; then
        warn "High error rate ($total_other / $total_requests). Check proxy logs."
    fi

    echo ""
}

# Progress indicator
show_progress() {
    local end_time=$1
    local start_time=$(date +%s)

    while [[ $(date +%s) -lt $end_time ]]; do
        if [[ -f "$HANG_FLAG" ]]; then
            echo ""
            error "HANG DETECTED — a request exceeded ${HANG_TIMEOUT}s timeout!"
            echo ""
            cat "$HANG_FLAG"
            echo ""
            return 1
        fi

        local elapsed=$(($(date +%s) - start_time))
        local remaining=$((DURATION - elapsed))
        local active=$(jobs -r | wc -l)

        printf "\r  ${CYAN}[%3ds remaining]${NC} Active workers: %d " "$remaining" "$active"
        sleep 1
    done
    printf "\r%-60s\r" " "
    return 0
}

# Main test
run_test() {
    local end_time=$(($(date +%s) + DURATION))

    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  PHASE 2 — LOAD TEST (concurrent)"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Config:"
    echo "    Proxy:           $PROXY_HOST"
    echo "    Target:          $TARGET_HOST (local echo server)"
    echo "    Duration:        ${DURATION}s"
    echo "    Workers:         $CONCURRENCY"
    echo "    Hang timeout:    ${HANG_TIMEOUT}s per request"
    echo ""
    log "Starting $CONCURRENCY workers..."

    local worker_pids=()
    for i in $(seq 1 "$CONCURRENCY"); do
        worker "$i" "$end_time" &
        worker_pids+=($!)
    done

    local hang_detected=0
    show_progress "$end_time" || hang_detected=1

    log "Waiting for workers to finish..."
    for pid in "${worker_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    if [[ $hang_detected -eq 1 ]]; then
        error "TEST FAILED: proxy hung during load test"
        show_stats
        exit 1
    fi

    success "All workers completed"
    show_stats
}

# ──────────────────────────────────────────────────
# Check dependencies & proxy
# ──────────────────────────────────────────────────
check_deps() {
    local missing=0
    for cmd in curl python3; do
        if ! command -v $cmd &>/dev/null; then
            error "$cmd is required but not installed"
            ((missing++))
        fi
    done
    [[ $missing -gt 0 ]] && exit 1
    success "Dependencies OK (curl, python3)"
}

check_proxy() {
    log "Checking proxy at $PROXY_HOST..."
    if curl -sf --proxy "http://$PROXY_HOST" "http://${TARGET_HOST}/health" \
        -o /dev/null --max-time 10 2>/dev/null; then
        success "Proxy forwarding to local echo server"
    else
        error "Proxy not responding"
        echo ""
        echo "Start the proxy with:"
        echo "  cargo run --release -- -c loadtest/config.yaml"
        exit 1
    fi
}

# Main
main() {
    echo ""
    echo "  ____"
    echo " |  _ \ ___  __  ___   _"
    echo " | |_) / _ \ \ \/ / | | |"
    echo " |  _ < (_) | >  <| |_| |"
    echo " |_| \_\___/ /_/\_\\__, |"
    echo "                   |___/  Load Tester"
    echo ""

    check_deps
    start_echo_server
    check_proxy
    verify_rules
    run_test

    echo "═══════════════════════════════════════════════════════════════════"
    echo "  Load test complete!"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"
