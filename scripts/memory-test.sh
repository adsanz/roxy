#!/usr/bin/env bash
#
# Memory Profiling Script for Roxy
#
# Uses valgrind massif to measure heap usage during request processing.
# Tests both regular forwarding and header mangle paths using google.es.
#
# Prerequisites:
#   - valgrind installed (apt install valgrind)
#   - curl installed
#   - Rust toolchain
#
# Usage:
#   ./scripts/memory-test.sh [requests] [threshold_kb]
#
# Examples:
#   ./scripts/memory-test.sh              # 250 requests, 10MB threshold
#   ./scripts/memory-test.sh 100 5120     # 100 requests, 5MB threshold
#

set -uo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROXY_ADDR="127.0.0.1:8080"
TARGET_HOST="google.es"
WARMUP_REQUESTS=10
TEST_REQUESTS="${1:-250}"
THRESHOLD_KB="${2:-10240}"  # 10MB default, will calibrate

# Output files
MASSIF_OUT="$PROJECT_DIR/massif.out"
MASSIF_REPORT="$PROJECT_DIR/massif_report.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }

# PIDs for cleanup
ROXY_PID=""

cleanup() {
    local exit_code=$?
    log "Cleaning up..."
    
    # Kill proxy
    if [[ -n "$ROXY_PID" ]]; then
        kill "$ROXY_PID" 2>/dev/null || true
        wait "$ROXY_PID" 2>/dev/null || true
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Build release binary
build_roxy() {
    log "Building Roxy (release)..."
    cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1 | tail -5
    success "Build complete"
}

# Create test config for google.es
create_config() {
    cat > "$PROJECT_DIR/tests/fixtures/memory-test.yaml" << 'INNEREOF'
listen: "127.0.0.1:8080"

rules:
  - name: "mangle-google"
    rule: 'host("google.es") && header("X-Duh") = mangle'
  - name: "allow-all"
    rule: 'host("*") = pass'

headers:
  - rules: ["mangle-google"]
    add:
      - name: "X-Proxy-Test"
        value: "memory-profiling"
      - name: "X-Request-Id"
        value: "test-12345"
    remove:
      - "X-Unused-Header"
INNEREOF
    success "Created test config"
}

# Start Roxy under valgrind massif
start_roxy_valgrind() {
    log "Starting Roxy under valgrind massif..."
    
    # Clean up old output
    rm -f "$MASSIF_OUT"* "$MASSIF_REPORT"
    
    valgrind --tool=massif \
        --massif-out-file="$MASSIF_OUT" \
        --detailed-freq=10 \
        --max-snapshots=100 \
        "$PROJECT_DIR/target/release/roxy" \
        --config "$PROJECT_DIR/tests/fixtures/memory-test.yaml" \
        2>&1 &
    
    ROXY_PID=$!
    
    # Wait for proxy to be ready
    log "Waiting for Roxy to start..."
    for i in {1..30}; do
        if curl -s -H "X-Duh: test" --proxy "http://$PROXY_ADDR" "http://example.com" >/dev/null 2>&1; then
            success "Roxy is ready (PID: $ROXY_PID)"
            return 0
        fi
        sleep 1
    done
    
    error "Roxy failed to start within 30 seconds"
    return 1
}

# Run warmup requests
warmup() {
    log "Running $WARMUP_REQUESTS warmup requests..."
    for ((i=1; i<=WARMUP_REQUESTS; i++)); do
        curl -s -H "X-Duh: test" --proxy "http://$PROXY_ADDR" -k "https://$TARGET_HOST/" -o /dev/null || true
    done
    success "Warmup complete"
}

# Run test requests with HTTPS
run_test() {
    local count=$1
    
    log "Running $count HTTPS requests to $TARGET_HOST..."
    
    local successful=0
    local failed=0
    
    for ((i=1; i<=count; i++)); do
        if curl -s -H "X-Duh: test" --proxy "http://$PROXY_ADDR" -k "https://$TARGET_HOST/" -o /dev/null --max-time 10; then
            ((successful++))
        else
            ((failed++))
        fi
        
        # Progress indicator every 50 requests
        if ((i % 50 == 0)); then
            log "Progress: $i/$count (success: $successful, failed: $failed)"
        fi
    done
    
    success "Completed: $successful successful, $failed failed"
}

# Stop Roxy gracefully
stop_roxy() {
    if [[ -n "$ROXY_PID" ]]; then
        log "Stopping Roxy..."
        kill -TERM "$ROXY_PID" 2>/dev/null || true
        
        # Wait for graceful shutdown
        for i in {1..10}; do
            if ! kill -0 "$ROXY_PID" 2>/dev/null; then
                success "Roxy stopped"
                break
            fi
            sleep 1
        done
        
        # Force kill if still running
        if kill -0 "$ROXY_PID" 2>/dev/null; then
            warn "Force killing Roxy..."
            kill -9 "$ROXY_PID" 2>/dev/null || true
        fi
        
        ROXY_PID=""
    fi
}

# Analyze massif output
analyze_results() {
    log "Analyzing memory profile..."
    
    if [[ ! -f "$MASSIF_OUT" ]]; then
        error "Massif output not found!"
        return 1
    fi
    
    # Generate report
    ms_print "$MASSIF_OUT" > "$MASSIF_REPORT" 2>&1 || true
    
    # Extract peak memory (in KB)
    local peak_kb
    peak_kb=$(grep -oP "peak: \K[0-9,]+" "$MASSIF_REPORT" | tr -d ',' || echo "0")
    
    if [[ -z "$peak_kb" || "$peak_kb" == "0" ]]; then
        # Try alternative extraction
        peak_kb=$(grep "mem_heap_B=" "$MASSIF_OUT" | sed 's/mem_heap_B=//' | sort -n | tail -1 || echo "0")
        peak_kb=$((peak_kb / 1024))
    fi
    
    local peak_mb=$((peak_kb / 1024))
    
    echo ""
    echo "========================================"
    echo "         MEMORY PROFILE RESULTS         "
    echo "========================================"
    echo "  Requests:     $TEST_REQUESTS"
    echo "  Target:       $TARGET_HOST (HTTPS)"
    echo "  Peak Memory:  ${peak_kb} KB (${peak_mb} MB)"
    echo "  Threshold:    ${THRESHOLD_KB} KB"
    echo "========================================"
    
    # Show top allocations from report
    if [[ -f "$MASSIF_REPORT" ]]; then
        echo ""
        log "Top memory allocations:"
        head -100 "$MASSIF_REPORT" | tail -60
    fi
    
    # Check threshold
    if [[ "$peak_kb" -gt "$THRESHOLD_KB" ]]; then
        error "FAIL: Peak memory (${peak_kb} KB) exceeds threshold (${THRESHOLD_KB} KB)"
        return 1
    else
        success "PASS: Peak memory within threshold"
        return 0
    fi
}

# Main
main() {
    echo ""
    echo "================================================"
    echo "   Roxy Memory Profiling Test"
    echo "   Target: $TARGET_HOST | Requests: $TEST_REQUESTS"
    echo "================================================"
    echo ""
    
    # Check dependencies
    command -v valgrind >/dev/null || { error "valgrind not installed"; exit 1; }
    command -v curl >/dev/null || { error "curl not installed"; exit 1; }
    command -v ms_print >/dev/null || { warn "ms_print not found, report may be limited"; }
    
    build_roxy
    create_config
    start_roxy_valgrind
    
    # Give valgrind time to initialize
    sleep 2
    
    warmup
    run_test "$TEST_REQUESTS"
    
    stop_roxy
    
    # Wait for massif to finish writing
    sleep 2
    
    analyze_results
}

main "$@"
