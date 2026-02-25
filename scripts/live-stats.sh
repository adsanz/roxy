#!/usr/bin/env bash
# live-stats.sh — Parse roxy JSON logs from docker and display live stats.
#
# Usage:
#   docker logs -f <container> 2>&1 | ./scripts/live-stats.sh
#   docker run ... 2>&1 | ./scripts/live-stats.sh
#
# Requires: jq

set -euo pipefail

if ! command -v jq &>/dev/null; then
  echo "Error: jq is required. Install with: apt install jq / brew install jq" >&2
  exit 1
fi

# --- state ---
declare -A paths=()        # path -> count
declare -A rules=()        # rule -> count
declare -A errors=()       # error message -> count
rate_limited=0
credit_exhausted=0
total=0
total_errors=0
start_time=$(date +%s)

# --- display ---
refresh() {
  local now elapsed rps
  now=$(date +%s)
  elapsed=$(( now - start_time ))
  (( elapsed == 0 )) && elapsed=1
  rps=$(awk "BEGIN{printf \"%.1f\", $total / $elapsed}")

  clear

  printf '\e[1m%-60s\e[0m\n' "═══ roxy live stats ═══"
  printf '  Total requests: \e[1;36m%d\e[0m   (%s req/s)   uptime: %ds\n\n' \
    "$total" "$rps" "$elapsed"

  # --- Paths ---
  printf '\e[1;33m%-50s %s\e[0m\n' "PATH" "HITS"
  printf '%-50s %s\n' "──────────────────────────────────────────────────" "────"
  for p in "${!paths[@]}"; do
    printf '%-50s %d\n' "$p" "${paths[$p]}"
  done | sort -t$'\t' -k2 -rn | head -20
  echo

  # --- Rules ---
  printf '\e[1;33m%-40s %s\e[0m\n' "RULE" "REQUESTS"
  printf '%-40s %s\n' "────────────────────────────────────────" "────────"
  for r in "${!rules[@]}"; do
    printf '%-40s %d\n' "$r" "${rules[$r]}"
  done | sort -t$'\t' -k2 -rn
  echo

  # --- Actions ---
  printf '\e[1;33m%-40s %s\e[0m\n' "ACTION" "COUNT"
  printf '%-40s %s\n' "────────────────────────────────────────" "────────"
  printf '%-40s \e[1;31m%d\e[0m\n' "Rate limited (429)" "$rate_limited"
  printf '%-40s \e[1;31m%d\e[0m\n' "Credit exhausted (429)" "$credit_exhausted"
  echo

  # --- Errors ---
  printf '\e[1;33m%-60s %s\e[0m\n' "ERRORS (total: $total_errors)" "COUNT"
  printf '%-60s %s\n' "────────────────────────────────────────────────────────────" "────"
  if (( total_errors == 0 )); then
    printf '  \e[32m(none)\e[0m\n'
  else
    for e in "${!errors[@]}"; do
      printf '%-60s \e[1;31m%d\e[0m\n' "$e" "${errors[$e]}"
    done | sort -t$'\t' -k2 -rn
  fi
  echo
}

# --- main loop ---
# Buffer: refresh screen every N lines or every 1 second via timeout
last_refresh=$SECONDS

while IFS= read -r line; do
  # Skip non-JSON lines (e.g. docker startup messages)
  [[ "$line" == "{"* ]] || continue

  # Extract level and check for errors/warnings
  level=$(echo "$line" | jq -r '.level // empty' 2>/dev/null) || continue

  if [[ "$level" == "ERROR" || "$level" == "WARN" ]]; then
    msg=$(echo "$line" | jq -r '.fields.message // empty' 2>/dev/null)
    [[ -z "$msg" ]] && continue
    err_key="[$level] $msg"
    errors["$err_key"]=$(( ${errors["$err_key"]:-0} + 1 ))
    total_errors=$(( total_errors + 1 ))

    # Refresh display at most once per second
    if (( SECONDS - last_refresh >= 1 )); then
      refresh
      last_refresh=$SECONDS
    fi
    continue
  fi

  # INFO logs: only care about lines with an action field
  action=$(echo "$line" | jq -r '.fields.action // empty' 2>/dev/null) || continue
  [[ -z "$action" ]] && continue

  path=$(echo "$line" | jq -r '.fields.path // "-"' 2>/dev/null)
  rule=$(echo "$line" | jq -r '.fields.rule // "(none)"' 2>/dev/null)

  (( total += 1 ))

  # Paths
  paths["$path"]=$(( ${paths["$path"]:-0} + 1 ))

  # Rules
  rules["$rule"]=$(( ${rules["$rule"]:-0} + 1 ))

  # Special counters
  case "$action" in
    rate_limited)    (( rate_limited += 1 )) ;;
    credit_exhausted) (( credit_exhausted += 1 )) ;;
  esac

  # Refresh display at most once per second
  if (( SECONDS - last_refresh >= 1 )); then
    refresh
    last_refresh=$SECONDS
  fi
done

# Final display on EOF / Ctrl-C
refresh
