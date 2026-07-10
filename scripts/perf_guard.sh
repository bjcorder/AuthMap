#!/usr/bin/env bash
set -euo pipefail

baseline_file="${1:-ci/perf-baseline.env}"
if [[ ! -f "$baseline_file" ]]; then
  printf 'performance baseline file not found: %s\n' "$baseline_file" >&2
  exit 2
fi

source "$baseline_file"

: "${AUTHMAP_PERF_BASELINE_MS:?missing AUTHMAP_PERF_BASELINE_MS}"
: "${AUTHMAP_PERF_THRESHOLD_PERCENT:?missing AUTHMAP_PERF_THRESHOLD_PERCENT}"
: "${AUTHMAP_PERF_FIXTURE:?missing AUTHMAP_PERF_FIXTURE}"

cargo build -p authmap-cli --release --locked

binary="target/release/authmap"
if [[ ! -x "$binary" ]]; then
  printf 'authmap binary not found after release build: %s\n' "$binary" >&2
  exit 2
fi

tmp_output="$(mktemp)"
trap 'rm -f "$tmp_output"' EXIT

start_ns="$(date +%s%N)"
"$binary" scan "$AUTHMAP_PERF_FIXTURE" --format json --output "$tmp_output" >/dev/null
end_ns="$(date +%s%N)"

elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
allowed_ms=$(( AUTHMAP_PERF_BASELINE_MS + (AUTHMAP_PERF_BASELINE_MS * AUTHMAP_PERF_THRESHOLD_PERCENT / 100) ))

printf 'AuthMap perf guard: fixture=%s elapsed_ms=%s baseline_ms=%s threshold_percent=%s allowed_ms=%s\n' \
  "$AUTHMAP_PERF_FIXTURE" "$elapsed_ms" "$AUTHMAP_PERF_BASELINE_MS" "$AUTHMAP_PERF_THRESHOLD_PERCENT" "$allowed_ms"

if (( elapsed_ms > allowed_ms )); then
  printf 'performance regression: elapsed %sms exceeds allowed %sms\n' "$elapsed_ms" "$allowed_ms" >&2
  exit 1
fi
