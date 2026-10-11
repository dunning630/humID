#!/usr/bin/env bash
# Run cargo in CI and, if it fails, surface the compiler errors as a GitHub
# annotation. Annotations show on the run's summary page and through the API,
# so a failure can be diagnosed without downloading the full log.
#
#   tools/ci-cargo.sh build --target aarch64-apple-ios --lib
set -uo pipefail

log=$(mktemp)
cargo "$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

if [ "$status" -ne 0 ]; then
  # Rust errors, build-script panics and linker failures, with context.
  # Swift / C compiler diagnostics look like "File.swift:12:5: error: ...".
  native=$(grep -E -A6 '(\.swift|\.m|\.c|\.h):[0-9]+:[0-9]+: (fatal )?error:' "$log" | head -60)
  rust=$(grep -E -A14 '^error(\[E[0-9]+\])?:|panicked at|^  = note:|ld: |undefined symbols' "$log" | head -80)
  summary=$(printf '%s\n%s' "$native" "$rust")
  [ -z "$native$rust" ] && summary=$(tail -60 "$log")
  # GitHub annotations encode newlines as %0A; keep under the size limit.
  encoded=$(printf '%s' "$summary" | head -c 3800 | sed -e 's/%/%25/g' | awk 'BEGIN{ORS="%0A"} {print}')
  echo "::error title=cargo $* failed::${encoded}"
fi
exit "$status"
