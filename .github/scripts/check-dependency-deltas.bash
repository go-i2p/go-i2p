#!/usr/bin/env bash
set -euo pipefail

deps=(
  github.com/go-i2p/go-noise
  github.com/go-i2p/common
  github.com/go-i2p/crypto
)

echo "Dependency delta report ($(date -u +"%Y-%m-%dT%H:%M:%SZ"))"
echo

for dep in "${deps[@]}"; do
  json="$(go list -m -u -json "$dep")"
  current="$(printf '%s\n' "$json" | awk -F '"' '/"Version":/ { print $4; exit }')"
  latest="$(printf '%s\n' "$json" | awk -F '"' '/"Update": \{/ { in_update=1 } in_update && /"Version":/ { print $4; exit }')"

  if [[ -n "$latest" ]]; then
    status="update-available"
  else
    latest="$current"
    status="up-to-date"
  fi

  printf '%-34s current=%-28s latest=%-28s status=%s\n' "$dep" "$current" "$latest" "$status"
done