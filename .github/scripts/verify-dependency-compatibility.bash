#!/usr/bin/env bash
set -euo pipefail

changed_go_mod="${1:-true}"

if [[ "$changed_go_mod" != "true" ]]; then
  echo "go.mod unchanged; no tracked dependency compatibility checks required"
  exit 0
fi

tracked_changed=false

for dep in github.com/go-i2p/go-noise github.com/go-i2p/common github.com/go-i2p/crypto; do
  if git --no-pager diff --unified=0 origin/main...HEAD -- go.mod | grep -q "$dep"; then
    tracked_changed=true
    break
  fi
done

if [[ "$tracked_changed" != "true" ]]; then
  echo "No tracked dependency deltas detected in go.mod"
  exit 0
fi

echo "Tracked dependency delta detected; running compatibility checks"
go test ./lib/transport/...
go test ./lib/tunnel/...
go test ./lib/netdb/...