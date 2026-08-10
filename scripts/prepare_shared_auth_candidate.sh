#!/usr/bin/env bash
set -euo pipefail

: "${SHARED_AUTH_SHA:?missing SHARED_AUTH_SHA}"
root="${1:-shared-auth-server}"

test "$(git -C "$root" rev-parse HEAD)" = "$SHARED_AUTH_SHA"
(
  cd "$root"
  cargo generate-lockfile
  python3 scripts/check-ores-dependency-policy.py
)
