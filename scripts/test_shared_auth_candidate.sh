#!/usr/bin/env bash
set -euo pipefail

: "${SHARED_AUTH_SHA:?missing SHARED_AUTH_SHA}"
root="${1:-shared-auth-server}"

test "$(git -C "$root" rev-parse HEAD)" = "$SHARED_AUTH_SHA"
(
  cd "$root"
  git diff --exit-code -- Cargo.toml .zpkg.toml src scripts docs
  cargo fmt --all -- --check
  cargo test --all-targets
  cargo clippy --all-targets -- -D warnings
  python3 scripts/check-ores-dependency-policy.py
)
