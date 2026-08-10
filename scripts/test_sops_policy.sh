#!/usr/bin/env bash
set -euo pipefail

: "${SHARED_AUTH_SOPS_SHA:?missing SHARED_AUTH_SOPS_SHA}"
root="${1:-shared-auth-sops}"

test "$(git -C "$root" rev-parse HEAD)" = "$SHARED_AUTH_SOPS_SHA"
(
  cd "$root"
  bash scripts/check-env-policy.sh
  python3 scripts/verify-sops-release-policy.py
  python3 -m py_compile scripts/verify-sops-release-policy.py

  test -f .sops.yaml
  test -f justfile
  test -f .nix/flake.nix
  test -f env/enc/dev.env.enc
  test -f env/enc/prod.env.enc
  test -z "$(git ls-files 'env/dec/**' '.env' '*.agekey' '*.pem' | tr -d '\n')"
  git check-ignore -q --no-index env/dec/dev.env
  git check-ignore -q --no-index env/dec/prod.env
  git check-ignore -q --no-index .env

  python3 - <<'PY'
from pathlib import Path
import re

root = Path('.')
patterns = (
    re.compile(r'AGE-SECRET-KEY-1[A-Z0-9]{20,}'),
    re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{32,}',
        re.DOTALL,
    ),
)
for path in root.rglob('*'):
    if not path.is_file() or '.git' in path.parts or path.stat().st_size > 2_000_000:
        continue
    try:
        text = path.read_text(encoding='utf-8')
    except UnicodeError:
        continue
    for pattern in patterns:
        if pattern.search(text):
            raise SystemExit(f'private identity material found in {path}')
print('SOPS tree contains ciphertext policy only; no private identity material detected')
PY
)

echo "Structural SOPS/Just/Nix policy passed."
echo "No decrypt was attempted: recipient private identities and production plaintext are not test-org inputs."
