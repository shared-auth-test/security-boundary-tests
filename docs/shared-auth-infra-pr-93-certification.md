# Shared Auth infra PR 93 certification

This sibling test repository independently executes the security-critical,
dependency-free Worker sources from `shared-auth/shared-auth-infra#93` because
the product organization's hosted jobs were created with no runner and zero
steps.

## Exact source identity

Product PR head: `f24cf71e74b98c490e18af9971e910f045a3fc4b`.

The candidate files are byte-for-byte Git-blob identical to the product branch:

| Product path | Git blob |
|---|---|
| `workers/auth-policy/package.json` | `41e2e4c252904ed6a43807b1134b6e7ac57509a6` |
| `workers/auth-policy/index.mjs` | `c2cb35563e629fb29df7ca7da2a7030dbfb70b93` |
| `workers/auth-policy/index.d.ts` | `0a7bc1dc6f64c8055c7e6121826962f957886402` |
| `workers/auth-policy/test/policy.test.mjs` | `afccf274d541401eefbfe502bed966093afa67f1` |
| `workers/auth-policy/test/okla-quaestor.test.mjs` | `3d9a14b44a3ccbbcb8ee3ba036ce9658f2fd7934` |
| `workers/auth-edge/src/index.mjs` | `6900aa298b1169bc75d4b9fa560574204c9c2bfb` |
| `workers/auth-edge/test/index.test.mjs` | `e7edfdfb32b2cd3a802288738bb5b450eaa7d662` |

The workflow fails before tests if any copied product blob changes.

## Scope

Node 22 checks and executes the exact proof-policy implementation, its exhaustive
provider-ordering/strict-pair/independent-proof tests, the synthetic
Okla-Quaestor sensitive-operation contract tests, and the auth-edge regression
suite that proves session-creating exchange is single-path rather than raced
against direct-provider verification.

This is independent execution evidence, not a production deployment and not a
claim that the product-org zero-step jobs passed. It does not certify Cloudflare
bindings, Nix/Wrangler packaging, durable queue/outbox infrastructure, or the
separate shared-auth-gateway test changed by the product PR.
