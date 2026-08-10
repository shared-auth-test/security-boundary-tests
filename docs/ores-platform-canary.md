# ORES platform exact-head canary

This test-org workflow certifies the dependency and security boundary that links
Shared Auth to the shared ORES contract, core, and logging repositories.

## Exact inputs

The workflow checks out immutable 40-character commits for:

- `ores-otel/ores-interfaces`;
- `ores-otel/ores-lib-core`;
- `ores-otel/ores.otel.log`;
- the proposed `shared-auth/shared-auth-server.rs` integration;
- the separate Shared Auth SOPS/Just/Nix lifecycle proposal.

Every checkout is compared to the declared SHA before tests run. Updating a SHA
is a reviewed compatibility decision, not a floating branch refresh.

## Evidence produced

The canary verifies repository-template SHA-256 provenance, the nine-method auth
contract, non-retaining platform-biometric semantics, the ORES core dependency
policy, all seven language targets, the logger workspace lock, and a fresh Cargo
git consumer. It then generates the proposed Shared Auth `Cargo.lock`, uploads
that exact file as a one-day review artifact, and runs formatting, tests, Clippy,
dependency policy, and secret checks.

The SOPS job is deliberately structural. It verifies ciphertext locations,
ignore rules, distinct recipient policy, Just recipes, pinned Nix inputs, release
policy, and absence of committed private identities. It does **not** decrypt:
production recipient custody and plaintext are not inputs to an untrusted test
organization.

## Biometric boundary

Face and fingerprint are platform-authenticator modality hints only. The canary
requires user verification and a signed authenticator verdict while forbidding
raw images/templates. No test fixture contains or requests biometric material.
