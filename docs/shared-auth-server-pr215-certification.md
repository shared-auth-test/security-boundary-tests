# Shared Auth server PR 215 exact-head certification

This certification executes the source-owned workload-identity contract against exact product head `a1e06aa5f99df226f5d81e689f64fc24b208bac9`.

It reproduces the product workflow with Postgres 17: baseline schema, idempotent workload schema application, adversarial DB invariants, rustfmt, workload identity/token-profile tests, integration tests, and strict Clippy.

This is evidence for the non-human workload identity foundation only. It does not advertise or enable OAuth client_credentials.
