# Shared Auth lib PR 39 certification

This test harness independently compiles and executes the exact Rust proof-policy
and typed provider-adapter sources from `shared-auth/shared-auth-lib#39`.

Product head: `6523b43b33102f05fcc400547b75132465a546b8`.

Exact product blobs:

- `proof_policy.rs`: `990417a0216df954a6ee3ee9ab087bae85f6768c`
- `provider_adapter.rs`: `64e509625d70e5818fe4b89d85a65a775d82d7f7`

The harness supplies only a minimal crate boundary and Tokio test runtime. The
workflow verifies the copied blobs before running Rust 1.85 formatting, Clippy
with warnings denied, and all embedded unit tests. It does not certify the rest
of the product repository or a deployment.
