# Shared Auth PR 73 Rust SOPS policy certification

This sibling test repository independently compiles and exercises the validator
proposed in `shared-auth/shared-auth-clients#73`. The product organization is
currently creating hosted jobs with zero steps and no log blobs, so test evidence
is deliberately produced here rather than weakening or bypassing the product
policy gate.

## Security boundary

The validator owns parsing of `.sops.yaml` creation rules and release admission
for public age recipients. It must reject malformed YAML, duplicate or missing
dev/prod rules, empty sets, duplicate recipients, invalid Bech32 encodings,
invalid checksums, non-zero padding, non-32-byte X25519 payloads, environment
typos, equal dev/prod sets, production sets with fewer than two recipients, and
production sets with no independent recipient.

The fixture contains public age recipients only. It contains no age identity,
private key, decrypted environment value, credential, or token.

## Deeper negative audit

The first Rust draft improved on the Python regex scan but still accepted any
lowercase string beginning with `age1` and silently deduplicated repeated values.
It also returned success for non-production environment names without parsing
configuration. Those fail-open behaviors are now explicit regressions.

## Exact source identity

After canonical Rust 1.85 formatting, the certification source and product PR
source are byte-identical Git blobs:

```text
cd489e2c7b520dcf5afb35e30236eed35324e936
```

The product branch commit carrying that exact source is
`bfeb1bed35063da5345db1da8ed9d57fede5382e`. Certification applies only to this
blob and later commits that preserve it exactly.

## Admission evidence

The certification workflow uses the declared Rust 1.85 MSRV and runs:

- `cargo fmt --check`;
- `cargo clippy --all-targets -- -D warnings`;
- all nine Rust unit tests;
- a live validation of the reviewed public-recipient fixture;
- separate command-level rejection probes for a bad checksum, duplicate
  recipient, and mistyped environment.

The human-authored exact head must be green before the certification PR is made
ready or merged.
