# Provider identity binding v1

This contract makes the canonical Shared Auth provider identity binding executable without changing the published legacy `Identity` payload.

## Canonical identity key

The only provider identity key defined by this contract is the ordered tuple:

```text
(provider, issuer, subject, realm)
```

A `ProviderIdentityBinding` maps exactly one such tuple to exactly one `shared_user_id`. Consumers, persistence layers, events, SDKs, and provider adapters must preserve all four key components. `provider_tenant`, provider display names, project names, email addresses, phone numbers, and profile attributes are not substitutes for the tuple.

`issuer` is the exact reviewed HTTPS issuer used by the provider proof. It is not reconstructed from an email domain or a mutable display name. `subject` is the provider subject in that issuer namespace. `realm` prevents customer/admin or other explicitly separated identity planes from collapsing into one namespace.

## Migration from older identities

The legacy v1 wire identity remains valid and unchanged. Migration is additive:

- `principal_id` may be retained as a legacy internal reference while the canonical `shared_user_id` is materialized.
- `provider_tenant` and `provider_subject` may be retained as migration evidence, but `provider_tenant` is not silently promoted to `issuer`.
- `migration_basis = reviewed_provider_mapping` means a versioned/reviewed provider-resource mapping supplied the exact issuer.
- `migration_basis = fresh_reverification` means the provider was reverified and emitted the canonical tuple directly.
- `migration_basis = insufficient_evidence` must remain quarantined; no canonical binding may be inferred from email, phone, display name, or tenant-name similarity.
- Existing records that already carry the canonical tuple use `canonical_tuple` and need no identity inference.

Migration code must be idempotent on the canonical tuple and fail closed on collisions: one tuple must never map to two `shared_user_id` values, and two different tuples are never merged merely because profile data matches.

## Email non-merge invariant

`IdentityNonMergeScenario` exists specifically as executable evidence for the legacy failure mode where two providers report the same verified email. The fixture under `instances/IdentityNonMergeScenario/valid/` gives Supabase and Neon identities the same profile email while requiring distinct canonical bindings. Email is not a field of `ProviderIdentityKey` and is explicitly marked non-evidence in the scenario.

## Authority

`main.tsp` and `authored.schema.json` are independent peer authorities. Neither is generated from the other. `ORESoftware/typespec-json-schema-validator` compiles Schema B from TypeSpec only as comparison evidence and must report zero unexplained findings before this contract is admitted.

The legacy `schema/identity.schema.json`, `typespec/peer/identity.tsp`, and generated language bindings are intentionally unchanged by this contract. A future public wire migration can project this binding into SDKs only through an explicit versioned payload change.
