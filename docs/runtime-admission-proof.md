# Native runtime admission evidence

Tracks DEN-2194 / DEN-2843 and shared-auth/shared-auth-infra#94.
The source org's run 36250358405 failed before runner assignment. This suite
uses the snapshot fallback authorized by the test org's CROSS_ORG_SOURCE_ACCESS
policy, without production credentials or private checkout tokens.

`admission-source.json` records the exact upstream commit and Git blob IDs.
`scripts/verify_admission_snapshot.py` checks every byte before native execution.
The snapshot is generated from the authoritative Shared Auth repository; fixes
belong upstream, followed by a new manifest and regenerated snapshot.

The workflow compiles OTP 27 modules with warnings as errors and runs EUnit.
Independent jobs exercise Nginx, Caddy and HAProxy against local synthetic
verifier/application services. No deployment or source status override occurs.
Evidence qualifies only the recorded source bytes; it does not prove cross-org
App access, live identity providers, product authorization, or production readiness.
