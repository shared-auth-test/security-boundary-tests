# Shared Auth credential-plane contract

This repository treats authentication evidence according to the authority it can safely carry.

| Evidence | Purpose | Assurance | May carry roles | May delegate | Verification |
|---|---|---:|---:|---:|---|
| Interactive JWT/session | Human application access | AAL1/AAL2 | Policy-bound | Narrowly, by policy | JWT plus revocation/session checks |
| WebAuthn/passkey | Human authentication or step-up | AAL2 after verified ceremony | Through the interactive session only | Narrowly, by policy | Server-owned WebAuthn ceremony |
| SSH public key | Non-interactive data plane | Fixed AAL1 | No | No | One-time challenge; opaque online-introspected token |
| Kerberos/SPNEGO | Explicitly mapped enterprise data plane | Fixed AAL1 | No; PAC/groups ignored | No | Isolated GSSAPI bridge, exact realm/principal, channel binding, opaque token |
| OpenPGP detached signature | Artifact provenance only | Not access assurance | No | No | Full fingerprint and historical binding window |
| External face/ID/voice recovery evidence | Consented recovery risk signal | Not an access credential | No | No | Non-retaining provider reference/verdict only |

## Biometric boundary

Face and thumbprint login must use platform WebAuthn/passkey user verification. Shared Auth receives the WebAuthn result, not the modality or biometric template. Recovery may use an external, consented, non-retaining provider, but the server rejects raw images, frames, templates, embeddings, voice audio, and voiceprints.

## Sandbox token boundary

SSH and Kerberos credentials receive an opaque `sat_` token. Only authenticated online introspection can authorize it. The authority stores a keyed digest, not the bearer token, so key or mapping revocation is immediately visible. Sandbox credentials have empty roles, no `auth_time`, fixed AAL1, explicit audience/scopes, no control-plane scopes, and no delegation path.

## OpenPGP boundary

A valid detached signature answers who signed an artifact and whether the principal-to-key binding was valid at signing time. It never authenticates a request, opens a session, mints a token, grants a scope, or creates a role.
