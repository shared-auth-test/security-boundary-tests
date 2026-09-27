use axum::{response::Html, Json};
use serde_json::{json, Value};

pub async fn openapi() -> Json<Value> {
    Json(document())
}

pub async fn api_docs() -> Html<String> {
    Html(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>shared-auth API</title><style>body{font:15px/1.5 ui-monospace,monospace;max-width:52rem;margin:3rem auto;padding:0 1rem}code{background:#8882;padding:.1rem .3rem}li{margin:.5rem 0}</style></head><body><h1>shared-auth API</h1><p>Postgres-primary, provider-neutral authentication. The machine-readable OpenAPI contract is at <a href="/api/docs.json"><code>/api/docs.json</code></a>.</p><ul><li><code>POST /auth/register</code> — optional local registration</li><li><code>POST /auth/login</code> — local login</li><li><code>POST /auth/passwordless/request</code> — send a branded six-digit SendGrid email OTP; no link</li><li><code>POST /auth/passwordless/consume</code> — exchange an email OTP or already-issued legacy token</li><li><code>GET /auth/browser/session</code> — resolve the first-party session cookie into bounded active claims</li><li><code>POST /hooks/supabase/send-email</code> — signed Supabase Send Email Hook with OTP-only SendGrid delivery</li><li><code>POST /auth/mfa/sms/request</code> — start Twilio Verify SMS enrollment/challenge</li><li><code>POST /auth/mfa/sms/verify</code> — verify SMS and issue an AAL2 session</li><li><code>POST /auth/exchange</code> — exchange a secondary-provider token</li><li><code>POST /auth/delegate</code> — exchange a user token for a configured audience/scope-limited product token</li><li><code>POST /auth/ssh/keys</code> — register an SSH public key for non-interactive clients (interactive LOA2 only)</li><li><code>POST /auth/ssh/challenge</code> — open a public-key handshake</li><li><code>POST /auth/ssh/verify</code> — exchange an SSHSIG signature for a sandboxed, scope-limited token</li><li><code>POST /auth/refresh</code> — rotate a refresh token</li><li><code>POST /auth/logout</code> — revoke a refresh session</li><li><code>POST /auth/introspect</code> — inspect a shared-auth or delegated access token</li><li><code>GET /.well-known/jwks.json</code> — public ES256 keys</li></ul></body></html>"#.to_owned(),
    )
}

fn document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "shared-auth API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Postgres-primary authentication with OTP-only passwordless email, signed Supabase delivery hooks, SMS MFA, provider adapters, rotated sessions, ES256 access tokens, and fail-closed product delegation."
        },
        "paths": {
            "/auth/register": { "post": { "summary": "Register a local principal", "responses": { "200": { "description": "Token pair" }, "403": { "description": "Registration disabled" } } } },
            "/auth/login": { "post": { "summary": "Authenticate local credentials", "responses": { "200": { "description": "Token pair" }, "401": { "description": "Uniform authentication failure" } } } },
            "/auth/passwordless/request": { "post": { "summary": "Send a branded six-digit email OTP through SendGrid; no sign-in link is generated", "responses": { "202": { "description": "Enumeration-resistant acceptance" }, "503": { "description": "Passwordless email is not configured" } } } },
            "/auth/passwordless/consume": { "post": { "summary": "Consume a six-digit email OTP or an already-issued legacy token", "responses": { "200": { "description": "AAL1 shared-auth token pair" }, "401": { "description": "Invalid, expired, or consumed credential" } } } },
            "/auth/browser/consume": { "get": { "summary": "Consume a first-party magic link and establish the product-scoped browser session", "responses": { "303": { "description": "Browser session established and redirected to the sealed return path" }, "401": { "description": "Invalid, expired, or consumed magic link" } } } },
            "/auth/browser/otp": { "post": { "summary": "Consume an email OTP and establish the product-scoped browser session", "responses": { "303": { "description": "Browser session established and redirected to the sealed return path" }, "401": { "description": "Invalid, expired, or consumed email OTP" } } } },
            "/auth/browser/session": { "get": { "summary": "Resolve the first-party browser session cookie into bounded active claims", "description": "For same-origin product gateways only. Possession of exactly one valid realm-specific __Host- session cookie authorizes this read. The server verifies JWT signature, expiry, audience, session revocation, and principal epoch; it never exposes the cookie, refresh token, session id, provider subject, JWT lineage, seal secret, or introspection service credential. Responses are private and no-store.", "responses": { "200": { "description": "Active bounded browser identity", "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["user_id", "provider", "provider_tenant", "roles", "aal"], "properties": { "user_id": { "type": "string" }, "provider": { "type": "string" }, "provider_tenant": { "type": "string" }, "roles": { "type": "array", "items": { "type": "string" } }, "aal": { "type": "integer", "minimum": 1 }, "auth_time": { "type": "integer" }, "amr": { "type": "array", "items": { "type": "string" } }, "acr": { "type": "string" }, "project": { "type": "string" }, "email": { "type": "string" }, "scope": { "type": "string" }, "azp": { "type": "string" }, "cred": { "type": "string" } } } } } }, "401": { "description": "Missing, ambiguous, malformed, expired, or revoked session cookie" }, "503": { "description": "The browser session contract or authoritative session store is unavailable" } } } },
            "/authorize": { "get": { "summary": "Open a registered product-client sign-in ceremony", "responses": { "200": { "description": "First-party sign-in form" }, "400": { "description": "Invalid client, redirect, state, or PKCE request" } } }, "post": { "summary": "Authenticate and issue a PKCE-bound one-time handoff code", "responses": { "303": { "description": "Redirect to the exact registered client callback" }, "401": { "description": "Authentication failed" } } } },
            "/hooks/supabase/send-email": { "post": { "summary": "Verify a signed Supabase Send Email Hook and deliver only its numeric OTP through SendGrid", "responses": { "200": { "description": "OTP delivery accepted" }, "401": { "description": "Invalid, stale, or missing webhook signature" }, "502": { "description": "SendGrid delivery failed" } } } },
            "/auth/mfa/sms/request": { "post": { "summary": "Start a Twilio Verify SMS challenge for an authenticated user", "responses": { "202": { "description": "Challenge started" }, "401": { "description": "A valid shared-auth bearer token is required" }, "503": { "description": "Twilio Verify is not configured" } } } },
            "/auth/mfa/sms/verify": { "post": { "summary": "Verify an SMS code and upgrade to AAL2", "responses": { "200": { "description": "AAL2 shared-auth token pair" }, "401": { "description": "Invalid bearer token or SMS code" } } } },
            "/auth/handoff/redeem": { "post": { "summary": "Redeem a browser handoff code for the encrypted provider token bundle", "responses": { "200": { "description": "Decrypted provider token bundle; the code is marked consumed before it is returned" }, "401": { "description": "A registered client secret is required" }, "503": { "description": "Browser handoff is not configured for this deployment" } } } },
            "/auth/risk/evaluate": { "post": { "summary": "Evaluate IP, device-fingerprint, and behavioral-embedding signals", "description": "Warning plane only. Raw IP and client hints are hashed; responses never echo them. Deny requires AUTH_RISK_DENY_ON_BAD_ACTOR.", "responses": { "200": { "description": "allow, warn, step_up, or deny with redacted hashes" }, "400": { "description": "Malformed embedding or fingerprint" } } } },
            "/auth/qr/challenge": { "post": { "summary": "Start a signed-in QR device-bind ceremony", "responses": { "200": { "description": "QR payload containing only a challenge id and nonce" }, "401": { "description": "A valid shared-auth bearer token is required" } } } },
            "/auth/qr/consume": { "post": { "summary": "Approve a device-bind QR challenge from the signed-in device", "responses": { "200": { "description": "Challenge approved" }, "401": { "description": "Invalid challenge or nonce" } } } },
            "/auth/qr/login/start": { "post": { "summary": "Open an unauthenticated cross-device QR login challenge", "description": "Companion to TOTP otpauth_uri. The QR carries no session secret.", "responses": { "200": { "description": "QR payload for the desktop to render" } } } },
            "/auth/qr/login/approve": { "post": { "summary": "Approve a QR login challenge from a signed-in phone", "responses": { "200": { "description": "Challenge approved" }, "401": { "description": "Invalid challenge or nonce" } } } },
            "/auth/qr/login/poll": { "post": { "summary": "Poll a QR login challenge without enumerating unknowns", "responses": { "200": { "description": "pending, approved, consumed, or pending for unknown ids" } } } },
            "/auth/idv/sessions": { "post": { "summary": "Start a third-party ID and age verification session", "description": "Shared-auth never accepts ID photos or face images. The browser is sent to the vendor HTTPS capture URL. Persist only inquiry id and age-over-N verdicts.", "responses": { "200": { "description": "Vendor capture URL and local session id" }, "401": { "description": "A valid shared-auth bearer token is required" }, "503": { "description": "AUTH_IDV_CAPTURE_BASE is not configured" } } } },
            "/auth/idv/sessions/{sessionId}": { "post": { "summary": "Read a bounded ID-verification session status", "responses": { "200": { "description": "Status and optional age/document verdict" }, "401": { "description": "Unknown session or caller mismatch" } } } },
            "/auth/idv/sessions/{sessionId}/complete": { "post": { "summary": "Normalize vendor evidence into an age and document verdict", "responses": { "200": { "description": "Normalized verdict; raw media is never stored" }, "400": { "description": "Invalid vendor confidence or document type" } } } },
            "/auth/recovery/capabilities": { "get": { "summary": "Report which account-recovery ceremonies this deployment offers", "responses": { "200": { "description": "Recovery capability flags; reports disabled with all requirements asserted when recovery is unconfigured" } } } },
            "/auth/factors": { "get": { "summary": "List the authenticated principal's enrolled MFA factors", "responses": { "200": { "description": "Enrolled factor metadata without TOTP seeds or biometric material" }, "401": { "description": "A valid active shared-auth bearer token is required" }, "503": { "description": "Durable factor storage is unavailable" } } } },
            "/auth/factors/{factorId}": { "delete": { "summary": "Delete an enrolled MFA factor under the factor-management assurance policy", "responses": { "204": { "description": "Factor deleted" }, "403": { "description": "A fresh interactive factor-management session is required" } } } },
            "/auth/factors/totp/enroll": { "post": { "summary": "Begin TOTP factor enrollment", "responses": { "200": { "description": "Pending enrollment and provisioning material" }, "403": { "description": "Factor-management policy denied enrollment" } } } },
            "/auth/factors/totp/confirm": { "post": { "summary": "Confirm a pending TOTP enrollment", "responses": { "200": { "description": "Verified factor metadata" }, "401": { "description": "The TOTP code was not accepted" } } } },
            "/auth/challenges": { "post": { "summary": "Create a challenge for an enrolled MFA factor", "responses": { "200": { "description": "Single-use factor challenge" }, "401": { "description": "The factor is unavailable to this principal" } } } },
            "/auth/challenges/{challengeId}/verify": { "post": { "summary": "Verify a factor challenge and mint an upgraded session", "responses": { "200": { "description": "AAL2 shared-auth token pair" }, "401": { "description": "Invalid, expired, replayed, or incorrect challenge" } } } },
            "/auth/passkeys/registration/options": { "post": { "summary": "Begin passkey registration", "responses": { "200": { "description": "WebAuthn creation options" }, "403": { "description": "Factor-management policy denied registration" } } } },
            "/auth/passkeys/registration/verify": { "post": { "summary": "Verify and store a passkey registration", "responses": { "200": { "description": "Verified passkey metadata" }, "401": { "description": "Registration ceremony verification failed" } } } },
            "/auth/passkeys/authentication/options": { "post": { "summary": "Begin passkey authentication", "responses": { "200": { "description": "WebAuthn request options" }, "401": { "description": "No eligible passkey is available" } } } },
            "/auth/passkeys/authentication/verify": { "post": { "summary": "Verify a passkey assertion and mint an upgraded session", "responses": { "200": { "description": "AAL2 shared-auth token pair" }, "401": { "description": "Authentication ceremony verification failed" } } } },
            "/auth/recovery/enrollment": { "post": { "summary": "Begin recovery enrollment", "responses": { "200": { "description": "Recovery enrollment ceremony" }, "403": { "description": "Recovery enrollment policy denied the request" } } }, "delete": { "summary": "Revoke recovery enrollment", "responses": { "204": { "description": "Recovery enrollment revoked" } } } },
            "/auth/recovery/enrollment/{ceremonyId}/complete": { "post": { "summary": "Complete recovery enrollment", "responses": { "200": { "description": "Recovery enrollment completed" }, "401": { "description": "Enrollment ceremony verification failed" } } } },
            "/auth/recovery/ceremonies": { "post": { "summary": "Begin an account-recovery ceremony", "responses": { "202": { "description": "Recovery ceremony accepted without account enumeration" } } } },
            "/auth/recovery/ceremonies/{ceremonyId}/status": { "post": { "summary": "Read the bounded status of a recovery ceremony", "responses": { "200": { "description": "Recovery ceremony status" }, "401": { "description": "Recovery status credential was not accepted" } } } },
            "/auth/recovery/ceremonies/{ceremonyId}/complete": { "post": { "summary": "Submit recovery evidence for policy evaluation", "responses": { "202": { "description": "Recovery evidence accepted for evaluation or review" }, "403": { "description": "Recovery policy denied completion" } } } },
            "/auth/recovery/ceremonies/{ceremonyId}/redeem": { "post": { "summary": "Redeem an approved recovery ceremony", "responses": { "200": { "description": "Recovered shared-auth token pair" }, "401": { "description": "Recovery redemption was invalid, premature, expired, or consumed" } } } },
            "/auth/exchange": { "post": { "summary": "Exchange a secondary-provider bearer token", "responses": { "200": { "description": "Shared-auth token pair" }, "401": { "description": "Uniform authentication failure" } } } },
            "/auth/delegate": { "post": { "summary": "Mint a short-lived configured audience/scope-limited product token", "description": "Uses the current shared-auth bearer as the subject credential. The allow-list is configured with AUTH_DELEGATION_POLICIES. Sensitive scopes can require recent LOA2 assurance; no factor application is called directly.", "responses": { "200": { "description": "Delegated bearer with a new jti, inherited session revocation, and preserved assurance provenance" }, "401": { "description": "Invalid or inactive subject token" }, "403": { "description": "Client, audience, scope, role, or assurance policy denied the exchange" } } } },
            "/auth/ssh/keys": { "get": { "summary": "List the caller's registered SSH public keys", "responses": { "200": { "description": "Fingerprints, labels, audiences, and scope grants; never key material beyond the public blob's fingerprint" }, "401": { "description": "A valid shared-auth bearer token is required" } } }, "post": { "summary": "Register an SSH public key for non-interactive authentication", "description": "Requires an interactive session at LOA2: registering a credential is a control-plane operation, so it cannot be performed by a token minted from this plane. The key is stored with an explicit audience and scope allow-list that becomes its entire authority.", "responses": { "201": { "description": "Registered key" }, "400": { "description": "Unsupported or malformed public key" }, "403": { "description": "Not an interactive LOA2 session, or the requested scopes reach the control plane" }, "409": { "description": "That key is already registered on this deployment" } } } },
            "/auth/ssh/keys/{publicKeyId}": { "delete": { "summary": "Remove a key and revoke the tokens it minted", "responses": { "204": { "description": "Removed; live sessions for the key are revoked in the same transaction" }, "403": { "description": "Not an interactive LOA2 session" } } } },
            "/auth/ssh/challenge": { "post": { "summary": "Open a public-key handshake", "description": "Unauthenticated by construction — the key is the credential. Returns the exact message to sign and the required SSHSIG namespace. Bounded by a per-key ceiling on open challenges.", "responses": { "200": { "description": "Single-use challenge with a server-chosen message" }, "401": { "description": "Unknown, disabled, or malformed fingerprint" }, "429": { "description": "Too many open challenges for this key" } } } },
            "/auth/ssh/verify": { "post": { "summary": "Exchange an SSHSIG signature for a sandboxed token", "description": "The token is limited by construction: base assurance with no path to step-up, the key's registered scopes and no roles, a non-base audience, non-delegable, and bound to a revocable session.", "responses": { "200": { "description": "Sandboxed bearer for the key's registered audience and scopes" }, "401": { "description": "Invalid, replayed, or expired challenge or signature" }, "403": { "description": "Stored scopes no longer satisfy the sandbox policy" } } } },
            "/auth/refresh": { "post": { "summary": "Atomically rotate a refresh token", "responses": { "200": { "description": "Rotated token pair" }, "401": { "description": "Invalid, expired, revoked, or replayed token" } } } },
            "/auth/logout": { "post": { "summary": "Revoke a refresh session", "responses": { "204": { "description": "Revoked or already absent" } } } },
            // The stricter entry below supersedes the older generic introspection description.
            "/auth/verify": { "get": { "summary": "Bearer check for gateway auth_request", "responses": { "200": { "description": "Token accepted" }, "401": { "description": "Token rejected" } } } },
            "/auth/introspect": { "post": { "summary": "Inspect a shared-auth or exact-audience delegated access token", "description": "The exact shared-auth-web-server audience is fail-closed and returns only the canonical DirectoryAdminGrantSet envelope from current Postgres grants; raw email, provider subjects, flat scope/roles, and organization_ids are omitted.", "responses": { "200": { "description": "Generic verified claims, strict redacted directory grant envelope, or inactive sentinel according to the exact requested audience" } } } },
            "/auth/capabilities": { "get": { "summary": "Read configured factor methods and the fresh fail-closed security capability document", "description": "Returns shared-auth/capabilities/v1 with no-store. The method list advertises only configured email OTP, SMS OTP, TOTP, and passkey lanes. Global revocation is implemented only when every authoritative startup gate is active; external face/fingerprint recovery remains disabled. QR login, risk signals, and third-party ID/age verification never store raw biometrics.", "responses": { "200": { "description": "Configured factor methods and capability document" } } } },
            "/auth/admin/revocation-token-exchange": { "post": { "summary": "Exchange an active dashboard token for one bounded revocation scope", "description": "Requires an independent exact-256-bit service bearer. The canonical body carries the transient subject token; tokens are never logged or persisted.", "responses": { "200": { "description": "AdminRevocationTokenExchangeResult valid for at most 300 seconds" }, "401": { "description": "Missing service credential or inactive subject token" }, "403": { "description": "Wrong source audience/scope/role or stale WebAuthn" } } } },
            "/admin/v1/session-revocations/search": { "post": { "summary": "Search the authoritative keyed principal-alias index", "description": "Accepts only PrincipalSearchRequest. Raw email is prohibited; incomplete keyed alias or directory inventory fails closed.", "responses": { "200": { "description": "PrincipalSearchResult with no_match, unique, or ambiguous state" }, "403": { "description": "Wrong audience/client/scope or role" }, "428": { "description": "Fresh phishing-resistant step-up required" } } } },
            "/admin/v1/session-revocations/selections": { "post": { "summary": "Select one immutable principal from a stored lookup", "description": "Accepts PrincipalSelectionRequest and returns a one-use opaque selection handle.", "responses": { "200": { "description": "PrincipalSelectionResult" }, "409": { "description": "Expired lookup, mismatched principal, or consumed state" } } } },
            "/admin/v1/session-revocations/previews": { "post": { "summary": "Create an exact-scope global revocation preview", "description": "Consumes only the server-bound selection handle; principal and email fields are rejected.", "responses": { "200": { "description": "GlobalRevocationPreview with explicit known/null inventory counts" }, "409": { "description": "Expired or consumed selection" } } } },
            "/admin/v1/session-revocations/previews/{previewId}": { "get": { "summary": "Review an exact unexpired preview", "responses": { "200": { "description": "Canonical redacted GlobalRevocationPreview" }, "428": { "description": "Fresh phishing-resistant step-up required" } } } },
            "/admin/v1/session-revocations/previews/{previewId}/commit-authorizations": { "post": { "summary": "Create a one-use distinct-operator commit authorization", "description": "The request body is empty. Server-verified WebAuthn evidence and actor/session bindings never come from client JSON.", "responses": { "200": { "description": "GlobalRevocationCommitAuthorization" }, "403": { "description": "Dual control not satisfied" }, "428": { "description": "Fresh phishing-resistant step-up required" } } } },
            "/admin/v1/session-revocations/operations": { "post": { "summary": "Commit an idempotent global auth-epoch fence", "description": "Atomically consumes the commit authorization and persists the central fence, target states, audit, and outbox. Unsupported adapters remain explicit.", "responses": { "202": { "description": "New GlobalRevocationOperation" }, "200": { "description": "Identical idempotent replay" }, "409": { "description": "Expired/consumed authorization or cross-payload idempotency reuse" } } } },
            "/admin/v1/session-revocations/operations/{operationId}": { "get": { "summary": "Read the durable central fence and truthful per-target state", "responses": { "200": { "description": "GlobalRevocationOperation" }, "404": { "description": "Control plane disabled or operation absent" } } } },
            "/.well-known/jwks.json": { "get": { "summary": "Read public ES256 signing keys", "responses": { "200": { "description": "JWKS" } } } },
            "/scim/v2/ServiceProviderConfig": { "get": { "summary": "SCIM 2.0 provider capability document", "description": "Advertises only what is implemented: no bulk, no sorting, no changePassword. A capability advertised here that the server does not honour is a contract break, not a nicety.", "responses": { "200": { "description": "ServiceProviderConfig" }, "401": { "description": "Missing or invalid tenant SCIM credential" } } } },
            "/scim/v2/ResourceTypes": { "get": { "summary": "SCIM resource types", "responses": { "200": { "description": "ListResponse of ResourceType" }, "401": { "description": "Missing or invalid tenant SCIM credential" } } } },
            "/scim/v2/Schemas": { "get": { "summary": "SCIM schemas", "responses": { "200": { "description": "ListResponse of Schema" }, "401": { "description": "Missing or invalid tenant SCIM credential" } } } },
            "/scim/v2/Users": { "get": { "summary": "List provisioned users for the credential's tenant", "description": "Hard-scoped to the tenant that owns the SCIM credential; a filter or explicit id cannot reach another tenant. Supports startIndex/count paging and the advertised filter subset only.", "responses": { "200": { "description": "ListResponse of User" }, "400": { "description": "Unsupported filter or paging parameter" }, "401": { "description": "Missing or invalid tenant SCIM credential" } } }, "post": { "summary": "Provision a user", "description": "Always creates a new principal; never adopts an existing one by email, which would be a cross-tenant takeover.", "responses": { "201": { "description": "Created User" }, "400": { "description": "Malformed or unknown attribute" }, "409": { "description": "userName already provisioned in this tenant" } } } },
            "/scim/v2/Users/{scimUserId}": { "get": { "summary": "Read one provisioned user", "responses": { "200": { "description": "User" }, "404": { "description": "Absent, or owned by another tenant" } } }, "put": { "summary": "Replace a provisioned user", "responses": { "200": { "description": "Replaced User" }, "412": { "description": "If-Match did not equal the current meta.version" } } }, "patch": { "summary": "Apply RFC 7644 PatchOp operations", "responses": { "200": { "description": "Patched User" }, "400": { "description": "Unsupported operation or value path" }, "412": { "description": "If-Match did not equal the current meta.version" } } }, "delete": { "summary": "Deactivate a provisioned user", "description": "Sets the principal status; an auth principal is never hard-deleted. Session termination remains the global revocation control plane's authority, so an access token can outlive this call by up to its TTL.", "responses": { "204": { "description": "Deactivated" }, "412": { "description": "If-Match did not equal the current meta.version" } } } },
            "/scim/v2/Groups": { "get": { "summary": "List provisioned groups for the credential's tenant", "responses": { "200": { "description": "ListResponse of Group" }, "401": { "description": "Missing or invalid tenant SCIM credential" } } }, "post": { "summary": "Provision a group", "description": "A group binds to one identity-plane role, fixed at creation. A SCIM credential can never bind a group to an administrative role — that is the escalation path every SCIM integration invites.", "responses": { "201": { "description": "Created Group" }, "403": { "description": "Requested role is outside the provisioning credential's authority" } } } },
            "/scim/v2/Groups/{scimGroupId}": { "get": { "summary": "Read one provisioned group", "responses": { "200": { "description": "Group" }, "404": { "description": "Absent, or owned by another tenant" } } }, "put": { "summary": "Replace a provisioned group", "responses": { "200": { "description": "Replaced Group" }, "400": { "description": "roleName is immutable after creation" } } }, "patch": { "summary": "Apply RFC 7644 PatchOp operations to membership", "responses": { "200": { "description": "Patched Group" }, "412": { "description": "If-Match did not equal the current meta.version" } } }, "delete": { "summary": "Remove a provisioned group and its role assignments", "responses": { "204": { "description": "Removed" } } } },
            "/auth/saml/{registration}/metadata": { "get": { "summary": "SP metadata for one SAML registration", "description": "Declares WantAssertionsSigned. No SingleLogoutService is advertised because SLO is not implemented.", "responses": { "200": { "description": "EntityDescriptor XML" }, "404": { "description": "Unknown or disabled registration" } } } },
            "/auth/saml/{registration}/login": { "get": { "summary": "Begin SP-initiated SAML login", "description": "Issues a DEFLATE+base64 AuthnRequest over the HTTP-Redirect binding. RelayState is an opaque handle to a single-use server-side record; its contents are never used as a redirect target.", "responses": { "302": { "description": "Redirect to the IdP SSO endpoint" }, "404": { "description": "Unknown or disabled registration" } } } },
            "/auth/saml/{registration}/acs": { "post": { "summary": "Consume a SAML assertion over the HTTP-POST binding", "description": "Every response must match an outstanding request record, so IdP-initiated login is refused as a class. Signature, XSW, audience, condition-window, and replay checks all run before any session exists. Returns the same JSON shape as /auth/exchange and sets no cookie.", "responses": { "200": { "description": "Shared-auth token pair and the resolved return URL" }, "401": { "description": "Uniform assertion rejection" }, "404": { "description": "Unknown or disabled registration" } } } },
            "/healthz": { "get": { "summary": "Liveness", "responses": { "200": { "description": "Alive" } } } },
            "/readyz": { "get": { "summary": "Postgres-aware readiness", "responses": { "200": { "description": "Ready" }, "503": { "description": "Not ready" } } } }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn router_paths(source: &str) -> BTreeSet<String> {
        source
            .split(".route")
            .skip(1)
            .filter_map(|tail| {
                let arguments = &tail[tail.find('(')? + 1..];
                let quoted = &arguments[arguments.find('"')? + 1..];
                let end = quoted.find('"')?;
                let path = &quoted[..end];
                path.starts_with('/').then(|| path.to_owned())
            })
            .collect()
    }

    #[test]
    fn openapi_has_stable_auth_and_recovery_paths() {
        let value = document();
        assert_eq!(value["openapi"], "3.1.0");
        for path in [
            "/auth/login",
            "/auth/passwordless/request",
            "/auth/passwordless/consume",
            "/auth/browser/consume",
            "/auth/browser/otp",
            "/auth/browser/session",
            "/hooks/supabase/send-email",
            "/auth/mfa/sms/request",
            "/auth/mfa/sms/verify",
            "/auth/capabilities",
            "/auth/risk/evaluate",
            "/auth/qr/login/start",
            "/auth/idv/sessions",
            "/auth/factors",
            "/auth/exchange",
            "/auth/delegate",
            "/auth/ssh/keys",
            "/auth/ssh/challenge",
            "/auth/ssh/verify",
            "/auth/refresh",
            "/auth/introspect",
            "/auth/capabilities",
            "/auth/admin/revocation-token-exchange",
            "/admin/v1/session-revocations/search",
            "/admin/v1/session-revocations/selections",
            "/admin/v1/session-revocations/previews",
            "/admin/v1/session-revocations/previews/{previewId}",
            "/admin/v1/session-revocations/previews/{previewId}/commit-authorizations",
            "/admin/v1/session-revocations/operations",
            "/admin/v1/session-revocations/operations/{operationId}",
            "/.well-known/jwks.json",
        ] {
            assert!(value["paths"].get(path).is_some(), "missing {path}");
        }
    }

    /// Every public route must appear in the OpenAPI document.
    ///
    /// Client SDKs are written against this contract, and they had drifted
    /// badly: eleven documented endpoints did not exist on the server, while
    /// the whole passwordless/SMS-MFA surface that does exist had no client
    /// coverage at all. Nothing detected it because no test compared the two.
    /// This reads the router source so a new `.route(...)` cannot ship
    /// undocumented.
    #[test]
    fn openapi_documents_every_public_route() {
        // Operational and browser-facing surfaces are deliberately excluded:
        // they are not part of the SDK contract.
        const NOT_PUBLIC_API: [&str; 12] = [
            "/",
            "/ui",
            "/ui/exchange",
            "/auth/browser/sign-in",
            "/docs/api",
            "/api/docs",
            "/metrics",
            "/internal/webhook/sync",
            "/internal/recovery/ceremonies/{ceremonyId}/review",
            "/api/docs.json",
            // Compiled only into an explicit integration-test binary. It is
            // documented in the operator test runbook, never the public SDK.
            "/auth/test/supabase/session",
            "/auth/test/supabase/sms-hook",
        ];

        let served = router_paths(include_str!("mod.rs"));
        let documented = document();
        let undocumented: Vec<_> = served
            .into_iter()
            .filter(|path| !NOT_PUBLIC_API.contains(&path.as_str()))
            .filter(|path| documented["paths"].get(path).is_none())
            .collect();

        assert!(
            undocumented.is_empty(),
            "routes missing from the OpenAPI contract: {undocumented:?}"
        );
    }

    /// The inverse: the document must not promise routes that do not exist.
    #[test]
    fn openapi_documents_no_route_the_router_lacks() {
        let served = router_paths(include_str!("mod.rs"));
        let documented = document();
        let paths = documented["paths"].as_object().expect("paths object");

        let phantom = paths
            .keys()
            .filter(|path| path.as_str() != "/api/docs.json")
            .filter(|path| !served.contains(path.as_str()))
            .cloned()
            .collect::<Vec<_>>();

        assert!(
            phantom.is_empty(),
            "OpenAPI promises routes the server does not serve: {phantom:?}"
        );
    }
}
