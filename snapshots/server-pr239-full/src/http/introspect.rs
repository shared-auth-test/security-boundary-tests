//! Access-token introspection and gateway verification.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Once;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, FixedOffset, Utc};
use hmac::{Hmac, KeyInit, Mac};
use rand::{rngs::SysRng, TryRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use uuid::Uuid;

use crate::directory_grants::{
    DirectoryAdminGrant, DIRECTORY_ADMIN_AUDIENCE, DIRECTORY_ADMIN_CLIENT_ID,
    DIRECTORY_ADMIN_DELEGATED_SCOPE, DIRECTORY_GRANT_SCHEMA,
};
use crate::error::AuthError;
use crate::state::AppState;
use crate::token::{OreClaims, ACR_LOA2};
use crate::workload::store::WorkloadStore;
use crate::workload_token::enforce_workload_session_revocation;

use super::bearer;

#[derive(Deserialize)]
enum IntrospectionRequestContract {
    #[serde(rename = "IntrospectionRequest")]
    IntrospectionRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntrospectionRequestEnvelope {
    contract: IntrospectionRequestContract,
    payload: IntrospectionRequestPayload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntrospectionRequestPayload {
    token: String,
    /// Exact expected audience for a delegated product token.
    audience: String,
    required_scopes: Vec<String>,
}

impl fmt::Debug for IntrospectionRequestPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntrospectionRequestPayload")
            .field("token", &"[REDACTED]")
            .field("audience", &self.audience)
            .field("required_scopes", &self.required_scopes)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryAdminGrantSetPayload {
    schema: &'static str,
    principal_id: Uuid,
    audience: &'static str,
    assurance: &'static str,
    directory_grants: Vec<DirectoryAdminGrant>,
    evaluated_at: DateTime<FixedOffset>,
    /// Exact expiry of the already-verified delegated token/session contract;
    /// this is independent from each authorization grant's optional expiry.
    expires_at: DateTime<FixedOffset>,
    exact_organization_match_required: bool,
    cross_organization_fallback_allowed: bool,
    raw_emails_present: bool,
}

#[derive(Serialize)]
struct DirectoryAdminIntrospectionEnvelope {
    contract: &'static str,
    payload: DirectoryAdminGrantSetPayload,
}

/// Enforce caller authentication before introspection reveals full token claims.
///
/// Introspection is disabled unless `AUTH_INTROSPECT_SECRET` is configured. This
/// is intentionally fail-closed: possessing an end-user token must not also grant
/// permission to recover its complete identity, provider, role, session, email,
/// and assurance claim set. Authorized service callers present the independent
/// credential as `Authorization: Bearer <secret>`.
fn authorize_caller(state: &AppState, headers: &HeaderMap) -> Result<(), AuthError> {
    let Some(expected) = state.config.introspect_secret.as_deref() else {
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!("/auth/introspect is disabled because AUTH_INTROSPECT_SECRET is unset");
        });
        return Err(AuthError::Unauthorized);
    };
    authorize_service_credential(Some(expected), bearer(headers))
}

pub(crate) fn authorize_service_credential(
    expected: Option<&str>,
    presented: Option<&str>,
) -> Result<(), AuthError> {
    let expected = expected.ok_or(AuthError::Unauthorized)?;
    let presented = presented.ok_or(AuthError::Unauthorized)?;
    if credentials_match(expected, presented) {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

/// Constant-time credential comparison via double-HMAC under a per-call random
/// key, so the final byte comparison leaks nothing about the secret in timing.
/// Reuses the `hmac`/`sha2`/`rand` deps already used by the webhook signer.
fn credentials_match(expected: &str, presented: &str) -> bool {
    let mut key = [0u8; 32];
    if SysRng.try_fill_bytes(&mut key).is_err() {
        return false;
    }
    let tag = |data: &[u8]| {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes()
    };
    tag(expected.as_bytes()) == tag(presented.as_bytes())
}

pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Authenticate the service before parsing caller-controlled JSON. This
    // keeps the endpoint undiscoverable to an unauthorized caller even when
    // that caller submits a malformed or obsolete request shape.
    if let Err(error) = authorize_caller(&state, &headers) {
        return error.into_response();
    }
    let request: IntrospectionRequestEnvelope = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return AuthError::BadRequest("invalid introspection request").into_response(),
    };
    let IntrospectionRequestEnvelope {
        contract: IntrospectionRequestContract::IntrospectionRequest,
        payload: request,
    } = request;
    let expected_audience = request.audience.as_str();
    let request_valid = request.token.len() <= 16 * 1024
        && valid_audience(expected_audience)
        && valid_required_scopes(&request.required_scopes)
        && (expected_audience != DIRECTORY_ADMIN_AUDIENCE
            || request.required_scopes.as_slice() == [DIRECTORY_ADMIN_DELEGATED_SCOPE]);
    let verified = if request_valid {
        active_claims_for_audience(&state, &request.token, expected_audience)
            .await
            .and_then(|claims| {
                claims_have_required_scopes(&claims, &request.required_scopes)
                    .then_some(claims)
                    .ok_or(AuthError::Unauthorized)
            })
    } else {
        Err(AuthError::Unauthorized)
    };
    let response = match verified {
        Ok(claims) if expected_audience == DIRECTORY_ADMIN_AUDIENCE => {
            match directory_admin_introspection(&state, &claims).await {
                Ok(response) => serde_json::to_value(response).ok(),
                Err(_) => None,
            }
        }
        Ok(claims) => Some(json!({
            "active": true,
            "sub": claims.sub,
            "iss": claims.iss,
            "aud": claims.aud,
            "exp": claims.exp,
            "iat": claims.iat,
            "nbf": claims.nbf,
            "jti": claims.jti,
            "auth_time": claims.auth_time,
            "webauthn_auth_time": claims.webauthn_auth_time,
            "auth_epoch": claims.auth_epoch,
            "sid": claims.sid,
            "provider": claims.provider,
            "provider_tenant": claims.provider_tenant,
            "provider_subject": claims.provider_subject,
            "project": claims.project,
            "supabase_user_id": claims.supabase_user_id,
            "email": claims.email,
            "email_verified": claims.email_verified,
            "roles": claims.roles,
            "aal": claims.aal,
            "amr": claims.amr,
            "acr": claims.acr,
            "scope": claims.scope,
            "azp": claims.azp,
            "parent_jti": claims.parent_jti,
            // Credential class for sandboxed machine-credential tokens. A
            // remote-introspection consumer enforces the sandbox rule from this
            // field; omitting it here would make the restriction invisible to
            // exactly the services that outsource verification to us.
            "cred": claims.cred,
        })),
        Err(_) => None,
    };
    state
        .metrics
        .introspections
        .with_label_values(&[if response.is_some() {
            "active"
        } else {
            "inactive"
        }])
        .inc();
    Json(response.unwrap_or_else(|| json!({ "active": false }))).into_response()
}

async fn directory_admin_introspection(
    state: &AppState,
    claims: &OreClaims,
) -> Result<DirectoryAdminIntrospectionEnvelope, AuthError> {
    if !valid_directory_admin_claims(claims) {
        return Err(AuthError::Forbidden);
    }
    let shared_user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::Unauthorized)?;
    let session_id = claims
        .sid
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(AuthError::Unauthorized)?;
    let evaluated_at = Utc::now().fixed_offset();
    let expires_at = DateTime::<Utc>::from_timestamp(
        i64::try_from(claims.exp).map_err(|_| AuthError::Unauthorized)?,
        0,
    )
    .ok_or(AuthError::Unauthorized)?
    .fixed_offset();
    if expires_at <= evaluated_at {
        return Err(AuthError::Unauthorized);
    }
    let db = state.db.as_ref().ok_or(AuthError::Unavailable)?;
    let grants = db
        .directory_admin_grants_for_session(shared_user_id, session_id, claims.auth_epoch)
        .await?
        .ok_or(AuthError::Forbidden)?;
    if !grants.validate(evaluated_at) {
        return Err(AuthError::Forbidden);
    }
    Ok(DirectoryAdminIntrospectionEnvelope {
        contract: "DirectoryAdminGrantSet",
        payload: DirectoryAdminGrantSetPayload {
            schema: DIRECTORY_GRANT_SCHEMA,
            principal_id: grants.principal_ref,
            audience: DIRECTORY_ADMIN_AUDIENCE,
            assurance: if claims.aal >= 3 { "aal3" } else { "aal2" },
            directory_grants: grants.grants,
            evaluated_at,
            expires_at,
            exact_organization_match_required: true,
            cross_organization_fallback_allowed: false,
            raw_emails_present: false,
        },
    })
}

pub(crate) fn valid_directory_admin_claims(claims: &OreClaims) -> bool {
    let mut scopes = claims.scope.split_ascii_whitespace();
    let exact_scope =
        scopes.next() == Some(DIRECTORY_ADMIN_DELEGATED_SCOPE) && scopes.next().is_none();
    claims.aud == DIRECTORY_ADMIN_AUDIENCE
        && claims.azp.as_deref() == Some(DIRECTORY_ADMIN_CLIENT_ID)
        && claims.is_delegated()
        && exact_scope
        && claims.aal >= 2
        && claims.has_acr(ACR_LOA2)
        && claims.auth_time.is_some()
}

pub async fn verify(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(token) = bearer(&headers) else {
        return AuthError::Unauthorized.into_response();
    };
    match active_claims(&state, token).await {
        Ok(claims) => {
            let mut output = HeaderMap::new();
            insert_header(&mut output, "x-auth-user-id", &claims.sub);
            insert_header(&mut output, "x-auth-provider", &claims.provider);
            insert_header(
                &mut output,
                "x-auth-provider-tenant",
                &claims.provider_tenant,
            );
            insert_header(&mut output, "x-auth-roles", &claims.roles.join(","));
            insert_header(&mut output, "x-auth-aal", &claims.aal.to_string());
            if let Some(auth_time) = claims.auth_time {
                insert_header(&mut output, "x-auth-time", &auth_time.to_string());
            }
            if !claims.amr.is_empty() {
                insert_header(&mut output, "x-auth-amr", &claims.amr.join(","));
            }
            if let Some(acr) = &claims.acr {
                insert_header(&mut output, "x-auth-acr", acr);
            }
            if let Some(project) = &claims.project {
                insert_header(&mut output, "x-auth-project", project);
            }
            if let Some(email) = &claims.email {
                insert_header(&mut output, "x-auth-email", email);
            }
            if !claims.scope.is_empty() {
                insert_header(&mut output, "x-auth-scope", &claims.scope);
            }
            if let Some(authorized_party) = &claims.azp {
                insert_header(&mut output, "x-auth-azp", authorized_party);
            }
            // Present exactly when the token is on the sandboxed plane, so a
            // gateway can refuse control-plane routes with a header match
            // instead of decoding the token a second time.
            if let Some(credential_class) = &claims.cred {
                insert_header(&mut output, "x-auth-cred", credential_class);
            }
            (StatusCode::OK, output).into_response()
        }
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn active_claims(state: &AppState, token: &str) -> Result<OreClaims, AuthError> {
    active_claims_for_audience(state, token, state.config.signing.audience.as_str()).await
}

pub(crate) async fn active_claims_for_audience(
    state: &AppState,
    token: &str,
    expected_audience: &str,
) -> Result<OreClaims, AuthError> {
    let claims = state.minter.verify_for_audience(token, expected_audience)?;
    enforce_session_revocation(state, &claims).await?;
    Ok(claims)
}

async fn enforce_session_revocation(state: &AppState, claims: &OreClaims) -> Result<(), AuthError> {
    if claims.is_workload() {
        let db = state.db.as_ref().ok_or(AuthError::Unauthorized)?;
        let store = WorkloadStore::new(db);
        return enforce_workload_session_revocation(&store, claims).await;
    }

    match (&state.db, claims.sid.as_deref()) {
        (Some(db), Some(raw_session_id)) => {
            let session_id =
                Uuid::parse_str(raw_session_id).map_err(|_| AuthError::Unauthorized)?;
            if let Some(cache) = &state.cache {
                match cache.is_revoked(session_id).await {
                    Ok(true) => return Err(AuthError::Unauthorized),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, %session_id, "Redis revocation check failed")
                    }
                }
            }
            if !db
                .session_is_active_at_epoch(session_id, claims.auth_epoch)
                .await?
            {
                return Err(AuthError::Unauthorized);
            }
        }
        // A production token without a session id bypasses revocation, so reject
        // it whenever the authoritative session store is configured.
        (Some(_), None) => return Err(AuthError::Unauthorized),
        (None, _) => {}
    }
    Ok(())
}

fn valid_audience(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_required_scopes(scopes: &[String]) -> bool {
    if scopes.len() > 64 {
        return false;
    }
    let unique = scopes.iter().collect::<BTreeSet<_>>();
    unique.len() == scopes.len()
        && scopes.iter().all(|scope| {
            !scope.is_empty()
                && scope.len() <= 128
                && scope.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
                })
        })
}

fn claims_have_required_scopes(claims: &OreClaims, required: &[String]) -> bool {
    let present = claims
        .scope
        .split_ascii_whitespace()
        .collect::<BTreeSet<_>>();
    required
        .iter()
        .all(|scope| present.contains(scope.as_str()))
}

fn insert_header(map: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = axum::http::HeaderValue::from_str(value) {
        map.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        authorize_service_credential, valid_directory_admin_claims, DirectoryAdminGrantSetPayload,
        DirectoryAdminIntrospectionEnvelope, IntrospectionRequestPayload,
    };
    use crate::directory_grants::{
        DirectoryAdminGrant, DIRECTORY_ADMIN_AUDIENCE, DIRECTORY_ADMIN_CLIENT_ID,
        DIRECTORY_ADMIN_DELEGATED_SCOPE, DIRECTORY_GRANT_SCHEMA,
    };
    use crate::token::{OreClaims, ACR_LOA2};
    use uuid::Uuid;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn introspection_fails_closed_without_a_configured_service_secret() {
        assert!(authorize_service_credential(None, None).is_err());
        assert!(authorize_service_credential(None, Some(SECRET)).is_err());
    }

    #[test]
    fn introspection_rejects_missing_or_incorrect_service_credentials() {
        assert!(authorize_service_credential(Some(SECRET), None).is_err());
        assert!(authorize_service_credential(
            Some(SECRET),
            Some("fedcba9876543210fedcba9876543210")
        )
        .is_err());
    }

    #[test]
    fn introspection_accepts_only_the_independent_service_credential() {
        assert!(authorize_service_credential(Some(SECRET), Some(SECRET)).is_ok());
    }

    #[test]
    fn introspection_payload_debug_never_exposes_the_bearer_token() {
        let token = "introspection-token-must-never-appear";
        let payload = IntrospectionRequestPayload {
            token: token.into(),
            audience: "shared-auth-web-server".into(),
            required_scopes: vec!["shared-auth:directory:read".into()],
        };
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains(token));
        assert!(rendered.contains("[REDACTED]"));
    }

    fn directory_claims() -> OreClaims {
        OreClaims {
            sub: Uuid::new_v4().to_string(),
            iss: "https://admin.auth.example".into(),
            aud: DIRECTORY_ADMIN_AUDIENCE.into(),
            iat: 1_000,
            exp: 2_000,
            nbf: 999,
            jti: Uuid::new_v4().to_string(),
            sid: Some(Uuid::new_v4().to_string()),
            provider: "local".into(),
            provider_tenant: "admin".into(),
            provider_subject: "opaque".into(),
            project: None,
            supabase_user_id: None,
            email: None,
            email_verified: true,
            roles: Vec::new(),
            aal: 2,
            amr: vec!["passkey".into()],
            acr: Some(ACR_LOA2.into()),
            auth_time: Some(1_000),
            webauthn_auth_time: Some(1_000),
            auth_epoch: 1,
            scope: DIRECTORY_ADMIN_DELEGATED_SCOPE.into(),
            azp: Some(DIRECTORY_ADMIN_CLIENT_ID.into()),
            parent_jti: Some(Uuid::new_v4().to_string()),
            cred: None,
        }
    }

    #[test]
    fn directory_profile_requires_exact_audience_scope_client_and_aal2() {
        assert!(valid_directory_admin_claims(&directory_claims()));
        let mut extra_scope = directory_claims();
        extra_scope.scope.push_str(" directory.sessions.write");
        assert!(!valid_directory_admin_claims(&extra_scope));
        let mut wrong_client = directory_claims();
        wrong_client.azp = Some("other-client".into());
        assert!(!valid_directory_admin_claims(&wrong_client));
        let mut aal1 = directory_claims();
        aal1.aal = 1;
        assert!(!valid_directory_admin_claims(&aal1));
    }

    #[test]
    fn directory_profile_serializes_only_the_canonical_redacted_envelope() {
        let now = chrono::Utc::now().fixed_offset();
        let envelope = DirectoryAdminIntrospectionEnvelope {
            contract: "DirectoryAdminGrantSet",
            payload: DirectoryAdminGrantSetPayload {
                schema: DIRECTORY_GRANT_SCHEMA,
                principal_id: Uuid::new_v4(),
                audience: DIRECTORY_ADMIN_AUDIENCE,
                assurance: "aal2",
                directory_grants: vec![DirectoryAdminGrant {
                    grant_id: Uuid::new_v4(),
                    organization_id: Uuid::new_v4(),
                    project_ids: None,
                    scopes: vec!["directory.dashboard.read".into()],
                    roles: vec!["directory_admin".into()],
                    granted_at: now,
                    expires_at: None,
                }],
                evaluated_at: now,
                expires_at: now + chrono::TimeDelta::minutes(5),
                exact_organization_match_required: true,
                cross_organization_fallback_allowed: false,
                raw_emails_present: false,
            },
        };
        let value = serde_json::to_value(envelope).unwrap();
        assert_eq!(value["contract"], "DirectoryAdminGrantSet");
        assert_eq!(
            value["payload"]["schema"],
            "ores.shared-auth-admin-directory-grant-set/v1"
        );
        assert!(value.get("active").is_none());
        for forbidden in ["email", "scope", "roles", "organization_ids", "sub"] {
            assert!(value["payload"].get(forbidden).is_none());
        }
    }
}
