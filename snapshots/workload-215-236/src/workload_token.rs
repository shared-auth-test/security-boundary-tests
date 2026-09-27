//! Pure claim-profile construction and revocation verification for first-class
//! workload OAuth tokens.
//!
//! This module does **not** sign JWTs. Signing remains owned by the existing
//! [`crate::token::TokenMinter`] so Shared Auth never grows a second signing
//! authority. The purpose here is to make the machine-identity claim semantics
//! and DB-backed revocation contract independently testable before
//! `client_credentials` is advertised.

use uuid::Uuid;

use crate::error::AuthError;
use crate::token::OreClaims;
use crate::workload::store::WorkloadStore;
use crate::workload::{
    WorkloadClientBinding, WorkloadPrincipal, WorkloadSessionSnapshot,
    OAUTH_CLIENT_CREDENTIAL_CLASS,
};

pub const WORKLOAD_PROVIDER: &str = "shared_auth_workload";
pub const WORKLOAD_AMR: &str = "client_credentials";
pub const WORKLOAD_SUBJECT_PREFIX: &str = "workload:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadTokenProfileError {
    EmptyIssuer,
    EmptyJti,
    InactiveLineage,
    ScopeMismatch,
    InvalidExpiry,
}

pub struct WorkloadTokenContext<'a> {
    pub principal: &'a WorkloadPrincipal,
    pub binding: &'a WorkloadClientBinding,
    pub session: &'a WorkloadSessionSnapshot,
    pub oauth_client_allowed_scopes: &'a [String],
    pub issuer: &'a str,
    pub issued_at_unix: u64,
    pub jti: &'a str,
}

/// Build the exact unsigned claim profile for a first-class service-account
/// access token.
///
/// Human identity/assurance fields are intentionally empty. `aal=0` is not a
/// third human assurance level; it is the explicit absence of a human ceremony.
/// Consumers that require human authentication must therefore fail closed even
/// before checking `cred`/provider/subject class.
pub fn build_workload_claims(
    context: WorkloadTokenContext<'_>,
) -> Result<OreClaims, WorkloadTokenProfileError> {
    if context.issuer.trim().is_empty() {
        return Err(WorkloadTokenProfileError::EmptyIssuer);
    }

    if context.jti.trim().is_empty() {
        return Err(WorkloadTokenProfileError::EmptyJti);
    }

    if context.session.expires_at_unix <= context.issued_at_unix {
        return Err(WorkloadTokenProfileError::InvalidExpiry);
    }

    if !context.session.is_active_for(
        context.principal,
        context.binding,
        context.issued_at_unix,
    ) {
        return Err(WorkloadTokenProfileError::InactiveLineage);
    }

    let effective_scope = context
        .binding
        .effective_scope(
            &context.session.scopes,
            context.oauth_client_allowed_scopes,
        )
        .map_err(|_| WorkloadTokenProfileError::ScopeMismatch)?;

    let mut session_scope = context.session.scopes.clone();
    session_scope.sort_unstable();
    if effective_scope != session_scope {
        return Err(WorkloadTokenProfileError::ScopeMismatch);
    }

    return Ok(OreClaims {
        sub: format!(
            "{WORKLOAD_SUBJECT_PREFIX}{}",
            context.principal.service_account_id
        ),
        iss: context.issuer.to_string(),
        aud: context.binding.audience.clone(),
        iat: context.issued_at_unix,
        exp: context.session.expires_at_unix,
        nbf: context.issued_at_unix.saturating_sub(5),
        jti: context.jti.to_string(),
        sid: Some(context.session.session_id.to_string()),
        provider: WORKLOAD_PROVIDER.to_string(),
        provider_tenant: context.principal.application_id.to_string(),
        provider_subject: context.principal.service_account_id.to_string(),
        project: None,
        supabase_user_id: None,
        email: None,
        email_verified: false,
        roles: Vec::new(),
        aal: 0,
        amr: vec![WORKLOAD_AMR.to_string()],
        acr: None,
        auth_time: None,
        webauthn_auth_time: None,
        auth_epoch: context.principal.auth_epoch,
        scope: effective_scope.join(" "),
        azp: Some(context.binding.client_id.clone()),
        parent_jti: None,
        cred: Some(OAUTH_CLIENT_CREDENTIAL_CLASS.to_string()),
    });
}

/// Compare signed workload claims with the DB-owned issuance lineage. This is
/// deliberately stricter than checking only `sid`: every identity/routing field
/// must agree so a valid token cannot be replayed across clients, applications,
/// audiences, service accounts, scopes, or expiries.
pub fn workload_claims_match_session(
    claims: &OreClaims,
    session: &WorkloadSessionSnapshot,
) -> bool {
    if !claims.is_workload() {
        return false;
    }

    if claims.sub != format!("{WORKLOAD_SUBJECT_PREFIX}{}", session.service_account_id) {
        return false;
    }

    if claims.provider_tenant != session.application_id.to_string()
        || claims.provider_subject != session.service_account_id.to_string()
    {
        return false;
    }

    let session_id = session.session_id.to_string();
    if claims.sid.as_deref() != Some(session_id.as_str()) {
        return false;
    }

    if claims.azp.as_deref() != Some(session.client_id.as_str())
        || claims.aud != session.audience
        || claims.auth_epoch != session.service_account_auth_epoch
        || claims.exp != session.expires_at_unix
    {
        return false;
    }

    if claims.amr.len() != 1
        || claims.amr.first().map(String::as_str) != Some(WORKLOAD_AMR)
        || claims.parent_jti.is_some()
        || claims.cred.as_deref() != Some(OAUTH_CLIENT_CREDENTIAL_CLASS)
    {
        return false;
    }

    let mut token_scopes: Vec<&str> = claims.scope.split_ascii_whitespace().collect();
    if token_scopes.is_empty() {
        return false;
    }
    let token_scope_count = token_scopes.len();
    token_scopes.sort_unstable();
    token_scopes.dedup();
    if token_scopes.len() != token_scope_count {
        return false;
    }

    let mut session_scopes: Vec<&str> = session.scopes.iter().map(String::as_str).collect();
    if session_scopes.is_empty() {
        return false;
    }
    let session_scope_count = session_scopes.len();
    session_scopes.sort_unstable();
    session_scopes.dedup();
    if session_scopes.len() != session_scope_count {
        return false;
    }

    return token_scopes == session_scopes;
}

/// Fail closed against the current workload identity/session state.
///
/// `WorkloadStore::active_session` checks service-account status/epoch,
/// client-binding status/credential epoch, OAuth client/application status,
/// audience, expiry and explicit revocation. This function then proves the
/// signed claims describe that exact issuance lineage.
pub async fn enforce_workload_session_revocation(
    store: &WorkloadStore,
    claims: &OreClaims,
) -> Result<(), AuthError> {
    if !claims.is_workload() {
        return Err(AuthError::Unauthorized);
    }

    let session_id = claims
        .sid
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(AuthError::Unauthorized)?;
    let client_id = claims.azp.as_deref().ok_or(AuthError::Unauthorized)?;

    let session = store
        .active_session(session_id, client_id)
        .await?
        .ok_or(AuthError::Unauthorized)?;
    if !workload_claims_match_session(claims, &session) {
        return Err(AuthError::Unauthorized);
    }

    return Ok(());
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::workload::WorkloadStatus;

    use super::*;

    fn principal() -> WorkloadPrincipal {
        return WorkloadPrincipal {
            service_account_id: Uuid::from_u128(10),
            application_id: Uuid::from_u128(20),
            status: WorkloadStatus::Active,
            auth_epoch: 7,
        };
    }

    fn binding() -> WorkloadClientBinding {
        return WorkloadClientBinding {
            client_id: "svc-build".to_string(),
            service_account_id: Uuid::from_u128(10),
            application_id: Uuid::from_u128(20),
            audience: "build-api".to_string(),
            status: WorkloadStatus::Active,
            credential_epoch: 3,
            allowed_scopes: vec!["build:read".to_string(), "build:write".to_string()],
            default_scopes: vec!["build:read".to_string()],
        };
    }

    fn session() -> WorkloadSessionSnapshot {
        return WorkloadSessionSnapshot {
            session_id: Uuid::from_u128(30),
            service_account_id: Uuid::from_u128(10),
            client_id: "svc-build".to_string(),
            application_id: Uuid::from_u128(20),
            service_account_auth_epoch: 7,
            credential_epoch: 3,
            audience: "build-api".to_string(),
            scopes: vec!["build:write".to_string(), "build:read".to_string()],
            expires_at_unix: 2_000,
            revoked: false,
        };
    }

    fn oauth_allowed() -> Vec<String> {
        return vec!["build:read".to_string(), "build:write".to_string()];
    }

    fn claims() -> OreClaims {
        let principal = principal();
        let binding = binding();
        let session = session();
        let oauth_allowed = oauth_allowed();
        return build_workload_claims(WorkloadTokenContext {
            principal: &principal,
            binding: &binding,
            session: &session,
            oauth_client_allowed_scopes: &oauth_allowed,
            issuer: "https://auth.example.test",
            issued_at_unix: 1_000,
            jti: "00000000-0000-0000-0000-000000000040",
        })
        .unwrap();
    }

    #[test]
    fn workload_profile_contains_no_human_identity_or_assurance() {
        let principal = principal();
        let binding = binding();
        let session = session();
        let claims = claims();

        assert_eq!(claims.sub, format!("workload:{}", principal.service_account_id));
        assert_eq!(claims.provider, WORKLOAD_PROVIDER);
        assert_eq!(claims.provider_tenant, principal.application_id.to_string());
        assert_eq!(claims.provider_subject, principal.service_account_id.to_string());
        assert_eq!(claims.aud, binding.audience);
        assert_eq!(claims.sid, Some(session.session_id.to_string()));
        assert_eq!(claims.auth_epoch, principal.auth_epoch);
        assert_eq!(claims.azp.as_deref(), Some(binding.client_id.as_str()));
        assert_eq!(claims.cred.as_deref(), Some(OAUTH_CLIENT_CREDENTIAL_CLASS));
        assert_eq!(claims.aal, 0);
        assert_eq!(claims.amr, vec![WORKLOAD_AMR.to_string()]);
        assert!(claims.acr.is_none());
        assert!(claims.auth_time.is_none());
        assert!(claims.webauthn_auth_time.is_none());
        assert!(claims.email.is_none());
        assert!(!claims.email_verified);
        assert!(claims.roles.is_empty());
        assert!(claims.parent_jti.is_none());
        assert!(claims.is_workload());
        assert!(claims.is_sandboxed());
        assert!(workload_claims_match_session(&claims, &session));
    }

    #[test]
    fn workload_profile_scope_is_deterministic_and_bounded_by_both_allowlists() {
        let principal = principal();
        let binding = binding();
        let session = session();
        let oauth_allowed = oauth_allowed();
        let claims = build_workload_claims(WorkloadTokenContext {
            principal: &principal,
            binding: &binding,
            session: &session,
            oauth_client_allowed_scopes: &oauth_allowed,
            issuer: "https://auth.example.test",
            issued_at_unix: 1_000,
            jti: "00000000-0000-0000-0000-000000000041",
        })
        .unwrap();

        assert_eq!(claims.scope, "build:read build:write");

        let too_narrow = vec!["build:read".to_string()];
        assert!(matches!(
            build_workload_claims(WorkloadTokenContext {
                principal: &principal,
                binding: &binding,
                session: &session,
                oauth_client_allowed_scopes: &too_narrow,
                issuer: "https://auth.example.test",
                issued_at_unix: 1_000,
                jti: "00000000-0000-0000-0000-000000000042",
            }),
            Err(WorkloadTokenProfileError::ScopeMismatch)
        ));
    }

    #[test]
    fn expired_or_cross_application_lineage_cannot_build_claims() {
        let principal = principal();
        let mut binding = binding();
        let session = session();
        let oauth_allowed = oauth_allowed();

        assert!(matches!(
            build_workload_claims(WorkloadTokenContext {
                principal: &principal,
                binding: &binding,
                session: &session,
                oauth_client_allowed_scopes: &oauth_allowed,
                issuer: "https://auth.example.test",
                issued_at_unix: 2_000,
                jti: "00000000-0000-0000-0000-000000000043",
            }),
            Err(WorkloadTokenProfileError::InvalidExpiry)
        ));

        binding.application_id = Uuid::from_u128(99);
        assert!(matches!(
            build_workload_claims(WorkloadTokenContext {
                principal: &principal,
                binding: &binding,
                session: &session,
                oauth_client_allowed_scopes: &oauth_allowed,
                issuer: "https://auth.example.test",
                issued_at_unix: 1_000,
                jti: "00000000-0000-0000-0000-000000000044",
            }),
            Err(WorkloadTokenProfileError::InactiveLineage)
        ));
    }

    #[test]
    fn workload_claim_matching_rejects_cross_client_application_human_and_expiry_mutation() {
        let session = session();
        let original = claims();
        assert!(workload_claims_match_session(&original, &session));

        let mut wrong_client = original.clone();
        wrong_client.azp = Some("svc-other".to_string());
        assert!(!workload_claims_match_session(&wrong_client, &session));

        let mut wrong_application = original.clone();
        wrong_application.provider_tenant = Uuid::from_u128(99).to_string();
        assert!(!workload_claims_match_session(&wrong_application, &session));

        let mut human_role = original.clone();
        human_role.roles.push("admin".to_string());
        assert!(!workload_claims_match_session(&human_role, &session));

        let mut human_aal = original.clone();
        human_aal.aal = 1;
        assert!(!workload_claims_match_session(&human_aal, &session));

        let mut wrong_scope = original.clone();
        wrong_scope.scope = "build:read".to_string();
        assert!(!workload_claims_match_session(&wrong_scope, &session));

        let mut duplicate_scope = original.clone();
        duplicate_scope.scope = "build:read build:read build:write".to_string();
        assert!(!workload_claims_match_session(&duplicate_scope, &session));

        let mut extended_expiry = original.clone();
        extended_expiry.exp += 1;
        assert!(!workload_claims_match_session(&extended_expiry, &session));
    }
}
