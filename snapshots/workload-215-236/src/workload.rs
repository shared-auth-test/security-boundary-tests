//! First-class workload/service-account identity primitives.
//!
//! This module intentionally does not mint OAuth tokens yet. It defines the
//! machine-principal invariants that `client_credentials` must consume so a
//! confidential OAuth client can never be represented as a fake human user or
//! a row in `shared_auth.sessions`.

pub mod store;

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::oauth_as::{
    scope_is_wellformed, MAX_SCOPE_BYTES, MAX_SCOPE_ENTRIES, OFFLINE_ACCESS_SCOPE, PROTOCOL_SCOPE,
};

pub const OAUTH_CLIENT_CREDENTIAL_CLASS: &str = "oauth_client";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadStatus {
    Active,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadPrincipal {
    pub service_account_id: Uuid,
    pub application_id: Uuid,
    pub status: WorkloadStatus,
    pub auth_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadClientBinding {
    pub client_id: String,
    pub service_account_id: Uuid,
    pub application_id: Uuid,
    pub audience: String,
    pub status: WorkloadStatus,
    pub credential_epoch: u64,
    pub allowed_scopes: Vec<String>,
    pub default_scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadSessionSnapshot {
    pub session_id: Uuid,
    pub service_account_id: Uuid,
    pub client_id: String,
    pub application_id: Uuid,
    pub service_account_auth_epoch: u64,
    pub credential_epoch: u64,
    pub audience: String,
    pub scopes: Vec<String>,
    pub expires_at_unix: u64,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadScopeError {
    Empty,
    Malformed,
    Duplicate,
    HumanProtocolScope,
    ExceedsClientRegistration,
    ExceedsWorkloadBinding,
}

impl WorkloadClientBinding {
    /// Resolve a client-credentials scope without any human-consent semantics.
    ///
    /// The effective machine authority is exactly the requested/default set,
    /// provided every scope exists in both the OAuth client's registration and
    /// this workload binding. There is no silent narrowing: a disagreement is a
    /// hard error so callers do not receive a token with surprising authority.
    pub fn effective_scope(
        &self,
        requested: &[String],
        oauth_client_allowed_scopes: &[String],
    ) -> Result<Vec<String>, WorkloadScopeError> {
        let selected = if requested.is_empty() {
            self.default_scopes.as_slice()
        } else {
            requested
        };

        validate_machine_scope_set(selected)?;

        let oauth_allowed: BTreeSet<&str> = oauth_client_allowed_scopes
            .iter()
            .map(String::as_str)
            .collect();
        let workload_allowed: BTreeSet<&str> =
            self.allowed_scopes.iter().map(String::as_str).collect();

        for scope in selected {
            if !oauth_allowed.contains(scope.as_str()) {
                return Err(WorkloadScopeError::ExceedsClientRegistration);
            }

            if !workload_allowed.contains(scope.as_str()) {
                return Err(WorkloadScopeError::ExceedsWorkloadBinding);
            }
        }

        let mut effective = selected.to_vec();
        effective.sort_unstable();
        Ok(effective)
    }
}

impl WorkloadSessionSnapshot {
    /// Decide whether this issuance lineage is still valid against the current
    /// workload principal and client binding.
    ///
    /// Both epochs are equality checks, not `>=` checks. Rotation/disable
    /// advances an epoch and permanently invalidates older sessions, preventing
    /// a later re-enable from resurrecting a cryptographically valid old JWT.
    pub fn is_active_for(
        &self,
        principal: &WorkloadPrincipal,
        binding: &WorkloadClientBinding,
        now_unix: u64,
    ) -> bool {
        if self.revoked {
            return false;
        }

        if now_unix >= self.expires_at_unix {
            return false;
        }

        if principal.status != WorkloadStatus::Active || binding.status != WorkloadStatus::Active {
            return false;
        }

        if self.service_account_id != principal.service_account_id
            || self.service_account_id != binding.service_account_id
        {
            return false;
        }

        if self.application_id != principal.application_id
            || self.application_id != binding.application_id
        {
            return false;
        }

        if self.client_id != binding.client_id || self.audience != binding.audience {
            return false;
        }

        if self.service_account_auth_epoch != principal.auth_epoch {
            return false;
        }

        if self.credential_epoch != binding.credential_epoch {
            return false;
        }

        true
    }
}

pub fn validate_machine_scope_set(scopes: &[String]) -> Result<(), WorkloadScopeError> {
    if scopes.is_empty() || scopes.len() > MAX_SCOPE_ENTRIES {
        return Err(WorkloadScopeError::Empty);
    }

    let encoded_len = scopes
        .iter()
        .map(String::len)
        .sum::<usize>()
        .saturating_add(scopes.len().saturating_sub(1));
    if encoded_len > MAX_SCOPE_BYTES {
        return Err(WorkloadScopeError::Malformed);
    }

    let mut seen = BTreeSet::new();
    for scope in scopes {
        if !scope_is_wellformed(scope) {
            return Err(WorkloadScopeError::Malformed);
        }

        if scope.as_str() == PROTOCOL_SCOPE || scope.as_str() == OFFLINE_ACCESS_SCOPE {
            return Err(WorkloadScopeError::HumanProtocolScope);
        }

        if !seen.insert(scope.as_str()) {
            return Err(WorkloadScopeError::Duplicate);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> WorkloadPrincipal {
        WorkloadPrincipal {
            service_account_id: Uuid::from_u128(10),
            application_id: Uuid::from_u128(20),
            status: WorkloadStatus::Active,
            auth_epoch: 7,
        }
    }

    fn binding() -> WorkloadClientBinding {
        WorkloadClientBinding {
            client_id: "svc-build".to_string(),
            service_account_id: Uuid::from_u128(10),
            application_id: Uuid::from_u128(20),
            audience: "build-api".to_string(),
            status: WorkloadStatus::Active,
            credential_epoch: 3,
            allowed_scopes: vec!["build:read".to_string(), "build:write".to_string()],
            default_scopes: vec!["build:read".to_string()],
        }
    }

    fn session() -> WorkloadSessionSnapshot {
        WorkloadSessionSnapshot {
            session_id: Uuid::from_u128(30),
            service_account_id: Uuid::from_u128(10),
            client_id: "svc-build".to_string(),
            application_id: Uuid::from_u128(20),
            service_account_auth_epoch: 7,
            credential_epoch: 3,
            audience: "build-api".to_string(),
            scopes: vec!["build:read".to_string()],
            expires_at_unix: 2_000,
            revoked: false,
        }
    }

    #[test]
    fn machine_scope_uses_defaults_without_human_consent() {
        let effective = binding()
            .effective_scope(&[], &["build:read".to_string(), "build:write".to_string()])
            .unwrap();
        assert_eq!(effective, vec!["build:read"]);
    }

    #[test]
    fn machine_scope_never_silently_widens_or_narrows() {
        let requested = vec!["build:write".to_string()];
        let result = binding().effective_scope(&requested, &["build:read".to_string()]);
        assert_eq!(result, Err(WorkloadScopeError::ExceedsClientRegistration));
    }

    #[test]
    fn oidc_and_offline_access_are_not_machine_scopes() {
        for reserved in [PROTOCOL_SCOPE, OFFLINE_ACCESS_SCOPE] {
            let result = validate_machine_scope_set(&[reserved.to_string()]);
            assert_eq!(result, Err(WorkloadScopeError::HumanProtocolScope));
        }
    }

    #[test]
    fn duplicate_machine_scope_is_rejected() {
        let result =
            validate_machine_scope_set(&["build:read".to_string(), "build:read".to_string()]);
        assert_eq!(result, Err(WorkloadScopeError::Duplicate));
    }

    #[test]
    fn workload_session_is_active_only_at_exact_epochs() {
        assert!(session().is_active_for(&principal(), &binding(), 1_500));

        let mut rotated_principal = principal();
        rotated_principal.auth_epoch += 1;
        assert!(!session().is_active_for(&rotated_principal, &binding(), 1_500));

        let mut rotated_credential = binding();
        rotated_credential.credential_epoch += 1;
        assert!(!session().is_active_for(&principal(), &rotated_credential, 1_500));
    }

    #[test]
    fn disable_then_reenable_cannot_resurrect_old_epoch() {
        let old = session();
        let mut current = principal();
        current.status = WorkloadStatus::Disabled;
        assert!(!old.is_active_for(&current, &binding(), 1_500));

        current.status = WorkloadStatus::Active;
        current.auth_epoch += 1;
        assert!(!old.is_active_for(&current, &binding(), 1_500));
    }

    #[test]
    fn cross_application_binding_is_rejected() {
        let mut cross_application = binding();
        cross_application.application_id = Uuid::from_u128(99);
        assert!(!session().is_active_for(&principal(), &cross_application, 1_500));
    }

    #[test]
    fn workload_session_rejects_wrong_client_audience_revocation_and_expiry() {
        let mut wrong_client = binding();
        wrong_client.client_id = "svc-other".to_string();
        assert!(!session().is_active_for(&principal(), &wrong_client, 1_500));

        let mut wrong_audience = binding();
        wrong_audience.audience = "other-api".to_string();
        assert!(!session().is_active_for(&principal(), &wrong_audience, 1_500));

        let mut revoked = session();
        revoked.revoked = true;
        assert!(!revoked.is_active_for(&principal(), &binding(), 1_500));

        assert!(!session().is_active_for(&principal(), &binding(), 2_000));
    }
}
