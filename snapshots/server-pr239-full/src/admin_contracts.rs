//! Strict Ores Shared Auth admin envelopes used at the HTTP trust boundary.
//!
//! These wire types intentionally duplicate no authorization logic. Incoming
//! documents are validated against exact discriminator/schema constants by the
//! handler, while every response is constructed only from authoritative state.

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::revocation::RevocationScope;

pub const PRINCIPAL_SEARCH_REQUEST_SCHEMA: &str =
    "ores.shared-auth-admin-principal-search-request/v1";
pub const PRINCIPAL_SEARCH_RESULT_SCHEMA: &str =
    "ores.shared-auth-admin-principal-search-result/v1";
pub const PRINCIPAL_SELECTION_REQUEST_SCHEMA: &str =
    "ores.shared-auth-admin-principal-selection-request/v1";
pub const PRINCIPAL_SELECTION_RESULT_SCHEMA: &str =
    "ores.shared-auth-admin-principal-selection-result/v1";
pub const GLOBAL_REVOCATION_PREVIEW_REQUEST_SCHEMA: &str =
    "ores.shared-auth-admin-global-revocation-preview-request/v1";
pub const GLOBAL_REVOCATION_PREVIEW_SCHEMA: &str =
    "ores.shared-auth-admin-global-revocation-preview/v1";
pub const GLOBAL_REVOCATION_COMMIT_AUTHORIZATION_SCHEMA: &str =
    "ores.shared-auth-admin-global-revocation-commit-authorization/v1";
pub const GLOBAL_REVOCATION_REQUEST_SCHEMA: &str =
    "ores.shared-auth-admin-global-revocation-request/v1";
pub const GLOBAL_REVOCATION_OPERATION_SCHEMA: &str =
    "ores.shared-auth-admin-global-revocation-operation/v1";
pub const ADMIN_REVOCATION_TOKEN_EXCHANGE_REQUEST_SCHEMA: &str =
    "ores.shared-auth-admin-revocation-token-exchange-request/v1";
pub const ADMIN_REVOCATION_TOKEN_EXCHANGE_RESULT_SCHEMA: &str =
    "ores.shared-auth-admin-revocation-token-exchange-result/v1";
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingEnvelope<T> {
    pub contract: String,
    pub payload: T,
}

#[derive(Serialize)]
pub struct ContractEnvelope<T> {
    pub contract: &'static str,
    pub payload: T,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationRedaction {
    pub raw_emails_present: bool,
    pub raw_tokens_present: bool,
    pub raw_session_identifiers_present: bool,
    pub raw_biometric_material_present: bool,
}

impl RevocationRedaction {
    pub const SAFE: Self = Self {
        raw_emails_present: false,
        raw_tokens_present: false,
        raw_session_identifiers_present: false,
        raw_biometric_material_present: false,
    };

    pub fn is_safe(self) -> bool {
        !self.raw_emails_present
            && !self.raw_tokens_present
            && !self.raw_session_identifiers_present
            && !self.raw_biometric_material_present
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenExchangeRedaction {
    pub subject_token_logged: bool,
    pub subject_token_persisted: bool,
    pub access_token_logged: bool,
    pub access_token_persisted: bool,
    pub tokens_returned_in_diagnostics: bool,
    pub raw_emails_present: bool,
    pub raw_biometric_material_present: bool,
}

impl TokenExchangeRedaction {
    pub const SAFE: Self = Self {
        subject_token_logged: false,
        subject_token_persisted: false,
        access_token_logged: false,
        access_token_persisted: false,
        tokens_returned_in_diagnostics: false,
        raw_emails_present: false,
        raw_biometric_material_present: false,
    };

    pub fn is_safe(self) -> bool {
        !self.subject_token_logged
            && !self.subject_token_persisted
            && !self.access_token_logged
            && !self.access_token_persisted
            && !self.tokens_returned_in_diagnostics
            && !self.raw_emails_present
            && !self.raw_biometric_material_present
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminRevocationTokenExchangeRequest {
    pub schema: String,
    pub request_id: String,
    pub subject_token: String,
    pub subject_token_type: String,
    pub audience: String,
    pub requested_scope: String,
    pub requested_at: DateTime<FixedOffset>,
    pub redaction: TokenExchangeRedaction,
}

impl fmt::Debug for AdminRevocationTokenExchangeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminRevocationTokenExchangeRequest")
            .field("schema", &self.schema)
            .field("request_id", &self.request_id)
            .field("subject_token", &"[REDACTED]")
            .field("subject_token_type", &self.subject_token_type)
            .field("audience", &self.audience)
            .field("requested_scope", &self.requested_scope)
            .field("requested_at", &self.requested_at)
            .field("redaction", &self.redaction)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRevocationTokenExchangeResult {
    pub schema: &'static str,
    pub request_id: String,
    pub access_token: String,
    pub issued_token_type: &'static str,
    pub token_type: &'static str,
    pub expires_in_seconds: u64,
    pub audience: &'static str,
    pub authorized_party: &'static str,
    pub scope: &'static str,
    pub issued_at: DateTime<FixedOffset>,
    pub expires_at: DateTime<FixedOffset>,
    pub redaction: TokenExchangeRedaction,
}

impl fmt::Debug for AdminRevocationTokenExchangeResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminRevocationTokenExchangeResult")
            .field("schema", &self.schema)
            .field("request_id", &self.request_id)
            .field("access_token", &"[REDACTED]")
            .field("issued_token_type", &self.issued_token_type)
            .field("token_type", &self.token_type)
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field("audience", &self.audience)
            .field("authorized_party", &self.authorized_party)
            .field("scope", &self.scope)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("redaction", &self.redaction)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrincipalSearchRequest {
    pub schema: String,
    pub request_id: String,
    pub requested_by_principal_id: String,
    pub email_search_key_hash: String,
    pub purpose: String,
    pub requested_at: DateTime<FixedOffset>,
    pub redaction: RevocationRedaction,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderIdentityRef {
    pub provider_id: String,
    pub provider_tenant_id: String,
    pub opaque_identity_handle: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalSearchCandidate {
    pub principal_id: String,
    pub identities: Vec<ProviderIdentityRef>,
    pub organization_count: u64,
    pub active_session_count: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalSearchResult {
    pub schema: &'static str,
    pub lookup_id: String,
    pub email_search_key_hash: String,
    pub state: &'static str,
    pub candidates: Vec<PrincipalSearchCandidate>,
    pub requires_explicit_principal_selection: bool,
    pub generated_at: DateTime<FixedOffset>,
    pub redaction: RevocationRedaction,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrincipalSelectionRequest {
    pub schema: String,
    pub request_id: String,
    pub lookup_id: String,
    pub principal_id: String,
    pub selection_confirmed: bool,
    pub requested_at: DateTime<FixedOffset>,
    pub redaction: RevocationRedaction,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalSelectionResult {
    pub schema: &'static str,
    pub selection_id: String,
    pub lookup_id: String,
    pub principal_id: String,
    pub selected_at: DateTime<FixedOffset>,
    pub expires_at: DateTime<FixedOffset>,
    pub redaction: RevocationRedaction,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GlobalRevocationPreviewRequest {
    pub schema: String,
    pub request_id: String,
    pub selection_id: String,
    pub selected_scopes: Vec<RevocationScope>,
    pub requested_at: DateTime<FixedOffset>,
    pub redaction: RevocationRedaction,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationBlastRadius {
    pub provider_tenant_count: Option<u64>,
    pub identity_count: Option<u64>,
    pub organization_count: Option<u64>,
    pub project_count: Option<u64>,
    pub interactive_session_count: Option<u64>,
    pub refresh_token_family_count: Option<u64>,
    pub offline_grant_count: Option<u64>,
    pub downstream_session_count: Option<u64>,
    pub impersonation_session_count: Option<u64>,
    pub user_api_credential_count: Option<u64>,
    pub registered_device_session_count: Option<u64>,
    pub inventory_status: &'static str,
    pub unknown_fields: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationPreviewTarget {
    pub target_id_hash: String,
    pub identity: ProviderIdentityRef,
    pub scope: RevocationScope,
    pub estimated_resource_count: u64,
    pub supported: bool,
    pub requires_provider_fanout: bool,
    pub residual_access_token_max_seconds: Option<u64>,
    pub warning_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalRevocationPreview {
    pub schema: &'static str,
    pub preview_id: String,
    pub principal_id: String,
    pub generated_at: DateTime<FixedOffset>,
    pub expires_at: DateTime<FixedOffset>,
    pub selected_scopes: Vec<RevocationScope>,
    pub blast_radius: RevocationBlastRadius,
    pub targets: Vec<RevocationPreviewTarget>,
    pub ambiguity_resolved: bool,
    pub requires_step_up: bool,
    pub minimum_assurance: &'static str,
    pub phishing_resistant_step_up_required: bool,
    pub redaction: RevocationRedaction,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationStepUp {
    pub actor_principal_id: String,
    pub actor_session_id_hash: String,
    pub evidence_id_hash: String,
    pub assurance: &'static str,
    pub auth_methods: Vec<&'static str>,
    pub phishing_resistant: bool,
    pub verified_at: DateTime<FixedOffset>,
    pub fresh_until: DateTime<FixedOffset>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalRevocationCommitAuthorization {
    pub schema: &'static str,
    pub commit_authorization_id: String,
    pub preview_id: String,
    pub principal_id: String,
    pub selected_scopes: Vec<RevocationScope>,
    pub preview_created_by_principal_id_hash: String,
    pub commit_authorized_by_principal_id_hash: String,
    pub commit_authorized_by_session_id_hash: String,
    pub dual_control_required: bool,
    pub dual_control_satisfied: bool,
    pub verified_step_up: RevocationStepUp,
    pub issued_at: DateTime<FixedOffset>,
    pub expires_at: DateTime<FixedOffset>,
    pub redaction: RevocationRedaction,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationRequestCorrelation {
    pub request_id: String,
    pub trace_id: String,
    pub reason_code: String,
    #[serde(default)]
    pub ticket_reference_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GlobalRevocationRequest {
    pub schema: String,
    pub preview_id: String,
    pub commit_authorization_id: String,
    pub idempotency_key: String,
    pub selected_scopes: Vec<RevocationScope>,
    pub requested_at: DateTime<FixedOffset>,
    pub correlation: RevocationRequestCorrelation,
    pub redaction: RevocationRedaction,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationTargetResult {
    pub target_id_hash: String,
    pub identity: ProviderIdentityRef,
    pub scope: RevocationScope,
    pub state: String,
    pub attempt_count: u32,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<DateTime<FixedOffset>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<DateTime<FixedOffset>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<FixedOffset>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_request_id_hash: Option<String>,
    pub residual_access_token_max_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationFence {
    pub applied_at: DateTime<FixedOffset>,
    pub not_before: DateTime<FixedOffset>,
    pub previous_auth_epoch: u64,
    pub auth_epoch: u64,
    pub effective: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationAuditCorrelation {
    pub audit_event_id: String,
    pub correlation_id: String,
    pub request_id: String,
    pub trace_id: String,
    pub actor_principal_id: String,
    pub actor_session_id_hash: String,
    pub idempotency_key_hash: String,
    pub reason_code: String,
    pub raw_emails_present: bool,
    pub raw_tokens_present: bool,
    pub raw_biometric_material_present: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalRevocationOperation {
    pub schema: &'static str,
    pub operation_id: String,
    pub principal_id: String,
    pub preview_id: String,
    pub state: String,
    pub selected_scopes: Vec<RevocationScope>,
    pub created_at: DateTime<FixedOffset>,
    pub updated_at: DateTime<FixedOffset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<FixedOffset>>,
    pub fence: RevocationFence,
    pub targets: Vec<RevocationTargetResult>,
    pub audit: RevocationAuditCorrelation,
    pub redaction: RevocationRedaction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_exchange_debug_output_is_always_redacted() {
        let now = chrono::Utc::now().fixed_offset();
        let request_secret = "request-token-must-never-appear";
        let request = AdminRevocationTokenExchangeRequest {
            schema: ADMIN_REVOCATION_TOKEN_EXCHANGE_REQUEST_SCHEMA.into(),
            request_id: "request-1".into(),
            subject_token: request_secret.into(),
            subject_token_type: ACCESS_TOKEN_TYPE.into(),
            audience: "shared-auth-web-server".into(),
            requested_scope: "shared-auth:sessions:revoke:global".into(),
            requested_at: now,
            redaction: TokenExchangeRedaction::SAFE,
        };
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(request_secret));
        assert!(request_debug.contains("[REDACTED]"));

        let response_secret = "response-token-must-never-appear";
        let response = AdminRevocationTokenExchangeResult {
            schema: ADMIN_REVOCATION_TOKEN_EXCHANGE_RESULT_SCHEMA,
            request_id: "request-1".into(),
            access_token: response_secret.into(),
            issued_token_type: ACCESS_TOKEN_TYPE,
            token_type: "Bearer",
            expires_in_seconds: 60,
            audience: "shared-auth-web-server",
            authorized_party: "shared-auth-web-server",
            scope: "shared-auth:sessions:revoke:global",
            issued_at: now,
            expires_at: now + chrono::TimeDelta::minutes(1),
            redaction: TokenExchangeRedaction::SAFE,
        };
        let response_debug = format!("{response:?}");
        assert!(!response_debug.contains(response_secret));
        assert!(response_debug.contains("[REDACTED]"));
    }
}
