//! Disabled-by-default, redacted global session-revocation control plane.
//!
//! Every request and response on this surface uses a strict Ores
//! `{contract,payload}` envelope. Raw email is deliberately absent: a trusted
//! edge submits only a keyed alias digest, then an operator explicitly selects
//! one immutable opaque principal from the short-lived stored candidate set.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, FixedOffset, TimeDelta, Utc};
use uuid::Uuid;

use crate::admin_contracts::{
    AdminRevocationTokenExchangeRequest, AdminRevocationTokenExchangeResult, ContractEnvelope,
    GlobalRevocationCommitAuthorization, GlobalRevocationOperation, GlobalRevocationPreview,
    GlobalRevocationPreviewRequest, GlobalRevocationRequest, IncomingEnvelope,
    PrincipalSearchCandidate, PrincipalSearchRequest, PrincipalSearchResult,
    PrincipalSelectionRequest, PrincipalSelectionResult, ProviderIdentityRef,
    RevocationAuditCorrelation, RevocationBlastRadius, RevocationFence, RevocationPreviewTarget,
    RevocationRedaction, RevocationStepUp, RevocationTargetResult, TokenExchangeRedaction,
    ACCESS_TOKEN_TYPE, ADMIN_REVOCATION_TOKEN_EXCHANGE_REQUEST_SCHEMA,
    ADMIN_REVOCATION_TOKEN_EXCHANGE_RESULT_SCHEMA, GLOBAL_REVOCATION_COMMIT_AUTHORIZATION_SCHEMA,
    GLOBAL_REVOCATION_OPERATION_SCHEMA, GLOBAL_REVOCATION_PREVIEW_REQUEST_SCHEMA,
    GLOBAL_REVOCATION_PREVIEW_SCHEMA, GLOBAL_REVOCATION_REQUEST_SCHEMA,
    PRINCIPAL_SEARCH_REQUEST_SCHEMA, PRINCIPAL_SEARCH_RESULT_SCHEMA,
    PRINCIPAL_SELECTION_REQUEST_SCHEMA, PRINCIPAL_SELECTION_RESULT_SCHEMA,
};
use crate::config::GlobalRevocationConfig;
use crate::error::AuthError;
use crate::revocation::{
    normalize_global_scopes, valid_contract_identifier, valid_email_search_key_hash,
    valid_idempotency_key, valid_opaque_identifier, valid_reason_code,
    RevocationBlastRadius as StoredBlastRadius, RevocationCandidate, RevocationJob,
    RevocationOperator, RevocationScope, StoredCommitAuthorization, StoredRevocationPreview,
    StoredRevocationSearch, REVOCATION_OPERATOR_ROLE,
};
use crate::state::AppState;
use crate::token::{OreClaims, ACR_LOA2};

use super::bearer;
use super::introspect::{
    active_claims_for_audience, authorize_service_credential, valid_directory_admin_claims,
};

const ADMIN_AUDIENCE: &str = "shared-auth-web-server";
const ADMIN_CLIENT_ID: &str = "shared-auth-web-server";
const REQUIRED_SCOPE: &str = "shared-auth:sessions:revoke:global";
const DIRECTORY_SOURCE_SCOPE: &str = "shared-auth:directory:read";
const SEARCH_PURPOSE: &str = "operator_email_search";
const MAX_PRINCIPAL_CANDIDATES: usize = 50;
const REQUEST_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_REQUEST_AGE_SECONDS: i64 = 300;

/// Service-authenticated exchange from an active dashboard actor token to a
/// short-lived token whose only OAuth scope is the global-revocation scope.
/// The web service authenticates with an independent credential and never
/// receives signing material or chooses audience, azp, or scope.
pub async fn exchange_revocation_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<IncomingEnvelope<AdminRevocationTokenExchangeRequest>>,
) -> Result<Json<ContractEnvelope<AdminRevocationTokenExchangeResult>>, AuthError> {
    if envelope.contract != "AdminRevocationTokenExchangeRequest" {
        return Err(AuthError::BadRequest("invalid admin contract"));
    }
    authorize_service_credential(
        state.config.admin_token_exchange_secret.as_deref(),
        bearer(&headers),
    )?;
    let request = envelope.payload;
    if request.schema != ADMIN_REVOCATION_TOKEN_EXCHANGE_REQUEST_SCHEMA
        || !valid_contract_identifier(&request.request_id)
        || !(32..=8_192).contains(&request.subject_token.len())
        || request.subject_token_type != ACCESS_TOKEN_TYPE
        || request.audience != ADMIN_AUDIENCE
        || request.requested_scope != REQUIRED_SCOPE
        || !request.redaction.is_safe()
        || !valid_request_time(&request.requested_at)
    {
        return Err(AuthError::BadRequest("invalid token exchange request"));
    }

    let claims = active_claims_for_audience(&state, &request.subject_token, ADMIN_AUDIENCE).await?;
    if !valid_directory_admin_claims(&claims)
        || !claims
            .roles
            .iter()
            .any(|role| role == REVOCATION_OPERATOR_ROLE)
    {
        return Err(AuthError::Forbidden);
    }
    validate_fresh_webauthn(&state.config.global_revocation, &claims, now_secs())?;

    // Dashboard tokens retain the authority's internal subject. Only the
    // exchanged revocation token receives the opaque admin principal ref.
    let shared_user_id = canonical_uuid(&claims.sub).map_err(|_| AuthError::Unauthorized)?;
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    if !db
        .has_active_role(shared_user_id, REVOCATION_OPERATOR_ROLE)
        .await?
    {
        return Err(AuthError::Forbidden);
    }
    let principal_ref = db.admin_principal_ref(shared_user_id).await?;
    let minted = state.minter.mint_same_party_admin_scope(
        &claims,
        &principal_ref.to_string(),
        ADMIN_AUDIENCE,
        ADMIN_CLIENT_ID,
        DIRECTORY_SOURCE_SCOPE,
        REQUIRED_SCOPE,
        300,
    )?;
    let expires_at = unix_timestamp(minted.expires_at)?;
    let issued_at = Utc::now().fixed_offset();
    let expires_in_seconds = u64::try_from((expires_at - issued_at).num_seconds())
        .map_err(|_| AuthError::Unauthorized)?
        .min(300);
    if expires_in_seconds == 0 {
        return Err(AuthError::Unauthorized);
    }
    Ok(Json(ContractEnvelope {
        contract: "AdminRevocationTokenExchangeResult",
        payload: AdminRevocationTokenExchangeResult {
            schema: ADMIN_REVOCATION_TOKEN_EXCHANGE_RESULT_SCHEMA,
            request_id: request.request_id,
            access_token: minted.token,
            issued_token_type: ACCESS_TOKEN_TYPE,
            token_type: "Bearer",
            expires_in_seconds,
            audience: ADMIN_AUDIENCE,
            authorized_party: ADMIN_CLIENT_ID,
            scope: REQUIRED_SCOPE,
            issued_at,
            expires_at,
            redaction: TokenExchangeRedaction::SAFE,
        },
    }))
}

pub async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<IncomingEnvelope<PrincipalSearchRequest>>,
) -> Result<Json<ContractEnvelope<PrincipalSearchResult>>, AuthError> {
    if envelope.contract != "PrincipalSearchRequest" {
        return Err(AuthError::BadRequest("invalid admin contract"));
    }
    let operator = authorized_operator(&state, &headers).await?;
    let request = envelope.payload;
    if request.schema != PRINCIPAL_SEARCH_REQUEST_SCHEMA
        || !valid_contract_identifier(&request.request_id)
        || request.requested_by_principal_id != operator.principal_ref.to_string()
        || !valid_email_search_key_hash(&request.email_search_key_hash)
        || request.purpose != SEARCH_PURPOSE
        || !request.redaction.is_safe()
        || !valid_request_time(&request.requested_at)
    {
        return Err(AuthError::BadRequest("invalid principal search request"));
    }
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let search = db
        .begin_global_revocation_search(
            operator,
            &request.request_id,
            &request.email_search_key_hash,
            state.config.global_revocation.preview_ttl_secs,
        )
        .await?;
    let candidates = search_candidates(&search)?;
    let (result_state, selection_required) = match candidates.len() {
        0 => ("no_match", false),
        1 => ("unique", false),
        _ => ("ambiguous", true),
    };
    Ok(Json(ContractEnvelope {
        contract: "PrincipalSearchResult",
        payload: PrincipalSearchResult {
            schema: PRINCIPAL_SEARCH_RESULT_SCHEMA,
            lookup_id: search.operation_id.to_string(),
            email_search_key_hash: search.email_search_key_hash,
            state: result_state,
            candidates,
            requires_explicit_principal_selection: selection_required,
            generated_at: Utc::now().fixed_offset(),
            redaction: RevocationRedaction::SAFE,
        },
    }))
}

pub async fn select(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<IncomingEnvelope<PrincipalSelectionRequest>>,
) -> Result<Json<ContractEnvelope<PrincipalSelectionResult>>, AuthError> {
    if envelope.contract != "PrincipalSelectionRequest" {
        return Err(AuthError::BadRequest("invalid admin contract"));
    }
    let operator = authorized_operator(&state, &headers).await?;
    let request = envelope.payload;
    if request.schema != PRINCIPAL_SELECTION_REQUEST_SCHEMA
        || !valid_contract_identifier(&request.request_id)
        || !request.selection_confirmed
        || !request.redaction.is_safe()
        || !valid_request_time(&request.requested_at)
    {
        return Err(AuthError::BadRequest("invalid principal selection request"));
    }
    let lookup_id = canonical_uuid(&request.lookup_id)?;
    let principal_id = canonical_uuid(&request.principal_id)?;
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let selection = db
        .select_global_revocation_candidate(
            operator,
            &request.request_id,
            lookup_id,
            principal_id,
            state.config.global_revocation.preview_ttl_secs,
        )
        .await?;
    Ok(Json(ContractEnvelope {
        contract: "PrincipalSelectionResult",
        payload: PrincipalSelectionResult {
            schema: PRINCIPAL_SELECTION_RESULT_SCHEMA,
            selection_id: selection.selection_id,
            lookup_id: selection.operation_id.to_string(),
            principal_id: selection.target_principal_ref.to_string(),
            selected_at: selection.selected_at,
            expires_at: selection.expires_at,
            redaction: RevocationRedaction::SAFE,
        },
    }))
}

pub async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<IncomingEnvelope<GlobalRevocationPreviewRequest>>,
) -> Result<Json<ContractEnvelope<GlobalRevocationPreview>>, AuthError> {
    if envelope.contract != "GlobalRevocationPreviewRequest" {
        return Err(AuthError::BadRequest("invalid admin contract"));
    }
    let operator = authorized_operator(&state, &headers).await?;
    let request = envelope.payload;
    if request.schema != GLOBAL_REVOCATION_PREVIEW_REQUEST_SCHEMA
        || !valid_contract_identifier(&request.request_id)
        || !valid_opaque_identifier(&request.selection_id)
        || !request.redaction.is_safe()
        || !valid_request_time(&request.requested_at)
    {
        return Err(AuthError::BadRequest(
            "invalid global revocation preview request",
        ));
    }
    let selected_scopes =
        normalize_global_scopes(request.selected_scopes).map_err(AuthError::BadRequest)?;
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let stored = db
        .create_global_revocation_preview_from_selection(
            operator,
            &request.request_id,
            &request.selection_id,
            &selected_scopes,
            state.config.global_revocation.preview_ttl_secs,
        )
        .await?;
    Ok(Json(ContractEnvelope {
        contract: "GlobalRevocationPreview",
        payload: preview_payload(&state, stored).await?,
    }))
}

pub async fn get_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(preview_id): Path<String>,
) -> Result<Json<ContractEnvelope<GlobalRevocationPreview>>, AuthError> {
    authorized_operator(&state, &headers).await?;
    let preview_id = canonical_uuid(&preview_id)?;
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let stored = db.global_revocation_preview(preview_id).await?;
    Ok(Json(ContractEnvelope {
        contract: "GlobalRevocationPreview",
        payload: preview_payload(&state, stored).await?,
    }))
}

/// A fresh, phishing-resistant second operator receives a one-use handle bound
/// server-side to the preview, immutable principal, exact scopes, session,
/// proof evidence, and freshness window. The route accepts no client body.
pub async fn authorize_commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(preview_id): Path<String>,
) -> Result<Json<ContractEnvelope<GlobalRevocationCommitAuthorization>>, AuthError> {
    let (operator, claims) = authorized_operator_with_claims(&state, &headers).await?;
    let preview_id = canonical_uuid(&preview_id)?;
    let verified_at = unix_timestamp(claims.webauthn_auth_time.ok_or(AuthError::StepUpRequired)?)?;
    let token_expires_at = unix_timestamp(claims.exp)?;
    let fresh_until = (verified_at
        + TimeDelta::seconds(
            i64::try_from(state.config.global_revocation.max_auth_age_secs)
                .map_err(|_| AuthError::StepUpRequired)?,
        ))
    .min(token_expires_at);
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let authorization = db
        .create_global_revocation_commit_authorization(
            operator,
            preview_id,
            verified_at,
            fresh_until,
            &claims.jti,
        )
        .await?;
    Ok(Json(ContractEnvelope {
        contract: "GlobalRevocationCommitAuthorization",
        payload: commit_authorization_payload(&state, authorization)?,
    }))
}

pub async fn commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<IncomingEnvelope<GlobalRevocationRequest>>,
) -> Result<
    (
        StatusCode,
        Json<ContractEnvelope<GlobalRevocationOperation>>,
    ),
    AuthError,
> {
    if envelope.contract != "GlobalRevocationRequest" {
        return Err(AuthError::BadRequest("invalid admin contract"));
    }
    let operator = authorized_operator(&state, &headers).await?;
    let request = envelope.payload;
    if request.schema != GLOBAL_REVOCATION_REQUEST_SCHEMA
        || !valid_opaque_identifier(&request.commit_authorization_id)
        || !valid_idempotency_key(&request.idempotency_key)
        || !valid_contract_identifier(&request.correlation.request_id)
        || !valid_contract_identifier(&request.correlation.trace_id)
        || !valid_reason_code(&request.correlation.reason_code)
        || request
            .correlation
            .ticket_reference_hash
            .as_deref()
            .is_some_and(|value| !valid_opaque_identifier(value))
        || !request.redaction.is_safe()
        || !valid_request_time(&request.requested_at)
    {
        return Err(AuthError::BadRequest("invalid global revocation request"));
    }
    if let Some(header_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
    {
        if header_key != request.idempotency_key {
            return Err(AuthError::Conflict);
        }
    }
    let preview_id = canonical_uuid(&request.preview_id)?;
    let selected_scopes =
        normalize_global_scopes(request.selected_scopes).map_err(AuthError::BadRequest)?;
    let db = state.db.clone().ok_or(AuthError::NotFound)?;
    let cache_configured = state.config.redis.is_some();
    let commit_authorization_id = request.commit_authorization_id.clone();
    let idempotency_key = request.idempotency_key.clone();
    let request_id = request.correlation.request_id.clone();
    let trace_id = request.correlation.trace_id.clone();
    let reason_code = request.correlation.reason_code.clone();
    let ticket_reference_hash = request.correlation.ticket_reference_hash.clone();
    let requested_at = request.requested_at;
    let committed = state
        .with_revocation_lock(move || async move {
            db.commit_global_revocation(
                operator,
                preview_id,
                &commit_authorization_id,
                &idempotency_key,
                &selected_scopes,
                requested_at,
                &request_id,
                &trace_id,
                &reason_code,
                ticket_reference_hash.as_deref(),
                cache_configured,
            )
            .await
        })
        .await?;
    let status = if committed.newly_created {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(ContractEnvelope {
            contract: "GlobalRevocationOperation",
            payload: operation_payload(committed.job)?,
        }),
    ))
}

pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> Result<Json<ContractEnvelope<GlobalRevocationOperation>>, AuthError> {
    authorized_operator(&state, &headers).await?;
    let operation_id = canonical_uuid(&operation_id)?;
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    Ok(Json(ContractEnvelope {
        contract: "GlobalRevocationOperation",
        payload: operation_payload(db.global_revocation_job(operation_id).await?)?,
    }))
}

async fn preview_payload(
    state: &AppState,
    preview: StoredRevocationPreview,
) -> Result<GlobalRevocationPreview, AuthError> {
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let identities = db
        .revocation_identities_for_principal(preview.target.shared_user_id)
        .await?;
    let targets = preview_targets(state, &preview, identities)?;
    Ok(GlobalRevocationPreview {
        schema: GLOBAL_REVOCATION_PREVIEW_SCHEMA,
        preview_id: preview.preview_id.to_string(),
        principal_id: preview.target_principal_ref.to_string(),
        generated_at: preview.generated_at,
        expires_at: preview.expires_at,
        selected_scopes: preview.scopes.clone(),
        blast_radius: blast_radius_payload(&preview.blast_radius),
        targets,
        ambiguity_resolved: true,
        requires_step_up: true,
        minimum_assurance: "aal2",
        phishing_resistant_step_up_required: true,
        redaction: RevocationRedaction::SAFE,
    })
}

fn preview_targets(
    state: &AppState,
    preview: &StoredRevocationPreview,
    identities: Vec<RevocationCandidate>,
) -> Result<Vec<RevocationPreviewTarget>, AuthError> {
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let authority_handle = db.opaque_admin_identifier_hash(
        "preview-authority-identity",
        &format!("{}:{}", preview.preview_id, preview.target_principal_ref),
    )?;
    let mut targets: Vec<RevocationPreviewTarget> = preview
        .scopes
        .iter()
        .map(|scope| {
            let supported = is_authority_supported(*scope);
            let target_id_hash = db.opaque_admin_identifier_hash(
                "preview-target",
                &format!("{}:shared_auth:{}", preview.preview_id, scope.as_str()),
            )?;
            Ok(RevocationPreviewTarget {
                target_id_hash,
                identity: ProviderIdentityRef {
                    provider_id: "shared_auth".into(),
                    provider_tenant_id: "authority".into(),
                    opaque_identity_handle: authority_handle.clone(),
                },
                scope: *scope,
                estimated_resource_count: authority_scope_count(&preview.blast_radius, *scope),
                supported,
                requires_provider_fanout: false,
                residual_access_token_max_seconds: supported
                    .then_some(state.config.signing.ttl_secs.min(86_400)),
                warning_codes: if supported {
                    vec!["shared_auth.offline_validator_residual_window".into()]
                } else {
                    vec!["shared_auth.inventory_adapter_unavailable".into()]
                },
            })
        })
        .collect::<Result<_, AuthError>>()?;
    for identity in identities
        .into_iter()
        .filter(|identity| !matches!(identity.selector.provider.as_str(), "local" | "magic_link"))
    {
        if !valid_contract_identifier(&identity.selector.provider) {
            return Err(AuthError::Internal);
        }
        let opaque_identity_handle = db.opaque_admin_identifier_hash(
            "preview-provider-identity",
            &format!("{}:{}", preview.preview_id, identity.provider_identity_id),
        )?;
        for scope in &preview.scopes {
            let target_id_hash = db.opaque_admin_identifier_hash(
                "preview-target",
                &format!(
                    "{}:{}:{}",
                    preview.preview_id,
                    identity.provider_identity_id,
                    scope.as_str()
                ),
            )?;
            targets.push(RevocationPreviewTarget {
                target_id_hash,
                identity: ProviderIdentityRef {
                    provider_id: identity.selector.provider.clone(),
                    provider_tenant_id: identity.provider_tenant_ref.to_string(),
                    opaque_identity_handle: opaque_identity_handle.clone(),
                },
                scope: *scope,
                estimated_resource_count: 0,
                supported: false,
                requires_provider_fanout: true,
                residual_access_token_max_seconds: None,
                warning_codes: vec!["shared_auth.provider_adapter_unavailable".into()],
            });
        }
    }
    Ok(targets)
}

fn commit_authorization_payload(
    state: &AppState,
    authorization: StoredCommitAuthorization,
) -> Result<GlobalRevocationCommitAuthorization, AuthError> {
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let preview_actor_hash = db.opaque_admin_identifier_hash(
        "principal-ref",
        &authorization.preview.previewed_by_principal_ref.to_string(),
    )?;
    let commit_actor_hash = db.opaque_admin_identifier_hash(
        "principal-ref",
        &authorization.authorized_by.principal_ref.to_string(),
    )?;
    Ok(GlobalRevocationCommitAuthorization {
        schema: GLOBAL_REVOCATION_COMMIT_AUTHORIZATION_SCHEMA,
        commit_authorization_id: authorization.commit_authorization_id,
        preview_id: authorization.preview.preview_id.to_string(),
        principal_id: authorization.preview.target_principal_ref.to_string(),
        selected_scopes: authorization.preview.scopes,
        preview_created_by_principal_id_hash: preview_actor_hash,
        commit_authorized_by_principal_id_hash: commit_actor_hash,
        commit_authorized_by_session_id_hash: authorization.actor_session_id_hash.clone(),
        dual_control_required: state.config.global_revocation.require_dual_control,
        dual_control_satisfied: true,
        verified_step_up: RevocationStepUp {
            actor_principal_id: authorization.authorized_by.principal_ref.to_string(),
            actor_session_id_hash: authorization.actor_session_id_hash,
            evidence_id_hash: authorization.evidence_id_hash,
            assurance: "aal2",
            auth_methods: vec!["webauthn"],
            phishing_resistant: true,
            verified_at: authorization.verified_at,
            fresh_until: authorization.fresh_until,
        },
        issued_at: authorization.issued_at,
        expires_at: authorization.expires_at,
        redaction: RevocationRedaction::SAFE,
    })
}

fn operation_payload(job: RevocationJob) -> Result<GlobalRevocationOperation, AuthError> {
    let state = match job.status.as_str() {
        "complete" => "succeeded",
        "partial" => "partial",
        "failed" => "failed",
        "running" => "running",
        _ => "queued",
    }
    .to_owned();
    let terminal = matches!(
        state.as_str(),
        "partial" | "succeeded" | "failed" | "cancelled"
    );
    if terminal && job.completed_at.is_none() {
        return Err(AuthError::Internal);
    }
    let targets = job
        .targets
        .into_iter()
        .map(|target| {
            if !valid_opaque_identifier(&target.target_id_hash)
                || !valid_contract_identifier(&target.provider_id)
                || !valid_contract_identifier(&target.provider_tenant_id)
                || !valid_opaque_identifier(&target.opaque_identity_handle)
                || target.attempts > 100
                || target
                    .retry_after_seconds
                    .is_some_and(|value| value > 86_400)
                || target
                    .residual_access_token_max_seconds
                    .is_some_and(|value| value > 86_400)
                || target
                    .provider_request_id_hash
                    .as_deref()
                    .is_some_and(|value| !valid_opaque_identifier(value))
                || target
                    .last_error_code
                    .as_deref()
                    .is_some_and(|value| !valid_reason_code(value))
            {
                return Err(AuthError::Internal);
            }
            let terminal_target = matches!(
                target.status.as_str(),
                "succeeded" | "failed" | "skipped" | "unsupported"
            );
            if terminal_target
                && (target.completed_at.is_none() || target.last_error_code.is_none())
            {
                return Err(AuthError::Internal);
            }
            Ok(RevocationTargetResult {
                target_id_hash: target.target_id_hash,
                identity: ProviderIdentityRef {
                    provider_id: target.provider_id,
                    provider_tenant_id: target.provider_tenant_id,
                    opaque_identity_handle: target.opaque_identity_handle,
                },
                scope: target.scope,
                state: target.status,
                attempt_count: target.attempts,
                retryable: target.retryable,
                last_attempt_at: target.last_attempt_at,
                next_attempt_at: target.next_attempt_at,
                retry_after_seconds: target.retry_after_seconds,
                completed_at: target.completed_at,
                result_code: target.last_error_code,
                provider_request_id_hash: target.provider_request_id_hash,
                residual_access_token_max_seconds: target.residual_access_token_max_seconds,
            })
        })
        .collect::<Result<Vec<_>, AuthError>>()?;
    Ok(GlobalRevocationOperation {
        schema: GLOBAL_REVOCATION_OPERATION_SCHEMA,
        operation_id: job.job_id.to_string(),
        principal_id: job.target_principal_ref.to_string(),
        preview_id: job.preview_id.to_string(),
        state,
        selected_scopes: job.scopes,
        created_at: job.created_at,
        updated_at: job.updated_at,
        completed_at: job.completed_at,
        fence: RevocationFence {
            applied_at: job.not_before,
            not_before: job.not_before,
            previous_auth_epoch: job.previous_auth_epoch,
            auth_epoch: job.auth_epoch,
            effective: true,
        },
        targets,
        audit: RevocationAuditCorrelation {
            audit_event_id: job.audit_event_id.to_string(),
            correlation_id: job.correlation_id.to_string(),
            request_id: job.request_id,
            trace_id: job.trace_id,
            actor_principal_id: job.committed_by_principal_ref.to_string(),
            actor_session_id_hash: job.actor_session_id_hash,
            idempotency_key_hash: job.idempotency_key_hash,
            reason_code: job.reason_code,
            raw_emails_present: false,
            raw_tokens_present: false,
            raw_biometric_material_present: false,
        },
        redaction: RevocationRedaction::SAFE,
    })
}

fn search_candidates(
    search: &StoredRevocationSearch,
) -> Result<Vec<PrincipalSearchCandidate>, AuthError> {
    let mut grouped: BTreeMap<Uuid, (Vec<ProviderIdentityRef>, u64, u64)> = BTreeMap::new();
    for candidate in &search.candidates {
        if !valid_contract_identifier(&candidate.selector.provider) {
            return Err(AuthError::Internal);
        }
        let entry = grouped.entry(candidate.principal_ref).or_insert_with(|| {
            (
                Vec::new(),
                candidate.organization_count,
                candidate.active_session_count,
            )
        });
        if entry.1 != candidate.organization_count || entry.2 != candidate.active_session_count {
            return Err(AuthError::Internal);
        }
        entry.0.push(ProviderIdentityRef {
            provider_id: candidate.selector.provider.clone(),
            provider_tenant_id: candidate.provider_tenant_ref.to_string(),
            opaque_identity_handle: candidate.provider_identity_id.to_string(),
        });
    }
    if grouped.len() > MAX_PRINCIPAL_CANDIDATES {
        return Err(AuthError::Conflict);
    }
    Ok(grouped
        .into_iter()
        .map(
            |(principal_id, (identities, organization_count, active_session_count))| {
                PrincipalSearchCandidate {
                    principal_id: principal_id.to_string(),
                    identities,
                    organization_count,
                    active_session_count,
                }
            },
        )
        .collect())
}

fn blast_radius_payload(value: &StoredBlastRadius) -> RevocationBlastRadius {
    let mut unknown_fields = vec![
        "impersonationSessionCount",
        "registeredDeviceSessionCount",
        "userApiCredentialCount",
    ];
    if value.organization_count.is_none() {
        unknown_fields.push("organizationCount");
    }
    if value.project_count.is_none() {
        unknown_fields.push("projectCount");
    }
    unknown_fields.sort_unstable();
    RevocationBlastRadius {
        provider_tenant_count: Some(value.provider_tenant_count),
        identity_count: Some(value.identity_count),
        organization_count: value.organization_count,
        project_count: value.project_count,
        interactive_session_count: Some(value.browser_sessions),
        refresh_token_family_count: Some(value.refresh_credentials),
        offline_grant_count: Some(value.offline_grants),
        downstream_session_count: Some(value.downstream_grants),
        impersonation_session_count: None,
        user_api_credential_count: None,
        registered_device_session_count: None,
        inventory_status: "partial",
        unknown_fields,
    }
}

fn authority_scope_count(value: &StoredBlastRadius, scope: RevocationScope) -> u64 {
    match scope {
        RevocationScope::InteractiveSessions => value.browser_sessions,
        RevocationScope::RefreshTokenFamilies => value.refresh_credentials,
        RevocationScope::OfflineGrants => value.offline_grants,
        RevocationScope::DownstreamSessions => value.downstream_grants,
        RevocationScope::ImpersonationSessions
        | RevocationScope::UserApiCredentials
        | RevocationScope::RegisteredDeviceSessions => 0,
    }
}

fn is_authority_supported(scope: RevocationScope) -> bool {
    matches!(
        scope,
        RevocationScope::InteractiveSessions
            | RevocationScope::RefreshTokenFamilies
            | RevocationScope::OfflineGrants
            | RevocationScope::DownstreamSessions
    )
}

async fn authorized_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<RevocationOperator, AuthError> {
    authorized_operator_with_claims(state, headers)
        .await
        .map(|(operator, _)| operator)
}

async fn authorized_operator_with_claims(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(RevocationOperator, OreClaims), AuthError> {
    let config = &state.config.global_revocation;
    if !config.enabled || !config.admin_realm || state.db.is_none() {
        return Err(AuthError::NotFound);
    }
    let claims = active_claims_for_audience(
        state,
        bearer(headers).ok_or(AuthError::Unauthorized)?,
        ADMIN_AUDIENCE,
    )
    .await?;
    validate_operator_claims(config, &claims, now_secs())?;
    // Revocation-token subjects are the stable opaque admin references, not
    // the internal shared_user_id used by ordinary tokens.
    let principal_ref = canonical_uuid(&claims.sub).map_err(|_| AuthError::Unauthorized)?;
    let session_id = claims
        .sid
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(AuthError::Unauthorized)?;
    let db = state.db.as_ref().ok_or(AuthError::NotFound)?;
    let shared_user_id = db
        .shared_user_id_for_admin_principal_ref(principal_ref)
        .await?;
    if !db
        .has_active_role(shared_user_id, REVOCATION_OPERATOR_ROLE)
        .await?
    {
        return Err(AuthError::Forbidden);
    }
    Ok((
        RevocationOperator {
            shared_user_id,
            principal_ref,
            session_id,
            auth_epoch: claims.auth_epoch,
        },
        claims,
    ))
}

fn validate_operator_claims(
    config: &GlobalRevocationConfig,
    claims: &OreClaims,
    now: u64,
) -> Result<(), AuthError> {
    if !config.enabled || !config.admin_realm {
        return Err(AuthError::NotFound);
    }
    if !claims.is_delegated()
        || claims.aud != ADMIN_AUDIENCE
        || claims.azp.as_deref() != Some(ADMIN_CLIENT_ID)
        || !has_exact_scope(claims, REQUIRED_SCOPE)
        || !claims
            .roles
            .iter()
            .any(|role| role == REVOCATION_OPERATOR_ROLE)
    {
        return Err(AuthError::Forbidden);
    }
    validate_fresh_webauthn(config, claims, now)
}

fn has_exact_scope(claims: &OreClaims, required: &str) -> bool {
    let mut scopes = claims.scope.split_ascii_whitespace();
    scopes.next() == Some(required) && scopes.next().is_none()
}

fn validate_fresh_webauthn(
    config: &GlobalRevocationConfig,
    claims: &OreClaims,
    now: u64,
) -> Result<(), AuthError> {
    if claims.aal < 2 || !claims.has_acr(ACR_LOA2) || !claims.used_method("passkey") {
        return Err(AuthError::StepUpRequired);
    }
    let auth_time = claims.webauthn_auth_time.ok_or(AuthError::StepUpRequired)?;
    if claims.auth_time != Some(auth_time)
        || auth_time > now.saturating_add(30)
        || now.saturating_sub(auth_time) > config.max_auth_age_secs
    {
        return Err(AuthError::StepUpRequired);
    }
    Ok(())
}

/// Generic passkey enrollment remains available to normal users. A principal
/// holding the revoker role may add a passkey only from an already fresh
/// server-verified passkey session. Role changes fence all prior sessions.
pub(crate) async fn enforce_privileged_passkey_enrollment(
    state: &AppState,
    claims: &OreClaims,
) -> Result<bool, AuthError> {
    let Some(db) = state.db.as_ref() else {
        return Ok(false);
    };
    let shared_user_id = canonical_uuid(&claims.sub).map_err(|_| AuthError::Unauthorized)?;
    if !db
        .has_active_role(shared_user_id, REVOCATION_OPERATOR_ROLE)
        .await?
    {
        return Ok(false);
    }
    if claims.is_delegated()
        || !claims
            .roles
            .iter()
            .any(|role| role == REVOCATION_OPERATOR_ROLE)
    {
        return Err(AuthError::Forbidden);
    }
    validate_fresh_webauthn(&state.config.global_revocation, claims, now_secs())?;
    Ok(true)
}

fn valid_request_time(value: &DateTime<FixedOffset>) -> bool {
    let now = Utc::now().fixed_offset();
    *value <= now + TimeDelta::seconds(REQUEST_CLOCK_SKEW_SECONDS)
        && *value >= now - TimeDelta::seconds(MAX_REQUEST_AGE_SECONDS)
}

fn canonical_uuid(value: &str) -> Result<Uuid, AuthError> {
    let parsed = Uuid::parse_str(value).map_err(|_| AuthError::BadRequest("invalid identifier"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(AuthError::BadRequest("invalid identifier"));
    }
    Ok(parsed)
}

fn unix_timestamp(value: u64) -> Result<DateTime<FixedOffset>, AuthError> {
    DateTime::<Utc>::from_timestamp(
        i64::try_from(value).map_err(|_| AuthError::Unauthorized)?,
        0,
    )
    .map(|timestamp| timestamp.fixed_offset())
    .ok_or(AuthError::Unauthorized)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> GlobalRevocationConfig {
        GlobalRevocationConfig {
            enabled: true,
            admin_realm: true,
            max_auth_age_secs: 300,
            preview_ttl_secs: 600,
            require_dual_control: true,
        }
    }

    fn claims(now: u64) -> OreClaims {
        OreClaims {
            sub: Uuid::new_v4().to_string(),
            iss: "https://admin.auth.example".into(),
            aud: ADMIN_AUDIENCE.into(),
            iat: now,
            exp: now + 300,
            nbf: now,
            jti: Uuid::new_v4().to_string(),
            sid: Some(Uuid::new_v4().to_string()),
            provider: "shared_auth_admin".into(),
            provider_tenant: "redacted".into(),
            provider_subject: "redacted".into(),
            project: None,
            supabase_user_id: None,
            email: None,
            email_verified: false,
            roles: vec![REVOCATION_OPERATOR_ROLE.into()],
            aal: 2,
            amr: vec!["pwd".into(), "passkey".into()],
            acr: Some(ACR_LOA2.into()),
            auth_time: Some(now),
            webauthn_auth_time: Some(now),
            auth_epoch: 7,
            scope: REQUIRED_SCOPE.into(),
            azp: Some(ADMIN_CLIENT_ID.into()),
            parent_jti: Some(Uuid::new_v4().to_string()),
            cred: None,
        }
    }

    #[test]
    fn operator_requires_delegated_dashboard_token_and_exact_scope() {
        let now = 10_000;
        assert!(validate_operator_claims(&config(), &claims(now), now).is_ok());
        let mut candidate = claims(now);
        candidate.scope = "shared-auth:sessions:revoke".into();
        assert!(matches!(
            validate_operator_claims(&config(), &candidate, now),
            Err(AuthError::Forbidden)
        ));
        let mut candidate = claims(now);
        candidate.scope = format!("{REQUIRED_SCOPE} shared-auth:directory:read");
        assert!(matches!(
            validate_operator_claims(&config(), &candidate, now),
            Err(AuthError::Forbidden)
        ));
        let mut candidate = claims(now);
        candidate.azp = Some("other-client".into());
        assert!(matches!(
            validate_operator_claims(&config(), &candidate, now),
            Err(AuthError::Forbidden)
        ));
    }

    #[test]
    fn operator_requires_fresh_server_verified_passkey() {
        let now = 10_000;
        let mut candidate = claims(now);
        candidate.amr = vec!["pwd".into(), "totp".into()];
        assert!(matches!(
            validate_operator_claims(&config(), &candidate, now),
            Err(AuthError::StepUpRequired)
        ));
        let candidate = claims(now - 301);
        assert!(matches!(
            validate_operator_claims(&config(), &candidate, now),
            Err(AuthError::StepUpRequired)
        ));
    }

    #[test]
    fn global_scope_and_opaque_identifiers_fail_closed() {
        assert!(normalize_global_scopes(RevocationScope::ALL.to_vec()).is_ok());
        assert!(normalize_global_scopes(vec![
            RevocationScope::InteractiveSessions,
            RevocationScope::RefreshTokenFamilies,
        ])
        .is_err());
        assert!(valid_opaque_identifier("opaque_identifier_1234567890"));
        assert!(!valid_opaque_identifier("short"));
    }
}
