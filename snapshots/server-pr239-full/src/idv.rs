//! Third-party identity and age verification.
//!
//! Shared-auth never accepts ID photos or face images on this surface. The
//! browser is sent to the vendor capture URL. We persist only the provider
//! inquiry id, document type, and age-over-N verdicts. In-house "recognition"
//! is a confidence heuristic over those vendor fields — not pixel analysis.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db::DbStore;
use crate::error::AuthError;
use crate::http::bearer;
use crate::state::AppState;

const SESSION_TTL: Duration = Duration::from_secs(900);
const MAX_OPEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdvStatus {
    Pending,
    Passed,
    Failed,
    Review,
    Expired,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdvVerdict {
    pub document_verified: bool,
    pub face_match: bool,
    pub face_liveness: bool,
    pub age_over_18: bool,
    pub age_over_21: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_age_years: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_type: Option<String>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct IdvRecord {
    principal: Uuid,
    provider: String,
    provider_session_id: String,
    capture_url: String,
    expires_at: Instant,
    status: IdvStatus,
    verdict: Option<IdvVerdict>,
}

#[derive(Clone, Default)]
pub struct IdvStore {
    inner: Arc<Mutex<HashMap<Uuid, IdvRecord>>>,
    db: Option<DbStore>,
}

#[derive(Clone, Debug, Default)]
pub struct IdvProviderConfig {
    pub capture_base: Option<url::Url>,
}

#[derive(Debug, Deserialize)]
pub struct IdvStartRequest {
    #[serde(default)]
    purpose: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IdvSessionLaunch {
    pub session_id: Uuid,
    pub capture_url: String,
    pub expires_in_seconds: u64,
    pub stores_raw_media: bool,
}

#[derive(Debug, Serialize)]
pub struct IdvSessionStatus {
    pub session_id: Uuid,
    pub status: IdvStatus,
    pub stores_raw_media: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<IdvVerdict>,
}

#[derive(Debug, Deserialize)]
pub struct ProviderEvidence {
    pub document_verified: Option<bool>,
    pub face_match: Option<bool>,
    pub face_liveness: Option<bool>,
    pub age_over_18: Option<bool>,
    pub age_over_21: Option<bool>,
    pub estimated_age_years: Option<u8>,
    pub document_type: Option<String>,
    pub document_confidence: Option<f64>,
    pub face_confidence: Option<f64>,
}

impl IdvStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_db(db: DbStore) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            db: Some(db),
        }
    }

    pub async fn start(
        &self,
        principal: Uuid,
        provider: &str,
        provider_session_id: String,
        capture_url: String,
    ) -> Result<IdvSessionLaunch, AuthError> {
        validate_capture_url(&capture_url)?;
        if !(8..=128).contains(&provider_session_id.len()) {
            return Err(AuthError::Upstream);
        }
        let session_id = Uuid::new_v4();
        if let Some(db) = &self.db {
            return db
                .insert_idv_session(
                    session_id,
                    principal,
                    provider,
                    &provider_session_id,
                    capture_url,
                )
                .await;
        }
        let mut guard = self.inner.lock().await;
        sweep(&mut guard);
        if guard.len() >= MAX_OPEN {
            return Err(AuthError::RateLimited);
        }
        guard.insert(
            session_id,
            IdvRecord {
                principal,
                provider: provider.to_owned(),
                provider_session_id,
                capture_url: capture_url.clone(),
                expires_at: Instant::now() + SESSION_TTL,
                status: IdvStatus::Pending,
                verdict: None,
            },
        );
        Ok(IdvSessionLaunch {
            session_id,
            capture_url,
            expires_in_seconds: SESSION_TTL.as_secs(),
            stores_raw_media: false,
        })
    }

    pub async fn status(
        &self,
        session_id: Uuid,
        principal: Uuid,
    ) -> Result<IdvSessionStatus, AuthError> {
        if let Some(db) = &self.db {
            return db.idv_session_status(session_id, principal).await;
        }
        let mut guard = self.inner.lock().await;
        sweep(&mut guard);
        let record = guard.get(&session_id).ok_or(AuthError::Unauthorized)?;
        if record.principal != principal {
            return Err(AuthError::Unauthorized);
        }
        Ok(IdvSessionStatus {
            session_id,
            status: record.status,
            stores_raw_media: false,
            verdict: record.verdict.clone(),
        })
    }

    pub async fn complete(
        &self,
        session_id: Uuid,
        principal: Uuid,
        evidence: &ProviderEvidence,
    ) -> Result<IdvSessionStatus, AuthError> {
        let verdict = verdict_from_provider(evidence)?;
        let status = if verdict.document_verified && verdict.face_match && verdict.face_liveness {
            IdvStatus::Passed
        } else if evidence.document_verified == Some(false) || evidence.face_liveness == Some(false)
        {
            IdvStatus::Failed
        } else {
            IdvStatus::Review
        };
        if let Some(db) = &self.db {
            return db
                .complete_idv_session(session_id, principal, status, &verdict)
                .await;
        }
        let mut guard = self.inner.lock().await;
        sweep(&mut guard);
        let record = guard.get_mut(&session_id).ok_or(AuthError::Unauthorized)?;
        if record.principal != principal || Instant::now() >= record.expires_at {
            return Err(AuthError::Unauthorized);
        }
        record.verdict = Some(verdict.clone());
        record.status = status;
        Ok(IdvSessionStatus {
            session_id,
            status: record.status,
            stores_raw_media: false,
            verdict: Some(verdict),
        })
    }
}

/// Normalize vendor fields. Missing age claims stay false (fail closed for
/// age-gated product actions). Confidence outside 0..=1 is rejected.
pub fn verdict_from_provider(evidence: &ProviderEvidence) -> Result<IdvVerdict, AuthError> {
    for confidence in [evidence.document_confidence, evidence.face_confidence] {
        if confidence.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
            return Err(AuthError::BadRequest("invalid provider confidence"));
        }
    }
    if let Some(age) = evidence.estimated_age_years {
        if age > 120 {
            return Err(AuthError::BadRequest("invalid estimated age"));
        }
    }
    if let Some(kind) = evidence.document_type.as_deref() {
        if kind.is_empty()
            || kind.len() > 32
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(AuthError::BadRequest("invalid document type"));
        }
    }
    let estimated = evidence.estimated_age_years;
    Ok(IdvVerdict {
        document_verified: evidence.document_verified == Some(true),
        face_match: evidence.face_match == Some(true),
        face_liveness: evidence.face_liveness == Some(true),
        age_over_18: evidence.age_over_18 == Some(true) || estimated.is_some_and(|age| age >= 18),
        age_over_21: evidence.age_over_21 == Some(true) || estimated.is_some_and(|age| age >= 21),
        estimated_age_years: estimated,
        document_type: evidence.document_type.clone(),
    })
}

fn validate_capture_url(url: &str) -> Result<(), AuthError> {
    let parsed = url::Url::parse(url).map_err(|_| AuthError::Upstream)?;
    if parsed.scheme() != "https" {
        return Err(AuthError::Upstream);
    }
    Ok(())
}

fn sweep(map: &mut HashMap<Uuid, IdvRecord>) {
    let now = Instant::now();
    map.retain(|_, record| now < record.expires_at);
}

async fn caller(state: &AppState, headers: &HeaderMap) -> Result<Uuid, AuthError> {
    let token = bearer(headers).ok_or(AuthError::Unauthorized)?;
    let claims = state.minter.verify(token)?;
    Uuid::parse_str(&claims.sub).map_err(|_| AuthError::Unauthorized)
}

pub async fn start_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IdvStartRequest>,
) -> Result<Json<IdvSessionLaunch>, AuthError> {
    let principal = caller(&state, &headers).await?;
    if let Some(purpose) = request.purpose.as_deref() {
        if !matches!(purpose, "identity" | "age") {
            return Err(AuthError::BadRequest("purpose must be identity or age"));
        }
    }
    let base = state
        .idv_provider
        .capture_base
        .as_ref()
        .ok_or(AuthError::Unavailable)?;
    let provider_session = format!("idv_{}", Uuid::new_v4().as_simple());
    let capture_url = format!(
        "{}/{}",
        base.as_str().trim_end_matches('/'),
        provider_session
    );
    let launch = state
        .idv
        .start(principal, "external-idv", provider_session, capture_url)
        .await?;
    Ok(Json(launch))
}

pub async fn session_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<Json<IdvSessionStatus>, AuthError> {
    let principal = caller(&state, &headers).await?;
    Ok(Json(state.idv.status(session_id, principal).await?))
}

pub async fn complete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
    Json(evidence): Json<ProviderEvidence>,
) -> Result<Json<IdvSessionStatus>, AuthError> {
    let principal = caller(&state, &headers).await?;
    Ok(Json(
        state.idv.complete(session_id, principal, &evidence).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_fail_closed_unless_vendor_or_estimate_proves_it() {
        let young = verdict_from_provider(&ProviderEvidence {
            document_verified: Some(true),
            face_match: Some(true),
            face_liveness: Some(true),
            age_over_18: None,
            age_over_21: None,
            estimated_age_years: Some(17),
            document_type: Some("passport".into()),
            document_confidence: Some(0.9),
            face_confidence: Some(0.9),
        })
        .unwrap();
        assert!(young.document_verified);
        assert!(!young.age_over_18);
        assert!(!young.age_over_21);

        let adult = verdict_from_provider(&ProviderEvidence {
            document_verified: Some(true),
            face_match: Some(true),
            face_liveness: Some(true),
            age_over_18: None,
            age_over_21: None,
            estimated_age_years: Some(34),
            document_type: Some("drivers_license".into()),
            document_confidence: Some(0.95),
            face_confidence: Some(0.92),
        })
        .unwrap();
        assert!(adult.age_over_18);
        assert!(adult.age_over_21);
    }

    #[test]
    fn rejects_non_https_capture_and_bad_confidence() {
        assert!(validate_capture_url("http://evil.example/x").is_err());
        assert!(validate_capture_url("https://vendor.example/capture").is_ok());
        assert!(verdict_from_provider(&ProviderEvidence {
            document_verified: Some(true),
            face_match: Some(true),
            face_liveness: Some(true),
            age_over_18: Some(true),
            age_over_21: Some(true),
            estimated_age_years: None,
            document_type: Some("passport".into()),
            document_confidence: Some(1.5),
            face_confidence: Some(0.2),
        })
        .is_err());
    }

    #[tokio::test]
    async fn other_principal_cannot_read_or_complete() {
        let store = IdvStore::new();
        let owner = Uuid::new_v4();
        let other = Uuid::new_v4();
        let launch = store
            .start(
                owner,
                "persona",
                "idv_abcd1234".into(),
                "https://vendor.example/c".into(),
            )
            .await
            .unwrap();
        assert!(!launch.stores_raw_media);
        assert!(store.status(launch.session_id, other).await.is_err());
        assert!(store
            .complete(
                launch.session_id,
                other,
                &ProviderEvidence {
                    document_verified: Some(true),
                    face_match: Some(true),
                    face_liveness: Some(true),
                    age_over_18: Some(true),
                    age_over_21: Some(true),
                    estimated_age_years: None,
                    document_type: Some("passport".into()),
                    document_confidence: Some(0.9),
                    face_confidence: Some(0.9),
                }
            )
            .await
            .is_err());
    }
}
