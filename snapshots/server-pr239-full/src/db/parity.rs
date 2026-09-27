//! Durable DML for risk signals, QR challenges, and IDV sessions.
//!
//! Schema lives in `db/schema.sql`. This module never stores raw IP, device
//! hints, ID photos, or face material — only hashes, classes, and vendor
//! verdicts. `stores_raw_media` stays false.

use chrono::{DateTime, Utc};
use sea_orm::ConnectionTrait;
use uuid::Uuid;

use super::{db_error, statement, DbStore};
use crate::error::AuthError;
use crate::idv::{IdvSessionLaunch, IdvSessionStatus, IdvStatus, IdvVerdict};
use crate::qr::{QrChallengeResponse, QrPurpose, QrStatus, QrStatusResponse};
use crate::risk::{IpClass, RiskDecision, RiskEvaluateResponse};

const QR_TTL_SECS: i64 = 120;
const IDV_TTL_SECS: i64 = 900;
const MAX_OPEN: i64 = 256;

pub struct QrInsert {
    pub challenge_id: Uuid,
    pub purpose: QrPurpose,
    pub nonce_hash: String,
    pub created_for: Option<Uuid>,
    pub expires_in_seconds: u64,
    pub qr_payload: String,
    pub label: Option<String>,
}

impl DbStore {
    pub async fn record_risk_signal(
        &self,
        shared_user_id: Option<Uuid>,
        evaluation: &RiskEvaluateResponse,
    ) -> Result<(), AuthError> {
        let ip_hash = evaluation
            .ip_hash
            .clone()
            .unwrap_or_else(|| format!("{:_<43}", "unspecified"));
        if ip_hash.len() != 43 {
            return Err(AuthError::Internal);
        }
        if evaluation
            .fingerprint_hash
            .as_ref()
            .is_some_and(|hash| hash.len() != 43)
        {
            return Err(AuthError::Internal);
        }
        let signals = evaluation.signals.join(",");
        self.db
            .execute_raw(statement(
                "INSERT INTO shared_auth.risk_signals \
                    (shared_user_id, ip_hash, ip_class, fingerprint_hash, \
                     decision, score, signals, embedding_similarity) \
                 VALUES ($1, $2, $3, $4, $5, $6, \
                    CASE WHEN $7 = '' THEN '{}'::text[] ELSE string_to_array($7, ',') END, \
                    $8)",
                vec![
                    shared_user_id.into(),
                    ip_hash.into(),
                    ip_class_sql(evaluation.ip_class).into(),
                    evaluation.fingerprint_hash.clone().into(),
                    decision_sql(evaluation.decision).into(),
                    i16::from(evaluation.score).into(),
                    signals.into(),
                    evaluation.embedding_similarity.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        Ok(())
    }

    pub async fn insert_qr_challenge(
        &self,
        insert: QrInsert,
    ) -> Result<QrChallengeResponse, AuthError> {
        if let Some(principal) = insert.created_for {
            self.require_principal(principal).await?;
        }
        self.enforce_open_qr_budget().await?;
        let expires_at = Utc::now() + chrono::Duration::seconds(QR_TTL_SECS);
        self.db
            .execute_raw(statement(
                "INSERT INTO shared_auth.qr_challenges \
                    (challenge_id, purpose, nonce_hash, created_for, expires_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                vec![
                    insert.challenge_id.into(),
                    purpose_sql(insert.purpose).into(),
                    insert.nonce_hash.into(),
                    insert.created_for.into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        Ok(QrChallengeResponse {
            challenge_id: insert.challenge_id,
            expires_in_seconds: insert.expires_in_seconds,
            qr_payload: insert.qr_payload,
            purpose: insert.purpose,
            label: insert.label,
        })
    }

    pub async fn approve_qr_challenge(
        &self,
        challenge_id: Uuid,
        nonce_hash: &str,
        principal: Uuid,
        purpose: QrPurpose,
    ) -> Result<QrStatusResponse, AuthError> {
        self.require_principal(principal).await?;
        let row = self
            .db
            .query_one_raw(statement(
                "UPDATE shared_auth.qr_challenges \
                 SET approved_by = $3 \
                 WHERE challenge_id = $1 \
                   AND nonce_hash = $2 \
                   AND purpose = $4 \
                   AND consumed_at IS NULL \
                   AND expires_at > clock_timestamp() \
                   AND (purpose = 'login' OR created_for = $3) \
                 RETURNING challenge_id, purpose, approved_by, consumed_at, expires_at",
                vec![
                    challenge_id.into(),
                    nonce_hash.to_owned().into(),
                    principal.into(),
                    purpose_sql(purpose).into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        qr_status_from_row(&row, false)
    }

    pub async fn poll_qr_challenge(
        &self,
        challenge_id: Uuid,
        consume: bool,
    ) -> Result<QrStatusResponse, AuthError> {
        let Some(row) = self
            .db
            .query_one_raw(statement(
                "SELECT challenge_id, purpose, approved_by, consumed_at, expires_at \
                 FROM shared_auth.qr_challenges WHERE challenge_id = $1",
                vec![challenge_id.into()],
            ))
            .await
            .map_err(db_error)?
        else {
            return Ok(hidden_pending(challenge_id));
        };
        let consumed_at: Option<DateTime<Utc>> =
            row.try_get("", "consumed_at").map_err(db_error)?;
        if consumed_at.is_some() {
            return Ok(hidden_pending(challenge_id));
        }
        let approved_by: Option<Uuid> = row.try_get("", "approved_by").map_err(db_error)?;
        if consume && approved_by.is_some() {
            let consumed = self
                .db
                .query_one_raw(statement(
                    "UPDATE shared_auth.qr_challenges \
                     SET consumed_at = clock_timestamp() \
                     WHERE challenge_id = $1 AND consumed_at IS NULL AND approved_by IS NOT NULL \
                     RETURNING challenge_id, purpose, approved_by, consumed_at, expires_at",
                    vec![challenge_id.into()],
                ))
                .await
                .map_err(db_error)?;
            if let Some(consumed) = consumed {
                return qr_status_from_row(&consumed, true);
            }
            return Ok(hidden_pending(challenge_id));
        }
        qr_status_from_row(&row, false)
    }

    pub async fn insert_idv_session(
        &self,
        session_id: Uuid,
        principal: Uuid,
        provider: &str,
        provider_session_id: &str,
        capture_url: String,
    ) -> Result<IdvSessionLaunch, AuthError> {
        self.require_principal(principal).await?;
        self.enforce_open_idv_budget().await?;
        let expires_at = Utc::now() + chrono::Duration::seconds(IDV_TTL_SECS);
        self.db
            .execute_raw(statement(
                "INSERT INTO shared_auth.idv_sessions \
                    (session_id, shared_user_id, provider, provider_session_id, \
                     status, stores_raw_media, expires_at) \
                 VALUES ($1, $2, $3, $4, 'pending', false, $5)",
                vec![
                    session_id.into(),
                    principal.into(),
                    provider.to_owned().into(),
                    provider_session_id.to_owned().into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        Ok(IdvSessionLaunch {
            session_id,
            capture_url,
            expires_in_seconds: u64::try_from(IDV_TTL_SECS).unwrap_or(900),
            stores_raw_media: false,
        })
    }

    pub async fn idv_session_status(
        &self,
        session_id: Uuid,
        principal: Uuid,
    ) -> Result<IdvSessionStatus, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT session_id, status, document_verified, face_match, face_liveness, \
                        age_over_18, age_over_21, estimated_age_years, document_type, expires_at \
                 FROM shared_auth.idv_sessions \
                 WHERE session_id = $1 AND shared_user_id = $2",
                vec![session_id.into(), principal.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        idv_status_from_row(&row)
    }

    pub async fn complete_idv_session(
        &self,
        session_id: Uuid,
        principal: Uuid,
        status: IdvStatus,
        verdict: &IdvVerdict,
    ) -> Result<IdvSessionStatus, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "UPDATE shared_auth.idv_sessions \
                 SET status = $3, document_verified = $4, face_match = $5, face_liveness = $6, \
                     age_over_18 = $7, age_over_21 = $8, estimated_age_years = $9, \
                     document_type = $10, completed_at = clock_timestamp() \
                 WHERE session_id = $1 AND shared_user_id = $2 \
                   AND status = 'pending' AND expires_at > clock_timestamp() \
                 RETURNING session_id, status, document_verified, face_match, face_liveness, \
                           age_over_18, age_over_21, estimated_age_years, document_type, expires_at",
                vec![
                    session_id.into(),
                    principal.into(),
                    idv_status_sql(status).into(),
                    verdict.document_verified.into(),
                    verdict.face_match.into(),
                    verdict.face_liveness.into(),
                    verdict.age_over_18.into(),
                    verdict.age_over_21.into(),
                    verdict.estimated_age_years.map(i16::from).into(),
                    verdict.document_type.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        idv_status_from_row(&row)
    }

    async fn require_principal(&self, principal: Uuid) -> Result<(), AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT 1 AS present FROM shared_auth.principals WHERE shared_user_id = $1",
                vec![principal.into()],
            ))
            .await
            .map_err(db_error)?;
        if row.is_none() {
            return Err(AuthError::Unauthorized);
        }
        Ok(())
    }

    async fn enforce_open_qr_budget(&self) -> Result<(), AuthError> {
        let count = open_count(
            &self.db,
            "SELECT count(*)::bigint AS open_count FROM shared_auth.qr_challenges \
             WHERE consumed_at IS NULL AND expires_at > clock_timestamp()",
        )
        .await?;
        if count >= MAX_OPEN {
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }

    async fn enforce_open_idv_budget(&self) -> Result<(), AuthError> {
        let count = open_count(
            &self.db,
            "SELECT count(*)::bigint AS open_count FROM shared_auth.idv_sessions \
             WHERE status = 'pending' AND expires_at > clock_timestamp()",
        )
        .await?;
        if count >= MAX_OPEN {
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }
}

async fn open_count(db: &sea_orm::DatabaseConnection, sql: &str) -> Result<i64, AuthError> {
    let row = db
        .query_one_raw(statement(sql, vec![]))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Internal)?;
    row.try_get("", "open_count").map_err(db_error)
}

fn hidden_pending(challenge_id: Uuid) -> QrStatusResponse {
    QrStatusResponse {
        challenge_id,
        status: QrStatus::Pending,
        purpose: QrPurpose::Login,
        approved_principal: None,
    }
}

fn qr_status_from_row(
    row: &sea_orm::QueryResult,
    just_consumed: bool,
) -> Result<QrStatusResponse, AuthError> {
    let challenge_id: Uuid = row.try_get("", "challenge_id").map_err(db_error)?;
    let purpose = parse_purpose(&row.try_get::<String>("", "purpose").map_err(db_error)?)?;
    let approved_by: Option<Uuid> = row.try_get("", "approved_by").map_err(db_error)?;
    let consumed_at: Option<DateTime<Utc>> = row.try_get("", "consumed_at").map_err(db_error)?;
    let expires_at: DateTime<Utc> = row.try_get("", "expires_at").map_err(db_error)?;
    let status = if just_consumed || consumed_at.is_some() {
        QrStatus::Consumed
    } else if Utc::now() >= expires_at {
        QrStatus::Expired
    } else if approved_by.is_some() {
        QrStatus::Approved
    } else {
        QrStatus::Pending
    };
    Ok(QrStatusResponse {
        challenge_id,
        status,
        purpose,
        approved_principal: approved_by.map(|id| id.to_string()),
    })
}

fn idv_status_from_row(row: &sea_orm::QueryResult) -> Result<IdvSessionStatus, AuthError> {
    let session_id: Uuid = row.try_get("", "session_id").map_err(db_error)?;
    let status = parse_idv_status(&row.try_get::<String>("", "status").map_err(db_error)?)?;
    let expires_at: DateTime<Utc> = row.try_get("", "expires_at").map_err(db_error)?;
    let status = if status == IdvStatus::Pending && Utc::now() >= expires_at {
        IdvStatus::Expired
    } else {
        status
    };
    let document_verified: Option<bool> = row.try_get("", "document_verified").map_err(db_error)?;
    let verdict = document_verified.map(|document_verified| IdvVerdict {
        document_verified,
        face_match: row
            .try_get("", "face_match")
            .ok()
            .flatten()
            .unwrap_or(false),
        face_liveness: row
            .try_get("", "face_liveness")
            .ok()
            .flatten()
            .unwrap_or(false),
        age_over_18: row
            .try_get("", "age_over_18")
            .ok()
            .flatten()
            .unwrap_or(false),
        age_over_21: row
            .try_get("", "age_over_21")
            .ok()
            .flatten()
            .unwrap_or(false),
        estimated_age_years: row
            .try_get::<Option<i16>>("", "estimated_age_years")
            .ok()
            .flatten()
            .and_then(|years| u8::try_from(years).ok()),
        document_type: row.try_get("", "document_type").ok().flatten(),
    });
    Ok(IdvSessionStatus {
        session_id,
        status,
        stores_raw_media: false,
        verdict,
    })
}

fn purpose_sql(purpose: QrPurpose) -> &'static str {
    match purpose {
        QrPurpose::Login => "login",
        QrPurpose::DeviceBind => "device_bind",
    }
}

fn parse_purpose(raw: &str) -> Result<QrPurpose, AuthError> {
    match raw {
        "login" => Ok(QrPurpose::Login),
        "device_bind" => Ok(QrPurpose::DeviceBind),
        _ => Err(AuthError::Internal),
    }
}

fn idv_status_sql(status: IdvStatus) -> &'static str {
    match status {
        IdvStatus::Pending => "pending",
        IdvStatus::Passed => "passed",
        IdvStatus::Failed => "failed",
        IdvStatus::Review => "review",
        IdvStatus::Expired => "expired",
    }
}

fn parse_idv_status(raw: &str) -> Result<IdvStatus, AuthError> {
    match raw {
        "pending" => Ok(IdvStatus::Pending),
        "passed" => Ok(IdvStatus::Passed),
        "failed" => Ok(IdvStatus::Failed),
        "review" => Ok(IdvStatus::Review),
        "expired" => Ok(IdvStatus::Expired),
        _ => Err(AuthError::Internal),
    }
}

fn ip_class_sql(class: IpClass) -> &'static str {
    match class {
        IpClass::Public => "public",
        IpClass::Private => "private",
        IpClass::Loopback => "loopback",
        IpClass::LinkLocal => "link_local",
        IpClass::Unspecified => "unspecified",
        IpClass::Invalid => "invalid",
    }
}

fn decision_sql(decision: RiskDecision) -> &'static str {
    match decision {
        RiskDecision::Allow => "allow",
        RiskDecision::Warn => "warn",
        RiskDecision::StepUp => "step_up",
        RiskDecision::Deny => "deny",
    }
}
