//! Durable workload identity state.
//!
//! This store borrows the realm database pool from [`DbStore`] and keeps
//! workload principals/sessions completely separate from human principals and
//! `shared_auth.sessions`.

use std::sync::Arc;

use chrono::{DateTime, FixedOffset, Utc};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

use crate::db::DbStore;
use crate::error::AuthError;
use crate::oauth_as::{scope_is_wellformed, MAX_SCOPE_ENTRIES, MAX_SCOPE_LEN};

use super::{
    WorkloadClientBinding, WorkloadPrincipal, WorkloadSessionSnapshot, WorkloadStatus,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedWorkloadBinding {
    pub principal: WorkloadPrincipal,
    pub binding: WorkloadClientBinding,
    pub oauth_client_allowed_scopes: Vec<String>,
}

#[derive(Clone)]
pub struct WorkloadStore {
    db: Arc<DatabaseConnection>,
}

impl WorkloadStore {
    pub fn new(db: &DbStore) -> Self {
        return Self {
            db: db.connection(),
        };
    }

    /// Resolve one active confidential OAuth client to one active workload
    /// principal. The SQL re-checks application ownership even though the
    /// database trigger enforces it at write time; request-time authorization
    /// never relies on a historic invariant remaining true by assumption.
    pub async fn resolve_active_client(
        &self,
        client_id: &str,
    ) -> Result<Option<ResolvedWorkloadBinding>, AuthError> {
        let Some(row) = self
            .db
            .query_one_raw(statement(
                "SELECT \
                    s.service_account_id, \
                    s.application_id, \
                    s.status AS service_status, \
                    s.auth_epoch, \
                    b.client_id, \
                    b.status AS binding_status, \
                    b.credential_epoch, \
                    b.allowed_scopes AS workload_allowed_scopes, \
                    b.default_scopes, \
                    c.audience, \
                    c.allowed_scopes AS oauth_allowed_scopes \
                 FROM shared_auth.oauth_client_workload_bindings b \
                 JOIN shared_auth.service_accounts s \
                   ON s.service_account_id = b.service_account_id \
                 JOIN shared_auth.oauth_clients c \
                   ON c.client_id = b.client_id \
                 JOIN shared_auth.applications a \
                   ON a.application_id = c.application_id \
                 WHERE b.client_id = $1 \
                   AND b.status = 'active' \
                   AND s.status = 'active' \
                   AND c.status = 'active' \
                   AND c.client_type = 'confidential' \
                   AND a.status = 'active' \
                   AND s.application_id = c.application_id",
                vec![client_id.to_owned().into()],
            ))
            .await
            .map_err(db_error)?
        else {
            return Ok(None);
        };

        let service_status: String = row.try_get("", "service_status").map_err(db_error)?;
        let binding_status: String = row.try_get("", "binding_status").map_err(db_error)?;
        let application_id: Uuid = row.try_get("", "application_id").map_err(db_error)?;
        let service_account_id: Uuid = row
            .try_get("", "service_account_id")
            .map_err(db_error)?;

        let principal = WorkloadPrincipal {
            service_account_id,
            application_id,
            status: parse_status(&service_status)?,
            auth_epoch: nonnegative_epoch(row.try_get("", "auth_epoch").map_err(db_error)?)?,
        };
        let binding = WorkloadClientBinding {
            client_id: row.try_get("", "client_id").map_err(db_error)?,
            service_account_id,
            application_id,
            audience: row.try_get("", "audience").map_err(db_error)?,
            status: parse_status(&binding_status)?,
            credential_epoch: nonnegative_epoch(
                row.try_get("", "credential_epoch").map_err(db_error)?,
            )?,
            allowed_scopes: scope_list(
                row.try_get("", "workload_allowed_scopes")
                    .map_err(db_error)?,
                true,
            )?,
            default_scopes: scope_list(
                row.try_get("", "default_scopes").map_err(db_error)?,
                true,
            )?,
        };
        let oauth_client_allowed_scopes = scope_list(
            row.try_get("", "oauth_allowed_scopes").map_err(db_error)?,
            false,
        )?;

        return Ok(Some(ResolvedWorkloadBinding {
            principal,
            binding,
            oauth_client_allowed_scopes,
        }));
    }

    /// Insert the revocation anchor for a freshly minted workload token.
    ///
    /// The caller supplies the exact principal/binding snapshot it just
    /// authorized. The INSERT re-checks both epochs and all active states in one
    /// statement so a concurrent disable/rotation cannot race between an
    /// authorization read and session creation.
    pub async fn create_session(
        &self,
        resolved: &ResolvedWorkloadBinding,
        scopes: &[String],
        expires_at: DateTime<FixedOffset>,
    ) -> Result<Option<WorkloadSessionSnapshot>, AuthError> {
        let effective = resolved
            .binding
            .effective_scope(scopes, &resolved.oauth_client_allowed_scopes)
            .map_err(|_| AuthError::Forbidden)?;
        if effective != scopes {
            return Err(AuthError::Forbidden);
        }

        if expires_at <= Utc::now().fixed_offset() {
            return Err(AuthError::Internal);
        }

        let scopes_json = serde_json::Value::Array(
            scopes
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        );

        let Some(row) = self
            .db
            .query_one_raw(statement(
                "INSERT INTO shared_auth.workload_sessions ( \
                    service_account_id, client_id, service_account_auth_epoch, \
                    credential_epoch, audience, scopes, expires_at) \
                 SELECT \
                    s.service_account_id, b.client_id, s.auth_epoch, \
                    b.credential_epoch, c.audience, $6, $7 \
                 FROM shared_auth.service_accounts s \
                 JOIN shared_auth.oauth_client_workload_bindings b \
                   ON b.service_account_id = s.service_account_id \
                 JOIN shared_auth.oauth_clients c \
                   ON c.client_id = b.client_id \
                 JOIN shared_auth.applications a \
                   ON a.application_id = c.application_id \
                 WHERE s.service_account_id = $1 \
                   AND s.application_id = $2 \
                   AND b.client_id = $3 \
                   AND s.auth_epoch = $4 \
                   AND b.credential_epoch = $5 \
                   AND s.status = 'active' \
                   AND b.status = 'active' \
                   AND c.status = 'active' \
                   AND c.client_type = 'confidential' \
                   AND a.status = 'active' \
                   AND s.application_id = c.application_id \
                 RETURNING session_id, service_account_id, client_id, \
                           service_account_auth_epoch, credential_epoch, \
                           audience, scopes, expires_at, revoked_at",
                vec![
                    resolved.principal.service_account_id.into(),
                    resolved.principal.application_id.into(),
                    resolved.binding.client_id.clone().into(),
                    i64::try_from(resolved.principal.auth_epoch)
                        .map_err(|_| AuthError::Internal)?
                        .into(),
                    i64::try_from(resolved.binding.credential_epoch)
                        .map_err(|_| AuthError::Internal)?
                        .into(),
                    scopes_json.into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?
        else {
            return Ok(None);
        };

        let expires_at: DateTime<FixedOffset> =
            row.try_get("", "expires_at").map_err(db_error)?;
        let revoked_at: Option<DateTime<FixedOffset>> =
            row.try_get("", "revoked_at").map_err(db_error)?;

        return Ok(Some(WorkloadSessionSnapshot {
            session_id: row.try_get("", "session_id").map_err(db_error)?,
            service_account_id: row
                .try_get("", "service_account_id")
                .map_err(db_error)?,
            client_id: row.try_get("", "client_id").map_err(db_error)?,
            application_id: resolved.principal.application_id,
            service_account_auth_epoch: nonnegative_epoch(
                row.try_get("", "service_account_auth_epoch")
                    .map_err(db_error)?,
            )?,
            credential_epoch: nonnegative_epoch(
                row.try_get("", "credential_epoch").map_err(db_error)?,
            )?,
            audience: row.try_get("", "audience").map_err(db_error)?,
            scopes: scope_list(row.try_get("", "scopes").map_err(db_error)?, true)?,
            expires_at_unix: u64::try_from(expires_at.timestamp()).map_err(|_| AuthError::Internal)?,
            revoked: revoked_at.is_some(),
        }));
    }

    /// Re-evaluate a workload session against the current principal, binding,
    /// OAuth client, and application state. Any mismatch returns `None`; callers
    /// should report an inactive credential rather than disclose which part was
    /// revoked or reconfigured.
    pub async fn active_session(
        &self,
        session_id: Uuid,
        client_id: &str,
    ) -> Result<Option<WorkloadSessionSnapshot>, AuthError> {
        let Some(row) = self
            .db
            .query_one_raw(statement(
                "SELECT \
                    w.session_id, w.service_account_id, w.client_id, \
                    s.application_id, w.service_account_auth_epoch, \
                    w.credential_epoch, w.audience, w.scopes, \
                    w.expires_at, w.revoked_at \
                 FROM shared_auth.workload_sessions w \
                 JOIN shared_auth.service_accounts s \
                   ON s.service_account_id = w.service_account_id \
                 JOIN shared_auth.oauth_client_workload_bindings b \
                   ON b.client_id = w.client_id \
                  AND b.service_account_id = w.service_account_id \
                 JOIN shared_auth.oauth_clients c \
                   ON c.client_id = b.client_id \
                 JOIN shared_auth.applications a \
                   ON a.application_id = c.application_id \
                 WHERE w.session_id = $1 \
                   AND w.client_id = $2 \
                   AND w.revoked_at IS NULL \
                   AND w.expires_at > now() \
                   AND s.status = 'active' \
                   AND b.status = 'active' \
                   AND c.status = 'active' \
                   AND c.client_type = 'confidential' \
                   AND a.status = 'active' \
                   AND s.application_id = c.application_id \
                   AND w.service_account_auth_epoch = s.auth_epoch \
                   AND w.credential_epoch = b.credential_epoch \
                   AND w.audience = c.audience",
                vec![session_id.into(), client_id.to_owned().into()],
            ))
            .await
            .map_err(db_error)?
        else {
            return Ok(None);
        };

        let expires_at: DateTime<FixedOffset> =
            row.try_get("", "expires_at").map_err(db_error)?;
        let revoked_at: Option<DateTime<FixedOffset>> =
            row.try_get("", "revoked_at").map_err(db_error)?;

        return Ok(Some(WorkloadSessionSnapshot {
            session_id: row.try_get("", "session_id").map_err(db_error)?,
            service_account_id: row
                .try_get("", "service_account_id")
                .map_err(db_error)?,
            client_id: row.try_get("", "client_id").map_err(db_error)?,
            application_id: row.try_get("", "application_id").map_err(db_error)?,
            service_account_auth_epoch: nonnegative_epoch(
                row.try_get("", "service_account_auth_epoch")
                    .map_err(db_error)?,
            )?,
            credential_epoch: nonnegative_epoch(
                row.try_get("", "credential_epoch").map_err(db_error)?,
            )?,
            audience: row.try_get("", "audience").map_err(db_error)?,
            scopes: scope_list(row.try_get("", "scopes").map_err(db_error)?, true)?,
            expires_at_unix: u64::try_from(expires_at.timestamp()).map_err(|_| AuthError::Internal)?,
            revoked: revoked_at.is_some(),
        }));
    }

    /// Idempotently revoke one workload session owned by one client.
    pub async fn revoke_session(
        &self,
        session_id: Uuid,
        client_id: &str,
    ) -> Result<bool, AuthError> {
        let result = self
            .db
            .execute_raw(statement(
                "UPDATE shared_auth.workload_sessions \
                    SET revoked_at = COALESCE(revoked_at, now()) \
                  WHERE session_id = $1 AND client_id = $2",
                vec![session_id.into(), client_id.to_owned().into()],
            ))
            .await
            .map_err(db_error)?;
        return Ok(result.rows_affected() > 0);
    }
}

pub fn expiry_from_now(ttl_secs: i64) -> Result<DateTime<FixedOffset>, AuthError> {
    if ttl_secs <= 0 {
        return Err(AuthError::Internal);
    }

    return Ok(Utc::now().fixed_offset() + chrono::TimeDelta::seconds(ttl_secs));
}

fn parse_status(value: &str) -> Result<WorkloadStatus, AuthError> {
    return match value {
        "active" => Ok(WorkloadStatus::Active),
        "disabled" => Ok(WorkloadStatus::Disabled),
        _ => {
            tracing::error!("stored workload status violates the status grammar");
            Err(AuthError::Internal)
        }
    };
}

fn nonnegative_epoch(value: i64) -> Result<u64, AuthError> {
    return u64::try_from(value).map_err(|_| {
        tracing::error!("stored workload epoch is negative");
        AuthError::Internal
    });
}

fn scope_list(
    value: serde_json::Value,
    reject_human_protocol_scopes: bool,
) -> Result<Vec<String>, AuthError> {
    let serde_json::Value::Array(entries) = value else {
        tracing::error!("stored workload scope list is not an array");
        return Err(AuthError::Internal);
    };

    if entries.len() > MAX_SCOPE_ENTRIES {
        tracing::error!("stored workload scope list exceeds its bound");
        return Err(AuthError::Internal);
    }

    let mut scopes: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let serde_json::Value::String(scope) = entry else {
            tracing::error!("stored workload scope is not a string");
            return Err(AuthError::Internal);
        };

        if scope.len() > MAX_SCOPE_LEN || !scope_is_wellformed(&scope) {
            tracing::error!("stored workload scope violates the scope grammar");
            return Err(AuthError::Internal);
        }

        if reject_human_protocol_scopes && matches!(scope.as_str(), "openid" | "offline_access") {
            tracing::error!("stored workload scope contains a human protocol scope");
            return Err(AuthError::Internal);
        }

        if scopes.iter().any(|existing| existing == &scope) {
            tracing::error!("stored workload scope list contains a duplicate");
            return Err(AuthError::Internal);
        }

        scopes.push(scope);
    }

    scopes.sort_unstable();
    return Ok(scopes);
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    return Statement::from_sql_and_values(DbBackend::Postgres, sql, values);
}

fn db_error<E>(_error: E) -> AuthError {
    tracing::error!("shared-auth workload store operation failed");
    return AuthError::Upstream;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parser_is_closed() {
        assert_eq!(parse_status("active"), Ok(WorkloadStatus::Active));
        assert_eq!(parse_status("disabled"), Ok(WorkloadStatus::Disabled));
        assert!(parse_status("unknown").is_err());
    }

    #[test]
    fn scope_parser_rejects_human_protocol_scopes() {
        let value = serde_json::json!(["service:read", "openid"]);
        assert!(scope_list(value, true).is_err());
    }

    #[test]
    fn scope_parser_allows_empty_default_set() {
        let value = serde_json::json!([]);
        assert_eq!(scope_list(value, true).unwrap(), Vec::<String>::new());
    }
}
