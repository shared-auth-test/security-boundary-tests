//! Postgres-backed identity, credential, role, and session store.
//!
//! `db/schema.sql` is the declarative schema and this module executes DML only.
//! Postgres is authoritative. Supabase and future providers are represented by
//! rows in `provider_identities`, so adding an adapter does not change the core
//! user/session model.

use std::sync::Arc;

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction, DbBackend,
    Statement, TransactionTrait,
};
use uuid::Uuid;

use crate::config::DbConfig;
use crate::directory_grants::{DirectoryAdminGrant, StoredDirectoryAdminGrantSet};
use crate::error::AuthError;
use crate::revocation::{
    admin_opaque_hash, admin_opaque_hash_matches, decode_email_search_hmac_key,
    email_search_key_hash, email_search_key_id, generate_selection_token,
    normalize_email_search_alias, normalize_global_scopes, valid_contract_identifier,
    valid_email_search_key_hash, valid_idempotency_key, valid_reason_code, CommittedRevocation,
    PrincipalSelector, RevocationBlastRadius, RevocationCandidate, RevocationJob,
    RevocationOperator, RevocationScope, RevocationTargetStatus, StoredCommitAuthorization,
    StoredRevocationPreview, StoredRevocationSearch, StoredRevocationSelection,
    REVOCATION_OPERATOR_ROLE,
};
use crate::supabase::VerifiedIdentity;

mod parity;
pub(crate) use parity::QrInsert;

const IDENTITY_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6e, 0x7f, 0x92, 0x29, 0x8a, 0xe2, 0x4b, 0x3f, 0x9a, 0xd7, 0x38, 0x0a, 0xb8, 0xdd, 0x73, 0x2b,
]);

fn auth_methods_json(auth_methods: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        auth_methods
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    )
}

fn auth_methods_from_json(value: serde_json::Value) -> Result<Vec<String>, AuthError> {
    let serde_json::Value::Array(methods) = value else {
        return Err(AuthError::Internal);
    };
    let methods = methods
        .into_iter()
        .map(|method| match method {
            serde_json::Value::String(method)
                if !method.is_empty()
                    && method.len() <= 64
                    && method.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                    }) =>
            {
                Ok(method)
            }
            _ => Err(AuthError::Internal),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if methods.is_empty() || methods.len() > 16 {
        return Err(AuthError::Internal);
    }
    Ok(methods)
}

#[derive(Clone, Debug)]
pub struct AuthenticatedIdentity {
    pub shared_user_id: Uuid,
    pub provider: String,
    pub provider_tenant: String,
    pub provider_subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct LocalCredential {
    pub identity: AuthenticatedIdentity,
    pub password_hash: String,
    pub locked: bool,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub session_id: Uuid,
    pub identity: AuthenticatedIdentity,
    pub expires_at: chrono::DateTime<chrono::FixedOffset>,
    pub auth_level: u8,
    pub auth_methods: Vec<String>,
    pub auth_epoch: u64,
}

#[derive(Clone)]
pub struct DbStore {
    db: Arc<DatabaseConnection>,
    admin_email_search_hmac_key: Option<Arc<Vec<u8>>>,
    admin_email_search_key_id: Option<Arc<str>>,
}

impl DbStore {
    pub async fn connect(config: &DbConfig) -> anyhow::Result<Self> {
        let mut options = ConnectOptions::new(config.url.clone());
        options
            .max_connections(config.max_connections)
            .min_connections(1)
            .connect_timeout(std::time::Duration::from_secs(5))
            .acquire_timeout(std::time::Duration::from_secs(5))
            .idle_timeout(std::time::Duration::from_secs(300))
            .sqlx_logging(false);
        let db = Database::connect(options).await?;
        let admin_email_search_hmac_key = match config.admin_email_search_hmac_key.as_deref() {
            Some(value) => Some(Arc::new(decode_email_search_hmac_key(value).ok_or_else(
                || anyhow::anyhow!("invalid configured admin email search HMAC key"),
            )?)),
            None => None,
        };
        let admin_email_search_key_id = admin_email_search_hmac_key
            .as_deref()
            .map(|key| Arc::<str>::from(email_search_key_id(key)));
        Ok(Self {
            db: Arc::new(db),
            admin_email_search_hmac_key,
            admin_email_search_key_id,
        })
    }

    fn indexed_email_search_values(
        &self,
        email: Option<&str>,
        email_verified: bool,
    ) -> Result<(Option<String>, Option<String>), AuthError> {
        if !email_verified {
            return Ok((None, None));
        }
        let Some(email) = email else {
            return Ok((None, None));
        };
        let Some(key) = self.admin_email_search_hmac_key.as_deref() else {
            return Ok((None, None));
        };
        let normalized = normalize_email_search_alias(email)
            .ok_or(AuthError::BadRequest("invalid verified email alias"))?;
        Ok((
            Some(email_search_key_hash(key, &normalized)),
            self.admin_email_search_key_id.as_deref().map(str::to_owned),
        ))
    }

    /// Share the realm connection pool with a feature module that owns its own
    /// SQL.
    ///
    /// Feature stores in this tree normally open their own bounded pool
    /// (`FactorService`, `PublicKeyService`) because their work is independent
    /// of an identity upsert. SAML federation is not: every one of its
    /// statements runs inside the same request that upserts a provider identity
    /// and inserts a session, so a second pool would only add a second place to
    /// exhaust connections. Handing out the `Arc` keeps one pool and one set of
    /// limits.
    pub(crate) fn connection(&self) -> Arc<DatabaseConnection> {
        Arc::clone(&self.db)
    }

    /// Open a transaction and take `pg_advisory_xact_lock` for `key`.
    /// The lock is released automatically on commit or rollback — never unlock
    /// a transaction-scoped advisory lock with `pg_advisory_unlock`.
    pub async fn begin_advisory_xact(&self, key: &str) -> Result<DatabaseTransaction, AuthError> {
        crate::locks::validate_lock_key(key)?;
        let txn = self.db.begin().await.map_err(db_error)?;
        self.lock_advisory_xact(&txn, key).await?;
        Ok(txn)
    }

    /// Take `pg_advisory_xact_lock` on an already-open transaction.
    pub async fn lock_advisory_xact(
        &self,
        txn: &DatabaseTransaction,
        key: &str,
    ) -> Result<(), AuthError> {
        crate::locks::validate_lock_key(key)?;
        txn.query_one_raw(statement(
            "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 913742)) AS locked",
            vec![crate::locks::advisory_lock_name(key).into()],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Internal)?;
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), AuthError> {
        self.db.ping().await.map_err(|_error| {
            // Database errors can embed DSNs or rejected column values. Keep
            // readiness telemetry coarse so secret URLs and identity aliases
            // never enter logs.
            tracing::warn!("Postgres readiness check failed");
            AuthError::Upstream
        })
    }

    /// Materialize the keyed verified-email alias index under the configured
    /// generation. This is an explicit administrative bootstrap/rotation step;
    /// request handling never performs a surprise full-table rewrite.
    pub async fn materialize_admin_email_search_index(&self) -> Result<u64, AuthError> {
        let key = self
            .admin_email_search_hmac_key
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let key_id = self
            .admin_email_search_key_id
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let transaction = self.db.begin().await.map_err(db_error)?;
        transaction
            .query_one_raw(statement(
                "SELECT pg_advisory_xact_lock(1963742381) AS locked",
                vec![],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        transaction
            .execute_raw(statement(
                "DELETE FROM shared_auth.admin_email_search_index_state",
                vec![],
            ))
            .await
            .map_err(db_error)?;

        let mut materialized = 0_u64;
        loop {
            let rows = transaction
                .query_all_raw(statement(
                    "SELECT provider_identity_id, email \
                     FROM shared_auth.provider_identities \
                     WHERE email_verified = true AND email IS NOT NULL \
                       AND (email_search_key_id IS DISTINCT FROM $1 \
                            OR email_search_key_hash IS NULL) \
                     ORDER BY provider_identity_id LIMIT 500 FOR UPDATE",
                    vec![key_id.to_owned().into()],
                ))
                .await
                .map_err(db_error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let identity_id: Uuid =
                    row.try_get("", "provider_identity_id").map_err(db_error)?;
                let email: String = row.try_get("", "email").map_err(db_error)?;
                let normalized = normalize_email_search_alias(&email)
                    .ok_or(AuthError::BadRequest("invalid verified email alias"))?;
                let digest = email_search_key_hash(key, &normalized);
                transaction
                    .execute_raw(statement(
                        "UPDATE shared_auth.provider_identities \
                         SET email_search_key_hash = $2, email_search_key_id = $3, \
                             updated_at = clock_timestamp() \
                         WHERE provider_identity_id = $1",
                        vec![identity_id.into(), digest.into(), key_id.to_owned().into()],
                    ))
                    .await
                    .map_err(db_error)?;
                materialized = materialized.checked_add(1).ok_or(AuthError::Internal)?;
            }
        }
        let count = transaction
            .query_one_raw(statement(
                "SELECT count(*) AS verified_identity_count \
                 FROM shared_auth.provider_identities \
                 WHERE email_verified = true AND email IS NOT NULL",
                vec![],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        let verified_identity_count: i64 = count
            .try_get("", "verified_identity_count")
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.admin_email_search_index_state \
                    (singleton, email_search_key_id, verified_identity_count, materialized_at) \
                 VALUES (true, $1, $2, clock_timestamp()) \
                 ON CONFLICT (singleton) DO UPDATE SET \
                    email_search_key_id = EXCLUDED.email_search_key_id, \
                    verified_identity_count = EXCLUDED.verified_identity_count, \
                    materialized_at = EXCLUDED.materialized_at",
                vec![key_id.to_owned().into(), verified_identity_count.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(materialized)
    }

    /// Fail closed unless every currently searchable identity belongs to the
    /// configured HMAC-key generation. This is checked at startup and again in
    /// each search transaction to catch out-of-band identity writes.
    pub async fn assert_admin_email_search_index_ready(&self) -> Result<(), AuthError> {
        let key_id = self
            .admin_email_search_key_id
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT state.email_search_key_id, state.verified_identity_count, \
                        current.verified_identity_count AS current_identity_count, \
                        current.stale_identity_count \
                 FROM shared_auth.admin_email_search_index_state state \
                 CROSS JOIN ( \
                    SELECT count(*) AS verified_identity_count, \
                           count(*) FILTER (WHERE email_search_key_id IS DISTINCT FROM $1 \
                                             OR email_search_key_hash IS NULL) \
                               AS stale_identity_count \
                    FROM shared_auth.provider_identities \
                    WHERE email_verified = true AND email IS NOT NULL \
                 ) current \
                 WHERE state.singleton = true",
                vec![key_id.to_owned().into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unavailable)?;
        let stored_key_id: String = row.try_get("", "email_search_key_id").map_err(db_error)?;
        let stored_count: i64 = row
            .try_get("", "verified_identity_count")
            .map_err(db_error)?;
        let current_count: i64 = row
            .try_get("", "current_identity_count")
            .map_err(db_error)?;
        let stale_count: i64 = row.try_get("", "stale_identity_count").map_err(db_error)?;
        if stored_key_id != key_id || stored_count != current_count || stale_count != 0 {
            return Err(AuthError::Unavailable);
        }
        Ok(())
    }

    /// Resolve a verified Supabase identity into the provider-neutral user
    /// namespace. We never auto-link accounts merely because emails match.
    pub async fn upsert_supabase_identity(
        &self,
        identity: &VerifiedIdentity,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        self.upsert_external_identity(
            "supabase",
            &identity.project,
            &identity.supabase_user_id,
            identity.email.clone(),
            identity.email_verified,
            serde_json::json!({
                "phone": identity.phone,
                "role": identity.role,
                "user_metadata": identity.user_metadata,
                "app_metadata": identity.app_metadata,
            }),
        )
        .await
    }

    pub async fn upsert_external_identity(
        &self,
        provider: &str,
        provider_tenant: &str,
        provider_subject: &str,
        email: Option<String>,
        email_verified: bool,
        metadata: serde_json::Value,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        let (email_search_key_hash, email_search_key_id) =
            self.indexed_email_search_values(email.as_deref(), email_verified)?;
        let transaction = self.db.begin().await.map_err(db_error)?;

        let existing = transaction
            .query_one_raw(statement(
                "SELECT shared_user_id FROM shared_auth.provider_identities \
                 WHERE provider = $1 AND provider_tenant = $2 AND provider_subject = $3",
                vec![
                    provider.to_owned().into(),
                    provider_tenant.to_owned().into(),
                    provider_subject.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;

        let stable_name = format!("{provider}\0{provider_tenant}\0{provider_subject}");
        let shared_user_id = existing
            .as_ref()
            .and_then(|row| row.try_get("", "shared_user_id").ok())
            .unwrap_or_else(|| Uuid::new_v5(&IDENTITY_NAMESPACE, stable_name.as_bytes()));

        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.principals (shared_user_id, last_seen_at) \
                 VALUES ($1, now()) \
                 ON CONFLICT (shared_user_id) DO UPDATE \
                 SET last_seen_at = now(), updated_at = now()",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;

        let row = transaction
            .query_one_raw(statement(
                "INSERT INTO shared_auth.provider_identities \
                    (shared_user_id, provider, provider_tenant, provider_subject, email, \
                     email_verified, email_search_key_hash, email_search_key_id, metadata, \
                     last_seen_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now()) \
                 ON CONFLICT (provider, provider_tenant, provider_subject) DO UPDATE SET \
                    email = EXCLUDED.email, \
                    email_verified = EXCLUDED.email_verified, \
                    email_search_key_hash = EXCLUDED.email_search_key_hash, \
                    email_search_key_id = EXCLUDED.email_search_key_id, \
                    metadata = EXCLUDED.metadata, \
                    updated_at = now(), last_seen_at = now() \
                 RETURNING shared_user_id, provider, provider_tenant, provider_subject, \
                           email, email_verified",
                vec![
                    shared_user_id.into(),
                    provider.to_owned().into(),
                    provider_tenant.to_owned().into(),
                    provider_subject.to_owned().into(),
                    email.into(),
                    email_verified.into(),
                    email_search_key_hash.into(),
                    email_search_key_id.into(),
                    metadata.into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;

        transaction.commit().await.map_err(db_error)?;
        let mut resolved = identity_from_row(&row)?;
        resolved.roles = self.roles_for(shared_user_id).await?;
        Ok(resolved)
    }

    pub async fn create_local_user(
        &self,
        email: &str,
        display_name: Option<&str>,
        password_hash: &str,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        let shared_user_id = Uuid::new_v4();
        let subject = shared_user_id.to_string();

        let inserted = transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.principals \
                    (shared_user_id, email, email_verified, display_name) \
                 VALUES ($1, $2, false, $3)",
                vec![
                    shared_user_id.into(),
                    email.to_owned().into(),
                    display_name.map(str::to_owned).into(),
                ],
            ))
            .await;
        if let Err(_error) = inserted {
            tracing::info!("local registration conflicted");
            return Err(AuthError::Conflict);
        }

        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.provider_identities \
                    (shared_user_id, provider, provider_tenant, provider_subject, email) \
                 VALUES ($1, 'local', 'default', $2, $3)",
                vec![
                    shared_user_id.into(),
                    subject.clone().into(),
                    email.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.local_credentials (shared_user_id, password_hash) \
                 VALUES ($1, $2)",
                vec![shared_user_id.into(), password_hash.to_owned().into()],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.roles (shared_user_id, role_name) VALUES ($1, 'user')",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;

        Ok(AuthenticatedIdentity {
            shared_user_id,
            provider: "local".into(),
            provider_tenant: "default".into(),
            provider_subject: subject,
            email: Some(email.to_owned()),
            email_verified: false,
            roles: vec!["user".into()],
        })
    }

    /// Prepare a passwordless login without exposing whether the address exists.
    ///
    /// When signup is enabled, a new provider-neutral principal is created. A
    /// password account with the same verified address reuses its principal, but
    /// external provider identities are never linked merely because their email
    /// claim happens to match.
    pub async fn prepare_magic_link(
        &self,
        email: &str,
        allow_signup: bool,
        token_hash: &str,
        otp_hash: &str,
        identifier_hash: &str,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> Result<bool, AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        let recent = transaction
            .query_one_raw(statement(
                "SELECT count(*)::bigint AS count \
                 FROM shared_auth.magic_link_tokens \
                 WHERE identifier_hash = $1 AND created_at > now() - interval '15 minutes'",
                vec![identifier_hash.to_owned().into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        let recent_count: i64 = recent.try_get("", "count").map_err(db_error)?;
        if recent_count >= 5 {
            transaction.rollback().await.map_err(db_error)?;
            return Ok(false);
        }

        let existing = transaction
            .query_one_raw(statement(
                "SELECT shared_user_id FROM shared_auth.principals \
                 WHERE lower(email) = $1 AND status = 'active'",
                vec![email.to_owned().into()],
            ))
            .await
            .map_err(db_error)?;
        let shared_user_id: Uuid = if let Some(row) = existing {
            row.try_get("", "shared_user_id").map_err(db_error)?
        } else if allow_signup {
            let candidate = Uuid::new_v4();
            transaction
                .execute_raw(statement(
                    "INSERT INTO shared_auth.principals \
                        (shared_user_id, email, email_verified) \
                     VALUES ($1, $2, false) \
                     ON CONFLICT DO NOTHING",
                    vec![candidate.into(), email.to_owned().into()],
                ))
                .await
                .map_err(db_error)?;
            transaction
                .query_one_raw(statement(
                    "SELECT shared_user_id FROM shared_auth.principals \
                     WHERE lower(email) = $1 AND status = 'active'",
                    vec![email.to_owned().into()],
                ))
                .await
                .map_err(db_error)?
                .ok_or(AuthError::Conflict)?
                .try_get("", "shared_user_id")
                .map_err(db_error)?
        } else {
            transaction.rollback().await.map_err(db_error)?;
            return Ok(false);
        };
        let subject = shared_user_id.to_string();

        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.provider_identities \
                    (shared_user_id, provider, provider_tenant, provider_subject, email) \
                 VALUES ($1, 'magic_link', 'default', $2, $3) \
                 ON CONFLICT (provider, provider_tenant, provider_subject) DO UPDATE SET \
                    email = EXCLUDED.email, updated_at = now(), last_seen_at = now()",
                vec![
                    shared_user_id.into(),
                    subject.into(),
                    email.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.roles (shared_user_id, role_name) \
                 VALUES ($1, 'user') ON CONFLICT DO NOTHING",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.magic_link_tokens SET consumed_at = now() \
                 WHERE shared_user_id = $1 AND consumed_at IS NULL",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.magic_link_tokens \
                    (token_hash, otp_hash, shared_user_id, identifier_hash, expires_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                vec![
                    token_hash.to_owned().into(),
                    otp_hash.to_owned().into(),
                    shared_user_id.into(),
                    identifier_hash.to_owned().into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(true)
    }

    /// Atomically consume a passwordless token and return its verified identity.
    pub async fn consume_magic_link(
        &self,
        token_hash: &str,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        let consumed = transaction
            .query_one_raw(statement(
                "UPDATE shared_auth.magic_link_tokens SET consumed_at = now() \
                 WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
                 RETURNING shared_user_id",
                vec![token_hash.to_owned().into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let shared_user_id: Uuid = consumed.try_get("", "shared_user_id").map_err(db_error)?;
        let row = verify_magic_link_identity(
            &transaction,
            shared_user_id,
            self.admin_email_search_hmac_key
                .as_deref()
                .map(Vec::as_slice),
            self.admin_email_search_key_id.as_deref(),
        )
        .await?;
        transaction.commit().await.map_err(db_error)?;
        let mut identity = identity_from_row(&row)?;
        identity.roles = self.roles_for(shared_user_id).await?;
        Ok(identity)
    }

    /// Consume a six-digit email OTP with a strict attempt cap.
    pub async fn consume_email_otp(
        &self,
        identifier_hash: &str,
        otp_hash: &str,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        let consumed = transaction
            .query_one_raw(statement(
                "UPDATE shared_auth.magic_link_tokens SET consumed_at = now() \
                 WHERE token_hash = ( \
                    SELECT token_hash FROM shared_auth.magic_link_tokens \
                    WHERE identifier_hash = $1 AND otp_hash = $2 \
                      AND consumed_at IS NULL AND expires_at > now() \
                      AND failed_attempts < 5 \
                    ORDER BY created_at DESC LIMIT 1 FOR UPDATE \
                 ) \
                 RETURNING shared_user_id",
                vec![
                    identifier_hash.to_owned().into(),
                    otp_hash.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        let Some(consumed) = consumed else {
            transaction
                .execute_raw(statement(
                    "UPDATE shared_auth.magic_link_tokens SET \
                        failed_attempts = LEAST(failed_attempts + 1, 5), \
                        consumed_at = CASE WHEN failed_attempts + 1 >= 5 \
                                           THEN now() ELSE consumed_at END \
                     WHERE token_hash = ( \
                        SELECT token_hash FROM shared_auth.magic_link_tokens \
                        WHERE identifier_hash = $1 AND consumed_at IS NULL \
                          AND expires_at > now() \
                        ORDER BY created_at DESC LIMIT 1 FOR UPDATE \
                     )",
                    vec![identifier_hash.to_owned().into()],
                ))
                .await
                .map_err(db_error)?;
            transaction.commit().await.map_err(db_error)?;
            return Err(AuthError::Unauthorized);
        };
        let shared_user_id: Uuid = consumed.try_get("", "shared_user_id").map_err(db_error)?;
        let row = verify_magic_link_identity(
            &transaction,
            shared_user_id,
            self.admin_email_search_hmac_key
                .as_deref()
                .map(Vec::as_slice),
            self.admin_email_search_key_id.as_deref(),
        )
        .await?;
        transaction.commit().await.map_err(db_error)?;
        let mut identity = identity_from_row(&row)?;
        identity.roles = self.roles_for(shared_user_id).await?;
        Ok(identity)
    }

    pub async fn phone_for_user(&self, shared_user_id: Uuid) -> Result<Option<String>, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT phone FROM shared_auth.principals \
                 WHERE shared_user_id = $1 AND status = 'active'",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        row.try_get("", "phone").map_err(db_error)
    }

    pub async fn create_sms_challenge(
        &self,
        shared_user_id: Uuid,
        phone_e164: &str,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> Result<Uuid, AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.mfa_sms_challenges SET verified_at = now() \
                 WHERE shared_user_id = $1 AND verified_at IS NULL",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        let challenge_id = Uuid::new_v4();
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.mfa_sms_challenges \
                    (challenge_id, shared_user_id, phone_e164, expires_at) \
                 VALUES ($1, $2, $3, $4)",
                vec![
                    challenge_id.into(),
                    shared_user_id.into(),
                    phone_e164.to_owned().into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(challenge_id)
    }

    pub async fn sms_challenge_phone(
        &self,
        shared_user_id: Uuid,
        challenge_id: Uuid,
    ) -> Result<String, AuthError> {
        self.db
            .query_one_raw(statement(
                "SELECT phone_e164 FROM shared_auth.mfa_sms_challenges \
                 WHERE challenge_id = $1 AND shared_user_id = $2 \
                   AND verified_at IS NULL AND expires_at > now()",
                vec![challenge_id.into(), shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?
            .try_get("", "phone_e164")
            .map_err(db_error)
    }

    pub async fn complete_sms_challenge(
        &self,
        shared_user_id: Uuid,
        challenge_id: Uuid,
    ) -> Result<(), AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        let row = transaction
            .query_one_raw(statement(
                "UPDATE shared_auth.mfa_sms_challenges SET verified_at = now() \
                 WHERE challenge_id = $1 AND shared_user_id = $2 \
                   AND verified_at IS NULL AND expires_at > now() \
                 RETURNING phone_e164",
                vec![challenge_id.into(), shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let phone: String = row.try_get("", "phone_e164").map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.principals SET phone = $2, updated_at = now() \
                 WHERE shared_user_id = $1 AND status = 'active'",
                vec![shared_user_id.into(), phone.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(())
    }

    pub async fn local_credential(
        &self,
        normalized_email: &str,
    ) -> Result<Option<LocalCredential>, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT u.shared_user_id, 'local' AS provider, 'default' AS provider_tenant, \
                        u.shared_user_id::text AS provider_subject, u.email, u.email_verified, \
                        c.password_hash, \
                        (c.locked_until IS NOT NULL AND c.locked_until > now()) AS locked \
                 FROM shared_auth.principals u \
                 JOIN shared_auth.local_credentials c USING (shared_user_id) \
                 WHERE lower(u.email) = $1 AND u.status = 'active'",
                vec![normalized_email.to_owned().into()],
            ))
            .await
            .map_err(db_error)?;
        let Some(row) = row else { return Ok(None) };
        let mut identity = identity_from_row(&row)?;
        identity.roles = self.roles_for(identity.shared_user_id).await?;
        Ok(Some(LocalCredential {
            identity,
            password_hash: row.try_get("", "password_hash").map_err(db_error)?,
            locked: row.try_get("", "locked").map_err(db_error)?,
        }))
    }

    pub async fn record_login_result(
        &self,
        shared_user_id: Uuid,
        success: bool,
    ) -> Result<(), AuthError> {
        let sql = if success {
            "UPDATE shared_auth.local_credentials SET failed_attempts = 0, locked_until = NULL, \
             updated_at = now() WHERE shared_user_id = $1"
        } else {
            "UPDATE shared_auth.local_credentials SET \
             failed_attempts = failed_attempts + 1, \
             locked_until = CASE WHEN failed_attempts + 1 >= 5 \
                                 THEN now() + interval '15 minutes' ELSE locked_until END, \
             updated_at = now() WHERE shared_user_id = $1"
        };
        self.db
            .execute_raw(statement(sql, vec![shared_user_id.into()]))
            .await
            .map_err(db_error)?;
        Ok(())
    }

    pub async fn create_session(
        &self,
        identity: AuthenticatedIdentity,
        refresh_token_hash: &str,
        expires_at: chrono::DateTime<chrono::FixedOffset>,
        rotated_from: Option<Uuid>,
        auth_level: u8,
        auth_methods: &[String],
    ) -> Result<SessionRecord, AuthError> {
        let session_id = Uuid::new_v4();
        let transaction = self.db.begin().await.map_err(db_error)?;
        // Principal-first locking gives global revocation one linearization
        // point. If this login wins the shared lock, the later global commit
        // revokes it; if the global commit wins, this session receives the new
        // epoch and is a genuinely post-revocation login.
        let principal = transaction
            .query_one_raw(statement(
                "SELECT auth_epoch FROM shared_auth.principals \
                 WHERE shared_user_id = $1 AND status = 'active' FOR SHARE",
                vec![identity.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let auth_epoch: i64 = principal.try_get("", "auth_epoch").map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.sessions \
                    (session_id, shared_user_id, refresh_token_hash, provider, provider_tenant, \
                     provider_subject, expires_at, rotated_from, auth_level, auth_methods, \
                     auth_epoch, created_at, updated_at, last_seen_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                         clock_timestamp(), clock_timestamp(), clock_timestamp())",
                vec![
                    session_id.into(),
                    identity.shared_user_id.into(),
                    refresh_token_hash.to_owned().into(),
                    identity.provider.clone().into(),
                    identity.provider_tenant.clone().into(),
                    identity.provider_subject.clone().into(),
                    expires_at.into(),
                    rotated_from.into(),
                    i16::from(auth_level).into(),
                    auth_methods_json(auth_methods).into(),
                    auth_epoch.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(SessionRecord {
            session_id,
            identity,
            expires_at,
            auth_level,
            auth_methods: auth_methods.to_vec(),
            auth_epoch: u64::try_from(auth_epoch).map_err(|_| AuthError::Internal)?,
        })
    }

    /// Atomically consume a refresh token and replace it. A replay sees the old
    /// row as revoked and is rejected, preventing parallel refresh reuse.
    pub async fn rotate_session(
        &self,
        old_hash: &str,
        new_hash: &str,
        new_expires_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> Result<SessionRecord, AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        // Discover the principal without taking a session lock, then acquire
        // locks in the same principal -> session order used by the global
        // revocation transaction. This avoids a refresh/revocation deadlock.
        let owner = transaction
            .query_one_raw(statement(
                "SELECT shared_user_id FROM shared_auth.sessions \
                 WHERE refresh_token_hash = $1",
                vec![old_hash.to_owned().into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let owner_id: Uuid = owner.try_get("", "shared_user_id").map_err(db_error)?;
        let principal = transaction
            .query_one_raw(statement(
                "SELECT auth_epoch, auth_not_before FROM shared_auth.principals \
                 WHERE shared_user_id = $1 AND status = 'active' FOR SHARE",
                vec![owner_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let auth_epoch: i64 = principal.try_get("", "auth_epoch").map_err(db_error)?;
        let auth_not_before: chrono::DateTime<chrono::FixedOffset> =
            principal.try_get("", "auth_not_before").map_err(db_error)?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT s.session_id, s.shared_user_id, s.provider, s.provider_tenant, \
                        s.provider_subject, COALESCE(pi.email, u.email) AS email, \
                        COALESCE(pi.email_verified, u.email_verified) AS email_verified, \
                        s.auth_level, s.auth_methods, s.auth_epoch \
                 FROM shared_auth.sessions s \
                 JOIN shared_auth.principals u USING (shared_user_id) \
                 LEFT JOIN shared_auth.provider_identities pi \
                   ON pi.shared_user_id = s.shared_user_id AND pi.provider = s.provider \
                  AND pi.provider_tenant = s.provider_tenant \
                  AND pi.provider_subject = s.provider_subject \
                 WHERE s.refresh_token_hash = $1 AND s.shared_user_id = $2 \
                   AND s.revoked_at IS NULL AND s.expires_at > now() \
                   AND u.status = 'active' AND s.auth_epoch = $3 \
                   AND s.created_at >= $4 \
                 FOR UPDATE OF s",
                vec![
                    old_hash.to_owned().into(),
                    owner_id.into(),
                    auth_epoch.into(),
                    auth_not_before.into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let old_session_id: Uuid = row.try_get("", "session_id").map_err(db_error)?;
        let auth_level: i16 = row.try_get("", "auth_level").map_err(db_error)?;
        let auth_methods = auth_methods_from_json(
            row.try_get::<serde_json::Value>("", "auth_methods")
                .map_err(db_error)?,
        )?;
        let mut identity = identity_from_row(&row)?;

        let revoked = transaction
            .execute_raw(statement(
                "UPDATE shared_auth.sessions SET revoked_at = now(), updated_at = now() \
                 WHERE session_id = $1 AND revoked_at IS NULL",
                vec![old_session_id.into()],
            ))
            .await
            .map_err(db_error)?;
        if revoked.rows_affected() != 1 {
            return Err(AuthError::Unauthorized);
        }

        let new_session_id = Uuid::new_v4();
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.sessions \
                    (session_id, shared_user_id, refresh_token_hash, provider, provider_tenant, \
                     provider_subject, expires_at, rotated_from, auth_level, auth_methods, \
                     auth_epoch, created_at, updated_at, last_seen_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                         clock_timestamp(), clock_timestamp(), clock_timestamp())",
                vec![
                    new_session_id.into(),
                    identity.shared_user_id.into(),
                    new_hash.to_owned().into(),
                    identity.provider.clone().into(),
                    identity.provider_tenant.clone().into(),
                    identity.provider_subject.clone().into(),
                    new_expires_at.into(),
                    old_session_id.into(),
                    auth_level.into(),
                    auth_methods_json(&auth_methods).into(),
                    auth_epoch.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        identity.roles = self.roles_for(identity.shared_user_id).await?;
        Ok(SessionRecord {
            session_id: new_session_id,
            identity,
            expires_at: new_expires_at,
            auth_level: u8::try_from(auth_level).map_err(|_| AuthError::Internal)?,
            auth_methods,
            auth_epoch: u64::try_from(auth_epoch).map_err(|_| AuthError::Internal)?,
        })
    }

    pub async fn revoke_by_refresh_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Uuid>, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "UPDATE shared_auth.sessions SET revoked_at = now(), updated_at = now() \
                 WHERE refresh_token_hash = $1 AND revoked_at IS NULL RETURNING session_id",
                vec![token_hash.to_owned().into()],
            ))
            .await
            .map_err(db_error)?;
        Ok(row.and_then(|row| row.try_get("", "session_id").ok()))
    }

    pub async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        self.db
            .execute_raw(statement(
                "UPDATE shared_auth.sessions SET revoked_at = COALESCE(revoked_at, now()), \
                 updated_at = now() WHERE session_id = $1",
                vec![session_id.into()],
            ))
            .await
            .map_err(db_error)?;
        Ok(())
    }

    /// Revoke every currently-active session for a user and return the affected
    /// session ids. Used when a security-sensitive credential change (removing an
    /// authenticator) must invalidate already-issued access tokens whose assurance
    /// was earned by the now-removed factor. The caller mirrors the returned ids
    /// into the revocation cache so bearer checks fail before their natural TTL.
    pub async fn revoke_sessions_for_user(
        &self,
        shared_user_id: Uuid,
    ) -> Result<Vec<Uuid>, AuthError> {
        let rows = self
            .db
            .query_all_raw(statement(
                "UPDATE shared_auth.sessions SET revoked_at = now(), updated_at = now() \
                 WHERE shared_user_id = $1 AND revoked_at IS NULL AND expires_at > now() \
                 RETURNING session_id",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        rows.into_iter()
            .map(|row| row.try_get("", "session_id").map_err(db_error))
            .collect()
    }

    pub async fn session_is_active(&self, session_id: Uuid) -> Result<bool, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT EXISTS (SELECT 1 FROM shared_auth.sessions s \
                 JOIN shared_auth.principals u USING (shared_user_id) \
                 WHERE s.session_id = $1 AND s.revoked_at IS NULL \
                   AND s.expires_at > now() AND u.status = 'active' \
                   AND s.auth_epoch = u.auth_epoch \
                   AND s.created_at >= u.auth_not_before) AS active",
                vec![session_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        row.try_get("", "active").map_err(db_error)
    }

    pub async fn session_is_active_at_epoch(
        &self,
        session_id: Uuid,
        expected_epoch: u64,
    ) -> Result<bool, AuthError> {
        let expected_epoch = i64::try_from(expected_epoch).map_err(|_| AuthError::Unauthorized)?;
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT EXISTS (SELECT 1 FROM shared_auth.sessions s \
                 JOIN shared_auth.principals u USING (shared_user_id) \
                 WHERE s.session_id = $1 AND s.auth_epoch = $2 \
                   AND s.revoked_at IS NULL AND s.expires_at > now() \
                   AND u.status = 'active' AND s.auth_epoch = u.auth_epoch \
                   AND s.created_at >= u.auth_not_before) AS active",
                vec![session_id.into(), expected_epoch.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        row.try_get("", "active").map_err(db_error)
    }

    /// JWT role claims are snapshots. Privileged control-plane requests also
    /// consult the current Postgres grant so removing an operator role takes
    /// effect without waiting for an access token to expire.
    pub async fn has_active_role(
        &self,
        shared_user_id: Uuid,
        role: &str,
    ) -> Result<bool, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT EXISTS (SELECT 1 FROM shared_auth.roles r \
                 JOIN shared_auth.principals u USING (shared_user_id) \
                 WHERE r.shared_user_id = $1 AND r.role_name = $2 \
                   AND u.status = 'active') AS allowed",
                vec![shared_user_id.into(), role.to_owned().into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        row.try_get("", "allowed").map_err(db_error)
    }

    /// Resolve/create the stable opaque principal identifier exposed by every
    /// admin contract. The authority's internal shared_user_id never crosses
    /// the web control-plane boundary.
    pub async fn admin_principal_ref(&self, shared_user_id: Uuid) -> Result<Uuid, AuthError> {
        ensure_admin_principal_ref(self.db.as_ref(), shared_user_id).await
    }

    pub async fn shared_user_id_for_admin_principal_ref(
        &self,
        principal_ref: Uuid,
    ) -> Result<Uuid, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT r.shared_user_id FROM shared_auth.admin_principal_refs r \
                 JOIN shared_auth.principals p USING (shared_user_id) \
                 WHERE r.principal_ref = $1 AND p.status = 'active'",
                vec![principal_ref.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        row.try_get("", "shared_user_id").map_err(db_error)
    }

    /// Domain-separated keyed identifier used only for redacted admin
    /// contracts and audit correlation. It is never suitable for email lookup.
    pub fn opaque_admin_identifier_hash(
        &self,
        context: &str,
        value: &str,
    ) -> Result<String, AuthError> {
        let key = self
            .admin_email_search_hmac_key
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        Ok(admin_opaque_hash(key, context, value))
    }

    /// Atomically replace one principal's authoritative cross-organization
    /// inventory snapshot. The caller is a trusted directory synchronizer;
    /// browser/admin requests never write this table. An empty organization
    /// list is a known zero only because the same transaction marks the
    /// snapshot complete.
    pub async fn replace_principal_directory_inventory(
        &self,
        shared_user_id: Uuid,
        memberships: &[(Uuid, Vec<Uuid>)],
        source_snapshot_hash: &str,
        observed_at: chrono::DateTime<chrono::FixedOffset>,
    ) -> Result<(), AuthError> {
        if !valid_email_search_key_hash(source_snapshot_hash)
            || memberships.len() > 500
            || memberships.iter().any(|(organization_id, project_ids)| {
                organization_id.is_nil()
                    || project_ids.len() > 200
                    || project_ids.iter().any(Uuid::is_nil)
            })
        {
            return Err(AuthError::BadRequest(
                "invalid directory inventory snapshot",
            ));
        }
        let mut normalized = memberships.to_vec();
        normalized.sort_unstable_by_key(|(organization_id, _)| *organization_id);
        if normalized.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(AuthError::BadRequest("duplicate organization inventory"));
        }
        for (_, project_ids) in &mut normalized {
            project_ids.sort_unstable();
            project_ids.dedup();
        }
        let transaction = self.db.begin().await.map_err(db_error)?;
        transaction
            .query_one_raw(statement(
                "SELECT shared_user_id FROM shared_auth.principals \
                 WHERE shared_user_id = $1 AND status = 'active' FOR UPDATE",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::NotFound)?;
        transaction
            .execute_raw(statement(
                "DELETE FROM shared_auth.principal_organization_memberships \
                 WHERE shared_user_id = $1",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        for (organization_id, project_ids) in normalized {
            transaction
                .execute_raw(statement(
                    "INSERT INTO shared_auth.principal_organization_memberships \
                        (shared_user_id, organization_id, project_ids, \
                         source_snapshot_hash, observed_at) \
                     VALUES ($1, $2, $3, $4, $5)",
                    vec![
                        shared_user_id.into(),
                        organization_id.into(),
                        (!project_ids.is_empty()).then_some(project_ids).into(),
                        source_snapshot_hash.to_owned().into(),
                        observed_at.into(),
                    ],
                ))
                .await
                .map_err(db_error)?;
        }
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.principal_directory_inventory_state \
                    (shared_user_id, inventory_complete, source_snapshot_hash, \
                     observed_at, updated_at) \
                 VALUES ($1, true, $2, $3, clock_timestamp()) \
                 ON CONFLICT (shared_user_id) DO UPDATE \
                 SET inventory_complete = true, source_snapshot_hash = EXCLUDED.source_snapshot_hash, \
                     observed_at = EXCLUDED.observed_at, updated_at = clock_timestamp()",
                vec![
                    shared_user_id.into(),
                    source_snapshot_hash.to_owned().into(),
                    observed_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)
    }

    /// Load the exact current dashboard grants while binding the read to the
    /// presenting principal/session/epoch. Grant issuance and revocation fence
    /// the principal, so this transaction linearizes either before the change
    /// (one already-started request) or after it (the old session is denied).
    pub async fn directory_admin_grants_for_session(
        &self,
        shared_user_id: Uuid,
        session_id: Uuid,
        auth_epoch: u64,
    ) -> Result<Option<StoredDirectoryAdminGrantSet>, AuthError> {
        let auth_epoch = i64::try_from(auth_epoch).map_err(|_| AuthError::Unauthorized)?;
        let transaction = self.db.begin().await.map_err(db_error)?;
        transaction
            .query_one_raw(statement(
                "SELECT shared_user_id FROM shared_auth.principals \
                 WHERE shared_user_id = $1 AND status = 'active' AND auth_epoch = $2 \
                 FOR SHARE",
                vec![shared_user_id.into(), auth_epoch.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        transaction
            .query_one_raw(statement(
                "SELECT s.session_id FROM shared_auth.sessions s \
                 JOIN shared_auth.principals p USING (shared_user_id) \
                 WHERE s.session_id = $1 AND s.shared_user_id = $2 AND s.auth_epoch = $3 \
                   AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() \
                   AND s.created_at >= p.auth_not_before \
                 FOR SHARE",
                vec![session_id.into(), shared_user_id.into(), auth_epoch.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let rows = transaction
            .query_all_raw(statement(
                "SELECT r.principal_ref, g.grant_id, g.organization_id, \
                        to_json(g.project_ids) AS project_ids, to_json(g.scopes) AS scopes, \
                        to_json(g.roles) AS roles, g.granted_at, g.expires_at \
                 FROM shared_auth.admin_principal_refs r \
                 JOIN shared_auth.directory_admin_grants g USING (shared_user_id) \
                 WHERE r.shared_user_id = $1 AND g.revoked_at IS NULL \
                   AND (g.expires_at IS NULL OR g.expires_at > clock_timestamp()) \
                 ORDER BY g.organization_id, g.grant_id LIMIT 501",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        if rows.len() > 500 {
            return Err(AuthError::Forbidden);
        }
        let Some(first) = rows.first() else {
            transaction.commit().await.map_err(db_error)?;
            return Ok(None);
        };
        let principal_ref: Uuid = first.try_get("", "principal_ref").map_err(db_error)?;
        let mut grants = Vec::with_capacity(rows.len());
        for row in rows {
            let row_principal_ref: Uuid = row.try_get("", "principal_ref").map_err(db_error)?;
            if row_principal_ref != principal_ref {
                return Err(AuthError::Internal);
            }
            let project_ids_json: Option<serde_json::Value> =
                row.try_get("", "project_ids").map_err(db_error)?;
            let mut project_ids = project_ids_json
                .map(serde_json::from_value::<Vec<Uuid>>)
                .transpose()
                .map_err(|_| AuthError::Internal)?;
            if let Some(project_ids) = project_ids.as_mut() {
                project_ids.sort_unstable();
            }
            let mut scopes: Vec<String> =
                serde_json::from_value(row.try_get("", "scopes").map_err(db_error)?)
                    .map_err(|_| AuthError::Internal)?;
            scopes.sort_unstable();
            let mut roles: Vec<String> =
                serde_json::from_value(row.try_get("", "roles").map_err(db_error)?)
                    .map_err(|_| AuthError::Internal)?;
            roles.sort_unstable();
            grants.push(DirectoryAdminGrant {
                grant_id: row.try_get("", "grant_id").map_err(db_error)?,
                organization_id: row.try_get("", "organization_id").map_err(db_error)?,
                project_ids,
                scopes,
                roles,
                granted_at: row.try_get("", "granted_at").map_err(db_error)?,
                expires_at: row.try_get("", "expires_at").map_err(db_error)?,
            });
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(Some(StoredDirectoryAdminGrantSet {
            principal_ref,
            grants,
        }))
    }

    /// Find canonical identities through the trusted edge's keyed alias. The
    /// result is discovery only: callers must return one exact principal from
    /// the short-lived candidate set before a preview can be persisted.
    pub async fn global_revocation_candidates(
        &self,
        email_search_key_hash: &str,
    ) -> Result<Vec<RevocationCandidate>, AuthError> {
        if !valid_email_search_key_hash(email_search_key_hash) {
            return Err(AuthError::BadRequest("invalid email search key hash"));
        }
        self.assert_admin_email_search_index_ready().await?;
        let key_id = self
            .admin_email_search_key_id
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let rows = self
            .db
            .query_all_raw(statement(
                "SELECT pi.provider_identity_id, pi.shared_user_id, pi.provider, pi.provider_tenant, \
                        pi.provider_subject, COALESCE(inv.inventory_complete, false) AS inventory_complete, \
                        (SELECT count(*) FROM shared_auth.principal_organization_memberships m \
                         WHERE m.shared_user_id = pi.shared_user_id) AS organization_count, \
                        (SELECT count(*) FROM shared_auth.sessions s WHERE s.shared_user_id = pi.shared_user_id \
                         AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp()) AS active_session_count \
                 FROM shared_auth.provider_identities pi \
                 JOIN shared_auth.principals u USING (shared_user_id) \
                 LEFT JOIN shared_auth.principal_directory_inventory_state inv USING (shared_user_id) \
                 WHERE pi.email_search_key_id = $1 AND pi.email_search_key_hash = $2 \
                   AND pi.email_verified = true \
                   AND u.status = 'active' \
                 ORDER BY pi.provider, pi.provider_tenant, pi.provider_subject \
                 LIMIT 101",
                vec![
                    key_id.to_owned().into(),
                    email_search_key_hash.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            let selector = selector_from_row(&row)?;
            if !row
                .try_get::<bool>("", "inventory_complete")
                .map_err(db_error)?
            {
                return Err(AuthError::Unavailable);
            }
            let provider_tenant_ref = ensure_admin_provider_tenant_ref(
                self.db.as_ref(),
                &selector.provider,
                &selector.provider_tenant,
            )
            .await?;
            candidates.push(RevocationCandidate {
                provider_identity_id: row.try_get("", "provider_identity_id").map_err(db_error)?,
                principal_ref: ensure_admin_principal_ref(
                    self.db.as_ref(),
                    selector.shared_user_id,
                )
                .await?,
                provider_tenant_ref,
                organization_count: nonnegative_count(&row, "organization_count")?,
                active_session_count: nonnegative_count(&row, "active_session_count")?,
                selector,
            });
        }
        Ok(candidates)
    }

    pub async fn revocation_identities_for_principal(
        &self,
        shared_user_id: Uuid,
    ) -> Result<Vec<RevocationCandidate>, AuthError> {
        let rows = self
            .db
            .query_all_raw(statement(
                "SELECT pi.provider_identity_id, pi.shared_user_id, pi.provider, \
                        pi.provider_tenant, pi.provider_subject, \
                        COALESCE(inv.inventory_complete, false) AS inventory_complete, \
                        (SELECT count(*) FROM shared_auth.principal_organization_memberships m \
                         WHERE m.shared_user_id = pi.shared_user_id) AS organization_count, \
                        (SELECT count(*) FROM shared_auth.sessions s WHERE s.shared_user_id = pi.shared_user_id \
                         AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp()) AS active_session_count \
                 FROM shared_auth.provider_identities pi \
                 JOIN shared_auth.principals p USING (shared_user_id) \
                 LEFT JOIN shared_auth.principal_directory_inventory_state inv USING (shared_user_id) \
                 WHERE pi.shared_user_id = $1 AND p.status = 'active' \
                 ORDER BY pi.provider, pi.provider_tenant, pi.provider_subject",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        let principal_ref = ensure_admin_principal_ref(self.db.as_ref(), shared_user_id).await?;
        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            let selector = selector_from_row(&row)?;
            candidates.push(RevocationCandidate {
                provider_identity_id: row.try_get("", "provider_identity_id").map_err(db_error)?,
                principal_ref,
                provider_tenant_ref: ensure_admin_provider_tenant_ref(
                    self.db.as_ref(),
                    &selector.provider,
                    &selector.provider_tenant,
                )
                .await?,
                organization_count: if row
                    .try_get::<bool>("", "inventory_complete")
                    .map_err(db_error)?
                {
                    nonnegative_count(&row, "organization_count")?
                } else {
                    0
                },
                active_session_count: nonnegative_count(&row, "active_session_count")?,
                selector,
            });
        }
        Ok(candidates)
    }

    /// Start a short-lived verified-email search from a digest produced by the
    /// trusted web edge. Raw email is not an argument and cannot be persisted.
    pub async fn begin_global_revocation_search(
        &self,
        operator: RevocationOperator,
        request_id: &str,
        email_search_key_hash: &str,
        ttl_secs: u64,
    ) -> Result<StoredRevocationSearch, AuthError> {
        if !valid_contract_identifier(request_id)
            || !valid_email_search_key_hash(email_search_key_hash)
        {
            return Err(AuthError::BadRequest("invalid principal search request"));
        }
        self.assert_admin_email_search_index_ready().await?;
        let key_id = self
            .admin_email_search_key_id
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let ttl_secs = i64::try_from(ttl_secs).map_err(|_| AuthError::BadRequest("invalid ttl"))?;
        let transaction = self.db.begin().await.map_err(db_error)?;
        lock_revocation_operator_context(
            &transaction,
            operator,
            operator.shared_user_id,
            PrincipalLock::Share,
        )
        .await?;

        // Bound both storage growth and alias enumeration with the Postgres
        // authority. Redis is deliberately not the sole limiter.
        transaction
            .query_one_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 913742)) AS locked",
                vec![operator.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        transaction
            .execute_raw(statement(
                "DELETE FROM shared_auth.global_revocation_searches \
                 WHERE operation_id IN ( \
                   SELECT operation_id FROM shared_auth.global_revocation_searches \
                   WHERE expires_at < clock_timestamp() ORDER BY expires_at LIMIT 100 \
                 )",
                vec![],
            ))
            .await
            .map_err(db_error)?;
        let recent = transaction
            .query_one_raw(statement(
                "SELECT count(*) AS recent_count \
                 FROM shared_auth.global_revocation_searches \
                 WHERE requested_by = $1 \
                   AND created_at > clock_timestamp() - interval '1 minute'",
                vec![operator.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        let recent_count: i64 = recent.try_get("", "recent_count").map_err(db_error)?;
        if recent_count >= 10 {
            return Err(AuthError::RateLimited);
        }

        let rows = transaction
            .query_all_raw(statement(
                "SELECT pi.provider_identity_id, pi.shared_user_id, pi.provider, \
                        pi.provider_tenant, pi.provider_subject, \
                        COALESCE(inv.inventory_complete, false) AS inventory_complete, \
                        (SELECT count(*) FROM shared_auth.principal_organization_memberships m \
                         WHERE m.shared_user_id = pi.shared_user_id) AS organization_count, \
                        (SELECT count(*) FROM shared_auth.sessions s WHERE s.shared_user_id = pi.shared_user_id \
                         AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp()) AS active_session_count \
                 FROM shared_auth.provider_identities pi \
                 JOIN shared_auth.principals u USING (shared_user_id) \
                 LEFT JOIN shared_auth.principal_directory_inventory_state inv USING (shared_user_id) \
                 WHERE pi.email_search_key_id = $1 AND pi.email_search_key_hash = $2 \
                   AND pi.email_verified = true \
                   AND u.status = 'active' \
                 ORDER BY pi.shared_user_id, pi.provider, pi.provider_tenant, \
                          pi.provider_subject LIMIT 101",
                vec![
                    key_id.to_owned().into(),
                    email_search_key_hash.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        if rows.len() > 100 {
            return Err(AuthError::Conflict);
        }
        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            let selector = selector_from_row(&row)?;
            if !row
                .try_get::<bool>("", "inventory_complete")
                .map_err(db_error)?
            {
                return Err(AuthError::Unavailable);
            }
            let provider_tenant_ref = ensure_admin_provider_tenant_ref(
                &transaction,
                &selector.provider,
                &selector.provider_tenant,
            )
            .await?;
            candidates.push(RevocationCandidate {
                provider_identity_id: row.try_get("", "provider_identity_id").map_err(db_error)?,
                principal_ref: ensure_admin_principal_ref(&transaction, selector.shared_user_id)
                    .await?,
                provider_tenant_ref,
                organization_count: nonnegative_count(&row, "organization_count")?,
                active_session_count: nonnegative_count(&row, "active_session_count")?,
                selector,
            });
        }
        let operation_id = Uuid::new_v4();
        let expires_at = chrono::Utc::now().fixed_offset() + chrono::TimeDelta::seconds(ttl_secs);
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.global_revocation_searches \
                    (operation_id, requested_by, requested_by_principal_ref, request_id, \
                     email_search_key_hash, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                vec![
                    operation_id.into(),
                    operator.shared_user_id.into(),
                    operator.principal_ref.into(),
                    request_id.to_owned().into(),
                    email_search_key_hash.to_owned().into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        for candidate in &candidates {
            transaction
                .execute_raw(statement(
                    "INSERT INTO shared_auth.global_revocation_search_candidates \
                        (operation_id, provider_identity_id, shared_user_id, principal_ref, \
                         provider, provider_tenant, provider_tenant_ref, provider_subject) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    vec![
                        operation_id.into(),
                        candidate.provider_identity_id.into(),
                        candidate.selector.shared_user_id.into(),
                        candidate.principal_ref.into(),
                        candidate.selector.provider.clone().into(),
                        candidate.selector.provider_tenant.clone().into(),
                        candidate.provider_tenant_ref.into(),
                        candidate.selector.provider_subject.clone().into(),
                    ],
                ))
                .await
                .map_err(db_error)?;
        }
        transaction.commit().await.map_err(db_error)?;
        Ok(StoredRevocationSearch {
            operation_id,
            request_id: request_id.to_owned(),
            email_search_key_hash: email_search_key_hash.to_owned(),
            expires_at,
            candidates,
        })
    }

    pub async fn select_global_revocation_candidate(
        &self,
        operator: RevocationOperator,
        request_id: &str,
        operation_id: Uuid,
        principal_id: Uuid,
        ttl_secs: u64,
    ) -> Result<StoredRevocationSelection, AuthError> {
        if !valid_contract_identifier(request_id) || principal_id.is_nil() {
            return Err(AuthError::BadRequest("invalid principal selection"));
        }
        let ttl_secs = i64::try_from(ttl_secs).map_err(|_| AuthError::BadRequest("invalid ttl"))?;
        let transaction = self.db.begin().await.map_err(db_error)?;
        let search = transaction
            .query_one_raw(statement(
                "SELECT expires_at \
                 FROM shared_auth.global_revocation_searches \
                 WHERE operation_id = $1 AND requested_by = $2 \
                   AND expires_at > clock_timestamp() \
                 FOR UPDATE",
                vec![operation_id.into(), operator.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;
        let search_expires_at: chrono::DateTime<chrono::FixedOffset> =
            search.try_get("", "expires_at").map_err(db_error)?;
        let selected = transaction
            .query_one_raw(statement(
                "SELECT provider_identity_id, shared_user_id, principal_ref, provider, \
                        provider_tenant, provider_subject \
                 FROM shared_auth.global_revocation_search_candidates \
                 WHERE operation_id = $1 AND principal_ref = $2 \
                 ORDER BY provider, provider_tenant, provider_subject LIMIT 1",
                vec![operation_id.into(), principal_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;
        let provider_identity_id: Uuid = selected
            .try_get("", "provider_identity_id")
            .map_err(db_error)?;
        let target_principal_ref: Uuid = selected.try_get("", "principal_ref").map_err(db_error)?;
        let target = selector_from_row(&selected)?;
        lock_revocation_operator_context(
            &transaction,
            operator,
            target.shared_user_id,
            PrincipalLock::Share,
        )
        .await?;
        transaction
            .query_one_raw(statement(
                "SELECT provider_identity_id FROM shared_auth.provider_identities \
                 WHERE provider_identity_id = $1 AND shared_user_id = $2 \
                   AND provider = $3 AND provider_tenant = $4 AND provider_subject = $5 \
                   AND email_verified = true FOR SHARE",
                vec![
                    provider_identity_id.into(),
                    target.shared_user_id.into(),
                    target.provider.clone().into(),
                    target.provider_tenant.clone().into(),
                    target.provider_subject.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;
        let (selection_id, selection_id_hash) = generate_selection_token();
        let selected_at = chrono::Utc::now().fixed_offset();
        let expires_at =
            (selected_at + chrono::TimeDelta::seconds(ttl_secs)).min(search_expires_at);
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.global_revocation_selections \
                    (selection_id_hash, operation_id, request_id, selected_by, \
                     selected_by_principal_ref, target_shared_user_id, target_principal_ref, \
                     target_provider, target_provider_tenant, target_provider_subject, \
                     selected_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                vec![
                    selection_id_hash.into(),
                    operation_id.into(),
                    request_id.to_owned().into(),
                    operator.shared_user_id.into(),
                    operator.principal_ref.into(),
                    target.shared_user_id.into(),
                    target_principal_ref.into(),
                    target.provider.into(),
                    target.provider_tenant.into(),
                    target.provider_subject.into(),
                    selected_at.into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(StoredRevocationSelection {
            selection_id,
            operation_id,
            target_principal_ref,
            selected_at,
            expires_at,
        })
    }

    pub async fn create_global_revocation_preview_from_selection(
        &self,
        operator: RevocationOperator,
        request_id: &str,
        selection_id: &str,
        scopes: &[RevocationScope],
        ttl_secs: u64,
    ) -> Result<StoredRevocationPreview, AuthError> {
        if !valid_contract_identifier(request_id) || !(32..=128).contains(&selection_id.len()) {
            return Err(AuthError::BadRequest("invalid preview request"));
        }
        let scopes = normalize_global_scopes(scopes.to_vec()).map_err(AuthError::BadRequest)?;
        let opaque_key = self
            .admin_email_search_hmac_key
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let ttl_secs = i64::try_from(ttl_secs).map_err(|_| AuthError::BadRequest("invalid ttl"))?;
        let transaction = self.db.begin().await.map_err(db_error)?;
        let selection_id_hash = crate::session::hash_token(selection_id);
        let row = transaction
            .query_one_raw(statement(
                "SELECT target_shared_user_id AS shared_user_id, target_principal_ref, \
                        target_provider AS provider, target_provider_tenant AS provider_tenant, \
                        target_provider_subject AS provider_subject, expires_at \
                 FROM shared_auth.global_revocation_selections \
                 WHERE selection_id_hash = $1 AND selected_by = $2 \
                   AND preview_id IS NULL AND expires_at > clock_timestamp() FOR UPDATE",
                vec![
                    selection_id_hash.clone().into(),
                    operator.shared_user_id.into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;
        let target = selector_from_row(&row)?;
        let target_principal_ref: Uuid =
            row.try_get("", "target_principal_ref").map_err(db_error)?;
        let selection_expires_at: chrono::DateTime<chrono::FixedOffset> =
            row.try_get("", "expires_at").map_err(db_error)?;
        lock_revocation_operator_context(
            &transaction,
            operator,
            target.shared_user_id,
            PrincipalLock::Share,
        )
        .await?;
        transaction
            .query_one_raw(statement(
                "SELECT provider_identity_id FROM shared_auth.provider_identities \
                 WHERE shared_user_id = $1 AND provider = $2 AND provider_tenant = $3 \
                   AND provider_subject = $4 AND email_verified = true FOR SHARE",
                vec![
                    target.shared_user_id.into(),
                    target.provider.clone().into(),
                    target.provider_tenant.clone().into(),
                    target.provider_subject.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;
        let remaining_selection_ttl =
            (selection_expires_at - chrono::Utc::now().fixed_offset()).num_seconds();
        if remaining_selection_ttl <= 0 {
            return Err(AuthError::Conflict);
        }
        let preview = insert_global_revocation_preview(
            &transaction,
            opaque_key,
            operator,
            &selection_id_hash,
            request_id,
            target_principal_ref,
            &target,
            &scopes,
            ttl_secs.min(remaining_selection_ttl),
        )
        .await?;
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.global_revocation_selections SET preview_id = $2 \
                 WHERE selection_id_hash = $1",
                vec![selection_id_hash.into(), preview.preview_id.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(preview)
    }

    pub async fn global_revocation_preview(
        &self,
        preview_id: Uuid,
    ) -> Result<StoredRevocationPreview, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT preview_id, previewed_by, previewed_by_principal_ref, created_at, \
                        target_principal_ref, target_shared_user_id AS shared_user_id, \
                        target_provider AS provider, \
                        target_provider_tenant AS provider_tenant, \
                        target_provider_subject AS provider_subject, requested_scopes, \
                        blast_radius, expires_at \
                 FROM shared_auth.global_revocation_previews \
                 WHERE preview_id = $1 AND committed_job_id IS NULL \
                   AND expires_at > clock_timestamp()",
                vec![preview_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::NotFound)?;
        stored_revocation_preview_from_row(&row)
    }

    pub async fn create_global_revocation_commit_authorization(
        &self,
        operator: RevocationOperator,
        preview_id: Uuid,
        verified_at: chrono::DateTime<chrono::FixedOffset>,
        fresh_until: chrono::DateTime<chrono::FixedOffset>,
        evidence_id: &str,
    ) -> Result<StoredCommitAuthorization, AuthError> {
        let opaque_key = self
            .admin_email_search_hmac_key
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let now = chrono::Utc::now().fixed_offset();
        if evidence_id.is_empty()
            || evidence_id.len() > 128
            || verified_at > now + chrono::TimeDelta::seconds(30)
            || fresh_until <= now
            || fresh_until <= verified_at
        {
            return Err(AuthError::StepUpRequired);
        }
        let transaction = self.db.begin().await.map_err(db_error)?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT preview_id, previewed_by, previewed_by_principal_ref, created_at, \
                        target_principal_ref, target_shared_user_id AS shared_user_id, \
                        target_provider AS provider, target_provider_tenant AS provider_tenant, \
                        target_provider_subject AS provider_subject, requested_scopes, \
                        blast_radius, expires_at \
                 FROM shared_auth.global_revocation_previews \
                 WHERE preview_id = $1 AND committed_job_id IS NULL \
                   AND expires_at > clock_timestamp() FOR SHARE",
                vec![preview_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;
        let preview = stored_revocation_preview_from_row(&row)?;
        if preview.previewed_by == operator.shared_user_id {
            return Err(AuthError::Forbidden);
        }
        lock_revocation_operator_context(
            &transaction,
            operator,
            preview.target.shared_user_id,
            PrincipalLock::Share,
        )
        .await?;
        let expires_at = preview.expires_at.min(fresh_until);
        if expires_at <= now {
            return Err(AuthError::StepUpRequired);
        }
        let (commit_authorization_id, commit_authorization_id_hash) = generate_selection_token();
        let actor_session_id_hash = admin_opaque_hash(
            opaque_key,
            "actor-session",
            &operator.session_id.to_string(),
        );
        let evidence_id_hash = admin_opaque_hash(opaque_key, "step-up-evidence", evidence_id);
        let scopes_json = serde_json::to_value(&preview.scopes).map_err(|_| AuthError::Internal)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.global_revocation_commit_authorizations \
                    (commit_authorization_id_hash, preview_id, target_shared_user_id, \
                     target_principal_ref, selected_scopes, authorized_by, \
                     authorized_by_principal_ref, authorized_by_session_id_hash, \
                     evidence_id_hash, verified_at, fresh_until, issued_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                vec![
                    commit_authorization_id_hash.into(),
                    preview.preview_id.into(),
                    preview.target.shared_user_id.into(),
                    preview.target_principal_ref.into(),
                    scopes_json.into(),
                    operator.shared_user_id.into(),
                    operator.principal_ref.into(),
                    actor_session_id_hash.clone().into(),
                    evidence_id_hash.clone().into(),
                    verified_at.into(),
                    fresh_until.into(),
                    now.into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.global_revocation_audit_events \
                    (event_id, actor_id, target_principal_id, event_type, redacted_payload) \
                 VALUES ($1, $2, $3, 'commit_authorized', $4)",
                vec![
                    Uuid::new_v4().into(),
                    operator.shared_user_id.into(),
                    preview.target.shared_user_id.into(),
                    serde_json::json!({
                        "preview_id": preview.preview_id,
                        "actor_principal_ref_hash": admin_opaque_hash(
                            opaque_key,
                            "principal-ref",
                            &operator.principal_ref.to_string()
                        ),
                        "actor_session_id_hash": actor_session_id_hash,
                        "evidence_id_hash": evidence_id_hash,
                        "expires_at": expires_at,
                    })
                    .into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(StoredCommitAuthorization {
            commit_authorization_id,
            preview,
            authorized_by: operator,
            actor_session_id_hash,
            evidence_id_hash,
            verified_at,
            fresh_until,
            issued_at: now,
            expires_at,
        })
    }

    /// Commit the central fence and all durable work records in one Postgres
    /// transaction. Provider/cache/WebSocket work happens only after this
    /// returns; callers therefore cannot observe successful fan-out before the
    /// authoritative epoch has advanced.
    // These arguments are the exact independently validated bindings that are
    // committed atomically; grouping them into a loose options bag would make
    // it easier to omit a security-relevant idempotency/audit dimension.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_global_revocation(
        &self,
        operator: RevocationOperator,
        preview_id: Uuid,
        commit_authorization_id: &str,
        idempotency_key: &str,
        requested_scopes: &[RevocationScope],
        requested_at: chrono::DateTime<chrono::FixedOffset>,
        request_id: &str,
        trace_id: &str,
        reason_code: &str,
        ticket_reference_hash: Option<&str>,
        cache_configured: bool,
    ) -> Result<CommittedRevocation, AuthError> {
        if !crate::revocation::valid_opaque_identifier(commit_authorization_id)
            || !valid_idempotency_key(idempotency_key)
            || !valid_contract_identifier(request_id)
            || !valid_contract_identifier(trace_id)
            || !valid_reason_code(reason_code)
            || ticket_reference_hash
                .is_some_and(|value| !crate::revocation::valid_opaque_identifier(value))
        {
            return Err(AuthError::BadRequest("invalid global revocation request"));
        }
        let requested_scopes =
            normalize_global_scopes(requested_scopes.to_vec()).map_err(AuthError::BadRequest)?;
        let opaque_key = self
            .admin_email_search_hmac_key
            .as_deref()
            .ok_or(AuthError::Unavailable)?;
        let commit_authorization_id_hash = crate::session::hash_token(commit_authorization_id);
        let idempotency_key_hash =
            admin_opaque_hash(opaque_key, "idempotency-key", idempotency_key);
        let transaction = self.db.begin().await.map_err(db_error)?;
        self.lock_advisory_xact(&transaction, crate::locks::GLOBAL_REVOCATION_LOCK_KEY)
            .await?;

        if let Some(existing) = transaction
            .query_one_raw(statement(
                "SELECT job_id, preview_id, target_shared_user_id, \
                        commit_authorization_id_hash, requested_scopes, requested_at, \
                        request_id, trace_id, reason_code, ticket_reference_hash, \
                        actor_session_id_hash \
                 FROM shared_auth.global_revocation_jobs \
                 WHERE committed_by = $1 AND idempotency_key_hash = $2",
                vec![
                    operator.shared_user_id.into(),
                    idempotency_key_hash.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?
        {
            if !revocation_idempotent_row_matches(
                &existing,
                preview_id,
                &commit_authorization_id_hash,
                &requested_scopes,
                requested_at,
                request_id,
                trace_id,
                reason_code,
                ticket_reference_hash,
                opaque_key,
                operator.session_id,
            )? {
                return Err(AuthError::Conflict);
            }
            let target_id: Uuid = existing
                .try_get("", "target_shared_user_id")
                .map_err(db_error)?;
            lock_revocation_operator_context(
                &transaction,
                operator,
                target_id,
                PrincipalLock::Share,
            )
            .await?;
            let job_id: Uuid = existing.try_get("", "job_id").map_err(db_error)?;
            transaction.commit().await.map_err(db_error)?;
            return Ok(CommittedRevocation {
                job: self.global_revocation_job(job_id).await?,
                revoked_session_ids: Vec::new(),
                newly_created: false,
            });
        }

        let preview = transaction
            .query_one_raw(statement(
                "SELECT p.previewed_by, p.target_principal_ref, \
                        p.target_shared_user_id AS shared_user_id, p.target_provider AS provider, \
                        target_provider_tenant AS provider_tenant, \
                        p.target_provider_subject AS provider_subject, p.requested_scopes, \
                        a.selected_scopes AS authorized_scopes, \
                        a.authorized_by_session_id_hash, a.verified_at, a.fresh_until \
                 FROM shared_auth.global_revocation_commit_authorizations a \
                 JOIN shared_auth.global_revocation_previews p USING (preview_id) \
                 WHERE p.preview_id = $1 AND a.commit_authorization_id_hash = $2 \
                   AND a.authorized_by = $3 AND a.consumed_job_id IS NULL \
                   AND a.expires_at > clock_timestamp() AND p.committed_job_id IS NULL \
                   AND p.expires_at > clock_timestamp() FOR UPDATE OF a, p",
                vec![
                    preview_id.into(),
                    commit_authorization_id_hash.clone().into(),
                    operator.shared_user_id.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        let Some(preview) = preview else {
            // A concurrent identical retry may have waited for the first
            // transaction to commit the preview. Re-read the idempotency row
            // before reporting a conflict.
            if let Some(existing) = transaction
                .query_one_raw(statement(
                    "SELECT job_id, preview_id, target_shared_user_id, \
                            commit_authorization_id_hash, requested_scopes, requested_at, \
                            request_id, trace_id, reason_code, ticket_reference_hash, \
                            actor_session_id_hash \
                     FROM shared_auth.global_revocation_jobs \
                     WHERE committed_by = $1 AND idempotency_key_hash = $2",
                    vec![
                        operator.shared_user_id.into(),
                        idempotency_key_hash.clone().into(),
                    ],
                ))
                .await
                .map_err(db_error)?
            {
                if revocation_idempotent_row_matches(
                    &existing,
                    preview_id,
                    &commit_authorization_id_hash,
                    &requested_scopes,
                    requested_at,
                    request_id,
                    trace_id,
                    reason_code,
                    ticket_reference_hash,
                    opaque_key,
                    operator.session_id,
                )? {
                    let target_id: Uuid = existing
                        .try_get("", "target_shared_user_id")
                        .map_err(db_error)?;
                    lock_revocation_operator_context(
                        &transaction,
                        operator,
                        target_id,
                        PrincipalLock::Share,
                    )
                    .await?;
                    let job_id: Uuid = existing.try_get("", "job_id").map_err(db_error)?;
                    transaction.commit().await.map_err(db_error)?;
                    return Ok(CommittedRevocation {
                        job: self.global_revocation_job(job_id).await?,
                        revoked_session_ids: Vec::new(),
                        newly_created: false,
                    });
                }
            }
            return Err(AuthError::Conflict);
        };
        let target = selector_from_row(&preview)?;
        let scopes_json: serde_json::Value =
            preview.try_get("", "requested_scopes").map_err(db_error)?;
        let scopes: Vec<RevocationScope> =
            serde_json::from_value(scopes_json.clone()).map_err(|_| AuthError::Internal)?;
        let scopes = normalize_global_scopes(scopes).map_err(|_| AuthError::Conflict)?;
        let authorized_scopes_json: serde_json::Value =
            preview.try_get("", "authorized_scopes").map_err(db_error)?;
        let authorized_scopes: Vec<RevocationScope> =
            serde_json::from_value(authorized_scopes_json).map_err(|_| AuthError::Internal)?;
        let authorization_verified_at: chrono::DateTime<chrono::FixedOffset> =
            preview.try_get("", "verified_at").map_err(db_error)?;
        let authorization_fresh_until: chrono::DateTime<chrono::FixedOffset> =
            preview.try_get("", "fresh_until").map_err(db_error)?;
        let actor_session_id_hash: String = preview
            .try_get("", "authorized_by_session_id_hash")
            .map_err(db_error)?;
        if scopes != requested_scopes
            || authorized_scopes != requested_scopes
            || requested_at < authorization_verified_at
            || requested_at > authorization_fresh_until
            || !admin_opaque_hash_matches(
                opaque_key,
                "actor-session",
                &operator.session_id.to_string(),
                &actor_session_id_hash,
            )
        {
            return Err(AuthError::Conflict);
        }

        // Actor and target principals are locked together in UUID order. This
        // is both the target fence linearization point and the transactional
        // recheck of the exact presenting operator session/epoch. It avoids the
        // A->B / B->A cross-revocation deadlock.
        lock_revocation_operator_context(
            &transaction,
            operator,
            target.shared_user_id,
            PrincipalLock::Update,
        )
        .await?;
        // Another request using this actor/key may have waited on the same
        // principal lock after our initial lookup. Recheck before fencing so a
        // cross-preview collision is a clean conflict, never a UNIQUE error
        // after an irreversible epoch increment.
        if transaction
            .query_one_raw(statement(
                "SELECT preview_id FROM shared_auth.global_revocation_jobs \
                 WHERE committed_by = $1 AND idempotency_key_hash = $2",
                vec![
                    operator.shared_user_id.into(),
                    idempotency_key_hash.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .is_some()
        {
            return Err(AuthError::Conflict);
        }
        // Lock the canonical mapping after the principal. A preview cannot be
        // committed after its immutable provider tuple is relinked.
        transaction
            .query_one_raw(statement(
                "SELECT provider_identity_id FROM shared_auth.provider_identities \
                 WHERE shared_user_id = $1 AND provider = $2 AND provider_tenant = $3 \
                   AND provider_subject = $4 FOR SHARE",
                vec![
                    target.shared_user_id.into(),
                    target.provider.clone().into(),
                    target.provider_tenant.clone().into(),
                    target.provider_subject.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;

        let actual_impact = revocation_blast_radius(&transaction, target.shared_user_id).await?;
        let fence = transaction
            .query_one_raw(statement(
                "UPDATE shared_auth.principals \
                 SET auth_epoch = auth_epoch + 1, auth_not_before = clock_timestamp(), \
                     updated_at = clock_timestamp() \
                 WHERE shared_user_id = $1 AND status = 'active' \
                 RETURNING auth_epoch - 1 AS previous_auth_epoch, auth_epoch, auth_not_before",
                vec![target.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Conflict)?;
        let auth_epoch: i64 = fence.try_get("", "auth_epoch").map_err(db_error)?;
        let auth_epoch_u64 = u64::try_from(auth_epoch).map_err(|_| AuthError::Internal)?;
        let previous_auth_epoch: i64 =
            fence.try_get("", "previous_auth_epoch").map_err(db_error)?;
        let previous_auth_epoch_u64 =
            u64::try_from(previous_auth_epoch).map_err(|_| AuthError::Internal)?;
        let auth_not_before: chrono::DateTime<chrono::FixedOffset> =
            fence.try_get("", "auth_not_before").map_err(db_error)?;

        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.session_application_grants sag \
                 SET revoked_at = COALESCE(sag.revoked_at, clock_timestamp()) \
                 FROM shared_auth.sessions s \
                 WHERE sag.session_id = s.session_id AND s.shared_user_id = $1 \
                   AND sag.revoked_at IS NULL",
                vec![target.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.application_consents \
                 SET revoked_at = COALESCE(revoked_at, clock_timestamp()), \
                     updated_at = clock_timestamp() \
                 WHERE shared_user_id = $1 AND revoked_at IS NULL",
                vec![target.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        let revoked_rows = transaction
            .query_all_raw(statement(
                "UPDATE shared_auth.sessions \
                 SET revoked_at = COALESCE(revoked_at, clock_timestamp()), \
                     updated_at = clock_timestamp() \
                 WHERE shared_user_id = $1 AND revoked_at IS NULL \
                   AND expires_at > now() \
                 RETURNING session_id",
                vec![target.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        let revoked_session_ids = revoked_rows
            .into_iter()
            .map(|row| row.try_get("", "session_id").map_err(db_error))
            .collect::<Result<Vec<Uuid>, AuthError>>()?;

        let job_id = Uuid::new_v4();
        let audit_event_id = Uuid::new_v4();
        let correlation_id = Uuid::new_v4();
        let target_principal_ref: Uuid = preview
            .try_get("", "target_principal_ref")
            .map_err(db_error)?;
        let impact_json = serde_json::to_value(&actual_impact).map_err(|_| AuthError::Internal)?;
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.global_revocation_jobs \
                    (job_id, preview_id, committed_by, committed_by_principal_ref, \
                     commit_authorization_id_hash, idempotency_key_hash, \
                     target_shared_user_id, target_principal_ref, target_provider, \
                     target_provider_tenant, target_provider_subject, requested_scopes, \
                     previous_auth_epoch, auth_epoch, auth_not_before, actual_impact, \
                     requested_at, request_id, trace_id, reason_code, ticket_reference_hash, \
                     actor_session_id_hash, audit_event_id, correlation_id, status, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                         $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, \
                         $24, 'committed_local_queued_fanout', $25)",
                vec![
                    job_id.into(),
                    preview_id.into(),
                    operator.shared_user_id.into(),
                    operator.principal_ref.into(),
                    commit_authorization_id_hash.clone().into(),
                    idempotency_key_hash.clone().into(),
                    target.shared_user_id.into(),
                    target_principal_ref.into(),
                    target.provider.clone().into(),
                    target.provider_tenant.clone().into(),
                    target.provider_subject.clone().into(),
                    scopes_json.into(),
                    previous_auth_epoch.into(),
                    auth_epoch.into(),
                    auth_not_before.into(),
                    impact_json.clone().into(),
                    requested_at.into(),
                    request_id.to_owned().into(),
                    trace_id.to_owned().into(),
                    reason_code.to_owned().into(),
                    ticket_reference_hash.map(str::to_owned).into(),
                    actor_session_id_hash.clone().into(),
                    audit_event_id.into(),
                    correlation_id.into(),
                    auth_not_before.into(),
                ],
            ))
            .await
            .map_err(db_error)?;

        // The authority owns and has synchronously fenced these four resource
        // classes. The remaining three canonical classes have no inventory or
        // adapter in this service, so their terminal state is explicitly
        // unsupported rather than pending or (worse) fabricated success.
        for scope in RevocationScope::ALL {
            let supported = matches!(
                scope,
                RevocationScope::InteractiveSessions
                    | RevocationScope::RefreshTokenFamilies
                    | RevocationScope::OfflineGrants
                    | RevocationScope::DownstreamSessions
            );
            let (opaque_identity_handle, _) = generate_selection_token();
            insert_revocation_target(
                &transaction,
                opaque_key,
                job_id,
                "shared_auth",
                "authority",
                &opaque_identity_handle,
                scope,
                if supported {
                    "succeeded"
                } else {
                    "unsupported"
                },
                u32::from(supported),
                false,
                Some(auth_not_before),
                Some(if supported {
                    "shared_auth.central_fence_applied"
                } else {
                    "shared_auth.inventory_adapter_unavailable"
                }),
                None,
            )
            .await?;
        }
        let provider_rows = transaction
            .query_all_raw(statement(
                "SELECT provider_identity_id, provider, provider_tenant, provider_subject \
                 FROM shared_auth.provider_identities WHERE shared_user_id = $1 \
                   AND provider NOT IN ('local', 'magic_link') \
                 ORDER BY provider, provider_tenant, provider_subject",
                vec![target.shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        let has_external_providers = !provider_rows.is_empty();
        for row in provider_rows {
            let provider_identity_id: Uuid =
                row.try_get("", "provider_identity_id").map_err(db_error)?;
            let provider: String = row.try_get("", "provider").map_err(db_error)?;
            let tenant: String = row.try_get("", "provider_tenant").map_err(db_error)?;
            let subject: String = row.try_get("", "provider_subject").map_err(db_error)?;
            // Random per-operation handle: provider subjects can be enumerable,
            // so neither status responses nor cross-job correlation use a
            // deterministic digest of the tuple.
            let (_, opaque_target_key) = generate_selection_token();
            let provider_tenant_ref =
                ensure_admin_provider_tenant_ref(&transaction, &provider, &tenant).await?;
            transaction
                .execute_raw(statement(
                    "INSERT INTO shared_auth.global_revocation_provider_snapshots \
                        (job_id, provider_identity_id, provider, provider_tenant, \
                         provider_subject, opaque_target_key) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    vec![
                        job_id.into(),
                        provider_identity_id.into(),
                        provider.clone().into(),
                        tenant.into(),
                        subject.into(),
                        opaque_target_key.clone().into(),
                    ],
                ))
                .await
                .map_err(db_error)?;
            for scope in RevocationScope::ALL {
                insert_revocation_target(
                    &transaction,
                    opaque_key,
                    job_id,
                    &provider,
                    &provider_tenant_ref.to_string(),
                    &opaque_target_key,
                    scope,
                    "unsupported",
                    0,
                    false,
                    Some(auth_not_before),
                    Some("shared_auth.provider_adapter_unavailable"),
                    None,
                )
                .await?;
            }
        }

        // Every target written by this synchronous implementation is now in a
        // truthful terminal state. Core authority resources succeeded while
        // unsupported inventories/adapters did not, so the aggregate is
        // partial. Later worker implementations can instead leave specific
        // targets pending and advance this durable aggregate transactionally.
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.global_revocation_jobs \
                 SET status = 'partial', updated_at = clock_timestamp(), \
                     completed_at = clock_timestamp() \
                 WHERE job_id = $1",
                vec![job_id.into()],
            ))
            .await
            .map_err(db_error)?;

        let preview_bound = transaction
            .execute_raw(statement(
                "UPDATE shared_auth.global_revocation_previews \
                 SET committed_job_id = $2 \
                 WHERE preview_id = $1 AND committed_job_id IS NULL",
                vec![preview_id.into(), job_id.into()],
            ))
            .await
            .map_err(db_error)?;
        if preview_bound.rows_affected() != 1 {
            return Err(AuthError::Conflict);
        }
        let authorization_consumed = transaction
            .execute_raw(statement(
                "UPDATE shared_auth.global_revocation_commit_authorizations \
                 SET consumed_job_id = $2 \
                 WHERE commit_authorization_id_hash = $1 AND consumed_job_id IS NULL",
                vec![commit_authorization_id_hash.clone().into(), job_id.into()],
            ))
            .await
            .map_err(db_error)?;
        if authorization_consumed.rows_affected() != 1 {
            return Err(AuthError::Conflict);
        }
        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.global_revocation_audit_events \
                    (event_id, job_id, actor_id, target_principal_id, event_type, \
                     redacted_payload) \
                 VALUES ($1, $2, $3, $4, 'revocation_committed', $5)",
                vec![
                    audit_event_id.into(),
                    job_id.into(),
                    operator.shared_user_id.into(),
                    target.shared_user_id.into(),
                    serde_json::json!({
                        "preview_id": preview_id,
                        "auth_epoch": auth_epoch_u64,
                        "previous_auth_epoch": previous_auth_epoch_u64,
                        "auth_not_before": auth_not_before,
                        "scopes": &scopes,
                        "actual_impact": &actual_impact,
                        "status": "partial",
                        "requested_at": requested_at,
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "reason_code": reason_code,
                        "correlation_id": correlation_id,
                        "actor_session_id_hash": actor_session_id_hash,
                        "idempotency_key_hash": &idempotency_key_hash,
                    })
                    .into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        let mut event_types = vec!["out_of_band_notification"];
        if cache_configured {
            event_types.push("redis_revocation_cache");
        }
        if has_external_providers {
            event_types.push("external_provider_revocation");
        }
        for event_type in event_types {
            transaction
                .execute_raw(statement(
                    "INSERT INTO shared_auth.global_revocation_outbox \
                        (outbox_id, job_id, event_type, payload) \
                     VALUES ($1, $2, $3, $4)",
                    vec![
                        Uuid::new_v4().into(),
                        job_id.into(),
                        event_type.to_owned().into(),
                        serde_json::json!({
                            "job_id": job_id,
                            "auth_epoch": auth_epoch_u64,
                        })
                        .into(),
                    ],
                ))
                .await
                .map_err(db_error)?;
        }
        transaction.commit().await.map_err(db_error)?;

        Ok(CommittedRevocation {
            job: self.global_revocation_job(job_id).await?,
            revoked_session_ids,
            newly_created: true,
        })
    }

    pub async fn global_revocation_job(&self, job_id: Uuid) -> Result<RevocationJob, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT job_id, preview_id, target_shared_user_id, target_principal_ref, \
                        status, previous_auth_epoch, auth_epoch, auth_not_before, \
                        requested_scopes, actual_impact, created_at, updated_at, completed_at, \
                        committed_by_principal_ref, actor_session_id_hash, \
                        idempotency_key_hash, audit_event_id, correlation_id, \
                        request_id, trace_id, reason_code \
                 FROM shared_auth.global_revocation_jobs WHERE job_id = $1",
                vec![job_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::NotFound)?;
        let target_rows = self
            .db
            .query_all_raw(statement(
                "SELECT target_id_hash, provider_id, provider_tenant_id, \
                        opaque_identity_handle, scope, status, attempts, retryable, \
                        last_attempt_at, next_attempt_at, retry_after_seconds, completed_at, \
                        last_error_code, provider_request_id_hash, \
                        residual_access_token_max_seconds \
                 FROM shared_auth.global_revocation_targets WHERE job_id = $1 \
                 ORDER BY provider_id, provider_tenant_id, opaque_identity_handle, scope",
                vec![job_id.into()],
            ))
            .await
            .map_err(db_error)?;
        revocation_job_from_rows(row, target_rows)
    }

    pub async fn replace_roles(
        &self,
        shared_user_id: Uuid,
        roles: &[String],
    ) -> Result<(), AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        transaction
            .query_one_raw(statement(
                "SELECT shared_user_id FROM shared_auth.principals \
                 WHERE shared_user_id = $1 FOR UPDATE",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::NotFound)?;
        let current_rows = transaction
            .query_all_raw(statement(
                "SELECT role_name FROM shared_auth.roles \
                 WHERE shared_user_id = $1 ORDER BY role_name FOR UPDATE",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        let current = current_rows
            .into_iter()
            .map(|row| row.try_get("", "role_name").map_err(db_error))
            .collect::<Result<Vec<String>, AuthError>>()?;
        let mut desired = roles.to_vec();
        desired.sort();
        desired.dedup();
        if current == desired {
            transaction.commit().await.map_err(db_error)?;
            return Ok(());
        }
        transaction
            .execute_raw(statement(
                "DELETE FROM shared_auth.roles WHERE shared_user_id = $1",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        for role in desired {
            transaction
                .execute_raw(statement(
                    "INSERT INTO shared_auth.roles (shared_user_id, role_name) VALUES ($1, $2)",
                    vec![shared_user_id.into(), role.into()],
                ))
                .await
                .map_err(db_error)?;
        }
        // Role grants and removals invalidate every pre-change bearer. This
        // prevents an AAL1 session from enrolling a passkey before/after a
        // privileged grant and prevents removed role snapshots from surviving.
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.principals \
                 SET auth_epoch = auth_epoch + 1, auth_not_before = clock_timestamp(), \
                     updated_at = clock_timestamp() \
                 WHERE shared_user_id = $1",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.sessions \
                 SET revoked_at = COALESCE(revoked_at, clock_timestamp()), \
                     updated_at = clock_timestamp() \
                 WHERE shared_user_id = $1 AND revoked_at IS NULL",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;
        Ok(())
    }

    pub async fn record_webhook_event(
        &self,
        event_id: Uuid,
        provider: &str,
        event_type: &str,
        payload_sha256: &str,
    ) -> Result<bool, AuthError> {
        let result = self
            .db
            .execute_raw(statement(
                "INSERT INTO shared_auth.webhook_events \
                    (event_id, provider, event_type, payload_sha256) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (event_id) DO NOTHING",
                vec![
                    event_id.into(),
                    provider.to_owned().into(),
                    event_type.to_owned().into(),
                    payload_sha256.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn roles_for(&self, shared_user_id: Uuid) -> Result<Vec<String>, AuthError> {
        let rows = self
            .db
            .query_all_raw(statement(
                "SELECT role_name FROM shared_auth.roles WHERE shared_user_id = $1 \
                 ORDER BY role_name",
                vec![shared_user_id.into()],
            ))
            .await
            .map_err(db_error)?;
        rows.into_iter()
            .map(|row| row.try_get("", "role_name").map_err(db_error))
            .collect()
    }
}

fn selector_from_row(row: &sea_orm::QueryResult) -> Result<PrincipalSelector, AuthError> {
    Ok(PrincipalSelector {
        shared_user_id: row.try_get("", "shared_user_id").map_err(db_error)?,
        provider: row.try_get("", "provider").map_err(db_error)?,
        provider_tenant: row.try_get("", "provider_tenant").map_err(db_error)?,
        provider_subject: row.try_get("", "provider_subject").map_err(db_error)?,
    })
}

async fn revocation_blast_radius<C>(
    connection: &C,
    shared_user_id: Uuid,
) -> Result<RevocationBlastRadius, AuthError>
where
    C: ConnectionTrait,
{
    let row = connection
        .query_one_raw(statement(
            "SELECT \
                (SELECT count(*) FROM shared_auth.sessions s \
                 WHERE s.shared_user_id = $1 AND s.revoked_at IS NULL \
                   AND s.expires_at > now()) AS active_sessions, \
                (SELECT count(*) FROM shared_auth.application_consents c \
                 WHERE c.shared_user_id = $1 AND c.revoked_at IS NULL) AS offline_grants, \
                (SELECT count(*) FROM shared_auth.session_application_grants sag \
                 JOIN shared_auth.sessions s USING (session_id) \
                 WHERE s.shared_user_id = $1 AND sag.revoked_at IS NULL) AS downstream_grants, \
                (SELECT count(DISTINCT application_id) FROM ( \
                    SELECT c.application_id FROM shared_auth.application_consents c \
                     WHERE c.shared_user_id = $1 AND c.revoked_at IS NULL \
                    UNION \
                    SELECT sag.application_id FROM shared_auth.session_application_grants sag \
                     JOIN shared_auth.sessions s USING (session_id) \
                     WHERE s.shared_user_id = $1 AND sag.revoked_at IS NULL \
                ) applications) AS application_count, \
                (SELECT count(DISTINCT sag.client_id) \
                 FROM shared_auth.session_application_grants sag \
                 JOIN shared_auth.sessions s USING (session_id) \
                 WHERE s.shared_user_id = $1 AND sag.revoked_at IS NULL) AS client_count, \
                (SELECT count(DISTINCT pi.provider) \
                 FROM shared_auth.provider_identities pi \
                 WHERE pi.shared_user_id = $1) AS provider_count, \
                (SELECT count(DISTINCT (pi.provider, pi.provider_tenant)) \
                 FROM shared_auth.provider_identities pi \
                 WHERE pi.shared_user_id = $1) AS provider_tenant_count, \
                (SELECT count(*) FROM shared_auth.provider_identities pi \
                 WHERE pi.shared_user_id = $1) AS identity_count, \
                COALESCE((SELECT inventory_complete \
                 FROM shared_auth.principal_directory_inventory_state \
                 WHERE shared_user_id = $1), false) AS directory_inventory_complete, \
                (SELECT count(*) FROM shared_auth.principal_organization_memberships m \
                 WHERE m.shared_user_id = $1) AS organization_count, \
                (SELECT count(DISTINCT project_id) FROM \
                    shared_auth.principal_organization_memberships m, \
                    unnest(COALESCE(m.project_ids, ARRAY[]::uuid[])) AS project_id \
                 WHERE m.shared_user_id = $1) AS project_count",
            vec![shared_user_id.into()],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Internal)?;
    let active_sessions = nonnegative_count(&row, "active_sessions")?;
    let directory_inventory_complete: bool = row
        .try_get("", "directory_inventory_complete")
        .map_err(db_error)?;
    Ok(RevocationBlastRadius {
        active_sessions,
        // This schema intentionally has one server-side session record for the
        // browser and its rotating refresh credential. Report both scope views
        // without pretending they are independently enumerable.
        browser_sessions: active_sessions,
        refresh_credentials: active_sessions,
        offline_grants: nonnegative_count(&row, "offline_grants")?,
        downstream_grants: nonnegative_count(&row, "downstream_grants")?,
        application_count: nonnegative_count(&row, "application_count")?,
        client_count: nonnegative_count(&row, "client_count")?,
        provider_count: nonnegative_count(&row, "provider_count")?,
        provider_tenant_count: nonnegative_count(&row, "provider_tenant_count")?,
        identity_count: nonnegative_count(&row, "identity_count")?,
        organization_count: directory_inventory_complete
            .then(|| nonnegative_count(&row, "organization_count"))
            .transpose()?,
        project_count: directory_inventory_complete
            .then(|| nonnegative_count(&row, "project_count"))
            .transpose()?,
        directory_inventory_complete,
    })
}

fn nonnegative_count(row: &sea_orm::QueryResult, column: &str) -> Result<u64, AuthError> {
    let value: i64 = row.try_get("", column).map_err(db_error)?;
    u64::try_from(value).map_err(|_| AuthError::Internal)
}

#[allow(clippy::too_many_arguments)]
fn revocation_idempotent_row_matches(
    row: &sea_orm::QueryResult,
    preview_id: Uuid,
    commit_authorization_id_hash: &str,
    requested_scopes: &[RevocationScope],
    requested_at: chrono::DateTime<chrono::FixedOffset>,
    request_id: &str,
    trace_id: &str,
    reason_code: &str,
    ticket_reference_hash: Option<&str>,
    opaque_key: &[u8],
    operator_session_id: Uuid,
) -> Result<bool, AuthError> {
    let existing_scopes: serde_json::Value =
        row.try_get("", "requested_scopes").map_err(db_error)?;
    let existing_scopes: Vec<RevocationScope> =
        serde_json::from_value(existing_scopes).map_err(|_| AuthError::Internal)?;
    let existing_ticket_reference_hash: Option<String> =
        row.try_get("", "ticket_reference_hash").map_err(db_error)?;
    let actor_session_id_hash: String =
        row.try_get("", "actor_session_id_hash").map_err(db_error)?;
    Ok(
        row.try_get::<Uuid>("", "preview_id").map_err(db_error)? == preview_id
            && row
                .try_get::<String>("", "commit_authorization_id_hash")
                .map_err(db_error)?
                == commit_authorization_id_hash
            && existing_scopes == requested_scopes
            && row
                .try_get::<chrono::DateTime<chrono::FixedOffset>>("", "requested_at")
                .map_err(db_error)?
                == requested_at
            && row.try_get::<String>("", "request_id").map_err(db_error)? == request_id
            && row.try_get::<String>("", "trace_id").map_err(db_error)? == trace_id
            && row.try_get::<String>("", "reason_code").map_err(db_error)? == reason_code
            && existing_ticket_reference_hash.as_deref() == ticket_reference_hash
            && admin_opaque_hash_matches(
                opaque_key,
                "actor-session",
                &operator_session_id.to_string(),
                &actor_session_id_hash,
            ),
    )
}

// Keep every canonical target field explicit at the persistence boundary.
#[allow(clippy::too_many_arguments)]
async fn insert_revocation_target<C>(
    connection: &C,
    opaque_key: &[u8],
    job_id: Uuid,
    provider_id: &str,
    provider_tenant_id: &str,
    opaque_identity_handle: &str,
    scope: RevocationScope,
    status: &str,
    attempts: u32,
    retryable: bool,
    completed_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    result_code: Option<&str>,
    residual_access_token_max_seconds: Option<u64>,
) -> Result<(), AuthError>
where
    C: ConnectionTrait,
{
    let (target_nonce, _) = generate_selection_token();
    let target_id_hash = admin_opaque_hash(opaque_key, "revocation-target-id", &target_nonce);
    let attempts = i32::try_from(attempts).map_err(|_| AuthError::Internal)?;
    let residual_access_token_max_seconds = residual_access_token_max_seconds
        .map(i32::try_from)
        .transpose()
        .map_err(|_| AuthError::Internal)?;
    connection
        .execute_raw(statement(
            "INSERT INTO shared_auth.global_revocation_targets \
                (job_id, target_id_hash, provider_id, provider_tenant_id, \
                 opaque_identity_handle, scope, status, attempts, retryable, \
                 last_attempt_at, completed_at, last_error_code, \
                 residual_access_token_max_seconds) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                     CASE WHEN $8 > 0 THEN $10 ELSE NULL END, $10, $11, $12)",
            vec![
                job_id.into(),
                target_id_hash.into(),
                provider_id.to_owned().into(),
                provider_tenant_id.to_owned().into(),
                opaque_identity_handle.to_owned().into(),
                scope.as_str().to_owned().into(),
                status.to_owned().into(),
                attempts.into(),
                retryable.into(),
                completed_at.into(),
                result_code.map(str::to_owned).into(),
                residual_access_token_max_seconds.into(),
            ],
        ))
        .await
        .map_err(db_error)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum PrincipalLock {
    Share,
    Update,
}

/// Lock actor and target principals in one deterministic UUID-ordered query,
/// then bind authorization to the exact presenting session, epoch, and current
/// role. Concurrent revocation/role removal either linearizes first and denies
/// this request, or waits until this already-authorized transaction completes.
async fn lock_revocation_operator_context<C>(
    connection: &C,
    operator: RevocationOperator,
    target_id: Uuid,
    lock: PrincipalLock,
) -> Result<(), AuthError>
where
    C: ConnectionTrait,
{
    let expected_epoch = i64::try_from(operator.auth_epoch).map_err(|_| AuthError::Forbidden)?;
    let sql = match lock {
        PrincipalLock::Share => {
            "SELECT shared_user_id, auth_epoch FROM shared_auth.principals \
             WHERE shared_user_id IN ($1, $2) AND status = 'active' \
             ORDER BY shared_user_id FOR SHARE"
        }
        PrincipalLock::Update => {
            "SELECT shared_user_id, auth_epoch FROM shared_auth.principals \
             WHERE shared_user_id IN ($1, $2) AND status = 'active' \
             ORDER BY shared_user_id FOR UPDATE"
        }
    };
    let principal_rows = connection
        .query_all_raw(statement(
            sql,
            vec![operator.shared_user_id.into(), target_id.into()],
        ))
        .await
        .map_err(db_error)?;
    let expected_count = if operator.shared_user_id == target_id {
        1
    } else {
        2
    };
    if principal_rows.len() != expected_count {
        return Err(AuthError::Conflict);
    }
    let actor_epoch = principal_rows
        .iter()
        .find_map(|row| {
            let id: Uuid = row.try_get("", "shared_user_id").ok()?;
            (id == operator.shared_user_id)
                .then(|| row.try_get::<i64>("", "auth_epoch").ok())
                .flatten()
        })
        .ok_or(AuthError::Forbidden)?;
    if actor_epoch != expected_epoch {
        return Err(AuthError::Forbidden);
    }
    connection
        .query_one_raw(statement(
            "SELECT s.session_id FROM shared_auth.sessions s \
             JOIN shared_auth.principals p USING (shared_user_id) \
             WHERE s.session_id = $1 AND s.shared_user_id = $2 \
               AND s.auth_epoch = $3 AND p.auth_epoch = $3 \
               AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp() \
               AND s.created_at >= p.auth_not_before AND p.status = 'active' \
             FOR SHARE OF s",
            vec![
                operator.session_id.into(),
                operator.shared_user_id.into(),
                expected_epoch.into(),
            ],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Forbidden)?;
    connection
        .query_one_raw(statement(
            "SELECT role_id FROM shared_auth.roles \
             WHERE shared_user_id = $1 AND role_name = $2 FOR SHARE",
            vec![
                operator.shared_user_id.into(),
                REVOCATION_OPERATOR_ROLE.to_owned().into(),
            ],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Forbidden)?;
    Ok(())
}

// The immutable selection/actor/target/scope bindings are deliberately visible
// at this one insert boundary rather than hidden in a partially initialized bag.
#[allow(clippy::too_many_arguments)]
async fn insert_global_revocation_preview<C>(
    connection: &C,
    opaque_key: &[u8],
    operator: RevocationOperator,
    selection_id_hash: &str,
    request_id: &str,
    target_principal_ref: Uuid,
    target: &PrincipalSelector,
    scopes: &[RevocationScope],
    ttl_secs: i64,
) -> Result<StoredRevocationPreview, AuthError>
where
    C: ConnectionTrait,
{
    let blast_radius = revocation_blast_radius(connection, target.shared_user_id).await?;
    let preview_id = Uuid::new_v4();
    let generated_at = chrono::Utc::now().fixed_offset();
    let expires_at = generated_at + chrono::TimeDelta::seconds(ttl_secs);
    let scopes_json = serde_json::to_value(scopes).map_err(|_| AuthError::Internal)?;
    let blast_json = serde_json::to_value(&blast_radius).map_err(|_| AuthError::Internal)?;
    connection
        .execute_raw(statement(
            "INSERT INTO shared_auth.global_revocation_previews \
                (preview_id, selection_id_hash, request_id, previewed_by, previewed_by_principal_ref, \
                 target_shared_user_id, target_principal_ref, target_provider, \
                 target_provider_tenant, target_provider_subject, requested_scopes, \
                 blast_radius, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            vec![
                preview_id.into(),
                selection_id_hash.to_owned().into(),
                request_id.to_owned().into(),
                operator.shared_user_id.into(),
                operator.principal_ref.into(),
                target.shared_user_id.into(),
                target_principal_ref.into(),
                target.provider.clone().into(),
                target.provider_tenant.clone().into(),
                target.provider_subject.clone().into(),
                scopes_json.into(),
                blast_json.into(),
                generated_at.into(),
                expires_at.into(),
            ],
        ))
        .await
        .map_err(db_error)?;
    connection
        .execute_raw(statement(
            "INSERT INTO shared_auth.global_revocation_audit_events \
                (event_id, actor_id, target_principal_id, event_type, redacted_payload) \
             VALUES ($1, $2, $3, 'preview_created', $4)",
            vec![
                Uuid::new_v4().into(),
                operator.shared_user_id.into(),
                target.shared_user_id.into(),
                serde_json::json!({
                    "preview_id": preview_id,
                    "scopes": scopes,
                    "blast_radius": &blast_radius,
                    "actor_session_id_hash": admin_opaque_hash(
                        opaque_key,
                        "actor-session",
                        &operator.session_id.to_string()
                    ),
                })
                .into(),
            ],
        ))
        .await
        .map_err(db_error)?;
    Ok(StoredRevocationPreview {
        preview_id,
        previewed_by: operator.shared_user_id,
        previewed_by_principal_ref: operator.principal_ref,
        generated_at,
        expires_at,
        target_principal_ref,
        target: target.clone(),
        scopes: scopes.to_vec(),
        blast_radius,
    })
}

fn stored_revocation_preview_from_row(
    row: &sea_orm::QueryResult,
) -> Result<StoredRevocationPreview, AuthError> {
    let scopes_json: serde_json::Value = row.try_get("", "requested_scopes").map_err(db_error)?;
    let blast_json: serde_json::Value = row.try_get("", "blast_radius").map_err(db_error)?;
    Ok(StoredRevocationPreview {
        preview_id: row.try_get("", "preview_id").map_err(db_error)?,
        previewed_by: row.try_get("", "previewed_by").map_err(db_error)?,
        previewed_by_principal_ref: row
            .try_get("", "previewed_by_principal_ref")
            .map_err(db_error)?,
        generated_at: row.try_get("", "created_at").map_err(db_error)?,
        expires_at: row.try_get("", "expires_at").map_err(db_error)?,
        target_principal_ref: row.try_get("", "target_principal_ref").map_err(db_error)?,
        target: selector_from_row(row)?,
        scopes: serde_json::from_value(scopes_json).map_err(|_| AuthError::Internal)?,
        blast_radius: serde_json::from_value(blast_json).map_err(|_| AuthError::Internal)?,
    })
}

fn revocation_job_from_rows(
    row: sea_orm::QueryResult,
    target_rows: Vec<sea_orm::QueryResult>,
) -> Result<RevocationJob, AuthError> {
    let epoch: i64 = row.try_get("", "auth_epoch").map_err(db_error)?;
    let previous_epoch: i64 = row.try_get("", "previous_auth_epoch").map_err(db_error)?;
    let scopes_json: serde_json::Value = row.try_get("", "requested_scopes").map_err(db_error)?;
    let impact_json: serde_json::Value = row.try_get("", "actual_impact").map_err(db_error)?;
    let targets = target_rows
        .into_iter()
        .map(|target| {
            let attempts: i32 = target.try_get("", "attempts").map_err(db_error)?;
            let retry_after_seconds: Option<i32> = target
                .try_get("", "retry_after_seconds")
                .map_err(db_error)?;
            let residual_access_token_max_seconds: Option<i32> = target
                .try_get("", "residual_access_token_max_seconds")
                .map_err(db_error)?;
            let scope: String = target.try_get("", "scope").map_err(db_error)?;
            Ok(RevocationTargetStatus {
                target_id_hash: target.try_get("", "target_id_hash").map_err(db_error)?,
                provider_id: target.try_get("", "provider_id").map_err(db_error)?,
                provider_tenant_id: target.try_get("", "provider_tenant_id").map_err(db_error)?,
                opaque_identity_handle: target
                    .try_get("", "opaque_identity_handle")
                    .map_err(db_error)?,
                scope: RevocationScope::parse_contract(&scope).ok_or(AuthError::Internal)?,
                status: target.try_get("", "status").map_err(db_error)?,
                attempts: u32::try_from(attempts).map_err(|_| AuthError::Internal)?,
                retryable: target.try_get("", "retryable").map_err(db_error)?,
                last_attempt_at: target.try_get("", "last_attempt_at").map_err(db_error)?,
                next_attempt_at: target.try_get("", "next_attempt_at").map_err(db_error)?,
                retry_after_seconds: retry_after_seconds
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| AuthError::Internal)?,
                completed_at: target.try_get("", "completed_at").map_err(db_error)?,
                last_error_code: target.try_get("", "last_error_code").map_err(db_error)?,
                provider_request_id_hash: target
                    .try_get("", "provider_request_id_hash")
                    .map_err(db_error)?,
                residual_access_token_max_seconds: residual_access_token_max_seconds
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| AuthError::Internal)?,
            })
        })
        .collect::<Result<Vec<_>, AuthError>>()?;
    let status = if targets.iter().any(|target| {
        matches!(
            target.status.as_str(),
            "pending" | "running" | "retry_scheduled"
        )
    }) {
        if targets.iter().all(|target| target.status == "pending") {
            "queued"
        } else {
            "running"
        }
    } else if targets
        .iter()
        .all(|target| matches!(target.status.as_str(), "succeeded" | "skipped"))
    {
        "complete"
    } else if targets
        .iter()
        .all(|target| matches!(target.status.as_str(), "failed" | "unsupported"))
    {
        "failed"
    } else if targets
        .iter()
        .any(|target| matches!(target.status.as_str(), "succeeded" | "skipped"))
        && targets
            .iter()
            .any(|target| matches!(target.status.as_str(), "failed" | "unsupported"))
    {
        "partial"
    } else {
        "failed"
    };
    Ok(RevocationJob {
        job_id: row.try_get("", "job_id").map_err(db_error)?,
        preview_id: row.try_get("", "preview_id").map_err(db_error)?,
        target_shared_user_id: row.try_get("", "target_shared_user_id").map_err(db_error)?,
        target_principal_ref: row.try_get("", "target_principal_ref").map_err(db_error)?,
        // Derive aggregate state from durable targets so worker progress can
        // never leave the response stuck at the insertion-time queued state.
        status: status.to_owned(),
        auth_epoch: u64::try_from(epoch).map_err(|_| AuthError::Internal)?,
        previous_auth_epoch: u64::try_from(previous_epoch).map_err(|_| AuthError::Internal)?,
        not_before: row.try_get("", "auth_not_before").map_err(db_error)?,
        scopes: serde_json::from_value(scopes_json).map_err(|_| AuthError::Internal)?,
        actual_impact: serde_json::from_value(impact_json).map_err(|_| AuthError::Internal)?,
        created_at: row.try_get("", "created_at").map_err(db_error)?,
        updated_at: row.try_get("", "updated_at").map_err(db_error)?,
        completed_at: row.try_get("", "completed_at").map_err(db_error)?,
        committed_by_principal_ref: row
            .try_get("", "committed_by_principal_ref")
            .map_err(db_error)?,
        actor_session_id_hash: row.try_get("", "actor_session_id_hash").map_err(db_error)?,
        idempotency_key_hash: row.try_get("", "idempotency_key_hash").map_err(db_error)?,
        audit_event_id: row.try_get("", "audit_event_id").map_err(db_error)?,
        correlation_id: row.try_get("", "correlation_id").map_err(db_error)?,
        request_id: row.try_get("", "request_id").map_err(db_error)?,
        trace_id: row.try_get("", "trace_id").map_err(db_error)?,
        reason_code: row.try_get("", "reason_code").map_err(db_error)?,
        targets,
    })
}

async fn verify_magic_link_identity(
    transaction: &sea_orm::DatabaseTransaction,
    shared_user_id: Uuid,
    email_search_hmac_key: Option<&[u8]>,
    email_search_key_id: Option<&str>,
) -> Result<sea_orm::QueryResult, AuthError> {
    let identity = transaction
        .query_one_raw(statement(
            "SELECT email FROM shared_auth.provider_identities \
             WHERE shared_user_id = $1 AND provider = 'magic_link' FOR UPDATE",
            vec![shared_user_id.into()],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Unauthorized)?;
    let email: Option<String> = identity.try_get("", "email").map_err(db_error)?;
    let (email_search_key_hash, email_search_key_id) = match (
        email_search_hmac_key,
        email_search_key_id,
        email.as_deref().and_then(normalize_email_search_alias),
    ) {
        (Some(key), Some(key_id), Some(normalized)) => (
            Some(email_search_key_hash(key, &normalized)),
            Some(key_id.to_owned()),
        ),
        _ => (None, None),
    };
    let updated = transaction
        .execute_raw(statement(
            "UPDATE shared_auth.principals SET email_verified = true, \
                updated_at = now(), last_seen_at = now() \
             WHERE shared_user_id = $1 AND status = 'active'",
            vec![shared_user_id.into()],
        ))
        .await
        .map_err(db_error)?;
    if updated.rows_affected() != 1 {
        return Err(AuthError::Unauthorized);
    }
    transaction
        .query_one_raw(statement(
            "UPDATE shared_auth.provider_identities SET email_verified = true, \
                email_search_key_hash = $2, email_search_key_id = $3, \
                updated_at = now(), last_seen_at = now() \
             WHERE shared_user_id = $1 AND provider = 'magic_link' \
             RETURNING shared_user_id, provider, provider_tenant, provider_subject, \
                       email, email_verified",
            vec![
                shared_user_id.into(),
                email_search_key_hash.into(),
                email_search_key_id.into(),
            ],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Unauthorized)
}

async fn ensure_admin_principal_ref<C>(
    connection: &C,
    shared_user_id: Uuid,
) -> Result<Uuid, AuthError>
where
    C: ConnectionTrait,
{
    let row = connection
        .query_one_raw(statement(
            "INSERT INTO shared_auth.admin_principal_refs (shared_user_id) \
             VALUES ($1) \
             ON CONFLICT (shared_user_id) DO UPDATE \
                SET shared_user_id = EXCLUDED.shared_user_id \
             RETURNING principal_ref",
            vec![shared_user_id.into()],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Internal)?;
    row.try_get("", "principal_ref").map_err(db_error)
}

async fn ensure_admin_provider_tenant_ref<C>(
    connection: &C,
    provider: &str,
    provider_tenant: &str,
) -> Result<Uuid, AuthError>
where
    C: ConnectionTrait,
{
    let row = connection
        .query_one_raw(statement(
            "INSERT INTO shared_auth.admin_provider_tenant_refs \
                (provider, provider_tenant) VALUES ($1, $2) \
             ON CONFLICT (provider, provider_tenant) DO UPDATE \
                SET provider = EXCLUDED.provider \
             RETURNING provider_tenant_ref",
            vec![
                provider.to_owned().into(),
                provider_tenant.to_owned().into(),
            ],
        ))
        .await
        .map_err(db_error)?
        .ok_or(AuthError::Internal)?;
    row.try_get("", "provider_tenant_ref").map_err(db_error)
}

fn identity_from_row(row: &sea_orm::QueryResult) -> Result<AuthenticatedIdentity, AuthError> {
    Ok(AuthenticatedIdentity {
        shared_user_id: row.try_get("", "shared_user_id").map_err(db_error)?,
        provider: row.try_get("", "provider").map_err(db_error)?,
        provider_tenant: row.try_get("", "provider_tenant").map_err(db_error)?,
        provider_subject: row.try_get("", "provider_subject").map_err(db_error)?,
        email: row.try_get("", "email").map_err(db_error)?,
        email_verified: row.try_get("", "email_verified").map_err(db_error)?,
        roles: Vec::new(),
    })
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

fn db_error<E>(_error: E) -> AuthError {
    // Driver error strings may include the DSN or PostgreSQL DETAIL values
    // (including email/provider identifiers). The request path exposes only a
    // coarse dependency failure and emits no sensitive database diagnostic.
    tracing::error!("shared-auth database operation failed");
    AuthError::Upstream
}
