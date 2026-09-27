//! Nested Fiducia lease + Postgres transaction-scoped advisory lock.
//!
//! [`LockPlan`] selects which backends run:
//! - both (usual): acquire the Fiducia lock/lease, then `BEGIN`, then
//!   `pg_advisory_xact_lock` **inside that transaction**, then the work, then
//!   `COMMIT`/`ROLLBACK` (which releases the xact lock), then Fiducia release
//! - Fiducia only, or Postgres xact-advisory only
//! - neither — only via [`LockPlan::NEITHER`]; [`LockPlan::from_flags`] refuses
//!   the accidental `(false, false)` combination
//!
//! Fiducia is the liveness/fencing complement (github.com/fiducia-cloud). It
//! does not replace a durable uniqueness or transaction guard. Postgres
//! `pg_advisory_xact_lock` is transaction-scoped: it is taken after `BEGIN` and
//! is released automatically on `COMMIT` or `ROLLBACK`. Do not pair it with
//! session-level `pg_advisory_unlock`.
//!
//! Fail-closed rules this module enforces:
//! - a credential never crosses cleartext `http://` to a public host
//! - redirects are refused, so a `Location` cannot capture a bearer
//! - lock keys are bounded; they never enter SQL by concatenation
//! - a fencing token must be a positive integer; `0` is not a grant
//! - `renewed: false` / an expired `lease_expires_ms` is lost fencing — the
//!   Postgres transaction rolls back instead of committing
//! - contention is a try-lock (`wait: false`); waiting is an explicit opt-in

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sea_orm::DatabaseTransaction;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::db::DbStore;
use crate::error::AuthError;

const MAX_LOCK_KEY_BYTES: usize = 128;
/// Exclusive key for committing a global revocation job.
pub const GLOBAL_REVOCATION_LOCK_KEY: &str = "global-revocation:commit";
const FIDUCIA_TTL_MS: u64 = 60_000;
const FIDUCIA_RETRY_MAX: usize = 3;
const FIDUCIA_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Which lock backends to enter. Flip the two booleans independently, but do
/// not construct the unlocked plan except via [`Self::NEITHER`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockPlan {
    /// github.com/fiducia-cloud lock/lease (outer).
    pub fiducia: bool,
    /// `pg_advisory_xact_lock` taken inside a database transaction (inner).
    pub pg_advisory_xact: bool,
}

impl LockPlan {
    pub const BOTH: Self = Self {
        fiducia: true,
        pg_advisory_xact: true,
    };
    pub const FIDUCIA_ONLY: Self = Self {
        fiducia: true,
        pg_advisory_xact: false,
    };
    pub const PG_ONLY: Self = Self {
        fiducia: false,
        pg_advisory_xact: true,
    };
    /// Unlocked. Rare: there is no distributed or transactional exclusion.
    /// Prefer [`Self::from_flags`] so `(false, false)` cannot happen by accident.
    pub const NEITHER: Self = Self {
        fiducia: false,
        pg_advisory_xact: false,
    };

    /// Construct a locked plan. Both flags false is an error; use [`Self::NEITHER`].
    pub fn from_flags(fiducia: bool, pg_advisory_xact: bool) -> Result<Self, NestedLockError> {
        if !fiducia && !pg_advisory_xact {
            return Err(NestedLockError::NeitherRequiresExplicit);
        }
        Ok(Self {
            fiducia,
            pg_advisory_xact,
        })
    }

    pub fn is_neither(self) -> bool {
        !self.fiducia && !self.pg_advisory_xact
    }

    /// Production revocation/commit path: Postgres xact advisory is always on.
    /// Fiducia is added only when a lock/lease endpoint is configured.
    /// This never returns [`Self::NEITHER`].
    pub const fn for_production(fiducia_configured: bool) -> Self {
        if fiducia_configured {
            Self::BOTH
        } else {
            Self::PG_ONLY
        }
    }
}

impl Default for LockPlan {
    fn default() -> Self {
        Self::BOTH
    }
}

/// Observable nesting for tests and docs. Advisory lock is never listed
/// without the surrounding transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStep {
    FiduciaAcquire,
    BeginTxn,
    AdvisoryXactLock,
    Work,
    CommitTxn,
    RollbackTxn,
    FiduciaRelease,
}

/// Steps that will run on the success path for `plan`.
pub fn planned_steps(plan: LockPlan) -> Vec<LockStep> {
    let mut steps = Vec::new();
    if plan.fiducia {
        steps.push(LockStep::FiduciaAcquire);
    }
    if plan.pg_advisory_xact {
        steps.push(LockStep::BeginTxn);
        steps.push(LockStep::AdvisoryXactLock);
    }
    steps.push(LockStep::Work);
    if plan.pg_advisory_xact {
        steps.push(LockStep::CommitTxn);
    }
    if plan.fiducia {
        steps.push(LockStep::FiduciaRelease);
    }
    steps
}

#[derive(Clone, Debug)]
pub struct FiduciaGrant {
    pub key: String,
    pub holder: String,
    pub fencing_token: u64,
    pub lease_expires_ms: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum NestedLockError {
    #[error("fiducia lock/lease is enabled but no Fiducia backend was supplied")]
    FiduciaRequired,
    #[error("pg advisory xact lock is enabled but no database was supplied")]
    PgRequired,
    #[error("unlocked lock plan must be LockPlan::NEITHER, not from_flags(false, false)")]
    NeitherRequiresExplicit,
    #[error("invalid lock key")]
    InvalidKey,
    #[error("refusing to send a Fiducia credential over cleartext http to a public host")]
    InsecureTransport,
    #[error("fiducia lock was not granted")]
    FiduciaBusy,
    #[error("fiducia fencing token was lost or the lease expired")]
    LostFencing,
    #[error("fiducia lock/lease failed")]
    Fiducia,
    #[error("postgres advisory transaction lock failed")]
    Postgres,
    #[error("{0}")]
    Auth(#[from] AuthError),
}

impl From<NestedLockError> for AuthError {
    fn from(error: NestedLockError) -> Self {
        match error {
            NestedLockError::Auth(error) => error,
            NestedLockError::FiduciaRequired
            | NestedLockError::PgRequired
            | NestedLockError::NeitherRequiresExplicit => AuthError::Unavailable,
            NestedLockError::InvalidKey | NestedLockError::InsecureTransport => {
                AuthError::BadRequest("invalid lock configuration")
            }
            NestedLockError::FiduciaBusy => AuthError::Conflict,
            NestedLockError::LostFencing => AuthError::Conflict,
            NestedLockError::Fiducia | NestedLockError::Postgres => AuthError::Upstream,
        }
    }
}

/// Fiducia lock/lease backend. The production adapter talks to the Fiducia
/// node HTTP surface (`POST /v1/locks/acquire`, `POST /v1/locks/release`).
pub trait FiduciaLease: Send + Sync {
    fn acquire(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<FiduciaGrant, NestedLockError>> + Send;
    fn release(
        &self,
        grant: &FiduciaGrant,
    ) -> impl Future<Output = Result<(), NestedLockError>> + Send;
}

/// Postgres backend that begins a transaction and takes a *transaction-scoped*
/// advisory lock before yielding the open transaction to the caller.
pub trait PgAdvisoryXact: Send + Sync {
    type Txn: Send + Sync;
    fn begin_and_lock(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Self::Txn, NestedLockError>> + Send;
    fn commit(&self, txn: Self::Txn) -> impl Future<Output = Result<(), NestedLockError>> + Send;
    fn rollback(&self, txn: Self::Txn) -> impl Future<Output = ()> + Send;
}

pub type NestedLockWork<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, NestedLockError>> + Send + 'a>>;

/// Run `work` under `plan`.
///
/// When both backends are enabled, the Postgres transaction (and therefore the
/// xact advisory lock) is nested *inside* the Fiducia lease. A Fiducia lease
/// never wraps work without a transaction when `pg_advisory_xact` is set, and
/// an xact lock is never taken outside a transaction.
pub async fn with_nested_lock<L, P, T>(
    plan: LockPlan,
    key: &str,
    fiducia: Option<&L>,
    pg: Option<&P>,
    work: impl for<'a> FnOnce(Option<&'a P::Txn>) -> NestedLockWork<'a, T>,
) -> Result<T, NestedLockError>
where
    L: FiduciaLease,
    P: PgAdvisoryXact,
{
    validate_lock_key(key)?;
    if plan.fiducia && fiducia.is_none() {
        return Err(NestedLockError::FiduciaRequired);
    }
    if plan.pg_advisory_xact && pg.is_none() {
        return Err(NestedLockError::PgRequired);
    }
    if plan.is_neither() {
        tracing::warn!(
            key,
            "nested lock plan is neither Fiducia nor pg advisory xact; running without exclusion"
        );
    }

    let grant = if plan.fiducia {
        let backend = fiducia.ok_or(NestedLockError::FiduciaRequired)?;
        Some(backend.acquire(key).await?)
    } else {
        None
    };

    let work_result = if plan.pg_advisory_xact {
        let pg = pg.ok_or(NestedLockError::PgRequired)?;
        match pg.begin_and_lock(key).await {
            Ok(txn) => {
                let result = work(Some(&txn)).await;
                match result {
                    Ok(value) => {
                        if let Some(grant) = grant.as_ref() {
                            if lease_lost_fencing(grant) {
                                pg.rollback(txn).await;
                                tracing::error!(
                                    key,
                                    "fiducia lease expired before commit; rolling back"
                                );
                                Err(NestedLockError::LostFencing)
                            } else {
                                match pg.commit(txn).await {
                                    Ok(()) => Ok(value),
                                    Err(error) => Err(error),
                                }
                            }
                        } else {
                            match pg.commit(txn).await {
                                Ok(()) => Ok(value),
                                Err(error) => Err(error),
                            }
                        }
                    }
                    Err(error) => {
                        pg.rollback(txn).await;
                        Err(error)
                    }
                }
            }
            Err(error) => Err(error),
        }
    } else {
        let result = work(None).await;
        if result.is_ok() {
            if let Some(grant) = grant.as_ref() {
                if lease_lost_fencing(grant) {
                    tracing::error!(key, "fiducia lease expired before work completed");
                    Err(NestedLockError::LostFencing)
                } else {
                    result
                }
            } else {
                result
            }
        } else {
            result
        }
    };

    if let Some(grant) = grant.as_ref() {
        if let Some(backend) = fiducia {
            if let Err(error) = backend.release(grant).await {
                // The lease TTL is the backstop. A failed release must not undo a
                // committed Postgres transaction (Fiducia is liveness, not durability).
                tracing::error!(
                    key = grant.key.as_str(),
                    error = %error,
                    "fiducia lease release failed; TTL is the backstop"
                );
            }
        }
    }

    work_result
}

/// Slash-safe lock identity: 1..=128 printable ASCII bytes, no spaces or
/// control characters. Rejected keys never reach Postgres or Fiducia.
pub fn validate_lock_key(key: &str) -> Result<(), NestedLockError> {
    if key.is_empty() || key.len() > MAX_LOCK_KEY_BYTES {
        return Err(NestedLockError::InvalidKey);
    }
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return Err(NestedLockError::InvalidKey);
    };
    if !first.is_ascii_alphanumeric() {
        return Err(NestedLockError::InvalidKey);
    }
    if !bytes.all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':')
    }) {
        return Err(NestedLockError::InvalidKey);
    }
    Ok(())
}

/// Namespaced advisory-lock name hashed by `pg_advisory_xact_lock` (see db::lock_advisory_xact).
pub(crate) fn advisory_lock_name(key: &str) -> String {
    format!("shared-auth:lock:{key}")
}

fn lease_lost_fencing(grant: &FiduciaGrant) -> bool {
    if grant.fencing_token == 0 {
        return true;
    }
    let Some(expires_ms) = grant.lease_expires_ms else {
        // A grant without an expiry cannot prove it is still held.
        return true;
    };
    now_unix_ms() >= expires_ms
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

impl PgAdvisoryXact for DbStore {
    type Txn = DatabaseTransaction;

    async fn begin_and_lock(&self, key: &str) -> Result<DatabaseTransaction, NestedLockError> {
        validate_lock_key(key)?;
        self.begin_advisory_xact(key)
            .await
            .map_err(|_| NestedLockError::Postgres)
    }

    async fn commit(&self, txn: DatabaseTransaction) -> Result<(), NestedLockError> {
        txn.commit().await.map_err(|_| NestedLockError::Postgres)
    }

    async fn rollback(&self, txn: DatabaseTransaction) {
        if let Err(_error) = txn.rollback().await {
            tracing::error!("postgres rollback after nested lock work failed");
        }
    }
}

/// HTTP adapter for Fiducia node lock/lease endpoints.
pub struct FiduciaHttpLease {
    base: String,
    http: reqwest::Client,
    bearer: Option<String>,
    internal_auth: Option<String>,
    ttl_ms: u64,
    wait: bool,
    holder: String,
}

impl std::fmt::Debug for FiduciaHttpLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FiduciaHttpLease")
            .field("base", &self.base)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .field(
                "internal_auth",
                &self.internal_auth.as_ref().map(|_| "<redacted>"),
            )
            .field("ttl_ms", &self.ttl_ms)
            .field("wait", &self.wait)
            .field("holder", &self.holder)
            .finish()
    }
}

impl FiduciaHttpLease {
    pub fn new(base_url: &str, bearer: Option<String>) -> Result<Self, NestedLockError> {
        Self::build(base_url, bearer, None, false)
    }

    /// Trusted in-cluster hop: `x-fiducia-internal-auth` is bearer-equivalent.
    pub fn internal(
        base_url: &str,
        internal_secret: &str,
        bearer: Option<String>,
    ) -> Result<Self, NestedLockError> {
        if internal_secret.is_empty() {
            return Err(NestedLockError::InvalidKey);
        }
        Self::build(base_url, bearer, Some(internal_secret.to_owned()), false)
    }

    /// Block until granted or the wait budget elapses. Default is try-lock.
    pub fn with_wait(mut self) -> Self {
        self.wait = true;
        self
    }

    fn build(
        base_url: &str,
        bearer: Option<String>,
        internal_auth: Option<String>,
        wait: bool,
    ) -> Result<Self, NestedLockError> {
        let base = normalize_fiducia_base(base_url)?;
        let has_credential = bearer.as_ref().is_some_and(|value| !value.is_empty())
            || internal_auth
                .as_ref()
                .is_some_and(|value| !value.is_empty());
        if has_credential && !transport_is_acceptable(&base) {
            return Err(NestedLockError::InsecureTransport);
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| NestedLockError::Fiducia)?;
        Ok(Self {
            base,
            http,
            bearer: bearer.filter(|value| !value.is_empty()),
            internal_auth,
            ttl_ms: FIDUCIA_TTL_MS,
            wait,
            holder: format!("shared-auth-{}", Uuid::new_v4().simple()),
        })
    }

    fn apply_auth(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = self.bearer.as_deref() {
            request = request.bearer_auth(token);
        }
        if let Some(secret) = self.internal_auth.as_deref() {
            request = request.header("x-fiducia-internal-auth", secret);
        }
        request
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<(u16, Value), NestedLockError> {
        let request = self.apply_auth(self.http.post(format!("{}{path}", self.base)));
        let response = request
            .json(&body)
            .send()
            .await
            .map_err(|_| NestedLockError::Fiducia)?;
        let status = response.status().as_u16();
        let parsed = response.json::<Value>().await.ok().unwrap_or(Value::Null);
        Ok((status, parsed))
    }
}

impl FiduciaLease for FiduciaHttpLease {
    async fn acquire(&self, key: &str) -> Result<FiduciaGrant, NestedLockError> {
        validate_lock_key(key)?;
        let request_id = format!("fdc-attempt-{}", Uuid::new_v4().simple());
        let payload = json!({
            "key": key,
            "holder": self.holder,
            "request_id": request_id,
            "ttl_ms": self.ttl_ms,
            "wait": self.wait,
            "wait_timeout_ms": 30_000,
        });
        let mut last_status = 0_u16;
        let mut last_body = Value::Null;
        for attempt in 0..=FIDUCIA_RETRY_MAX {
            if attempt > 0 {
                tokio::time::sleep(FIDUCIA_RETRY_DELAY).await;
            }
            let (status, body) = self.post_json("/v1/locks/acquire", payload.clone()).await?;
            last_status = status;
            last_body = body;
            if (200..300).contains(&status) {
                break;
            }
            if !fiducia_retryable(status, &last_body) {
                return Err(NestedLockError::Fiducia);
            }
        }
        if !(200..300).contains(&last_status) {
            return Err(NestedLockError::Fiducia);
        }
        grant_from_acquire_output(key, &self.holder, fiducia_output(&last_body))
    }

    async fn release(&self, grant: &FiduciaGrant) -> Result<(), NestedLockError> {
        if grant.fencing_token == 0 {
            return Err(NestedLockError::LostFencing);
        }
        let (status, body) = self
            .post_json(
                "/v1/locks/release",
                json!({
                    "key": grant.key,
                    "holder": grant.holder,
                    "fencing_token": grant.fencing_token,
                }),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(NestedLockError::Fiducia);
        }
        let output = fiducia_output(&body);
        // `released: false` is a committed no-op (lease already lapsed). That
        // is not a crash, and it is not proof we still hold the grant.
        if output.get("released").and_then(Value::as_bool) == Some(false) {
            tracing::warn!(
                key = grant.key.as_str(),
                "fiducia release was a committed no-op; lease had already lapsed"
            );
        }
        Ok(())
    }
}

/// Committed mutation data lives under `result.output`; `committed: true` only
/// means the command reached the Raft log.
fn fiducia_output(body: &Value) -> &Value {
    &body["result"]["output"]
}

fn grant_from_acquire_output(
    key: &str,
    holder: &str,
    output: &Value,
) -> Result<FiduciaGrant, NestedLockError> {
    if output["acquired"].as_bool() != Some(true) {
        return Err(NestedLockError::FiduciaBusy);
    }
    let fencing_token = output["fencing_token"]
        .as_u64()
        .filter(|token| *token > 0)
        .ok_or(NestedLockError::Fiducia)?;
    let lease_expires_ms = output["lease_expires_ms"].as_u64();
    if lease_expires_ms.is_none() {
        return Err(NestedLockError::Fiducia);
    }
    Ok(FiduciaGrant {
        key: key.to_owned(),
        holder: holder.to_owned(),
        fencing_token,
        lease_expires_ms,
    })
}

fn fiducia_retryable(status: u16, body: &Value) -> bool {
    if status == 429 {
        return true;
    }
    status == 503 && explicit_not_leader(body)
}

fn explicit_not_leader(body: &Value) -> bool {
    if body.get("error").and_then(Value::as_str) == Some("not_leader") {
        return body.get("retryable").and_then(Value::as_bool) == Some(true);
    }
    let Some(error) = body.get("error").and_then(Value::as_object) else {
        return false;
    };
    let reason = error
        .get("reason")
        .or_else(|| error.get("code"))
        .and_then(Value::as_str);
    reason == Some("not_leader") && error.get("retryable").and_then(Value::as_bool) == Some(true)
}

fn normalize_fiducia_base(base_url: &str) -> Result<String, NestedLockError> {
    let trimmed = base_url.trim();
    let parsed = url::Url::parse(trimmed).map_err(|_| NestedLockError::InsecureTransport)?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(NestedLockError::InsecureTransport);
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(NestedLockError::InsecureTransport);
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(NestedLockError::InsecureTransport);
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(NestedLockError::InsecureTransport);
    }
    Ok(trimmed.trim_end_matches('/').to_owned())
}

fn transport_is_acceptable(base: &str) -> bool {
    cleartext_http_host(base).is_none_or(cleartext_internal_host_allowed)
}

fn cleartext_http_host(base: &str) -> Option<&str> {
    base.get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))?;
    let authority = base[7..].split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    Some(match host_port.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => host_port.split(':').next().unwrap_or_default(),
    })
}

fn cleartext_internal_host_allowed(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    if host == "::1" {
        return true;
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let seg0 = v6.segments()[0];
        return v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback() || v4.is_private() || v4.is_link_local();
    }
    !host.contains('.')
        || host.ends_with(".svc")
        || host.ends_with(".svc.cluster.local")
        || host.ends_with(".cluster.local")
        || host.ends_with(".internal")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingFiducia {
        order: Mutex<Vec<LockStep>>,
        fail_acquire: bool,
        expires_ms: Option<u64>,
        fencing_token: u64,
    }

    impl FiduciaLease for RecordingFiducia {
        async fn acquire(&self, key: &str) -> Result<FiduciaGrant, NestedLockError> {
            self.order.lock().unwrap().push(LockStep::FiduciaAcquire);
            if self.fail_acquire {
                return Err(NestedLockError::FiduciaBusy);
            }
            Ok(FiduciaGrant {
                key: key.to_owned(),
                holder: "test".into(),
                fencing_token: self.fencing_token,
                lease_expires_ms: self.expires_ms,
            })
        }

        async fn release(&self, _grant: &FiduciaGrant) -> Result<(), NestedLockError> {
            self.order.lock().unwrap().push(LockStep::FiduciaRelease);
            Ok(())
        }
    }

    struct RecordingPg {
        order: Mutex<Vec<LockStep>>,
    }

    struct FakeTxn;

    impl PgAdvisoryXact for RecordingPg {
        type Txn = FakeTxn;

        async fn begin_and_lock(&self, _key: &str) -> Result<FakeTxn, NestedLockError> {
            let mut order = self.order.lock().unwrap();
            order.push(LockStep::BeginTxn);
            order.push(LockStep::AdvisoryXactLock);
            Ok(FakeTxn)
        }

        async fn commit(&self, _txn: FakeTxn) -> Result<(), NestedLockError> {
            self.order.lock().unwrap().push(LockStep::CommitTxn);
            Ok(())
        }

        async fn rollback(&self, _txn: FakeTxn) {
            self.order.lock().unwrap().push(LockStep::RollbackTxn);
        }
    }

    fn live_fiducia() -> RecordingFiducia {
        RecordingFiducia {
            order: Mutex::new(Vec::new()),
            fail_acquire: false,
            expires_ms: Some(u64::MAX),
            fencing_token: 1,
        }
    }

    #[test]
    fn both_nests_advisory_inside_transaction_inside_fiducia() {
        assert_eq!(
            planned_steps(LockPlan::BOTH),
            vec![
                LockStep::FiduciaAcquire,
                LockStep::BeginTxn,
                LockStep::AdvisoryXactLock,
                LockStep::Work,
                LockStep::CommitTxn,
                LockStep::FiduciaRelease,
            ]
        );
    }

    #[test]
    fn pg_only_still_takes_advisory_inside_a_transaction() {
        assert_eq!(
            planned_steps(LockPlan::PG_ONLY),
            vec![
                LockStep::BeginTxn,
                LockStep::AdvisoryXactLock,
                LockStep::Work,
                LockStep::CommitTxn,
            ]
        );
    }

    #[test]
    fn fiducia_only_has_no_xact_lock() {
        assert_eq!(
            planned_steps(LockPlan::FIDUCIA_ONLY),
            vec![
                LockStep::FiduciaAcquire,
                LockStep::Work,
                LockStep::FiduciaRelease
            ]
        );
    }

    #[test]
    fn neither_is_work_only() {
        assert!(LockPlan::NEITHER.is_neither());
        assert_eq!(planned_steps(LockPlan::NEITHER), vec![LockStep::Work]);
    }

    #[test]
    fn from_flags_refuses_accidental_neither() {
        assert!(matches!(
            LockPlan::from_flags(false, false),
            Err(NestedLockError::NeitherRequiresExplicit)
        ));
        assert_eq!(LockPlan::from_flags(true, true).unwrap(), LockPlan::BOTH);
    }

    #[test]
    fn for_production_never_returns_neither() {
        assert_eq!(LockPlan::for_production(true), LockPlan::BOTH);
        assert_eq!(LockPlan::for_production(false), LockPlan::PG_ONLY);
        assert!(!LockPlan::for_production(true).is_neither());
        assert!(!LockPlan::for_production(false).is_neither());
    }

    #[test]
    fn lock_keys_are_bounded_and_slash_safe() {
        assert!(validate_lock_key("principals/rotate").is_ok());
        assert!(validate_lock_key("").is_err());
        assert!(validate_lock_key("/leading-slash").is_err());
        assert!(validate_lock_key("has space").is_err());
        assert!(validate_lock_key("bad\nkey").is_err());
        assert!(validate_lock_key(&"a".repeat(MAX_LOCK_KEY_BYTES + 1)).is_err());
    }

    #[test]
    fn zero_fencing_token_is_lost_fencing() {
        let grant = FiduciaGrant {
            key: "k".into(),
            holder: "h".into(),
            fencing_token: 0,
            lease_expires_ms: Some(u64::MAX),
        };
        assert!(lease_lost_fencing(&grant));
    }

    #[test]
    fn missing_lease_expiry_is_lost_fencing() {
        let grant = FiduciaGrant {
            key: "k".into(),
            holder: "h".into(),
            fencing_token: 7,
            lease_expires_ms: None,
        };
        assert!(lease_lost_fencing(&grant));
    }

    #[test]
    fn acquire_output_requires_positive_fencing_token_and_expiry() {
        let ok = json!({"acquired": true, "fencing_token": 9, "lease_expires_ms": 99});
        let grant = grant_from_acquire_output("k", "h", &ok).unwrap();
        assert_eq!(grant.fencing_token, 9);
        assert!(matches!(
            grant_from_acquire_output(
                "k",
                "h",
                &json!({"acquired": true, "fencing_token": 0, "lease_expires_ms": 99})
            ),
            Err(NestedLockError::Fiducia)
        ));
        assert!(matches!(
            grant_from_acquire_output("k", "h", &json!({"acquired": true, "fencing_token": 9})),
            Err(NestedLockError::Fiducia)
        ));
        assert!(matches!(
            grant_from_acquire_output(
                "k",
                "h",
                &json!({"acquired": false, "fencing_token": 9, "lease_expires_ms": 99})
            ),
            Err(NestedLockError::FiduciaBusy)
        ));
    }

    #[test]
    fn bearer_never_crosses_cleartext_to_a_public_host() {
        assert!(matches!(
            FiduciaHttpLease::new("http://api.fiducia.cloud", Some("secret".into())),
            Err(NestedLockError::InsecureTransport)
        ));
        assert!(matches!(
            FiduciaHttpLease::new("http://8.8.8.8", Some("secret".into())),
            Err(NestedLockError::InsecureTransport)
        ));
        assert!(FiduciaHttpLease::new("https://api.fiducia.cloud", Some("secret".into())).is_ok());
        assert!(FiduciaHttpLease::new("http://fiducia-node:8090", Some("secret".into())).is_ok());
        assert!(FiduciaHttpLease::new("http://127.0.0.1:8090", Some("secret".into())).is_ok());
        assert!(
            FiduciaHttpLease::new("http://user:pass@fiducia-node:8090", Some("secret".into()))
                .is_err()
        );
    }

    #[test]
    fn anonymous_cleartext_to_public_host_is_allowed() {
        // No credential: nothing to disclose. Still refuse userinfo URLs.
        assert!(FiduciaHttpLease::new("http://api.fiducia.cloud", None).is_ok());
    }

    #[test]
    fn debug_redacts_credentials() {
        let lease = FiduciaHttpLease::new("https://api.fiducia.cloud", Some("super-secret".into()))
            .unwrap();
        let rendered = format!("{lease:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn not_leader_is_retryable_only_when_marked() {
        assert!(fiducia_retryable(
            503,
            &json!({"error": {"reason": "not_leader", "retryable": true}})
        ));
        assert!(!fiducia_retryable(
            503,
            &json!({"error": {"reason": "not_leader", "retryable": false}})
        ));
        assert!(fiducia_retryable(429, &json!({})));
        assert!(!fiducia_retryable(500, &json!({})));
    }

    #[tokio::test]
    async fn both_runs_in_nested_order() {
        let fiducia = live_fiducia();
        let pg = RecordingPg {
            order: Mutex::new(Vec::new()),
        };
        let value = with_nested_lock(
            LockPlan::BOTH,
            "principals/rotate",
            Some(&fiducia),
            Some(&pg),
            |txn| {
                Box::pin(async move {
                    assert!(txn.is_some());
                    Ok(7_u8)
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(
            fiducia.order.lock().unwrap().as_slice(),
            &[LockStep::FiduciaAcquire, LockStep::FiduciaRelease]
        );
        assert_eq!(
            pg.order.lock().unwrap().as_slice(),
            &[
                LockStep::BeginTxn,
                LockStep::AdvisoryXactLock,
                LockStep::CommitTxn
            ]
        );
        assert_eq!(
            advisory_lock_name("principals/rotate"),
            "shared-auth:lock:principals/rotate"
        );
    }

    #[tokio::test]
    async fn work_error_rolls_back_then_releases_fiducia() {
        let fiducia = live_fiducia();
        let pg = RecordingPg {
            order: Mutex::new(Vec::new()),
        };
        let err = with_nested_lock(
            LockPlan::BOTH,
            "principals/rotate",
            Some(&fiducia),
            Some(&pg),
            |_txn| Box::pin(async { Err::<(), _>(NestedLockError::Auth(AuthError::Conflict)) }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, NestedLockError::Auth(AuthError::Conflict)));
        assert_eq!(
            fiducia.order.lock().unwrap().as_slice(),
            &[LockStep::FiduciaAcquire, LockStep::FiduciaRelease]
        );
        assert_eq!(
            pg.order.lock().unwrap().as_slice(),
            &[
                LockStep::BeginTxn,
                LockStep::AdvisoryXactLock,
                LockStep::RollbackTxn
            ]
        );
    }

    #[tokio::test]
    async fn expired_fiducia_lease_rolls_back_instead_of_committing() {
        let fiducia = RecordingFiducia {
            order: Mutex::new(Vec::new()),
            fail_acquire: false,
            expires_ms: Some(1),
            fencing_token: 3,
        };
        let pg = RecordingPg {
            order: Mutex::new(Vec::new()),
        };
        let err = with_nested_lock(
            LockPlan::BOTH,
            "principals/rotate",
            Some(&fiducia),
            Some(&pg),
            |_txn| Box::pin(async { Ok(()) }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, NestedLockError::LostFencing));
        assert_eq!(
            pg.order.lock().unwrap().as_slice(),
            &[
                LockStep::BeginTxn,
                LockStep::AdvisoryXactLock,
                LockStep::RollbackTxn
            ]
        );
        assert!(fiducia
            .order
            .lock()
            .unwrap()
            .contains(&LockStep::FiduciaRelease));
    }

    #[tokio::test]
    async fn invalid_key_never_touches_backends() {
        let fiducia = live_fiducia();
        let pg = RecordingPg {
            order: Mutex::new(Vec::new()),
        };
        let err = with_nested_lock(
            LockPlan::BOTH,
            "has space",
            Some(&fiducia),
            Some(&pg),
            |_txn| Box::pin(async { Ok(()) }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, NestedLockError::InvalidKey));
        assert!(fiducia.order.lock().unwrap().is_empty());
        assert!(pg.order.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_backend_fails_closed() {
        let err = with_nested_lock(
            LockPlan::BOTH,
            "k",
            None::<&RecordingFiducia>,
            None::<&RecordingPg>,
            |_txn| Box::pin(async { Ok(()) }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, NestedLockError::FiduciaRequired));
    }

    #[tokio::test]
    async fn neither_runs_work_without_backends() {
        let value = with_nested_lock(
            LockPlan::NEITHER,
            "k",
            None::<&RecordingFiducia>,
            None::<&RecordingPg>,
            |txn| {
                Box::pin(async move {
                    assert!(txn.is_none());
                    Ok(1_u8)
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 1);
    }
}
