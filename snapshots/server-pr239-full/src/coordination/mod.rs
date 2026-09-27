//! Composite mutual exclusion: a Fiducia lease wrapped around a PostgreSQL
//! advisory lock.
//!
//! Shared Auth has a handful of operations that must not run twice at once —
//! global revocation commits, SCIM tenant reconciliation, SAML certificate
//! rotation, key rollover, outbox drains. Two mechanisms are available and they
//! fail in *different* ways, which is the entire reason this module exists
//! rather than a call to one of them.
//!
//! **Fiducia** ([`github.com/fiducia-cloud`]) is a Raft-backed coordination
//! service: cluster-wide, spans more than one database, and hands back a
//! **fencing token** so a downstream effect can reject a writer whose authority
//! has already been revoked. Its weakness is the weakness of every lease: it is
//! bounded by *time*. A lease can lapse while its holder is alive but stalled —
//! a long GC pause, a paused container, a network partition — and Fiducia will
//! correctly promote someone else while the original holder still believes it
//! holds the lock. That is not a bug in Fiducia; it is what a lease is.
//!
//! **PostgreSQL advisory locks** are the opposite trade. They are confined to a
//! single database and carry no token, but they are held by a *connection*, not
//! by a clock. There is no interval during which two sessions both hold one. A
//! transaction-scoped advisory lock is released by the same COMMIT or ROLLBACK
//! that decides the data, so the lock and the write it guards cannot disagree.
//!
//! Neither is a superset of the other, so this module composes them.
//!
//! # Nesting order: Fiducia outside, advisory inside
//!
//! When both are enabled the acquisition order is always Fiducia first, then
//! the advisory lock inside the database transaction. It is never the reverse,
//! and the order is not configurable. Three independent reasons:
//!
//! 1. **A pooled connection must never wait on a network round trip.** Fiducia
//!    with `wait: true` reserves a FIFO queue slot and the *client* polls — a
//!    contended acquire can take the whole wait budget. Taking the advisory
//!    lock first would mean holding an open Postgres transaction, and therefore
//!    a pool connection, for that entire wait. A slow coordinator would then
//!    present as connection-pool exhaustion and take down authentication
//!    requests that have nothing to do with the guarded work.
//!
//! 2. **The advisory lock is the backstop for lease expiry.** Because it is the
//!    inner lock and is scoped to the transaction, the actual database mutation
//!    is serialized by Postgres regardless of what the lease believes. If the
//!    Fiducia lease silently lapses mid-work, the second holder still blocks on
//!    the advisory lock until the first transaction commits or rolls back. The
//!    two writers cannot interleave *in the database*. This is the property
//!    that survives a clock problem, and it is why running both is worth the
//!    extra round trip.
//!
//! 3. **One global order prevents deadlock between the two subsystems.** Two
//!    call sites that took the locks in opposite orders could deadlock against
//!    each other in a way neither system can detect: Postgres cannot see a
//!    Fiducia queue, and Fiducia cannot see `pg_locks`. Fixing the order here,
//!    once, removes the possibility rather than documenting it.
//!
//! Release is the mirror image and mostly automatic: COMMIT or ROLLBACK drops
//! the advisory lock, and only then is the Fiducia lease released.
//!
//! # Why the work runs inside a closure
//!
//! `pg_advisory_xact_lock` is released by the end of the transaction and
//! **cannot be unlocked manually**. There is no way to hand a caller a guard
//! object that owns a transaction-scoped advisory lock and still lets the
//! caller choose when the transaction ends. So the transaction and the guarded
//! work must be the same scope, which makes a closure the only honest API. The
//! signature mirrors `sea_orm::TransactionTrait::transaction` deliberately, so
//! it reads the same as the transactions already in this codebase.
//!
//! # Policy
//!
//! [`CoordinationPolicy`] flips each mechanism independently:
//!
//! | policy | meaning |
//! |---|---|
//! | [`both`](CoordinationPolicy::both) | cluster-wide lease **and** in-database serialization. The default for anything that mutates authorization state. |
//! | [`fiducia_only`](CoordinationPolicy::fiducia_only) | the critical section's effects are not confined to this database (an external API call, a fan-out, a different datastore), so an advisory lock would guard nothing. |
//! | [`advisory_only`](CoordinationPolicy::advisory_only) | the work is entirely inside this one database and Fiducia is not deployed in this realm. Correct and cheap; it just does not extend past the database. |
//! | [`unsynchronized`](CoordinationPolicy::unsynchronized) | no lock at all. Rare and deliberately awkward to reach — see its documentation. |
//!
//! # Fail closed
//!
//! If a mechanism is enabled and cannot be acquired, the operation fails. It is
//! never downgraded to the other mechanism. Silently continuing with weaker
//! mutual exclusion than the caller asked for is how a coordination outage
//! turns into data corruption, and it is precisely the case where nobody is
//! reading logs. There is no "degrade on outage" flag, and adding one would be
//! a mistake: a caller who genuinely wants advisory-only behaviour during an
//! outage can say so with a policy, at the call site, in review.
//!
//! [`github.com/fiducia-cloud`]: https://github.com/fiducia-cloud

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, Statement,
    TransactionTrait,
};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

/// Upper bound on how long `pg_advisory_xact_lock` may block before Postgres
/// aborts the statement. A blocking advisory lock with no `lock_timeout` waits
/// forever and holds a pool connection while it does, so this module always
/// sets one; there is no way to opt out.
pub const DEFAULT_ADVISORY_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Default Fiducia lease TTL. Long enough that a normal critical section will
/// not need a renewal, short enough that a crashed holder is reaped promptly.
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(60);

/// Default budget for waiting on a contended Fiducia lock before giving up.
pub const DEFAULT_LEASE_WAIT: Duration = Duration::from_secs(30);

/// Which mechanisms guard a critical section.
///
/// Both fields are plain booleans on purpose — the caller asked for a flag they
/// could flip — but the constructors below are the intended way to build one,
/// because a named constructor forces the *reason* for the combination into the
/// call site where a reviewer will see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoordinationPolicy {
    /// Take the outer, cluster-wide Fiducia lease.
    pub fiducia: bool,
    /// Take the inner, database-scoped PostgreSQL advisory lock.
    pub advisory: bool,
}

impl CoordinationPolicy {
    /// Cluster-wide lease plus in-database serialization. Use this unless there
    /// is a specific reason not to.
    pub const fn both() -> Self {
        Self {
            fiducia: true,
            advisory: true,
        }
    }

    /// Lease only. Correct when the guarded effects are not confined to this
    /// database — an outbound API call, a fan-out to another datastore, a
    /// cross-region operation — so an advisory lock in *this* database would
    /// serialize nothing that matters.
    pub const fn fiducia_only() -> Self {
        Self {
            fiducia: true,
            advisory: false,
        }
    }

    /// Advisory lock only. Correct when every effect of the critical section is
    /// a write to this database and Fiducia is not deployed in this realm. It
    /// is genuinely safe within that boundary; it simply does not extend past
    /// the database.
    pub const fn advisory_only() -> Self {
        Self {
            fiducia: false,
            advisory: true,
        }
    }

    /// No mutual exclusion at all. The work still runs inside a transaction, so
    /// it is atomic, but nothing prevents a second caller from running it
    /// concurrently.
    ///
    /// This is rare and should stay rare. It is legitimate in exactly two
    /// situations, and both should be stated in a comment at the call site:
    ///
    /// * a single-process development or test binary where no second writer can
    ///   exist; or
    /// * work whose mutual exclusion is already guaranteed by the schema —
    ///   a unique index, an `ON CONFLICT DO NOTHING`, or a `SELECT … FOR UPDATE`
    ///   on the row being changed. In that case Postgres is already doing the
    ///   serialization and a second lock buys nothing.
    ///
    /// If neither applies, this is the wrong policy.
    pub const fn unsynchronized() -> Self {
        Self {
            fiducia: false,
            advisory: false,
        }
    }

    /// True when no mechanism is enabled.
    pub const fn is_unsynchronized(&self) -> bool {
        !self.fiducia && !self.advisory
    }
}

impl Default for CoordinationPolicy {
    /// The safe combination. A caller who does not think about it gets the
    /// strongest guarantee, not the cheapest one.
    fn default() -> Self {
        Self::both()
    }
}

/// Whether the advisory lock excludes all other holders or only writers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvisoryMode {
    /// `pg_advisory_xact_lock` — excludes every other holder of the same key.
    Exclusive,
    /// `pg_advisory_xact_lock_shared` — several readers may hold it at once,
    /// but no exclusive holder can run while any of them does.
    Shared,
}

/// Whether an acquisition may wait for a busy lock or must fail immediately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contention {
    /// Wait, bounded by `lease_wait` (Fiducia) and `advisory_lock_timeout`
    /// (Postgres). Neither wait is unbounded.
    Wait,
    /// Return [`CoordinationError::Contended`] the moment the lock is found
    /// held. Use this for opportunistic background work — a periodic reconcile
    /// that another node is already running should simply skip this tick rather
    /// than queue up behind it.
    Fail,
}

/// A name for one mutually-exclusive operation, in both vocabularies at once.
///
/// The same logical operation needs a string key for Fiducia and a `bigint` for
/// Postgres. Deriving both from one value here is what keeps them from drifting
/// — a call site that hand-rolled the advisory key would eventually guard a
/// different thing than the lease it sits inside, and nothing would report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinationKey {
    namespace: &'static str,
    name: String,
}

impl CoordinationKey {
    /// Build a key. `namespace` is a compile-time constant so the set of
    /// namespaces stays greppable; `name` may be dynamic (a tenant id, a
    /// registration id, a job id).
    pub fn new(namespace: &'static str, name: impl Into<String>) -> Self {
        Self {
            namespace,
            name: name.into(),
        }
    }

    /// The Fiducia lock key. Fiducia keys are hierarchical strings, so the
    /// namespace prefix also keeps Shared Auth's keys from colliding with
    /// another service's in a shared Fiducia cluster.
    pub fn fiducia_key(&self) -> String {
        format!("shared-auth/{}/{}", self.namespace, self.name)
    }

    /// The 64-bit advisory-lock key.
    ///
    /// Two things about this are worth stating plainly.
    ///
    /// **Advisory locks are database-global, not schema-scoped.** Shared Auth
    /// connects with `search_path=shared_auth`, but `pg_advisory_xact_lock` does
    /// not care: every application sharing this database draws from one 64-bit
    /// namespace. The `shared-auth/` prefix hashed in below is what stops us
    /// colliding with another application's hand-picked constant like `1` or
    /// `42`, which is a real and surprisingly common way to deadlock two
    /// unrelated services against each other.
    ///
    /// **A hash collision over-locks; it never under-locks.** Two different
    /// keys landing on the same `i64` would serialize against each other
    /// needlessly — a liveness cost, and at 2^-64 per pair not one worth
    /// engineering around. The failure this ordering rules out is the dangerous
    /// one: two callers who *should* exclude each other never end up with
    /// different lock keys, because the key is a pure function of the name.
    pub fn advisory_key(&self) -> i64 {
        let mut hasher = Sha256::new();
        hasher.update(b"shared-auth/advisory/v1\0");
        hasher.update(self.namespace.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.name.as_bytes());
        let digest = hasher.finalize();
        let mut head = [0u8; 8];
        head.copy_from_slice(&digest[..8]);
        i64::from_be_bytes(head)
    }
}

impl fmt::Display for CoordinationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.namespace, self.name)
    }
}

/// Tuning for one guarded section.
#[derive(Clone, Debug)]
pub struct CoordinationOptions {
    pub policy: CoordinationPolicy,
    pub contention: Contention,
    pub advisory_mode: AdvisoryMode,
    /// Fiducia lease TTL. The lease is *not* renewed automatically — see
    /// [`Lease::renew`] for why.
    pub lease_ttl: Duration,
    /// Total time to keep waiting for a contended Fiducia lock.
    pub lease_wait: Duration,
    /// `lock_timeout` applied to the advisory acquisition. Bounded, always set.
    pub advisory_lock_timeout: Duration,
}

impl Default for CoordinationOptions {
    fn default() -> Self {
        Self {
            policy: CoordinationPolicy::default(),
            contention: Contention::Wait,
            advisory_mode: AdvisoryMode::Exclusive,
            lease_ttl: DEFAULT_LEASE_TTL,
            lease_wait: DEFAULT_LEASE_WAIT,
            advisory_lock_timeout: DEFAULT_ADVISORY_LOCK_TIMEOUT,
        }
    }
}

impl CoordinationOptions {
    /// Shorthand for the common "run this under both locks" case.
    pub fn both() -> Self {
        Self {
            policy: CoordinationPolicy::both(),
            ..Self::default()
        }
    }

    /// Shorthand for opportunistic background work that should skip a tick
    /// rather than queue behind another node.
    pub fn skip_if_busy() -> Self {
        Self {
            contention: Contention::Fail,
            ..Self::default()
        }
    }

    pub fn with_policy(mut self, policy: CoordinationPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_lease_ttl(mut self, ttl: Duration) -> Self {
        self.lease_ttl = ttl;
        self
    }
}

/// Why a guarded section could not run.
#[derive(Debug)]
pub enum CoordinationError {
    /// The lock is held elsewhere. Under [`Contention::Fail`] this is the
    /// expected, non-exceptional outcome; under [`Contention::Wait`] it means
    /// the wait budget or `lock_timeout` elapsed.
    Contended { key: String },
    /// Fiducia was enabled but could not be reached or refused the request.
    /// This is deliberately NOT downgraded to advisory-only.
    LeaseUnavailable { key: String, detail: String },
    /// A held lease was lost before the work finished — Fiducia has already
    /// reaped the grant and may have promoted another holder. Any external
    /// effect performed under the old fencing token must be assumed rejected.
    LeaseLost { key: String },
    /// Fiducia was enabled but no client is wired into this process.
    LeaseBackendMissing { key: String },
    /// The database rejected the lock or the transaction.
    Database,
    /// The guarded work itself failed. The transaction is rolled back and both
    /// locks released.
    Work(crate::error::AuthError),
}

impl fmt::Display for CoordinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contended { key } => write!(formatter, "coordination: {key} is held elsewhere"),
            Self::LeaseUnavailable { key, detail } => {
                write!(
                    formatter,
                    "coordination: lease for {key} unavailable: {detail}"
                )
            }
            Self::LeaseLost { key } => {
                write!(
                    formatter,
                    "coordination: lost the lease for {key} mid-operation"
                )
            }
            Self::LeaseBackendMissing { key } => write!(
                formatter,
                "coordination: {key} requires a Fiducia lease but no client is configured"
            ),
            Self::Database => write!(formatter, "coordination: database lock failed"),
            Self::Work(error) => write!(formatter, "coordination: guarded work failed: {error}"),
        }
    }
}

impl std::error::Error for CoordinationError {}

impl From<crate::error::AuthError> for CoordinationError {
    fn from(error: crate::error::AuthError) -> Self {
        Self::Work(error)
    }
}

impl From<CoordinationError> for crate::error::AuthError {
    /// Collapse to the coarse request-time error set. Contention is a
    /// [`Conflict`](crate::error::AuthError::Conflict), not a server fault: the
    /// caller may retry and nothing is broken. A lost or unreachable lease is
    /// [`Unavailable`](crate::error::AuthError::Unavailable) — we could not
    /// decide it was safe to proceed, which is exactly the "fail closed without
    /// claiming the user is wrong" posture the rest of this server takes.
    fn from(error: CoordinationError) -> Self {
        match error {
            CoordinationError::Contended { .. } => Self::Conflict,
            CoordinationError::LeaseUnavailable { .. }
            | CoordinationError::LeaseLost { .. }
            | CoordinationError::LeaseBackendMissing { .. } => Self::Unavailable,
            CoordinationError::Database => Self::Upstream,
            CoordinationError::Work(inner) => inner,
        }
    }
}

/// One granted Fiducia lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseGrant {
    pub fencing_token: u64,
    pub lease_expires_ms: Option<u64>,
}

/// What the guarded closure is told about its own authority.
///
/// `fencing_token` is `None` whenever the policy did not take a Fiducia lease.
/// That is not an inconvenience to paper over: a caller that performs an
/// external, non-transactional effect **must** pass a fencing token to the
/// receiving system, and if it finds `None` here it is being run under a policy
/// that cannot give it one. Treat `None` as "this policy does not authorize a
/// fenced external effect", not as "no fencing needed".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fenced {
    pub fencing_token: Option<u64>,
    pub lease_expires_ms: Option<u64>,
}

/// The Fiducia operations this module needs.
///
/// Shared Auth does not currently depend on the `fiducia-client` crate, and
/// this module deliberately does not add that dependency: a trait keeps the
/// composition testable with an in-memory fake, keeps a Fiducia outage from
/// being a compile-time concern for realms that do not deploy it, and makes the
/// integration a single `impl` block rather than a rewrite. The method shapes
/// mirror `fiducia_client::AsyncFiduciaClient::{acquire, renew, release}`
/// exactly, so the adapter is mechanical — see `docs/coordination-locks.md`.
///
/// Futures are hand-boxed rather than using an `async fn` in trait so the trait
/// stays object-safe (`Arc<dyn FiduciaLeases>`) without adding `async-trait`.
pub trait FiduciaLeases: Send + Sync + 'static {
    /// Acquire `key` for `holder`. `Ok(None)` means the lock is held by someone
    /// else — contention, not failure. `Err` means we do *not* know who holds
    /// it, which is a different and more dangerous state.
    fn acquire<'a>(
        &'a self,
        key: &'a str,
        holder: &'a str,
        ttl_ms: u64,
        wait: bool,
        wait_budget_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Option<LeaseGrant>, String>> + Send + 'a>>;

    /// Extend a held lease without changing its fencing token. `Ok(None)` means
    /// the grant was already reaped — lost authority, not a warning.
    fn renew<'a>(
        &'a self,
        key: &'a str,
        holder: &'a str,
        fencing_token: u64,
        ttl_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, String>> + Send + 'a>>;

    /// Release a held lease. `Ok(false)` is a committed no-op — usually a lease
    /// that had already lapsed.
    fn release<'a>(
        &'a self,
        key: &'a str,
        holder: &'a str,
        fencing_token: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;
}

/// Composes a Fiducia lease with a PostgreSQL advisory lock.
#[derive(Clone)]
pub struct Coordinator {
    db: Arc<DatabaseConnection>,
    fiducia: Option<Arc<dyn FiduciaLeases>>,
    holder: Arc<str>,
}

impl fmt::Debug for Coordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Coordinator")
            .field("fiducia_configured", &self.fiducia.is_some())
            .field("holder", &self.holder)
            .finish_non_exhaustive()
    }
}

impl Coordinator {
    /// Build a coordinator. `holder` identifies this process to Fiducia and is
    /// also the release key, so it must be unguessable and stable for the
    /// lifetime of the process — a pod name plus a random suffix, not a
    /// hostname alone. Two processes sharing a holder identity can release each
    /// other's leases.
    pub fn new(
        db: Arc<DatabaseConnection>,
        fiducia: Option<Arc<dyn FiduciaLeases>>,
        holder: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            db,
            fiducia,
            holder: holder.into(),
        }
    }

    /// True when a Fiducia client is wired in. A policy that requests a lease
    /// without one fails closed rather than running unguarded.
    pub fn has_lease_backend(&self) -> bool {
        self.fiducia.is_some()
    }

    /// Run `work` inside a database transaction guarded by the configured
    /// mechanisms.
    ///
    /// Order is fixed: acquire the Fiducia lease, open the transaction, take the
    /// advisory lock, run the work, commit, release the lease. On any failure
    /// the transaction is rolled back (which releases the advisory lock) before
    /// the lease is released, so the locks always unwind inside-out.
    ///
    /// The closure receives the transaction — every statement the guarded work
    /// runs must use it, not the pool, or that statement runs on a different
    /// connection that does **not** hold the advisory lock.
    pub async fn with_transaction<T, F>(
        &self,
        key: &CoordinationKey,
        options: &CoordinationOptions,
        work: F,
    ) -> Result<T, CoordinationError>
    where
        T: Send,
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
                Fenced,
            ) -> Pin<
                Box<dyn Future<Output = Result<T, CoordinationError>> + Send + 'c>,
            > + Send,
    {
        let lease = if options.policy.fiducia {
            Some(self.acquire_lease(key, options).await?)
        } else {
            None
        };

        let fenced = Fenced {
            fencing_token: lease.map(|grant| grant.fencing_token),
            lease_expires_ms: lease.and_then(|grant| grant.lease_expires_ms),
        };

        let outcome = self.run_guarded(key, options, fenced, work).await;

        // Release after the transaction has ended, never before: the advisory
        // lock is the inner lock and must be the first one dropped.
        if let Some(grant) = lease {
            self.release_lease(key, grant).await;
        }

        outcome
    }

    async fn run_guarded<T, F>(
        &self,
        key: &CoordinationKey,
        options: &CoordinationOptions,
        fenced: Fenced,
        work: F,
    ) -> Result<T, CoordinationError>
    where
        T: Send,
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
                Fenced,
            ) -> Pin<
                Box<dyn Future<Output = Result<T, CoordinationError>> + Send + 'c>,
            > + Send,
    {
        let transaction = self.db.begin().await.map_err(|error| {
            tracing::error!(key = %key, "coordination: could not open transaction: {error}");
            CoordinationError::Database
        })?;

        if options.policy.advisory {
            if let Err(error) = acquire_advisory(&transaction, key, options).await {
                // Roll back explicitly so the connection returns to the pool
                // immediately rather than waiting on drop.
                let _ = transaction.rollback().await;
                return Err(error);
            }
        }

        match work(&transaction, fenced).await {
            Ok(value) => match transaction.commit().await {
                Ok(()) => Ok(value),
                Err(error) => {
                    tracing::error!(key = %key, "coordination: commit failed: {error}");
                    Err(CoordinationError::Database)
                }
            },
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(error)
            }
        }
    }

    async fn acquire_lease(
        &self,
        key: &CoordinationKey,
        options: &CoordinationOptions,
    ) -> Result<LeaseGrant, CoordinationError> {
        let Some(fiducia) = self.fiducia.as_ref() else {
            return Err(CoordinationError::LeaseBackendMissing {
                key: key.to_string(),
            });
        };

        let fiducia_key = key.fiducia_key();
        let wait = matches!(options.contention, Contention::Wait);
        let result = fiducia
            .acquire(
                &fiducia_key,
                &self.holder,
                millis(options.lease_ttl),
                wait,
                millis(options.lease_wait),
            )
            .await;

        match result {
            Ok(Some(grant)) => Ok(grant),
            Ok(None) => Err(CoordinationError::Contended {
                key: key.to_string(),
            }),
            // An error is not contention. We do not know whether anyone holds
            // the lock, so we must not proceed and must not silently fall back
            // to the advisory lock alone.
            Err(detail) => Err(CoordinationError::LeaseUnavailable {
                key: key.to_string(),
                detail,
            }),
        }
    }

    /// Extend a lease held by this coordinator.
    ///
    /// There is no background auto-renewer, on purpose. A renewal task that
    /// outlives a stalled worker is how a lease-based system produces two
    /// simultaneous holders that both believe they are current: the worker is
    /// wedged, the renewer keeps the lease alive, and the safety property the
    /// TTL exists to provide is gone. Long critical sections should either
    /// renew explicitly at points where they have proven they are still making
    /// progress, or be restructured into shorter ones.
    pub async fn renew_lease(
        &self,
        key: &CoordinationKey,
        grant: LeaseGrant,
        ttl: Duration,
    ) -> Result<LeaseGrant, CoordinationError> {
        let Some(fiducia) = self.fiducia.as_ref() else {
            return Err(CoordinationError::LeaseBackendMissing {
                key: key.to_string(),
            });
        };
        let fiducia_key = key.fiducia_key();
        match fiducia
            .renew(&fiducia_key, &self.holder, grant.fencing_token, millis(ttl))
            .await
        {
            Ok(Some(lease_expires_ms)) => Ok(LeaseGrant {
                fencing_token: grant.fencing_token,
                lease_expires_ms: Some(lease_expires_ms),
            }),
            Ok(None) => Err(CoordinationError::LeaseLost {
                key: key.to_string(),
            }),
            Err(detail) => Err(CoordinationError::LeaseUnavailable {
                key: key.to_string(),
                detail,
            }),
        }
    }

    async fn release_lease(&self, key: &CoordinationKey, grant: LeaseGrant) {
        let Some(fiducia) = self.fiducia.as_ref() else {
            return;
        };
        let fiducia_key = key.fiducia_key();
        match fiducia
            .release(&fiducia_key, &self.holder, grant.fencing_token)
            .await
        {
            // A committed no-op means the lease had already lapsed. The work is
            // already committed or rolled back at this point, so this is a
            // signal about lease sizing, not a failure to report to the caller.
            Ok(false) => tracing::warn!(
                key = %key,
                "coordination: release matched no grant; the lease had already lapsed"
            ),
            Ok(true) => {}
            Err(detail) => tracing::warn!(
                key = %key,
                "coordination: lease release failed, leaving it to expire: {detail}"
            ),
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Take the transaction-scoped advisory lock.
///
/// `lock_timeout` is set first and always. `pg_advisory_xact_lock` has no
/// timeout of its own: without this it waits forever, and it waits while
/// holding an open transaction and a pooled connection, so one stuck holder
/// would drain the pool and take down unrelated authentication traffic. It is
/// set with `set_config(..., is_local => true)` rather than a `SET LOCAL`
/// string so the value is a bound parameter and cannot be spliced into SQL.
async fn acquire_advisory(
    transaction: &DatabaseTransaction,
    key: &CoordinationKey,
    options: &CoordinationOptions,
) -> Result<(), CoordinationError> {
    let timeout_ms = millis(options.advisory_lock_timeout).max(1);
    // sea-orm 2.0: `query_one`/`execute` take a StatementBuilder; a prebuilt
    // `Statement` goes through the `_raw` variants.
    transaction
        .query_one_raw(statement(
            "select set_config('lock_timeout', $1, true)",
            vec![format!("{timeout_ms}ms").into()],
        ))
        .await
        .map_err(|error| {
            tracing::error!(key = %key, "coordination: could not set lock_timeout: {error}");
            CoordinationError::Database
        })?;

    let advisory_key = key.advisory_key();

    match options.contention {
        Contention::Fail => {
            let function = match options.advisory_mode {
                AdvisoryMode::Exclusive => "pg_try_advisory_xact_lock",
                AdvisoryMode::Shared => "pg_try_advisory_xact_lock_shared",
            };
            let row = transaction
                .query_one_raw(statement(
                    &format!("select {function}($1) as locked"),
                    vec![advisory_key.into()],
                ))
                .await
                .map_err(|error| {
                    tracing::error!(key = %key, "coordination: advisory try-lock failed: {error}");
                    CoordinationError::Database
                })?
                .ok_or(CoordinationError::Database)?;
            let locked: bool = row.try_get("", "locked").map_err(|error| {
                tracing::error!(key = %key, "coordination: advisory try-lock read failed: {error}");
                CoordinationError::Database
            })?;
            if locked {
                Ok(())
            } else {
                Err(CoordinationError::Contended {
                    key: key.to_string(),
                })
            }
        }
        Contention::Wait => {
            let function = match options.advisory_mode {
                AdvisoryMode::Exclusive => "pg_advisory_xact_lock",
                AdvisoryMode::Shared => "pg_advisory_xact_lock_shared",
            };
            match transaction
                .execute_raw(statement(
                    &format!("select {function}($1)"),
                    vec![advisory_key.into()],
                ))
                .await
            {
                Ok(_) => Ok(()),
                Err(error) => {
                    // A `lock_timeout` abort is contention, not a fault: the
                    // caller may retry and nothing is broken. Anything else is
                    // a real database failure. sea-orm 2.0 does not surface a
                    // stable typed SQLSTATE here, so this matches on the code
                    // and the message text Postgres emits for 55P03.
                    if is_lock_timeout(&error) {
                        Err(CoordinationError::Contended {
                            key: key.to_string(),
                        })
                    } else {
                        tracing::error!(key = %key, "coordination: advisory lock failed: {error}");
                        Err(CoordinationError::Database)
                    }
                }
            }
        }
    }
}

/// Whether a driver error is PostgreSQL's `55P03 lock_not_available`.
fn is_lock_timeout(error: &sea_orm::DbErr) -> bool {
    let text = error.to_string();
    text.contains("55P03")
        || text.contains("lock_not_available")
        || text.contains("canceling statement due to lock timeout")
}

fn statement(sql: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}
