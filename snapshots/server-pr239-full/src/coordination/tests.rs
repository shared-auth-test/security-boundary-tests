//! Unit tests for the composite coordination utility.
//!
//! The advisory-lock path needs a live PostgreSQL connection and is therefore
//! exercised by the integration suite, not here. What these tests pin down is
//! everything that can go wrong without a database: key derivation, the policy
//! matrix, the fail-closed lease behaviour, and the error mapping that decides
//! whether a caller sees "retry" or "we could not decide".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::error::AuthError;

/// Scripted Fiducia backend. Each call pops the next scripted outcome, so a
/// test states the exact sequence the coordinator should encounter.
#[derive(Default)]
struct ScriptedFiducia {
    acquisitions: Mutex<Vec<Result<Option<LeaseGrant>, String>>>,
    renewals: Mutex<Vec<Result<Option<u64>, String>>>,
    releases: AtomicUsize,
}

impl ScriptedFiducia {
    fn with_acquisitions(outcomes: Vec<Result<Option<LeaseGrant>, String>>) -> Arc<Self> {
        Arc::new(Self {
            acquisitions: Mutex::new(outcomes),
            ..Self::default()
        })
    }

    fn next<T>(slot: &Mutex<Vec<Result<T, String>>>) -> Result<T, String>
    where
        T: Default,
    {
        let mut queue = match slot.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        if queue.is_empty() {
            return Err("scripted backend exhausted".to_string());
        }
        queue.remove(0)
    }
}

impl FiduciaLeases for ScriptedFiducia {
    fn acquire<'a>(
        &'a self,
        _key: &'a str,
        _holder: &'a str,
        _ttl_ms: u64,
        _wait: bool,
        _wait_budget_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Option<LeaseGrant>, String>> + Send + 'a>> {
        Box::pin(async move { Self::next(&self.acquisitions) })
    }

    fn renew<'a>(
        &'a self,
        _key: &'a str,
        _holder: &'a str,
        _fencing_token: u64,
        _ttl_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, String>> + Send + 'a>> {
        Box::pin(async move { Self::next(&self.renewals) })
    }

    fn release<'a>(
        &'a self,
        _key: &'a str,
        _holder: &'a str,
        _fencing_token: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            self.releases.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        })
    }
}

fn coordinator(fiducia: Option<Arc<dyn FiduciaLeases>>) -> Coordinator {
    Coordinator::new(
        Arc::new(DatabaseConnection::default()),
        fiducia,
        "test-holder-0000",
    )
}

fn key() -> CoordinationKey {
    CoordinationKey::new("revocation", "commit/9f2a")
}

#[test]
fn advisory_keys_are_deterministic_and_namespace_separated() {
    let first = CoordinationKey::new("revocation", "commit/9f2a");
    let same = CoordinationKey::new("revocation", "commit/9f2a");
    let other_name = CoordinationKey::new("revocation", "commit/9f2b");
    let other_namespace = CoordinationKey::new("scim", "commit/9f2a");

    assert_eq!(first.advisory_key(), same.advisory_key());
    assert_ne!(first.advisory_key(), other_name.advisory_key());
    // Two subsystems using the same local name must not collide. If this ever
    // fails, unrelated operations start serializing against each other.
    assert_ne!(first.advisory_key(), other_namespace.advisory_key());
}

#[test]
fn fiducia_keys_are_prefixed_so_they_cannot_collide_with_another_service() {
    assert_eq!(key().fiducia_key(), "shared-auth/revocation/commit/9f2a");
}

#[test]
fn the_policy_matrix_is_exactly_four_combinations() {
    assert_eq!(
        CoordinationPolicy::both(),
        CoordinationPolicy {
            fiducia: true,
            advisory: true
        }
    );
    assert_eq!(
        CoordinationPolicy::fiducia_only(),
        CoordinationPolicy {
            fiducia: true,
            advisory: false
        }
    );
    assert_eq!(
        CoordinationPolicy::advisory_only(),
        CoordinationPolicy {
            fiducia: false,
            advisory: true
        }
    );
    assert_eq!(
        CoordinationPolicy::unsynchronized(),
        CoordinationPolicy {
            fiducia: false,
            advisory: false
        }
    );
    assert!(CoordinationPolicy::unsynchronized().is_unsynchronized());
    assert!(!CoordinationPolicy::advisory_only().is_unsynchronized());
    // The default must be the strong combination, not the cheap one.
    assert_eq!(CoordinationPolicy::default(), CoordinationPolicy::both());
}

#[tokio::test]
async fn a_policy_requiring_a_lease_fails_closed_when_no_backend_is_wired() {
    let coordinator = coordinator(None);
    let error = coordinator
        .with_transaction::<(), _>(&key(), &CoordinationOptions::both(), |_txn, _fenced| {
            Box::pin(async move { panic!("guarded work must not run without a lease") })
        })
        .await
        .expect_err("a missing lease backend must not fall through to the advisory lock");

    assert!(matches!(
        error,
        CoordinationError::LeaseBackendMissing { .. }
    ));
    // Fail-closed means unavailable, not "the caller did something wrong".
    assert!(matches!(AuthError::from(error), AuthError::Unavailable));
}

#[tokio::test]
async fn a_held_lease_is_contention_and_the_work_does_not_run() {
    let fiducia = ScriptedFiducia::with_acquisitions(vec![Ok(None)]);
    let coordinator = coordinator(Some(fiducia.clone()));

    let error = coordinator
        .with_transaction::<(), _>(
            &key(),
            &CoordinationOptions::skip_if_busy(),
            |_txn, _fenced| {
                Box::pin(async move { panic!("guarded work must not run while contended") })
            },
        )
        .await
        .expect_err("a held lease must not run the work");

    assert!(matches!(error, CoordinationError::Contended { .. }));
    // Contention is retryable and nothing is broken.
    assert!(matches!(AuthError::from(error), AuthError::Conflict));
    // Nothing was acquired, so nothing may be released.
    assert_eq!(fiducia.releases.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unreachable_coordinator_is_not_downgraded_to_advisory_only() {
    let fiducia = ScriptedFiducia::with_acquisitions(vec![Err("connection refused".to_string())]);
    let coordinator = coordinator(Some(fiducia));

    let error = coordinator
        .with_transaction::<(), _>(&key(), &CoordinationOptions::both(), |_txn, _fenced| {
            Box::pin(async move { panic!("guarded work must not run after a lease error") })
        })
        .await
        .expect_err("an unreachable coordinator must fail closed");

    // The distinction matters: contention means someone else holds it, this
    // means we do not know who holds it.
    assert!(matches!(error, CoordinationError::LeaseUnavailable { .. }));
    assert!(matches!(AuthError::from(error), AuthError::Unavailable));
}

#[tokio::test]
async fn a_lost_renewal_is_an_error_rather_than_a_warning() {
    let fiducia = Arc::new(ScriptedFiducia {
        renewals: Mutex::new(vec![Ok(None)]),
        ..ScriptedFiducia::default()
    });
    let coordinator = coordinator(Some(fiducia));
    let grant = LeaseGrant {
        fencing_token: 7,
        lease_expires_ms: None,
    };

    let error = coordinator
        .renew_lease(&key(), grant, DEFAULT_LEASE_TTL)
        .await
        .expect_err("a reaped grant must surface as lost authority");

    assert!(matches!(error, CoordinationError::LeaseLost { .. }));
}

#[tokio::test]
async fn renewal_preserves_the_fencing_token() {
    let fiducia = Arc::new(ScriptedFiducia {
        renewals: Mutex::new(vec![Ok(Some(1_700_000_000_000))]),
        ..ScriptedFiducia::default()
    });
    let coordinator = coordinator(Some(fiducia));
    let grant = LeaseGrant {
        fencing_token: 7,
        lease_expires_ms: None,
    };

    let renewed = coordinator
        .renew_lease(&key(), grant, DEFAULT_LEASE_TTL)
        .await
        .expect("renewal should succeed");

    // A renewal extends the lease; it must never mint a new token, or every
    // downstream fencing check would have to tolerate the token moving.
    assert_eq!(renewed.fencing_token, 7);
    assert_eq!(renewed.lease_expires_ms, Some(1_700_000_000_000));
}

#[test]
fn an_unfenced_policy_reports_no_token_rather_than_a_placeholder() {
    let fenced = Fenced::default();
    assert_eq!(fenced.fencing_token, None);
    assert_eq!(fenced.lease_expires_ms, None);
}

#[test]
fn lock_timeout_aborts_are_recognized_as_contention() {
    let timeout = sea_orm::DbErr::Custom(
        "error returned from database: 55P03: canceling statement due to lock timeout".to_string(),
    );
    let other = sea_orm::DbErr::Custom("connection closed".to_string());
    assert!(is_lock_timeout(&timeout));
    assert!(!is_lock_timeout(&other));
}

#[test]
fn guarded_work_failures_keep_their_original_error() {
    let error = CoordinationError::from(AuthError::Forbidden);
    assert!(matches!(AuthError::from(error), AuthError::Forbidden));
}
