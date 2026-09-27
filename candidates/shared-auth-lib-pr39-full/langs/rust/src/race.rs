//! The dual-auth race.
//!
//! Both authorities can validate a Supabase access token:
//!
//! - **shared-auth** — verifies locally against its published JWKS (an existing
//!   shared-auth token), or exchanges a Supabase token at `/auth/exchange`.
//! - **supabase** — `GET {project_url}/auth/v1/user` with the token.
//!
//! We run them **concurrently** and take the **first success**. This is not just
//! a latency trick: it is the resilience property. Either authority alone can
//! carry the request, so a multi-minute outage of one is invisible to callers.
//!
//! Rules (see shared-auth-interfaces/SPEC.md §3):
//! 1. First `Authenticated` wins; the loser is dropped.
//! 2. One erroring does **not** abort the other — the survivor still decides.
//! 3. Both definitively invalid → `Unauthenticated`.
//! 4. Both unreachable/timeout → `Degraded` (never silently "logged out").
//! 5. The winning `authority` is recorded on the identity.
//! 6. A deadline bounds the whole race.

use std::time::{Duration, Instant};
use std::{future::Future, pin::Pin};

use futures_util::stream::{FuturesUnordered, StreamExt};
use shared_auth_interfaces::{AuthOutcome, Authority, Identity};

/// Why a single authority did not authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmFailure {
    /// Definite: the credential is invalid/expired. Counts toward `Unauthenticated`.
    Invalid,
    /// Indefinite: transport error, timeout, 5xx. Counts toward `Degraded`.
    Unavailable,
}

/// One authority's verdict.
pub type ArmResult = Result<Identity, ArmFailure>;

pub type BoxedAuthorityArm<'a> = (
    Authority,
    Pin<Box<dyn Future<Output = ArmResult> + Send + 'a>>,
);

/// Race any number of authorities. This is the provider-extensible primitive;
/// [`race`] below preserves the convenient shared-auth/Supabase two-arm API.
#[tracing::instrument(
    name = "shared_auth.race",
    skip(arms),
    fields(auth.deadline_ms = deadline.as_millis() as u64)
)]
pub async fn race_many(arms: Vec<BoxedAuthorityArm<'_>>, deadline: Duration) -> AuthOutcome {
    if arms.is_empty() {
        return AuthOutcome::Degraded {
            reason: "no auth authorities configured".into(),
        };
    }
    let started = Instant::now();
    let arm_count = arms.len();
    let mut pending = FuturesUnordered::new();
    for (authority, future) in arms {
        pending.push(async move { (authority, future.await) });
    }

    let outcome = async {
        let mut failures = Vec::with_capacity(arm_count);
        while let Some((authority, result)) = pending.next().await {
            match result {
                Ok(mut identity) => {
                    identity.authority = authority;
                    tracing::info!(auth.authority = ?authority, "authentication authority won race");
                    return AuthOutcome::Authenticated {
                        identity: Box::new(identity),
                        authority,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    };
                }
                Err(failure) => failures.push(failure),
            }
        }
        if failures.len() == arm_count
            && failures
                .iter()
                .all(|failure| *failure == ArmFailure::Invalid)
        {
            AuthOutcome::Unauthenticated
        } else {
            AuthOutcome::Degraded {
                reason: "no authority could verify the credential".into(),
            }
        }
    };
    tokio::time::timeout(deadline, outcome)
        .await
        .unwrap_or_else(|_| AuthOutcome::Degraded {
            reason: "auth race deadline exceeded".into(),
        })
}

/// Race two authority futures, applying the SPEC rules.
///
/// `deadline` bounds the whole race; exceeding it with no success is `Degraded`
/// (we could not decide), never `Unauthenticated`.
pub async fn race<S, P>(shared: S, supabase: P, deadline: Duration) -> AuthOutcome
where
    S: std::future::Future<Output = ArmResult> + Send,
    P: std::future::Future<Output = ArmResult> + Send,
{
    race_many(
        vec![
            (Authority::SharedAuth, Box::pin(shared)),
            (Authority::Supabase, Box::pin(supabase)),
        ],
        deadline,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            shared_user_id: "u-1".into(),
            provider: "supabase".into(),
            provider_tenant: "fiducia-cloud".into(),
            provider_subject: "sub-1".into(),
            project: Some("fiducia-cloud".into()),
            supabase_user_id: Some("sub-1".into()),
            session_id: None,
            email: Some("a@b.co".into()),
            email_verified: true,
            roles: vec!["user".into()],
            amr: vec![],
            acr: None,
            cred: None,
            // Deliberately "wrong" — the race must overwrite it with the winner.
            authority: Authority::Supabase,
        }
    }

    async fn ok_after(ms: u64) -> ArmResult {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        Ok(identity())
    }
    async fn fail_after(ms: u64, f: ArmFailure) -> ArmResult {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        Err(f)
    }

    #[tokio::test]
    async fn fastest_success_wins_and_stamps_authority() {
        // shared-auth answers first.
        let o = race(ok_after(5), ok_after(80), Duration::from_secs(2)).await;
        match o {
            AuthOutcome::Authenticated {
                authority,
                identity,
                ..
            } => {
                assert_eq!(authority, Authority::SharedAuth);
                assert_eq!(identity.authority, Authority::SharedAuth);
            }
            other => panic!("expected authenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn supabase_wins_when_shared_auth_is_slower() {
        let o = race(ok_after(120), ok_after(5), Duration::from_secs(2)).await;
        assert!(matches!(
            o,
            AuthOutcome::Authenticated {
                authority: Authority::Supabase,
                ..
            }
        ));
    }

    // The headline resilience property: one authority down, the other still authenticates.
    #[tokio::test]
    async fn survivor_authenticates_when_the_other_is_unavailable() {
        let o = race(
            fail_after(2, ArmFailure::Unavailable),
            ok_after(30),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(
            o,
            AuthOutcome::Authenticated {
                authority: Authority::Supabase,
                ..
            }
        ));

        let o = race(
            ok_after(30),
            fail_after(2, ArmFailure::Unavailable),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(
            o,
            AuthOutcome::Authenticated {
                authority: Authority::SharedAuth,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn both_definitely_invalid_is_unauthenticated() {
        let o = race(
            fail_after(1, ArmFailure::Invalid),
            fail_after(2, ArmFailure::Invalid),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(o, AuthOutcome::Unauthenticated);
    }

    // Crucial: an unreachable authority must NOT be reported as "logged out".
    #[tokio::test]
    async fn invalid_plus_unavailable_is_degraded_not_unauthenticated() {
        let o = race(
            fail_after(1, ArmFailure::Invalid),
            fail_after(2, ArmFailure::Unavailable),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(o, AuthOutcome::Degraded { .. }));
    }

    #[tokio::test]
    async fn both_unavailable_is_degraded() {
        let o = race(
            fail_after(1, ArmFailure::Unavailable),
            fail_after(1, ArmFailure::Unavailable),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(o, AuthOutcome::Degraded { .. }));
    }

    #[tokio::test]
    async fn deadline_exceeded_is_degraded() {
        let o = race(ok_after(500), ok_after(500), Duration::from_millis(20)).await;
        assert!(matches!(o, AuthOutcome::Degraded { .. }));
    }

    #[tokio::test]
    async fn empty_multi_race_is_degraded() {
        let outcome = race_many(vec![], Duration::from_millis(20)).await;
        assert!(matches!(outcome, AuthOutcome::Degraded { .. }));
    }
}
