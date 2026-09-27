//! Executable proof policies and deterministic provider arbitration.
//!
//! This is intentionally separate from the legacy availability race in
//! `crate::race`. Routes that need strict proof requirements must opt in to
//! these policy types instead of inheriting first-success semantics.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderKind {
    SharedAuth,
    Supabase,
    NeonAuth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofClass {
    CustomerIdentity,
    SubsystemGrant,
    PrivilegedAdministration,
}

/// Canonical identity key. Email/profile data is intentionally not part of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderIdentityKey {
    pub provider: ProviderKind,
    pub issuer: String,
    pub subject: String,
    pub realm: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProof {
    pub identity: ProviderIdentityKey,
    pub shared_user_id: String,
    pub class: ProofClass,
    pub assurance: u8,
    /// Opaque root identifier used to prove two assertions are independent.
    pub root_proof_id: String,
    pub policy_revision: String,
    pub verified_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderVerdict {
    Verified(VerifiedProof),
    Invalid { provider: ProviderKind },
    Unavailable { provider: ProviderKind },
    Revoked { provider: ProviderKind },
    Conflict { provider: ProviderKind },
}

impl ProviderVerdict {
    fn provider(&self) -> ProviderKind {
        match self {
            Self::Verified(proof) => proof.identity.provider,
            Self::Invalid { provider }
            | Self::Unavailable { provider }
            | Self::Revoked { provider }
            | Self::Conflict { provider } => *provider,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptimisticCustomerPolicy {
    pub required_providers: BTreeSet<ProviderKind>,
    pub max_pending_seconds: u64,
    pub minimum_assurance: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictProviderPairPolicy {
    pub providers: [ProviderKind; 2],
    pub minimum_assurance: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictSubsystemGrantPolicy {
    pub required_provider: ProviderKind,
    pub minimum_assurance: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivilegedAdministrationPolicy {
    pub required_provider: ProviderKind,
    pub minimum_assurance: u8,
}

/// The four policy classes are deliberately distinct. A caller cannot silently
/// substitute one proof requirement for another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofPolicy {
    OptimisticCustomer(OptimisticCustomerPolicy),
    StrictProviderPair(StrictProviderPairPolicy),
    StrictSubsystemGrant(StrictSubsystemGrantPolicy),
    PrivilegedAdministration(PrivilegedAdministrationPolicy),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedIdentity {
    pub shared_user_id: String,
    pub realm: String,
    pub policy_revision: String,
    pub assurance: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    InvalidProof,
    RevokedProof,
    ProviderConflict,
    CanonicalIdentityConflict,
    PolicyRevisionConflict,
    StaleProof,
    InsufficientAssurance,
    NonIndependentProofs,
    WrongProofClass,
    InvalidPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArbitrationDecision {
    Accepted(AcceptedIdentity),
    /// Customer-only early acceptance. Callers must persist reconciliation and
    /// fence this session from strict operations until it resolves.
    Provisional {
        identity: AcceptedIdentity,
        reconcile_by_unix_seconds: u64,
        pending_providers: BTreeSet<ProviderKind>,
    },
    Rejected(RejectionReason),
    Degraded {
        unavailable_providers: BTreeSet<ProviderKind>,
    },
}

/// Arbitrate a complete provider-result snapshot.
///
/// Arrival order is absent from the input model, so the same set of results is
/// deterministic. Revocation, rejection, provider conflict, stale proof, or
/// canonical identity disagreement always dominates a prior success.
pub fn arbitrate(
    policy: &ProofPolicy,
    verdicts: &[ProviderVerdict],
    now_unix_seconds: u64,
) -> ArbitrationDecision {
    let mut by_provider = BTreeMap::new();
    for verdict in verdicts {
        if by_provider.insert(verdict.provider(), verdict).is_some() {
            return ArbitrationDecision::Rejected(RejectionReason::ProviderConflict);
        }
    }

    if verdicts
        .iter()
        .any(|verdict| matches!(verdict, ProviderVerdict::Revoked { .. }))
    {
        return ArbitrationDecision::Rejected(RejectionReason::RevokedProof);
    }
    if verdicts
        .iter()
        .any(|verdict| matches!(verdict, ProviderVerdict::Conflict { .. }))
    {
        return ArbitrationDecision::Rejected(RejectionReason::ProviderConflict);
    }
    if verdicts
        .iter()
        .any(|verdict| matches!(verdict, ProviderVerdict::Invalid { .. }))
    {
        return ArbitrationDecision::Rejected(RejectionReason::InvalidProof);
    }

    let verified = verdicts
        .iter()
        .filter_map(|verdict| match verdict {
            ProviderVerdict::Verified(proof) => Some(proof),
            _ => None,
        })
        .collect::<Vec<_>>();

    if verified.iter().any(|proof| {
        proof.identity.issuer.trim().is_empty()
            || proof.identity.subject.trim().is_empty()
            || proof.identity.realm.trim().is_empty()
            || proof.shared_user_id.trim().is_empty()
            || proof.root_proof_id.trim().is_empty()
            || proof.policy_revision.trim().is_empty()
            || proof.verified_at_unix_seconds > now_unix_seconds
            || proof.expires_at_unix_seconds <= now_unix_seconds
    }) {
        return ArbitrationDecision::Rejected(RejectionReason::StaleProof);
    }

    if let Some(first) = verified.first() {
        if verified.iter().any(|proof| {
            proof.shared_user_id != first.shared_user_id
                || proof.identity.realm != first.identity.realm
        }) {
            return ArbitrationDecision::Rejected(RejectionReason::CanonicalIdentityConflict);
        }
        if verified
            .iter()
            .any(|proof| proof.policy_revision != first.policy_revision)
        {
            return ArbitrationDecision::Rejected(RejectionReason::PolicyRevisionConflict);
        }
    }

    match policy {
        ProofPolicy::OptimisticCustomer(policy) => {
            optimistic(policy, &by_provider, &verified, now_unix_seconds)
        }
        ProofPolicy::StrictProviderPair(policy) => strict_pair(policy, &by_provider),
        ProofPolicy::StrictSubsystemGrant(policy) => explicit_class(
            policy.required_provider,
            policy.minimum_assurance,
            ProofClass::SubsystemGrant,
            &by_provider,
        ),
        ProofPolicy::PrivilegedAdministration(policy) => explicit_class(
            policy.required_provider,
            policy.minimum_assurance,
            ProofClass::PrivilegedAdministration,
            &by_provider,
        ),
    }
}

fn optimistic(
    policy: &OptimisticCustomerPolicy,
    by_provider: &BTreeMap<ProviderKind, &ProviderVerdict>,
    verified: &[&VerifiedProof],
    now: u64,
) -> ArbitrationDecision {
    if policy.required_providers.is_empty() || policy.max_pending_seconds == 0 {
        return ArbitrationDecision::Rejected(RejectionReason::InvalidPolicy);
    }

    for provider in &policy.required_providers {
        if let Some(ProviderVerdict::Verified(proof)) = by_provider.get(provider) {
            if proof.class != ProofClass::CustomerIdentity {
                return ArbitrationDecision::Rejected(RejectionReason::WrongProofClass);
            }
            if proof.assurance < policy.minimum_assurance {
                return ArbitrationDecision::Rejected(RejectionReason::InsufficientAssurance);
            }
        }
    }

    let eligible = verified
        .iter()
        .copied()
        .filter(|proof| {
            proof.class == ProofClass::CustomerIdentity
                && proof.assurance >= policy.minimum_assurance
                && policy.required_providers.contains(&proof.identity.provider)
        })
        .collect::<Vec<_>>();

    if eligible.is_empty() {
        if verified
            .iter()
            .any(|proof| proof.assurance < policy.minimum_assurance)
        {
            return ArbitrationDecision::Rejected(RejectionReason::InsufficientAssurance);
        }
        if verified
            .iter()
            .any(|proof| proof.class != ProofClass::CustomerIdentity)
        {
            return ArbitrationDecision::Rejected(RejectionReason::WrongProofClass);
        }
        return degraded(&policy.required_providers, by_provider);
    }

    let pending = policy
        .required_providers
        .iter()
        .copied()
        .filter(|provider| {
            !matches!(
                by_provider.get(provider),
                Some(ProviderVerdict::Verified(proof))
                    if proof.class == ProofClass::CustomerIdentity
                        && proof.assurance >= policy.minimum_assurance
            )
        })
        .collect::<BTreeSet<_>>();

    let identity = accepted_identity(&eligible);
    if pending.is_empty() {
        ArbitrationDecision::Accepted(identity)
    } else if pending.iter().all(|provider| {
        matches!(
            by_provider.get(provider),
            None | Some(ProviderVerdict::Unavailable { .. })
        )
    }) {
        ArbitrationDecision::Provisional {
            identity,
            reconcile_by_unix_seconds: now.saturating_add(policy.max_pending_seconds),
            pending_providers: pending,
        }
    } else {
        degraded(&policy.required_providers, by_provider)
    }
}

fn strict_pair(
    policy: &StrictProviderPairPolicy,
    by_provider: &BTreeMap<ProviderKind, &ProviderVerdict>,
) -> ArbitrationDecision {
    if policy.providers[0] == policy.providers[1] {
        return ArbitrationDecision::Rejected(RejectionReason::InvalidPolicy);
    }

    let required = policy.providers.into_iter().collect::<BTreeSet<_>>();
    let mut selected = Vec::with_capacity(2);
    for provider in policy.providers {
        match by_provider.get(&provider) {
            Some(ProviderVerdict::Verified(proof)) => selected.push(proof),
            Some(ProviderVerdict::Unavailable { .. }) | None => {
                return degraded(&required, by_provider);
            }
            _ => {
                return ArbitrationDecision::Rejected(RejectionReason::ProviderConflict);
            }
        }
    }

    if selected
        .iter()
        .any(|proof| proof.class != ProofClass::CustomerIdentity)
    {
        return ArbitrationDecision::Rejected(RejectionReason::WrongProofClass);
    }
    if selected
        .iter()
        .any(|proof| proof.assurance < policy.minimum_assurance)
    {
        return ArbitrationDecision::Rejected(RejectionReason::InsufficientAssurance);
    }
    if selected[0].root_proof_id == selected[1].root_proof_id {
        return ArbitrationDecision::Rejected(RejectionReason::NonIndependentProofs);
    }

    ArbitrationDecision::Accepted(accepted_identity(&selected))
}

fn explicit_class(
    provider: ProviderKind,
    minimum_assurance: u8,
    class: ProofClass,
    by_provider: &BTreeMap<ProviderKind, &ProviderVerdict>,
) -> ArbitrationDecision {
    let required = BTreeSet::from([provider]);
    let proof = match by_provider.get(&provider) {
        Some(ProviderVerdict::Verified(proof)) => proof,
        Some(ProviderVerdict::Unavailable { .. }) | None => {
            return degraded(&required, by_provider);
        }
        _ => {
            return ArbitrationDecision::Rejected(RejectionReason::ProviderConflict);
        }
    };

    if proof.class != class {
        return ArbitrationDecision::Rejected(RejectionReason::WrongProofClass);
    }
    if proof.assurance < minimum_assurance {
        return ArbitrationDecision::Rejected(RejectionReason::InsufficientAssurance);
    }

    ArbitrationDecision::Accepted(accepted_identity(&[proof]))
}

fn accepted_identity(proofs: &[&VerifiedProof]) -> AcceptedIdentity {
    let first = proofs[0];
    AcceptedIdentity {
        shared_user_id: first.shared_user_id.clone(),
        realm: first.identity.realm.clone(),
        policy_revision: first.policy_revision.clone(),
        assurance: proofs
            .iter()
            .map(|proof| proof.assurance)
            .min()
            .unwrap_or(first.assurance),
    }
}

fn degraded(
    required: &BTreeSet<ProviderKind>,
    by_provider: &BTreeMap<ProviderKind, &ProviderVerdict>,
) -> ArbitrationDecision {
    ArbitrationDecision::Degraded {
        unavailable_providers: required
            .iter()
            .copied()
            .filter(|provider| {
                matches!(
                    by_provider.get(provider),
                    None | Some(ProviderVerdict::Unavailable { .. })
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(provider: ProviderKind, root: &str, class: ProofClass) -> ProviderVerdict {
        ProviderVerdict::Verified(VerifiedProof {
            identity: ProviderIdentityKey {
                provider,
                issuer: format!("https://{provider:?}.example.invalid"),
                subject: format!("subject-{provider:?}"),
                realm: "customer".into(),
            },
            shared_user_id: "user-1".into(),
            class,
            assurance: 2,
            root_proof_id: root.into(),
            policy_revision: "policy-7".into(),
            verified_at_unix_seconds: 90,
            expires_at_unix_seconds: 200,
        })
    }

    fn strict_pair_policy() -> ProofPolicy {
        ProofPolicy::StrictProviderPair(StrictProviderPairPolicy {
            providers: [ProviderKind::Supabase, ProviderKind::NeonAuth],
            minimum_assurance: 1,
        })
    }

    #[test]
    fn strict_pair_is_arrival_order_independent() {
        let a = proof(
            ProviderKind::Supabase,
            "root-a",
            ProofClass::CustomerIdentity,
        );
        let b = proof(
            ProviderKind::NeonAuth,
            "root-b",
            ProofClass::CustomerIdentity,
        );
        let expected = arbitrate(&strict_pair_policy(), &[a.clone(), b.clone()], 100);
        assert!(matches!(expected, ArbitrationDecision::Accepted(_)));
        assert_eq!(expected, arbitrate(&strict_pair_policy(), &[b, a], 100));
    }

    #[test]
    fn late_revocation_overrides_fast_success_in_every_order() {
        let valid = proof(
            ProviderKind::Supabase,
            "root-a",
            ProofClass::CustomerIdentity,
        );
        let revoked = ProviderVerdict::Revoked {
            provider: ProviderKind::NeonAuth,
        };
        let expected = ArbitrationDecision::Rejected(RejectionReason::RevokedProof);
        assert_eq!(
            arbitrate(
                &strict_pair_policy(),
                &[valid.clone(), revoked.clone()],
                100,
            ),
            expected
        );
        assert_eq!(
            arbitrate(&strict_pair_policy(), &[revoked, valid], 100),
            expected
        );
    }

    #[test]
    fn canonical_identity_disagreement_fails_closed() {
        let left = proof(
            ProviderKind::Supabase,
            "root-a",
            ProofClass::CustomerIdentity,
        );
        let mut right = match proof(
            ProviderKind::NeonAuth,
            "root-b",
            ProofClass::CustomerIdentity,
        ) {
            ProviderVerdict::Verified(proof) => proof,
            _ => unreachable!(),
        };
        right.shared_user_id = "user-2".into();
        assert_eq!(
            arbitrate(
                &strict_pair_policy(),
                &[left, ProviderVerdict::Verified(right)],
                100,
            ),
            ArbitrationDecision::Rejected(RejectionReason::CanonicalIdentityConflict,)
        );
    }

    #[test]
    fn derived_assertions_do_not_count_as_independent_proofs() {
        let a = proof(
            ProviderKind::Supabase,
            "same-root",
            ProofClass::CustomerIdentity,
        );
        let b = proof(
            ProviderKind::NeonAuth,
            "same-root",
            ProofClass::CustomerIdentity,
        );
        assert_eq!(
            arbitrate(&strict_pair_policy(), &[a, b], 100),
            ArbitrationDecision::Rejected(RejectionReason::NonIndependentProofs,)
        );
    }

    #[test]
    fn identity_agreement_cannot_substitute_for_subsystem_grant() {
        let policy = ProofPolicy::StrictSubsystemGrant(StrictSubsystemGrantPolicy {
            required_provider: ProviderKind::SharedAuth,
            minimum_assurance: 2,
        });
        let ordinary = proof(
            ProviderKind::SharedAuth,
            "root-shared",
            ProofClass::CustomerIdentity,
        );
        assert_eq!(
            arbitrate(&policy, &[ordinary], 100),
            ArbitrationDecision::Rejected(RejectionReason::WrongProofClass)
        );
    }

    #[test]
    fn privileged_admin_requires_explicit_admin_class() {
        let policy = ProofPolicy::PrivilegedAdministration(PrivilegedAdministrationPolicy {
            required_provider: ProviderKind::SharedAuth,
            minimum_assurance: 2,
        });
        let ordinary = proof(
            ProviderKind::SharedAuth,
            "root-shared",
            ProofClass::CustomerIdentity,
        );
        assert_eq!(
            arbitrate(&policy, &[ordinary], 100),
            ArbitrationDecision::Rejected(RejectionReason::WrongProofClass)
        );

        let admin = proof(
            ProviderKind::SharedAuth,
            "root-admin",
            ProofClass::PrivilegedAdministration,
        );
        assert!(matches!(
            arbitrate(&policy, &[admin], 100),
            ArbitrationDecision::Accepted(_)
        ));
    }

    #[test]
    fn optimistic_customer_session_is_bounded_and_pending() {
        let policy = ProofPolicy::OptimisticCustomer(OptimisticCustomerPolicy {
            required_providers: BTreeSet::from([ProviderKind::Supabase, ProviderKind::NeonAuth]),
            max_pending_seconds: 30,
            minimum_assurance: 1,
        });
        let valid = proof(
            ProviderKind::Supabase,
            "root-a",
            ProofClass::CustomerIdentity,
        );
        let unavailable = ProviderVerdict::Unavailable {
            provider: ProviderKind::NeonAuth,
        };
        match arbitrate(&policy, &[valid, unavailable], 100) {
            ArbitrationDecision::Provisional {
                reconcile_by_unix_seconds,
                pending_providers,
                ..
            } => {
                assert_eq!(reconcile_by_unix_seconds, 130);
                assert_eq!(pending_providers, BTreeSet::from([ProviderKind::NeonAuth]));
            }
            other => panic!("expected provisional decision, got {other:?}"),
        }
    }

    #[test]
    fn optimistic_required_provider_with_weak_assurance_is_rejected() {
        let policy = ProofPolicy::OptimisticCustomer(OptimisticCustomerPolicy {
            required_providers: BTreeSet::from([ProviderKind::Supabase, ProviderKind::NeonAuth]),
            max_pending_seconds: 30,
            minimum_assurance: 2,
        });
        let strong = proof(
            ProviderKind::Supabase,
            "root-a",
            ProofClass::CustomerIdentity,
        );
        let mut weak = match proof(
            ProviderKind::NeonAuth,
            "root-b",
            ProofClass::CustomerIdentity,
        ) {
            ProviderVerdict::Verified(proof) => proof,
            _ => panic!("proof helper must return verified"),
        };
        weak.assurance = 1;

        assert_eq!(
            arbitrate(&policy, &[strong, ProviderVerdict::Verified(weak)], 100),
            ArbitrationDecision::Rejected(RejectionReason::InsufficientAssurance)
        );
    }

    #[test]
    fn optimistic_required_provider_with_wrong_class_is_rejected() {
        let policy = ProofPolicy::OptimisticCustomer(OptimisticCustomerPolicy {
            required_providers: BTreeSet::from([ProviderKind::Supabase, ProviderKind::NeonAuth]),
            max_pending_seconds: 30,
            minimum_assurance: 1,
        });
        let customer = proof(
            ProviderKind::Supabase,
            "root-a",
            ProofClass::CustomerIdentity,
        );
        let subsystem = proof(ProviderKind::NeonAuth, "root-b", ProofClass::SubsystemGrant);

        assert_eq!(
            arbitrate(&policy, &[customer, subsystem], 100),
            ArbitrationDecision::Rejected(RejectionReason::WrongProofClass)
        );
    }

    #[test]
    fn strict_pair_never_accepts_first_success_on_peer_outage() {
        let valid = proof(
            ProviderKind::Supabase,
            "root-a",
            ProofClass::CustomerIdentity,
        );
        let unavailable = ProviderVerdict::Unavailable {
            provider: ProviderKind::NeonAuth,
        };
        assert_eq!(
            arbitrate(&strict_pair_policy(), &[valid, unavailable], 100),
            ArbitrationDecision::Degraded {
                unavailable_providers: BTreeSet::from([ProviderKind::NeonAuth,])
            }
        );
    }
}
