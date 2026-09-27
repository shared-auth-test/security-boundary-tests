//! Runtime decision semantics layered over the secret-free provider topology.
//!
//! Both provider lanes are always configured. `AvailabilityFirst` permits one
//! active, valid lane to carry an ordinary customer request only when the other
//! provider is unavailable. A contradictory invalid result is never ignored.
//! `StrictPaired` is mandatory for admin and sensitive operations.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auth_topology::{
    AuthDataPlane, AuthProvider, AuthTopology, DualAuthError, ProviderProof, VerifiedIdentity,
    validate_proof, verify_dual_provider_proofs,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DualAuthDecisionMode {
    AvailabilityFirst,
    StrictPaired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthOperation {
    Ordinary,
    Sensitive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderDecisionOutcome {
    Authenticated(ProviderProof),
    Invalid,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDecision {
    pub provider: AuthProvider,
    pub outcome: ProviderDecisionOutcome,
}

impl ProviderDecision {
    #[must_use]
    pub fn authenticated(proof: ProviderProof) -> Self {
        Self {
            provider: proof.provider,
            outcome: ProviderDecisionOutcome::Authenticated(proof),
        }
    }

    #[must_use]
    pub const fn invalid(provider: AuthProvider) -> Self {
        Self {
            provider,
            outcome: ProviderDecisionOutcome::Invalid,
        }
    }

    #[must_use]
    pub const fn unavailable(provider: AuthProvider) -> Self {
        Self {
            provider,
            outcome: ProviderDecisionOutcome::Unavailable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvailableIdentity {
    pub canonical_user_id: String,
    pub tenant_id: String,
    pub audience: String,
    pub data_plane: AuthDataPlane,
    pub winning_provider: AuthProvider,
    pub supabase_subject: Option<String>,
    pub neon_subject: Option<String>,
}

impl From<(VerifiedIdentity, AuthProvider)> for AvailableIdentity {
    fn from((identity, winning_provider): (VerifiedIdentity, AuthProvider)) -> Self {
        Self {
            canonical_user_id: identity.canonical_user_id,
            tenant_id: identity.tenant_id,
            audience: identity.audience,
            data_plane: identity.data_plane,
            winning_provider,
            supabase_subject: Some(identity.supabase_subject),
            neon_subject: Some(identity.neon_subject),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum DualAuthDecision {
    Authenticated {
        identity: AvailableIdentity,
        mode: DualAuthDecisionMode,
    },
    Unauthenticated,
    Degraded,
}

/// Decide an ordinary request. Admin topologies still require strict paired
/// proof. Use [`decide_dual_auth_for_operation`] when the caller knows a
/// customer operation is sensitive.
///
/// # Errors
///
/// Returns [`DualAuthDecisionError`] when the topology is invalid, provider
/// lanes are missing or duplicated, proof and provider tags disagree, strict
/// paired proof is required, or authenticated provider evidence fails closed.
pub fn decide_dual_auth(
    topology: &AuthTopology,
    mode: DualAuthDecisionMode,
    decisions: impl IntoIterator<Item = ProviderDecision>,
) -> Result<DualAuthDecision, DualAuthDecisionError> {
    decide_dual_auth_for_operation(topology, AuthOperation::Ordinary, mode, decisions)
}

/// Decide from exactly one Supabase lane and one Neon lane.
///
/// Missing or duplicate lanes are configuration errors. Availability-first is
/// rejected for admin and sensitive operations. An authenticated proof is
/// checked for status, audience, realm, canonical identity and tenant before
/// it can carry a request.
///
/// # Errors
///
/// Returns [`DualAuthDecisionError`] when topology validation fails; either
/// provider lane is missing or duplicated; an authenticated proof's provider
/// tag is inconsistent; availability-first is used for an admin or sensitive
/// operation; providers disagree; or strict proof reconciliation fails.
pub fn decide_dual_auth_for_operation(
    topology: &AuthTopology,
    operation: AuthOperation,
    mode: DualAuthDecisionMode,
    decisions: impl IntoIterator<Item = ProviderDecision>,
) -> Result<DualAuthDecision, DualAuthDecisionError> {
    topology
        .validate()
        .map_err(DualAuthDecisionError::InvalidTopology)?;

    if mode == DualAuthDecisionMode::AvailabilityFirst
        && (topology.server_role.is_admin() || operation == AuthOperation::Sensitive)
    {
        return Err(DualAuthDecisionError::StrictPairedRequired);
    }

    let mut supabase = None;
    let mut neon = None;
    for decision in decisions {
        if let ProviderDecisionOutcome::Authenticated(proof) = &decision.outcome {
            if proof.provider != decision.provider {
                return Err(DualAuthDecisionError::ProviderTagMismatch);
            }
        }
        let slot = match decision.provider {
            AuthProvider::Supabase => &mut supabase,
            AuthProvider::Neon => &mut neon,
        };
        if slot.replace(decision.outcome).is_some() {
            return Err(DualAuthDecisionError::DuplicateProviderDecision);
        }
    }

    let supabase = supabase.ok_or(DualAuthDecisionError::MissingProviderDecision(
        AuthProvider::Supabase,
    ))?;
    let neon = neon.ok_or(DualAuthDecisionError::MissingProviderDecision(
        AuthProvider::Neon,
    ))?;

    match mode {
        DualAuthDecisionMode::StrictPaired => decide_strict(topology, supabase, neon),
        DualAuthDecisionMode::AvailabilityFirst => {
            decide_availability_first(topology, supabase, neon)
        }
    }
}

fn decide_strict(
    topology: &AuthTopology,
    supabase: ProviderDecisionOutcome,
    neon: ProviderDecisionOutcome,
) -> Result<DualAuthDecision, DualAuthDecisionError> {
    match (supabase, neon) {
        (
            ProviderDecisionOutcome::Authenticated(supabase),
            ProviderDecisionOutcome::Authenticated(neon),
        ) => {
            let identity = verify_dual_provider_proofs(topology, [supabase, neon])?;
            Ok(DualAuthDecision::Authenticated {
                identity: (identity, AuthProvider::Supabase).into(),
                mode: DualAuthDecisionMode::StrictPaired,
            })
        }
        (ProviderDecisionOutcome::Invalid, _) | (_, ProviderDecisionOutcome::Invalid) => {
            Ok(DualAuthDecision::Unauthenticated)
        }
        _ => Ok(DualAuthDecision::Degraded),
    }
}

fn decide_availability_first(
    topology: &AuthTopology,
    supabase: ProviderDecisionOutcome,
    neon: ProviderDecisionOutcome,
) -> Result<DualAuthDecision, DualAuthDecisionError> {
    match (supabase, neon) {
        (
            ProviderDecisionOutcome::Authenticated(supabase),
            ProviderDecisionOutcome::Authenticated(neon),
        ) => {
            let identity = verify_dual_provider_proofs(topology, [supabase, neon])?;
            Ok(DualAuthDecision::Authenticated {
                identity: (identity, AuthProvider::Supabase).into(),
                mode: DualAuthDecisionMode::AvailabilityFirst,
            })
        }
        (ProviderDecisionOutcome::Authenticated(proof), ProviderDecisionOutcome::Unavailable)
        | (ProviderDecisionOutcome::Unavailable, ProviderDecisionOutcome::Authenticated(proof)) => {
            validate_proof(topology, &proof)?;
            Ok(DualAuthDecision::Authenticated {
                identity: identity_from_single(proof),
                mode: DualAuthDecisionMode::AvailabilityFirst,
            })
        }
        (ProviderDecisionOutcome::Authenticated(_), ProviderDecisionOutcome::Invalid)
        | (ProviderDecisionOutcome::Invalid, ProviderDecisionOutcome::Authenticated(_)) => {
            Err(DualAuthDecisionError::ProviderDisagreement)
        }
        (ProviderDecisionOutcome::Invalid, _) | (_, ProviderDecisionOutcome::Invalid) => {
            Ok(DualAuthDecision::Unauthenticated)
        }
        _ => Ok(DualAuthDecision::Degraded),
    }
}

fn identity_from_single(proof: ProviderProof) -> AvailableIdentity {
    let (supabase_subject, neon_subject) = match proof.provider {
        AuthProvider::Supabase => (Some(proof.subject), None),
        AuthProvider::Neon => (None, Some(proof.subject)),
    };
    AvailableIdentity {
        canonical_user_id: proof.canonical_user_id,
        tenant_id: proof.tenant_id,
        audience: proof.audience,
        data_plane: proof.data_plane,
        winning_provider: proof.provider,
        supabase_subject,
        neon_subject,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualAuthDecisionError {
    InvalidTopology(crate::auth_topology::TopologyError),
    MissingProviderDecision(AuthProvider),
    DuplicateProviderDecision,
    ProviderTagMismatch,
    StrictPairedRequired,
    ProviderDisagreement,
    StrictProof(DualAuthError),
}

impl From<DualAuthError> for DualAuthDecisionError {
    fn from(error: DualAuthError) -> Self {
        Self::StrictProof(error)
    }
}

impl fmt::Display for DualAuthDecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTopology(error) => write!(formatter, "invalid auth topology: {error}"),
            Self::MissingProviderDecision(provider) => {
                write!(formatter, "missing required {provider:?} decision lane")
            }
            Self::DuplicateProviderDecision => {
                formatter.write_str("duplicate provider decision lane")
            }
            Self::ProviderTagMismatch => {
                formatter.write_str("provider decision and proof tags do not match")
            }
            Self::StrictPairedRequired => formatter
                .write_str("strict paired proof is required for admin and sensitive operations"),
            Self::ProviderDisagreement => formatter.write_str(
                "provider decisions disagree; availability-first cannot ignore an invalid result",
            ),
            Self::StrictProof(error) => write!(formatter, "provider proof failed: {error}"),
        }
    }
}

impl std::error::Error for DualAuthDecisionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_topology::{
        ProviderProofStatus, ServerRole, SharedAuthIntegration, SupabasePlacement,
    };

    fn topology(role: ServerRole) -> AuthTopology {
        AuthTopology::new(
            "messaging-intel",
            "messaging-intel",
            "messaging_intel",
            SupabasePlacement::DedicatedOrganization,
            "messaging-intel",
            role,
            "msgint",
            SharedAuthIntegration::OresMiddleware,
        )
        .expect("valid dedicated topology")
    }

    fn proof(provider: AuthProvider, role: ServerRole) -> ProviderProof {
        ProviderProof {
            provider,
            subject: format!("{provider:?}-subject"),
            canonical_user_id: "user-123".into(),
            tenant_id: "tenant-456".into(),
            audience: "msgint".into(),
            data_plane: role.auth_data_plane(),
            status: ProviderProofStatus::Active,
        }
    }

    #[test]
    fn availability_first_accepts_one_valid_lane_only_when_peer_is_unavailable() {
        let role = ServerRole::WebServer;
        let decision = decide_dual_auth(
            &topology(role),
            DualAuthDecisionMode::AvailabilityFirst,
            [
                ProviderDecision::authenticated(proof(AuthProvider::Supabase, role)),
                ProviderDecision::unavailable(AuthProvider::Neon),
            ],
        )
        .expect("one healthy lane may carry an ordinary customer request");

        assert!(matches!(
            decision,
            DualAuthDecision::Authenticated {
                identity: AvailableIdentity {
                    winning_provider: AuthProvider::Supabase,
                    neon_subject: None,
                    ..
                },
                mode: DualAuthDecisionMode::AvailabilityFirst,
            }
        ));
    }

    #[test]
    fn availability_first_rejects_provider_disagreement() {
        let role = ServerRole::WebServer;
        assert_eq!(
            decide_dual_auth(
                &topology(role),
                DualAuthDecisionMode::AvailabilityFirst,
                [
                    ProviderDecision::authenticated(proof(AuthProvider::Supabase, role)),
                    ProviderDecision::invalid(AuthProvider::Neon),
                ],
            ),
            Err(DualAuthDecisionError::ProviderDisagreement)
        );
    }

    #[test]
    fn admin_and_sensitive_operations_require_strict_paired() {
        let admin_role = ServerRole::AdminApiServer;
        assert_eq!(
            decide_dual_auth(
                &topology(admin_role),
                DualAuthDecisionMode::AvailabilityFirst,
                [
                    ProviderDecision::authenticated(proof(AuthProvider::Supabase, admin_role)),
                    ProviderDecision::unavailable(AuthProvider::Neon),
                ],
            ),
            Err(DualAuthDecisionError::StrictPairedRequired)
        );

        let customer_role = ServerRole::ApiServer;
        assert_eq!(
            decide_dual_auth_for_operation(
                &topology(customer_role),
                AuthOperation::Sensitive,
                DualAuthDecisionMode::AvailabilityFirst,
                [
                    ProviderDecision::authenticated(proof(AuthProvider::Supabase, customer_role)),
                    ProviderDecision::unavailable(AuthProvider::Neon),
                ],
            ),
            Err(DualAuthDecisionError::StrictPairedRequired)
        );
    }

    #[test]
    fn strict_paired_never_accepts_one_lane() {
        let role = ServerRole::AdminApiServer;
        assert_eq!(
            decide_dual_auth(
                &topology(role),
                DualAuthDecisionMode::StrictPaired,
                [
                    ProviderDecision::authenticated(proof(AuthProvider::Supabase, role)),
                    ProviderDecision::unavailable(AuthProvider::Neon),
                ],
            ),
            Ok(DualAuthDecision::Degraded)
        );
    }

    #[test]
    fn invalid_proof_is_unauthenticated_even_when_peer_is_unavailable() {
        let role = ServerRole::ApiServer;
        for mode in [
            DualAuthDecisionMode::AvailabilityFirst,
            DualAuthDecisionMode::StrictPaired,
        ] {
            assert_eq!(
                decide_dual_auth(
                    &topology(role),
                    mode,
                    [
                        ProviderDecision::invalid(AuthProvider::Supabase),
                        ProviderDecision::unavailable(AuthProvider::Neon),
                    ],
                ),
                Ok(DualAuthDecision::Unauthenticated)
            );
            assert_eq!(
                decide_dual_auth(
                    &topology(role),
                    mode,
                    [
                        ProviderDecision::unavailable(AuthProvider::Supabase),
                        ProviderDecision::invalid(AuthProvider::Neon),
                    ],
                ),
                Ok(DualAuthDecision::Unauthenticated)
            );
        }
    }

    #[test]
    fn both_invalid_is_unauthenticated_but_both_unavailable_is_degraded() {
        let role = ServerRole::ApiServer;
        assert_eq!(
            decide_dual_auth(
                &topology(role),
                DualAuthDecisionMode::AvailabilityFirst,
                [
                    ProviderDecision::invalid(AuthProvider::Supabase),
                    ProviderDecision::invalid(AuthProvider::Neon),
                ],
            ),
            Ok(DualAuthDecision::Unauthenticated)
        );
        assert_eq!(
            decide_dual_auth(
                &topology(role),
                DualAuthDecisionMode::AvailabilityFirst,
                [
                    ProviderDecision::unavailable(AuthProvider::Supabase),
                    ProviderDecision::unavailable(AuthProvider::Neon),
                ],
            ),
            Ok(DualAuthDecision::Degraded)
        );
    }

    #[test]
    fn strict_paired_reconciles_canonical_identity() {
        let role = ServerRole::AdminWebServer;
        let mut neon = proof(AuthProvider::Neon, role);
        neon.canonical_user_id = "different-user".into();
        assert!(matches!(
            decide_dual_auth(
                &topology(role),
                DualAuthDecisionMode::StrictPaired,
                [
                    ProviderDecision::authenticated(proof(AuthProvider::Supabase, role)),
                    ProviderDecision::authenticated(neon),
                ],
            ),
            Err(DualAuthDecisionError::StrictProof(
                DualAuthError::CanonicalIdentityMismatch
            ))
        ));
    }

    #[test]
    fn missing_or_duplicate_lane_is_a_configuration_error() {
        let role = ServerRole::WebServer;
        assert_eq!(
            decide_dual_auth(
                &topology(role),
                DualAuthDecisionMode::AvailabilityFirst,
                [ProviderDecision::unavailable(AuthProvider::Supabase)],
            ),
            Err(DualAuthDecisionError::MissingProviderDecision(
                AuthProvider::Neon
            ))
        );
        assert_eq!(
            decide_dual_auth(
                &topology(role),
                DualAuthDecisionMode::AvailabilityFirst,
                [
                    ProviderDecision::unavailable(AuthProvider::Supabase),
                    ProviderDecision::invalid(AuthProvider::Supabase),
                    ProviderDecision::unavailable(AuthProvider::Neon),
                ],
            ),
            Err(DualAuthDecisionError::DuplicateProviderDecision)
        );
    }
}
