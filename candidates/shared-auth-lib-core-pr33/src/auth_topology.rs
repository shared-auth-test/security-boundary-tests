//! Secret-free topology and proof reconciliation for the fleet-wide Shared Auth boundary.
//!
//! This module contains no database client and never reads process environment
//! variables. Executable servers resolve the returned environment keys through
//! `flags-2-env`; `shared-auth-orm-core` owns opaque database capabilities.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const SUPABASE_AUTH_DATABASE_URL_ENV: &str = "SUPABASE_AUTH_DATABASE_URL";
pub const NEON_AUTH_DATABASE_URL_ENV: &str = "NEON_AUTH_DATABASE_URL";
pub const SUPABASE_ADMIN_DATABASE_URL_ENV: &str = "SUPABASE_ADMIN_DATABASE_URL";
pub const NEON_ADMIN_DATABASE_URL_ENV: &str = "NEON_ADMIN_DATABASE_URL";
pub const MAX_ORGANIZATION_SLUG_LEN: usize = 100;
pub const MAX_PROVIDER_SCHEMA_LEN: usize = 63;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerRole {
    WebServer,
    ApiServer,
    AdminWebServer,
    AdminApiServer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthDataPlane {
    CustomerAuth,
    AdminAuth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    Supabase,
    Neon,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SharedAuthIntegration {
    Direct,
    OresMiddleware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SupabasePlacement {
    /// Retained only so older serialized configuration fails with an explicit
    /// policy error rather than being misread. It is never accepted.
    #[serde(rename = "shared-org-schema")]
    SharedOrganizationNamespace,
    #[serde(rename = "dedicated-org")]
    DedicatedOrganization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDatabaseEnvKeys {
    pub supabase: &'static str,
    pub neon: &'static str,
}

impl ServerRole {
    #[must_use]
    pub const fn auth_data_plane(self) -> AuthDataPlane {
        match self {
            Self::WebServer | Self::ApiServer => AuthDataPlane::CustomerAuth,
            Self::AdminWebServer | Self::AdminApiServer => AuthDataPlane::AdminAuth,
        }
    }

    #[must_use]
    pub const fn database_env_keys(self) -> ProviderDatabaseEnvKeys {
        self.auth_data_plane().database_env_keys()
    }

    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(self, Self::AdminWebServer | Self::AdminApiServer)
    }
}

impl AuthDataPlane {
    #[must_use]
    pub const fn database_env_keys(self) -> ProviderDatabaseEnvKeys {
        match self {
            Self::CustomerAuth => ProviderDatabaseEnvKeys {
                supabase: SUPABASE_AUTH_DATABASE_URL_ENV,
                neon: NEON_AUTH_DATABASE_URL_ENV,
            },
            Self::AdminAuth => ProviderDatabaseEnvKeys {
                supabase: SUPABASE_ADMIN_DATABASE_URL_ENV,
                neon: NEON_ADMIN_DATABASE_URL_ENV,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthTopology {
    pub github_org: String,
    pub supabase_org: String,
    /// Canonical organization-scoped `PostgreSQL` schema used by both the
    /// Supabase and Neon projections. The field name is retained for source
    /// compatibility; callers must use [`Self::provider_schema`] when the
    /// provider-neutral meaning matters.
    pub supabase_schema: String,
    pub supabase_placement: SupabasePlacement,
    pub neon_org: String,
    pub server_role: ServerRole,
    pub audience: String,
    pub integration: SharedAuthIntegration,
}

impl AuthTopology {
    /// Construct and validate a dedicated Supabase-and-Neon topology.
    ///
    /// # Errors
    ///
    /// Returns [`TopologyError`] when an organization slug or provider schema
    /// is invalid, either provider organization differs from `github_org`, the
    /// Supabase placement is not dedicated, or `audience` is empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        github_org: impl Into<String>,
        supabase_org: impl Into<String>,
        provider_schema: impl Into<String>,
        supabase_placement: SupabasePlacement,
        neon_org: impl Into<String>,
        server_role: ServerRole,
        audience: impl Into<String>,
        integration: SharedAuthIntegration,
    ) -> Result<Self, TopologyError> {
        let topology = Self {
            github_org: github_org.into(),
            supabase_org: supabase_org.into(),
            supabase_schema: provider_schema.into(),
            supabase_placement,
            neon_org: neon_org.into(),
            server_role,
            audience: audience.into(),
            integration,
        };
        topology.validate()?;
        Ok(topology)
    }

    /// Recheck all organization, schema, placement, and audience invariants.
    ///
    /// # Errors
    ///
    /// Returns [`TopologyError`] when any topology field is malformed or when
    /// the two provider organizations do not match the GitHub organization.
    pub fn validate(&self) -> Result<(), TopologyError> {
        validate_slug("githubOrg", &self.github_org)?;
        validate_slug("supabaseOrg", &self.supabase_org)?;
        validate_provider_schema(&self.supabase_schema)?;
        validate_slug("neonOrg", &self.neon_org)?;

        if self.supabase_placement != SupabasePlacement::DedicatedOrganization {
            return Err(TopologyError::SharedSupabaseOrganizationForbidden);
        }
        if self.supabase_org != self.github_org {
            return Err(TopologyError::SupabaseOrganizationMismatch);
        }
        if self.neon_org != self.github_org {
            return Err(TopologyError::NeonOrganizationMismatch);
        }
        if self.audience.trim().is_empty() {
            return Err(TopologyError::EmptyAudience);
        }
        Ok(())
    }

    #[must_use]
    pub const fn data_plane(&self) -> AuthDataPlane {
        self.server_role.auth_data_plane()
    }

    #[must_use]
    pub const fn database_env_keys(&self) -> ProviderDatabaseEnvKeys {
        self.server_role.database_env_keys()
    }

    #[must_use]
    pub const fn required_providers(&self) -> [AuthProvider; 2] {
        [AuthProvider::Supabase, AuthProvider::Neon]
    }

    /// Return the one organization-scoped schema that both provider
    /// projections must use. A separate Neon schema value is intentionally not
    /// representable, so schema disagreement fails at the type boundary.
    #[must_use]
    pub fn provider_schema(&self) -> &str {
        &self.supabase_schema
    }

    #[must_use]
    pub fn neon_schema(&self) -> &str {
        self.provider_schema()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderProofStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderProof {
    pub provider: AuthProvider,
    /// Provider-native subject. Supabase and Neon subjects may differ.
    pub subject: String,
    /// Canonical Shared Auth identity to which the provider subject is bound.
    pub canonical_user_id: String,
    pub tenant_id: String,
    pub audience: String,
    pub data_plane: AuthDataPlane,
    pub status: ProviderProofStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedIdentity {
    pub canonical_user_id: String,
    pub tenant_id: String,
    pub supabase_subject: String,
    pub neon_subject: String,
    pub audience: String,
    pub data_plane: AuthDataPlane,
}

/// Reconcile exactly one active Supabase proof and one active Neon proof.
///
/// Provider-native subjects need not be equal; Shared Auth binds both to one
/// canonical identity. Every security boundary must agree. Missing, duplicated,
/// revoked, or mismatched evidence fails closed.
///
/// # Errors
///
/// Returns [`DualAuthError`] when the topology is invalid; a provider proof is
/// missing, duplicated, revoked, empty, or targets the wrong audience or data
/// plane; or the two proofs disagree on canonical identity or tenant.
pub fn verify_dual_provider_proofs(
    topology: &AuthTopology,
    proofs: impl IntoIterator<Item = ProviderProof>,
) -> Result<VerifiedIdentity, DualAuthError> {
    topology
        .validate()
        .map_err(DualAuthError::InvalidTopology)?;

    let mut supabase = None;
    let mut neon = None;
    for proof in proofs {
        let target = match proof.provider {
            AuthProvider::Supabase => &mut supabase,
            AuthProvider::Neon => &mut neon,
        };
        if target.replace(proof).is_some() {
            return Err(DualAuthError::DuplicateProviderProof);
        }
    }

    let supabase = supabase.ok_or(DualAuthError::MissingProviderProof(AuthProvider::Supabase))?;
    let neon = neon.ok_or(DualAuthError::MissingProviderProof(AuthProvider::Neon))?;

    validate_proof(topology, &supabase)?;
    validate_proof(topology, &neon)?;

    if supabase.canonical_user_id != neon.canonical_user_id {
        return Err(DualAuthError::CanonicalIdentityMismatch);
    }
    if supabase.tenant_id != neon.tenant_id {
        return Err(DualAuthError::TenantMismatch);
    }

    Ok(VerifiedIdentity {
        canonical_user_id: supabase.canonical_user_id,
        tenant_id: supabase.tenant_id,
        supabase_subject: supabase.subject,
        neon_subject: neon.subject,
        audience: topology.audience.clone(),
        data_plane: topology.data_plane(),
    })
}

pub(crate) fn validate_proof(
    topology: &AuthTopology,
    proof: &ProviderProof,
) -> Result<(), DualAuthError> {
    if proof.status == ProviderProofStatus::Revoked {
        return Err(DualAuthError::RevokedProviderProof(proof.provider));
    }
    if proof.subject.trim().is_empty() || proof.canonical_user_id.trim().is_empty() {
        return Err(DualAuthError::EmptyIdentityField(proof.provider));
    }
    if proof.tenant_id.trim().is_empty() {
        return Err(DualAuthError::EmptyTenant(proof.provider));
    }
    if proof.audience != topology.audience {
        return Err(DualAuthError::AudienceMismatch(proof.provider));
    }
    if proof.data_plane != topology.data_plane() {
        return Err(DualAuthError::DataPlaneMismatch(proof.provider));
    }
    Ok(())
}

fn validate_slug(field: &'static str, value: &str) -> Result<(), TopologyError> {
    if value.len() > MAX_ORGANIZATION_SLUG_LEN {
        return Err(TopologyError::OrganizationSlugTooLong(field));
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(TopologyError::InvalidSlug(field));
    };
    if !first.is_ascii_alphanumeric()
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err(TopologyError::InvalidSlug(field));
    }
    Ok(())
}

fn validate_provider_schema(value: &str) -> Result<(), TopologyError> {
    if value.len() > MAX_PROVIDER_SCHEMA_LEN {
        return Err(TopologyError::ProviderSchemaTooLong);
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(TopologyError::InvalidProviderSchema);
    };
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(TopologyError::InvalidProviderSchema);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopologyError {
    InvalidSlug(&'static str),
    OrganizationSlugTooLong(&'static str),
    InvalidProviderSchema,
    ProviderSchemaTooLong,
    SharedSupabaseOrganizationForbidden,
    SupabaseOrganizationMismatch,
    NeonOrganizationMismatch,
    EmptyAudience,
}

impl fmt::Display for TopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSlug(field) => {
                write!(formatter, "{field} is not a valid organization slug")
            }
            Self::OrganizationSlugTooLong(field) => write!(
                formatter,
                "{field} exceeds the {MAX_ORGANIZATION_SLUG_LEN}-character contract limit",
            ),
            Self::InvalidProviderSchema => {
                formatter.write_str("provider schema must be an unquoted PostgreSQL identifier")
            }
            Self::ProviderSchemaTooLong => write!(
                formatter,
                "provider schema exceeds PostgreSQL's {MAX_PROVIDER_SCHEMA_LEN}-character identifier limit",
            ),
            Self::SharedSupabaseOrganizationForbidden => {
                formatter.write_str("Supabase placement must be a dedicated organization")
            }
            Self::SupabaseOrganizationMismatch => {
                formatter.write_str("Supabase organization must equal the GitHub organization")
            }
            Self::NeonOrganizationMismatch => {
                formatter.write_str("Neon organization must equal the GitHub organization")
            }
            Self::EmptyAudience => formatter.write_str("audience must not be empty"),
        }
    }
}

impl std::error::Error for TopologyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualAuthError {
    InvalidTopology(TopologyError),
    MissingProviderProof(AuthProvider),
    DuplicateProviderProof,
    RevokedProviderProof(AuthProvider),
    EmptyIdentityField(AuthProvider),
    EmptyTenant(AuthProvider),
    AudienceMismatch(AuthProvider),
    DataPlaneMismatch(AuthProvider),
    CanonicalIdentityMismatch,
    TenantMismatch,
}

impl fmt::Display for DualAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTopology(error) => write!(formatter, "invalid auth topology: {error}"),
            Self::MissingProviderProof(provider) => {
                write!(formatter, "missing required {provider:?} proof")
            }
            Self::DuplicateProviderProof => formatter.write_str("duplicate provider proof"),
            Self::RevokedProviderProof(provider) => {
                write!(formatter, "{provider:?} proof is revoked")
            }
            Self::EmptyIdentityField(provider) => {
                write!(formatter, "{provider:?} proof has an empty identity field")
            }
            Self::EmptyTenant(provider) => {
                write!(formatter, "{provider:?} proof has an empty tenant")
            }
            Self::AudienceMismatch(provider) => {
                write!(formatter, "{provider:?} proof has the wrong audience")
            }
            Self::DataPlaneMismatch(provider) => {
                write!(
                    formatter,
                    "{provider:?} proof targets the wrong auth data plane"
                )
            }
            Self::CanonicalIdentityMismatch => {
                formatter.write_str("provider proofs map to different canonical identities")
            }
            Self::TenantMismatch => formatter.write_str("provider proofs map to different tenants"),
        }
    }
}

impl std::error::Error for DualAuthError {}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn proof(provider: AuthProvider, subject: &str, role: ServerRole) -> ProviderProof {
        ProviderProof {
            provider,
            subject: subject.into(),
            canonical_user_id: "user-123".into(),
            tenant_id: "tenant-456".into(),
            audience: "msgint".into(),
            data_plane: role.auth_data_plane(),
            status: ProviderProofStatus::Active,
        }
    }

    #[test]
    fn server_roles_select_disjoint_database_settings() {
        assert_eq!(
            ServerRole::WebServer.database_env_keys(),
            ProviderDatabaseEnvKeys {
                supabase: SUPABASE_AUTH_DATABASE_URL_ENV,
                neon: NEON_AUTH_DATABASE_URL_ENV,
            }
        );
        assert_eq!(
            ServerRole::AdminApiServer.database_env_keys(),
            ProviderDatabaseEnvKeys {
                supabase: SUPABASE_ADMIN_DATABASE_URL_ENV,
                neon: NEON_ADMIN_DATABASE_URL_ENV,
            }
        );
        assert_ne!(
            ServerRole::WebServer.database_env_keys(),
            ServerRole::AdminWebServer.database_env_keys()
        );
    }

    #[test]
    fn requires_dedicated_provider_organizations() {
        let value = topology(ServerRole::ApiServer);
        assert_eq!(value.supabase_org, value.github_org);
        assert_eq!(value.neon_org, value.github_org);
        assert_eq!(
            value.supabase_placement,
            SupabasePlacement::DedicatedOrganization
        );
        assert_eq!(
            value.required_providers(),
            [AuthProvider::Supabase, AuthProvider::Neon]
        );

        assert_eq!(
            AuthTopology::new(
                "messaging-intel",
                "oresoftware",
                "messaging_intel",
                SupabasePlacement::SharedOrganizationNamespace,
                "messaging-intel",
                ServerRole::ApiServer,
                "msgint",
                SharedAuthIntegration::Direct,
            ),
            Err(TopologyError::SharedSupabaseOrganizationForbidden)
        );
        assert_eq!(
            AuthTopology::new(
                "messaging-intel",
                "oresoftware",
                "messaging_intel",
                SupabasePlacement::DedicatedOrganization,
                "messaging-intel",
                ServerRole::ApiServer,
                "msgint",
                SharedAuthIntegration::Direct,
            ),
            Err(TopologyError::SupabaseOrganizationMismatch)
        );
        assert_eq!(
            AuthTopology::new(
                "messaging-intel",
                "messaging-intel",
                "messaging_intel",
                SupabasePlacement::DedicatedOrganization,
                "other-org",
                ServerRole::ApiServer,
                "msgint",
                SharedAuthIntegration::Direct,
            ),
            Err(TopologyError::NeonOrganizationMismatch)
        );
    }

    #[test]
    fn one_schema_is_shared_by_both_provider_projections() {
        let value = topology(ServerRole::WebServer);
        assert_eq!(value.provider_schema(), "messaging_intel");
        assert_eq!(value.neon_schema(), value.provider_schema());
    }

    #[test]
    fn enforces_interface_length_limits() {
        let overlong_org = "a".repeat(MAX_ORGANIZATION_SLUG_LEN + 1);
        assert_eq!(
            AuthTopology::new(
                &overlong_org,
                &overlong_org,
                "valid_schema",
                SupabasePlacement::DedicatedOrganization,
                &overlong_org,
                ServerRole::ApiServer,
                "msgint",
                SharedAuthIntegration::Direct,
            ),
            Err(TopologyError::OrganizationSlugTooLong("githubOrg"))
        );

        let overlong_schema = "a".repeat(MAX_PROVIDER_SCHEMA_LEN + 1);
        assert_eq!(
            AuthTopology::new(
                "messaging-intel",
                "messaging-intel",
                overlong_schema,
                SupabasePlacement::DedicatedOrganization,
                "messaging-intel",
                ServerRole::ApiServer,
                "msgint",
                SharedAuthIntegration::Direct,
            ),
            Err(TopologyError::ProviderSchemaTooLong)
        );
    }

    #[test]
    fn placement_serialization_matches_interface_contract() {
        assert_eq!(
            serde_json::to_string(&SupabasePlacement::DedicatedOrganization)
                .expect("placement serializes"),
            "\"dedicated-org\""
        );
        assert_eq!(
            serde_json::to_string(&SupabasePlacement::SharedOrganizationNamespace)
                .expect("legacy placement serializes"),
            "\"shared-org-schema\""
        );
    }

    #[test]
    fn accepts_different_provider_subjects_bound_to_one_identity() {
        let role = ServerRole::WebServer;
        let verified = verify_dual_provider_proofs(
            &topology(role),
            [
                proof(AuthProvider::Supabase, "supabase-subject", role),
                proof(AuthProvider::Neon, "neon-subject", role),
            ],
        )
        .expect("both provider bindings agree");

        assert_eq!(verified.canonical_user_id, "user-123");
        assert_eq!(verified.supabase_subject, "supabase-subject");
        assert_eq!(verified.neon_subject, "neon-subject");
    }

    #[test]
    fn fails_closed_when_one_provider_is_missing() {
        let role = ServerRole::ApiServer;
        assert_eq!(
            verify_dual_provider_proofs(
                &topology(role),
                [proof(AuthProvider::Supabase, "supabase-subject", role)]
            ),
            Err(DualAuthError::MissingProviderProof(AuthProvider::Neon))
        );
    }

    #[test]
    fn rejects_revoked_wrong_audience_and_cross_plane_proofs() {
        let role = ServerRole::AdminWebServer;
        let expected = topology(role);

        let mut revoked = proof(AuthProvider::Supabase, "s", role);
        revoked.status = ProviderProofStatus::Revoked;
        assert!(matches!(
            verify_dual_provider_proofs(&expected, [revoked, proof(AuthProvider::Neon, "n", role)]),
            Err(DualAuthError::RevokedProviderProof(AuthProvider::Supabase))
        ));

        let mut wrong_audience = proof(AuthProvider::Supabase, "s", role);
        wrong_audience.audience = "customer-app".into();
        assert!(matches!(
            verify_dual_provider_proofs(
                &expected,
                [wrong_audience, proof(AuthProvider::Neon, "n", role)]
            ),
            Err(DualAuthError::AudienceMismatch(AuthProvider::Supabase))
        ));

        let mut customer_proof = proof(AuthProvider::Supabase, "s", role);
        customer_proof.data_plane = AuthDataPlane::CustomerAuth;
        assert!(matches!(
            verify_dual_provider_proofs(
                &expected,
                [customer_proof, proof(AuthProvider::Neon, "n", role)]
            ),
            Err(DualAuthError::DataPlaneMismatch(AuthProvider::Supabase))
        ));
    }

    #[test]
    fn rejects_identity_and_tenant_disagreement() {
        let role = ServerRole::ApiServer;
        let expected = topology(role);

        let supabase = proof(AuthProvider::Supabase, "s", role);
        let mut neon = proof(AuthProvider::Neon, "n", role);
        neon.canonical_user_id = "different-user".into();
        assert_eq!(
            verify_dual_provider_proofs(&expected, [supabase.clone(), neon]),
            Err(DualAuthError::CanonicalIdentityMismatch)
        );

        let mut neon = proof(AuthProvider::Neon, "n", role);
        neon.tenant_id = "different-tenant".into();
        assert_eq!(
            verify_dual_provider_proofs(&expected, [supabase, neon]),
            Err(DualAuthError::TenantMismatch)
        );
    }

    #[test]
    fn rejects_ambiguous_topology_names() {
        assert_eq!(
            AuthTopology::new(
                "messaging-intel",
                "messaging-intel",
                "messaging-intel",
                SupabasePlacement::DedicatedOrganization,
                "messaging-intel",
                ServerRole::ApiServer,
                "msgint",
                SharedAuthIntegration::Direct,
            ),
            Err(TopologyError::InvalidProviderSchema)
        );
    }
}
