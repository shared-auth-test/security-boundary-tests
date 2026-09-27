#![forbid(unsafe_code)]

//! Shared, persistence-free authentication domain behavior.
//!
//! Executable ORM entities, database configuration, connection capabilities,
//! schema revision checks, and migration concerns belong only in the private
//! `shared-auth-orm-core` package.

pub mod auth_decision;
pub mod auth_topology;
pub mod central_config;
pub mod config;
pub mod config_discovery;
pub mod consumer_policy;
pub mod proximity;
pub mod shared_auth_config;

pub use auth_decision::{
    AuthOperation, AvailableIdentity, DualAuthDecision, DualAuthDecisionError,
    DualAuthDecisionMode, ProviderDecision, ProviderDecisionOutcome, decide_dual_auth,
    decide_dual_auth_for_operation,
};
pub use auth_topology::{
    AuthDataPlane, AuthProvider, AuthTopology, DualAuthError, MAX_ORGANIZATION_SLUG_LEN,
    MAX_PROVIDER_SCHEMA_LEN, NEON_ADMIN_DATABASE_URL_ENV, NEON_AUTH_DATABASE_URL_ENV,
    ProviderDatabaseEnvKeys, ProviderProof, ProviderProofStatus,
    SUPABASE_ADMIN_DATABASE_URL_ENV, SUPABASE_AUTH_DATABASE_URL_ENV, ServerRole,
    SharedAuthIntegration, SupabasePlacement, TopologyError, VerifiedIdentity,
    verify_dual_provider_proofs,
};
pub use central_config::{
    CENTRAL_SHARED_AUTH_CONFIG_TOML, SHARED_AUTH_INTERFACES_POLICY_REVISION,
    central_shared_auth_defaults, central_shared_auth_policy,
    central_shared_auth_policy_for_revision, load_project_config_with_central_defaults,
    load_project_config_with_central_defaults_for_revision,
};
pub use config::{
    AuthPage, CANONICAL_CONFIG_FILE, CONFIG_SCHEMA_VERSION, CommitRange, Compatibility,
    ExactCompatibility, FactorMethod, FactorsPolicy, FactorsPolicyOverlay, LEGACY_CONFIG_FILE,
    LoadedSharedAuthConfig, PagesPolicy, PagesPolicyOverlay, RangeCompatibility,
    ResolvedSharedAuthConfig, SHARED_AUTH_INTERFACES_REPOSITORY, SharedAuthConfigError,
    SharedAuthConfigOverlay, SharedAuthDefaults, StylingPolicy, StylingPolicyOverlay,
    Theme, ThreeFactorPolicy, ThreeFactorPolicyOverlay, TwoFactorPolicy,
    TwoFactorPolicyOverlay, discover_project_config, load_project_config,
};
pub use config_discovery::{
    discover_project_config_hardened, is_repo_root as is_shared_auth_config_repo_root,
    load_project_config_hardened, DiscoveredSharedAuthConfig, SharedAuthDiscoveryError,
    MAX_DISCOVERY_ANCESTORS, MAX_DISCOVERY_CONFIG_BYTES,
};
pub use consumer_policy::{ConsumerPolicyAction, ConsumerPolicyDenied};
pub use proximity::{
    ConsumeContext, MintCommand, ProximityAuthority, ProximityConsumeResult,
    ProximityStepUpRequest, THREEFA_APP_AMR,
};
// DEN-606 landed twice on 2026-09-09: #15 (`config`, the overlay/defaults
// resolver that `central_config` builds on) and #16 (`shared_auth_config`, the
// fail-closed file runtime pinned to an interfaces authority revision). Both
// exported the same 15 names at the crate root, so the crate stopped compiling.
// `config` keeps the root names because `central_config` and the resolver depend
// on them; `shared_auth_config` stays whole and its overlapping types remain
// reachable by path (`shared_auth_config::LoadedSharedAuthConfig`, ...). Only
// names it alone defines are re-exported here.
pub use shared_auth_config::{
    CANONICAL_CONFIG_FILENAME, COMPATIBILITY_ALIAS_FILENAME, ConfigError, ProjectConfigSource,
    SHARED_AUTH_CONFIG_AUTHORITY_REVISION, SharedAuthConfigFile,
};
