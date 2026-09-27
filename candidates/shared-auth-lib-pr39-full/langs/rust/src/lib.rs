//! Reusable Rust guard primitives for shared-auth consumers.
//!
//! Most services only need [`Guard`]:
//!
//! ```ignore
//! let guard = Arc::new(Guard::new(GuardConfig { /* endpoints, login_url */ ..Default::default() }));
//! // in a handler:
//! let identity = match guard.require(&headers, Some(path)).await {
//!     Ok(identity) => identity,
//!     Err(limited) => return limited, // 401/503, limited HTML for browsers, JSON otherwise
//! };
//! ```
//!
//! Browser applications that need to rotate a provider token into the newly
//! issued Shared Auth access token use [`SessionAwareAuthGuard`]. The returned
//! [`SessionUpgrade`] is redacted in `Debug` and never contains a refresh token.
//!
//! The lower layers are public for services that need custom composition:
//! [`race`]/[`race_many`] (the dual-auth race), [`authority`] (the individual
//! arms), and [`limited`] (the limited-page renderer).

pub mod authority;
// The public guard API intentionally returns a complete Axum response so callers
// can return 401/403/503 immediately. Boxing it would be an API-breaking change.
#[allow(clippy::result_large_err)]
pub mod guard;
pub mod limited;
pub mod provider_adapter;
pub mod provider_jwt;
pub mod proof_policy;
pub mod race;
pub mod rate_limit;
pub mod session_guard;

pub use authority::{
    exchange_at_shared_auth, verify_at_supabase, verify_shared_auth_token, AuthorityConfig,
    SupabaseBackend,
};
pub use guard::{
    AccessPolicy, AuthGuard, AuthGuardConfig, Guard, GuardConfig, ORE_SESSION_COOKIE,
    SUPABASE_TOKEN_COOKIE, SUPABASE_TOKEN_HEADER,
};
pub use provider_adapter::{
    validate_adapter_contract, ExchangeRequest, ExchangeResult, NativeSharedAuthAdapter,
    NeonAuthAdapter, ProviderAdapter, ProviderBackend, ProviderCapabilities, ProviderError,
    ProviderErrorClass, ProviderFuture, ProviderOperation, ProviderSessionState, RevokeRequest,
    SessionInspection, SessionInspectionRequest, SupabaseAdapter, VerifyProofRequest,
};
pub use provider_jwt::{
    JwtVerificationError, ProviderJwtConfig, ProviderJwtVerifier, ServerJwtSigner, SignedJwt,
    SigningConfig, VerifiedJwt,
};
pub use proof_policy::{
    arbitrate, AcceptedIdentity, ArbitrationDecision, OptimisticCustomerPolicy,
    PrivilegedAdministrationPolicy, ProofClass, ProofPolicy, ProviderIdentityKey, ProviderKind,
    ProviderVerdict, RejectionReason, StrictProviderPairPolicy, StrictSubsystemGrantPolicy,
    VerifiedProof,
};
pub use race::{race, race_many, ArmFailure, ArmResult, BoxedAuthorityArm};
pub use rate_limit::{
    RateLimitPrincipalEnvelope, RateLimitPrincipalResolution, RATE_LIMIT_PRINCIPAL_PROTOCOL,
};
pub use session_guard::{
    exchange_session_at_shared_auth, SessionAwareAuthGuard, SessionDecision, SessionUpgrade,
};
pub use shared_auth_interfaces::{AuthOutcome, Authority, Identity, LimitedPage};
