//! Typed provider-adapter boundary.
//!
//! Provider-specific implementations remain independent, while callers consume
//! one operation contract. The typed wrappers fix the provider identity so a
//! backend cannot relabel a Supabase proof as Neon or native Shared Auth.

use std::{fmt, future::Future, pin::Pin};

use crate::proof_policy::{ProviderKind, VerifiedProof};

pub type ProviderFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProviderError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderOperation {
    VerifyProof,
    InspectSession,
    Exchange,
    Revoke,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCapabilities {
    pub verify_proof: bool,
    pub inspect_session: bool,
    pub exchange: bool,
    pub revoke: bool,
}

impl ProviderCapabilities {
    pub const fn full() -> Self {
        Self {
            verify_proof: true,
            inspect_session: true,
            exchange: true,
            revoke: true,
        }
    }

    pub const fn verification_only() -> Self {
        Self {
            verify_proof: true,
            inspect_session: false,
            exchange: false,
            revoke: false,
        }
    }

    pub fn supports(self, operation: ProviderOperation) -> bool {
        match operation {
            ProviderOperation::VerifyProof => self.verify_proof,
            ProviderOperation::InspectSession => self.inspect_session,
            ProviderOperation::Exchange => self.exchange,
            ProviderOperation::Revoke => self.revoke,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorClass {
    Invalid,
    Unavailable,
    Revoked,
    Conflict,
    Configuration,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    pub class: ProviderErrorClass,
    pub operation: ProviderOperation,
    pub reason: &'static str,
}

impl ProviderError {
    pub const fn new(
        class: ProviderErrorClass,
        operation: ProviderOperation,
        reason: &'static str,
    ) -> Self {
        Self {
            class,
            operation,
            reason,
        }
    }

    fn provider_mismatch(operation: ProviderOperation) -> Self {
        Self::new(
            ProviderErrorClass::Conflict,
            operation,
            "adapter returned proof for a different provider",
        )
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "provider {:?} {:?}: {}",
            self.operation, self.class, self.reason
        )
    }
}

impl std::error::Error for ProviderError {}

pub struct VerifyProofRequest {
    pub credential: String,
    pub realm: String,
    pub audience: String,
    pub now_unix_seconds: u64,
}

impl fmt::Debug for VerifyProofRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifyProofRequest")
            .field("credential", &"[redacted]")
            .field("realm", &self.realm)
            .field("audience", &self.audience)
            .field("now_unix_seconds", &self.now_unix_seconds)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInspectionRequest {
    pub session_id: String,
    pub realm: String,
}

pub struct ExchangeRequest {
    pub credential: String,
    pub realm: String,
    pub audience: String,
}

impl fmt::Debug for ExchangeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExchangeRequest")
            .field("credential", &"[redacted]")
            .field("realm", &self.realm)
            .field("audience", &self.audience)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeRequest {
    pub session_id: String,
    pub realm: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSessionState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInspection {
    pub state: ProviderSessionState,
    pub proof: Option<VerifiedProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeResult {
    pub session_id: String,
    pub proof: VerifiedProof,
}

/// Provider-specific backend implementation.
///
/// This is the only layer that knows a provider's native APIs and token/session
/// semantics. Error classification is part of the interface rather than being
/// reconstructed by callers from status codes.
pub trait ProviderBackend: Send + Sync {
    fn capabilities(&self) -> ProviderCapabilities;

    fn verify_proof<'a>(
        &'a self,
        request: &'a VerifyProofRequest,
    ) -> ProviderFuture<'a, VerifiedProof>;

    fn inspect_session<'a>(
        &'a self,
        request: &'a SessionInspectionRequest,
    ) -> ProviderFuture<'a, SessionInspection>;

    fn exchange<'a>(
        &'a self,
        request: &'a ExchangeRequest,
    ) -> ProviderFuture<'a, ExchangeResult>;

    fn revoke<'a>(
        &'a self,
        request: &'a RevokeRequest,
    ) -> ProviderFuture<'a, ()>;
}

pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> ProviderKind;
    fn capabilities(&self) -> ProviderCapabilities;

    fn verify_proof<'a>(
        &'a self,
        request: &'a VerifyProofRequest,
    ) -> ProviderFuture<'a, VerifiedProof>;

    fn inspect_session<'a>(
        &'a self,
        request: &'a SessionInspectionRequest,
    ) -> ProviderFuture<'a, SessionInspection>;

    fn exchange<'a>(
        &'a self,
        request: &'a ExchangeRequest,
    ) -> ProviderFuture<'a, ExchangeResult>;

    fn revoke<'a>(
        &'a self,
        request: &'a RevokeRequest,
    ) -> ProviderFuture<'a, ()>;
}

macro_rules! typed_adapter {
    ($name:ident, $provider:expr) => {
        pub struct $name<B> {
            backend: B,
        }

        impl<B> $name<B> {
            pub fn new(backend: B) -> Self {
                Self { backend }
            }

            pub fn into_inner(self) -> B {
                self.backend
            }
        }

        impl<B> ProviderAdapter for $name<B>
        where
            B: ProviderBackend,
        {
            fn provider(&self) -> ProviderKind {
                $provider
            }

            fn capabilities(&self) -> ProviderCapabilities {
                self.backend.capabilities()
            }

            fn verify_proof<'a>(
                &'a self,
                request: &'a VerifyProofRequest,
            ) -> ProviderFuture<'a, VerifiedProof> {
                Box::pin(async move {
                    let proof = self.backend.verify_proof(request).await?;
                    enforce_proof_provider(
                        $provider,
                        ProviderOperation::VerifyProof,
                        proof,
                    )
                })
            }

            fn inspect_session<'a>(
                &'a self,
                request: &'a SessionInspectionRequest,
            ) -> ProviderFuture<'a, SessionInspection> {
                Box::pin(async move {
                    let mut inspection =
                        self.backend.inspect_session(request).await?;
                    if let Some(proof) = inspection.proof.take() {
                        inspection.proof = Some(enforce_proof_provider(
                            $provider,
                            ProviderOperation::InspectSession,
                            proof,
                        )?);
                    }
                    Ok(inspection)
                })
            }

            fn exchange<'a>(
                &'a self,
                request: &'a ExchangeRequest,
            ) -> ProviderFuture<'a, ExchangeResult> {
                Box::pin(async move {
                    let mut result = self.backend.exchange(request).await?;
                    result.proof = enforce_proof_provider(
                        $provider,
                        ProviderOperation::Exchange,
                        result.proof,
                    )?;
                    Ok(result)
                })
            }

            fn revoke<'a>(
                &'a self,
                request: &'a RevokeRequest,
            ) -> ProviderFuture<'a, ()> {
                self.backend.revoke(request)
            }
        }
    };
}

typed_adapter!(NativeSharedAuthAdapter, ProviderKind::SharedAuth);
typed_adapter!(SupabaseAdapter, ProviderKind::Supabase);
typed_adapter!(NeonAuthAdapter, ProviderKind::NeonAuth);

fn enforce_proof_provider(
    expected: ProviderKind,
    operation: ProviderOperation,
    proof: VerifiedProof,
) -> Result<VerifiedProof, ProviderError> {
    if proof.identity.provider != expected {
        return Err(ProviderError::provider_mismatch(operation));
    }
    Ok(proof)
}

/// Shared adapter conformance gate used by provider implementations and tests.
pub fn validate_adapter_contract(
    adapter: &dyn ProviderAdapter,
    required: ProviderCapabilities,
) -> Result<(), ProviderError> {
    let actual = adapter.capabilities();
    for operation in [
        ProviderOperation::VerifyProof,
        ProviderOperation::InspectSession,
        ProviderOperation::Exchange,
        ProviderOperation::Revoke,
    ] {
        if required.supports(operation) && !actual.supports(operation) {
            return Err(ProviderError::new(
                ProviderErrorClass::Configuration,
                operation,
                "required provider capability is not implemented",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_policy::{
        ProofClass, ProviderIdentityKey, VerifiedProof,
    };

    struct StubBackend {
        provider: ProviderKind,
        capabilities: ProviderCapabilities,
    }

    impl StubBackend {
        fn proof(&self) -> VerifiedProof {
            VerifiedProof {
                identity: ProviderIdentityKey {
                    provider: self.provider,
                    issuer: "https://issuer.example.invalid".into(),
                    subject: "subject-1".into(),
                    realm: "customer".into(),
                },
                shared_user_id: "user-1".into(),
                class: ProofClass::CustomerIdentity,
                assurance: 1,
                root_proof_id: "root-1".into(),
                policy_revision: "policy-1".into(),
                verified_at_unix_seconds: 1,
                expires_at_unix_seconds: 2,
            }
        }
    }

    impl ProviderBackend for StubBackend {
        fn capabilities(&self) -> ProviderCapabilities {
            self.capabilities
        }

        fn verify_proof<'a>(
            &'a self,
            _request: &'a VerifyProofRequest,
        ) -> ProviderFuture<'a, VerifiedProof> {
            Box::pin(async move { Ok(self.proof()) })
        }

        fn inspect_session<'a>(
            &'a self,
            _request: &'a SessionInspectionRequest,
        ) -> ProviderFuture<'a, SessionInspection> {
            Box::pin(async move {
                Ok(SessionInspection {
                    state: ProviderSessionState::Active,
                    proof: Some(self.proof()),
                })
            })
        }

        fn exchange<'a>(
            &'a self,
            _request: &'a ExchangeRequest,
        ) -> ProviderFuture<'a, ExchangeResult> {
            Box::pin(async move {
                Ok(ExchangeResult {
                    session_id: "session-1".into(),
                    proof: self.proof(),
                })
            })
        }

        fn revoke<'a>(
            &'a self,
            _request: &'a RevokeRequest,
        ) -> ProviderFuture<'a, ()> {
            Box::pin(async move { Ok(()) })
        }
    }

    #[test]
    fn typed_adapters_fix_provider_identity() {
        let shared = NativeSharedAuthAdapter::new(StubBackend {
            provider: ProviderKind::SharedAuth,
            capabilities: ProviderCapabilities::full(),
        });
        let supabase = SupabaseAdapter::new(StubBackend {
            provider: ProviderKind::Supabase,
            capabilities: ProviderCapabilities::full(),
        });
        let neon = NeonAuthAdapter::new(StubBackend {
            provider: ProviderKind::NeonAuth,
            capabilities: ProviderCapabilities::full(),
        });

        assert_eq!(shared.provider(), ProviderKind::SharedAuth);
        assert_eq!(supabase.provider(), ProviderKind::Supabase);
        assert_eq!(neon.provider(), ProviderKind::NeonAuth);
        assert!(validate_adapter_contract(
            &shared,
            ProviderCapabilities::full()
        )
        .is_ok());
        assert!(validate_adapter_contract(
            &supabase,
            ProviderCapabilities::full()
        )
        .is_ok());
        assert!(validate_adapter_contract(
            &neon,
            ProviderCapabilities::full()
        )
        .is_ok());
    }

    #[tokio::test]
    async fn typed_adapter_rejects_backend_provider_spoofing() {
        let adapter = SupabaseAdapter::new(StubBackend {
            provider: ProviderKind::NeonAuth,
            capabilities: ProviderCapabilities::full(),
        });
        let request = VerifyProofRequest {
            credential: "redacted-test-credential".into(),
            realm: "customer".into(),
            audience: "product".into(),
            now_unix_seconds: 1,
        };
        let error = adapter.verify_proof(&request).await.unwrap_err();
        assert_eq!(error.class, ProviderErrorClass::Conflict);
        assert_eq!(error.operation, ProviderOperation::VerifyProof);
        assert!(!error.to_string().contains("redacted-test-credential"));
    }

    #[test]
    fn conformance_gate_rejects_missing_required_capability() {
        let adapter = NeonAuthAdapter::new(StubBackend {
            provider: ProviderKind::NeonAuth,
            capabilities: ProviderCapabilities::verification_only(),
        });
        let error =
            validate_adapter_contract(&adapter, ProviderCapabilities::full())
                .unwrap_err();
        assert_eq!(error.class, ProviderErrorClass::Configuration);
        assert_eq!(error.operation, ProviderOperation::InspectSession);
    }

    #[test]
    fn credential_requests_redact_debug_output() {
        let verify = VerifyProofRequest {
            credential: "secret-marker".into(),
            realm: "customer".into(),
            audience: "product".into(),
            now_unix_seconds: 1,
        };
        let exchange = ExchangeRequest {
            credential: "secret-marker".into(),
            realm: "customer".into(),
            audience: "product".into(),
        };
        assert!(!format!("{verify:?}").contains("secret-marker"));
        assert!(!format!("{exchange:?}").contains("secret-marker"));
    }
}
