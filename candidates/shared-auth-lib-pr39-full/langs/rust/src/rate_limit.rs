use std::fmt;

use serde::Serialize;
use shared_auth_interfaces::{AuthOutcome, Identity};

pub const RATE_LIMIT_PRINCIPAL_PROTOCOL: &str = "shared-auth.rate-limit-principal.v1";
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_TENANT_BYTES: usize = 256;

/// Minimal verified identity material exposed to a trusted rate-limit boundary.
///
/// This contract deliberately excludes email, provider subject, session id,
/// roles, tokens, cookies, and authentication claims. The receiving boundary
/// derives its own opaque HMAC key before storing, caching, or logging anything.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum RateLimitPrincipalResolution {
    Authenticated {
        subject: String,
        #[serde(rename = "tenantId", skip_serializing_if = "Option::is_none")]
        tenant_id: Option<String>,
    },
    Unauthenticated,
    Degraded,
}

impl RateLimitPrincipalResolution {
    #[must_use]
    pub fn from_auth_outcome(outcome: &AuthOutcome) -> Self {
        match outcome {
            AuthOutcome::Authenticated { identity, .. } => Self::from_identity(identity),
            AuthOutcome::Anonymous | AuthOutcome::Unauthenticated => Self::Unauthenticated,
            AuthOutcome::Degraded { .. } => Self::Degraded,
        }
    }

    fn from_identity(identity: &Identity) -> Self {
        if !is_opaque_component(&identity.shared_user_id, MAX_SUBJECT_BYTES) {
            return Self::Degraded;
        }

        let tenant_id = if identity.provider_tenant.is_empty() {
            None
        } else if is_opaque_component(&identity.provider_tenant, MAX_TENANT_BYTES) {
            Some(identity.provider_tenant.clone())
        } else {
            return Self::Degraded;
        };

        Self::Authenticated {
            subject: identity.shared_user_id.clone(),
            tenant_id,
        }
    }
}

impl fmt::Debug for RateLimitPrincipalResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated { tenant_id, .. } => formatter
                .debug_struct("Authenticated")
                .field("subject", &"<redacted>")
                .field("tenant_id", &tenant_id.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::Unauthenticated => formatter.write_str("Unauthenticated"),
            Self::Degraded => formatter.write_str("Degraded"),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct RateLimitPrincipalEnvelope {
    pub protocol: &'static str,
    #[serde(flatten)]
    pub principal: RateLimitPrincipalResolution,
}

impl RateLimitPrincipalEnvelope {
    #[must_use]
    pub fn from_auth_outcome(outcome: &AuthOutcome) -> Self {
        Self {
            protocol: RATE_LIMIT_PRINCIPAL_PROTOCOL,
            principal: RateLimitPrincipalResolution::from_auth_outcome(outcome),
        }
    }
}

impl fmt::Debug for RateLimitPrincipalEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitPrincipalEnvelope")
            .field("protocol", &self.protocol)
            .field("principal", &self.principal)
            .finish()
    }
}

fn is_opaque_component(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_auth_interfaces::Authority;

    fn verified_identity() -> Identity {
        serde_json::from_str(include_str!(
            "../../../vendor/shared-auth-interfaces/fixtures/identity.json"
        ))
        .unwrap()
    }

    fn authenticated(identity: Identity) -> AuthOutcome {
        AuthOutcome::Authenticated {
            identity: Box::new(identity),
            authority: Authority::SharedAuth,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn authenticated_contract_contains_only_stable_scoping_material() {
        let identity = verified_identity();
        let subject = identity.shared_user_id.clone();
        let email = identity.email.clone().expect("fixture carries an email");
        let provider_subject = identity.provider_subject.clone();
        let envelope = RateLimitPrincipalEnvelope::from_auth_outcome(&authenticated(identity));
        let json = serde_json::to_string(&envelope).unwrap();

        assert!(json.contains(RATE_LIMIT_PRINCIPAL_PROTOCOL));
        assert!(json.contains("\"outcome\":\"authenticated\""));
        assert!(json.contains(&subject));
        assert!(!json.contains("email"));
        assert!(!json.contains(&email));
        assert!(!json.contains(&provider_subject));
        assert!(!format!("{envelope:?}").contains(&subject));
    }

    #[test]
    fn unauthenticated_outcomes_are_collapsed_without_claims() {
        for outcome in [AuthOutcome::Anonymous, AuthOutcome::Unauthenticated] {
            assert_eq!(
                RateLimitPrincipalResolution::from_auth_outcome(&outcome),
                RateLimitPrincipalResolution::Unauthenticated
            );
        }
    }

    #[test]
    fn degraded_auth_remains_distinct() {
        let outcome = AuthOutcome::Degraded {
            reason: "authority unavailable".to_owned(),
        };
        assert_eq!(
            RateLimitPrincipalResolution::from_auth_outcome(&outcome),
            RateLimitPrincipalResolution::Degraded
        );
    }

    #[test]
    fn malformed_or_email_shaped_stable_ids_degrade() {
        for invalid in ["", "raw@example.com", "contains space", "contains/slash"] {
            let mut identity = verified_identity();
            identity.shared_user_id = invalid.to_owned();
            assert_eq!(
                RateLimitPrincipalResolution::from_auth_outcome(&authenticated(identity)),
                RateLimitPrincipalResolution::Degraded
            );
        }
    }

    #[test]
    fn malformed_tenant_degrades_instead_of_changing_scope() {
        let mut identity = verified_identity();
        identity.provider_tenant = "tenant/escape".to_owned();
        assert_eq!(
            RateLimitPrincipalResolution::from_auth_outcome(&authenticated(identity)),
            RateLimitPrincipalResolution::Degraded
        );
    }
}
