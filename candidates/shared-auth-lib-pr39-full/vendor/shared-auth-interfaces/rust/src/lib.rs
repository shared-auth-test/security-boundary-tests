//! shared-auth contract types. Structurally identical across every binding —
//! see `SPEC.md` at the repo root. Keep this file and the other `generated/*`
//! bindings in lockstep.

use serde::{Deserialize, Serialize};

/// Which authority proved the identity. Set by the dual-auth race.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authority {
    SharedAuth,
    Supabase,
}

/// A verified end user.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    /// Stable OreSoftware id (`sub` of a shared-auth token).
    pub shared_user_id: String,
    /// Identity provider adapter (`local`, `supabase`, `clerk`, `cognito`, ...).
    pub provider: String,
    pub provider_tenant: String,
    pub provider_subject: String,
    /// Supabase compatibility aliases; absent for local/other providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supabase_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub email_verified: bool,
    #[serde(default)]
    pub roles: Vec<String>,
    /// Authentication Methods References. Missing on legacy tokens decodes as empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    /// Authentication Context Class Reference. `loa:2` denotes verified step-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Credential class of a sandboxed identity (`ssh_key`, ...); absent on
    /// interactive and delegated identities. See `SPEC.md` §1.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred: Option<String>,
    pub authority: Authority,
}

impl Identity {
    /// True only when the identity explicitly carries the requested ACR.
    pub fn has_acr(&self, required: &str) -> bool {
        self.acr.as_deref() == Some(required)
    }

    /// True only when the identity explicitly lists the requested method.
    pub fn used_method(&self, method: &str) -> bool {
        self.amr.iter().any(|candidate| candidate == method)
    }

    /// True when the identity was proven by a registered credential rather than
    /// an interactive ceremony. Fail-closed: any non-null `cred`, including an
    /// unrecognized class, counts. See `SPEC.md` §1.2.
    pub fn is_sandboxed(&self) -> bool {
        self.cred.is_some()
    }
}

/// The result of an auth check.
///
/// `Degraded` is deliberately distinct from `Unauthenticated`: it means we could
/// not *decide*, not that the user is invalid. Fail closed for privileged actions,
/// but never present it as "logged out".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum AuthOutcome {
    Authenticated {
        /// Boxed only in the Rust representation to keep the result enum compact.
        /// Serde treats `Box<T>` transparently, so the cross-language JSON contract
        /// and every existing fixture remain unchanged.
        identity: Box<Identity>,
        authority: Authority,
        elapsed_ms: u64,
    },
    /// No credential presented.
    Anonymous,
    /// Credential presented but invalid/expired.
    Unauthenticated,
    /// Both authorities unreachable.
    Degraded { reason: String },
}

impl AuthOutcome {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthOutcome::Authenticated { .. })
    }
    pub fn identity(&self) -> Option<&Identity> {
        match self {
            AuthOutcome::Authenticated { identity, .. } => Some(identity.as_ref()),
            _ => None,
        }
    }
}

/// Contract for the limited page a guard returns to an unauthenticated caller.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LimitedPage {
    pub status_code: u16,
    pub login_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_to: Option<String>,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_fixture_roundtrips() {
        let raw = include_str!("../../../fixtures/identity.json");
        let id: Identity = serde_json::from_str(raw).unwrap();
        assert_eq!(id.provider, "supabase");
        assert_eq!(id.project.as_deref(), Some("fiducia-cloud"));
        assert_eq!(id.authority, Authority::SharedAuth);
        assert!(id.email_verified);
        assert!(id.used_method("federated"));
        assert!(id.has_acr("urn:oresoftware:loa:1"));
        let back = serde_json::to_value(&id).unwrap();
        assert_eq!(back["authority"], "shared-auth");
    }

    #[test]
    fn sandboxed_identity_is_recognized_and_carries_no_authority() {
        let raw = include_str!("../../../fixtures/identity_sandboxed.json");
        let id: Identity = serde_json::from_str(raw).unwrap();
        assert_eq!(id.cred.as_deref(), Some("ssh_key"));
        assert!(id.is_sandboxed());
        assert!(id.roles.is_empty(), "a sandboxed identity carries no roles");
        assert!(id.email.is_none());
        assert!(id.used_method("ssh_key"));
        assert!(id.has_acr("urn:oresoftware:loa:1"));
        assert!(!id.has_acr("urn:oresoftware:loa:2"));
        // Fail-closed: an unrecognized future class is still sandboxed.
        let mut future = id.clone();
        future.cred = Some("mtls".to_owned());
        assert!(future.is_sandboxed());
    }

    #[test]
    fn interactive_identity_is_not_sandboxed() {
        let raw = include_str!("../../../fixtures/identity.json");
        let id: Identity = serde_json::from_str(raw).unwrap();
        assert!(id.cred.is_none());
        assert!(!id.is_sandboxed());
    }

    #[test]
    fn legacy_identity_defaults_assurance_fields() {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/identity.json")).unwrap();
        value.as_object_mut().unwrap().remove("amr");
        value.as_object_mut().unwrap().remove("acr");
        let id: Identity = serde_json::from_value(value).unwrap();
        assert!(id.amr.is_empty());
        assert!(id.acr.is_none());
        assert!(!id.has_acr("urn:oresoftware:loa:2"));
    }

    #[test]
    fn outcome_variants_parse() {
        let raw = include_str!("../../../fixtures/outcomes.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let auth: AuthOutcome = serde_json::from_value(v["authenticated"].clone()).unwrap();
        assert!(auth.is_authenticated());
        assert_eq!(auth.identity().unwrap().authority, Authority::Supabase);

        let anon: AuthOutcome = serde_json::from_value(v["anonymous"].clone()).unwrap();
        assert_eq!(anon, AuthOutcome::Anonymous);
        let un: AuthOutcome = serde_json::from_value(v["unauthenticated"].clone()).unwrap();
        assert_eq!(un, AuthOutcome::Unauthenticated);
        let deg: AuthOutcome = serde_json::from_value(v["degraded"].clone()).unwrap();
        assert!(matches!(deg, AuthOutcome::Degraded { .. }));
    }
}
