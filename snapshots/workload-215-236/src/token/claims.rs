//! Claims for unified, delegated, sandboxed, and workload OreSoftware JWTs.

use serde::{Deserialize, Serialize};

/// The token this server mints. Human `sub` values are the stable OreSoftware
/// `shared_user_id`; first-class workload subjects use the reserved
/// `workload:<service_account_id>` namespace. Downstream services therefore get
/// one signed identity envelope without confusing machine subjects for humans.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OreClaims {
    /// Stable OreSoftware subject. Human sessions use `shared_user_id`; workload
    /// sessions use the reserved `workload:<service_account_id>` form.
    pub sub: String,
    pub iss: String,
    pub aud: String,
    /// Issued-at / expiry (unix seconds).
    pub iat: u64,
    pub exp: u64,
    pub nbf: u64,
    pub jti: String,
    /// Opaque session id used for revocation checks. Old stateless tokens may
    /// omit it during migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub provider: String,
    pub provider_tenant: String,
    pub provider_subject: String,
    /// Compatibility aliases for current Supabase consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supabase_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub email_verified: bool,
    #[serde(default)]
    pub roles: Vec<String>,
    /// Numeric human authentication assurance level. Human tokens use the AAL
    /// vocabulary derived from `acr`; first-class workload tokens deliberately
    /// set this to 0 so possession of a machine credential cannot be mistaken
    /// for a human authentication ceremony. Missing legacy human claims still
    /// decode as level 1 for rolling compatibility.
    #[serde(default = "default_auth_level")]
    pub aal: u8,
    /// Authentication/credential methods used for this token. Missing legacy
    /// claims decode as an empty list and therefore never satisfy an explicit
    /// method policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    /// Human authentication context. Workload tokens omit this rather than
    /// inventing an AAL/ACR mapping for machine credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Time the human authentication ceremony represented by `aal`/`amr`/`acr`
    /// completed, in unix seconds. Deliberately distinct from `iat`, which is
    /// only token mint time. Workload tokens omit this field.
    ///
    /// Emitted only for human AAL2 tokens. For a local step-up ceremony this is
    /// the ceremony completion time; for an exchanged provider token it is the
    /// newest verified upstream AMR timestamp. Delegation preserves the value
    /// rather than making a token exchange look like a fresh step-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    /// Time of a WebAuthn ceremony verified directly by this server. Workload
    /// tokens never carry this marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn_auth_time: Option<u64>,
    /// Principal epoch captured when the server-side session was created.
    /// Human tokens bind this to the human principal epoch; workload tokens bind
    /// it to the service-account epoch. The workload session separately binds
    /// its OAuth-client credential epoch.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub auth_epoch: u64,
    /// Space-delimited OAuth scopes. Base human identity tokens intentionally
    /// carry no product scopes; delegated and workload tokens carry only a
    /// reviewed allow-listed subset.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// OAuth authorized party. Present on delegated and workload OAuth tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// Parent token identifier. This provides delegation lineage without
    /// embedding or logging the parent bearer token itself. First-class
    /// client-credentials workload tokens have no parent token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_jti: Option<String>,
    /// Credential class for non-interactive proof-of-possession tokens.
    ///
    /// `ssh_key`/Kerberos-style credentials remain on the narrow sandbox plane.
    /// `oauth_client` identifies a first-class workload principal and has its
    /// own service-account/client/session revocation lineage. Both remain
    /// non-human and therefore fail [`Self::is_sandboxed`] checks protecting
    /// human factor/recovery/control-plane operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred: Option<String>,
}

impl OreClaims {
    pub fn has_acr(&self, required: &str) -> bool {
        self.acr.as_deref() == Some(required)
    }

    pub fn used_method(&self, method: &str) -> bool {
        self.amr.iter().any(|candidate| candidate == method)
    }

    pub fn has_scope(&self, required: &str) -> bool {
        self.scope
            .split_ascii_whitespace()
            .any(|candidate| candidate == required)
    }

    pub fn is_delegated(&self) -> bool {
        self.azp.is_some() || self.parent_jti.is_some() || !self.scope.is_empty()
    }

    /// True for any token minted from non-human credential possession rather
    /// than an interactive human ceremony. This remains intentionally broad so
    /// human factor/recovery/control-plane routes fail closed as new machine
    /// credential classes are introduced.
    pub fn is_sandboxed(&self) -> bool {
        self.cred.is_some()
    }

    /// True only for the first-class OAuth workload profile owned by #210.
    ///
    /// Every discriminator must agree. A token cannot opt into workload
    /// revocation merely by presenting `cred=oauth_client`, and an old generic
    /// sandbox token cannot become a service account by choosing the subject
    /// prefix alone.
    pub fn is_workload(&self) -> bool {
        self.cred.as_deref() == Some("oauth_client")
            && self.provider == "shared_auth_workload"
            && self.sub.starts_with("workload:")
            && self.aal == 0
            && self.acr.is_none()
            && self.auth_time.is_none()
            && self.webauthn_auth_time.is_none()
            && self.email.is_none()
            && !self.email_verified
            && self.roles.is_empty()
    }
}

fn default_auth_level() -> u8 {
    1
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}
