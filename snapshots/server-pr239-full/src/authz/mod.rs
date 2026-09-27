//! The identity-plane authorization model: roles, permissions, resource scope,
//! and a deny-by-default evaluator.
//!
//! # What this does and does not decide
//!
//! Shared Auth establishes *identity* and *authentication assurance*. Product
//! services authorize access to their own tenants and resources. That boundary
//! is stated in `docs/downstream-authorization-contract.md` and this module
//! does not move it. What it adds is a first-class model for the authorization
//! Shared Auth genuinely owns — its **own** administrative plane:
//!
//! * who may read the directory, terminate sessions, or commit a global
//!   revocation;
//! * what a SCIM provisioning credential may change;
//! * which SAML registration a caller may rotate certificates for;
//! * which scopes a delegated OAuth token may carry.
//!
//! Before this module those decisions were made by comparing role strings at
//! each call site. `shared_auth.roles` stores a flat `role_name` per principal,
//! `DirectoryAdminGrant` carries a parallel scope list, and the token's `roles`
//! claim is a third representation. Three vocabularies that must agree, with
//! nothing making them agree. This is the one evaluator they route through.
//!
//! A product role — `quaestor:tenant:<uuid>`, `quaestor:billing:write` — is
//! **not** modelled here and must not be. It is an authorization input owned by
//! that product's database. [`Permission::parse`] rejects any domain outside
//! [`IDENTITY_PLANE_DOMAINS`] precisely so a product permission cannot be
//! smuggled into an identity-plane decision.
//!
//! # The five least-privilege rules
//!
//! 1. **Deny by default.** The absence of an explicit permit is a deny. There
//!    is no ambient authority, no "admin bypasses everything", and no code path
//!    that returns [`Decision::Permit`] without naming the grant that produced
//!    it.
//!
//! 2. **Permissions are opaque leaves — no implication, no wildcards.**
//!    `directory.users.read` does not imply `directory.users.write`, and
//!    `directory.*` does not exist. Hierarchy is the mechanism by which a
//!    permission set silently grows when someone adds a new action under an
//!    existing prefix; every action must be granted by name.
//!
//! 3. **Scope narrows, never widens.** An organization-scoped grant cannot
//!    authorize a global action, and a project-scoped grant cannot authorize an
//!    organization-wide one. [`ResourceScope::covers`] is deliberately not
//!    symmetric, and the direction is asserted by tests.
//!
//! 4. **A sandboxed identity holds no identity-plane administrative authority.**
//!    Any non-null `cred` — *including a class this build does not recognize* —
//!    marks the identity as proven only by possession of a registered
//!    credential (`SPEC.md` §1.2). Such an identity is refused every permission
//!    marked [`PermissionSensitivity::Administrative`], before grants are even
//!    consulted. An SSH key on a CI runner authenticates a human acting
//!    non-interactively; it is not that human's admin console.
//!
//! 5. **Assurance floors are enforced here, not left to the caller.** A
//!    permission may require AAL2 and a maximum `auth_time` age. A missing or
//!    unrecognized `acr` never satisfies a floor.
//!
//! # Fail closed on malformed authority
//!
//! A grant row that violates its own invariants fails the **entire** evaluation
//! rather than being skipped. This mirrors [`crate::directory_grants`]: quietly
//! omitting one corrupt grant from a set turns a data-integrity problem into a
//! silently different — and possibly *broader* — decision, because the
//! remaining grants still evaluate. If the authority ledger cannot be trusted,
//! no answer from it can be.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, FixedOffset, TimeDelta};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(test)]
mod tests;

/// Permission domains this evaluator will decide. Anything else — a product's
/// `quaestor:` vocabulary above all — is rejected at parse time, so a product
/// permission can never reach an identity-plane decision even by accident.
pub const IDENTITY_PLANE_DOMAINS: [&str; 5] =
    ["directory", "provisioning", "federation", "credential", "session"];

/// How dangerous a permission is, which decides whether a sandboxed identity
/// may ever hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionSensitivity {
    /// Reading data the principal is already entitled to see. A sandboxed
    /// identity may hold this if a grant says so.
    Read,
    /// Changing state within an already-authorized scope — provisioning a user,
    /// updating a group. Available to a sandboxed identity only when a grant
    /// explicitly says so.
    Write,
    /// Changing who may do what, or destroying authentication state: issuing
    /// grants, committing revocations, rotating federation trust. **Never**
    /// available to a sandboxed identity, whatever its grants say.
    Administrative,
}

/// One permission: `<domain>.<resource>.<action>`.
///
/// Stored as three parts rather than a string so a comparison cannot
/// accidentally become a prefix match. `PartialEq` is the only membership test
/// in this module, and it is exact.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Permission {
    domain: String,
    resource: String,
    action: String,
}

impl Permission {
    /// Parse and validate. Rejects unknown domains, wildcards, empty segments,
    /// and anything outside `[a-z0-9_-]`.
    ///
    /// Wildcards are rejected explicitly rather than merely failing the
    /// character class, so the error is legible when someone reaches for the
    /// `directory.*` that this model deliberately does not have.
    pub fn parse(value: &str) -> Result<Self, PermissionParseError> {
        if value.len() > 191 {
            return Err(PermissionParseError::TooLong);
        }
        if value.contains('*') {
            return Err(PermissionParseError::Wildcard);
        }
        let mut parts = value.split('.');
        let (Some(domain), Some(resource), Some(action), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PermissionParseError::Shape);
        };
        for segment in [domain, resource, action] {
            if segment.is_empty()
                || segment.len() > 63
                || !segment.starts_with(|ch: char| ch.is_ascii_lowercase())
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
            {
                return Err(PermissionParseError::Segment);
            }
        }
        if !IDENTITY_PLANE_DOMAINS.contains(&domain) {
            return Err(PermissionParseError::ForeignDomain);
        }
        Ok(Self {
            domain: domain.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Sensitivity is a property of the permission itself, taken from the
    /// catalog. An unknown permission is treated as `Administrative`: a
    /// permission this build has not been taught about must not be the one that
    /// a sandboxed identity is allowed to hold.
    pub fn sensitivity(&self) -> PermissionSensitivity {
        catalog()
            .get(self)
            .copied()
            .unwrap_or(PermissionSensitivity::Administrative)
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.domain, self.resource, self.action)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionParseError {
    /// Not exactly three dot-separated segments.
    Shape,
    /// A segment was empty, too long, or used characters outside `[a-z0-9_-]`.
    Segment,
    /// Contained `*`. This model has no wildcards; see rule 2.
    Wildcard,
    /// A domain outside `IDENTITY_PLANE_DOMAINS` — most likely a product
    /// permission, which belongs in that product's database.
    ForeignDomain,
    TooLong,
}

impl fmt::Display for PermissionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Shape => "expected <domain>.<resource>.<action>",
            Self::Segment => "segment must match [a-z][a-z0-9_-]{0,62}",
            Self::Wildcard => "wildcards are not part of the authorization model",
            Self::ForeignDomain => "not an identity-plane domain",
            Self::TooLong => "permission is too long",
        };
        formatter.write_str(text)
    }
}

/// Where a permission applies.
///
/// Ordering matters and is deliberately asymmetric: a broader scope covers a
/// narrower one, never the reverse. `Global` is not a wildcard the way
/// `directory.*` would be — it is a distinct, separately granted scope that a
/// grant must name explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ResourceScope {
    /// The whole Shared Auth deployment. Granted rarely and audited loudly.
    Global,
    /// One organization.
    Organization { organization_id: Uuid },
    /// One project inside one organization.
    Project { organization_id: Uuid, project_id: Uuid },
}

impl ResourceScope {
    /// Whether a grant at `self` authorizes an action requested at `requested`.
    ///
    /// The asymmetry is the point. A global grant covers an organization
    /// request; an organization grant does **not** cover a global request, even
    /// though the organization is "inside" the deployment. A caller asking to
    /// act globally is asking to act on organizations it was never granted, so
    /// the only safe answer from an organization-scoped grant is no.
    pub fn covers(&self, requested: &ResourceScope) -> bool {
        match (self, requested) {
            (Self::Global, _) => true,
            (Self::Organization { .. }, Self::Global) => false,
            (
                Self::Organization { organization_id: granted },
                Self::Organization { organization_id: wanted },
            ) => granted == wanted,
            (
                Self::Organization { organization_id: granted },
                Self::Project { organization_id: wanted, .. },
            ) => granted == wanted,
            (Self::Project { .. }, Self::Global | Self::Organization { .. }) => false,
            (
                Self::Project { organization_id: granted_org, project_id: granted_project },
                Self::Project { organization_id: wanted_org, project_id: wanted_project },
            ) => granted_org == wanted_org && granted_project == wanted_project,
        }
    }
}

/// Assurance a permission demands before it may be exercised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssuranceFloor {
    /// Require `acr == urn:oresoftware:loa:2`.
    pub require_step_up: bool,
    /// Maximum age of `auth_time`, when a step-up is required. `None` means any
    /// AAL2 token is acceptable, which is almost never what a destructive
    /// operation wants — a refreshed session returns to AAL1, but a long-lived
    /// AAL2 token does not become fresh again on its own.
    pub max_auth_age: Option<TimeDelta>,
}

impl AssuranceFloor {
    pub const NONE: Self = Self { require_step_up: false, max_auth_age: None };

    pub fn fresh_step_up(max_age: TimeDelta) -> Self {
        Self { require_step_up: true, max_auth_age: Some(max_age) }
    }
}

/// The authentication facts an authorization decision is allowed to read.
///
/// This is deliberately a small, owned struct rather than the token or the
/// `Identity`: an evaluator that could see the whole token would eventually
/// grow a rule that reads `email` or `provider_tenant`, and provider tenancy is
/// not an authorization source.
#[derive(Clone, Debug)]
pub struct AuthenticationContext {
    /// `acr` from the verified token. `None` on legacy tokens, which therefore
    /// never satisfy a step-up floor.
    pub acr: Option<String>,
    /// `auth_time` from the verified token.
    pub auth_time: Option<DateTime<FixedOffset>>,
    /// `cred` from the verified token. Any non-null value — including one this
    /// build does not recognize — marks the identity sandboxed. See rule 4.
    pub cred: Option<String>,
}

impl AuthenticationContext {
    /// Fail closed: any non-null `cred` counts, recognized or not.
    pub fn is_sandboxed(&self) -> bool {
        self.cred.is_some()
    }

    fn satisfies(&self, floor: &AssuranceFloor, now: DateTime<FixedOffset>) -> bool {
        if !floor.require_step_up {
            return true;
        }
        if self.acr.as_deref() != Some(crate::token::ACR_LOA2) {
            return false;
        }
        let Some(max_age) = floor.max_auth_age else {
            return true;
        };
        let Some(auth_time) = self.auth_time else {
            return false;
        };
        // A future auth_time beyond ordinary clock skew is not "very fresh"; it
        // is a clock problem or a forged claim, and either way it must not
        // satisfy a freshness requirement.
        if auth_time > now + TimeDelta::seconds(30) {
            return false;
        }
        now - auth_time <= max_age
    }
}

/// One role assignment loaded from the authority ledger.
#[derive(Clone, Debug)]
pub struct RoleGrant {
    pub grant_id: Uuid,
    pub role: String,
    pub scope: ResourceScope,
    pub granted_at: DateTime<FixedOffset>,
    pub expires_at: Option<DateTime<FixedOffset>>,
}

impl RoleGrant {
    /// Recheck invariants at the trust boundary, exactly as
    /// [`crate::directory_grants::DirectoryAdminGrant::validate`] does. A row
    /// that fails this is not skipped — it fails the whole evaluation.
    fn is_structurally_valid(&self, now: DateTime<FixedOffset>) -> bool {
        if self.grant_id.is_nil() || !valid_role_name(&self.role) {
            return false;
        }
        if self.granted_at > now + TimeDelta::seconds(30) {
            return false;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.granted_at {
                return false;
            }
        }
        match self.scope {
            ResourceScope::Global => true,
            ResourceScope::Organization { organization_id } => !organization_id.is_nil(),
            ResourceScope::Project { organization_id, project_id } => {
                !organization_id.is_nil() && !project_id.is_nil()
            }
        }
    }

    fn is_active(&self, now: DateTime<FixedOffset>) -> bool {
        self.expires_at.is_unexpired(now)
    }
}

/// Small helper so the expiry test reads the same way everywhere: `None` means
/// a grant that never expires, which is unexpired.
trait ExpiryExt {
    fn is_unexpired(&self, now: DateTime<FixedOffset>) -> bool;
}

impl ExpiryExt for Option<DateTime<FixedOffset>> {
    fn is_unexpired(&self, now: DateTime<FixedOffset>) -> bool {
        match self {
            None => true,
            Some(expires_at) => *expires_at > now,
        }
    }
}

fn valid_role_name(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 64
        && role.starts_with(|ch: char| ch.is_ascii_lowercase())
        && role
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
}

/// The permission catalog: every identity-plane permission this build knows,
/// with its sensitivity and its assurance floor.
///
/// It is a static table rather than a database read on purpose. A permission's
/// *sensitivity* is a property of the code that implements it — whether the
/// handler can destroy authentication state — not a configurable fact. Making
/// it configurable would mean a database write could downgrade
/// `directory.revocations.execute` to `Read` and hand it to a sandboxed CI key.
/// Which *principals* hold which roles is data; what a permission *is* is code.
const PERMISSION_CATALOG: [(&str, PermissionSensitivity, bool); 16] = [
    ("directory.dashboard.read", PermissionSensitivity::Read, false),
    ("directory.users.read", PermissionSensitivity::Read, false),
    ("directory.sessions.read", PermissionSensitivity::Read, false),
    ("directory.roles.read", PermissionSensitivity::Read, false),
    ("directory.revocations.read", PermissionSensitivity::Read, false),
    // Terminates every session for a principal. Destructive, irreversible for
    // the user's in-flight requests, and the classic target of a stolen admin
    // session — hence administrative and step-up gated.
    ("directory.revocations.execute", PermissionSensitivity::Administrative, true),
    // Issuing or revoking a grant changes who may do what. Anything that edits
    // the authority ledger itself is administrative by definition.
    ("directory.grants.issue", PermissionSensitivity::Administrative, true),
    ("directory.grants.revoke", PermissionSensitivity::Administrative, true),
    ("provisioning.users.read", PermissionSensitivity::Read, false),
    ("provisioning.users.write", PermissionSensitivity::Write, false),
    ("provisioning.groups.read", PermissionSensitivity::Read, false),
    ("provisioning.groups.write", PermissionSensitivity::Write, false),
    ("federation.registrations.read", PermissionSensitivity::Read, false),
    // Rotating an IdP signing certificate decides which assertions this server
    // will believe. It is the single highest-value write in the federation
    // plane: an attacker who lands their own certificate here authenticates as
    // anyone in the tenant.
    ("federation.certificates.rotate", PermissionSensitivity::Administrative, true),
    ("credential.factors.read", PermissionSensitivity::Read, false),
    ("credential.factors.revoke", PermissionSensitivity::Administrative, true),
];

/// Role definitions. A role is a *named set of permissions*, nothing more — it
/// carries no scope of its own (scope comes from the grant) and no implicit
/// authority over other roles.
///
/// There is no role hierarchy. `directory_admin` does not "contain"
/// `directory_auditor`; it lists the permissions it needs. Inheritance is how a
/// role quietly acquires a permission that someone added to its parent, and the
/// reviewer of that change never sees the role that grew.
const ROLE_DEFINITIONS: [(&str, &[&str]); 5] = [
    (
        "directory_admin",
        &[
            "directory.dashboard.read",
            "directory.users.read",
            "directory.sessions.read",
            "directory.roles.read",
            "directory.revocations.read",
            "directory.grants.issue",
            "directory.grants.revoke",
        ],
    ),
    (
        "directory_security_operator",
        &[
            "directory.dashboard.read",
            "directory.users.read",
            "directory.sessions.read",
            "directory.revocations.read",
            "directory.revocations.execute",
            "credential.factors.read",
            "credential.factors.revoke",
        ],
    ),
    (
        "directory_auditor",
        &[
            "directory.dashboard.read",
            "directory.users.read",
            "directory.sessions.read",
            "directory.roles.read",
            "directory.revocations.read",
        ],
    ),
    // The role a SCIM tenant credential runs as. Note what is absent: no
    // `directory.grants.*`, no `directory.revocations.execute`, no
    // `credential.*`. An IdP that can create users must not thereby be able to
    // make one of them an administrator — that is the escalation path every
    // SCIM integration invites.
    (
        "scim_provisioner",
        &[
            "provisioning.users.read",
            "provisioning.users.write",
            "provisioning.groups.read",
            "provisioning.groups.write",
        ],
    ),
    (
        "federation_admin",
        &["federation.registrations.read", "federation.certificates.rotate"],
    ),
];

struct Catalog {
    sensitivity: BTreeMap<Permission, PermissionSensitivity>,
    floors: BTreeMap<Permission, AssuranceFloor>,
    roles: BTreeMap<String, BTreeSet<Permission>>,
}

/// Default freshness for a step-up-gated administrative permission. Chosen to
/// be short enough that a walked-away-from console is not still administrative,
/// long enough that a multi-step operation does not re-prompt mid-flow.
const ADMINISTRATIVE_MAX_AUTH_AGE_SECS: i64 = 900;

fn catalog_inner() -> &'static Catalog {
    static CATALOG: std::sync::OnceLock<Catalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut sensitivity = BTreeMap::new();
        let mut floors = BTreeMap::new();
        for (name, level, step_up) in PERMISSION_CATALOG {
            // A malformed catalog entry is a build-time authoring error, not a
            // runtime condition. Skipping it rather than panicking keeps a
            // typo from taking the process down; the permission simply does not
            // exist, and every request for it is denied — the safe direction.
            let Ok(permission) = Permission::parse(name) else {
                continue;
            };
            let floor = if step_up {
                AssuranceFloor::fresh_step_up(TimeDelta::seconds(ADMINISTRATIVE_MAX_AUTH_AGE_SECS))
            } else {
                AssuranceFloor::NONE
            };
            floors.insert(permission.clone(), floor);
            sensitivity.insert(permission, level);
        }

        let mut roles = BTreeMap::new();
        for (role, permissions) in ROLE_DEFINITIONS {
            let resolved = permissions
                .iter()
                .filter_map(|name| Permission::parse(name).ok())
                .collect::<BTreeSet<_>>();
            roles.insert(role.to_string(), resolved);
        }

        Catalog { sensitivity, floors, roles }
    })
}

fn catalog() -> &'static BTreeMap<Permission, PermissionSensitivity> {
    &catalog_inner().sensitivity
}

/// The permissions a role confers. An unknown role confers nothing — it is not
/// an error, because a role name may legitimately arrive from an older or newer
/// deployment, but it never contributes authority.
pub fn permissions_for_role(role: &str) -> BTreeSet<Permission> {
    catalog_inner().roles.get(role).cloned().unwrap_or_default()
}

/// The assurance floor for a permission. An unknown permission gets the
/// strictest floor, matching the unknown-permission sensitivity rule.
pub fn assurance_floor(permission: &Permission) -> AssuranceFloor {
    catalog_inner().floors.get(permission).copied().unwrap_or_else(|| {
        AssuranceFloor::fresh_step_up(TimeDelta::seconds(ADMINISTRATIVE_MAX_AUTH_AGE_SECS))
    })
}

/// Every permission this build knows about, for the discovery surfaces that
/// need to advertise the vocabulary (admin UI, `/auth/capabilities`).
pub fn known_permissions() -> Vec<Permission> {
    catalog().keys().cloned().collect()
}

/// A principal's resolved authority at one instant, as loaded from the ledger.
#[derive(Clone, Debug)]
pub struct PrincipalAuthorization {
    pub shared_user_id: Uuid,
    pub grants: Vec<RoleGrant>,
    pub authentication: AuthenticationContext,
}

/// What a caller is asking to do.
#[derive(Clone, Debug)]
pub struct AccessRequest<'a> {
    pub permission: &'a Permission,
    pub scope: ResourceScope,
}

/// Why a request was denied. These are for logs and audit, never for the HTTP
/// body: telling a caller *which* check failed turns the evaluator into an
/// oracle for the shape of the authority ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// No grant conferred the permission at a covering scope.
    NoGrant,
    /// A grant conferred it, but only at a narrower scope than requested.
    ScopeTooNarrow,
    /// The identity is sandboxed and the permission is administrative.
    SandboxedIdentity,
    /// The permission requires a step-up the token does not carry, or carries
    /// too old.
    AssuranceFloor,
    /// The authority ledger contained a grant that violates its own invariants.
    /// The whole evaluation fails; see the module docs.
    MalformedAuthority { grant_id: Uuid },
}

/// The outcome. `Permit` names the grant and role that produced it so the audit
/// record can answer "why was this allowed" without re-deriving the decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Permit { via_grant: Uuid, via_role: String },
    Deny { reason: DenyReason },
}

impl Decision {
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permit { .. })
    }
}

/// Decide one request. Deny by default.
///
/// Evaluation order is chosen so the cheapest and most absolute refusals happen
/// first, and so a malformed ledger can never be masked by an earlier permit:
///
/// 1. structural validation of every grant — a bad row fails the whole call;
/// 2. the sandboxed-identity refusal, which no grant can override;
/// 3. the assurance floor, which no grant can override either;
/// 4. finally, the search for a grant that actually confers the permission at a
///    covering scope.
///
/// Steps 2 and 3 come before step 4 deliberately. If they came after, a
/// sandboxed identity holding an administrative grant would be refused — but a
/// reader of the code would have to hold two conditions in their head to see
/// why, and the next person to add a fast path would put it in the wrong place.
pub fn authorize(
    principal: &PrincipalAuthorization,
    request: &AccessRequest<'_>,
    now: DateTime<FixedOffset>,
) -> Decision {
    for grant in &principal.grants {
        if !grant.is_structurally_valid(now) {
            tracing::error!(
                grant_id = %grant.grant_id,
                "authz: refusing every decision for this principal; the authority ledger holds a malformed grant"
            );
            return Decision::Deny {
                reason: DenyReason::MalformedAuthority { grant_id: grant.grant_id },
            };
        }
    }

    if principal.authentication.is_sandboxed()
        && request.permission.sensitivity() == PermissionSensitivity::Administrative
    {
        return Decision::Deny { reason: DenyReason::SandboxedIdentity };
    }

    let floor = assurance_floor(request.permission);
    if !principal.authentication.satisfies(&floor, now) {
        return Decision::Deny { reason: DenyReason::AssuranceFloor };
    }

    // Track whether any grant conferred the permission at *some* scope, so a
    // scope failure reports as ScopeTooNarrow rather than NoGrant. The two mean
    // different things to an operator reading an audit trail: one is "this
    // person has no business here", the other is "this person is an admin of
    // the wrong organization".
    let mut conferred_somewhere = false;

    for grant in &principal.grants {
        if !grant.is_active(now) {
            continue;
        }
        if !permissions_for_role(&grant.role).contains(request.permission) {
            continue;
        }
        conferred_somewhere = true;
        if grant.scope.covers(&request.scope) {
            return Decision::Permit {
                via_grant: grant.grant_id,
                via_role: grant.role.clone(),
            };
        }
    }

    Decision::Deny {
        reason: if conferred_somewhere { DenyReason::ScopeTooNarrow } else { DenyReason::NoGrant },
    }
}

/// The effective scope set for a delegated token.
///
/// Least privilege for delegation is an intersection, never a union and never a
/// fallback: the client's registered `allowed_scopes`, the user's recorded
/// consent, and what the principal can actually do. Widening at any of the three
/// is the bug — a client that asks for more than it is registered for must get
/// less, not an error that a caller might retry with a broader default.
///
/// The one thing this does *not* do is silently drop an unrequested-but-allowed
/// scope in the other direction: the result is exactly what was requested and
/// permitted, so a caller can compare lengths and refuse if it was narrowed.
pub fn effective_delegated_scopes(
    requested: &BTreeSet<String>,
    client_allowed: &BTreeSet<String>,
    user_consented: &BTreeSet<String>,
) -> BTreeSet<String> {
    requested
        .iter()
        .filter(|scope| client_allowed.contains(*scope) && user_consented.contains(*scope))
        .cloned()
        .collect()
}

/// Whether a sandboxed identity may hold `permission` at all, independent of
/// grants. Exposed so a caller can refuse early — before loading the ledger —
/// and so the rule is testable in isolation.
pub fn sandboxed_identity_may_hold(permission: &Permission) -> bool {
    permission.sensitivity() != PermissionSensitivity::Administrative
}
