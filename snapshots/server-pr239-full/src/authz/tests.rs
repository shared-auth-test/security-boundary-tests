//! Unit tests for the identity-plane authorization model.
//!
//! These pin down the five least-privilege rules from the module documentation.
//! Each rule has at least one test whose failure would be a real privilege
//! escalation, not a style regression.

use chrono::{DateTime, FixedOffset, TimeDelta, Utc};

use super::*;

fn now() -> DateTime<FixedOffset> {
    Utc::now().fixed_offset()
}

fn permission(name: &str) -> Permission {
    Permission::parse(name).expect("catalog permission should parse")
}

fn interactive(acr_level: u8, auth_age: Option<TimeDelta>) -> AuthenticationContext {
    AuthenticationContext {
        acr: Some(
            if acr_level >= 2 { crate::token::ACR_LOA2 } else { crate::token::ACR_LOA1 }
                .to_string(),
        ),
        auth_time: auth_age.map(|age| now() - age),
        cred: None,
    }
}

fn sandboxed() -> AuthenticationContext {
    AuthenticationContext {
        acr: Some(crate::token::ACR_LOA1.to_string()),
        auth_time: None,
        cred: Some("ssh_key".to_string()),
    }
}

fn grant(role: &str, scope: ResourceScope) -> RoleGrant {
    RoleGrant {
        grant_id: Uuid::new_v4(),
        role: role.to_string(),
        scope,
        granted_at: now() - TimeDelta::hours(1),
        expires_at: None,
    }
}

fn principal(
    grants: Vec<RoleGrant>,
    authentication: AuthenticationContext,
) -> PrincipalAuthorization {
    PrincipalAuthorization { shared_user_id: Uuid::new_v4(), grants, authentication }
}

fn decide(
    principal: &PrincipalAuthorization,
    name: &str,
    scope: ResourceScope,
) -> Decision {
    let permission = permission(name);
    authorize(principal, &AccessRequest { permission: &permission, scope }, now())
}

// --- rule 1: deny by default -------------------------------------------------

#[test]
fn a_principal_with_no_grants_is_denied() {
    let subject = principal(Vec::new(), interactive(1, None));
    assert_eq!(
        decide(&subject, "directory.users.read", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::NoGrant }
    );
}

#[test]
fn an_unknown_role_confers_nothing() {
    let subject = principal(
        vec![grant("role_from_a_newer_deployment", ResourceScope::Global)],
        interactive(2, Some(TimeDelta::minutes(1))),
    );
    assert!(!decide(&subject, "directory.users.read", ResourceScope::Global).is_permitted());
    assert!(permissions_for_role("role_from_a_newer_deployment").is_empty());
}

#[test]
fn an_expired_grant_confers_nothing() {
    let mut expired = grant("directory_auditor", ResourceScope::Global);
    expired.granted_at = now() - TimeDelta::hours(4);
    expired.expires_at = Some(now() - TimeDelta::hours(1));
    let subject = principal(vec![expired], interactive(1, None));
    assert_eq!(
        decide(&subject, "directory.users.read", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::NoGrant }
    );
}

// --- rule 2: no implication, no wildcards ------------------------------------

#[test]
fn a_read_permission_never_implies_its_write_neighbour() {
    let subject = principal(
        vec![grant("scim_provisioner", ResourceScope::Global)],
        interactive(1, None),
    );
    assert!(decide(&subject, "provisioning.users.read", ResourceScope::Global).is_permitted());

    // The auditor role holds only reads. If prefix matching ever crept into the
    // membership test, this would start permitting.
    let auditor = principal(
        vec![grant("directory_auditor", ResourceScope::Global)],
        interactive(2, Some(TimeDelta::minutes(1))),
    );
    assert!(!decide(&auditor, "directory.grants.issue", ResourceScope::Global).is_permitted());
}

#[test]
fn wildcards_are_rejected_by_name() {
    assert_eq!(Permission::parse("directory.*"), Err(PermissionParseError::Wildcard));
    assert_eq!(Permission::parse("directory.users.*"), Err(PermissionParseError::Wildcard));
}

#[test]
fn a_product_permission_cannot_enter_an_identity_plane_decision() {
    // The whole point of the domain allow-list: Quaestor's billing vocabulary
    // belongs in Quaestor's database and must not be decidable here.
    assert_eq!(
        Permission::parse("quaestor.billing.write"),
        Err(PermissionParseError::ForeignDomain)
    );
}

#[test]
fn malformed_permissions_are_rejected() {
    assert_eq!(Permission::parse("directory.users"), Err(PermissionParseError::Shape));
    assert_eq!(
        Permission::parse("directory.users.read.extra"),
        Err(PermissionParseError::Shape)
    );
    assert_eq!(Permission::parse("directory..read"), Err(PermissionParseError::Segment));
    assert_eq!(Permission::parse("Directory.users.read"), Err(PermissionParseError::Segment));
}

// --- rule 3: scope narrows, never widens -------------------------------------

#[test]
fn scope_coverage_is_asymmetric() {
    let organization = Uuid::new_v4();
    let project = Uuid::new_v4();
    let global = ResourceScope::Global;
    let org_scope = ResourceScope::Organization { organization_id: organization };
    let project_scope =
        ResourceScope::Project { organization_id: organization, project_id: project };

    assert!(global.covers(&org_scope));
    assert!(global.covers(&project_scope));
    assert!(org_scope.covers(&project_scope));

    // The direction that must never hold.
    assert!(!org_scope.covers(&global));
    assert!(!project_scope.covers(&global));
    assert!(!project_scope.covers(&org_scope));
}

#[test]
fn an_organization_admin_cannot_act_on_another_organization() {
    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    let subject = principal(
        vec![grant("directory_auditor", ResourceScope::Organization { organization_id: mine })],
        interactive(1, None),
    );

    assert!(decide(
        &subject,
        "directory.users.read",
        ResourceScope::Organization { organization_id: mine }
    )
    .is_permitted());

    assert_eq!(
        decide(
            &subject,
            "directory.users.read",
            ResourceScope::Organization { organization_id: theirs }
        ),
        Decision::Deny { reason: DenyReason::ScopeTooNarrow }
    );
}

#[test]
fn an_organization_grant_does_not_authorize_a_global_action() {
    let subject = principal(
        vec![grant(
            "directory_auditor",
            ResourceScope::Organization { organization_id: Uuid::new_v4() },
        )],
        interactive(1, None),
    );
    assert_eq!(
        decide(&subject, "directory.users.read", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::ScopeTooNarrow }
    );
}

// --- rule 4: sandboxed identities hold no administrative authority -----------

#[test]
fn a_sandboxed_identity_is_refused_administrative_permissions_despite_its_grants() {
    let subject = principal(
        vec![grant("directory_security_operator", ResourceScope::Global)],
        sandboxed(),
    );
    assert_eq!(
        decide(&subject, "directory.revocations.execute", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::SandboxedIdentity }
    );
}

#[test]
fn an_unrecognized_credential_class_still_counts_as_sandboxed() {
    // SPEC.md §1.2: the class list will grow, and a consumer must never treat a
    // new class as full authority merely because it has not been taught the name.
    let future_class = AuthenticationContext {
        acr: Some(crate::token::ACR_LOA2.to_string()),
        auth_time: Some(now()),
        cred: Some("workload_oidc_from_a_future_build".to_string()),
    };
    let subject =
        principal(vec![grant("federation_admin", ResourceScope::Global)], future_class);
    assert_eq!(
        decide(&subject, "federation.certificates.rotate", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::SandboxedIdentity }
    );
}

#[test]
fn a_sandboxed_identity_may_still_read() {
    let subject =
        principal(vec![grant("scim_provisioner", ResourceScope::Global)], sandboxed());
    assert!(decide(&subject, "provisioning.users.read", ResourceScope::Global).is_permitted());
}

#[test]
fn an_unknown_permission_is_treated_as_administrative() {
    // A permission this build has not been taught must not be the one a
    // sandboxed identity is allowed to hold.
    let unknown = Permission::parse("session.sessions.terminate")
        .expect("shape is valid even though it is not in the catalog");
    assert_eq!(unknown.sensitivity(), PermissionSensitivity::Administrative);
    assert!(!sandboxed_identity_may_hold(&unknown));
}

// --- rule 5: assurance floors ------------------------------------------------

#[test]
fn an_administrative_permission_requires_a_fresh_step_up() {
    let scope = ResourceScope::Global;
    let grants = || vec![grant("directory_admin", scope)];

    // AAL1 is refused.
    let base = principal(grants(), interactive(1, Some(TimeDelta::minutes(1))));
    assert_eq!(
        decide(&base, "directory.grants.issue", scope),
        Decision::Deny { reason: DenyReason::AssuranceFloor }
    );

    // AAL2 but stale is refused.
    let stale = principal(grants(), interactive(2, Some(TimeDelta::hours(3))));
    assert_eq!(
        decide(&stale, "directory.grants.issue", scope),
        Decision::Deny { reason: DenyReason::AssuranceFloor }
    );

    // AAL2 and fresh is permitted.
    let fresh = principal(grants(), interactive(2, Some(TimeDelta::minutes(2))));
    assert!(decide(&fresh, "directory.grants.issue", scope).is_permitted());
}

#[test]
fn a_legacy_token_without_acr_never_satisfies_a_floor() {
    let legacy = AuthenticationContext { acr: None, auth_time: Some(now()), cred: None };
    let subject = principal(vec![grant("directory_admin", ResourceScope::Global)], legacy);
    assert_eq!(
        decide(&subject, "directory.grants.issue", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::AssuranceFloor }
    );
}

#[test]
fn an_auth_time_in_the_future_is_not_freshness() {
    let skewed = AuthenticationContext {
        acr: Some(crate::token::ACR_LOA2.to_string()),
        auth_time: Some(now() + TimeDelta::hours(2)),
        cred: None,
    };
    let subject = principal(vec![grant("directory_admin", ResourceScope::Global)], skewed);
    assert_eq!(
        decide(&subject, "directory.grants.issue", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::AssuranceFloor }
    );
}

// --- fail closed on malformed authority --------------------------------------

#[test]
fn one_malformed_grant_fails_the_whole_evaluation() {
    let mut corrupt = grant("directory_auditor", ResourceScope::Global);
    corrupt.grant_id = Uuid::nil();
    let good = grant("directory_auditor", ResourceScope::Global);

    // The good grant alone would permit this. It must not, because the ledger
    // that produced both rows cannot be trusted.
    let subject = principal(vec![good, corrupt], interactive(1, None));
    assert!(matches!(
        decide(&subject, "directory.users.read", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::MalformedAuthority { .. } }
    ));
}

#[test]
fn a_grant_that_expires_before_it_was_issued_is_malformed() {
    let mut backwards = grant("directory_auditor", ResourceScope::Global);
    backwards.expires_at = Some(backwards.granted_at - TimeDelta::minutes(5));
    let subject = principal(vec![backwards], interactive(1, None));
    assert!(matches!(
        decide(&subject, "directory.users.read", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::MalformedAuthority { .. } }
    ));
}

#[test]
fn a_nil_organization_in_a_scoped_grant_is_malformed() {
    let subject = principal(
        vec![grant("directory_auditor", ResourceScope::Organization { organization_id: Uuid::nil() })],
        interactive(1, None),
    );
    assert!(matches!(
        decide(&subject, "directory.users.read", ResourceScope::Global),
        Decision::Deny { reason: DenyReason::MalformedAuthority { .. } }
    ));
}

// --- delegation is an intersection -------------------------------------------

#[test]
fn delegated_scopes_are_an_intersection_and_never_widen() {
    let requested: BTreeSet<String> =
        ["a:read", "a:write", "b:read"].iter().map(|s| s.to_string()).collect();
    let client: BTreeSet<String> =
        ["a:read", "a:write"].iter().map(|s| s.to_string()).collect();
    let consented: BTreeSet<String> = ["a:read", "b:read"].iter().map(|s| s.to_string()).collect();

    let effective = effective_delegated_scopes(&requested, &client, &consented);

    // Only the scope present in all three survives.
    assert_eq!(effective, ["a:read"].iter().map(|s| s.to_string()).collect());
    // And nothing the client was registered for but did not request leaks in.
    assert!(!effective.contains("a:write"));
}

#[test]
fn an_empty_consent_yields_no_scopes_rather_than_a_default() {
    let requested: BTreeSet<String> = ["a:read"].iter().map(|s| s.to_string()).collect();
    let client: BTreeSet<String> = ["a:read"].iter().map(|s| s.to_string()).collect();
    let effective = effective_delegated_scopes(&requested, &client, &BTreeSet::new());
    assert!(effective.is_empty());
}

// --- catalog integrity -------------------------------------------------------

#[test]
fn every_catalogued_permission_parses_and_every_role_permission_is_catalogued() {
    let known = known_permissions();
    assert_eq!(known.len(), PERMISSION_CATALOG.len(), "a catalog entry failed to parse");

    for (role, names) in ROLE_DEFINITIONS {
        for name in names {
            let permission = Permission::parse(name)
                .unwrap_or_else(|error| panic!("role {role} lists unparseable {name}: {error}"));
            assert!(
                known.contains(&permission),
                "role {role} grants {name}, which is not in the permission catalog"
            );
        }
    }
}

#[test]
fn no_role_grants_an_administrative_permission_without_a_step_up_floor() {
    for (role, names) in ROLE_DEFINITIONS {
        for name in names {
            let Ok(permission) = Permission::parse(name) else {
                continue;
            };
            if permission.sensitivity() == PermissionSensitivity::Administrative {
                assert!(
                    assurance_floor(&permission).require_step_up,
                    "role {role} grants administrative {name} with no step-up floor"
                );
            }
        }
    }
}

#[test]
fn the_provisioning_role_holds_no_administrative_permission() {
    // The SCIM escalation path: an IdP that can create users must not be able
    // to make one of them an administrator.
    for permission in permissions_for_role("scim_provisioner") {
        assert_ne!(
            permission.sensitivity(),
            PermissionSensitivity::Administrative,
            "scim_provisioner must not hold administrative {permission}"
        );
    }
}
