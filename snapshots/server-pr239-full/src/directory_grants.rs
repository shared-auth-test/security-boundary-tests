//! Authoritative, tenant-scoped directory administration grants.
//!
//! These records are loaded from Postgres after the caller's token and session
//! have been verified. Provider tenancy, email, flat token roles, and caller-
//! supplied organization lists are never authorization sources.

use std::collections::HashSet;

use chrono::{DateTime, FixedOffset};
use serde::Serialize;
use uuid::Uuid;

pub const DIRECTORY_ADMIN_AUDIENCE: &str = "shared-auth-web-server";
pub const DIRECTORY_ADMIN_CLIENT_ID: &str = "shared-auth-web-server";
pub const DIRECTORY_ADMIN_DELEGATED_SCOPE: &str = "shared-auth:directory:read";
pub const DIRECTORY_ADMIN_ROLE: &str = "directory_admin";
pub const DIRECTORY_GRANT_SCHEMA: &str = "ores.shared-auth-admin-directory-grant-set/v1";

pub const DIRECTORY_SCOPES: [&str; 6] = [
    "directory.dashboard.read",
    "directory.users.read",
    "directory.sessions.read",
    "directory.roles.read",
    "directory.revocations.read",
    "directory.revocations.execute",
];

pub const DIRECTORY_ROLES: [&str; 3] = [
    DIRECTORY_ADMIN_ROLE,
    "directory_security_operator",
    "directory_auditor",
];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryAdminGrant {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_ids: Option<Vec<Uuid>>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub granted_at: DateTime<FixedOffset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<FixedOffset>>,
}

impl DirectoryAdminGrant {
    /// Recheck database invariants at the trust boundary. A malformed row
    /// fails the entire grant set closed instead of being silently omitted.
    pub fn validate(&self, evaluated_at: DateTime<FixedOffset>) -> bool {
        if self.grant_id.is_nil()
            || self.organization_id.is_nil()
            || self.granted_at > evaluated_at + chrono::TimeDelta::seconds(30)
            || self.expires_at.as_ref().is_some_and(|expires_at| {
                *expires_at <= evaluated_at || *expires_at <= self.granted_at
            })
            || !valid_unique_values(&self.scopes, &DIRECTORY_SCOPES)
            || !valid_unique_values(&self.roles, &DIRECTORY_ROLES)
            || !self.roles.iter().any(|role| role == DIRECTORY_ADMIN_ROLE)
        {
            return false;
        }
        match self.project_ids.as_deref() {
            None => true,
            Some([]) => false,
            Some(project_ids) => {
                let mut unique = HashSet::with_capacity(project_ids.len());
                project_ids.len() <= 200
                    && project_ids
                        .iter()
                        .all(|project_id| !project_id.is_nil() && unique.insert(*project_id))
            }
        }
    }
}

fn valid_unique_values(values: &[String], allowed: &[&str]) -> bool {
    if values.is_empty() || values.len() > allowed.len() {
        return false;
    }
    let mut unique = HashSet::with_capacity(values.len());
    values
        .iter()
        .all(|value| allowed.contains(&value.as_str()) && unique.insert(value.as_str()))
}

#[derive(Clone, Debug)]
pub struct StoredDirectoryAdminGrantSet {
    pub principal_ref: Uuid,
    pub grants: Vec<DirectoryAdminGrant>,
}

impl StoredDirectoryAdminGrantSet {
    pub fn validate(&self, evaluated_at: DateTime<FixedOffset>) -> bool {
        if self.principal_ref.is_nil() || self.grants.is_empty() || self.grants.len() > 500 {
            return false;
        }
        let mut grant_ids = HashSet::with_capacity(self.grants.len());
        self.grants
            .iter()
            .all(|grant| grant_ids.insert(grant.grant_id) && grant.validate(evaluated_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> DirectoryAdminGrant {
        DirectoryAdminGrant {
            grant_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            project_ids: None,
            scopes: vec!["directory.dashboard.read".into()],
            roles: vec![DIRECTORY_ADMIN_ROLE.into()],
            granted_at: chrono::Utc::now().fixed_offset(),
            expires_at: None,
        }
    }

    #[test]
    fn grant_requires_tenant_scope_and_directory_admin_role() {
        let now = chrono::Utc::now().fixed_offset();
        assert!(grant().validate(now));
        let mut missing_role = grant();
        missing_role.roles = vec!["directory_auditor".into()];
        assert!(!missing_role.validate(now));
        let mut unknown_scope = grant();
        unknown_scope.scopes = vec!["directory.everything".into()];
        assert!(!unknown_scope.validate(now));
    }

    #[test]
    fn project_scope_is_absent_for_org_wide_or_nonempty_and_unique() {
        let now = chrono::Utc::now().fixed_offset();
        let mut candidate = grant();
        candidate.project_ids = Some(Vec::new());
        assert!(!candidate.validate(now));
        let project = Uuid::new_v4();
        candidate.project_ids = Some(vec![project, project]);
        assert!(!candidate.validate(now));
        candidate.project_ids = Some(vec![project]);
        assert!(candidate.validate(now));
    }
}
