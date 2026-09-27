use std::path::Path;

use crate::config::{
    LoadedSharedAuthConfig, ResolvedSharedAuthConfig, SharedAuthConfigError,
    SharedAuthConfigOverlay, SharedAuthDefaults, load_project_config,
};

/// Contract revision admitted by the central policy and runtime consumers.
/// Keep this synchronized with the checked-in central `.shared-auth.toml`.
pub const SHARED_AUTH_INTERFACES_POLICY_REVISION: &str =
    "f62d9dbed2db6774dda04586328e6c485423fff6";

/// The checked-in Shared Auth baseline. It is parsed by the same strict TOML
/// model as every consumer policy; it is not an independently interpreted
/// configuration format.
pub const CENTRAL_SHARED_AUTH_CONFIG_TOML: &str = include_str!("../.shared-auth.toml");

/// Parse and resolve the central policy over the compiled secure fallback.
///
/// Keeping a compiled fallback makes failure behavior conservative, while the
/// checked-in TOML remains executable policy and is validated on every call.
pub fn central_shared_auth_policy() -> Result<ResolvedSharedAuthConfig, SharedAuthConfigError> {
    SharedAuthConfigOverlay::parse_toml(CENTRAL_SHARED_AUTH_CONFIG_TOML)?
        .resolve(SharedAuthDefaults::default())
}

/// Parse the central policy and atomically admit the exact interfaces revision
/// the executable is built or deployed against.
///
/// Startup code should prefer this API over calling [`central_shared_auth_policy`]
/// and [`ResolvedSharedAuthConfig::admits_revision`] separately. Keeping the
/// admission inside the loader prevents a consumer from accidentally using a
/// syntactically valid policy whose contract provenance is stale.
pub fn central_shared_auth_policy_for_revision<F>(
    current_interfaces_revision: &str,
    mut is_ancestor: F,
) -> Result<ResolvedSharedAuthConfig, SharedAuthConfigError>
where
    F: FnMut(&str, &str) -> bool,
{
    let central = central_shared_auth_policy()?;
    central.admits_revision(current_interfaces_revision, |ancestor, descendant| {
        is_ancestor(ancestor, descendant)
    })?;
    Ok(central)
}

/// Resolve just the central values that consumer project overlays may shadow.
pub fn central_shared_auth_defaults() -> Result<SharedAuthDefaults, SharedAuthConfigError> {
    let central = central_shared_auth_policy()?;
    Ok(SharedAuthDefaults {
        factors: central.factors,
        pages: central.pages,
        styling: central.styling,
    })
}

/// Load a consumer project policy over the central Shared Auth baseline.
/// Arrays/sets use the config module's replacement semantics rather than union
/// semantics, so a downstream declaration deterministically shadows the
/// central value instead of accidentally expanding an allow-list.
///
/// This is a parse/resolve primitive. Executable startup should normally use
/// [`load_project_config_with_central_defaults_for_revision`] so both central
/// and project provenance are admitted before policy is returned.
pub fn load_project_config_with_central_defaults(
    root: &Path,
) -> Result<LoadedSharedAuthConfig, SharedAuthConfigError> {
    load_project_config(root, central_shared_auth_defaults()?)
}

/// Load a consumer policy over the central baseline and fail closed unless both
/// policies admit the same current `shared-auth-interfaces` revision.
///
/// The ancestry callback is used only for range-based compatibility. Exact
/// revision policies do not rely on callback behavior. No lexical SHA ordering
/// is used.
pub fn load_project_config_with_central_defaults_for_revision<F>(
    root: &Path,
    current_interfaces_revision: &str,
    mut is_ancestor: F,
) -> Result<LoadedSharedAuthConfig, SharedAuthConfigError>
where
    F: FnMut(&str, &str) -> bool,
{
    let central = central_shared_auth_policy()?;
    central.admits_revision(current_interfaces_revision, |ancestor, descendant| {
        is_ancestor(ancestor, descendant)
    })?;

    let defaults = SharedAuthDefaults {
        factors: central.factors,
        pages: central.pages,
        styling: central.styling,
    };
    let loaded = load_project_config(root, defaults)?;
    loaded.resolved.admits_revision(
        current_interfaces_revision,
        |ancestor, descendant| is_ancestor(ancestor, descendant),
    )?;
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthPage, FactorMethod, Theme, CANONICAL_CONFIG_FILE};
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    const OTHER_REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn test_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shared-auth-central-config-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory should be creatable");
        path
    }

    fn consumer_policy(revision: &str) -> String {
        format!(
            r#"schema_version = 1

[compatibility]
repository = "https://github.com/shared-auth/shared-auth-interfaces"
commit = "{revision}"

[factors.two_factor]
methods = ["passkey"]
"#
        )
    }

    #[test]
    fn checked_in_central_policy_matches_the_secure_baseline() {
        let central = central_shared_auth_policy().expect("central config must remain valid");
        let fallback = SharedAuthDefaults::default();
        assert_eq!(central.factors, fallback.factors);
        assert_eq!(central.pages, fallback.pages);
        assert_eq!(central.styling, fallback.styling);
        assert!(central.factors.two_factor.required);
        assert!(!central.factors.three_factor.enabled);
        assert_eq!(central.styling.theme, Theme::System);
        assert!(central.factors.two_factor.methods.contains(&FactorMethod::Passkey));
        assert!(!central.pages.show.contains(&AuthPage::SignUp));
    }

    #[test]
    fn checked_in_central_policy_matches_the_merged_interfaces_revision() {
        central_shared_auth_policy_for_revision(SHARED_AUTH_INTERFACES_POLICY_REVISION, |_, _| false)
            .expect("merged interfaces revision must be admitted by central policy");
        assert!(central_shared_auth_policy_for_revision(OTHER_REVISION, |_, _| true).is_err());
    }

    #[test]
    fn checked_in_central_policy_is_pinned_to_a_real_interface_contract_sha_shape() {
        let central = central_shared_auth_policy().expect("central config must remain valid");
        central
            .compatibility
            .validate()
            .expect("central compatibility pin must remain valid");
        central
            .admits_revision(SHARED_AUTH_INTERFACES_POLICY_REVISION, |_, _| false)
            .expect("exported policy revision must match checked-in central policy");
    }

    #[test]
    fn project_loader_admits_central_and_project_provenance_atomically() {
        let root = test_dir("admitted");
        fs::write(
            root.join(CANONICAL_CONFIG_FILE),
            consumer_policy(SHARED_AUTH_INTERFACES_POLICY_REVISION),
        )
        .expect("consumer policy should be writable");

        let loaded = load_project_config_with_central_defaults_for_revision(
            &root,
            SHARED_AUTH_INTERFACES_POLICY_REVISION,
            |_, _| false,
        )
        .expect("matching central and project revisions must load");
        assert_eq!(loaded.resolved.factors.two_factor.methods, vec![FactorMethod::Passkey]);

        fs::remove_dir_all(root).expect("test directory should be removable");
    }

    #[test]
    fn project_loader_rejects_project_policy_for_a_different_revision() {
        let root = test_dir("project-stale");
        fs::write(
            root.join(CANONICAL_CONFIG_FILE),
            consumer_policy(OTHER_REVISION),
        )
        .expect("consumer policy should be writable");

        let result = load_project_config_with_central_defaults_for_revision(
            &root,
            SHARED_AUTH_INTERFACES_POLICY_REVISION,
            |_, _| false,
        );
        assert!(result.is_err(), "project provenance must not be optional");

        fs::remove_dir_all(root).expect("test directory should be removable");
    }
}
