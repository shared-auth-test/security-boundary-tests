use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    hash::Hash,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const CANONICAL_CONFIG_FILE: &str = ".shared-auth.toml";
pub const LEGACY_CONFIG_FILE: &str = ".auth-shared.toml";
pub const SHARED_AUTH_INTERFACES_REPOSITORY: &str =
    "https://github.com/shared-auth/shared-auth-interfaces";
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FactorMethod {
    #[serde(rename = "totp")]
    Totp,
    #[serde(rename = "passkey")]
    Passkey,
    #[serde(rename = "security-key")]
    SecurityKey,
    #[serde(rename = "email-otp")]
    EmailOtp,
    #[serde(rename = "sms-otp")]
    SmsOtp,
    #[serde(rename = "backup-code")]
    BackupCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthPage {
    #[serde(rename = "sign-in")]
    SignIn,
    #[serde(rename = "sign-up")]
    SignUp,
    #[serde(rename = "challenge")]
    Challenge,
    #[serde(rename = "recovery")]
    Recovery,
    #[serde(rename = "consent")]
    Consent,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "signed-out")]
    SignedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    #[serde(rename = "system")]
    System,
    #[serde(rename = "light")]
    Light,
    #[serde(rename = "dark")]
    Dark,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRange {
    pub base: String,
    pub head: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactCompatibility {
    pub repository: String,
    pub commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeCompatibility {
    pub repository: String,
    pub range: CommitRange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Compatibility {
    Exact(ExactCompatibility),
    Range(RangeCompatibility),
}

impl Compatibility {
    pub fn validate(&self) -> Result<(), SharedAuthConfigError> {
        match self {
            Self::Exact(value) => {
                validate_repository(&value.repository)?;
                validate_git_sha("compatibility.commit", &value.commit)
            }
            Self::Range(value) => {
                validate_repository(&value.repository)?;
                validate_git_sha("compatibility.range.base", &value.range.base)?;
                validate_git_sha("compatibility.range.head", &value.range.head)
            }
        }
    }

    pub fn admits_revision<F>(
        &self,
        current_revision: &str,
        mut is_ancestor: F,
    ) -> Result<(), SharedAuthConfigError>
    where
        F: FnMut(&str, &str) -> bool,
    {
        validate_git_sha("current_revision", current_revision)?;
        self.validate()?;

        let admitted = match self {
            Self::Exact(value) => value.commit == current_revision,
            Self::Range(value) => {
                is_ancestor(&value.range.base, current_revision)
                    && is_ancestor(current_revision, &value.range.head)
            }
        };

        if admitted {
            Ok(())
        } else {
            Err(SharedAuthConfigError::RevisionNotAdmitted {
                revision: current_revision.to_owned(),
            })
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwoFactorPolicyOverlay {
    pub required: Option<bool>,
    pub methods: Option<Vec<FactorMethod>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreeFactorPolicyOverlay {
    pub enabled: Option<bool>,
    pub methods: Option<Vec<FactorMethod>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorsPolicyOverlay {
    pub two_factor: Option<TwoFactorPolicyOverlay>,
    pub three_factor: Option<ThreeFactorPolicyOverlay>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagesPolicyOverlay {
    pub show: Option<Vec<AuthPage>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StylingPolicyOverlay {
    pub theme: Option<Theme>,
    pub brand_name: Option<String>,
    pub accent_color: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAuthConfigOverlay {
    pub schema_version: u32,
    pub compatibility: Compatibility,
    pub factors: Option<FactorsPolicyOverlay>,
    pub pages: Option<PagesPolicyOverlay>,
    pub styling: Option<StylingPolicyOverlay>,
}

impl SharedAuthConfigOverlay {
    pub fn parse_toml(input: &str) -> Result<Self, SharedAuthConfigError> {
        let parsed: Self = toml::from_str(input)
            .map_err(|source| SharedAuthConfigError::Toml(source.to_string()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), SharedAuthConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(SharedAuthConfigError::UnsupportedSchemaVersion {
                found: self.schema_version,
                expected: CONFIG_SCHEMA_VERSION,
            });
        }
        self.compatibility.validate()?;

        if let Some(factors) = &self.factors {
            if let Some(two_factor) = &factors.two_factor {
                if let Some(methods) = &two_factor.methods {
                    validate_set("factors.two_factor.methods", methods)?;
                }
            }
            if let Some(three_factor) = &factors.three_factor {
                if let Some(methods) = &three_factor.methods {
                    validate_set("factors.three_factor.methods", methods)?;
                }
            }
        }
        if let Some(pages) = &self.pages {
            if let Some(show) = &pages.show {
                validate_set("pages.show", show)?;
            }
        }
        if let Some(styling) = &self.styling {
            if let Some(brand_name) = &styling.brand_name {
                validate_brand_name(brand_name)?;
            }
            if let Some(accent_color) = &styling.accent_color {
                validate_accent_color(accent_color)?;
            }
        }
        Ok(())
    }

    pub fn resolve(
        self,
        mut defaults: SharedAuthDefaults,
    ) -> Result<ResolvedSharedAuthConfig, SharedAuthConfigError> {
        self.validate()?;

        if let Some(factors) = self.factors {
            if let Some(two_factor) = factors.two_factor {
                if let Some(required) = two_factor.required {
                    defaults.factors.two_factor.required = required;
                }
                if let Some(methods) = two_factor.methods {
                    defaults.factors.two_factor.methods = methods;
                }
            }
            if let Some(three_factor) = factors.three_factor {
                if let Some(enabled) = three_factor.enabled {
                    defaults.factors.three_factor.enabled = enabled;
                }
                if let Some(methods) = three_factor.methods {
                    defaults.factors.three_factor.methods = methods;
                }
            }
        }
        if let Some(pages) = self.pages {
            if let Some(show) = pages.show {
                defaults.pages.show = show;
            }
        }
        if let Some(styling) = self.styling {
            if let Some(theme) = styling.theme {
                defaults.styling.theme = theme;
            }
            if let Some(brand_name) = styling.brand_name {
                defaults.styling.brand_name = brand_name;
            }
            if let Some(accent_color) = styling.accent_color {
                defaults.styling.accent_color = accent_color;
            }
        }

        defaults.validate()?;
        Ok(ResolvedSharedAuthConfig {
            schema_version: self.schema_version,
            compatibility: self.compatibility,
            factors: defaults.factors,
            pages: defaults.pages,
            styling: defaults.styling,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoFactorPolicy {
    pub required: bool,
    pub methods: Vec<FactorMethod>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeFactorPolicy {
    pub enabled: bool,
    pub methods: Vec<FactorMethod>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactorsPolicy {
    pub two_factor: TwoFactorPolicy,
    pub three_factor: ThreeFactorPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagesPolicy {
    pub show: Vec<AuthPage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StylingPolicy {
    pub theme: Theme,
    pub brand_name: String,
    pub accent_color: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAuthDefaults {
    pub factors: FactorsPolicy,
    pub pages: PagesPolicy,
    pub styling: StylingPolicy,
}

impl Default for SharedAuthDefaults {
    fn default() -> Self {
        Self {
            factors: FactorsPolicy {
                two_factor: TwoFactorPolicy {
                    required: true,
                    methods: vec![
                        FactorMethod::Totp,
                        FactorMethod::Passkey,
                        FactorMethod::SecurityKey,
                        FactorMethod::BackupCode,
                    ],
                },
                three_factor: ThreeFactorPolicy {
                    enabled: false,
                    methods: vec![
                        FactorMethod::Totp,
                        FactorMethod::Passkey,
                        FactorMethod::SecurityKey,
                    ],
                },
            },
            pages: PagesPolicy {
                show: vec![
                    AuthPage::SignIn,
                    AuthPage::Challenge,
                    AuthPage::Recovery,
                    AuthPage::Error,
                    AuthPage::SignedOut,
                ],
            },
            styling: StylingPolicy {
                theme: Theme::System,
                brand_name: "Shared Auth".to_owned(),
                accent_color: "#4F46E5".to_owned(),
            },
        }
    }
}

impl SharedAuthDefaults {
    pub fn validate(&self) -> Result<(), SharedAuthConfigError> {
        validate_set(
            "defaults.factors.two_factor.methods",
            &self.factors.two_factor.methods,
        )?;
        validate_set(
            "defaults.factors.three_factor.methods",
            &self.factors.three_factor.methods,
        )?;
        validate_set("defaults.pages.show", &self.pages.show)?;
        validate_brand_name(&self.styling.brand_name)?;
        validate_accent_color(&self.styling.accent_color)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSharedAuthConfig {
    pub schema_version: u32,
    pub compatibility: Compatibility,
    pub factors: FactorsPolicy,
    pub pages: PagesPolicy,
    pub styling: StylingPolicy,
}

impl ResolvedSharedAuthConfig {
    pub fn admits_revision<F>(
        &self,
        current_revision: &str,
        is_ancestor: F,
    ) -> Result<(), SharedAuthConfigError>
    where
        F: FnMut(&str, &str) -> bool,
    {
        self.compatibility
            .admits_revision(current_revision, is_ancestor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedSharedAuthConfig {
    pub source_path: PathBuf,
    pub used_legacy_alias: bool,
    pub resolved: ResolvedSharedAuthConfig,
}

pub fn discover_project_config(
    root: &Path,
) -> Result<Option<(PathBuf, bool)>, SharedAuthConfigError> {
    let canonical = root.join(CANONICAL_CONFIG_FILE);
    let legacy = root.join(LEGACY_CONFIG_FILE);
    let canonical_exists = canonical.is_file();
    let legacy_exists = legacy.is_file();

    match (canonical_exists, legacy_exists) {
        (true, true) => Err(SharedAuthConfigError::AmbiguousConfigFiles { canonical, legacy }),
        (true, false) => Ok(Some((canonical, false))),
        (false, true) => Ok(Some((legacy, true))),
        (false, false) => Ok(None),
    }
}

/// Hard ceiling on the ancestor walk, so a runaway search cannot wander the
/// filesystem from a deeply nested starting directory.
pub const MAX_DISCOVERY_ANCESTORS: usize = 64;

/// Whether `directory` is a fleet repository root: an adjacent `.git` directory.
///
/// Delegates to the hardened discovery so this crate has exactly one definition.
/// An earlier version here accepted a worktree/submodule `.git` file, which
/// contradicted the hardened rule exported from the same crate.
#[must_use]
pub fn is_repo_root(directory: &Path) -> bool {
    crate::config_discovery::is_repo_root(directory)
}

/// Finds the project config by walking up from `start`, taking the nearest
/// directory that holds one.
///
/// This is the spelling `ores-stack`'s server-config audit recognises, so it is
/// the one servers actually call. It therefore delegates to the hardened
/// discovery rather than keeping a weaker walk alive beside it: implicit
/// discovery stops at the first Git boundary, symlinked or non-regular leaves
/// are refused, and the non-root warning is really emitted. Two exported walks
/// with different trust properties would leave every caller on whichever one
/// the contract happens to name.
///
/// # Errors
/// Returns `AmbiguousConfigFiles` when one directory holds both filenames, and
/// an `Io` error when a candidate is unsafe to read or cannot be inspected.
pub fn discover_project_config_upward(
    start: &Path,
) -> Result<Option<(PathBuf, bool)>, SharedAuthConfigError> {
    crate::config_discovery::discover_project_config_hardened(start)
        .map(|found| found.map(|found| (found.path, found.used_legacy_alias)))
        .map_err(discovery_error_into_config_error)
}

/// Loads the project config found by walking up from `start`. Delegates to the
/// hardened loader; see [`discover_project_config_upward`].
///
/// # Errors
/// Returns `MissingProjectConfig` when no config exists up to the repository
/// boundary, plus the usual parse/validation errors.
pub fn load_project_config_upward(
    start: &Path,
    defaults: SharedAuthDefaults,
) -> Result<LoadedSharedAuthConfig, SharedAuthConfigError> {
    crate::config_discovery::load_project_config_hardened(start, defaults)
        .map_err(discovery_error_into_config_error)
}

fn discovery_error_into_config_error(
    error: crate::config_discovery::SharedAuthDiscoveryError,
) -> SharedAuthConfigError {
    use crate::config_discovery::SharedAuthDiscoveryError as Discovery;
    match error {
        Discovery::Config(error) => error,
        Discovery::Missing { start } => SharedAuthConfigError::MissingProjectConfig(start),
        Discovery::Metadata { path, source } => SharedAuthConfigError::Io { path, source },
        Discovery::UnsafeConfigLeaf { path } => SharedAuthConfigError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsafe config leaf: expected a regular non-symlink file no larger than 256 KiB",
            ),
            path,
        },
    }
}

pub fn load_project_config(
    root: &Path,
    defaults: SharedAuthDefaults,
) -> Result<LoadedSharedAuthConfig, SharedAuthConfigError> {
    let (path, used_legacy_alias) = discover_project_config(root)?
        .ok_or_else(|| SharedAuthConfigError::MissingProjectConfig(root.to_path_buf()))?;
    let input = fs::read_to_string(&path).map_err(|source| SharedAuthConfigError::Io {
        path: path.clone(),
        source,
    })?;
    let overlay = SharedAuthConfigOverlay::parse_toml(&input)?;
    let resolved = overlay.resolve(defaults)?;
    Ok(LoadedSharedAuthConfig {
        source_path: path,
        used_legacy_alias,
        resolved,
    })
}

#[derive(Debug, Error)]
pub enum SharedAuthConfigError {
    #[error(
        "both {canonical:?} and {legacy:?} exist; remove one instead of relying on precedence"
    )]
    AmbiguousConfigFiles { canonical: PathBuf, legacy: PathBuf },
    #[error("no {CANONICAL_CONFIG_FILE} or {LEGACY_CONFIG_FILE} found under {0:?}")]
    MissingProjectConfig(PathBuf),
    #[error("failed to read shared-auth config {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid shared-auth TOML: {0}")]
    Toml(String),
    #[error("unsupported shared-auth schema version {found}; expected {expected}")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("compatibility.repository must be {SHARED_AUTH_INTERFACES_REPOSITORY:?}, found {0:?}")]
    InvalidRepository(String),
    #[error("{field} must be a 40-character lowercase hexadecimal Git commit SHA")]
    InvalidGitSha { field: &'static str },
    #[error("{field} must contain at least one value")]
    EmptySet { field: &'static str },
    #[error("{field} contains a duplicate value")]
    DuplicateSetValue { field: &'static str },
    #[error("styling.brand_name must contain 1 to 80 Unicode scalar values")]
    InvalidBrandName,
    #[error("styling.accent_color must be a six-digit hexadecimal color such as #4F46E5")]
    InvalidAccentColor,
    #[error("shared-auth interfaces revision {revision} is outside the declared compatibility constraint")]
    RevisionNotAdmitted { revision: String },
}

fn validate_repository(repository: &str) -> Result<(), SharedAuthConfigError> {
    if repository == SHARED_AUTH_INTERFACES_REPOSITORY {
        Ok(())
    } else {
        Err(SharedAuthConfigError::InvalidRepository(
            repository.to_owned(),
        ))
    }
}

fn validate_git_sha(field: &'static str, value: &str) -> Result<(), SharedAuthConfigError> {
    let valid = value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(SharedAuthConfigError::InvalidGitSha { field })
    }
}

fn validate_set<T>(field: &'static str, values: &[T]) -> Result<(), SharedAuthConfigError>
where
    T: Eq + Hash,
{
    if values.is_empty() {
        return Err(SharedAuthConfigError::EmptySet { field });
    }
    let mut seen = HashSet::with_capacity(values.len());
    if values.iter().all(|value| seen.insert(value)) {
        Ok(())
    } else {
        Err(SharedAuthConfigError::DuplicateSetValue { field })
    }
}

fn validate_brand_name(value: &str) -> Result<(), SharedAuthConfigError> {
    let length = value.chars().count();
    if (1..=80).contains(&length) {
        Ok(())
    } else {
        Err(SharedAuthConfigError::InvalidBrandName)
    }
}

fn validate_accent_color(value: &str) -> Result<(), SharedAuthConfigError> {
    let bytes = value.as_bytes();
    let valid =
        bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit);
    if valid {
        Ok(())
    } else {
        Err(SharedAuthConfigError::InvalidAccentColor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const SHA_A: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA_B: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const SHA_C: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn walk_fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("shared-auth-walk-{tag}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("fixture root");
        root
    }

    #[test]
    fn walks_up_to_find_the_project_config() {
        let root = walk_fixture("basic");
        let deep = root.join("services/api/src");
        fs::create_dir_all(&deep).expect("dirs");
        fs::write(root.join(CANONICAL_CONFIG_FILE), exact_config("")).expect("write");

        let (path, legacy) = discover_project_config_upward(&deep)
            .expect("walks")
            .expect("finds a config");
        assert!(!legacy);
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(CANONICAL_CONFIG_FILE)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_nearest_config_wins_over_a_further_ancestor() {
        let root = walk_fixture("nearest");
        let inner = root.join("member");
        fs::create_dir_all(&inner).expect("dirs");
        fs::write(root.join(CANONICAL_CONFIG_FILE), exact_config("")).expect("write");
        fs::write(inner.join(CANONICAL_CONFIG_FILE), exact_config("")).expect("write");

        let (path, _) = discover_project_config_upward(&inner)
            .expect("walks")
            .expect("finds");
        assert_eq!(
            fs::canonicalize(path).expect("canon"),
            fs::canonicalize(inner.join(CANONICAL_CONFIG_FILE)).expect("canon"),
            "the closest config to the running code must win"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ambiguity_is_still_an_error_during_a_walk() {
        let root = walk_fixture("ambiguous");
        let deep = root.join("a/b");
        fs::create_dir_all(&deep).expect("dirs");
        // Both names in ONE directory stays ambiguous; the walk must not quietly
        // resolve it by preferring canonical, which would hide a real conflict.
        fs::write(root.join(CANONICAL_CONFIG_FILE), exact_config("")).expect("write");
        fs::write(root.join(LEGACY_CONFIG_FILE), exact_config("")).expect("write");

        let error = discover_project_config_upward(&deep).expect_err("ambiguous");
        assert!(
            matches!(error, SharedAuthConfigError::AmbiguousConfigFiles { .. }),
            "{error:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_legacy_alias_is_still_found_by_the_walk() {
        let root = walk_fixture("legacy");
        let deep = root.join("svc");
        fs::create_dir_all(&deep).expect("dirs");
        fs::write(root.join(LEGACY_CONFIG_FILE), exact_config("")).expect("write");

        let (path, used_legacy) = discover_project_config_upward(&deep)
            .expect("walks")
            .expect("finds");
        assert!(
            used_legacy,
            "the walk must still report the legacy alias as legacy"
        );
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(LEGACY_CONFIG_FILE)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_contract_named_upward_loader_stops_at_the_git_boundary() {
        // ores-stack's server-config audit names `*_upward`, so these are the
        // functions servers call. They must carry the hardened trust boundary,
        // not a weaker walk of their own.
        let outer = walk_fixture("upward-boundary");
        let repo = outer.join("checkout");
        let deep = repo.join("src");
        fs::create_dir_all(&deep).expect("dirs");
        fs::create_dir_all(repo.join(".git")).expect("git dir");
        fs::write(outer.join(CANONICAL_CONFIG_FILE), exact_config("")).expect("outside");

        let found = discover_project_config_upward(&deep).expect("walks");
        assert!(
            found.is_none(),
            "a config above the repository must not govern it"
        );
        let _ = fs::remove_dir_all(&outer);
    }

    #[cfg(unix)]
    #[test]
    fn the_contract_named_upward_loader_refuses_symlinked_configs() {
        use std::os::unix::fs::symlink;
        let root = walk_fixture("upward-symlink");
        fs::create_dir_all(root.join(".git")).expect("git dir");
        let actual = root.join("elsewhere.toml");
        fs::write(&actual, exact_config("")).expect("write");
        symlink(&actual, root.join(CANONICAL_CONFIG_FILE)).expect("symlink");

        let error = discover_project_config_upward(&root).expect_err("symlink refused");
        assert!(
            matches!(error, SharedAuthConfigError::Io { .. }),
            "{error:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn an_uninspectable_directory_stops_the_walk_instead_of_loading_a_higher_config() {
        use std::os::unix::fs::PermissionsExt;
        let outer = walk_fixture("permission");
        let locked = outer.join("locked");
        let deep = locked.join("svc");
        fs::create_dir_all(&deep).expect("dirs");
        fs::write(outer.join(CANONICAL_CONFIG_FILE), exact_config("")).expect("outer config");
        let start = fs::canonicalize(&deep).expect("canonical start");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("lock");

        let result = discover_project_config_upward(&start);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).expect("unlock");

        let is_root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0");
        match result {
            Err(SharedAuthConfigError::Io { .. }) => {}
            other => assert!(
                is_root,
                "walk climbed past an uninspectable directory: {other:?}"
            ),
        }
        let _ = fs::remove_dir_all(&outer);
    }

    #[test]
    fn a_start_that_cannot_be_canonicalised_is_an_error_not_a_lexical_walk() {
        let missing = std::env::temp_dir().join("shared-auth-walk-does-not-exist/a/b");
        assert!(matches!(
            discover_project_config_upward(&missing),
            Err(SharedAuthConfigError::Io { .. })
        ));
    }

    #[test]
    fn only_a_git_directory_is_a_repo_root() {
        let root = walk_fixture("repo-root");
        fs::create_dir_all(root.join(".git")).expect("git dir");
        assert!(is_repo_root(&root));
        let _ = fs::remove_dir_all(&root);

        // A worktree/submodule .git FILE is a traversal boundary but not fleet
        // repo-root placement, matching config_discovery::is_repo_root.
        let worktree = walk_fixture("git-file");
        fs::write(worktree.join(".git"), "gitdir: /elsewhere\n").expect("git file");
        assert!(!is_repo_root(&worktree));
        let _ = fs::remove_dir_all(&worktree);
    }

    #[test]
    fn a_walk_that_finds_nothing_in_the_fixture_never_returns_a_fixture_path() {
        let root = walk_fixture("absent");
        let deep = root.join("x/y");
        fs::create_dir_all(&deep).expect("dirs");

        // The walk continues past the fixture toward the filesystem root, so it
        // may legitimately find an unrelated config on a developer machine. What
        // must never happen is a hit inside the fixture, where nothing was written.
        let found = discover_project_config_upward(&deep).expect("walks without error");
        if let Some((path, _)) = found {
            assert!(
                !path.starts_with(&root),
                "nothing was written under the fixture, so no hit may come from it: {}",
                path.display()
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    fn exact_config(extra: &str) -> String {
        format!(
            r#"schema_version = 1

[compatibility]
repository = "{SHARED_AUTH_INTERFACES_REPOSITORY}"
commit = "{SHA_A}"

{extra}
"#
        )
    }

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shared-auth-lib-core-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory should be creatable");
        path
    }

    #[test]
    fn secure_defaults_are_stable() {
        let defaults = SharedAuthDefaults::default();
        defaults.validate().expect("defaults must remain valid");
        assert!(defaults.factors.two_factor.required);
        assert!(!defaults.factors.three_factor.enabled);
        assert_eq!(defaults.styling.theme, Theme::System);
        assert!(!defaults.pages.show.contains(&AuthPage::SignUp));
    }

    #[test]
    fn overlay_replaces_sets_instead_of_unioning_them() {
        let overlay = SharedAuthConfigOverlay::parse_toml(&exact_config(
            r#"[factors.two_factor]
methods = ["passkey"]

[pages]
show = ["sign-in", "challenge"]"#,
        ))
        .expect("valid overlay should parse");
        let resolved = overlay
            .resolve(SharedAuthDefaults::default())
            .expect("overlay should resolve");
        assert_eq!(
            resolved.factors.two_factor.methods,
            vec![FactorMethod::Passkey]
        );
        assert_eq!(
            resolved.pages.show,
            vec![AuthPage::SignIn, AuthPage::Challenge]
        );
    }

    #[test]
    fn unknown_keys_fail_closed_during_deserialization() {
        let result = SharedAuthConfigOverlay::parse_toml(&exact_config(
            r#"[factors.two_factor]
methods = ["totp"]
trust_me = true"#,
        ));
        assert!(matches!(result, Err(SharedAuthConfigError::Toml(_))));
    }

    #[test]
    fn duplicate_set_members_are_rejected() {
        let result = SharedAuthConfigOverlay::parse_toml(&exact_config(
            r#"[factors.two_factor]
methods = ["totp", "totp"]"#,
        ));
        assert!(matches!(
            result,
            Err(SharedAuthConfigError::DuplicateSetValue {
                field: "factors.two_factor.methods"
            })
        ));
    }

    #[test]
    fn malformed_revision_is_rejected() {
        let input = format!(
            r#"schema_version = 1

[compatibility]
repository = "{SHARED_AUTH_INTERFACES_REPOSITORY}"
commit = "ABC"
"#
        );
        let result = SharedAuthConfigOverlay::parse_toml(&input);
        assert!(matches!(
            result,
            Err(SharedAuthConfigError::InvalidGitSha {
                field: "compatibility.commit"
            })
        ));
    }

    #[test]
    fn canonical_and_legacy_files_together_are_ambiguous() {
        let root = test_dir("ambiguous");
        fs::write(root.join(CANONICAL_CONFIG_FILE), exact_config(""))
            .expect("canonical file should be writable");
        fs::write(root.join(LEGACY_CONFIG_FILE), exact_config(""))
            .expect("legacy file should be writable");
        let result = discover_project_config(&root);
        assert!(matches!(
            result,
            Err(SharedAuthConfigError::AmbiguousConfigFiles { .. })
        ));
        fs::remove_dir_all(root).expect("test directory should be removable");
    }

    #[test]
    fn legacy_alias_is_used_only_when_canonical_file_is_absent() {
        let root = test_dir("legacy");
        fs::write(root.join(LEGACY_CONFIG_FILE), exact_config(""))
            .expect("legacy file should be writable");
        let loaded = load_project_config(&root, SharedAuthDefaults::default())
            .expect("legacy-only config should load");
        assert!(loaded.used_legacy_alias);
        assert_eq!(
            loaded
                .source_path
                .file_name()
                .and_then(|name| name.to_str()),
            Some(LEGACY_CONFIG_FILE)
        );
        fs::remove_dir_all(root).expect("test directory should be removable");
    }

    #[test]
    fn exact_revision_admission_is_fail_closed() {
        let overlay = SharedAuthConfigOverlay::parse_toml(&exact_config(""))
            .expect("valid exact config should parse");
        let resolved = overlay
            .resolve(SharedAuthDefaults::default())
            .expect("config should resolve");
        resolved
            .admits_revision(SHA_A, |_, _| false)
            .expect("exact revision should be admitted");
        assert!(matches!(
            resolved.admits_revision(SHA_C, |_, _| false),
            Err(SharedAuthConfigError::RevisionNotAdmitted { .. })
        ));
    }

    #[test]
    fn range_revision_admission_uses_ancestry_not_sha_ordering() {
        let input = format!(
            r#"schema_version = 1

[compatibility]
repository = "{SHARED_AUTH_INTERFACES_REPOSITORY}"

[compatibility.range]
base = "{SHA_A}"
head = "{SHA_B}"
"#
        );
        let resolved = SharedAuthConfigOverlay::parse_toml(&input)
            .expect("valid range config should parse")
            .resolve(SharedAuthDefaults::default())
            .expect("range config should resolve");
        resolved
            .admits_revision(SHA_C, |ancestor, descendant| {
                (ancestor == SHA_A && descendant == SHA_C)
                    || (ancestor == SHA_C && descendant == SHA_B)
            })
            .expect("revision inside ancestry range should be admitted");
        assert!(matches!(
            resolved.admits_revision(SHA_C, |_, _| false),
            Err(SharedAuthConfigError::RevisionNotAdmitted { .. })
        ));
    }
}
