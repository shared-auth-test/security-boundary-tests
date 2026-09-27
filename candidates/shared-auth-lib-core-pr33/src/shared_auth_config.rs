use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::hash::Hash;
use std::path::{Path, PathBuf};

pub const CANONICAL_CONFIG_FILENAME: &str = ".shared-auth.toml";
pub const COMPATIBILITY_ALIAS_FILENAME: &str = ".auth-shared.toml";
pub const SHARED_AUTH_INTERFACES_REPOSITORY: &str =
    "https://github.com/shared-auth/shared-auth-interfaces";
pub const SHARED_AUTH_CONFIG_AUTHORITY_REVISION: &str =
    "52b7ac7fbf0c7c169684f613eda923f3aa6c82e9";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectConfigSource {
    Canonical,
    CompatibilityAlias,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSharedAuthConfig {
    pub source: ProjectConfigSource,
    pub path: PathBuf,
    pub config: SharedAuthConfigFile,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    AmbiguousFiles { canonical: PathBuf, alias: PathBuf },
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "shared-auth config I/O failed: {error}"),
            Self::Parse(error) => write!(f, "shared-auth TOML parsing failed: {error}"),
            Self::AmbiguousFiles { canonical, alias } => write!(
                f,
                "both {} and {} exist; refusing to choose a Shared Auth policy",
                canonical.display(),
                alias.display()
            ),
            Self::Invalid(message) => write!(f, "invalid shared-auth config: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::AmbiguousFiles { .. } | Self::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(value: toml::de::Error) -> Self {
        Self::Parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAuthConfigFile {
    pub schema_version: u8,
    pub compatibility: Compatibility,
    pub factors: Option<FactorsPolicy>,
    pub pages: Option<PagesPolicy>,
    pub styling: Option<StylingPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Compatibility {
    Exact(ExactCompatibility),
    Range(RangeCompatibility),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactCompatibility {
    pub repository: String,
    pub commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeCompatibility {
    pub repository: String,
    pub range: CommitRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRange {
    pub base: String,
    pub head: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorsPolicy {
    pub two_factor: Option<TwoFactorPolicy>,
    pub three_factor: Option<ThreeFactorPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwoFactorPolicy {
    pub required: Option<bool>,
    pub methods: Option<Vec<FactorMethod>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreeFactorPolicy {
    pub enabled: Option<bool>,
    pub methods: Option<Vec<FactorMethod>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactorMethod {
    Totp,
    Passkey,
    SecurityKey,
    EmailOtp,
    SmsOtp,
    BackupCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagesPolicy {
    pub show: Option<Vec<AuthPage>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthPage {
    SignIn,
    SignUp,
    Challenge,
    Recovery,
    Consent,
    Error,
    SignedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Theme {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StylingPolicy {
    pub theme: Option<Theme>,
    pub brand_name: Option<String>,
    pub accent_color: Option<String>,
}

impl SharedAuthConfigFile {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::Invalid(format!(
                "schema_version must equal 1, got {}",
                self.schema_version
            )));
        }

        match &self.compatibility {
            Compatibility::Exact(exact) => {
                validate_repository(&exact.repository)?;
                validate_revision(&exact.commit, "compatibility.commit")?;
            }
            Compatibility::Range(range) => {
                validate_repository(&range.repository)?;
                validate_revision(&range.range.base, "compatibility.range.base")?;
                validate_revision(&range.range.head, "compatibility.range.head")?;
            }
        }

        if let Some(factors) = &self.factors {
            if let Some(two_factor) = &factors.two_factor {
                if let Some(methods) = &two_factor.methods {
                    validate_nonempty_unique(methods, "factors.two_factor.methods")?;
                }
            }
            if let Some(three_factor) = &factors.three_factor {
                if let Some(methods) = &three_factor.methods {
                    validate_nonempty_unique(methods, "factors.three_factor.methods")?;
                }
            }
        }

        if let Some(pages) = &self.pages {
            if let Some(show) = &pages.show {
                validate_nonempty_unique(show, "pages.show")?;
            }
        }

        if let Some(styling) = &self.styling {
            if let Some(brand_name) = &styling.brand_name {
                let length = brand_name.chars().count();
                if !(1..=80).contains(&length) {
                    return Err(ConfigError::Invalid(
                        "styling.brand_name must contain 1..=80 Unicode scalar values".into(),
                    ));
                }
            }
            if let Some(accent_color) = &styling.accent_color {
                if !is_hex_color(accent_color) {
                    return Err(ConfigError::Invalid(
                        "styling.accent_color must be exactly #RRGGBB".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn compatibility_allows<F>(&self, running_revision: &str, mut is_ancestor: F) -> bool
    where
        F: FnMut(&str, &str) -> bool,
    {
        if !is_lower_hex_revision(running_revision) {
            return false;
        }
        match &self.compatibility {
            Compatibility::Exact(exact) => exact.commit == running_revision,
            Compatibility::Range(range) => {
                is_ancestor(&range.range.base, running_revision)
                    && is_ancestor(running_revision, &range.range.head)
            }
        }
    }
}

pub fn load_project_config(
    root: impl AsRef<Path>,
) -> Result<Option<LoadedSharedAuthConfig>, ConfigError> {
    let root = root.as_ref();
    let canonical = root.join(CANONICAL_CONFIG_FILENAME);
    let alias = root.join(COMPATIBILITY_ALIAS_FILENAME);
    let canonical_exists = canonical.try_exists()?;
    let alias_exists = alias.try_exists()?;

    if canonical_exists && alias_exists {
        return Err(ConfigError::AmbiguousFiles { canonical, alias });
    }

    let (path, source) = if canonical_exists {
        (canonical, ProjectConfigSource::Canonical)
    } else if alias_exists {
        (alias, ProjectConfigSource::CompatibilityAlias)
    } else {
        return Ok(None);
    };

    let input = fs::read_to_string(&path)?;
    let config = SharedAuthConfigFile::parse(&input)?;
    Ok(Some(LoadedSharedAuthConfig {
        source,
        path,
        config,
    }))
}

fn validate_repository(repository: &str) -> Result<(), ConfigError> {
    if repository != SHARED_AUTH_INTERFACES_REPOSITORY {
        return Err(ConfigError::Invalid(format!(
            "compatibility.repository must equal {SHARED_AUTH_INTERFACES_REPOSITORY}"
        )));
    }
    Ok(())
}

fn validate_revision(revision: &str, field: &str) -> Result<(), ConfigError> {
    if !is_lower_hex_revision(revision) {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a lowercase 40-character Git SHA"
        )));
    }
    Ok(())
}

fn is_lower_hex_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_hex_color(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

fn validate_nonempty_unique<T>(values: &[T], field: &str) -> Result<(), ConfigError>
where
    T: Eq + Hash,
{
    if values.is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must not be empty")));
    }
    let mut seen = HashSet::with_capacity(values.len());
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(ConfigError::Invalid(format!(
            "{field} must not contain duplicates"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir_all, remove_dir_all, write};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    const REVISION: &str = "52b7ac7fbf0c7c169684f613eda923f3aa6c82e9";

    fn valid_config() -> String {
        format!(
            r##"schema_version = 1

[compatibility]
repository = "https://github.com/shared-auth/shared-auth-interfaces"
commit = "{REVISION}"

[factors.two_factor]
required = true
methods = ["totp", "passkey", "security-key"]

[factors.three_factor]
enabled = false
methods = ["totp", "passkey", "security-key"]

[pages]
show = ["sign-in", "challenge", "recovery", "error", "signed-out"]

[styling]
theme = "system"
brand_name = "Shared Auth"
accent_color = "#4F46E5"
"##
        )
    }

    fn temp_root(test_name: &str) -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "shared-auth-config-{test_name}-{}-{id}",
            std::process::id()
        ));
        let _ = remove_dir_all(&root);
        create_dir_all(&root).expect("create temp root");
        root
    }

    #[test]
    fn parses_valid_authority_shape() {
        let config = SharedAuthConfigFile::parse(&valid_config()).expect("valid config");
        assert_eq!(config.schema_version, 1);
        assert!(config.compatibility_allows(REVISION, |_, _| false));
    }

    #[test]
    fn accepts_requested_compatibility_alias_when_canonical_is_absent() {
        let root = temp_root("alias");
        write(root.join(COMPATIBILITY_ALIAS_FILENAME), valid_config()).expect("write alias");
        let loaded = load_project_config(&root)
            .expect("load alias")
            .expect("config exists");
        assert_eq!(loaded.source, ProjectConfigSource::CompatibilityAlias);
        assert_eq!(loaded.path, root.join(COMPATIBILITY_ALIAS_FILENAME));
        remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn canonical_filename_wins_only_when_alias_is_absent() {
        let root = temp_root("canonical");
        write(root.join(CANONICAL_CONFIG_FILENAME), valid_config()).expect("write canonical");
        let loaded = load_project_config(&root)
            .expect("load canonical")
            .expect("config exists");
        assert_eq!(loaded.source, ProjectConfigSource::Canonical);
        remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn dual_filenames_fail_closed() {
        let root = temp_root("dual");
        write(root.join(CANONICAL_CONFIG_FILENAME), valid_config()).expect("write canonical");
        write(root.join(COMPATIBILITY_ALIAS_FILENAME), valid_config()).expect("write alias");
        let error = load_project_config(&root).expect_err("dual files must fail");
        assert!(matches!(error, ConfigError::AmbiguousFiles { .. }));
        remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn duplicate_factor_methods_fail_closed() {
        let input = valid_config().replace(
            "methods = [\"totp\", \"passkey\", \"security-key\"]",
            "methods = [\"totp\", \"totp\"]",
        );
        let error = SharedAuthConfigFile::parse(&input).expect_err("duplicate factor");
        assert!(error.to_string().contains("must not contain duplicates"));
    }

    #[test]
    fn unknown_fields_fail_at_deserialization_boundary() {
        let input = format!("{}\nplaintext_secret = \"synthetic-invalid\"\n", valid_config());
        let error = SharedAuthConfigFile::parse(&input).expect_err("unknown field");
        assert!(matches!(error, ConfigError::Parse(_)));
    }

    #[test]
    fn revision_ranges_use_ancestry_not_lexical_order() {
        let base = "1111111111111111111111111111111111111111";
        let head = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let running = "7777777777777777777777777777777777777777";
        let input = format!(
            r#"schema_version = 1

[compatibility]
repository = "https://github.com/shared-auth/shared-auth-interfaces"
range = {{ base = "{base}", head = "{head}" }}
"#
        );
        let config = SharedAuthConfigFile::parse(&input).expect("range config");
        assert!(config.compatibility_allows(running, |ancestor, descendant| {
            (ancestor == base && descendant == running)
                || (ancestor == running && descendant == head)
        }));
        assert!(!config.compatibility_allows(running, |_, _| false));
    }

    #[test]
    fn malformed_revision_and_style_tokens_fail_closed() {
        let bad_revision = valid_config().replace(REVISION, "MAIN");
        assert!(SharedAuthConfigFile::parse(&bad_revision).is_err());

        let bad_color = valid_config().replace("#4F46E5", "blue");
        assert!(SharedAuthConfigFile::parse(&bad_color).is_err());
    }

    #[test]
    fn no_project_file_means_no_overlay() {
        let root = temp_root("none");
        assert!(load_project_config(&root).expect("load none").is_none());
        remove_dir_all(root).expect("remove temp root");
    }
}
