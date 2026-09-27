#![forbid(unsafe_code)]

//! Hardened filesystem discovery for Shared Auth repository configuration.
//!
//! The existing `config` module remains the parser/schema/runtime authority.
//! This module only owns safe file selection, repository-boundary traversal,
//! and source-path provenance.

use std::{
    fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::config::{
    LoadedSharedAuthConfig, SharedAuthConfigError, SharedAuthConfigOverlay, SharedAuthDefaults,
    CANONICAL_CONFIG_FILE, LEGACY_CONFIG_FILE,
};

pub const MAX_DISCOVERY_ANCESTORS: usize = 64;
pub const MAX_DISCOVERY_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredSharedAuthConfig {
    pub path: PathBuf,
    pub used_legacy_alias: bool,
    /// Only an adjacent `.git` directory counts as fleet repo-root placement.
    /// A `.git` file is still a traversal boundary but reports `false` here.
    pub at_repository_root: bool,
}

#[derive(Debug, Error)]
pub enum SharedAuthDiscoveryError {
    #[error("failed to inspect Shared Auth config path {path}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsafe Shared Auth config leaf at {path}; expected a regular non-symlink file no larger than 256 KiB")]
    UnsafeConfigLeaf { path: PathBuf },
    #[error("no {CANONICAL_CONFIG_FILE} or {LEGACY_CONFIG_FILE} found from {start} to the repository boundary")]
    Missing { start: PathBuf },
    #[error(transparent)]
    Config(#[from] SharedAuthConfigError),
}

/// Only `NotFound` means "no boundary here". Any other failure inspecting `.git`
/// is reported: treating "could not look" as "nothing there" lets the walk climb
/// past a trust boundary it was unable to see.
fn has_git_boundary(directory: &Path) -> Result<bool, SharedAuthDiscoveryError> {
    Ok(metadata_if_present(&directory.join(".git"))?.is_some())
}

#[must_use]
pub fn is_repo_root(directory: &Path) -> bool {
    directory.join(".git").is_dir()
}

fn metadata_if_present(path: &Path) -> Result<Option<fs::Metadata>, SharedAuthDiscoveryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SharedAuthDiscoveryError::Metadata {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_leaf(path: &Path, metadata: &fs::Metadata) -> Result<(), SharedAuthDiscoveryError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DISCOVERY_CONFIG_BYTES
    {
        return Err(SharedAuthDiscoveryError::UnsafeConfigLeaf {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Finds the nearest Shared Auth config without crossing the first Git trust
/// boundary. Canonical/compatibility precedence remains per-directory: both
/// spellings together are ambiguous and fail closed.
pub fn discover_project_config_hardened(
    start: &Path,
) -> Result<Option<DiscoveredSharedAuthConfig>, SharedAuthDiscoveryError> {
    // A start that cannot be canonicalised is an error, not a cue to walk the
    // lexical path, which can traverse `..` and symlinks unseen.
    let start = fs::canonicalize(start).map_err(|source| SharedAuthDiscoveryError::Metadata {
        path: start.to_path_buf(),
        source,
    })?;

    for directory in start.ancestors().take(MAX_DISCOVERY_ANCESTORS) {
        let canonical = directory.join(CANONICAL_CONFIG_FILE);
        let legacy = directory.join(LEGACY_CONFIG_FILE);
        let canonical_metadata = metadata_if_present(&canonical)?;
        let legacy_metadata = metadata_if_present(&legacy)?;

        match (canonical_metadata.as_ref(), legacy_metadata.as_ref()) {
            (Some(_), Some(_)) => {
                return Err(
                    SharedAuthConfigError::AmbiguousConfigFiles { canonical, legacy }.into(),
                );
            }
            (Some(metadata), None) => {
                validate_leaf(&canonical, metadata)?;
                let found = DiscoveredSharedAuthConfig {
                    path: canonical,
                    used_legacy_alias: false,
                    at_repository_root: is_repo_root(directory),
                };
                warn_unless_repo_root(&found);
                return Ok(Some(found));
            }
            (None, Some(metadata)) => {
                validate_leaf(&legacy, metadata)?;
                let found = DiscoveredSharedAuthConfig {
                    path: legacy,
                    used_legacy_alias: true,
                    at_repository_root: is_repo_root(directory),
                };
                warn_unless_repo_root(&found);
                return Ok(Some(found));
            }
            (None, None) => {}
        }

        if has_git_boundary(directory)? {
            break;
        }
    }

    Ok(None)
}

/// Loads the exact owner-selected file while retaining its path for provenance
/// receipts. Parsing/resolution still delegates to `SharedAuthConfigOverlay`.
pub fn load_project_config_hardened(
    start: &Path,
    defaults: SharedAuthDefaults,
) -> Result<LoadedSharedAuthConfig, SharedAuthDiscoveryError> {
    let found = discover_project_config_hardened(start)?.ok_or_else(|| {
        SharedAuthDiscoveryError::Missing {
            start: start.to_path_buf(),
        }
    })?;
    let input = read_selected(&found.path)?;
    let overlay = SharedAuthConfigOverlay::parse_toml(&input)?;
    let resolved = overlay.resolve(defaults)?;
    Ok(LoadedSharedAuthConfig {
        source_path: found.path,
        used_legacy_alias: found.used_legacy_alias,
        resolved,
    })
}

/// Reads the file discovery selected, not whatever is at the path by then.
///
/// Discovery validates the leaf by metadata; re-opening by path afterwards
/// leaves a window in which it can be swapped for a symlink. The file is opened
/// once, the handle is confirmed to be a regular file and the same inode that
/// `symlink_metadata` described, and the bytes come from that handle under the
/// size bound.
fn read_selected(path: &Path) -> Result<String, SharedAuthDiscoveryError> {
    use std::io::Read;
    let io = |source| SharedAuthConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let validated = fs::symlink_metadata(path).map_err(io)?;
    let file = fs::File::open(path).map_err(io)?;
    let opened = file.metadata().map_err(io)?;
    #[cfg(unix)]
    let same_file = {
        use std::os::unix::fs::MetadataExt;
        opened.dev() == validated.dev() && opened.ino() == validated.ino()
    };
    #[cfg(not(unix))]
    let same_file = true;
    if validated.file_type().is_symlink()
        || !same_file
        || !opened.is_file()
        || opened.len() > MAX_DISCOVERY_CONFIG_BYTES
    {
        return Err(SharedAuthDiscoveryError::UnsafeConfigLeaf {
            path: path.to_path_buf(),
        });
    }
    let mut input = String::new();
    file.take(MAX_DISCOVERY_CONFIG_BYTES + 1)
        .read_to_string(&mut input)
        .map_err(io)?;
    if input.len() as u64 > MAX_DISCOVERY_CONFIG_BYTES {
        return Err(SharedAuthDiscoveryError::UnsafeConfigLeaf {
            path: path.to_path_buf(),
        });
    }
    Ok(input)
}

fn warn_unless_repo_root(found: &DiscoveredSharedAuthConfig) {
    if !found.at_repository_root {
        #[cfg(feature = "ores-logging")]
        {
            let _ = discovery_logger()
                .warn(vec![next_loggers::json!({
                    "event": "ores.config.not_at_repo_root",
                    "ores.config.file": found.path.file_name().and_then(|name| name.to_str()).unwrap_or(CANONICAL_CONFIG_FILE),
                    "ores.config.path": found.path.display().to_string(),
                    "ores.config.at_repo_root": false,
                    "detail": "Shared Auth configuration was selected without an adjacent .git directory; confirm this file is meant to govern the running service"
                })])
                .send();
        }
    }
}

#[cfg(feature = "ores-logging")]
fn discovery_logger() -> &'static next_loggers::Logger {
    static LOGGER: std::sync::OnceLock<next_loggers::Logger> = std::sync::OnceLock::new();
    LOGGER.get_or_init(|| {
        next_loggers::Logger::new(next_loggers::Options {
            app_name: "shared-auth-lib-core".into(),
            name: Some("config-discovery".into()),
            ..next_loggers::Options::default()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "shared-auth-hardened-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("root");
        root
    }

    #[test]
    fn canonical_file_is_selected_and_source_is_retained() {
        let root = scratch("canonical");
        let deep = root.join("services/api");
        fs::create_dir_all(root.join(".git")).expect("git dir");
        fs::create_dir_all(&deep).expect("deep");
        fs::write(root.join(CANONICAL_CONFIG_FILE), "schema_version = 1\n").expect("config");
        let found = discover_project_config_hardened(&deep)
            .expect("discover")
            .expect("found");
        // Discovery canonicalises its start, and on macOS the temp dir is /var,
        // a symlink to /private/var: compare canonical paths or this passes on
        // Linux CI and fails on every developer Mac.
        assert_eq!(
            fs::canonicalize(&found.path).expect("canonical found"),
            fs::canonicalize(root.join(CANONICAL_CONFIG_FILE)).expect("canonical expected")
        );
        assert!(!found.used_legacy_alias);
        assert!(found.at_repository_root);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn aliases_in_one_directory_remain_ambiguous() {
        let root = scratch("ambiguous");
        fs::write(root.join(CANONICAL_CONFIG_FILE), "x").expect("canonical");
        fs::write(root.join(LEGACY_CONFIG_FILE), "x").expect("legacy");
        let error = discover_project_config_hardened(&root).expect_err("ambiguous");
        assert!(matches!(
            error,
            SharedAuthDiscoveryError::Config(SharedAuthConfigError::AmbiguousConfigFiles { .. })
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn discovery_does_not_escape_repository_boundary() {
        let outer = scratch("boundary");
        let repo = outer.join("repo");
        let deep = repo.join("services/api");
        fs::create_dir_all(repo.join(".git")).expect("git dir");
        fs::create_dir_all(&deep).expect("deep");
        fs::write(outer.join(CANONICAL_CONFIG_FILE), "x").expect("outer config");
        assert!(discover_project_config_hardened(&deep)
            .expect("discover")
            .is_none());
        fs::remove_dir_all(outer).expect("cleanup");
    }

    #[test]
    fn git_file_is_boundary_but_not_root_placement() {
        let root = scratch("git-file");
        fs::write(root.join(".git"), "gitdir: /elsewhere\n").expect("git file");
        fs::write(root.join(CANONICAL_CONFIG_FILE), "x").expect("config");
        let found = discover_project_config_hardened(&root)
            .expect("discover")
            .expect("found");
        assert!(!found.at_repository_root);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_leaf_is_rejected_before_read() {
        use std::os::unix::fs::symlink;
        let root = scratch("symlink");
        let real = root.join("real.toml");
        fs::write(&real, "x").expect("real");
        symlink(&real, root.join(CANONICAL_CONFIG_FILE)).expect("symlink");
        let error = discover_project_config_hardened(&root).expect_err("symlink must fail");
        assert!(matches!(
            error,
            SharedAuthDiscoveryError::UnsafeConfigLeaf { .. }
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
