use crate::model::Policy;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use walkdir::WalkDir;

const TRUSTED_SDK_ENV: &str = "BMSCL_TRUSTED_SDK_DIR";

pub struct PreparedProject {
    root: PathBuf,
    _temp: Option<TempDir>,
    trusted_sdk_sha256: Option<String>,
}

impl PreparedProject {
    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn trusted_sdk_sha256(&self) -> Option<&str> {
        self.trusted_sdk_sha256.as_deref()
    }
}

pub fn prepare_project(project: &Path, policy: &Policy) -> Result<PreparedProject> {
    if !project_uses_trusted_sdk(project)? {
        return Ok(PreparedProject {
            root: project.to_path_buf(),
            _temp: None,
            trusted_sdk_sha256: None,
        });
    }

    let configured = env::var(TRUSTED_SDK_ENV).with_context(|| {
        format!(
            "project imports BeamScale SDK modules but {TRUSTED_SDK_ENV} is not configured by the trusted builder"
        )
    })?;
    let configured = PathBuf::from(configured);
    if !configured.is_absolute() {
        bail!("{TRUSTED_SDK_ENV} must be an absolute path");
    }
    let sdk = fs::canonicalize(&configured)
        .with_context(|| format!("canonicalize trusted SDK {}", configured.display()))?;
    if sdk != configured {
        bail!("{TRUSTED_SDK_ENV} must be canonical and may not traverse symlinks");
    }

    let actual = verify_trusted_sdk(&sdk)?;
    if actual != policy.trusted_sdk_sha256 {
        bail!(
            "trusted SDK digest mismatch: policy requires {}, builder provided {}",
            policy.trusted_sdk_sha256,
            actual
        );
    }

    let temp = tempfile::tempdir().context("create trusted build staging directory")?;
    let staged = temp.path().join("project");
    let staged_sdk = temp.path().join("trusted-sdk");
    copy_project(project, &staged)?;

    // Never build against the mutable host SDK path after admission. Snapshot
    // only the verified build closure into our private staging directory, then
    // re-hash that snapshot before making it visible to Gleam. This closes the
    // verify-then-build TOCTOU window on BMSCL_TRUSTED_SDK_DIR.
    copy_trusted_sdk(&sdk, &staged_sdk)?;
    let staged_actual = verify_trusted_sdk(&staged_sdk)?;
    if staged_actual != actual {
        bail!(
            "trusted SDK changed while being snapshotted: verified {actual}, staged {staged_actual}"
        );
    }
    inject_sdk_dependency(&staged, &staged_sdk)?;

    Ok(PreparedProject {
        root: staged,
        _temp: Some(temp),
        trusted_sdk_sha256: Some(staged_actual),
    })
}

fn project_uses_trusted_sdk(project: &Path) -> Result<bool> {
    for entry in WalkDir::new(project)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored_directory(entry))
    {
        let entry = entry.with_context(|| format!("walk {}", project.display()))?;
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|ext| ext.to_str()) != Some("gleam")
        {
            continue;
        }
        let source = fs::read_to_string(entry.path())?;
        for line in source.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix("import bmscl") else {
                continue;
            };
            if rest.is_empty()
                || rest.starts_with('/')
                || rest.starts_with('.')
                || rest.starts_with('{')
                || rest.chars().next().is_some_and(char::is_whitespace)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn ignored_directory(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() || entry.depth() == 0 {
        return false;
    }
    matches!(
        entry.file_name().to_str(),
        Some(".git" | "build" | "dist" | "node_modules" | "_build" | ".cache" | ".bmscl")
    )
}

fn copy_project(project: &Path, staged: &Path) -> Result<()> {
    fs::create_dir_all(staged)?;
    for entry in WalkDir::new(project)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored_directory(entry))
    {
        let entry = entry.with_context(|| format!("walk {}", project.display()))?;
        let relative = entry.path().strip_prefix(project)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "trusted build staging rejects project symlink {}",
                relative.display()
            );
        }
        let destination = staged.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&destination)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &destination)?;
        }
    }
    Ok(())
}

fn copy_trusted_sdk(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination.join("src"))?;
    fs::copy(source.join("gleam.toml"), destination.join("gleam.toml"))
        .context("snapshot trusted SDK gleam.toml")?;

    let source_src = source.join("src");
    for entry in WalkDir::new(&source_src).follow_links(false) {
        let entry =
            entry.with_context(|| format!("walk trusted SDK snapshot {}", source_src.display()))?;
        let relative = entry.path().strip_prefix(source)?;
        if entry.file_type().is_symlink() {
            bail!(
                "trusted SDK snapshot rejects symlink {}",
                relative.display()
            );
        }
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("gleam") {
                bail!(
                    "trusted SDK snapshot accepts only Gleam source; found {}",
                    relative.display()
                );
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)
                .with_context(|| format!("snapshot trusted SDK {}", relative.display()))?;
        }
    }
    Ok(())
}

fn inject_sdk_dependency(project: &Path, sdk: &Path) -> Result<()> {
    let manifest_path = project.join("gleam.toml");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let mut doc: toml::Value = toml::from_str(&raw).context("parse staged gleam.toml")?;
    let root = doc
        .as_table_mut()
        .context("staged gleam.toml root must be a table")?;
    let dependencies = root
        .entry("dependencies")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .context("gleam.toml dependencies must be a table")?;
    if dependencies.contains_key("bmscl_sdk") {
        bail!("tenant projects may not declare compiler-managed bmscl_sdk");
    }
    let sdk_path = sdk
        .to_str()
        .context("trusted SDK path must be valid UTF-8")?
        .to_owned();
    let mut spec = toml::map::Map::new();
    spec.insert("path".into(), toml::Value::String(sdk_path));
    dependencies.insert("bmscl_sdk".into(), toml::Value::Table(spec));
    fs::write(&manifest_path, toml::to_string_pretty(&doc)?)?;
    Ok(())
}

fn verify_trusted_sdk(sdk: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(sdk)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("trusted SDK root must be a real directory");
    }

    let manifest_path = sdk.join("gleam.toml");
    let manifest_meta = fs::symlink_metadata(&manifest_path)?;
    if manifest_meta.file_type().is_symlink() || !manifest_meta.is_file() {
        bail!("trusted SDK gleam.toml must be a regular non-symlink file");
    }
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest_text =
        std::str::from_utf8(&manifest_bytes).context("trusted SDK gleam.toml must be UTF-8")?;
    let manifest: toml::Value =
        toml::from_str(manifest_text).context("parse trusted SDK gleam.toml")?;
    if manifest.get("name").and_then(toml::Value::as_str) != Some("bmscl_sdk") {
        bail!("trusted SDK package name must be bmscl_sdk");
    }
    if manifest
        .get("target")
        .and_then(toml::Value::as_str)
        .unwrap_or("erlang")
        != "erlang"
    {
        bail!("trusted SDK target must be erlang");
    }
    for table in ["dependencies", "dev_dependencies"] {
        if manifest
            .get(table)
            .and_then(toml::Value::as_table)
            .is_some_and(|dependencies| !dependencies.is_empty())
        {
            bail!("trusted SDK must remain dependency-free; found [{table}]");
        }
    }

    let mut inputs = BTreeMap::new();
    inputs.insert("gleam.toml".to_owned(), manifest_bytes);
    let src = sdk.join("src");
    if !src.is_dir() {
        bail!("trusted SDK is missing src/");
    }
    for entry in WalkDir::new(&src).follow_links(false) {
        let entry = entry.with_context(|| format!("walk trusted SDK {}", src.display()))?;
        if entry.file_type().is_symlink() {
            bail!(
                "trusted SDK source may not contain symlink {}",
                entry.path().display()
            );
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("gleam") {
            bail!(
                "trusted SDK src/ may contain only Gleam source; found {}",
                entry.path().display()
            );
        }
        let relative = entry
            .path()
            .strip_prefix(sdk)?
            .to_string_lossy()
            .replace('\\', "/");
        inputs.insert(relative, fs::read(entry.path())?);
    }
    if inputs.len() <= 1 {
        bail!("trusted SDK contains no Gleam source");
    }

    let mut hasher = Sha256::new();
    for (name, bytes) in inputs {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        hasher.update([0]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::verify_trusted_sdk;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn trusted_sdk_rejects_package_dependencies() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("gleam.toml"),
            "name = \"bmscl_sdk\"\ntarget = \"erlang\"\n[dependencies]\ngleam_stdlib = \">= 1.0.0\"\n",
        )
        .unwrap();
        fs::write(root.path().join("src/bmscl.gleam"), "pub fn ok() { Nil }\n").unwrap();
        assert!(verify_trusted_sdk(root.path()).is_err());
    }

    #[test]
    fn trusted_sdk_snapshot_is_independent_of_original_after_copy() {
        let root = tempdir().unwrap();
        let snapshot = tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("gleam.toml"),
            "name = \"bmscl_sdk\"\ntarget = \"erlang\"\n",
        )
        .unwrap();
        let source = root.path().join("src/bmscl.gleam");
        fs::write(&source, "pub fn ok() { Nil }\n").unwrap();

        super::copy_trusted_sdk(root.path(), snapshot.path()).unwrap();
        let admitted = verify_trusted_sdk(snapshot.path()).unwrap();

        fs::write(&source, "pub fn tampered() { Nil }\n").unwrap();
        assert_eq!(verify_trusted_sdk(snapshot.path()).unwrap(), admitted);
        assert_ne!(verify_trusted_sdk(root.path()).unwrap(), admitted);
    }

    #[test]
    fn trusted_sdk_digest_changes_with_source() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("gleam.toml"),
            "name = \"bmscl_sdk\"\ntarget = \"erlang\"\n",
        )
        .unwrap();
        let source = root.path().join("src/bmscl.gleam");
        fs::write(&source, "pub fn ok() { Nil }\n").unwrap();
        let before = verify_trusted_sdk(root.path()).unwrap();
        fs::write(&source, "pub fn changed() { Nil }\n").unwrap();
        let after = verify_trusted_sdk(root.path()).unwrap();
        assert_ne!(before, after);
    }
}
