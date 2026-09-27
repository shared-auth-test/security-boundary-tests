use crate::{attestation::sign_artifact, build::digest_tree};
use anyhow::{bail, Context, Result};
use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io,
    path::{Component, Path, PathBuf},
};
use tar::Builder;
use walkdir::WalkDir;

pub const PHOENIX_PROFILE_V1: &str = "bmscl-phoenix-elixir-v1";
pub const PHOENIX_RELEASE_FORMAT_V1: &str = "bmscl-phoenix-release-v1";
const MAX_RELEASE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ROUTE_PLAN_BYTES: u64 = 2 * 1024 * 1024;
const PHOENIX_DISCOVERY_V2: &str = "bmscl.phoenix.discovery.v2";

#[derive(Debug, Clone)]
pub struct PhoenixReleaseOptions {
    pub release_dir: PathBuf,
    pub out_dir: PathBuf,
    pub app: String,
    pub version: String,
    pub router: String,
    pub endpoint: String,
    pub route_plan: PathBuf,
    pub source_sha256: String,
    pub builder_image_digest: String,
    pub signing_key: Option<PathBuf>,
    pub key_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PhoenixManifest {
    format_version: u32,
    artifact_format: String,
    artifact_root: String,
    runtime: String,
    language: String,
    profile: String,
    execution_class: String,
    isolation_class: String,
    source_sha256: String,
    build_sha256: String,
    provenance_sha256: String,
    app: String,
    version: String,
    router: String,
    endpoint: String,
    route_plan_sha256: String,
}

#[derive(Debug, Serialize)]
struct PhoenixAdmissionReport {
    admitted: bool,
    policy_version: &'static str,
    source_sha256: String,
    findings: Vec<serde_json::Value>,
    execution_class: &'static str,
    isolation_class: &'static str,
    route_plan_sha256: String,
}

#[derive(Debug, Serialize)]
struct PhoenixProvenance {
    format: &'static str,
    builder_image_digest: String,
    compiler_version: &'static str,
    compiler_revision: String,
    policy_sha256: String,
    source_sha256: String,
    build_sha256: String,
}

#[derive(Debug, Deserialize)]
struct PhoenixDiscoverySummary {
    schema_version: String,
    router: String,
    endpoint: Option<String>,
    build_granularity: String,
    isolation_class: String,
}

pub fn admit_release(options: PhoenixReleaseOptions) -> Result<()> {
    validate_identifier("app", &options.app)?;
    validate_version(&options.version)?;
    validate_module("router", &options.router)?;
    validate_module("endpoint", &options.endpoint)?;
    validate_sha256(&options.source_sha256, "source_sha256")?;
    validate_image_digest(&options.builder_image_digest)?;
    let route_plan_bytes = read_regular_bounded(
        &options.route_plan,
        MAX_ROUTE_PLAN_BYTES,
        "Phoenix route plan",
    )?;
    let route_plan = validate_route_plan(&route_plan_bytes, &options.router, &options.endpoint)?;
    let route_plan_sha256 = sha256_hex(&route_plan_bytes);
    debug_assert_eq!(route_plan.schema_version, PHOENIX_DISCOVERY_V2);
    match (&options.signing_key, &options.key_id) {
        (Some(_), None) | (None, Some(_)) => {
            bail!("--signing-key and --key-id must be supplied together")
        }
        _ => {}
    }

    let input_meta = fs::symlink_metadata(&options.release_dir)
        .with_context(|| format!("inspect {}", options.release_dir.display()))?;
    if input_meta.file_type().is_symlink() || !input_meta.is_dir() {
        bail!("--release-dir must be a regular non-symlink directory");
    }
    let release_dir = options
        .release_dir
        .canonicalize()
        .with_context(|| format!("resolve {}", options.release_dir.display()))?;
    verify_release_layout(&release_dir, &options.app, &options.version)?;

    if options.out_dir.exists() {
        let meta = fs::symlink_metadata(&options.out_dir)
            .with_context(|| format!("inspect {}", options.out_dir.display()))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            bail!("--out-dir must be a regular directory when it already exists");
        }
        if fs::read_dir(&options.out_dir)?.next().is_some() {
            bail!("--out-dir must be empty; refusing to delete existing content");
        }
    } else {
        fs::create_dir_all(&options.out_dir)?;
    }
    let out_canonical = options
        .out_dir
        .canonicalize()
        .with_context(|| format!("resolve {}", options.out_dir.display()))?;
    if out_canonical.starts_with(&release_dir) || release_dir.starts_with(&out_canonical) {
        bail!("--out-dir and --release-dir must not contain one another");
    }
    let staged = options.out_dir.join("release");
    copy_release_tree(&release_dir, &staged)?;
    verify_release_layout(&staged, &options.app, &options.version)?;
    fs::write(options.out_dir.join("route-plan.json"), &route_plan_bytes)?;

    let build_sha256 = digest_tree(&staged)?;
    let provenance = PhoenixProvenance {
        format: "bmscl-phoenix-build-provenance-v1",
        builder_image_digest: options.builder_image_digest,
        compiler_version: env!("CARGO_PKG_VERSION"),
        compiler_revision: std::env::var("BMSCL_COMPILER_REVISION")
            .unwrap_or_else(|_| "local-untracked".into()),
        policy_sha256: phoenix_policy_sha256(),
        source_sha256: options.source_sha256.clone(),
        build_sha256: build_sha256.clone(),
    };
    let provenance_bytes =
        serde_json::to_vec_pretty(&provenance).context("serialize Phoenix provenance")?;
    let provenance_sha256 = sha256_hex(&provenance_bytes);
    fs::write(options.out_dir.join("provenance.json"), provenance_bytes)?;

    let report = PhoenixAdmissionReport {
        admitted: true,
        policy_version: PHOENIX_PROFILE_V1,
        source_sha256: options.source_sha256.clone(),
        findings: Vec::new(),
        execution_class: "phoenix",
        isolation_class: "firecracker",
        route_plan_sha256: route_plan_sha256.clone(),
    };
    fs::write(
        options.out_dir.join("admission-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;

    let manifest = PhoenixManifest {
        format_version: 1,
        artifact_format: PHOENIX_RELEASE_FORMAT_V1.into(),
        artifact_root: "release".into(),
        runtime: "beam_release".into(),
        language: "elixir".into(),
        profile: PHOENIX_PROFILE_V1.into(),
        execution_class: "phoenix".into(),
        isolation_class: "firecracker".into(),
        source_sha256: options.source_sha256,
        build_sha256,
        provenance_sha256,
        app: options.app,
        version: options.version,
        router: options.router,
        endpoint: options.endpoint,
        route_plan_sha256,
    };
    fs::write(
        options.out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    if let (Some(key), Some(key_id)) = (options.signing_key.as_deref(), options.key_id.as_deref()) {
        sign_artifact(&options.out_dir, key_id, key)?;
    }
    package_release(&options.out_dir)?;
    Ok(())
}

pub fn artifact_root_from_dir(artifact_dir: &Path) -> Result<String> {
    let bytes = fs::read(artifact_dir.join("manifest.json")).context("read manifest.json")?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).context("parse manifest.json")?;
    Ok(json
        .get("artifact_root")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("beam")
        .to_string())
}

pub fn verify_release_artifact_dir(artifact_dir: &Path) -> Result<()> {
    let bytes = fs::read(artifact_dir.join("manifest.json")).context("read manifest.json")?;
    let manifest: PhoenixManifest =
        serde_json::from_slice(&bytes).context("parse Phoenix manifest")?;
    if manifest.artifact_format != PHOENIX_RELEASE_FORMAT_V1
        || manifest.artifact_root != "release"
        || manifest.runtime != "beam_release"
        || manifest.language != "elixir"
        || manifest.profile != PHOENIX_PROFILE_V1
        || manifest.execution_class != "phoenix"
        || manifest.isolation_class != "firecracker"
    {
        bail!("artifact is not a supported Firecracker Phoenix release");
    }
    validate_identifier("app", &manifest.app)?;
    validate_version(&manifest.version)?;
    validate_module("router", &manifest.router)?;
    validate_module("endpoint", &manifest.endpoint)?;
    validate_sha256(&manifest.source_sha256, "source_sha256")?;
    validate_sha256(&manifest.build_sha256, "build_sha256")?;
    validate_sha256(&manifest.provenance_sha256, "provenance_sha256")?;
    validate_sha256(&manifest.route_plan_sha256, "route_plan_sha256")?;
    let route_plan_bytes = read_regular_bounded(
        &artifact_dir.join("route-plan.json"),
        MAX_ROUTE_PLAN_BYTES,
        "Phoenix route plan",
    )?;
    let route_plan_sha256 = sha256_hex(&route_plan_bytes);
    if route_plan_sha256 != manifest.route_plan_sha256 {
        bail!("Phoenix route plan digest does not match manifest");
    }
    validate_route_plan(&route_plan_bytes, &manifest.router, &manifest.endpoint)?;
    verify_release_layout(
        &artifact_dir.join("release"),
        &manifest.app,
        &manifest.version,
    )?;
    let actual = digest_tree(&artifact_dir.join("release"))?;
    if actual != manifest.build_sha256 {
        bail!("Phoenix release tree digest does not match manifest");
    }
    Ok(())
}

pub fn package_release(out_dir: &Path) -> Result<()> {
    verify_release_artifact_dir(out_dir)?;
    let archive = out_dir.join("phoenix-release.tar.gz");
    if archive.exists() {
        fs::remove_file(&archive)?;
    }

    let file = File::create(&archive)?;
    let encoder = GzBuilder::new().mtime(0).write(file, Compression::best());
    let mut tar = Builder::new(encoder);

    for name in [
        "manifest.json",
        "admission-report.json",
        "provenance.json",
        "route-plan.json",
        "attestation.json",
    ] {
        let path = out_dir.join(name);
        if path.is_file() {
            append_file(&mut tar, &path, Path::new(name))?;
        }
    }

    let mut files = WalkDir::new(out_dir.join("release"))
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    files.sort_by(|a, b| a.path().cmp(b.path()));
    for entry in files {
        if entry.file_type().is_dir() {
            continue;
        }
        let source = entry.path();
        let relative = source.strip_prefix(out_dir)?;
        append_file(&mut tar, source, relative)?;
    }
    tar.finish()?;
    Ok(())
}

fn validate_route_plan(
    bytes: &[u8],
    expected_router: &str,
    expected_endpoint: &str,
) -> Result<PhoenixDiscoverySummary> {
    let plan: PhoenixDiscoverySummary =
        serde_json::from_slice(bytes).context("parse Phoenix discovery plan")?;
    if plan.schema_version != PHOENIX_DISCOVERY_V2 {
        bail!(
            "unsupported Phoenix discovery schema `{}`; expected {PHOENIX_DISCOVERY_V2}",
            plan.schema_version
        );
    }
    if plan.router != expected_router {
        bail!("Phoenix discovery router does not match packaged router");
    }
    if plan.endpoint.as_deref() != Some(expected_endpoint) {
        bail!("Phoenix discovery endpoint does not match packaged endpoint");
    }
    if plan.build_granularity != "application_generation" {
        bail!("Phoenix discovery plan must use application_generation build granularity");
    }
    if plan.isolation_class != "firecracker" {
        bail!("Phoenix discovery plan must require firecracker isolation");
    }
    Ok(plan)
}

fn read_regular_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("{label} must be a regular non-symlink file");
    }
    if meta.len() > max_bytes {
        bail!("{label} exceeds {max_bytes} bytes");
    }
    fs::read(path).with_context(|| format!("read {label} {}", path.display()))
}

fn verify_release_layout(root: &Path, app: &str, version: &str) -> Result<()> {
    let meta = fs::symlink_metadata(root)
        .with_context(|| format!("inspect release root {}", root.display()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!("Phoenix release root must be a regular non-symlink directory");
    }

    let bin = root.join("bin").join(app);
    require_regular_file(&bin)?;
    let boot = root.join("releases").join(version).join("start.boot");
    require_regular_file(&boot)?;

    let mut total = 0u64;
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            bail!(
                "symlinks are forbidden in Phoenix releases: {}",
                path.display()
            );
        }
        if meta.is_file() {
            total = total
                .checked_add(meta.len())
                .context("Phoenix release byte count overflow")?;
            if total > MAX_RELEASE_BYTES {
                bail!("Phoenix release exceeds {} bytes", MAX_RELEASE_BYTES);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o6000 != 0 {
                    bail!(
                        "setuid/setgid file forbidden in Phoenix release: {}",
                        path.display()
                    );
                }
            }
        } else if !meta.is_dir() {
            bail!(
                "special files are forbidden in Phoenix releases: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn copy_release_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let mut entries = WalkDir::new(source)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by(|a, b| a.path().cmp(b.path()));

    for entry in entries {
        let path = entry.path();
        if path == source {
            continue;
        }
        let relative = path.strip_prefix(source)?;
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            bail!("invalid Phoenix release path {}", relative.display());
        }
        let target = destination.join(relative);
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            bail!(
                "symlinks are forbidden in Phoenix releases: {}",
                path.display()
            );
        } else if meta.is_dir() {
            fs::create_dir_all(&target)?;
        } else if meta.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(path, &target)?;
            fs::set_permissions(&target, meta.permissions())?;
        } else {
            bail!(
                "special files are forbidden in Phoenix releases: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn append_file<W: io::Write>(
    tar: &mut Builder<W>,
    source: &Path,
    archive_path: &Path,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    let meta = fs::metadata(source)?;
    header.set_size(meta.len());
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        header.set_mode(meta.permissions().mode() & 0o777);
    }
    #[cfg(not(unix))]
    header.set_mode(0o644);
    header.set_cksum();
    let mut file = File::open(source)?;
    tar.append_data(&mut header, archive_path, &mut file)?;
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("required Phoenix release file missing: {}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!(
            "required Phoenix release path is not a regular file: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        bail!("{field} must match [A-Za-z0-9_-] and be 1..=128 bytes");
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
    {
        bail!("version contains unsupported characters");
    }
    Ok(())
}

fn validate_module(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.split('.').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    {
        bail!("{field} must be a dotted Elixir module name");
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("{field} must be a lowercase 64-character SHA-256 hex digest");
    }
    Ok(())
}

fn validate_image_digest(value: &str) -> Result<()> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        bail!("builder_image_digest must use sha256:<64 lowercase hex>");
    };
    validate_sha256(digest, "builder_image_digest")
}

fn phoenix_policy_sha256() -> String {
    sha256_hex(
        b"bmscl-phoenix-elixir-v1\nfirecracker\nbeam-process-spawn=allowed\nos-process-spawn=denied\nnative-code=denied\n",
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture(root: &Path) {
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("releases/1.2.3")).unwrap();
        fs::write(root.join("bin/demo"), b"#!/bin/sh\n").unwrap();
        fs::write(root.join("releases/1.2.3/start.boot"), b"boot").unwrap();
        fs::create_dir_all(root.join("lib/demo-1.2.3/ebin")).unwrap();
        fs::write(root.join("lib/demo-1.2.3/ebin/demo.beam"), b"beam").unwrap();
    }

    #[test]
    fn validates_release_shape_and_digest() {
        let dir = tempdir().unwrap();
        fixture(dir.path());
        verify_release_layout(dir.path(), "demo", "1.2.3").unwrap();
        assert_eq!(digest_tree(dir.path()).unwrap().len(), 64);
    }

    #[test]
    fn rejects_symlinked_release_files() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = tempdir().unwrap();
            fixture(dir.path());
            fs::remove_file(dir.path().join("bin/demo")).unwrap();
            symlink("/bin/sh", dir.path().join("bin/demo")).unwrap();
            assert!(verify_release_layout(dir.path(), "demo", "1.2.3").is_err());
        }
    }

    #[test]
    fn route_plan_is_bound_to_router_endpoint_and_firecracker() {
        let bytes = br#"{
          "schema_version": "bmscl.phoenix.discovery.v2",
          "router": "DemoWeb.Router",
          "endpoint": "DemoWeb.Endpoint",
          "build_granularity": "application_generation",
          "isolation_class": "firecracker",
          "routes": [],
          "connections": []
        }"#;
        let plan = validate_route_plan(bytes, "DemoWeb.Router", "DemoWeb.Endpoint").unwrap();
        assert_eq!(plan.schema_version, PHOENIX_DISCOVERY_V2);
        assert!(validate_route_plan(bytes, "Other.Router", "DemoWeb.Endpoint").is_err());

        let wrong_isolation = bytes
            .windows(b"firecracker".len())
            .position(|window| window == b"firecracker")
            .unwrap();
        let mut tampered = bytes.to_vec();
        tampered.splice(
            wrong_isolation..wrong_isolation + b"firecracker".len(),
            b"bareprocess".iter().copied(),
        );
        assert!(validate_route_plan(&tampered, "DemoWeb.Router", "DemoWeb.Endpoint").is_err());
    }

    #[test]
    fn policy_is_bound_to_firecracker_authority() {
        assert_eq!(phoenix_policy_sha256().len(), 64);
        assert!(validate_image_digest(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(validate_image_digest("latest").is_err());
    }
}
