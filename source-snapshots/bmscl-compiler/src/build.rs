use crate::{
    analyze::check_project_with_cache,
    model::{
        ArtifactManifest, BuildProvenance, Policy, CONTEXT_ABI_V1, MODULE_CONTRACT_V1,
        PROVENANCE_FORMAT_V1,
    },
    policy::{capability_grants, effective_limits, load_worker_config},
    safety_cache::VerifiedSafetyCache,
    trusted_sdk,
};
use anyhow::{bail, Context, Result};
use flate2::{Compression, GzBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;

#[derive(Debug, Serialize)]
struct PackageDigests {
    format_version: u32,
    worker_tar_gz_sha256: String,
    worker_zip_sha256: String,
}

pub fn build_project(
    project: &Path,
    out_dir: &Path,
    policy: &Policy,
    worker_config_path: Option<&Path>,
    deny_cpu_loops: bool,
    safety_cache: Option<&VerifiedSafetyCache>,
) -> Result<()> {
    let report = check_project_with_cache(
        project,
        policy,
        worker_config_path,
        deny_cpu_loops,
        safety_cache,
    )?;
    fs::create_dir_all(out_dir)?;
    remove_if_exists(&out_dir.join("attestation.json"))?;
    remove_if_exists(&out_dir.join("provenance.json"))?;
    remove_if_exists(&out_dir.join("worker.tar.gz"))?;
    remove_if_exists(&out_dir.join("worker.zip"))?;
    remove_if_exists(&out_dir.join("package-digests.json"))?;
    fs::write(
        out_dir.join("admission-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    if !report.admitted {
        bail!("worker rejected; see admission-report.json");
    }

    // Tenant admission is complete before any trusted SDK code is introduced.
    // Build in an ephemeral copy so customer source and dependency evidence are
    // never mutated by the compiler-managed SDK injection.
    let prepared = trusted_sdk::prepare_project(project, policy)?;
    let build_project = prepared.path();

    let status = Command::new("gleam")
        .args(["build", "--target", "erlang"])
        .current_dir(build_project)
        .status()
        .context("launch `gleam build --target erlang`; install/pin Gleam in the build image")?;
    if !status.success() {
        bail!("gleam build failed with {status}");
    }

    let package_name = package_name(build_project)?;
    let package_root = build_project
        .join("build")
        .join("dev")
        .join("erlang")
        .join(&package_name);
    let artefacts = package_root.join("_gleam_artefacts");
    if !artefacts.is_dir() {
        bail!(
            "Gleam build did not produce expected generated Erlang: {}",
            artefacts.display()
        );
    }

    verify_generated_erlang(&artefacts, policy)?;
    let beam_dir = out_dir.join("beam");
    copy_worker_beams(&package_root, &beam_dir)?;
    if prepared.trusted_sdk_sha256().is_some() {
        let sdk_package_root = build_project
            .join("build")
            .join("dev")
            .join("erlang")
            .join("bmscl_sdk");
        append_trusted_sdk_beams(&sdk_package_root, &beam_dir)?;
    }
    verify_beam_imports(&beam_dir)?;
    let build_sha256 = digest_tree(&beam_dir)?;
    let (worker_config, _) = load_worker_config(project, worker_config_path)?;

    let provenance = collect_provenance(
        project,
        policy,
        &report.source_sha256,
        &build_sha256,
        prepared.trusted_sdk_sha256(),
    )?;
    let provenance_bytes = serde_json::to_vec_pretty(&provenance)?;
    let provenance_sha256 = sha256_bytes(&provenance_bytes);
    fs::write(out_dir.join("provenance.json"), provenance_bytes)?;

    let manifest = ArtifactManifest {
        format_version: 2,
        runtime: "beam",
        language: "gleam",
        profile: policy.policy_version.clone(),
        module_contract_version: MODULE_CONTRACT_V1,
        context_abi: CONTEXT_ABI_V1,
        source_sha256: report.source_sha256,
        build_sha256,
        provenance_sha256,
        entrypoint: "worker:handle/2".into(),
        capabilities: capability_grants(&worker_config),
        runtime_limits: effective_limits(policy, &worker_config),
        durable: worker_config.durable.clone(),
    };
    fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!("admitted and built worker into {}", out_dir.display());
    Ok(())
}

fn collect_provenance(
    project: &Path,
    policy: &Policy,
    source_sha256: &str,
    build_sha256: &str,
    trusted_sdk_sha256: Option<&str>,
) -> Result<BuildProvenance> {
    let policy_bytes = serde_json::to_vec(policy).context("serialize effective policy")?;
    let dependency_lock_sha256 = optional_file_sha256(&project.join("manifest.toml"))?;
    let gleam_raw = tool_version("gleam", &["--version"])?;
    let gleam_version = gleam_raw
        .strip_prefix("gleam ")
        .unwrap_or(&gleam_raw)
        .to_string();

    Ok(BuildProvenance {
        format: PROVENANCE_FORMAT_V1,
        builder_id: env::var("BMSCL_BUILDER_ID").unwrap_or_else(|_| "local-untrusted".into()),
        builder_image_digest: env::var("BMSCL_BUILDER_IMAGE_DIGEST")
            .unwrap_or_else(|_| "local-untracked".into()),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        compiler_revision: env::var("BMSCL_COMPILER_REVISION")
            .unwrap_or_else(|_| "local-untracked".into()),
        gleam_version,
        otp_release: erlang_system_info("otp_release")?,
        erts_version: erlang_system_info("version")?,
        policy_sha256: sha256_bytes(&policy_bytes),
        dependency_lock_sha256,
        trusted_sdk_sha256: trusted_sdk_sha256.map(str::to_string),
        source_sha256: source_sha256.into(),
        build_sha256: build_sha256.into(),
    })
}

fn tool_version(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("launch `{program}` to record build provenance"))?;
    if !output.status.success() {
        bail!("`{program}` failed while collecting build provenance");
    }
    Ok(String::from_utf8(output.stdout)
        .context("tool version output was not UTF-8")?
        .trim()
        .to_string())
}

fn erlang_system_info(key: &str) -> Result<String> {
    let eval = format!("io:format(\"~s\", [erlang:system_info({key})]), halt(0).");
    let output = Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
        .context("launch Erlang to record build provenance")?;
    if !output.status.success() {
        bail!("Erlang failed while collecting build provenance for `{key}`");
    }
    Ok(String::from_utf8(output.stdout)
        .context("Erlang provenance output was not UTF-8")?
        .trim()
        .to_string())
}

pub fn package_project(out_dir: &Path) -> Result<()> {
    let entries = artifact_entries(out_dir)?;
    let tar_path = out_dir.join("worker.tar.gz");
    let zip_path = out_dir.join("worker.zip");

    write_tar_gz(&tar_path, &entries)?;
    write_zip(&zip_path, &entries)?;

    let digests = PackageDigests {
        format_version: 2,
        worker_tar_gz_sha256: sha256_file(&tar_path)?,
        worker_zip_sha256: sha256_file(&zip_path)?,
    };
    fs::write(
        out_dir.join("package-digests.json"),
        serde_json::to_vec_pretty(&digests)?,
    )?;

    println!("packaged {}", tar_path.display());
    println!("packaged {}", zip_path.display());
    println!("wrote {}", out_dir.join("package-digests.json").display());
    Ok(())
}

fn artifact_entries(out_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut entries = vec![
        (
            "admission-report.json".to_string(),
            out_dir.join("admission-report.json"),
        ),
        ("manifest.json".to_string(), out_dir.join("manifest.json")),
        (
            "provenance.json".to_string(),
            out_dir.join("provenance.json"),
        ),
    ];
    let attestation = out_dir.join("attestation.json");
    if attestation.is_file() {
        entries.push(("attestation.json".to_string(), attestation));
    }

    for entry in WalkDir::new(out_dir.join("beam"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        let name = entry.file_name().to_string_lossy();
        entries.push((format!("beam/{name}"), entry.into_path()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    for (archive_path, source) in &entries {
        if !source.is_file() {
            bail!(
                "package input missing: {archive_path} ({})",
                source.display()
            );
        }
    }
    Ok(entries)
}

fn write_tar_gz(path: &Path, entries: &[(String, PathBuf)]) -> Result<()> {
    let file = File::create(path)?;
    let encoder = GzBuilder::new().mtime(0).write(file, Compression::best());
    let mut tar = tar::Builder::new(encoder);
    for (archive_path, source) in entries {
        append_tar_file(&mut tar, source, Path::new(archive_path))?;
    }
    tar.finish()?;
    Ok(())
}

fn write_zip(path: &Path, entries: &[(String, PathBuf)]) -> Result<()> {
    let file = File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644)
        .last_modified_time(zip::DateTime::default());
    for (archive_path, source) in entries {
        zip.start_file(archive_path, options)?;
        let bytes = fs::read(source)?;
        zip.write_all(&bytes)?;
    }
    zip.finish()?;
    Ok(())
}

fn package_name(project: &Path) -> Result<String> {
    let path = project.join("gleam.toml");
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read package manifest {}", path.display()))?;
    let doc: toml::Value = toml::from_str(&raw).context("parse gleam.toml")?;
    doc.get("name")
        .and_then(toml::Value::as_str)
        .map(str::to_string)
        .context("gleam.toml must contain a package name")
}

fn is_launcher(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains("@@main."))
}

fn verify_generated_erlang(artefacts: &Path, policy: &Policy) -> Result<()> {
    for entry in WalkDir::new(artefacts).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if is_launcher(path) || path.extension().and_then(|ext| ext.to_str()) != Some("erl") {
            continue;
        }
        let source = fs::read_to_string(path)?;
        for pattern in &policy.forbidden_erlang_patterns {
            if source.contains(pattern) {
                bail!(
                    "generated Erlang verification failed: {} contains forbidden `{}`",
                    path.display(),
                    pattern
                );
            }
        }
    }
    Ok(())
}

fn copy_worker_beams(package_root: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;
    let mut copied = 0usize;
    for entry in WalkDir::new(package_root)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if is_launcher(path) || path.extension().and_then(|ext| ext.to_str()) != Some("beam") {
            continue;
        }
        let name = path.file_name().context("beam file name")?;
        fs::copy(path, destination.join(name))?;
        copied += 1;
    }
    if copied == 0 {
        bail!(
            "no worker BEAM modules were produced beneath {}",
            package_root.display()
        );
    }
    Ok(())
}

fn append_trusted_sdk_beams(package_root: &Path, destination: &Path) -> Result<()> {
    if !package_root.is_dir() {
        bail!(
            "trusted SDK build output is missing: {}",
            package_root.display()
        );
    }

    let mut copied = 0usize;
    let mut has_root_module = false;
    for entry in WalkDir::new(package_root)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if is_launcher(path) || path.extension().and_then(|ext| ext.to_str()) != Some("beam") {
            continue;
        }
        let name = path.file_name().context("trusted SDK beam file name")?;
        if name == std::ffi::OsStr::new("bmscl.beam") {
            has_root_module = true;
        }
        let target = destination.join(name);
        if target.exists() {
            bail!(
                "trusted SDK module collides with worker artifact module: {}",
                name.to_string_lossy()
            );
        }
        fs::copy(path, &target)?;
        copied += 1;
    }
    if copied == 0 || !has_root_module {
        bail!(
            "trusted SDK output must contain bmscl.beam beneath {}",
            package_root.display()
        );
    }
    Ok(())
}

pub(crate) fn verify_beam_imports(beam_dir: &Path) -> Result<()> {
    let mut checked = 0usize;
    for entry in WalkDir::new(beam_dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("beam") {
            continue;
        }
        checked += 1;
        let path_string = path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let eval = format!(
            "case beam_lib:chunks(\"{}\", [imports]) of {{ok,{{_,[{{imports,I}}]}}}} -> lists:foreach(fun({{M,F,A}}) -> io:format(\"~s:~s/~p~n\", [atom_to_list(M), atom_to_list(F), A]) end, I), halt(0); E -> io:format(\"ERROR ~p~n\", [E]), halt(2) end.",
            path_string
        );
        let output = Command::new("erl")
            .args(["-noshell", "-eval", &eval])
            .output()
            .with_context(|| format!("inspect BEAM imports for {}", path.display()))?;
        if !output.status.success() {
            bail!(
                "beam_lib import inspection failed for {}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for import in String::from_utf8_lossy(&output.stdout).lines() {
            if forbidden_beam_import(import) {
                bail!(
                    "BEAM import verification failed: {} imports forbidden `{}`",
                    path.display(),
                    import
                );
            }
        }
    }
    if checked == 0 {
        bail!("artifact contains no BEAM modules");
    }
    Ok(())
}

pub(crate) fn forbidden_beam_import(import: &str) -> bool {
    [
        "os:",
        "file:",
        "code:",
        "erl_ddll:",
        "net_kernel:",
        "rpc:",
        "erpc:",
        "global:",
        "persistent_term:",
        "ets:",
        "dets:",
        "mnesia:",
        "disk_log:",
        "application:",
        "init:",
        "sys:",
        "proc_lib:",
        "gen_server:",
        "gen_statem:",
        "supervisor:",
        "timer:apply",
        "gen_tcp:",
        "gen_udp:",
        "socket:",
        "ssl:",
        "httpc:",
        "inets:",
        "erlang:spawn",
        "erlang:apply/",
        "erlang:make_fun/",
        "erlang:halt/",
        "erlang:open_port/",
        "erlang:port_command/",
        "erlang:load_nif/",
        "erlang:whereis/",
        "erlang:register/",
        "erlang:unregister/",
        "erlang:processes/",
        "erlang:process_info/",
        "erlang:process_flag/",
        "erlang:link/",
        "erlang:unlink/",
        "erlang:monitor/",
        "erlang:demonitor/",
        "erlang:exit/2",
        "erlang:send/",
        "erlang:send_after/",
        "erlang:start_timer/",
        "erlang:group_leader/",
        "erlang:binary_to_atom/",
        "erlang:list_to_atom/",
    ]
    .iter()
    .any(|prefix| import.starts_with(prefix))
}

pub(crate) fn digest_tree(root: &Path) -> Result<String> {
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        entries.insert(rel, fs::read(entry.path())?);
    }
    let mut hasher = Sha256::new();
    for (name, bytes) in entries {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        hasher.update([0]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn append_tar_file<W: Write>(
    tar: &mut tar::Builder<W>,
    source: &Path,
    archive_path: &Path,
) -> Result<()> {
    let mut file = File::open(source)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, archive_path, bytes.as_slice())?;
    Ok(())
}

fn optional_file_sha256(path: &Path) -> Result<Option<String>> {
    if path.is_file() {
        Ok(Some(sha256_file(path)?))
    } else {
        Ok(None)
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_bytes(&fs::read(path)?))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove stale {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_trusted_sdk_beams, digest_tree, forbidden_beam_import, package_project, sha256_bytes,
    };
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn trusted_sdk_beams_are_bundled_and_collision_checked() {
        let package = tempdir().unwrap();
        let destination = tempdir().unwrap();
        fs::write(package.path().join("bmscl.beam"), b"sdk-root").unwrap();
        fs::write(package.path().join("bmscl@cluster.beam"), b"sdk-cluster").unwrap();

        append_trusted_sdk_beams(package.path(), destination.path()).unwrap();
        assert_eq!(
            fs::read(destination.path().join("bmscl.beam")).unwrap(),
            b"sdk-root"
        );
        assert_eq!(
            fs::read(destination.path().join("bmscl@cluster.beam")).unwrap(),
            b"sdk-cluster"
        );

        let error = append_trusted_sdk_beams(package.path(), destination.path()).unwrap_err();
        assert!(error.to_string().contains("collides"));
    }

    #[test]
    fn rejects_privileged_beam_imports() {
        assert!(forbidden_beam_import("file:read_file/1"));
        assert!(forbidden_beam_import("erlang:open_port/2"));
        assert!(forbidden_beam_import("erlang:spawn/1"));
        assert!(forbidden_beam_import("erlang:spawn_link/1"));
        assert!(forbidden_beam_import("erlang:spawn_monitor/1"));
        assert!(forbidden_beam_import("erlang:spawn_opt/2"));
        assert!(forbidden_beam_import("erlang:apply/3"));
        assert!(forbidden_beam_import("erlang:whereis/1"));
        assert!(forbidden_beam_import("erlang:send/2"));
        assert!(forbidden_beam_import("proc_lib:spawn/1"));
        assert!(forbidden_beam_import("gen_server:start_link/3"));
        assert!(forbidden_beam_import("gen_statem:start/3"));
        assert!(forbidden_beam_import("supervisor:start_child/2"));
        assert!(forbidden_beam_import("gen_tcp:connect/3"));
        assert!(!forbidden_beam_import("erlang:length/1"));
    }

    #[test]
    fn packaging_emits_tar_zip_and_digests() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("beam")).unwrap();
        fs::write(dir.path().join("manifest.json"), b"{}\n").unwrap();
        fs::write(dir.path().join("admission-report.json"), b"{}\n").unwrap();
        fs::write(dir.path().join("provenance.json"), b"{}\n").unwrap();
        fs::write(dir.path().join("beam/worker.beam"), b"beam").unwrap();
        package_project(dir.path()).unwrap();
        assert!(dir.path().join("worker.tar.gz").is_file());
        assert!(dir.path().join("worker.zip").is_file());
        let digests = fs::read_to_string(dir.path().join("package-digests.json")).unwrap();
        assert!(digests.contains("worker_tar_gz_sha256"));
        assert!(digests.contains("worker_zip_sha256"));
    }

    #[test]
    fn tree_digest_is_stable_by_relative_path() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("b.beam"), b"b").unwrap();
        fs::write(dir.path().join("a.beam"), b"a").unwrap();
        let first = digest_tree(dir.path()).unwrap();
        let second = digest_tree(dir.path()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn sha256_bytes_is_stable() {
        assert_eq!(
            sha256_bytes(b"beamscale"),
            "eecabee7521c6fcce50b2484769b71497d1c10a8d05ff58349664fa35b893c76"
        );
    }
}
