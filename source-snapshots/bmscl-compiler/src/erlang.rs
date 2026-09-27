use crate::{
    build::digest_tree,
    model::{
        AdmissionReport, ArtifactManifest, BuildProvenance, Policy, CONTEXT_ABI_V1,
        ERLANG_CRITICAL_SECTION_PROFILE_V1, MODULE_CONTRACT_V1, PROVENANCE_FORMAT_V1,
    },
    policy::{capability_grants, check_worker_config, effective_limits, load_worker_config},
};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use walkdir::WalkDir;

pub fn build_erlang_critical_section(
    project: &Path,
    out_dir: &Path,
    policy: &Policy,
    worker_config_path: Option<&Path>,
) -> Result<()> {
    let mut policy = policy.clone();
    policy.policy_version = ERLANG_CRITICAL_SECTION_PROFILE_V1.into();
    policy.max_processes = 1;

    let (worker_config, config_path) = load_worker_config(project, worker_config_path)?;
    if worker_config.durable.is_some() {
        bail!(
            "{}: [durable] belongs to the general Durable Actor profile; critical-section namespace and sharding are deployment-owned",
            config_path.display()
        );
    }
    if !worker_config.permissions.is_empty() {
        bail!("Erlang critical-section v1 does not admit ambient network permissions");
    }
    for (name, value) in &worker_config.security {
        if value != "deny" {
            bail!("security setting {name} must remain deny");
        }
    }

    let mut config_findings = Vec::new();
    check_worker_config(&worker_config, &config_path, &policy, &mut config_findings);
    if !config_findings.is_empty() {
        let messages = config_findings
            .iter()
            .map(|finding| format!("{}: {}", finding.code, finding.message))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("Erlang critical-section worker config rejected: {messages}");
    }

    let sources = collect_sources(project)?;
    validate_sources(&sources, &policy)?;
    let source_sha256 = digest_sources(project, &sources)?;

    clean_output(out_dir)?;
    let beam_dir = out_dir.join("beam");
    fs::create_dir_all(&beam_dir)?;
    compile_sources(&beam_dir, &sources)?;
    verify_worker_export(&beam_dir.join("worker.beam"))?;
    let build_sha256 = digest_tree(&beam_dir)?;

    let runtime_limits = effective_limits(&policy, &worker_config);
    let report = AdmissionReport {
        admitted: true,
        policy_version: policy.policy_version.clone(),
        source_sha256: source_sha256.clone(),
        findings: vec![],
        runtime_limits: runtime_limits.clone(),
        safety_cache_sha256: None,
        safety_analysis_policy_sha256: None,
        safety_cache_key_id: None,
        durable: None,
    };
    fs::write(
        out_dir.join("admission-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;

    let provenance = erlang_provenance(project, &policy, &source_sha256, &build_sha256)?;
    let provenance_bytes = serde_json::to_vec_pretty(&provenance)?;
    let provenance_sha256 = sha256_bytes(&provenance_bytes);
    fs::write(out_dir.join("provenance.json"), provenance_bytes)?;

    let manifest = ArtifactManifest {
        format_version: 2,
        runtime: "beam",
        language: "erlang",
        profile: ERLANG_CRITICAL_SECTION_PROFILE_V1.into(),
        module_contract_version: MODULE_CONTRACT_V1,
        context_abi: CONTEXT_ABI_V1,
        source_sha256,
        build_sha256,
        provenance_sha256,
        entrypoint: "worker:handle/2".into(),
        capabilities: capability_grants(&worker_config),
        runtime_limits,
        durable: None,
    };
    fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn collect_sources(project: &Path) -> Result<Vec<PathBuf>> {
    let root = project.join("src");
    if !root.is_dir() {
        bail!("Erlang critical-section project requires src/");
    }
    let mut sources = Vec::new();
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk {}", root.display()))?;
        let path = entry.path();
        if entry.file_type().is_symlink() {
            bail!("source symlinks are forbidden: {}", path.display());
        }
        if entry.file_type().is_file() {
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("erl") => sources.push(path.to_path_buf()),
                Some("hrl") => bail!(
                    "header includes are not admitted in Erlang critical-section v1: {}",
                    path.display()
                ),
                _ => {}
            }
        }
    }
    sources.sort();
    if sources.is_empty() {
        bail!("Erlang critical-section project contains no src/*.erl files");
    }
    if !root.join("worker.erl").is_file() {
        bail!("Erlang critical-section project requires src/worker.erl");
    }
    Ok(sources)
}

fn validate_sources(sources: &[PathBuf], policy: &Policy) -> Result<()> {
    for path in sources {
        let source = fs::read_to_string(path)
            .with_context(|| format!("read Erlang source {}", path.display()))?;
        if source.contains("-include(") || source.contains("-include_lib(") {
            bail!("{}: include directives are forbidden in v1", path.display());
        }
        if source.contains("-on_load(") || source.contains("-nifs(") {
            bail!(
                "{}: load-time or native hooks are forbidden",
                path.display()
            );
        }
        for pattern in &policy.forbidden_erlang_patterns {
            if source.contains(pattern) {
                bail!(
                    "{}: forbidden Erlang authority pattern '{}'",
                    path.display(),
                    pattern
                );
            }
        }
    }
    Ok(())
}

fn compile_sources(beam_dir: &Path, sources: &[PathBuf]) -> Result<()> {
    let mut command = Command::new("erlc");
    command
        .arg("-Werror")
        .arg("+deterministic")
        .arg("-o")
        .arg(beam_dir);
    for source in sources {
        command.arg(source);
    }
    let output = command.output().context("launch erlc")?;
    if !output.status.success() {
        bail!(
            "erlc rejected critical-section project:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn verify_worker_export(worker_beam: &Path) -> Result<()> {
    if !worker_beam.is_file() {
        bail!("compiled artifact is missing beam/worker.beam");
    }
    let path = worker_beam
        .to_str()
        .context("worker.beam path must be UTF-8")?;
    let program = r#"
case init:get_plain_arguments() of
  [Path] ->
    case beam_lib:chunks(Path, [exports]) of
      {ok,{worker,[{exports,Exports}]}} ->
        case lists:member({handle,2}, Exports) of
          true -> halt(0);
          false -> io:format(standard_error, "worker must export handle/2~n", []), halt(4)
        end;
      Other -> io:format(standard_error, "invalid worker beam: ~p~n", [Other]), halt(3)
    end;
  _ -> halt(2)
end.
"#;
    let output = Command::new("erl")
        .args(["-noshell", "-eval", program, "-extra", path])
        .output()
        .context("inspect worker:handle/2 export")?;
    if !output.status.success() {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

fn digest_sources(project: &Path, sources: &[PathBuf]) -> Result<String> {
    let mut entries = BTreeMap::new();
    for path in sources {
        let relative = path
            .strip_prefix(project)?
            .to_string_lossy()
            .replace('\\', "/");
        entries.insert(relative, fs::read(path)?);
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

fn erlang_provenance(
    project: &Path,
    policy: &Policy,
    source_sha256: &str,
    build_sha256: &str,
) -> Result<BuildProvenance> {
    let policy_sha256 = sha256_bytes(&serde_json::to_vec(policy)?);
    Ok(BuildProvenance {
        format: PROVENANCE_FORMAT_V1,
        builder_id: env::var("BMSCL_BUILDER_ID").unwrap_or_else(|_| "local-untrusted".into()),
        builder_image_digest: env::var("BMSCL_BUILDER_IMAGE_DIGEST")
            .unwrap_or_else(|_| "local-untracked".into()),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        compiler_revision: env::var("BMSCL_COMPILER_REVISION")
            .unwrap_or_else(|_| "local-untracked".into()),
        gleam_version: "na".into(),
        otp_release: erlang_system_info("otp_release")?,
        erts_version: erlang_system_info("version")?,
        policy_sha256,
        dependency_lock_sha256: optional_sha256(&project.join("rebar.lock"))?,
        trusted_sdk_sha256: None,
        source_sha256: source_sha256.into(),
        build_sha256: build_sha256.into(),
    })
}

fn erlang_system_info(key: &str) -> Result<String> {
    let eval = format!("io:format(\"~s\", [erlang:system_info({key})]), halt(0).");
    let output = Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
        .context("query Erlang runtime version")?;
    if !output.status.success() {
        bail!("Erlang failed while collecting {key}");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn optional_sha256(path: &Path) -> Result<Option<String>> {
    if path.is_file() {
        Ok(Some(sha256_bytes(&fs::read(path)?)))
    } else {
        Ok(None)
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn clean_output(out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    for name in [
        "attestation.json",
        "admission-report.json",
        "manifest.json",
        "provenance.json",
        "worker.tar.gz",
        "worker.zip",
        "package-digests.json",
    ] {
        let path = out_dir.join(name);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
    }
    let beam = out_dir.join("beam");
    if beam.exists() {
        fs::remove_dir_all(&beam)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_limit_validation_is_shared_with_hosted_profiles() {
        let policy = Policy {
            policy_version: ERLANG_CRITICAL_SECTION_PROFILE_V1.into(),
            max_wall_ms: 10_000,
            ..Policy::default()
        };
        let config = crate::model::WorkerConfig {
            limits: crate::model::WorkerLimits {
                max_wall_ms: Some(10_001),
                ..crate::model::WorkerLimits::default()
            },
            ..crate::model::WorkerConfig::default()
        };
        let mut findings = Vec::new();
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &policy,
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.code == "BMSCL_RUNTIME_LIMIT_OUT_OF_POLICY"));
    }

    #[test]
    fn source_digest_is_path_stable() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        let worker = temp.path().join("src/worker.erl");
        fs::write(
            &worker,
            "-module(worker).\n-export([handle/2]).\nhandle(R,C)->{R,C}.\n",
        )
        .unwrap();
        let first = digest_sources(temp.path(), std::slice::from_ref(&worker)).unwrap();
        let second = digest_sources(temp.path(), &[worker]).unwrap();
        assert_eq!(first, second);
    }
}
