mod admission;
mod analyze;
mod attestation;
mod beam_static_limits;
mod beam_verify;
mod build;
mod erlang;
mod host_bridge_verify;
mod model;
mod phoenix_release;
mod policy;
mod process_dict_verify;
mod safety_cache;
mod trusted_sdk;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::{env, fs, path::PathBuf};

use admission::{
    maybe_issue_admission_receipt, verify_admission_artifact, verify_admission_receipt,
    AdmissionReceipt,
};
use analyze::check_project_with_cache;
use attestation::{attach_signature, sign_artifact, signing_request, verifying_key_hex};
use beam_static_limits::verify_static_atom_budget;
use beam_verify::verify_final_beam;
use build::{build_project, package_project};
use erlang::build_erlang_critical_section;
use host_bridge_verify::verify_trusted_host_bridges;
use phoenix_release::{
    admit_release, artifact_root_from_dir, package_release, verify_release_artifact_dir,
    PhoenixReleaseOptions,
};
use policy::load_policy;
use process_dict_verify::verify_no_process_dictionary_access;
use safety_cache::{load_verified_safety_cache, VerifiedSafetyCache};

#[derive(Parser, Debug)]
#[command(
    name = "bmscl-compiler",
    version,
    about = "Compile capability-restricted Gleam and Erlang workers for BeamScale"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Statically check customer source, dependencies, permissions, and runtime policy.
    Check {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        /// Turn conservative recursive CPU-loop warnings into admission errors.
        #[arg(long)]
        deny_cpu_loops: bool,
    },
    /// Admit, compile to BEAM, verify generated code/imports, and emit an immutable manifest.
    Build {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
        #[arg(long)]
        deny_cpu_loops: bool,
    },
    /// Build and package verified application BEAM modules plus admission evidence.
    /// Emits deterministic worker.tar.gz + worker.zip and package-digests.json.
    /// The signing key belongs to the customer/build owner; BeamScale independently
    /// re-verifies the finished BEAM artifact before shared-tier admission.
    Package {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
        #[arg(long)]
        deny_cpu_loops: bool,
        /// Path to the customer's 32-byte Ed25519 signing seed encoded as 64 hex characters.
        #[arg(long, requires = "key_id")]
        signing_key: Option<PathBuf>,
        /// Stable customer signing-key identifier registered with the deployment service.
        #[arg(long, requires = "signing_key")]
        key_id: Option<String>,
    },
    /// Build a constrained Erlang worker for the tenant-dedicated critical-section service.
    BuildErlangCritical {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
    },
    /// Build, verify, sign, and package a constrained Erlang critical-section worker.
    PackageErlangCritical {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        worker_config: Option<PathBuf>,
        #[arg(long, default_value = "dist")]
        out_dir: PathBuf,
        #[arg(long, requires = "key_id")]
        signing_key: Option<PathBuf>,
        #[arg(long, requires = "signing_key")]
        key_id: Option<String>,
    },
    /// Admit and package an already-built Phoenix Mix release for Firecracker execution.
    PhoenixPackage {
        /// Existing Mix release directory, e.g. _build/prod/rel/my_app.
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long, default_value = "dist-phoenix")]
        out_dir: PathBuf,
        #[arg(long)]
        app: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        router: String,
        #[arg(long)]
        endpoint: String,
        /// Deterministic bmscl.phoenix.discovery.v2 plan emitted by bmscl phoenix-plan.
        #[arg(long)]
        route_plan: PathBuf,
        /// SHA-256 of the source snapshot that produced this isolated build.
        #[arg(long)]
        source_sha256: String,
        /// Immutable isolated builder image digest, sha256:<64 lowercase hex>.
        #[arg(long)]
        builder_image_digest: String,
        #[arg(long, requires = "key_id")]
        signing_key: Option<PathBuf>,
        #[arg(long, requires = "signing_key")]
        key_id: Option<String>,
    },
    /// Emit the canonical detached-signing request for an already built artifact.
    SigningRequest {
        #[arg(default_value = "dist")]
        artifact_dir: PathBuf,
        #[arg(long)]
        key_id: String,
    },
    /// Verify and attach an externally produced customer Ed25519 signature, then rebuild archives.
    AttachSignature {
        #[arg(default_value = "dist")]
        artifact_dir: PathBuf,
        #[arg(long)]
        key_id: String,
        /// Detached Ed25519 signature as exactly 128 hexadecimal characters.
        #[arg(long)]
        signature_hex: String,
        /// Customer public verification key as exactly 64 hexadecimal characters.
        #[arg(long)]
        public_key: String,
    },
    /// Verify a customer-signed artifact without rebuilding it.
    ///
    /// This checks exact signed bytes, manifest/report/provenance consistency,
    /// import policy plus disassembled final-BEAM instructions, and optional
    /// server policy/compiler constraints. A BeamScale admission receipt is
    /// emitted only after both verification layers succeed.
    Verify {
        #[arg(default_value = "dist")]
        artifact_dir: PathBuf,
        /// Registered customer Ed25519 public key as exactly 64 hexadecimal characters.
        #[arg(long)]
        public_key: String,
        /// Optionally require one exact registered customer key identifier.
        #[arg(long)]
        key_id: Option<String>,
        /// Require the customer build to use this exact policy SHA-256.
        #[arg(long)]
        required_policy_sha256: Option<String>,
        /// Require the customer build to use this exact bmscl-compiler revision.
        #[arg(long)]
        required_compiler_revision: Option<String>,
    },
    /// Verify a BeamScale admission receipt against the control-plane public key.
    VerifyReceipt {
        #[arg(default_value = "admission-receipt.json")]
        receipt: PathBuf,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Derive the Ed25519 public verification key for operator configuration.
    PublicKey {
        #[arg(long)]
        signing_key: PathBuf,
    },
}

fn verify_deployable_beam(beam_dir: &std::path::Path) -> Result<()> {
    verify_final_beam(beam_dir)?;
    verify_no_process_dictionary_access(beam_dir)?;
    verify_static_atom_budget(beam_dir)?;
    verify_trusted_host_bridges(beam_dir)
}

fn load_safety_cache(policy: &crate::model::Policy) -> Result<Option<VerifiedSafetyCache>> {
    let path = env::var_os("BMSCL_SAFETY_CACHE").map(PathBuf::from);
    let public_key = env::var("BMSCL_SAFETY_CACHE_PUBLIC_KEY").ok();
    let required_analysis_policy =
        env::var("BMSCL_REQUIRED_SAFETY_ANALYSIS_SHA256").ok();
    let key_id = env::var("BMSCL_SAFETY_CACHE_KEY_ID").ok();

    match (path, public_key, required_analysis_policy) {
        (None, None, None) if key_id.is_none() => Ok(None),
        (Some(path), Some(public_key), Some(required_analysis_policy)) => {
            Ok(Some(load_verified_safety_cache(
                &path,
                &public_key,
                key_id.as_deref(),
                &required_analysis_policy,
                policy,
            )?))
        }
        _ => bail!(
            "signed safety caching is fail-closed: set BMSCL_SAFETY_CACHE, BMSCL_SAFETY_CACHE_PUBLIC_KEY, and BMSCL_REQUIRED_SAFETY_ANALYSIS_SHA256 together; BMSCL_SAFETY_CACHE_KEY_ID is optional"
        ),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Check {
            project,
            policy,
            worker_config,
            deny_cpu_loops,
        } => {
            let policy = load_policy(policy.as_deref())?;
            let safety_cache = load_safety_cache(&policy)?;
            let report = check_project_with_cache(
                &project,
                &policy,
                worker_config.as_deref(),
                deny_cpu_loops,
                safety_cache.as_ref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.admitted {
                bail!("worker rejected by BeamScale admission policy");
            }
        }
        Commands::Build {
            project,
            policy,
            worker_config,
            out_dir,
            deny_cpu_loops,
        } => {
            let policy = load_policy(policy.as_deref())?;
            let safety_cache = load_safety_cache(&policy)?;
            build_project(
                &project,
                &out_dir,
                &policy,
                worker_config.as_deref(),
                deny_cpu_loops,
                safety_cache.as_ref(),
            )?;
            verify_deployable_beam(&out_dir.join("beam"))?;
        }
        Commands::Package {
            project,
            policy,
            worker_config,
            out_dir,
            deny_cpu_loops,
            signing_key,
            key_id,
        } => {
            let policy = load_policy(policy.as_deref())?;
            let safety_cache = load_safety_cache(&policy)?;
            build_project(
                &project,
                &out_dir,
                &policy,
                worker_config.as_deref(),
                deny_cpu_loops,
                safety_cache.as_ref(),
            )?;
            verify_deployable_beam(&out_dir.join("beam"))?;
            if let (Some(signing_key), Some(key_id)) = (signing_key.as_deref(), key_id.as_deref()) {
                sign_artifact(&out_dir, key_id, signing_key)?;
            }
            package_project(&out_dir)?;
        }
        Commands::BuildErlangCritical {
            project,
            policy,
            worker_config,
            out_dir,
        } => {
            let policy = load_policy(policy.as_deref())?;
            build_erlang_critical_section(&project, &out_dir, &policy, worker_config.as_deref())?;
            verify_deployable_beam(&out_dir.join("beam"))?;
        }
        Commands::PackageErlangCritical {
            project,
            policy,
            worker_config,
            out_dir,
            signing_key,
            key_id,
        } => {
            let policy = load_policy(policy.as_deref())?;
            build_erlang_critical_section(&project, &out_dir, &policy, worker_config.as_deref())?;
            verify_deployable_beam(&out_dir.join("beam"))?;
            if let (Some(signing_key), Some(key_id)) = (signing_key.as_deref(), key_id.as_deref()) {
                sign_artifact(&out_dir, key_id, signing_key)?;
            }
            package_project(&out_dir)?;
        }
        Commands::PhoenixPackage {
            release_dir,
            out_dir,
            app,
            version,
            router,
            endpoint,
            route_plan,
            source_sha256,
            builder_image_digest,
            signing_key,
            key_id,
        } => {
            admit_release(PhoenixReleaseOptions {
                release_dir,
                out_dir,
                app,
                version,
                router,
                endpoint,
                route_plan,
                source_sha256,
                builder_image_digest,
                signing_key,
                key_id,
            })?;
        }
        Commands::SigningRequest {
            artifact_dir,
            key_id,
        } => {
            match artifact_root_from_dir(&artifact_dir)?.as_str() {
                "beam" => verify_deployable_beam(&artifact_dir.join("beam"))?,
                "release" => verify_release_artifact_dir(&artifact_dir)?,
                other => bail!("unsupported artifact_root `{other}`"),
            }
            let request = signing_request(&artifact_dir, &key_id)?;
            println!("{}", serde_json::to_string_pretty(&request)?);
        }
        Commands::AttachSignature {
            artifact_dir,
            key_id,
            signature_hex,
            public_key,
        } => {
            let root = artifact_root_from_dir(&artifact_dir)?;
            match root.as_str() {
                "beam" => verify_deployable_beam(&artifact_dir.join("beam"))?,
                "release" => verify_release_artifact_dir(&artifact_dir)?,
                other => bail!("unsupported artifact_root `{other}`"),
            }
            attach_signature(&artifact_dir, &key_id, &signature_hex, &public_key)?;
            match root.as_str() {
                "beam" => package_project(&artifact_dir)?,
                "release" => package_release(&artifact_dir)?,
                _ => unreachable!(),
            }
        }
        Commands::Verify {
            artifact_dir,
            public_key,
            key_id,
            required_policy_sha256,
            required_compiler_revision,
        } => {
            let required_policy_sha256 =
                required_policy_sha256.or_else(|| env::var("BMSCL_REQUIRED_POLICY_SHA256").ok());
            let required_compiler_revision = required_compiler_revision
                .or_else(|| env::var("BMSCL_REQUIRED_COMPILER_REVISION").ok());
            let verified = verify_admission_artifact(
                &artifact_dir,
                &public_key,
                key_id.as_deref(),
                required_policy_sha256.as_deref(),
                required_compiler_revision.as_deref(),
            )?;
            match artifact_root_from_dir(&artifact_dir)?.as_str() {
                "beam" => verify_deployable_beam(&artifact_dir.join("beam"))?,
                "release" => verify_release_artifact_dir(&artifact_dir)?,
                other => bail!("unsupported artifact_root `{other}`"),
            }
            if maybe_issue_admission_receipt(&artifact_dir, &verified)?.is_some() {
                eprintln!(
                    "wrote {}",
                    artifact_dir.join("admission-receipt.json").display()
                );
            }
            println!("{}", serde_json::to_string_pretty(&verified)?);
        }
        Commands::VerifyReceipt {
            receipt,
            public_key,
            key_id,
        } => {
            let parsed: AdmissionReceipt = serde_json::from_slice(
                &fs::read(&receipt).with_context(|| format!("read {}", receipt.display()))?,
            )
            .with_context(|| format!("parse {}", receipt.display()))?;
            if let Some(expected) = key_id.as_deref() {
                if parsed.admission_key_id != expected {
                    bail!(
                        "admission receipt key `{}` does not match expected `{expected}`",
                        parsed.admission_key_id
                    );
                }
            }
            verify_admission_receipt(&parsed, &public_key)?;
            println!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        Commands::PublicKey { signing_key } => {
            println!("{}", verifying_key_hex(&signing_key)?);
        }
    }
    Ok(())
}
