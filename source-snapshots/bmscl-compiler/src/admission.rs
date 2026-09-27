use crate::{
    attestation::{verify_artifact_dir, VerifiedArtifact},
    build::verify_beam_imports,
    model::DurableActorConfig,
    phoenix_release::verify_release_artifact_dir,
};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

pub const ADMISSION_RECEIPT_FORMAT: &str = "bmscl-admission-receipt-v1";

#[derive(Debug, Clone, Serialize)]
pub struct AdmissionVerification {
    pub customer_key_id: String,
    pub build_sha256: String,
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub admission_report_sha256: String,
    pub provenance_sha256: String,
    pub policy_sha256: String,
    pub compiler_version: String,
    pub compiler_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionReceipt {
    pub format: String,
    pub algorithm: String,
    pub admission_key_id: String,
    pub customer_key_id: String,
    pub build_sha256: String,
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub admission_report_sha256: String,
    pub provenance_sha256: String,
    pub policy_sha256: String,
    pub compiler_version: String,
    pub compiler_revision: String,
    pub verifier_version: String,
    pub signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct ManifestSummary {
    profile: String,
    source_sha256: String,
    build_sha256: String,
    durable: Option<DurableActorConfig>,
    artifact_root: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdmissionReportSummary {
    admitted: bool,
    policy_version: String,
    source_sha256: String,
    durable: Option<DurableActorConfig>,
}

#[derive(Debug, Deserialize)]
struct ProvenanceSummary {
    compiler_version: String,
    compiler_revision: String,
    policy_sha256: String,
    source_sha256: String,
    build_sha256: String,
}

pub fn verify_admission_artifact(
    artifact_dir: &Path,
    customer_public_key_hex: &str,
    expected_customer_key_id: Option<&str>,
    required_policy_sha256: Option<&str>,
    required_compiler_revision: Option<&str>,
) -> Result<AdmissionVerification> {
    let signed: VerifiedArtifact = verify_artifact_dir(
        artifact_dir,
        customer_public_key_hex,
        expected_customer_key_id,
    )?;

    let manifest_path = artifact_dir.join("manifest.json");
    let report_path = artifact_dir.join("admission-report.json");
    let provenance_path = artifact_dir.join("provenance.json");
    let manifest_bytes =
        fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?;
    let report_bytes =
        fs::read(&report_path).with_context(|| format!("read {}", report_path.display()))?;
    let provenance_bytes = fs::read(&provenance_path)
        .with_context(|| format!("read {}", provenance_path.display()))?;
    require_equal(
        "manifest_sha256",
        &signed.manifest_sha256,
        &sha256_hex(&manifest_bytes),
    )?;
    require_equal(
        "admission_report_sha256",
        &signed.admission_report_sha256,
        &sha256_hex(&report_bytes),
    )?;
    require_equal(
        "provenance_sha256",
        &signed.provenance_sha256,
        &sha256_hex(&provenance_bytes),
    )?;

    let manifest: ManifestSummary =
        serde_json::from_slice(&manifest_bytes).context("parse manifest.json")?;
    let report: AdmissionReportSummary =
        serde_json::from_slice(&report_bytes).context("parse admission-report.json")?;
    let provenance: ProvenanceSummary =
        serde_json::from_slice(&provenance_bytes).context("parse provenance.json")?;

    if !report.admitted {
        bail!("artifact admission-report.json is not admitted");
    }
    require_equal(
        "manifest build_sha256",
        &signed.build_sha256,
        &manifest.build_sha256,
    )?;
    require_equal(
        "report policy_version",
        &manifest.profile,
        &report.policy_version,
    )?;
    require_equal(
        "report source_sha256",
        &manifest.source_sha256,
        &report.source_sha256,
    )?;
    if manifest.durable.as_ref() != report.durable.as_ref() {
        bail!("durable config mismatch between manifest.json and admission-report.json");
    }
    require_equal(
        "provenance source_sha256",
        &manifest.source_sha256,
        &provenance.source_sha256,
    )?;
    require_equal(
        "provenance build_sha256",
        &manifest.build_sha256,
        &provenance.build_sha256,
    )?;
    validate_sha256(&provenance.policy_sha256, "policy_sha256")?;

    if let Some(required) = required_policy_sha256 {
        validate_sha256(required, "required_policy_sha256")?;
        require_equal("policy_sha256", required, &provenance.policy_sha256)?;
    }
    if let Some(required) = required_compiler_revision {
        require_equal("compiler_revision", required, &provenance.compiler_revision)?;
    }

    // Server-side verification never executes customer build hooks. Shared
    // Hosted Gleam reuses the final-BEAM import choke point; Phoenix verifies
    // only the already-built release envelope and is always Firecracker-class.
    match manifest.artifact_root.as_deref().unwrap_or("beam") {
        "beam" => verify_beam_imports(&artifact_dir.join("beam"))?,
        "release" => verify_release_artifact_dir(artifact_dir)?,
        other => bail!("unsupported artifact_root `{other}`"),
    }

    Ok(AdmissionVerification {
        customer_key_id: signed.key_id,
        build_sha256: signed.build_sha256,
        source_sha256: manifest.source_sha256,
        manifest_sha256: signed.manifest_sha256,
        admission_report_sha256: signed.admission_report_sha256,
        provenance_sha256: signed.provenance_sha256,
        policy_sha256: provenance.policy_sha256,
        compiler_version: provenance.compiler_version,
        compiler_revision: provenance.compiler_revision,
    })
}

pub fn maybe_issue_admission_receipt(
    artifact_dir: &Path,
    verification: &AdmissionVerification,
) -> Result<Option<AdmissionReceipt>> {
    let signing_key_path = env::var_os("BMSCL_ADMISSION_SIGNING_KEY");
    let key_id = env::var("BMSCL_ADMISSION_KEY_ID").ok();
    match (signing_key_path, key_id) {
        (None, None) if require_admission_receipt() => bail!(
            "BMSCL_REQUIRE_ADMISSION_RECEIPT is enabled but BMSCL_ADMISSION_SIGNING_KEY and BMSCL_ADMISSION_KEY_ID are not configured"
        ),
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            bail!("BMSCL_ADMISSION_SIGNING_KEY and BMSCL_ADMISSION_KEY_ID must be configured together")
        }
        (Some(path), Some(key_id)) => {
            let receipt = issue_admission_receipt(verification, &key_id, Path::new(&path))?;
            fs::write(
                artifact_dir.join("admission-receipt.json"),
                serde_json::to_vec_pretty(&receipt)?,
            )?;
            Ok(Some(receipt))
        }
    }
}

pub fn issue_admission_receipt(
    verification: &AdmissionVerification,
    admission_key_id: &str,
    signing_key_path: &Path,
) -> Result<AdmissionReceipt> {
    validate_key_id(admission_key_id)?;
    let signing_key = load_signing_key(signing_key_path)?;
    let verifier_version = env!("CARGO_PKG_VERSION").to_string();
    let payload = canonical_receipt_payload(
        admission_key_id,
        &verification.customer_key_id,
        &verification.build_sha256,
        &verification.source_sha256,
        &verification.manifest_sha256,
        &verification.admission_report_sha256,
        &verification.provenance_sha256,
        &verification.policy_sha256,
        &verification.compiler_version,
        &verification.compiler_revision,
        &verifier_version,
    );
    let signature = signing_key.sign(&payload);
    Ok(AdmissionReceipt {
        format: ADMISSION_RECEIPT_FORMAT.into(),
        algorithm: "ed25519".into(),
        admission_key_id: admission_key_id.into(),
        customer_key_id: verification.customer_key_id.clone(),
        build_sha256: verification.build_sha256.clone(),
        source_sha256: verification.source_sha256.clone(),
        manifest_sha256: verification.manifest_sha256.clone(),
        admission_report_sha256: verification.admission_report_sha256.clone(),
        provenance_sha256: verification.provenance_sha256.clone(),
        policy_sha256: verification.policy_sha256.clone(),
        compiler_version: verification.compiler_version.clone(),
        compiler_revision: verification.compiler_revision.clone(),
        verifier_version,
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

pub fn verify_admission_receipt(
    receipt: &AdmissionReceipt,
    admission_public_key_hex: &str,
) -> Result<()> {
    if receipt.format != ADMISSION_RECEIPT_FORMAT {
        bail!("unsupported admission receipt format `{}`", receipt.format);
    }
    if receipt.algorithm != "ed25519" {
        bail!(
            "unsupported admission receipt algorithm `{}`",
            receipt.algorithm
        );
    }
    validate_key_id(&receipt.admission_key_id)?;
    validate_key_id(&receipt.customer_key_id)?;
    for (value, field) in [
        (&receipt.build_sha256, "build_sha256"),
        (&receipt.source_sha256, "source_sha256"),
        (&receipt.manifest_sha256, "manifest_sha256"),
        (&receipt.admission_report_sha256, "admission_report_sha256"),
        (&receipt.provenance_sha256, "provenance_sha256"),
        (&receipt.policy_sha256, "policy_sha256"),
    ] {
        validate_sha256(value, field)?;
    }
    let key = decode_verifying_key(admission_public_key_hex)?;
    let signature = decode_signature(&receipt.signature_hex)?;
    let payload = canonical_receipt_payload(
        &receipt.admission_key_id,
        &receipt.customer_key_id,
        &receipt.build_sha256,
        &receipt.source_sha256,
        &receipt.manifest_sha256,
        &receipt.admission_report_sha256,
        &receipt.provenance_sha256,
        &receipt.policy_sha256,
        &receipt.compiler_version,
        &receipt.compiler_revision,
        &receipt.verifier_version,
    );
    key.verify(&payload, &signature)
        .context("BeamScale admission receipt signature verification failed")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn canonical_receipt_payload(
    admission_key_id: &str,
    customer_key_id: &str,
    build_sha256: &str,
    source_sha256: &str,
    manifest_sha256: &str,
    admission_report_sha256: &str,
    provenance_sha256: &str,
    policy_sha256: &str,
    compiler_version: &str,
    compiler_revision: &str,
    verifier_version: &str,
) -> Vec<u8> {
    format!(
        "{ADMISSION_RECEIPT_FORMAT}\nadmission_key_id={admission_key_id}\ncustomer_key_id={customer_key_id}\nbuild_sha256={build_sha256}\nsource_sha256={source_sha256}\nmanifest_sha256={manifest_sha256}\nadmission_report_sha256={admission_report_sha256}\nprovenance_sha256={provenance_sha256}\npolicy_sha256={policy_sha256}\ncompiler_version={compiler_version}\ncompiler_revision={compiler_revision}\nverifier_version={verifier_version}\n"
    )
    .into_bytes()
}

fn require_admission_receipt() -> bool {
    matches!(
        env::var("BMSCL_REQUIRE_ADMISSION_RECEIPT")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn require_equal(field: &str, expected: &str, actual: &str) -> Result<()> {
    if expected != actual {
        bail!("{field} mismatch: expected `{expected}`, got `{actual}`");
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("key_id must match [A-Za-z0-9._-] and be 1..=64 bytes");
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

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read admission signing key {}", path.display()))?;
    let value = raw.trim();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "admission signing key must be exactly 32 bytes encoded as 64 hexadecimal characters"
        );
    }
    let bytes: [u8; 32] = hex::decode(value)
        .context("decode admission signing key hexadecimal")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("admission signing key must decode to exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_verifying_key(value: &str) -> Result<VerifyingKey> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("public key must be exactly 32 bytes encoded as 64 hexadecimal characters");
    }
    let bytes: [u8; 32] = hex::decode(value)
        .context("decode public key hexadecimal")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must decode to exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")
}

fn decode_signature(value: &str) -> Result<Signature> {
    let value = value.trim();
    if value.len() != 128 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("signature must be exactly 64 bytes encoded as 128 hexadecimal characters");
    }
    let bytes = hex::decode(value).context("decode signature hexadecimal")?;
    Signature::from_slice(&bytes).map_err(|_| anyhow::anyhow!("signature must decode to 64 bytes"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{canonical_receipt_payload, ADMISSION_RECEIPT_FORMAT};
    use crate::build::forbidden_beam_import;

    #[test]
    fn rejects_dynamic_and_privileged_imports() {
        assert!(forbidden_beam_import("file:read_file/1"));
        assert!(forbidden_beam_import("erlang:apply/3"));
        assert!(forbidden_beam_import("erlang:spawn_link/1"));
        assert!(forbidden_beam_import("erlang:load_nif/2"));
        assert!(forbidden_beam_import("erlang:whereis/1"));
        assert!(forbidden_beam_import("gen_tcp:connect/3"));
        assert!(!forbidden_beam_import("erlang:length/1"));
    }

    #[test]
    fn receipt_payload_is_domain_separated_and_deterministic() {
        let payload = canonical_receipt_payload(
            "admit-1",
            "customer-1",
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(64),
            &"f".repeat(64),
            "0.1.0",
            "0123456789012345678901234567890123456789",
            "0.1.0",
        );
        let text = String::from_utf8(payload).unwrap();
        assert!(text.starts_with(ADMISSION_RECEIPT_FORMAT));
        assert!(text.contains("customer_key_id=customer-1\n"));
        assert!(text.ends_with("verifier_version=0.1.0\n"));
    }
}
