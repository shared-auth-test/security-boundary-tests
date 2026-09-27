use crate::build::digest_tree;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub const ATTESTATION_FORMAT: &str = "bmscl-artifact-attestation-v2";
pub const SIGNING_REQUEST_FORMAT: &str = "bmscl-detached-signing-request-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactAttestation {
    pub format: String,
    pub algorithm: String,
    pub key_id: String,
    pub manifest_sha256: String,
    pub admission_report_sha256: String,
    pub provenance_sha256: String,
    pub build_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedArtifact {
    pub key_id: String,
    pub build_sha256: String,
    pub manifest_sha256: String,
    pub admission_report_sha256: String,
    pub provenance_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SigningRequest {
    pub format: &'static str,
    pub algorithm: &'static str,
    pub key_id: String,
    pub payload_hex: String,
    pub payload_sha256: String,
    pub manifest_sha256: String,
    pub admission_report_sha256: String,
    pub provenance_sha256: String,
    pub build_sha256: String,
}

#[derive(Debug)]
struct PreparedAttestation {
    manifest_sha256: String,
    admission_report_sha256: String,
    provenance_sha256: String,
    build_sha256: String,
    payload: Vec<u8>,
}

pub fn signing_request(out_dir: &Path, key_id: &str) -> Result<SigningRequest> {
    let prepared = prepare_attestation(out_dir, key_id)?;
    Ok(SigningRequest {
        format: SIGNING_REQUEST_FORMAT,
        algorithm: "ed25519",
        key_id: key_id.into(),
        payload_hex: hex::encode(&prepared.payload),
        payload_sha256: sha256_hex(&prepared.payload),
        manifest_sha256: prepared.manifest_sha256,
        admission_report_sha256: prepared.admission_report_sha256,
        provenance_sha256: prepared.provenance_sha256,
        build_sha256: prepared.build_sha256,
    })
}

pub fn attach_signature(
    out_dir: &Path,
    key_id: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<()> {
    let prepared = prepare_attestation(out_dir, key_id)?;
    let verifying_key = decode_verifying_key(public_key_hex)?;
    let signature = decode_signature(signature_hex)?;
    verifying_key
        .verify(&prepared.payload, &signature)
        .context("detached Ed25519 signature verification failed")?;
    write_attestation(out_dir, key_id, signature_hex, prepared)
}

pub fn sign_artifact(out_dir: &Path, key_id: &str, signing_key_path: &Path) -> Result<()> {
    let prepared = prepare_attestation(out_dir, key_id)?;
    let signing_key = load_signing_key(signing_key_path)?;
    let signature = signing_key.sign(&prepared.payload);
    write_attestation(
        out_dir,
        key_id,
        &hex::encode(signature.to_bytes()),
        prepared,
    )
}

fn prepare_attestation(out_dir: &Path, key_id: &str) -> Result<PreparedAttestation> {
    validate_key_id(key_id)?;

    let manifest_path = out_dir.join("manifest.json");
    let admission_path = out_dir.join("admission-report.json");
    let provenance_path = out_dir.join("provenance.json");
    let manifest =
        fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?;
    let admission =
        fs::read(&admission_path).with_context(|| format!("read {}", admission_path.display()))?;
    let provenance = fs::read(&provenance_path)
        .with_context(|| format!("read {}", provenance_path.display()))?;

    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest).context("parse manifest.json before attestation")?;
    let provenance_json: serde_json::Value =
        serde_json::from_slice(&provenance).context("parse provenance.json before attestation")?;
    let build_sha256 = required_string(&manifest_json, "build_sha256")?;
    let source_sha256 = required_string(&manifest_json, "source_sha256")?;
    let manifest_provenance_sha256 = required_string(&manifest_json, "provenance_sha256")?;
    validate_sha256(build_sha256, "build_sha256")?;
    validate_sha256(source_sha256, "source_sha256")?;
    validate_sha256(manifest_provenance_sha256, "provenance_sha256")?;

    let provenance_sha256 = sha256_hex(&provenance);
    if manifest_provenance_sha256 != provenance_sha256 {
        bail!("manifest provenance digest does not match provenance.json");
    }
    if required_string(&provenance_json, "build_sha256")? != build_sha256 {
        bail!("provenance build digest does not match manifest");
    }
    if required_string(&provenance_json, "source_sha256")? != source_sha256 {
        bail!("provenance source digest does not match manifest");
    }

    let artifact_root = artifact_root(&manifest_json)?;
    let actual_build = digest_tree(&out_dir.join(artifact_root))?;
    if actual_build != build_sha256 {
        bail!("{artifact_root} tree digest does not match manifest before signing");
    }

    let manifest_sha256 = sha256_hex(&manifest);
    let admission_report_sha256 = sha256_hex(&admission);
    let payload = canonical_payload(
        key_id,
        &manifest_sha256,
        &admission_report_sha256,
        &provenance_sha256,
        build_sha256,
    );

    Ok(PreparedAttestation {
        manifest_sha256,
        admission_report_sha256,
        provenance_sha256,
        build_sha256: build_sha256.into(),
        payload,
    })
}

fn write_attestation(
    out_dir: &Path,
    key_id: &str,
    signature_hex: &str,
    prepared: PreparedAttestation,
) -> Result<()> {
    let signature = decode_signature(signature_hex)?;
    let attestation = ArtifactAttestation {
        format: ATTESTATION_FORMAT.into(),
        algorithm: "ed25519".into(),
        key_id: key_id.into(),
        manifest_sha256: prepared.manifest_sha256,
        admission_report_sha256: prepared.admission_report_sha256,
        provenance_sha256: prepared.provenance_sha256,
        build_sha256: prepared.build_sha256,
        signature_hex: hex::encode(signature.to_bytes()),
    };

    fs::write(
        out_dir.join("attestation.json"),
        serde_json::to_vec_pretty(&attestation)?,
    )?;
    Ok(())
}

pub fn verifying_key_hex(signing_key_path: &Path) -> Result<String> {
    let signing_key = load_signing_key(signing_key_path)?;
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

pub fn verify_artifact_dir(
    artifact_dir: &Path,
    public_key_hex: &str,
    expected_key_id: Option<&str>,
) -> Result<VerifiedArtifact> {
    let manifest = fs::read(artifact_dir.join("manifest.json")).context("read manifest.json")?;
    let admission = fs::read(artifact_dir.join("admission-report.json"))
        .context("read admission-report.json")?;
    let provenance =
        fs::read(artifact_dir.join("provenance.json")).context("read provenance.json")?;
    let attestation: ArtifactAttestation = serde_json::from_slice(
        &fs::read(artifact_dir.join("attestation.json")).context("read attestation.json")?,
    )
    .context("parse attestation.json")?;

    if let Some(expected) = expected_key_id {
        if attestation.key_id != expected {
            bail!(
                "attestation key_id `{}` does not match expected `{expected}`",
                attestation.key_id
            );
        }
    }
    let verifying_key = decode_verifying_key(public_key_hex)?;
    verify_attestation(
        &attestation,
        &manifest,
        &admission,
        &provenance,
        &verifying_key,
    )?;

    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest).context("parse manifest.json")?;
    let artifact_root = artifact_root(&manifest_json)?;
    let actual_build = digest_tree(&artifact_dir.join(artifact_root))?;
    if actual_build != attestation.build_sha256 {
        bail!(
            "{artifact_root} tree digest does not match signed build digest: expected {}, got {actual_build}",
            attestation.build_sha256
        );
    }

    Ok(VerifiedArtifact {
        key_id: attestation.key_id,
        build_sha256: attestation.build_sha256,
        manifest_sha256: attestation.manifest_sha256,
        admission_report_sha256: attestation.admission_report_sha256,
        provenance_sha256: attestation.provenance_sha256,
    })
}

fn verify_attestation(
    attestation: &ArtifactAttestation,
    manifest: &[u8],
    admission_report: &[u8],
    provenance: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<()> {
    if attestation.format != ATTESTATION_FORMAT {
        bail!("unsupported attestation format `{}`", attestation.format);
    }
    if attestation.algorithm != "ed25519" {
        bail!(
            "unsupported attestation algorithm `{}`",
            attestation.algorithm
        );
    }
    validate_key_id(&attestation.key_id)?;
    validate_sha256(&attestation.manifest_sha256, "manifest_sha256")?;
    validate_sha256(
        &attestation.admission_report_sha256,
        "admission_report_sha256",
    )?;
    validate_sha256(&attestation.provenance_sha256, "provenance_sha256")?;
    validate_sha256(&attestation.build_sha256, "build_sha256")?;

    let actual_manifest = sha256_hex(manifest);
    let actual_admission = sha256_hex(admission_report);
    let actual_provenance = sha256_hex(provenance);
    if actual_manifest != attestation.manifest_sha256 {
        bail!("manifest digest does not match artifact attestation");
    }
    if actual_admission != attestation.admission_report_sha256 {
        bail!("admission report digest does not match artifact attestation");
    }
    if actual_provenance != attestation.provenance_sha256 {
        bail!("provenance digest does not match artifact attestation");
    }

    let manifest_json: serde_json::Value =
        serde_json::from_slice(manifest).context("parse attested manifest")?;
    let provenance_json: serde_json::Value =
        serde_json::from_slice(provenance).context("parse attested provenance")?;
    let manifest_build = required_string(&manifest_json, "build_sha256")?;
    if manifest_build != attestation.build_sha256 {
        bail!("manifest build digest does not match artifact attestation");
    }
    let manifest_provenance = required_string(&manifest_json, "provenance_sha256")?;
    if manifest_provenance != attestation.provenance_sha256 {
        bail!("manifest provenance digest does not match artifact attestation");
    }
    if required_string(&provenance_json, "build_sha256")? != manifest_build {
        bail!("provenance build digest does not match manifest");
    }
    if required_string(&provenance_json, "source_sha256")?
        != required_string(&manifest_json, "source_sha256")?
    {
        bail!("provenance source digest does not match manifest");
    }

    let signature = decode_signature(&attestation.signature_hex)?;
    let payload = canonical_payload(
        &attestation.key_id,
        &attestation.manifest_sha256,
        &attestation.admission_report_sha256,
        &attestation.provenance_sha256,
        &attestation.build_sha256,
    );
    verifying_key
        .verify(&payload, &signature)
        .context("Ed25519 artifact attestation verification failed")?;
    Ok(())
}

pub fn canonical_payload(
    key_id: &str,
    manifest_sha256: &str,
    admission_report_sha256: &str,
    provenance_sha256: &str,
    build_sha256: &str,
) -> Vec<u8> {
    format!(
        "{ATTESTATION_FORMAT}\nkey_id={key_id}\nmanifest_sha256={manifest_sha256}\nadmission_report_sha256={admission_report_sha256}\nprovenance_sha256={provenance_sha256}\nbuild_sha256={build_sha256}\n"
    )
    .into_bytes()
}

fn artifact_root(manifest: &serde_json::Value) -> Result<&str> {
    let root = manifest
        .get("artifact_root")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("beam");
    match root {
        "beam" | "release" => Ok(root),
        other => bail!("unsupported signed artifact_root `{other}`"),
    }
}

fn required_string<'a>(json: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    json.get(field)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("JSON missing string `{field}`"))
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

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("read signing key {}", path.display()))?;
    let value = raw.trim();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("signing key must be exactly 32 bytes encoded as 64 hexadecimal characters");
    }
    let bytes = hex::decode(value).context("decode signing key hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must decode to exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
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

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_unsigned_fixture(dir: &Path) -> (String, String) {
        fs::create_dir_all(dir.join("beam")).unwrap();
        fs::write(dir.join("beam/worker.beam"), b"beam-v1").unwrap();
        let build = digest_tree(&dir.join("beam")).unwrap();
        let source = "22".repeat(32);
        let provenance = format!("{{\"source_sha256\":\"{source}\",\"build_sha256\":\"{build}\"}}");
        let provenance_sha = sha256_hex(provenance.as_bytes());
        fs::write(
            dir.join("manifest.json"),
            format!(
                "{{\"source_sha256\":\"{source}\",\"build_sha256\":\"{build}\",\"provenance_sha256\":\"{provenance_sha}\"}}"
            )
            .as_bytes(),
        )
        .unwrap();
        fs::write(dir.join("admission-report.json"), b"{\"admitted\":true}").unwrap();
        fs::write(dir.join("provenance.json"), provenance.as_bytes()).unwrap();
        (source, build)
    }

    fn test_key(dir: &Path) -> (std::path::PathBuf, SigningKey) {
        let key_path = dir.join("key.hex");
        fs::write(
            &key_path,
            "0101010101010101010101010101010101010101010101010101010101010101\n",
        )
        .unwrap();
        let key = load_signing_key(&key_path).unwrap();
        (key_path, key)
    }

    #[test]
    fn canonical_payload_is_stable_and_line_delimited() {
        let payload = canonical_payload(
            "kid",
            &"aa".repeat(32),
            &"bb".repeat(32),
            &"cc".repeat(32),
            &"dd".repeat(32),
        );
        let text = String::from_utf8(payload).unwrap();
        assert!(text.starts_with("bmscl-artifact-attestation-v2\nkey_id=kid\n"));
        assert!(text.ends_with('\n'));
        assert_eq!(text.lines().count(), 6);
    }

    #[test]
    fn rejects_unsafe_key_ids() {
        assert!(validate_key_id("../key").is_err());
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id("safe-key.v1_2").is_ok());
    }

    #[test]
    fn release_artifact_root_is_signed_and_verified() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("release/bin")).unwrap();
        fs::write(dir.path().join("release/bin/app"), b"release-v1").unwrap();
        let build = digest_tree(&dir.path().join("release")).unwrap();
        let source = "33".repeat(32);
        let provenance = format!("{{\"source_sha256\":\"{source}\",\"build_sha256\":\"{build}\"}}");
        let provenance_sha = sha256_hex(provenance.as_bytes());
        fs::write(
            dir.path().join("manifest.json"),
            format!(
                "{{\"artifact_root\":\"release\",\"source_sha256\":\"{source}\",\"build_sha256\":\"{build}\",\"provenance_sha256\":\"{provenance_sha}\"}}"
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join("admission-report.json"),
            b"{\"admitted\":true}",
        )
        .unwrap();
        fs::write(dir.path().join("provenance.json"), provenance).unwrap();
        let (key_path, _) = test_key(dir.path());
        sign_artifact(dir.path(), "release-key", &key_path).unwrap();
        let public_key = verifying_key_hex(&key_path).unwrap();
        assert!(verify_artifact_dir(dir.path(), &public_key, Some("release-key")).is_ok());
    }

    #[test]
    fn detached_signature_round_trip_never_needs_private_key_attachment() {
        let dir = tempdir().unwrap();
        write_unsigned_fixture(dir.path());
        let (_key_path, signing_key) = test_key(dir.path());
        let request = signing_request(dir.path(), "test-key-1").unwrap();
        assert_eq!(request.format, SIGNING_REQUEST_FORMAT);
        let payload = hex::decode(&request.payload_hex).unwrap();
        assert_eq!(request.payload_sha256, sha256_hex(&payload));
        let signature = signing_key.sign(&payload);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());

        attach_signature(
            dir.path(),
            "test-key-1",
            &hex::encode(signature.to_bytes()),
            &public_key,
        )
        .unwrap();
        assert!(verify_artifact_dir(dir.path(), &public_key, Some("test-key-1")).is_ok());
    }

    #[test]
    fn detached_signature_rejects_wrong_payload_signature() {
        let dir = tempdir().unwrap();
        write_unsigned_fixture(dir.path());
        let (_key_path, signing_key) = test_key(dir.path());
        let signature = signing_key.sign(b"not-the-artifact-payload");
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        assert!(attach_signature(
            dir.path(),
            "test-key-1",
            &hex::encode(signature.to_bytes()),
            &public_key,
        )
        .is_err());
        assert!(!dir.path().join("attestation.json").exists());
    }

    #[test]
    fn verification_rejects_beam_and_provenance_tampering() {
        let dir = tempdir().unwrap();
        write_unsigned_fixture(dir.path());
        let (key_path, _signing_key) = test_key(dir.path());
        sign_artifact(dir.path(), "test-key-1", &key_path).unwrap();
        let public_key = verifying_key_hex(&key_path).unwrap();
        assert!(verify_artifact_dir(dir.path(), &public_key, Some("test-key-1")).is_ok());

        fs::write(dir.path().join("beam/worker.beam"), b"beam-v2").unwrap();
        assert!(verify_artifact_dir(dir.path(), &public_key, Some("test-key-1")).is_err());
        fs::write(dir.path().join("beam/worker.beam"), b"beam-v1").unwrap();
        fs::write(
            dir.path().join("provenance.json"),
            b"{\"source_sha256\":\"tampered\"}",
        )
        .unwrap();
        assert!(verify_artifact_dir(dir.path(), &public_key, Some("test-key-1")).is_err());
    }
}
