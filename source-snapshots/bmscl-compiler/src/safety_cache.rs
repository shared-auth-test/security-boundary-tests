use crate::model::Policy;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

pub const SAFETY_CACHE_FORMAT_V1: &str = "bmscl-safety-cache-v1";
pub const SAFETY_ANALYZER_SCHEMA_V1: &str = "bmscl-static-safety-analyzer-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SafetyCacheDocument {
    format: String,
    algorithm: String,
    key_id: String,
    analyzer_schema: String,
    analysis_policy_sha256: String,
    bmscl_policy_sha256: String,
    dependencies: Vec<DependencySafetyRecord>,
    sources: Vec<SourceSafetyRecord>,
    signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct DependencySafetyRecord {
    package: String,
    version: String,
    registry: String,
    outer_checksum: String,
    source_sha256: String,
    verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct SourceSafetyRecord {
    source_sha256: String,
    deny_cpu_loops: bool,
    verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DependencyKey {
    package: String,
    version: String,
    registry: String,
    outer_checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceKey {
    source_sha256: String,
    deny_cpu_loops: bool,
}

#[derive(Debug, Clone)]
pub struct VerifiedSafetyCache {
    cache_sha256: String,
    analysis_policy_sha256: String,
    key_id: String,
    dependencies: BTreeSet<DependencyKey>,
    sources: BTreeSet<SourceKey>,
}

impl VerifiedSafetyCache {
    pub fn cache_sha256(&self) -> &str {
        &self.cache_sha256
    }

    pub fn analysis_policy_sha256(&self) -> &str {
        &self.analysis_policy_sha256
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn approves_dependency(
        &self,
        package: &str,
        version: &str,
        registry: &str,
        outer_checksum: &str,
    ) -> bool {
        self.dependencies.contains(&DependencyKey {
            package: package.to_owned(),
            version: version.to_owned(),
            registry: registry.to_owned(),
            outer_checksum: outer_checksum.to_ascii_uppercase(),
        })
    }

    pub fn approves_source(&self, source: &[u8], deny_cpu_loops: bool) -> bool {
        self.sources.contains(&SourceKey {
            source_sha256: sha256_hex(source),
            deny_cpu_loops,
        })
    }
}

pub fn load_verified_safety_cache(
    path: &Path,
    public_key_hex: &str,
    expected_key_id: Option<&str>,
    required_analysis_policy_sha256: &str,
    policy: &Policy,
) -> Result<VerifiedSafetyCache> {
    validate_lower_sha256(
        required_analysis_policy_sha256,
        "required safety analysis policy SHA-256",
    )?;

    let bytes = fs::read(path).with_context(|| format!("read safety cache {}", path.display()))?;
    let mut document: SafetyCacheDocument =
        serde_json::from_slice(&bytes).context("parse signed safety cache JSON")?;

    if document.format != SAFETY_CACHE_FORMAT_V1 {
        bail!("unsupported safety cache format `{}`", document.format);
    }
    if document.algorithm != "ed25519" {
        bail!(
            "unsupported safety cache signature algorithm `{}`",
            document.algorithm
        );
    }
    validate_token(&document.key_id, "safety cache key_id")?;
    if let Some(expected) = expected_key_id {
        if document.key_id != expected {
            bail!(
                "safety cache key_id `{}` does not match expected `{expected}`",
                document.key_id
            );
        }
    }
    if document.analyzer_schema != SAFETY_ANALYZER_SCHEMA_V1 {
        bail!(
            "unsupported safety analyzer schema `{}`; expected `{}`",
            document.analyzer_schema,
            SAFETY_ANALYZER_SCHEMA_V1
        );
    }
    validate_lower_sha256(
        &document.analysis_policy_sha256,
        "safety cache analysis_policy_sha256",
    )?;
    if document.analysis_policy_sha256 != required_analysis_policy_sha256 {
        bail!(
            "safety cache analysis policy digest does not match the required Zed/BeamScale analysis policy"
        );
    }

    validate_lower_sha256(
        &document.bmscl_policy_sha256,
        "safety cache bmscl_policy_sha256",
    )?;
    let expected_bmscl_policy = policy_sha256(policy)?;
    if document.bmscl_policy_sha256 != expected_bmscl_policy {
        bail!("safety cache was produced for a different BeamScale admission policy");
    }

    normalize_and_validate_records(&mut document)?;
    let signature = decode_signature(&document.signature_hex)?;
    let verifying_key = decode_verifying_key(public_key_hex)?;
    let payload = canonical_payload(&document);
    verifying_key
        .verify(&payload, &signature)
        .context("signed safety cache Ed25519 verification failed")?;

    let dependencies = document
        .dependencies
        .into_iter()
        .map(|record| DependencyKey {
            package: record.package,
            version: record.version,
            registry: record.registry,
            outer_checksum: record.outer_checksum,
        })
        .collect();
    let sources = document
        .sources
        .into_iter()
        .map(|record| SourceKey {
            source_sha256: record.source_sha256,
            deny_cpu_loops: record.deny_cpu_loops,
        })
        .collect();

    Ok(VerifiedSafetyCache {
        cache_sha256: sha256_hex(&bytes),
        analysis_policy_sha256: document.analysis_policy_sha256,
        key_id: document.key_id,
        dependencies,
        sources,
    })
}

fn normalize_and_validate_records(document: &mut SafetyCacheDocument) -> Result<()> {
    for dependency in &mut document.dependencies {
        validate_token(&dependency.package, "dependency package")?;
        validate_token(&dependency.version, "dependency version")?;
        if dependency.registry != "hex" {
            bail!(
                "safety cache dependency `{}` uses unsupported registry `{}`",
                dependency.package,
                dependency.registry
            );
        }
        dependency.outer_checksum = dependency.outer_checksum.to_ascii_uppercase();
        validate_upper_sha256(&dependency.outer_checksum, "dependency outer_checksum")?;
        validate_lower_sha256(&dependency.source_sha256, "dependency source_sha256")?;
        if dependency.verdict != "safe" {
            bail!("safety cache may contain only positive `safe` dependency verdicts");
        }
    }
    document.dependencies.sort();

    for source in &document.sources {
        validate_lower_sha256(&source.source_sha256, "source source_sha256")?;
        if source.verdict != "safe" {
            bail!("safety cache may contain only positive `safe` source verdicts");
        }
    }
    document.sources.sort();

    if document
        .dependencies
        .windows(2)
        .any(|items| items[0] == items[1])
    {
        bail!("safety cache contains duplicate dependency records");
    }
    if document
        .sources
        .windows(2)
        .any(|items| items[0] == items[1])
    {
        bail!("safety cache contains duplicate source records");
    }
    Ok(())
}

fn canonical_payload(document: &SafetyCacheDocument) -> Vec<u8> {
    let mut payload = Vec::new();
    push_field(&mut payload, &document.format);
    push_field(&mut payload, &document.algorithm);
    push_field(&mut payload, &document.key_id);
    push_field(&mut payload, &document.analyzer_schema);
    push_field(&mut payload, &document.analysis_policy_sha256);
    push_field(&mut payload, &document.bmscl_policy_sha256);

    for dependency in &document.dependencies {
        push_field(&mut payload, "dependency");
        push_field(&mut payload, &dependency.package);
        push_field(&mut payload, &dependency.version);
        push_field(&mut payload, &dependency.registry);
        push_field(&mut payload, &dependency.outer_checksum);
        push_field(&mut payload, &dependency.source_sha256);
        push_field(&mut payload, &dependency.verdict);
    }
    for source in &document.sources {
        push_field(&mut payload, "source");
        push_field(&mut payload, &source.source_sha256);
        push_field(
            &mut payload,
            if source.deny_cpu_loops {
                "true"
            } else {
                "false"
            },
        );
        push_field(&mut payload, &source.verdict);
    }
    payload
}

fn push_field(payload: &mut Vec<u8>, value: &str) {
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
}

fn policy_sha256(policy: &Policy) -> Result<String> {
    Ok(sha256_hex(
        &serde_json::to_vec(policy).context("serialize BeamScale policy for safety cache")?,
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f || byte > 0x7e)
    {
        bail!("{label} must be 1..=256 printable ASCII characters");
    }
    Ok(())
}

fn validate_lower_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_upper_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        bail!("{label} must be exactly 64 uppercase hexadecimal characters");
    }
    Ok(())
}

fn decode_verifying_key(value: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(value).context("safety cache public key must be hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("safety cache public key must be exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 safety cache public key")
}

fn decode_signature(value: &str) -> Result<Signature> {
    let bytes = hex::decode(value).context("safety cache signature must be hexadecimal")?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("safety cache signature must be exactly 64 bytes"))?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_payload, load_verified_safety_cache, policy_sha256, DependencySafetyRecord,
        SafetyCacheDocument, SourceSafetyRecord, SAFETY_ANALYZER_SCHEMA_V1, SAFETY_CACHE_FORMAT_V1,
    };
    use crate::model::Policy;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use tempfile::tempdir;

    const ANALYSIS_POLICY: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DEPENDENCY_CHECKSUM: &str =
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const DEPENDENCY_SOURCE: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn signed_document(policy: &Policy, source: &[u8]) -> (SafetyCacheDocument, String) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut document = SafetyCacheDocument {
            format: SAFETY_CACHE_FORMAT_V1.into(),
            algorithm: "ed25519".into(),
            key_id: "zed-ci".into(),
            analyzer_schema: SAFETY_ANALYZER_SCHEMA_V1.into(),
            analysis_policy_sha256: ANALYSIS_POLICY.into(),
            bmscl_policy_sha256: policy_sha256(policy).unwrap(),
            dependencies: vec![DependencySafetyRecord {
                package: "safe_dep".into(),
                version: "1.2.3".into(),
                registry: "hex".into(),
                outer_checksum: DEPENDENCY_CHECKSUM.into(),
                source_sha256: DEPENDENCY_SOURCE.into(),
                verdict: "safe".into(),
            }],
            sources: vec![SourceSafetyRecord {
                source_sha256: super::sha256_hex(source),
                deny_cpu_loops: false,
                verdict: "safe".into(),
            }],
            signature_hex: String::new(),
        };
        let signature = signing_key.sign(&canonical_payload(&document));
        document.signature_hex = hex::encode(signature.to_bytes());
        (
            document,
            hex::encode(signing_key.verifying_key().to_bytes()),
        )
    }

    #[test]
    fn verifies_content_addressed_dependency_and_source_hits() {
        let policy = Policy::default();
        let source = b"pub fn handle(x) { x }\n";
        let (document, public_key) = signed_document(&policy, source);
        let root = tempdir().unwrap();
        let path = root.path().join("safety-cache.json");
        fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let cache = load_verified_safety_cache(
            &path,
            &public_key,
            Some("zed-ci"),
            ANALYSIS_POLICY,
            &policy,
        )
        .unwrap();

        assert!(cache.approves_dependency("safe_dep", "1.2.3", "hex", DEPENDENCY_CHECKSUM));
        assert!(!cache.approves_dependency("safe_dep", "1.2.4", "hex", DEPENDENCY_CHECKSUM));
        assert!(cache.approves_source(source, false));
        assert!(!cache.approves_source(b"pub fn changed(x) { x }\n", false));
        assert!(!cache.approves_source(source, true));
    }

    #[test]
    fn cached_dependency_verdict_can_admit_exact_locked_hex_package() {
        let policy = Policy::default();
        let source = b"pub fn handle(x) { x }\n";
        let (document, public_key) = signed_document(&policy, source);
        let root = tempdir().unwrap();
        let cache_path = root.path().join("safety-cache.json");
        fs::write(&cache_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let cache = load_verified_safety_cache(
            &cache_path,
            &public_key,
            Some("zed-ci"),
            ANALYSIS_POLICY,
            &policy,
        )
        .unwrap();

        let project = root.path().join("worker");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(project.join("src/worker.gleam"), source).unwrap();
        fs::write(
            project.join("gleam.toml"),
            "name = \"worker\"\nversion = \"0.1.0\"\n[dependencies]\nsafe_dep = \"1.2.3\"\n",
        )
        .unwrap();
        fs::write(
            project.join("manifest.toml"),
            format!(
                "[[packages]]\nname = \"safe_dep\"\nversion = \"1.2.3\"\nsource = \"hex\"\nbuild_tools = [\"gleam\"]\nouter_checksum = \"{DEPENDENCY_CHECKSUM}\"\n"
            ),
        )
        .unwrap();

        let report =
            crate::analyze::check_project_with_cache(&project, &policy, None, false, Some(&cache))
                .unwrap();
        assert!(report.admitted, "{:?}", report.findings);
        assert_eq!(
            report.safety_cache_sha256.as_deref(),
            Some(cache.cache_sha256())
        );

        fs::write(
            project.join("manifest.toml"),
            "[[packages]]\nname = \"safe_dep\"\nversion = \"1.2.3\"\nsource = \"hex\"\nbuild_tools = [\"gleam\"]\nouter_checksum = \"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\"\n",
        )
        .unwrap();
        let changed =
            crate::analyze::check_project_with_cache(&project, &policy, None, false, Some(&cache))
                .unwrap();
        assert!(!changed.admitted);
        assert!(changed.findings.iter().any(|finding| {
            finding.code == "BMSCL_DEPENDENCY_CHECKSUM_NOT_APPROVED"
                || finding.code == "BMSCL_UNAPPROVED_TRANSITIVE_DEPENDENCY"
        }));
    }

    #[test]
    fn rejects_tampered_cache_after_signing() {
        let policy = Policy::default();
        let (mut document, public_key) = signed_document(&policy, b"pub fn ok() { Nil }\n");
        document.dependencies[0].version = "9.9.9".into();
        let root = tempdir().unwrap();
        let path = root.path().join("safety-cache.json");
        fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        assert!(load_verified_safety_cache(
            &path,
            &public_key,
            Some("zed-ci"),
            ANALYSIS_POLICY,
            &policy,
        )
        .is_err());
    }

    #[test]
    fn rejects_cache_when_beamscale_policy_changes() {
        let policy = Policy::default();
        let (document, public_key) = signed_document(&policy, b"pub fn ok() { Nil }\n");
        let root = tempdir().unwrap();
        let path = root.path().join("safety-cache.json");
        fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let mut changed_policy = policy.clone();
        changed_policy.max_heap_bytes += 1;

        assert!(load_verified_safety_cache(
            &path,
            &public_key,
            Some("zed-ci"),
            ANALYSIS_POLICY,
            &changed_policy,
        )
        .is_err());
    }
}
