use crate::model::{
    CapabilityGrant, Finding, Policy, RuntimeLimits, WorkerConfig, DURABLE_ACTOR_PROFILE_V1,
    ERLANG_CRITICAL_SECTION_PROFILE_V1, FORBIDDEN_SECURITY_KEYS, HOSTED_PROFILE_V2,
    HOSTED_PROFILE_V3_HTTP, MAX_LAMBDA_WALL_MS,
};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

const HTTP_MAX_REQUEST_BODY_BYTES: u64 = 1024 * 1024;
const HTTP_MAX_RESPONSE_BODY_BYTES: u64 = 4 * 1024 * 1024;

pub fn load_policy(path: Option<&Path>) -> Result<Policy> {
    let policy = match path {
        None => Policy::default(),
        Some(path) => {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("read policy {}", path.display()))?;
            toml::from_str(&raw).context("parse policy TOML")?
        }
    };
    validate_policy(&policy)?;
    Ok(policy)
}

fn validate_policy(policy: &Policy) -> Result<()> {
    if policy.policy_version != HOSTED_PROFILE_V2
        && policy.policy_version != HOSTED_PROFILE_V3_HTTP
        && policy.policy_version != DURABLE_ACTOR_PROFILE_V1
        && policy.policy_version != ERLANG_CRITICAL_SECTION_PROFILE_V1
    {
        bail!(
            "unsupported hosted policy profile `{}`",
            policy.policy_version
        );
    }
    if !valid_lower_sha256(&policy.trusted_sdk_sha256) {
        bail!("policy trusted_sdk_sha256 must be exactly 64 lowercase hexadecimal characters");
    }
    if policy.max_wall_ms == 0 || policy.max_wall_ms > MAX_LAMBDA_WALL_MS {
        bail!(
            "policy max_wall_ms must be in 1..={MAX_LAMBDA_WALL_MS}; got {}",
            policy.max_wall_ms
        );
    }
    if policy.max_reductions == 0 {
        bail!("policy max_reductions must be positive");
    }
    if policy.max_heap_bytes < 1024 * 1024 {
        bail!("policy max_heap_bytes must be at least 1 MiB");
    }
    if policy.max_processes != 1 {
        bail!(
            "hosted policy max_processes must remain exactly 1; got {}",
            policy.max_processes
        );
    }
    Ok(())
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn load_worker_config(
    project: &Path,
    explicit: Option<&Path>,
) -> Result<(WorkerConfig, PathBuf)> {
    let path = explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(|| project.join(".ores-lambda.toml"));
    if !path.exists() {
        if explicit.is_some() {
            bail!("worker config does not exist: {}", path.display());
        }
        return Ok((WorkerConfig::default(), path));
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read worker config {}", path.display()))?;
    let config = toml::from_str(&raw).context("parse worker config TOML")?;
    Ok((config, path))
}

pub fn effective_limits(policy: &Policy, config: &WorkerConfig) -> RuntimeLimits {
    RuntimeLimits {
        max_wall_ms: config.limits.max_wall_ms.unwrap_or(policy.max_wall_ms),
        max_reductions: config
            .limits
            .max_reductions
            .unwrap_or(policy.max_reductions),
        max_heap_bytes: config
            .limits
            .max_heap_bytes
            .unwrap_or(policy.max_heap_bytes),
        max_processes: config.limits.max_processes.unwrap_or(policy.max_processes),
    }
}

pub fn check_worker_config(
    config: &WorkerConfig,
    path: &Path,
    policy: &Policy,
    findings: &mut Vec<Finding>,
) {
    for (key, value) in &config.security {
        if !FORBIDDEN_SECURITY_KEYS.contains(&key.as_str()) {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_UNKNOWN_SECURITY_SETTING",
                file: path.display().to_string(),
                line: None,
                message: format!(
                    "unknown security setting `{key}`; hosted security is fail-closed"
                ),
            });
        } else if value != "deny" {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_AMBIENT_AUTHORITY_FORBIDDEN",
                file: path.display().to_string(),
                line: None,
                message: format!("`{key}` must remain `deny` on the shared tier"),
            });
        }
    }

    let http_profile = policy.policy_version == HOSTED_PROFILE_V3_HTTP;
    for (key, values) in &config.permissions {
        if !http_profile || key != "http" {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_UNKNOWN_PERMISSION",
                file: path.display().to_string(),
                line: None,
                message: format!(
                    "permission `{key}` is not available in hosted profile `{}`",
                    policy.policy_version
                ),
            });
            continue;
        }
        if values.is_empty() {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_HTTP_SCOPE_REQUIRED",
                file: path.display().to_string(),
                line: None,
                message: "v3 HTTP capability requires at least one exact HTTPS origin".into(),
            });
        }
        for value in values {
            if !valid_https_origin(value) {
                findings.push(Finding {
                    severity: "error",
                    code: "BMSCL_INVALID_HTTP_ORIGIN",
                    file: path.display().to_string(),
                    line: None,
                    message: format!(
                        "HTTP scope `{value}` must be an exact public-style HTTPS origin with no path, query, fragment, wildcard, credentials, localhost, or IP literal"
                    ),
                });
            }
        }
    }
    if http_profile && !config.permissions.contains_key("http") {
        findings.push(Finding {
            severity: "error",
            code: "BMSCL_HTTP_SCOPE_REQUIRED",
            file: path.display().to_string(),
            line: None,
            message: "v3 HTTP capability requires [permissions].http exact HTTPS origins".into(),
        });
    }

    let durable_profile = policy.policy_version == DURABLE_ACTOR_PROFILE_V1;
    match (&config.durable, durable_profile) {
        (None, true) => findings.push(Finding {
            severity: "error",
            code: "BMSCL_DURABLE_CONFIG_REQUIRED",
            file: path.display().to_string(),
            line: None,
            message: "durable actor profile requires a [durable] section".into(),
        }),
        (Some(_), false) => findings.push(Finding {
            severity: "error",
            code: "BMSCL_DURABLE_CONFIG_FORBIDDEN",
            file: path.display().to_string(),
            line: None,
            message: "durable actor configuration is only valid for the durable actor profile"
                .into(),
        }),
        (Some(durable), true) => {
            let valid_namespace = !durable.namespace.is_empty()
                && durable.namespace.len() <= 128
                && durable
                    .namespace
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
            if !valid_namespace {
                findings.push(Finding {
                    severity: "error",
                    code: "BMSCL_DURABLE_NAMESPACE_INVALID",
                    file: path.display().to_string(),
                    line: None,
                    message:
                        "durable namespace must be 1..=128 ASCII letters, digits, '.', '_' or '-'"
                            .into(),
                });
            }

            let valid_layout = durable.virtual_shards >= 64
                && durable.virtual_shards <= 65_536
                && durable.shards_per_actor > 0
                && durable.shards_per_actor <= 4_096
                && durable.shards_per_actor <= durable.virtual_shards
                && durable.virtual_shards % durable.shards_per_actor == 0;
            if !valid_layout {
                findings.push(Finding {
                    severity: "error",
                    code: "BMSCL_DURABLE_SHARD_LAYOUT_INVALID",
                    file: path.display().to_string(),
                    line: None,
                    message: "durable virtual_shards must be 64..=65536; shards_per_actor must be 1..=4096, <= virtual_shards, and divide virtual_shards exactly".into(),
                });
            }
        }
        (None, false) => {}
    }

    let limits = effective_limits(policy, config);
    let invalid_limits = limits.max_wall_ms == 0
        || limits.max_wall_ms > policy.max_wall_ms
        || limits.max_wall_ms > MAX_LAMBDA_WALL_MS
        || limits.max_reductions == 0
        || limits.max_reductions > policy.max_reductions
        || limits.max_heap_bytes < 1024 * 1024
        || limits.max_heap_bytes > policy.max_heap_bytes
        || limits.max_processes != 1
        || limits.max_processes > policy.max_processes;
    if invalid_limits {
        findings.push(Finding {
            severity: "error",
            code: "BMSCL_RUNTIME_LIMIT_OUT_OF_POLICY",
            file: path.display().to_string(),
            line: None,
            message: format!(
                "worker runtime limits must reduce policy maxima, max_wall_ms may not exceed {MAX_LAMBDA_WALL_MS}, and max_processes must remain exactly 1"
            ),
        });
    }
}

pub fn capability_grants(config: &WorkerConfig) -> Vec<CapabilityGrant> {
    let mut grants = vec![
        CapabilityGrant {
            name: "ctx.log".into(),
            scope: Some(json!({
                "sink": "tenant-observability",
                "application_state": false
            })),
        },
        CapabilityGrant {
            name: "ctx.cluster".into(),
            scope: Some(json!({
                "transport": "http-semantics",
                "same_cluster_only": true,
                "version_affinity": "inherit",
                "methods": ["GET", "HEAD"],
                "max_request_body_bytes": 0
            })),
        },
    ];
    if let Some(origins) = config.permissions.get("http") {
        let mut origins = origins.clone();
        origins.sort();
        origins.dedup();
        grants.push(CapabilityGrant {
            name: "ctx.http".into(),
            scope: Some(json!({
                "origins": origins,
                "methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "max_request_body_bytes": HTTP_MAX_REQUEST_BODY_BYTES,
                "max_response_body_bytes": HTTP_MAX_RESPONSE_BODY_BYTES,
                "max_redirects": 0,
                "public_network_only": true
            })),
        });
    }
    grants
}

fn valid_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.contains('*')
        || authority.chars().any(char::is_whitespace)
    {
        return false;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        _ => (authority, None),
    };
    if host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || !host.contains('.')
        || host.chars().all(|c| c.is_ascii_digit() || c == '.')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }
    if let Some(port) = port {
        match port.parse::<u16>() {
            Ok(1..=u16::MAX) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{check_worker_config, valid_https_origin, validate_policy};
    use crate::model::{
        DurableActorConfig, Policy, WorkerConfig, DURABLE_ACTOR_PROFILE_V1, HOSTED_PROFILE_V3_HTTP,
        MAX_LAMBDA_WALL_MS,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn default_policy_respects_platform_invariants() {
        validate_policy(&Policy::default()).expect("default policy must remain valid");
    }

    #[test]
    fn rejects_invalid_trusted_sdk_digest() {
        let policy = Policy {
            trusted_sdk_sha256: "ABC".into(),
            ..Policy::default()
        };
        let error = validate_policy(&policy).expect_err("invalid SDK digest must fail closed");
        assert!(error.to_string().contains("trusted_sdk_sha256"));
    }

    #[test]
    fn rejects_policy_above_platform_wall_cap() {
        let policy = Policy {
            max_wall_ms: MAX_LAMBDA_WALL_MS + 1,
            ..Policy::default()
        };
        let error = validate_policy(&policy).expect_err("wall cap must fail closed");
        assert!(error.to_string().contains("max_wall_ms"));
        assert!(error.to_string().contains("90000"));
    }

    #[test]
    fn rejects_policy_that_allows_tenant_process_creation() {
        let policy = Policy {
            max_processes: 2,
            ..Policy::default()
        };
        let error = validate_policy(&policy).expect_err("process count must stay one");
        assert!(error.to_string().contains("exactly 1"));
    }

    #[test]
    fn v2_still_rejects_http_permissions() {
        let mut config = WorkerConfig::default();
        config
            .permissions
            .insert("http".into(), vec!["https://example.com".into()]);
        let mut findings = vec![];
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &Policy::default(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.code == "BMSCL_UNKNOWN_PERMISSION"));
    }

    #[test]
    fn worker_config_rejects_unknown_top_level_keys() {
        let raw = r#"
typo_permissions = {}
"#;
        let error = toml::from_str::<WorkerConfig>(raw)
            .expect_err("unknown top-level worker config keys must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn worker_config_rejects_unknown_limit_keys() {
        let raw = r#"
[limits]
max_heap_bytez = 1048576
"#;
        let error =
            toml::from_str::<WorkerConfig>(raw).expect_err("unknown limit keys must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn durable_profile_requires_valid_shard_layout() {
        let policy = Policy {
            policy_version: DURABLE_ACTOR_PROFILE_V1.into(),
            ..Policy::default()
        };
        let mut config = WorkerConfig {
            durable: Some(DurableActorConfig {
                namespace: "cart".into(),
                virtual_shards: 4096,
                shards_per_actor: 64,
            }),
            ..WorkerConfig::default()
        };
        let mut findings = vec![];
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &policy,
            &mut findings,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");

        config.durable = Some(DurableActorConfig {
            namespace: "cart".into(),
            virtual_shards: 4096,
            shards_per_actor: 63,
        });
        findings.clear();
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &policy,
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.code == "BMSCL_DURABLE_SHARD_LAYOUT_INVALID"));

        for invalid in [
            DurableActorConfig {
                namespace: "cart".into(),
                virtual_shards: 1,
                shards_per_actor: 1,
            },
            DurableActorConfig {
                namespace: "cart".into(),
                virtual_shards: 8192,
                shards_per_actor: 8192,
            },
        ] {
            config.durable = Some(invalid);
            findings.clear();
            check_worker_config(
                &config,
                Path::new(".ores-lambda.toml"),
                &policy,
                &mut findings,
            );
            assert!(findings
                .iter()
                .any(|f| f.code == "BMSCL_DURABLE_SHARD_LAYOUT_INVALID"));
        }

        config.durable = Some(DurableActorConfig {
            namespace: "cart/escape".into(),
            virtual_shards: 4096,
            shards_per_actor: 64,
        });
        findings.clear();
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &policy,
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.code == "BMSCL_DURABLE_NAMESPACE_INVALID"));
    }

    #[test]
    fn non_durable_profile_rejects_durable_config() {
        let config = WorkerConfig {
            durable: Some(DurableActorConfig {
                namespace: "cart".into(),
                virtual_shards: 1024,
                shards_per_actor: 64,
            }),
            ..WorkerConfig::default()
        };
        let mut findings = vec![];
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &Policy::default(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.code == "BMSCL_DURABLE_CONFIG_FORBIDDEN"));
    }

    #[test]
    fn v3_requires_exact_https_origins() {
        assert!(valid_https_origin("https://api.example.com"));
        assert!(valid_https_origin("https://api.example.com:8443"));
        for denied in [
            "http://api.example.com",
            "https://localhost",
            "https://127.0.0.1",
            "https://*.example.com",
            "https://api.example.com/path",
            "https://user@example.com",
        ] {
            assert!(
                !valid_https_origin(denied),
                "unexpectedly admitted {denied}"
            );
        }

        let policy = Policy {
            policy_version: HOSTED_PROFILE_V3_HTTP.into(),
            ..Policy::default()
        };
        let mut config = WorkerConfig {
            permissions: BTreeMap::from([("http".into(), vec!["https://api.example.com".into()])]),
            ..WorkerConfig::default()
        };
        let mut findings = vec![];
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &policy,
            &mut findings,
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");

        config
            .permissions
            .insert("http".into(), vec!["https://localhost".into()]);
        findings.clear();
        check_worker_config(
            &config,
            Path::new(".ores-lambda.toml"),
            &policy,
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.code == "BMSCL_INVALID_HTTP_ORIGIN"));
    }
}
