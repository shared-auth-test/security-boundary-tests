use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const HOSTED_PROFILE_V2: &str = "bmscl-hosted-gleam-v2-read-only";
pub const HOSTED_PROFILE_V3_HTTP: &str = "bmscl-hosted-gleam-v3-http-capability";
pub const DURABLE_ACTOR_PROFILE_V1: &str = "bmscl-hosted-gleam-durable-actor-v1";
pub const ERLANG_CRITICAL_SECTION_PROFILE_V1: &str = "bmscl-critical-section-erlang-v1";
pub const PROVENANCE_FORMAT_V1: &str = "bmscl-build-provenance-v1";
pub const MODULE_CONTRACT_V1: &str = "bmscl-module-contract-v1";
pub const CONTEXT_ABI_V1: &str = "bmscl.context/v1";
pub const DEFAULT_TRUSTED_SDK_SHA256: &str =
    "2c5818e5306d4bbcc02796a6a58cb3f1942eb0cbabb19a7dee6c3d7df178ea6b";
pub const MAX_LAMBDA_WALL_MS: u64 = 90_000;

/// Ambient machine authority that a hosted worker can never enable.
///
/// `dynamic_eval` covers erl_eval/compiler/code-generation style execution and
/// `compile_time_code_execution` covers parse transforms / build hooks. Both
/// are explicit policy knobs so an artifact cannot attempt to opt back into
/// them through worker configuration.
pub const FORBIDDEN_SECURITY_KEYS: &[&str] = &[
    "filesystem",
    "process_exec",
    "process_creation",
    "raw_sockets",
    "native_code",
    "code_loading",
    "beam_distribution",
    "global_ets",
    "persistent_term",
    "customer_ffi",
    "dynamic_eval",
    "compile_time_code_execution",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub policy_version: String,
    pub allowed_dependencies: BTreeSet<String>,
    pub allowed_dependency_checksums: BTreeMap<String, BTreeSet<String>>,
    pub trusted_sdk_sha256: String,
    pub forbidden_import_prefixes: Vec<String>,
    pub forbidden_source_patterns: Vec<String>,
    pub forbidden_erlang_patterns: Vec<String>,
    pub max_wall_ms: u64,
    pub max_reductions: u64,
    pub max_heap_bytes: u64,
    pub max_processes: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            policy_version: HOSTED_PROFILE_V2.into(),
            allowed_dependencies: ["gleam_stdlib"].into_iter().map(str::to_string).collect(),
            allowed_dependency_checksums: BTreeMap::new(),
            trusted_sdk_sha256: DEFAULT_TRUSTED_SDK_SHA256.into(),
            forbidden_import_prefixes: vec![
                "gleam/erlang".into(),
                "gleam/otp".into(),
                "gleam_erlang".into(),
                "gleam/io".into(),
                "gleam/iterator".into(),
            ],
            forbidden_source_patterns: vec![
                "@external(erlang".into(),
                "@external(elixir".into(),
                "@external(javascript".into(),
            ],
            forbidden_erlang_patterns: vec![
                "os:".into(),
                "file:".into(),
                "filelib:".into(),
                "prim_file:".into(),
                "erl_prim_loader:".into(),
                "erl_tar:".into(),
                "zip:".into(),
                "code:".into(),
                "compile:".into(),
                "epp:".into(),
                "erl_eval:".into(),
                "erl_scan:".into(),
                "erl_parse:".into(),
                "erl_ddll:".into(),
                "net_kernel:".into(),
                "rpc:".into(),
                "erpc:".into(),
                "persistent_term:".into(),
                "ets:".into(),
                "dets:".into(),
                "mnesia:".into(),
                "disk_log:".into(),
                "proc_lib:".into(),
                "gen_server:start".into(),
                "gen_statem:start".into(),
                "supervisor:start".into(),
                "gen_tcp:".into(),
                "gen_udp:".into(),
                "socket:".into(),
                "ssl:".into(),
                "httpc:".into(),
                "inets:".into(),
                "inet:".into(),
                "erlang:spawn".into(),
                "erlang:apply".into(),
                "erlang:make_fun".into(),
                "erlang:halt".into(),
                "erlang:open_port".into(),
                "erlang:load_nif".into(),
                "-compile({parse_transform".into(),
                "-on_load(".into(),
            ],
            max_wall_ms: 30_000,
            max_reductions: 50_000_000,
            max_heap_bytes: 64 * 1024 * 1024,
            max_processes: 1,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkerConfig {
    pub security: BTreeMap<String, String>,
    pub permissions: BTreeMap<String, Vec<String>>,
    pub limits: WorkerLimits,
    pub durable: Option<DurableActorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DurableActorConfig {
    pub namespace: String,
    pub virtual_shards: u32,
    pub shards_per_actor: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkerLimits {
    pub max_wall_ms: Option<u64>,
    pub max_reductions: Option<u64>,
    pub max_heap_bytes: Option<u64>,
    pub max_processes: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: &'static str,
    pub code: &'static str,
    pub file: String,
    pub line: Option<usize>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeLimits {
    pub max_wall_ms: u64,
    pub max_reductions: u64,
    pub max_heap_bytes: u64,
    pub max_processes: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdmissionReport {
    pub admitted: bool,
    pub policy_version: String,
    pub source_sha256: String,
    pub findings: Vec<Finding>,
    pub runtime_limits: RuntimeLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_cache_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_analysis_policy_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_cache_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durable: Option<DurableActorConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityGrant {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildProvenance {
    pub format: &'static str,
    pub builder_id: String,
    pub builder_image_digest: String,
    pub compiler_version: String,
    pub compiler_revision: String,
    pub gleam_version: String,
    pub otp_release: String,
    pub erts_version: String,
    pub policy_sha256: String,
    pub dependency_lock_sha256: Option<String>,
    pub trusted_sdk_sha256: Option<String>,
    pub source_sha256: String,
    pub build_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactManifest {
    pub format_version: u32,
    pub runtime: &'static str,
    pub language: &'static str,
    pub profile: String,
    pub module_contract_version: &'static str,
    pub context_abi: &'static str,
    pub source_sha256: String,
    pub build_sha256: String,
    pub provenance_sha256: String,
    pub entrypoint: String,
    pub capabilities: Vec<CapabilityGrant>,
    pub runtime_limits: RuntimeLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durable: Option<DurableActorConfig>,
}

#[cfg(test)]
mod durable_config_tests {
    use super::WorkerConfig;

    #[test]
    fn durable_config_rejects_unknown_fields() {
        let raw = r#"
[durable]
namespace = "rooms"
virtual_shards = 4096
shards_per_actor = 64
shards_per_acotr = 64
"#;
        let error =
            toml::from_str::<WorkerConfig>(raw).expect_err("unknown durable keys must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }
}
