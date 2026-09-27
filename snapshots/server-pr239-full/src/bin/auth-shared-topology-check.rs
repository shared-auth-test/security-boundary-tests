use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;

const TOPOLOGY_PATH: &str = "config/shared-auth-topology.toml";
const RUNTIME_PATH: &str = "config/auth-realms.contract.json";
const PROCFILE_PATH: &str = "Procfile";
const OVERMIND_ENV_PATH: &str = ".overmind.env.example";
const REALMS: [&str; 2] = ["customer", "admin"];
const REQUIRED_APPS: [&str; 3] = ["zed-pkg", "sonus-auris", "fiducia-cloud"];
const RESERVED_POLICY_FILES: [&str; 2] = [".shared-auth.toml", ".auth-shared.toml"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Atom {
    String(String),
    Bool(bool),
    Integer(i64),
    StringArray(Vec<String>),
}

#[derive(Debug, Default)]
struct MiniToml {
    sections: BTreeMap<String, BTreeMap<String, Atom>>,
    arrays: BTreeMap<String, Vec<BTreeMap<String, Atom>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    code: &'static str,
    message: String,
}

impl Finding {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
enum Scope {
    Section(String),
    Array(String, usize),
}

fn main() {
    let root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    match validate_repo(&root) {
        Ok(findings) if findings.is_empty() => {
            println!("auth-shared topology contract is valid");
        }
        Ok(findings) => {
            for finding in &findings {
                println!("{}: {}", finding.code, finding.message);
            }
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("auth-shared-topology-check: {error}");
            std::process::exit(2);
        }
    }
}

fn validate_repo(root: &Path) -> Result<Vec<Finding>, String> {
    let topology_path = root.join(TOPOLOGY_PATH);
    let topology_text = fs::read_to_string(&topology_path)
        .map_err(|error| format!("read {}: {error}", topology_path.display()))?;
    let runtime_text = fs::read_to_string(root.join(RUNTIME_PATH))
        .map_err(|error| format!("read {RUNTIME_PATH}: {error}"))?;
    let procfile_text = fs::read_to_string(root.join(PROCFILE_PATH))
        .map_err(|error| format!("read {PROCFILE_PATH}: {error}"))?;
    let overmind_text = fs::read_to_string(root.join(OVERMIND_ENV_PATH))
        .map_err(|error| format!("read {OVERMIND_ENV_PATH}: {error}"))?;
    validate_texts(
        root,
        Path::new(TOPOLOGY_PATH),
        &topology_text,
        &runtime_text,
        &procfile_text,
        &overmind_text,
    )
}

fn validate_texts(
    root: &Path,
    topology_path: &Path,
    topology_text: &str,
    runtime_text: &str,
    procfile_text: &str,
    overmind_text: &str,
) -> Result<Vec<Finding>, String> {
    let topology = parse_toml(topology_text)?;
    let runtime: JsonValue = serde_json::from_str(runtime_text)
        .map_err(|error| format!("invalid runtime JSON: {error}"))?;
    let mut findings = Vec::new();

    validate_reserved_filename(topology_path, &mut findings);
    validate_contract(root, &topology, &mut findings);
    validate_identity_and_canonical(&topology, &mut findings);
    validate_secret_hygiene(&topology, &mut findings);
    validate_topology_realms(&topology, &mut findings);
    validate_providers(&topology, &mut findings);
    validate_applications(&topology, &mut findings);
    validate_procfile(&topology, procfile_text, &mut findings);
    validate_overmind(overmind_text, &mut findings);
    validate_runtime(&topology, &runtime, &mut findings);

    Ok(findings)
}

fn parse_toml(text: &str) -> Result<MiniToml, String> {
    let mut parsed = MiniToml::default();
    let mut scope: Option<Scope> = None;

    for (line_number, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim().to_owned();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix("[[").and_then(|v| v.strip_suffix("]]")) {
            let name = name.trim();
            if name.is_empty() {
                return Err(format!("line {}: empty array-table name", line_number + 1));
            }
            let entries = parsed.arrays.entry(name.to_owned()).or_default();
            entries.push(BTreeMap::new());
            scope = Some(Scope::Array(name.to_owned(), entries.len() - 1));
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            let name = name.trim();
            if name.is_empty() {
                return Err(format!("line {}: empty table name", line_number + 1));
            }
            parsed.sections.entry(name.to_owned()).or_default();
            scope = Some(Scope::Section(name.to_owned()));
            continue;
        }

        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected key = value", line_number + 1))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("line {}: empty key", line_number + 1));
        }
        let value = parse_atom(raw_value.trim(), line_number + 1)?;

        match &scope {
            Some(Scope::Section(name)) => {
                let table = parsed.sections.get_mut(name).expect("section must exist");
                if table.insert(key.to_owned(), value).is_some() {
                    return Err(format!("line {}: duplicate key {name}.{key}", line_number + 1));
                }
            }
            Some(Scope::Array(name, index)) => {
                let table = parsed
                    .arrays
                    .get_mut(name)
                    .and_then(|entries| entries.get_mut(*index))
                    .expect("array table must exist");
                if table.insert(key.to_owned(), value).is_some() {
                    return Err(format!("line {}: duplicate key {name}[{index}].{key}", line_number + 1));
                }
            }
            None => {
                let table = parsed.sections.entry(String::new()).or_default();
                if table.insert(key.to_owned(), value).is_some() {
                    return Err(format!("line {}: duplicate root key {key}", line_number + 1));
                }
            }
        }
    }

    Ok(parsed)
}

fn strip_comment(line: &str) -> String {
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if ch == '#' && !quoted {
            return line[..index].to_owned();
        }
    }
    line.to_owned()
}

fn parse_atom(raw: &str, line_number: usize) -> Result<Atom, String> {
    if raw.starts_with('"') {
        let value = serde_json::from_str::<String>(raw)
            .map_err(|error| format!("line {line_number}: unsupported string syntax: {error}"))?;
        return Ok(Atom::String(value));
    }
    if raw.starts_with('[') {
        let values = serde_json::from_str::<Vec<String>>(raw)
            .map_err(|error| format!("line {line_number}: only string arrays are supported: {error}"))?;
        return Ok(Atom::StringArray(values));
    }
    if raw == "true" {
        return Ok(Atom::Bool(true));
    }
    if raw == "false" {
        return Ok(Atom::Bool(false));
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Ok(Atom::Integer(value));
    }
    Err(format!(
        "line {line_number}: unsupported topology value; use strings, booleans, integers, or string arrays"
    ))
}

fn section<'a>(topology: &'a MiniToml, name: &str) -> &'a BTreeMap<String, Atom> {
    topology.sections.get(name).unwrap_or(&EMPTY_TABLE)
}

static EMPTY_TABLE: BTreeMap<String, Atom> = BTreeMap::new();

fn string(table: &BTreeMap<String, Atom>, key: &str) -> Option<&str> {
    match table.get(key) {
        Some(Atom::String(value)) => Some(value),
        _ => None,
    }
}

fn boolean(table: &BTreeMap<String, Atom>, key: &str) -> Option<bool> {
    match table.get(key) {
        Some(Atom::Bool(value)) => Some(*value),
        _ => None,
    }
}

fn integer(table: &BTreeMap<String, Atom>, key: &str) -> Option<i64> {
    match table.get(key) {
        Some(Atom::Integer(value)) => Some(*value),
        _ => None,
    }
}

fn strings<'a>(table: &'a BTreeMap<String, Atom>, key: &str) -> Option<&'a [String]> {
    match table.get(key) {
        Some(Atom::StringArray(values)) => Some(values),
        _ => None,
    }
}

fn validate_reserved_filename(path: &Path, findings: &mut Vec<Finding>) {
    let filename = path.file_name().and_then(|value| value.to_str()).unwrap_or_default();
    if RESERVED_POLICY_FILES.contains(&filename) {
        findings.push(Finding::new(
            "U02-reserved-policy-filename",
            format!("topology must not use reserved consumer-policy filename {filename}"),
        ));
    }
}

fn validate_contract(root: &Path, topology: &MiniToml, findings: &mut Vec<Finding>) {
    let contract = section(topology, "contract");
    if string(contract, "name") != Some("shared-auth") || integer(contract, "schema_version") != Some(1) {
        findings.push(Finding::new(
            "U01-rust-topology-contract",
            "[contract] must declare name=shared-auth and schema_version=1",
        ));
    }
    if boolean(contract, "secrets_allowed") != Some(false) {
        findings.push(Finding::new(
            "U01-rust-topology-contract",
            "contract.secrets_allowed must be false",
        ));
    }
    if string(contract, "runtime_contract") != Some(RUNTIME_PATH)
        || string(contract, "runtime_schema") != Some("db/schema.sql")
    {
        findings.push(Finding::new(
            "U03-executable-authority-refs",
            "topology must reference config/auth-realms.contract.json and db/schema.sql",
        ));
    }
    for key in ["runtime_contract", "runtime_schema", "runtime_flags", "canonical_docs"] {
        match string(contract, key) {
            Some(value) if root.join(value).is_file() => {}
            Some(value) => findings.push(Finding::new(
                "U03-executable-authority-refs",
                format!("contract.{key} references missing file {value}"),
            )),
            None => findings.push(Finding::new(
                "U03-executable-authority-refs",
                format!("contract.{key} must be a repository-relative file path"),
            )),
        }
    }
}

fn validate_identity_and_canonical(topology: &MiniToml, findings: &mut Vec<Finding>) {
    let identity = section(topology, "identity");
    if string(identity, "stable_id") != Some("shared_user_id")
        || strings(identity, "provider_binding_key")
            != Some(&[
                "provider".to_owned(),
                "issuer".to_owned(),
                "subject".to_owned(),
                "realm".to_owned(),
            ][..])
    {
        findings.push(Finding::new(
            "U04-canonical-identity-boundary",
            "identity must use shared_user_id and provider/issuer/subject/realm binding",
        ));
    }
    for key in ["merge_by_email", "merge_by_phone", "merge_by_username"] {
        if boolean(identity, key) != Some(false) {
            findings.push(Finding::new(
                "U04-canonical-identity-boundary",
                format!("identity.{key} must be false"),
            ));
        }
    }
    if string(identity, "product_authorization_owner") != Some("application-databases") {
        findings.push(Finding::new(
            "U04-canonical-identity-boundary",
            "product authorization must remain owned by application databases",
        ));
    }
    let canonical = section(topology, "canonical_tables");
    if string(canonical, "mode") != Some("accepted-target-semantics")
        || string(canonical, "principals") != Some("shared_auth.principals")
    {
        findings.push(Finding::new(
            "U04-canonical-identity-boundary",
            "canonical table targets must remain semantic targets rooted at shared_auth.principals",
        ));
    }
}

fn validate_secret_hygiene(topology: &MiniToml, findings: &mut Vec<Finding>) {
    for (section_name, table) in &topology.sections {
        validate_table_secret_hygiene(section_name, table, findings);
    }
    for (name, entries) in &topology.arrays {
        for (index, table) in entries.iter().enumerate() {
            validate_table_secret_hygiene(&format!("{name}[{index}]"), table, findings);
        }
    }
}

fn validate_table_secret_hygiene(
    prefix: &str,
    table: &BTreeMap<String, Atom>,
    findings: &mut Vec<Finding>,
) {
    for (key, value) in table {
        let lower = key.to_ascii_lowercase();
        let sensitive_name = ["secret", "token", "password", "private", "credential", "api_key", "service_role"]
            .iter()
            .any(|part| lower.contains(part));
        let metadata_key = lower.ends_with("_env")
            || lower.ends_with("_ref")
            || matches!(lower.as_str(), "credentials_in_contract" | "secrets_allowed");
        if sensitive_name && !metadata_key {
            match value {
                Atom::Bool(false) => {}
                Atom::String(text) if text == "provider-native" => {}
                _ => findings.push(Finding::new(
                    "U10-inline-secret-hygiene",
                    format!("{prefix}.{key} looks secret-bearing and must be metadata-only"),
                )),
            }
        }
        if let Atom::String(text) = value {
            let upper = text.to_ascii_uppercase();
            let lower_value = text.to_ascii_lowercase();
            if upper.contains("BEGIN PRIVATE KEY")
                || upper.contains("BEGIN EC PRIVATE KEY")
                || lower_value.starts_with("postgres://")
                || lower_value.starts_with("postgresql://")
                || looks_like_jwt(text)
            {
                findings.push(Finding::new(
                    "U10-inline-secret-hygiene",
                    format!("{prefix}.{key} contains a secret-like inline value"),
                ));
            }
        }
    }
}

fn looks_like_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    matches!(parts.next(), Some(first) if first.starts_with("eyJ") && first.len() >= 16)
        && parts.next().is_some()
        && parts.next().is_some()
}

fn validate_topology_realms(topology: &MiniToml, findings: &mut Vec<Finding>) {
    let mut ports = BTreeSet::new();
    let mut cookies = BTreeSet::new();
    let mut envs_by_realm = BTreeMap::<&str, BTreeSet<String>>::new();

    for realm in REALMS {
        let table = section(topology, &format!("realms.{realm}"));
        if table.is_empty() {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                format!("missing [realms.{realm}]"),
            ));
            continue;
        }
        let bind = string(table, "local_bind_addr").unwrap_or_default();
        let issuer = string(table, "local_issuer").unwrap_or_default();
        let production_issuer = string(table, "production_issuer").unwrap_or_default();
        let cookie = string(table, "session_cookie_name").unwrap_or_default();
        let Some(port) = parse_loopback_bind(bind) else {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                format!("{realm} local_bind_addr must be loopback host:port"),
            ));
            continue;
        };
        if issuer != format!("http://127.0.0.1:{port}") && issuer != format!("http://localhost:{port}") {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                format!("{realm} local issuer must match its loopback bind port"),
            ));
        }
        if !production_issuer.starts_with("https://") {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                format!("{realm} production issuer must be HTTPS"),
            ));
        }
        if realm == "admin" && !production_issuer.contains("//admin-auth.") {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                "admin production issuer must use the admin-auth host",
            ));
        }
        if realm == "customer" && production_issuer.contains("//admin-auth.") {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                "customer production issuer must not use the admin-auth host",
            ));
        }
        if !cookie.starts_with("__Host-") || !cookie.contains(realm) || !cookies.insert(cookie.to_owned()) {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                format!("{realm} cookie must be distinct, realm-specific, and __Host- prefixed"),
            ));
        }
        if !ports.insert(port) {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                "customer/admin local ports must be distinct",
            ));
        }
        let mut envs = BTreeSet::new();
        for (key, value) in table {
            if key.ends_with("_env") {
                match value {
                    Atom::String(name) if is_env_name(name) => {
                        envs.insert(name.clone());
                    }
                    _ => findings.push(Finding::new(
                        "U07-dual-realm-topology",
                        format!("realms.{realm}.{key} must be an uppercase env identifier"),
                    )),
                }
            }
        }
        envs_by_realm.insert(realm, envs);
    }

    if let (Some(customer), Some(admin)) = (envs_by_realm.get("customer"), envs_by_realm.get("admin")) {
        if !customer.is_disjoint(admin) {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                "customer/admin wrapper env names must be disjoint",
            ));
        }
    }
}

fn parse_loopback_bind(value: &str) -> Option<u16> {
    let (host, port) = value.rsplit_once(':')?;
    if !matches!(host, "127.0.0.1" | "localhost") {
        return None;
    }
    port.parse::<u16>().ok().filter(|value| *value != 0)
}

fn is_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_uppercase())
        && chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn validate_providers(topology: &MiniToml, findings: &mut Vec<Finding>) {
    let supabase = section(topology, "providers.supabase");
    let neon = section(topology, "providers.neon_auth");
    for (name, table) in [("supabase", supabase), ("neon_auth", neon)] {
        if boolean(table, "enabled") != Some(true)
            || string(table, "authority") != Some("provider-native")
            || boolean(table, "credentials_in_contract") != Some(false)
        {
            findings.push(Finding::new(
                "U05-provider-native-boundary",
                format!("providers.{name} must be enabled, provider-native, and secret-free"),
            ));
        }
    }
    if boolean(supabase, "issuer_pinning_required") != Some(true)
        || boolean(supabase, "project_ref_pinning_required") != Some(true)
    {
        findings.push(Finding::new(
            "U05-provider-native-boundary",
            "Supabase issuer and project-ref pinning must remain required",
        ));
    }
    if string(neon, "endpoint_scope") != Some("branch")
        || boolean(neon, "branch_isolation_required") != Some(true)
    {
        findings.push(Finding::new(
            "U05-provider-native-boundary",
            "Neon Auth must remain branch-scoped with branch isolation",
        ));
    }
}

fn validate_applications(topology: &MiniToml, findings: &mut Vec<Finding>) {
    let entries = topology.arrays.get("applications").map(Vec::as_slice).unwrap_or_default();
    let mut keys = BTreeSet::new();
    let mut orgs = BTreeSet::new();
    let mut env_owners = BTreeMap::<String, String>::new();

    for (index, app) in entries.iter().enumerate() {
        let key = string(app, "key").unwrap_or_default();
        let org = string(app, "github_org").unwrap_or_default();
        if !is_slug(key) || !keys.insert(key.to_owned()) {
            findings.push(Finding::new(
                "U06-application-spoke-boundary",
                format!("applications[{index}] has an invalid or duplicate key"),
            ));
        }
        if !is_org(org) || !orgs.insert(org.to_ascii_lowercase()) {
            findings.push(Finding::new(
                "U06-application-spoke-boundary",
                format!("applications[{index}] has an invalid or duplicate GitHub org"),
            ));
        }
        if string(app, "realm") != Some("customer") || string(app, "supabase_role") != Some("spoke") {
            findings.push(Finding::new(
                "U06-application-spoke-boundary",
                format!("applications[{index}] must be a customer Supabase spoke"),
            ));
        }
        for (field, value) in app {
            if field.ends_with("_env") {
                let Some(name) = atom_string(value) else {
                    findings.push(Finding::new(
                        "U06-application-spoke-boundary",
                        format!("applications[{index}].{field} must be an env identifier"),
                    ));
                    continue;
                };
                if !is_env_name(name) {
                    findings.push(Finding::new(
                        "U06-application-spoke-boundary",
                        format!("applications[{index}].{field} must be an uppercase env identifier"),
                    ));
                }
                if is_sensitive_app_env(field) {
                    if let Some(previous) = env_owners.insert(name.to_owned(), key.to_owned()) {
                        if previous != key {
                            findings.push(Finding::new(
                                "U06-application-spoke-boundary",
                                format!("application env {name} is reused by {previous} and {key}"),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(host) = string(app, "supabase_auth_host") {
            if !host.starts_with("auth.")
                || host.chars().any(|ch| ch.is_ascii_uppercase())
                || host.contains('/')
                || host.contains(':')
                || host.contains('@')
            {
                findings.push(Finding::new(
                    "U06-application-spoke-boundary",
                    format!("applications[{index}].supabase_auth_host must be a lowercase auth.* hostname"),
                ));
            }
        }
    }

    for required in REQUIRED_APPS {
        if !keys.contains(required) {
            findings.push(Finding::new(
                "U06-application-spoke-boundary",
                format!("missing required initial application {required}"),
            ));
        }
    }
}

fn atom_string(value: &Atom) -> Option<&str> {
    match value {
        Atom::String(value) => Some(value),
        _ => None,
    }
}

fn is_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().next().is_some_and(|ch| ch.is_ascii_lowercase())
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn is_org(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
}

fn is_sensitive_app_env(field: &str) -> bool {
    matches!(
        field,
        "supabase_project_ref_env"
            | "supabase_auth_host_env"
            | "neon_project_id_env"
            | "neon_auth_base_url_env"
            | "audience_env"
    )
}

fn validate_procfile(topology: &MiniToml, text: &str, findings: &mut Vec<Finding>) {
    let mut processes = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, command)) = line.split_once(':') else {
            findings.push(Finding::new("U08-procfile-isolation", "Procfile contains a malformed process line"));
            continue;
        };
        processes.insert(name.trim().to_owned(), command.trim().to_owned());
    }
    if processes.keys().map(String::as_str).collect::<BTreeSet<_>>() != REALMS.into_iter().collect() {
        findings.push(Finding::new(
            "U08-procfile-isolation",
            "Procfile must define exactly customer and admin",
        ));
    }
    for realm in REALMS {
        let command = processes.get(realm).map(String::as_str).unwrap_or_default();
        let realm_table = section(topology, &format!("realms.{realm}"));
        let signing_env = format!("AUTH_{}_SIGNING_KEY_FILE", realm.to_ascii_uppercase());
        let other = if realm == "customer" {
            "AUTH_ADMIN_SIGNING_KEY_FILE"
        } else {
            "AUTH_CUSTOMER_SIGNING_KEY_FILE"
        };
        for token in [
            format!("--realm={realm}"),
            format!("--bind-addr={}", string(realm_table, "local_bind_addr").unwrap_or_default()),
            format!("--issuer={}", string(realm_table, "local_issuer").unwrap_or_default()),
            format!("--session-cookie-name={}", string(realm_table, "session_cookie_name").unwrap_or_default()),
            signing_env.clone(),
            "AUTH_SIGNING_KEY_FILE=".to_owned(),
            "AUTH_ALLOW_DBLESS=true".to_owned(),
        ] {
            if !command.contains(&token) {
                findings.push(Finding::new(
                    "U08-procfile-isolation",
                    format!("Procfile {realm} process is missing {token}"),
                ));
            }
        }
        if command.contains(other) {
            findings.push(Finding::new(
                "U08-procfile-isolation",
                format!("Procfile {realm} process references the other realm signing input"),
            ));
        }
    }
}

fn validate_overmind(text: &str, findings: &mut Vec<Finding>) {
    let mut values = BTreeMap::<String, String>::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    for key in [
        "OVERMIND_NO_PORT",
        "AUTH_CUSTOMER_SIGNING_KEY_FILE",
        "AUTH_ADMIN_SIGNING_KEY_FILE",
        "AUTH_CUSTOMER_SUPABASE_PROJECTS",
        "AUTH_ADMIN_SUPABASE_PROJECTS",
    ] {
        if !values.contains_key(key) {
            findings.push(Finding::new(
                "U09-overmind-secret-free",
                format!("{OVERMIND_ENV_PATH} is missing {key}"),
            ));
        }
    }
    if values.get("OVERMIND_NO_PORT").map(String::as_str) != Some("1") {
        findings.push(Finding::new(
            "U09-overmind-secret-free",
            "OVERMIND_NO_PORT must be 1",
        ));
    }
    for (key, value) in &values {
        let lower = key.to_ascii_lowercase();
        if ["signing_key", "secret", "token", "password"]
            .iter()
            .any(|part| lower.contains(part))
            && !value.is_empty()
        {
            findings.push(Finding::new(
                "U09-overmind-secret-free",
                format!("{OVERMIND_ENV_PATH} must not populate {key}"),
            ));
        }
    }
}

fn validate_runtime(topology: &MiniToml, runtime: &JsonValue, findings: &mut Vec<Finding>) {
    let object = runtime.as_object();
    if object.and_then(|value| value.get("applicationDatabaseFallbackAllowed")).and_then(JsonValue::as_bool)
        != Some(false)
    {
        findings.push(Finding::new(
            "N01-runtime-no-app-db-fallback",
            "runtime applicationDatabaseFallbackAllowed must be false",
        ));
    }
    if object.and_then(|value| value.get("loopbackAllowedInProduction")).and_then(JsonValue::as_bool)
        != Some(false)
    {
        findings.push(Finding::new(
            "N02-runtime-no-production-loopback",
            "runtime loopbackAllowedInProduction must be false",
        ));
    }
    if object.and_then(|value| value.get("productAuthorizationOwner")).and_then(JsonValue::as_str)
        != Some("application-databases")
    {
        findings.push(Finding::new(
            "N03-runtime-product-auth-owner",
            "runtime productAuthorizationOwner must remain application-databases",
        ));
    }
    let federation = object.and_then(|value| value.get("federation")).and_then(JsonValue::as_object);
    if federation
        .and_then(|value| value.get("emailNeverLinksProviders"))
        .and_then(JsonValue::as_bool)
        != Some(true)
    {
        findings.push(Finding::new(
            "N04-runtime-email-never-links",
            "runtime federation.emailNeverLinksProviders must be true",
        ));
    }
    if federation
        .and_then(|value| value.get("identityKey"))
        .and_then(JsonValue::as_str)
        != Some("provider-tenant-subject")
    {
        findings.push(Finding::new(
            "N05-runtime-immutable-provider-key",
            "runtime federation.identityKey must remain provider-tenant-subject",
        ));
    }

    let profiles = object
        .and_then(|value| value.get("profiles"))
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    let mut by_realm = BTreeMap::<String, JsonValue>::new();
    for profile in profiles {
        if let Some(realm) = profile.get("realm").and_then(JsonValue::as_str) {
            by_realm.insert(realm.to_owned(), profile);
        }
    }
    if by_realm.keys().map(String::as_str).collect::<BTreeSet<_>>() != REALMS.into_iter().collect() {
        findings.push(Finding::new(
            "N06-runtime-exact-realm-set",
            "runtime profiles must be exactly customer and admin",
        ));
    }

    let mut db_hosts = BTreeSet::new();
    let mut resource_refs = BTreeSet::new();
    let mut db_secret_refs = BTreeSet::new();
    let mut signing_refs = BTreeSet::new();
    let mut cookies = BTreeSet::new();
    let mut project_refs_by_realm = BTreeMap::<&str, BTreeSet<String>>::new();

    for realm in REALMS {
        let Some(profile) = by_realm.get(realm) else {
            continue;
        };
        let topology_realm = section(topology, &format!("realms.{realm}"));
        if profile.get("deployment").and_then(JsonValue::as_str) != string(topology_realm, "deployment")
            || profile.get("issuer").and_then(JsonValue::as_str) != string(topology_realm, "production_issuer")
        {
            findings.push(Finding::new(
                "U07-dual-realm-topology",
                format!("runtime {realm} deployment/issuer must match topology"),
            ));
        }
        let host = profile.get("databaseEndpointHost").and_then(JsonValue::as_str).unwrap_or_default();
        if host.is_empty() || !db_hosts.insert(host.to_owned()) {
            findings.push(Finding::new(
                "N07-runtime-db-host-isolation",
                "runtime database endpoint hosts must be non-empty and distinct",
            ));
        }
        let resource = profile.get("databaseResourceRef").and_then(JsonValue::as_str).unwrap_or_default();
        if resource.is_empty() || !resource_refs.insert(resource.to_owned()) {
            findings.push(Finding::new(
                "N08-runtime-db-resource-isolation",
                "runtime database resource refs must be non-empty and distinct",
            ));
        }
        let db_secret = profile.get("databaseSecretRef").and_then(JsonValue::as_str).unwrap_or_default();
        if db_secret.is_empty() || !db_secret_refs.insert(db_secret.to_owned()) {
            findings.push(Finding::new(
                "N09-runtime-db-secret-isolation",
                "runtime database secret refs must be non-empty and distinct",
            ));
        }
        let signing = profile.get("signingKeyRef").and_then(JsonValue::as_str).unwrap_or_default();
        if signing.is_empty() || !signing_refs.insert(signing.to_owned()) {
            findings.push(Finding::new(
                "N10-runtime-signing-key-isolation",
                "runtime signing key refs must be non-empty and distinct",
            ));
        }
        let cookie = profile.get("sessionCookieName").and_then(JsonValue::as_str).unwrap_or_default();
        if cookie != string(topology_realm, "session_cookie_name").unwrap_or_default()
            || !cookies.insert(cookie.to_owned())
        {
            findings.push(Finding::new(
                "N11-runtime-cookie-parity",
                format!("runtime {realm} cookie must match topology and remain distinct"),
            ));
        }

        let refs = profile
            .get("supabaseProjectRefs")
            .and_then(JsonValue::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let unique = refs.iter().cloned().collect::<BTreeSet<_>>();
        if unique.len() != refs.len() {
            findings.push(Finding::new(
                "N13-runtime-project-ref-uniqueness",
                format!("runtime {realm} Supabase project refs must be unique"),
            ));
        }
        let hub = profile.get("hubSupabaseProjectRef").and_then(JsonValue::as_str).unwrap_or_default();
        if hub.is_empty() || !unique.contains(hub) {
            findings.push(Finding::new(
                "N12-runtime-hub-project-membership",
                format!("runtime {realm} hubSupabaseProjectRef must be listed in supabaseProjectRefs"),
            ));
        }
        project_refs_by_realm.insert(realm, unique);

        let expected_prefix = format!("dd/shared-auth/{realm}/");
        if !db_secret.starts_with(&expected_prefix) || !signing.starts_with(&expected_prefix) {
            findings.push(Finding::new(
                "N15-runtime-realm-ref-namespacing",
                format!("runtime {realm} secret/signing refs must start with {expected_prefix}"),
            ));
        }
        if !resource.to_ascii_lowercase().contains(realm) {
            findings.push(Finding::new(
                "N15-runtime-realm-ref-namespacing",
                format!("runtime {realm} database resource ref must visibly name the realm"),
            ));
        }
    }

    if let (Some(customer), Some(admin)) = (
        project_refs_by_realm.get("customer"),
        project_refs_by_realm.get("admin"),
    ) {
        if !customer.is_disjoint(admin) {
            findings.push(Finding::new(
                "N14-runtime-cross-realm-project-isolation",
                "customer/admin Supabase project-ref allowlists must be disjoint",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOPOLOGY: &str = include_str!("../../config/shared-auth-topology.toml");
    const RUNTIME: &str = include_str!("../../config/auth-realms.contract.json");
    const PROCFILE: &str = include_str!("../../Procfile");
    const OVERMIND: &str = include_str!("../../.overmind.env.example");

    fn validate(topology: &str, runtime: &str, procfile: &str, overmind: &str) -> Vec<Finding> {
        validate_texts(
            Path::new("."),
            Path::new(TOPOLOGY_PATH),
            topology,
            runtime,
            procfile,
            overmind,
        )
        .expect("fixture must parse")
    }

    fn assert_code(findings: &[Finding], code: &str) {
        assert!(
            findings.iter().any(|finding| finding.code == code),
            "expected {code}, got {findings:#?}"
        );
    }

    #[test]
    fn current_repository_contract_is_valid() {
        let findings = validate(TOPOLOGY, RUNTIME, PROCFILE, OVERMIND);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn u01_rust_parser_rejects_unsupported_values() {
        let broken = TOPOLOGY.replace("schema_version = 1", "schema_version = { nope = true }");
        assert!(validate_texts(Path::new("."), Path::new(TOPOLOGY_PATH), &broken, RUNTIME, PROCFILE, OVERMIND).is_err());
    }

    #[test]
    fn u02_reserved_consumer_policy_filename_is_rejected() {
        let findings = validate_texts(
            Path::new("."),
            Path::new(".auth-shared.toml"),
            TOPOLOGY,
            RUNTIME,
            PROCFILE,
            OVERMIND,
        )
        .expect("fixture must parse");
        assert_code(&findings, "U02-reserved-policy-filename");
    }

    #[test]
    fn u03_missing_runtime_authority_ref_is_rejected() {
        let broken = TOPOLOGY.replace("runtime_schema = \"db/schema.sql\"", "runtime_schema = \"db/missing.sql\"");
        assert_code(&validate(&broken, RUNTIME, PROCFILE, OVERMIND), "U03-executable-authority-refs");
    }

    #[test]
    fn u04_provider_binding_drift_is_rejected() {
        let broken = TOPOLOGY.replace(
            "provider_binding_key = [\"provider\", \"issuer\", \"subject\", \"realm\"]",
            "provider_binding_key = [\"provider\", \"email\"]",
        );
        assert_code(&validate(&broken, RUNTIME, PROCFILE, OVERMIND), "U04-canonical-identity-boundary");
    }

    #[test]
    fn u05_provider_native_boundary_drift_is_rejected() {
        let broken = TOPOLOGY.replacen("authority = \"provider-native\"", "authority = \"shared-auth-owned\"", 1);
        assert_code(&validate(&broken, RUNTIME, PROCFILE, OVERMIND), "U05-provider-native-boundary");
    }

    #[test]
    fn u06_duplicate_application_key_is_rejected() {
        let broken = TOPOLOGY.replace("key = \"sonus-auris\"", "key = \"zed-pkg\"");
        assert_code(&validate(&broken, RUNTIME, PROCFILE, OVERMIND), "U06-application-spoke-boundary");
    }

    #[test]
    fn u07_shared_local_port_is_rejected() {
        let broken = TOPOLOGY
            .replace("127.0.0.1:8121", "127.0.0.1:8120")
            .replace("http://127.0.0.1:8121", "http://127.0.0.1:8120");
        assert_code(&validate(&broken, RUNTIME, PROCFILE, OVERMIND), "U07-dual-realm-topology");
    }

    #[test]
    fn u08_procfile_cross_realm_signing_input_is_rejected() {
        let broken = PROCFILE.replace(
            "${AUTH_ADMIN_SIGNING_KEY_FILE:?set AUTH_ADMIN_SIGNING_KEY_FILE}",
            "${AUTH_CUSTOMER_SIGNING_KEY_FILE:?set AUTH_CUSTOMER_SIGNING_KEY_FILE}",
        );
        assert_code(&validate(TOPOLOGY, RUNTIME, &broken, OVERMIND), "U08-procfile-isolation");
    }

    #[test]
    fn u09_secretful_overmind_example_is_rejected() {
        let broken = OVERMIND.replace("AUTH_CUSTOMER_SIGNING_KEY_FILE=", "AUTH_CUSTOMER_SIGNING_KEY_FILE=/tmp/customer.pem");
        assert_code(&validate(TOPOLOGY, RUNTIME, PROCFILE, &broken), "U09-overmind-secret-free");
    }

    #[test]
    fn u10_inline_secret_like_value_is_rejected() {
        let broken = TOPOLOGY.replace(
            "secrets_allowed = false",
            "secrets_allowed = false\npassword = \"postgresql://user:secret@example/db\"",
        );
        assert_code(&validate(&broken, RUNTIME, PROCFILE, OVERMIND), "U10-inline-secret-hygiene");
    }

    #[test]
    fn n01_application_database_fallback_is_rejected() {
        let broken = RUNTIME.replace("\"applicationDatabaseFallbackAllowed\": false", "\"applicationDatabaseFallbackAllowed\": true");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N01-runtime-no-app-db-fallback");
    }

    #[test]
    fn n02_production_loopback_is_rejected() {
        let broken = RUNTIME.replace("\"loopbackAllowedInProduction\": false", "\"loopbackAllowedInProduction\": true");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N02-runtime-no-production-loopback");
    }

    #[test]
    fn n03_product_authorization_owner_drift_is_rejected() {
        let broken = RUNTIME.replace("\"productAuthorizationOwner\": \"application-databases\"", "\"productAuthorizationOwner\": \"shared-auth\"");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N03-runtime-product-auth-owner");
    }

    #[test]
    fn n04_email_linking_is_rejected() {
        let broken = RUNTIME.replace("\"emailNeverLinksProviders\": true", "\"emailNeverLinksProviders\": false");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N04-runtime-email-never-links");
    }

    #[test]
    fn n05_runtime_identity_key_drift_is_rejected() {
        let broken = RUNTIME.replace("\"identityKey\": \"provider-tenant-subject\"", "\"identityKey\": \"email\"");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N05-runtime-immutable-provider-key");
    }

    #[test]
    fn n06_duplicate_runtime_realm_is_rejected() {
        let broken = RUNTIME.replace("\"realm\": \"admin\"", "\"realm\": \"customer\"");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N06-runtime-exact-realm-set");
    }

    #[test]
    fn n07_shared_database_host_is_rejected() {
        let broken = RUNTIME.replace(
            "shared-auth-admin-prod.cluster.example.rds.amazonaws.com",
            "shared-auth-customer-prod.cluster.example.rds.amazonaws.com",
        );
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N07-runtime-db-host-isolation");
    }

    #[test]
    fn n08_shared_database_resource_is_rejected() {
        let broken = RUNTIME.replace("aws:rds:shared-auth-admin-prod", "aws:rds:shared-auth-customer-prod");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N08-runtime-db-resource-isolation");
    }

    #[test]
    fn n09_shared_database_secret_ref_is_rejected() {
        let broken = RUNTIME.replace("dd/shared-auth/admin/database-url", "dd/shared-auth/customer/database-url");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N09-runtime-db-secret-isolation");
    }

    #[test]
    fn n10_shared_signing_key_ref_is_rejected() {
        let broken = RUNTIME.replace("dd/shared-auth/admin/signing-key", "dd/shared-auth/customer/signing-key");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N10-runtime-signing-key-isolation");
    }

    #[test]
    fn n11_runtime_cookie_drift_is_rejected() {
        let broken = RUNTIME.replace("__Host-shared-auth-admin", "__Host-shared-auth-customer");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N11-runtime-cookie-parity");
    }

    #[test]
    fn n12_hub_must_be_in_project_allowlist() {
        let broken = RUNTIME.replace("\"hubSupabaseProjectRef\": \"adminsupabaseproject01\"", "\"hubSupabaseProjectRef\": \"missinghubproject00001\"");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N12-runtime-hub-project-membership");
    }

    #[test]
    fn n13_duplicate_project_ref_is_rejected() {
        let broken = RUNTIME.replace("\"sonusaurisauthproj01\"", "\"customersupabaseproj01\"");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N13-runtime-project-ref-uniqueness");
    }

    #[test]
    fn n14_cross_realm_project_ref_overlap_is_rejected() {
        let broken = RUNTIME.replace("\"customersupabaseproj01\"", "\"adminsupabaseproject01\"");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N14-runtime-cross-realm-project-isolation");
    }

    #[test]
    fn n15_misnamespaced_realm_ref_is_rejected() {
        let broken = RUNTIME.replace("dd/shared-auth/admin/database-url", "dd/shared-auth/customer/admin-database-url");
        assert_code(&validate(TOPOLOGY, &broken, PROCFILE, OVERMIND), "N15-runtime-realm-ref-namespacing");
    }
}
