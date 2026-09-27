use crate::{
    model::{AdmissionReport, Finding, Policy},
    policy::{check_worker_config, effective_limits, load_worker_config},
    safety_cache::VerifiedSafetyCache,
};
use anyhow::{Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tree_sitter::{Node, Parser};
use walkdir::WalkDir;

const FORBIDDEN_NATIVE_EXTENSIONS: &[&str] = &[
    "a", "beam", "c", "cc", "cpp", "cxx", "dll", "dylib", "erl", "ex", "exs", "h", "hpp", "hrl",
    "js", "mjs", "nif", "o", "so", "wasm",
];

pub fn check_project_with_cache(
    project: &Path,
    policy: &Policy,
    worker_config_path: Option<&Path>,
    deny_cpu_loops: bool,
    safety_cache: Option<&VerifiedSafetyCache>,
) -> Result<AdmissionReport> {
    let mut findings = Vec::new();
    let mut files = gleam_files(project);
    files.sort();

    if files.is_empty() {
        findings.push(Finding {
            severity: "error",
            code: "BMSCL_NO_GLEAM_SOURCE",
            file: project.display().to_string(),
            line: None,
            message: "no .gleam source files found".into(),
        });
    }

    for file in &files {
        let source = fs::read_to_string(file)?;
        let cached_safe = safety_cache
            .is_some_and(|cache| cache.approves_source(source.as_bytes(), deny_cpu_loops));
        if !cached_safe {
            check_source(file, &source, policy, deny_cpu_loops, &mut findings)?;
        }
    }

    // Cache hits never skip structural/native checks. A signed source verdict only
    // substitutes for the expensive Gleam AST/source-policy pass for those exact bytes.
    check_native_sources(project, &mut findings)?;
    check_dependencies(project, policy, safety_cache, &mut findings)?;
    let (worker_config, config_path) = load_worker_config(project, worker_config_path)?;
    check_worker_config(&worker_config, &config_path, policy, &mut findings);
    let source_sha256 = digest_inputs(project, &files, &config_path)?;
    let admitted = !findings.iter().any(|finding| finding.severity == "error");

    Ok(AdmissionReport {
        admitted,
        policy_version: policy.policy_version.clone(),
        source_sha256,
        findings,
        runtime_limits: effective_limits(policy, &worker_config),
        safety_cache_sha256: safety_cache.map(|cache| cache.cache_sha256().to_owned()),
        safety_analysis_policy_sha256: safety_cache
            .map(|cache| cache.analysis_policy_sha256().to_owned()),
        safety_cache_key_id: safety_cache.map(|cache| cache.key_id().to_owned()),
        durable: worker_config.durable.clone(),
    })
}

fn check_source(
    file: &Path,
    source: &str,
    policy: &Policy,
    deny_cpu_loops: bool,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_gleam::LANGUAGE.into())
        .context("load tree-sitter Gleam grammar")?;
    let tree = parser
        .parse(source, None)
        .context("tree-sitter failed to parse Gleam source")?;
    if tree.root_node().has_error() {
        findings.push(Finding {
            severity: "error",
            code: "BMSCL_GLEAM_PARSE_ERROR",
            file: file.display().to_string(),
            line: None,
            message: "source must parse cleanly before hosted-worker admission".into(),
        });
    }
    walk_source_ast(tree.root_node(), source, file, policy, findings);

    for (line_idx, line) in source.lines().enumerate() {
        let compact = line.replace(char::is_whitespace, "").to_lowercase();
        for pattern in [
            "process.spawn(",
            "process.spawn_unlinked(",
            "actor.start(",
            "actor.start_spec(",
        ] {
            if compact.contains(pattern) {
                findings.push(Finding {
                    severity: "error",
                    code: "BMSCL_PROCESS_CREATION_FORBIDDEN",
                    file: file.display().to_string(),
                    line: Some(line_idx + 1),
                    message: "Hosted Gleam workers cannot create BEAM processes; use ctx HTTP/cluster invocation for concurrent fan-out".into(),
                });
            }
        }
    }

    let recursive = recursive_functions(source)?;
    for (name, line) in recursive {
        findings.push(Finding {
            severity: if deny_cpu_loops { "error" } else { "warning" },
            code: "BMSCL_CPU_LOOP_CANDIDATE",
            file: file.display().to_string(),
            line: Some(line),
            message: format!(
                "function `{name}` participates in a recursive call cycle; recursion is allowed, but it must remain bounded by runtime reduction/wall-clock budgets"
            ),
        });
    }

    for token in [
        "sync_iterator",
        "blocking_iterator",
        "blocking_read",
        "blocking_write",
    ] {
        if source.contains(token) {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_SYNC_IO_FORBIDDEN",
                file: file.display().to_string(),
                line: None,
                message: format!(
                    "synchronous/blocking primitive `{token}` is forbidden; use ctx capabilities"
                ),
            });
        }
    }

    Ok(())
}

fn walk_source_ast(
    node: Node<'_>,
    source: &str,
    file: &Path,
    policy: &Policy,
    findings: &mut Vec<Finding>,
) {
    if node.kind() == "attribute" {
        let text = node_text(node, source);
        let compact: String = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .flat_map(char::to_lowercase)
            .collect();
        if compact.starts_with("@external(") {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_FORBIDDEN_EXTERNAL",
                file: file.display().to_string(),
                line: Some(node.start_position().row + 1),
                message: "customer-authored FFI/external functions are forbidden on hosted workers"
                    .into(),
            });
        }
    }

    if node.kind() == "import" {
        let text = node_text(node, source);
        let rest = text.trim_start().strip_prefix("import").unwrap_or("");
        let module = rest
            .trim_start()
            .split(|character: char| character.is_whitespace() || matches!(character, '.' | '{'))
            .next()
            .unwrap_or("")
            .trim();
        if policy
            .forbidden_import_prefixes
            .iter()
            .any(|prefix| module.starts_with(prefix))
        {
            let process_module =
                module.starts_with("gleam/erlang/process") || module.starts_with("gleam/otp");
            findings.push(Finding {
                severity: "error",
                code: if process_module {
                    "BMSCL_PROCESS_CREATION_FORBIDDEN"
                } else {
                    "BMSCL_FORBIDDEN_IMPORT"
                },
                file: file.display().to_string(),
                line: Some(node.start_position().row + 1),
                message: if process_module {
                    format!(
                        "import {module} exposes tenant-owned BEAM process creation; use ctx HTTP/cluster invocation instead"
                    )
                } else {
                    format!("import {module} bypasses the hosted capability/runtime API")
                },
            });
        }
    }

    for index in 0..node.child_count() {
        if let Some(child) = node.child(index) {
            walk_source_ast(child, source, file, policy, findings);
        }
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}

fn recursive_functions(source: &str) -> Result<Vec<(String, usize)>> {
    let fn_re = Regex::new(r"(?m)^(?:pub\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")?;
    let matches: Vec<_> = fn_re.find_iter(source).collect();
    let mut bodies = BTreeMap::new();
    let mut lines = BTreeMap::new();

    for (idx, found) in matches.iter().enumerate() {
        let caps = fn_re
            .captures(found.as_str())
            .expect("function regex capture");
        let name = caps.get(1).expect("function name").as_str().to_string();
        let body_end = matches
            .get(idx + 1)
            .map(|next| next.start())
            .unwrap_or(source.len());
        bodies.insert(name.clone(), &source[found.end()..body_end]);
        lines.insert(name, source[..found.start()].lines().count() + 1);
    }

    let names: BTreeSet<_> = bodies.keys().cloned().collect();
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, body) in &bodies {
        let mut edges = BTreeSet::new();
        for candidate in &names {
            let call_re = Regex::new(&format!(r"\b{}\s*\(", regex::escape(candidate)))?;
            if call_re.is_match(body) {
                edges.insert(candidate.clone());
            }
        }
        graph.insert(name.clone(), edges);
    }

    let mut recursive = Vec::new();
    for name in names {
        let mut seen = BTreeSet::new();
        if reaches(&graph, &name, &name, &mut seen) {
            recursive.push((name.clone(), *lines.get(&name).unwrap_or(&1)));
        }
    }
    Ok(recursive)
}

fn reaches(
    graph: &BTreeMap<String, BTreeSet<String>>,
    current: &str,
    target: &str,
    seen: &mut BTreeSet<String>,
) -> bool {
    let Some(next) = graph.get(current) else {
        return false;
    };
    for candidate in next {
        if candidate == target {
            return true;
        }
        if seen.insert(candidate.clone()) && reaches(graph, candidate, target, seen) {
            return true;
        }
    }
    false
}

fn check_native_sources(project: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    for entry in WalkDir::new(project).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() || path_is_in_build(entry.path()) {
            continue;
        }
        let extension = entry
            .path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase);
        if extension
            .as_deref()
            .is_some_and(|ext| FORBIDDEN_NATIVE_EXTENSIONS.contains(&ext))
        {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_NATIVE_SOURCE_FORBIDDEN",
                file: entry.path().display().to_string(),
                line: None,
                message: "hosted workers may contain Gleam source only; native Erlang/Elixir/JS/C/BEAM artifacts and FFI sidecars are forbidden".into(),
            });
        }
    }
    Ok(())
}

fn check_dependencies(
    project: &Path,
    policy: &Policy,
    safety_cache: Option<&VerifiedSafetyCache>,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let path = project.join("gleam.toml");
    if !path.exists() {
        return Ok(());
    }
    let raw = fs::read_to_string(&path)?;
    let doc: toml::Value = toml::from_str(&raw)?;
    let mut has_dependencies = false;
    let mut direct_dependencies = BTreeSet::new();

    for section in ["dependencies", "dev_dependencies", "dev-dependencies"] {
        if let Some(table) = doc.get(section).and_then(toml::Value::as_table) {
            for (dep, spec) in table {
                has_dependencies = true;
                direct_dependencies.insert(dep.clone());
                if !spec.is_str() {
                    findings.push(Finding {
                        severity: "error",
                        code: "BMSCL_NON_HEX_DEPENDENCY_FORBIDDEN",
                        file: path.display().to_string(),
                        line: None,
                        message: format!(
                            "dependency `{dep}` must resolve from Hex by version; path and git dependencies are forbidden"
                        ),
                    });
                }
            }
        }
    }

    let manifest_path = project.join("manifest.toml");
    if has_dependencies && !manifest_path.is_file() {
        findings.push(Finding {
            severity: "error",
            code: "BMSCL_UNLOCKED_DEPENDENCY_GRAPH",
            file: manifest_path.display().to_string(),
            line: None,
            message: "projects with dependencies must commit Gleam manifest.toml so the full dependency graph and Hex checksums are locked".into(),
        });
        return Ok(());
    }

    let cache_approved = if manifest_path.is_file() {
        check_dependency_manifest(&manifest_path, policy, safety_cache, findings)?
    } else {
        BTreeSet::new()
    };

    for dep in direct_dependencies {
        if !policy.allowed_dependencies.contains(&dep) && !cache_approved.contains(&dep) {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_UNAPPROVED_DEPENDENCY",
                file: path.display().to_string(),
                line: None,
                message: format!(
                    "dependency `{dep}` is neither in the hosted-worker allowlist nor covered by the verified safety cache"
                ),
            });
        }
    }
    Ok(())
}

fn check_dependency_manifest(
    manifest_path: &Path,
    policy: &Policy,
    safety_cache: Option<&VerifiedSafetyCache>,
    findings: &mut Vec<Finding>,
) -> Result<BTreeSet<String>> {
    let raw = fs::read_to_string(manifest_path)?;
    let doc: toml::Value = toml::from_str(&raw)?;
    let Some(packages) = doc.get("packages").and_then(toml::Value::as_array) else {
        return Ok(BTreeSet::new());
    };

    let mut cache_approved_names = BTreeSet::new();
    for package in packages {
        let Some(table) = package.as_table() else {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_INVALID_DEPENDENCY_LOCK",
                file: manifest_path.display().to_string(),
                line: None,
                message: "manifest.toml contains a malformed package entry".into(),
            });
            continue;
        };

        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if name.is_empty() {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_INVALID_DEPENDENCY_LOCK",
                file: manifest_path.display().to_string(),
                line: None,
                message: "resolved package entry is missing a package name".into(),
            });
            continue;
        }
        let version = table
            .get("version")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if version.is_empty() {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_INVALID_DEPENDENCY_LOCK",
                file: manifest_path.display().to_string(),
                line: None,
                message: format!("resolved package `{name}` is missing a locked version"),
            });
        }

        let source = table
            .get("source")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if source != "hex" {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_NON_HEX_DEPENDENCY_FORBIDDEN",
                file: manifest_path.display().to_string(),
                line: None,
                message: format!(
                    "resolved package `{name}` uses source `{source}`; hosted dependencies must come from Hex"
                ),
            });
        }

        let build_tools_are_gleam_only = table
            .get("build_tools")
            .and_then(toml::Value::as_array)
            .is_some_and(|tools| {
                !tools.is_empty()
                    && tools
                        .iter()
                        .all(|tool| tool.as_str().is_some_and(|tool| tool == "gleam"))
            });
        if !build_tools_are_gleam_only {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_NATIVE_DEPENDENCY_BUILD_FORBIDDEN",
                file: manifest_path.display().to_string(),
                line: None,
                message: format!(
                    "resolved package `{name}` must use only the Gleam build tool; Mix/rebar/native dependency builds are forbidden"
                ),
            });
        }

        let checksum = table
            .get("outer_checksum")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let checksum_valid =
            checksum.len() == 64 && checksum.bytes().all(|byte| byte.is_ascii_hexdigit());

        let cache_hit = checksum_valid
            && source == "hex"
            && !version.is_empty()
            && safety_cache.is_some_and(|cache| {
                cache.approves_dependency(name, version, source, checksum)
            });

        if cache_hit {
            cache_approved_names.insert(name.to_owned());
        }

        if !policy.allowed_dependencies.contains(name) && !cache_hit {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_UNAPPROVED_TRANSITIVE_DEPENDENCY",
                file: manifest_path.display().to_string(),
                line: None,
                message: format!(
                    "resolved package `{name}` is neither in the hosted-worker dependency closure allowlist nor covered by the verified safety cache"
                ),
            });
        }

        if !checksum_valid {
            findings.push(Finding {
                severity: "error",
                code: "BMSCL_DEPENDENCY_CHECKSUM_REQUIRED",
                file: manifest_path.display().to_string(),
                line: None,
                message: format!(
                    "resolved package `{name}` must carry a 64-hex Hex outer_checksum in manifest.toml"
                ),
            });
        } else {
            let checksum_upper = checksum.to_ascii_uppercase();
            let pinned = policy
                .allowed_dependency_checksums
                .get(name)
                .is_some_and(|checksums| checksums.contains(&checksum_upper));
            if !pinned && !cache_hit {
                findings.push(Finding {
                    severity: "error",
                    code: "BMSCL_DEPENDENCY_CHECKSUM_NOT_APPROVED",
                    file: manifest_path.display().to_string(),
                    line: None,
                    message: format!(
                        "resolved package `{name}` checksum `{checksum_upper}` is neither pinned by the hosted policy nor covered by the verified safety cache"
                    ),
                });
            }
        }
    }
    Ok(cache_approved_names)
}

fn gleam_files(project: &Path) -> Vec<PathBuf> {
    WalkDir::new(project)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| !path_is_in_build(path))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("gleam"))
        .collect()
}

fn path_is_in_build(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "build")
}

fn digest_inputs(project: &Path, gleam_files: &[PathBuf], config_path: &Path) -> Result<String> {
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for path in gleam_files {
        let relative = path.strip_prefix(project).unwrap_or(path);
        entries.insert(
            relative.to_string_lossy().replace('\\', "/"),
            fs::read(path)?,
        );
    }
    for name in ["gleam.toml", "manifest.toml"] {
        let path = project.join(name);
        if path.is_file() {
            entries.insert(name.to_string(), fs::read(path)?);
        }
    }
    if config_path.is_file() {
        entries.insert(".bmscl-worker-config".into(), fs::read(config_path)?);
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

#[cfg(test)]
mod tests {
    use super::{check_project_with_cache, check_source, recursive_functions};
    use crate::model::Policy;
    use std::{fs, path::Path};
    use tempfile::tempdir;

    #[test]
    fn detects_mutual_recursion() {
        let source = r#"
pub fn even(n) {
  odd(n)
}

fn odd(n) {
  even(n)
}
"#;
        let names: Vec<_> = recursive_functions(source)
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, vec!["even", "odd"]);
    }

    #[test]
    fn structurally_rejects_multiline_external_attribute() {
        let source = r#"
@external(
  erlang,
  "os",
  "cmd",
)
fn bad(command: String) -> String
"#;
        let mut findings = Vec::new();
        check_source(
            Path::new("worker.gleam"),
            source,
            &Policy::default(),
            false,
            &mut findings,
        )
        .unwrap();
        assert!(findings
            .iter()
            .any(|finding| finding.code == "BMSCL_FORBIDDEN_EXTERNAL"));
    }

    #[test]
    fn rejects_native_sidecars_and_path_dependencies() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(
            dir.path().join("src/worker.gleam"),
            "pub fn handle(req, ctx) { #(req, ctx) }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("gleam.toml"),
            "name = \"worker\"\nversion = \"0.1.0\"\n[dependencies]\ngleam_stdlib = { path = \"../stdlib\" }\n",
        )
        .unwrap();
        fs::write(dir.path().join("src/escape.erl"), "-module(escape).\n").unwrap();

        let report =
            check_project_with_cache(dir.path(), &Policy::default(), None, false, None).unwrap();
        assert!(!report.admitted);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "BMSCL_NATIVE_SOURCE_FORBIDDEN"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "BMSCL_NON_HEX_DEPENDENCY_FORBIDDEN"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "BMSCL_UNLOCKED_DEPENDENCY_GRAPH"));
    }
}
