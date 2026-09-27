use std::{fs, process::Command};

fn run_check(source: &str) -> std::process::Output {
    run_check_with_config(source, None)
}

fn run_check_with_config(source: &str, config: Option<&str>) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/worker.gleam"), source).unwrap();
    if let Some(config) = config {
        fs::write(dir.path().join(".ores-lambda.toml"), config).unwrap();
    }

    Command::new(env!("CARGO_BIN_EXE_bmscl-compiler"))
        .arg("check")
        .arg(dir.path())
        .output()
        .expect("run bmscl-compiler")
}

#[test]
fn admits_pure_gleam() {
    let output = run_check("pub fn handle(x) { x }\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"admitted\": true"));
    assert!(stdout.contains("\"max_processes\": 1"));
}

#[test]
fn rejects_erlang_external() {
    let output = run_check(
        "@external(erlang, \"os\", \"cmd\")\nfn cmd(x: String) -> String\npub fn handle(x) { cmd(x) }\n",
    );
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_FORBIDDEN_EXTERNAL"));
}

#[test]
fn rejects_process_module_import() {
    let output =
        run_check("import gleam/erlang/process\npub fn handle(x) { process.spawn(fn() { x }) }\n");
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_PROCESS_CREATION_FORBIDDEN"));
}

#[test]
fn rejects_otp_actor_import() {
    let output = run_check("import gleam/otp/actor\npub fn handle(x) { x }\n");
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_PROCESS_CREATION_FORBIDDEN"));
}

#[test]
fn rejects_attempt_to_enable_process_creation() {
    let output = run_check_with_config(
        "pub fn handle(x) { x }\n",
        Some("[security]\nprocess_creation = \"allow\"\n"),
    );
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_AMBIENT_AUTHORITY_FORBIDDEN"));
}

#[test]
fn rejects_attempt_to_enable_dynamic_eval() {
    let output = run_check_with_config(
        "pub fn handle(x) { x }\n",
        Some("[security]\ndynamic_eval = \"allow\"\n"),
    );
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_AMBIENT_AUTHORITY_FORBIDDEN"));
}

#[test]
fn rejects_attempt_to_enable_compile_time_code_execution() {
    let output = run_check_with_config(
        "pub fn handle(x) { x }\n",
        Some("[security]\ncompile_time_code_execution = \"allow\"\n"),
    );
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_AMBIENT_AUTHORITY_FORBIDDEN"));
}

#[test]
fn rejects_more_than_one_tenant_process() {
    let output = run_check_with_config(
        "pub fn handle(x) { x }\n",
        Some("[limits]\nmax_processes = 2\n"),
    );
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_RUNTIME_LIMIT_OUT_OF_POLICY"));
}

#[test]
fn flags_direct_recursion() {
    let output = run_check("pub fn spin() { spin() }\n");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_CPU_LOOP_CANDIDATE"));
}

#[test]
fn rejects_attempt_to_enable_filesystem() {
    let output = run_check_with_config(
        "pub fn handle(x) { x }\n",
        Some("[security]\nfilesystem = \"allow\"\n"),
    );
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BMSCL_AMBIENT_AUTHORITY_FORBIDDEN"));
}

#[test]
fn rejects_all_configurable_permissions_in_read_only_profile() {
    for key in ["http", "kv", "databases", "queues", "env", "secrets"] {
        let config = format!("[permissions]\n{key} = [\"scope\"]\n");
        let output = run_check_with_config("pub fn handle(x) { x }\n", Some(&config));
        assert!(
            !output.status.success(),
            "permission {key} unexpectedly admitted"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("BMSCL_UNKNOWN_PERMISSION"),
            "unexpected rejection for {key}: {stdout}"
        );
    }
}
