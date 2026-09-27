use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_BEAM_MODULES: usize = 128;
const MAX_BEAM_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BEAM_TREE_BYTES: u64 = 64 * 1024 * 1024;
const DISASM_TIMEOUT: Duration = Duration::from_secs(5);

// Fixed Erlang program: customer-controlled paths are supplied only after -extra,
// never interpolated into executable Erlang source. beam_disasm reads/disassembles
// the module but does not load tenant code into the verifier VM.
const DISASM_CHECK: &str = r#"
case init:get_plain_arguments() of
  [Path] ->
    try
      case beam_disasm:file(Path) of
        {beam_file, Mod, _Exports, Attrs, _CompileInfo, Functions} ->
          UnsafeModule = fun(M) ->
            lists:member(M, [
              os, file, filelib, prim_file, erl_prim_loader, erl_tar, zip,
              code, compile, epp, erl_eval, erl_scan, erl_parse, erl_ddll,
              net_kernel, rpc, erpc, global, persistent_term, ets, dets,
              mnesia, disk_log, application, init, sys, proc_lib, gen,
              gen_server, gen_statem, gen_event, gen_fsm, supervisor, timer,
              gen_tcp, gen_udp, socket, ssl, httpc, inets, inet, inet_db,
              inet_res, io, logger, error_logger, prim_inet, prim_socket,
              erts_internal, erts_debug, beam_lib, beam_disasm, peer, slave,
              pg, pg2, shell
            ])
          end,
          UnsafeBif = fun(Name) ->
            S = atom_to_list(Name),
            lists:member(Name, [
              apply, make_fun, halt, open_port, port_command, port_connect,
              port_close, port_info, ports, load_nif, load_module,
              delete_module, purge_module, check_process_code,
              whereis, register, unregister, processes, process_info,
              process_flag, suspend_process, resume_process, link, unlink,
              monitor, demonitor, exit, send, send_after, start_timer,
              cancel_timer, group_leader, binary_to_atom, list_to_atom,
              binary_to_existing_atom, list_to_existing_atom, binary_to_term,
              term_to_binary, system_flag, system_info, statistics, trace,
              trace_pattern, node, nodes, disconnect_node, setnode, get_cookie,
              set_cookie, process_display, garbage_collect, memory,
              module_loaded, function_exported, fun_info, system_time,
              monotonic_time, time_offset, timestamp
            ]) orelse lists:prefix("spawn", S) orelse lists:prefix("port_", S)
          end,
          UnsafeErlang = fun(F, _A) -> UnsafeBif(F) end,
          Check = fun C(Term) when is_tuple(Term) ->
                    case Term of
                      {on_load, _} -> throw({deny, on_load_attribute});
                      {extfunc, M, F, A} ->
                        case UnsafeModule(M) orelse (M =:= erlang andalso UnsafeErlang(F, A)) of
                          true -> throw({deny, {external_call, M, F, A}});
                          false -> ok
                        end;
                      {bif, Name, _, _, _} ->
                        case UnsafeBif(Name) of
                          true -> throw({deny, {bif, Name}});
                          false -> ok
                        end;
                      {gc_bif, Name, _, _, _, _} ->
                        case UnsafeBif(Name) of
                          true -> throw({deny, {gc_bif, Name}});
                          false -> ok
                        end;
                      _ ->
                        Op = element(1, Term),
                        case lists:member(Op, [apply, apply_last, send, call_nif]) of
                          true -> throw({deny, {opcode, Op}});
                          false -> lists:foreach(fun(E) -> C(E) end, tuple_to_list(Term))
                        end
                    end;
                  C(send) -> throw({deny, {opcode, send}});
                  C(Term) when is_list(Term) -> lists:foreach(fun(E) -> C(E) end, Term);
                  C(Term) when is_pid(Term) -> throw({deny, literal_pid});
                  C(Term) when is_port(Term) -> throw({deny, literal_port});
                  C(Term) when is_reference(Term) -> throw({deny, literal_reference});
                  C(Term) when is_function(Term) -> throw({deny, literal_fun});
                  C(_) -> ok
                end,
          Check(Attrs),
          Check(Functions),
          io:format("MODULE=~s~nOK~n", [atom_to_list(Mod)]),
          halt(0);
        Other ->
          io:format(standard_error, "unsupported beam_disasm result: ~p~n", [Other]),
          halt(3)
      end
    catch
      throw:{deny, Reason} ->
        io:format(standard_error, "DENY ~p~n", [Reason]),
        halt(4);
      Class:Reason:Stack ->
        io:format(standard_error, "beam verifier failed ~p:~p ~p~n", [Class, Reason, Stack]),
        halt(5)
    end;
  _ ->
    io:format(standard_error, "expected exactly one BEAM path~n", []),
    halt(2)
end.
"#;

pub fn verify_final_beam(beam_dir: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(beam_dir)
        .with_context(|| format!("read BEAM directory metadata {}", beam_dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("BEAM artifact path must be a real directory, not a symlink");
    }

    let mut beams = Vec::new();
    let mut total_bytes = 0_u64;
    for entry in fs::read_dir(beam_dir)
        .with_context(|| format!("read BEAM directory {}", beam_dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("enumerate BEAM directory {}", beam_dir.display()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("read artifact metadata {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "BEAM directory may contain regular .beam files only: {}",
                path.display()
            );
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("beam") {
            bail!(
                "unexpected non-BEAM file in final BEAM tree: {}",
                path.display()
            );
        }
        if metadata.len() == 0 || metadata.len() > MAX_BEAM_FILE_BYTES {
            bail!(
                "BEAM module {} is {} bytes; allowed range is 1..={MAX_BEAM_FILE_BYTES}",
                path.display(),
                metadata.len()
            );
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .context("BEAM tree size overflow")?;
        if total_bytes > MAX_BEAM_TREE_BYTES {
            bail!("BEAM tree exceeds {MAX_BEAM_TREE_BYTES} bytes");
        }
        beams.push(path);
        if beams.len() > MAX_BEAM_MODULES {
            bail!("artifact contains more than {MAX_BEAM_MODULES} BEAM modules");
        }
    }
    if beams.is_empty() {
        bail!("artifact contains no BEAM modules");
    }
    beams.sort();

    let mut modules = BTreeSet::new();
    for path in beams {
        let module = disassemble_and_check(&path)?;
        let expected = path
            .file_stem()
            .and_then(|name| name.to_str())
            .context("BEAM filename must be valid UTF-8")?;
        if module != expected {
            bail!(
                "BEAM module identity `{module}` does not match artifact filename `{expected}.beam`"
            );
        }
        if !modules.insert(module) {
            bail!("duplicate BEAM module identity in artifact");
        }
    }
    Ok(())
}

fn disassemble_and_check(path: &Path) -> Result<String> {
    let path_arg = path
        .to_str()
        .context("BEAM verifier requires UTF-8 artifact paths")?;
    let mut child = Command::new("erl")
        .args(["-noshell", "-eval", DISASM_CHECK, "-extra", path_arg])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("launch OTP BEAM disassembler for {}", path.display()))?;

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("poll BEAM disassembler for {}", path.display()))?
        {
            break status;
        }
        if started.elapsed() >= DISASM_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "BEAM disassembly exceeded {} seconds for {}",
                DISASM_TIMEOUT.as_secs(),
                path.display()
            );
        }
        thread::sleep(Duration::from_millis(10));
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut output) = child.stdout.take() {
        output
            .read_to_string(&mut stdout)
            .context("read BEAM verifier stdout")?;
    }
    if let Some(mut output) = child.stderr.take() {
        output
            .read_to_string(&mut stderr)
            .context("read BEAM verifier stderr")?;
    }
    if !status.success() {
        bail!(
            "final BEAM admission rejected {}: {}",
            path.display(),
            stderr.trim()
        );
    }
    if !stdout.lines().any(|line| line == "OK") {
        bail!(
            "BEAM disassembler did not emit an explicit OK for {}",
            path.display()
        );
    }
    let module = stdout
        .lines()
        .find_map(|line| line.strip_prefix("MODULE="))
        .context("BEAM disassembler did not report module identity")?;
    validate_module_name(module)?;
    Ok(module.to_string())
}

fn validate_module_name(module: &str) -> Result<()> {
    if module.is_empty()
        || module.len() > 230
        || !module
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'@'))
        || !module.as_bytes()[0].is_ascii_lowercase()
    {
        bail!("invalid tenant BEAM module identity `{module}`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    fn otp_available() -> bool {
        Command::new("erlc")
            .arg("-version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn compile_fixture(module: &str, source: &str) -> Option<tempfile::TempDir> {
        if !otp_available() {
            return None;
        }
        let dir = tempdir().unwrap();
        let source_path = dir.path().join(format!("{module}.erl"));
        fs::write(&source_path, source).unwrap();
        let output = Command::new("erlc")
            .arg("-o")
            .arg(dir.path())
            .arg(&source_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "erlc failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(dir)
    }

    fn assert_rejected(module: &str, source: &str) {
        let Some(dir) = compile_fixture(module, source) else {
            return;
        };
        assert!(
            verify_final_beam(dir.path()).is_err(),
            "fixture {module} unexpectedly passed final BEAM admission"
        );
    }

    #[test]
    fn accepts_local_closure_calls() {
        let Some(dir) = compile_fixture(
            "safe_closure",
            "-module(safe_closure).\n-export([handle/2]).\nhandle(X, _Ctx) -> F = fun(Y) -> Y + 1 end, F(X).\n",
        ) else {
            return;
        };
        verify_final_beam(dir.path()).unwrap();
    }

    #[test]
    fn rejects_dynamic_apply_opcode() {
        assert_rejected(
            "dynamic_apply",
            "-module(dynamic_apply).\n-export([handle/2]).\nhandle(M, _Ctx) -> apply(M, length, [[]]).\n",
        );
    }

    #[test]
    fn rejects_send_opcode() {
        assert_rejected(
            "raw_send",
            "-module(raw_send).\n-export([handle/2]).\nhandle(Pid, _Ctx) -> Pid ! hello, ok.\n",
        );
    }

    #[test]
    fn rejects_process_spawn() {
        assert_rejected(
            "raw_spawn",
            "-module(raw_spawn).\n-export([handle/2]).\nhandle(_, _) -> spawn(fun() -> ok end), ok.\n",
        );
    }

    #[test]
    fn rejects_filesystem_read_and_write() {
        assert_rejected(
            "file_read",
            "-module(file_read).\n-export([handle/2]).\nhandle(_, _) -> file:read_file(\"/etc/passwd\").\n",
        );
        assert_rejected(
            "file_write",
            "-module(file_write).\n-export([handle/2]).\nhandle(_, _) -> file:write_file(\"/tmp/x\", <<\"x\">>).\n",
        );
    }

    #[test]
    fn rejects_file_helper_and_archive_modules() {
        assert_rejected(
            "filelib_read",
            "-module(filelib_read).\n-export([handle/2]).\nhandle(_, _) -> filelib:is_file(\"/etc/passwd\").\n",
        );
        assert_rejected(
            "zip_read",
            "-module(zip_read).\n-export([handle/2]).\nhandle(_, _) -> zip:table(\"/tmp/a.zip\").\n",
        );
    }

    #[test]
    fn rejects_runtime_eval_pipeline() {
        assert_rejected(
            "runtime_eval",
            "-module(runtime_eval).\n-export([handle/2]).\nhandle(_, _) -> {ok,T,_}=erl_scan:string(\"1+1.\"), {ok,E}=erl_parse:parse_exprs(T), erl_eval:exprs(E, []).\n",
        );
    }

    #[test]
    fn rejects_runtime_compilation() {
        assert_rejected(
            "runtime_compile",
            "-module(runtime_compile).\n-export([handle/2]).\nhandle(_, _) -> compile:forms([]).\n",
        );
    }

    #[test]
    fn rejects_on_load_modules() {
        assert_rejected(
            "with_on_load",
            "-module(with_on_load).\n-on_load(init/0).\n-export([handle/2]).\ninit() -> ok.\nhandle(_, _) -> ok.\n",
        );
    }

    #[test]
    fn rejects_malformed_beam() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("worker.beam"), b"not a BEAM file").unwrap();
        assert!(verify_final_beam(dir.path()).is_err());
    }

    #[test]
    fn rejects_symlinks_and_unexpected_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("worker.txt"), b"x").unwrap();
        assert!(verify_final_beam(dir.path()).is_err());
    }

    #[test]
    fn module_name_validation_is_strict() {
        assert!(validate_module_name("worker").is_ok());
        assert!(validate_module_name("pkg@worker_1").is_ok());
        assert!(validate_module_name("Worker").is_err());
        assert!(validate_module_name("../worker").is_err());
    }
}
