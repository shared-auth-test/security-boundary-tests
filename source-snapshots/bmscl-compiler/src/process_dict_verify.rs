use anyhow::{bail, Context, Result};
use std::{fs, path::Path, process::Command};

const PROCESS_DICT_CHECK: &str = r#"
case init:get_plain_arguments() of
  [Path] ->
    try
      case beam_disasm:file(Path) of
        {beam_file, _Mod, _Exports, Attrs, _CompileInfo, Functions} ->
          Unsafe = fun(Name) -> lists:member(Name, [get, get_keys, put, erase]) end,
          Check = fun C(Term) when is_tuple(Term) ->
                    case Term of
                      {extfunc, erlang, F, A} ->
                        case Unsafe(F) of
                          true -> throw({deny, {process_dictionary, F, A}});
                          false -> ok
                        end;
                      {bif, Name, _, _, _} ->
                        case Unsafe(Name) of
                          true -> throw({deny, {process_dictionary_bif, Name}});
                          false -> ok
                        end;
                      {gc_bif, Name, _, _, _, _} ->
                        case Unsafe(Name) of
                          true -> throw({deny, {process_dictionary_gc_bif, Name}});
                          false -> ok
                        end;
                      _ ->
                        lists:foreach(fun(E) -> C(E) end, tuple_to_list(Term))
                    end;
                  C(Term) when is_list(Term) -> lists:foreach(fun(E) -> C(E) end, Term);
                  C(_) -> ok
                end,
          Check(Attrs),
          Check(Functions),
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
        io:format(standard_error, "process dictionary verifier failed ~p:~p ~p~n", [Class, Reason, Stack]),
        halt(5)
    end;
  _ ->
    halt(2)
end.
"#;

pub fn verify_no_process_dictionary_access(beam_dir: &Path) -> Result<()> {
    for entry in fs::read_dir(beam_dir)
        .with_context(|| format!("read BEAM directory {}", beam_dir.display()))?
    {
        let entry = entry.with_context(|| format!("enumerate {}", beam_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("beam") {
            continue;
        }
        verify_one(&path)?;
    }
    Ok(())
}

fn verify_one(path: &Path) -> Result<()> {
    let path_arg = path
        .to_str()
        .context("process-dictionary verifier requires UTF-8 artifact paths")?;
    let output = Command::new("erl")
        .args(["-noshell", "-eval", PROCESS_DICT_CHECK, "-extra", path_arg])
        .output()
        .with_context(|| format!("inspect process-dictionary access in {}", path.display()))?;
    if !output.status.success() {
        bail!(
            "tenant BEAM {} may access the invocation process dictionary: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn compile_fixture(module: &str, body: &str) -> Option<tempfile::TempDir> {
        if !Command::new("erlc")
            .arg("-version")
            .output()
            .ok()?
            .status
            .success()
        {
            return None;
        }
        let dir = tempdir().unwrap();
        let source =
            format!("-module({module}).\n-export([handle/2]).\nhandle(_Req, _Ctx) -> {body}.\n");
        let path = dir.path().join(format!("{module}.erl"));
        fs::write(&path, source).unwrap();
        let output = Command::new("erlc")
            .arg("-o")
            .arg(dir.path())
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(dir)
    }

    fn rejects(module: &str, body: &str) {
        let Some(dir) = compile_fixture(module, body) else {
            return;
        };
        assert!(verify_no_process_dictionary_access(dir.path()).is_err());
    }

    #[test]
    fn rejects_process_dictionary_enumeration_and_reads() {
        rejects("pd_get_all", "erlang:get()");
        rejects("pd_get_key", "erlang:get(secret)");
        rejects("pd_get_keys", "erlang:get_keys()");
        rejects("pd_get_keys_value", "erlang:get_keys(secret)");
    }

    #[test]
    fn rejects_process_dictionary_writes_and_erasure() {
        rejects("pd_put", "erlang:put(secret, value)");
        rejects("pd_erase_all", "erlang:erase()");
        rejects("pd_erase_key", "erlang:erase(secret)");
    }

    #[test]
    fn permits_unrelated_pure_code() {
        let Some(dir) = compile_fixture("pd_safe", "1 + 2") else {
            return;
        };
        verify_no_process_dictionary_access(dir.path()).unwrap();
    }
}
