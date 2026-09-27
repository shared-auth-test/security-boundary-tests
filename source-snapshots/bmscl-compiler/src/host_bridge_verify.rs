use anyhow::{bail, Context, Result};
use std::{fs, path::Path, process::Command};

const IMPORTS_CHECK: &str = r#"
case init:get_plain_arguments() of
  [Path] ->
    case beam_lib:chunks(Path, [imports]) of
      {ok, {_Mod, [{imports, Imports}]}} ->
        lists:foreach(
          fun({M, F, A}) ->
            io:format("~s:~s/~p~n", [atom_to_list(M), atom_to_list(F), A])
          end,
          Imports),
        halt(0);
      Error ->
        io:format(standard_error, "beam import inspection failed: ~p~n", [Error]),
        halt(2)
    end;
  _ ->
    io:format(standard_error, "expected exactly one BEAM path~n", []),
    halt(3)
end.
"#;

/// Fail closed on imports into BeamScale's trusted runtime namespace.
///
/// Source/FFI checks are defense in depth only: the deployable BEAM itself may
/// call exactly the tiny public host bridge surface and no supervisor/control
/// module. Runtime capability tokens remain profile-specific; merely importing
/// the v3 HTTP bridge cannot mint authority into a v2 invocation.
pub fn verify_trusted_host_bridges(beam_dir: &Path) -> Result<()> {
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
        .context("trusted-host verifier requires UTF-8 artifact paths")?;
    let output = Command::new("erl")
        .args(["-noshell", "-eval", IMPORTS_CHECK, "-extra", path_arg])
        .output()
        .with_context(|| format!("inspect trusted-host imports for {}", path.display()))?;
    if !output.status.success() {
        bail!(
            "trusted-host import inspection failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    for import in String::from_utf8(output.stdout)
        .context("BEAM import output was not UTF-8")?
        .lines()
    {
        if forbidden_trusted_import(import) {
            bail!(
                "tenant BEAM {} imports non-public BeamScale runtime function `{import}`",
                path.display()
            );
        }
    }
    Ok(())
}

fn forbidden_trusted_import(import: &str) -> bool {
    let Some((module, _rest)) = import.split_once(':') else {
        return true;
    };
    if !module.starts_with("bmscl_") {
        return false;
    }
    !matches!(
        import,
        "bmscl_host_cluster:get/3"
            | "bmscl_host_cluster:head/3"
            | "bmscl_host_cluster:request_many/2"
            | "bmscl_host_http:request/5"
            | "bmscl_host_log:write/3"
    )
}

#[cfg(test)]
mod tests {
    use super::forbidden_trusted_import;

    #[test]
    fn permits_only_public_host_bridge_mfas() {
        assert!(!forbidden_trusted_import("bmscl_host_cluster:get/3"));
        assert!(!forbidden_trusted_import("bmscl_host_cluster:head/3"));
        assert!(!forbidden_trusted_import(
            "bmscl_host_cluster:request_many/2"
        ));
        assert!(!forbidden_trusted_import("bmscl_host_http:request/5"));
        assert!(!forbidden_trusted_import("bmscl_host_log:write/3"));
        assert!(!forbidden_trusted_import("gleam@list:map/2"));

        assert!(forbidden_trusted_import("bmscl_router:invoke/3"));
        assert!(forbidden_trusted_import(
            "bmscl_deployment_manager:pin_deployment/1"
        ));
        assert!(forbidden_trusted_import("bmscl_hosted_abi:authorize/2"));
        assert!(forbidden_trusted_import("bmscl_host_cluster:request/5"));
        assert!(forbidden_trusted_import(
            "bmscl_host_http:request_unscoped/4"
        ));
        assert!(forbidden_trusted_import("malformed-import"));
    }
}
