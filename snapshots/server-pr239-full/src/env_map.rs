//! Immutable application environment snapshot.
//!
//! `std::env` and process argv are copied at the process boundary. CLI
//! overrides from flags-2-env are merged into an ordinary map. This module
//! never writes the process environment.

use std::collections::BTreeMap;

pub type EnvMap = BTreeMap<String, String>;

/// Deterministic merge: later override entries win over the initial map.
pub fn get_env_map(
    initial: EnvMap,
    overrides: impl IntoIterator<Item = (String, String)>,
) -> EnvMap {
    overrides
        .into_iter()
        .fold(initial, |mut env, (key, value)| {
            env.insert(key, value);
            env
        })
}

/// Return a trimmed non-empty value from an environment snapshot.
pub fn env_value<'a>(env: &'a EnvMap, key: &str) -> Option<&'a str> {
    env.get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Parse CLI argv through flags-2-env without writing the process environment.
pub fn cli_overrides(argv: &[String]) -> Result<EnvMap, String> {
    let parser = unsafe { flags2env::Flags2Env::load(None) }
        .map_err(|error| format!("flags-2-env unavailable ({error})"))?;
    parser
        .parse(argv, None)
        .map(|overrides| overrides.into_iter().collect())
        .map_err(|error| format!("invalid CLI flags ({error})"))
}

/// Copy the process environment. This is an impure boundary helper.
pub fn process_env_map() -> EnvMap {
    std::env::vars().collect()
}

/// Copy process arguments. This is an impure boundary helper.
pub fn process_argv() -> Vec<String> {
    std::env::args().collect()
}

/// Merge argv overrides into a copied environment without process mutation.
///
/// Flags-2-env load or parse failures keep `initial`, matching the previous
/// fallback that left process env unchanged on error.
pub fn env_map_from_argv(initial: EnvMap, argv: &[String]) -> EnvMap {
    match cli_overrides(argv) {
        Ok(overrides) => get_env_map(initial, overrides),
        Err(error) => {
            tracing::debug!("{error}; using environment only");
            initial
        }
    }
}

/// Build the application environment: process env + CLI overrides.
pub fn current_env_map() -> EnvMap {
    env_map_from_argv(process_env_map(), &process_argv())
}

/// Historical flags entrypoint: snapshot process env and merge CLI overrides.
pub fn apply_cli_flags() -> EnvMap {
    current_env_map()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_values_override_environment_values() {
        let initial = EnvMap::from([
            ("AUTH_BIND_ADDR".into(), "0.0.0.0:8120".into()),
            ("AUTH_REALM".into(), "customer".into()),
        ]);
        let overrides = EnvMap::from([("AUTH_BIND_ADDR".into(), "127.0.0.1:18120".into())]);
        let env = get_env_map(initial, overrides);

        assert_eq!(
            env.get("AUTH_BIND_ADDR").map(String::as_str),
            Some("127.0.0.1:18120")
        );
        assert_eq!(env.get("AUTH_REALM").map(String::as_str), Some("customer"));
    }

    #[test]
    fn merge_does_not_mutate_process_environment() {
        let before = std::env::var_os("AUTH_BIND_ADDR");
        let env = get_env_map(
            EnvMap::from([("AUTH_BIND_ADDR".into(), "0.0.0.0:8120".into())]),
            [("AUTH_BIND_ADDR".into(), "127.0.0.1:18120".into())],
        );
        assert_eq!(
            env.get("AUTH_BIND_ADDR").map(String::as_str),
            Some("127.0.0.1:18120")
        );
        assert_eq!(std::env::var_os("AUTH_BIND_ADDR"), before);
    }

    #[test]
    fn source_does_not_write_process_environment() {
        const SRC: &str = include_str!("env_map.rs");
        let production = SRC.split("#[cfg(test)]").next().unwrap_or(SRC);
        assert!(!production.contains("set_var"));
    }
}
