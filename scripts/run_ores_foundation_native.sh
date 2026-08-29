#!/usr/bin/env bash
set -euo pipefail

: "${ORES_INTERFACES_SHA:?missing ORES_INTERFACES_SHA}"
: "${ORES_LIB_CORE_SHA:?missing ORES_LIB_CORE_SHA}"
: "${ORES_LOGGER_SHA:?missing ORES_LOGGER_SHA}"

interfaces="${1:-fixtures/ores-interfaces}"
core="${2:-fixtures/ores-lib-core}"
logger="${3:-fixtures/ores.otel.log}"

test "$(git -C "$interfaces" rev-parse HEAD)" = "$ORES_INTERFACES_SHA"
test "$(git -C "$core" rev-parse HEAD)" = "$ORES_LIB_CORE_SHA"
test "$(git -C "$logger" rev-parse HEAD)" = "$ORES_LOGGER_SHA"

python3 scripts/verify_ores_foundations.py --interfaces "$interfaces" --core "$core"
python3 "$interfaces/scripts/check_contracts.py"
python3 "$core/scripts/check_core.py"

run_interfaces() {
  local root="$interfaces/languages"
  (cd "$root/rust" && cargo test)
  (cd "$root/go" && go test ./...)
  (cd "$root/typescript" && npm test)
  (cd "$root/python" && PYTHONPATH=src python3 -m unittest discover -s tests -v)
  (cd "$root/dart" && dart pub get && dart analyze && dart run tool/check.dart)
  mkdir -p "$RUNNER_TEMP/interfaces-java"
  javac -d "$RUNNER_TEMP/interfaces-java" \
    "$root/java/src/main/java/com/oresoftware/interfaces/AuthContracts.java" \
    "$root/java/src/test/java/com/oresoftware/interfaces/AuthContractsTest.java"
  java -ea -cp "$RUNNER_TEMP/interfaces-java" com.oresoftware.interfaces.AuthContractsTest
  (cd "$root/swift" && swift test)
}

run_core() {
  local root="$core/languages"
  (cd "$root/rust" && cargo test)
  (cd "$root/go" && go test ./...)
  (cd "$root/typescript" && npm test)
  (cd "$root/python" && PYTHONPATH=src python3 -m unittest discover -s tests -v)
  (cd "$root/dart" && dart pub get && dart analyze && dart run tool/check.dart)
  mkdir -p "$RUNNER_TEMP/core-java"
  javac -d "$RUNNER_TEMP/core-java" \
    "$root/java/src/main/java/com/oresoftware/core/OresCore.java" \
    "$root/java/src/test/java/com/oresoftware/core/OresCoreTest.java"
  java -ea -cp "$RUNNER_TEMP/core-java" com.oresoftware.core.OresCoreTest
  (cd "$root/swift" && swift test)
}

run_interfaces
run_core

(
  cd "$logger"
  cargo metadata --locked --format-version 1 --no-deps \
    --manifest-path sdk/rust/Cargo.toml > "$RUNNER_TEMP/ores-logger-metadata.json"
  cargo fmt --manifest-path sdk/rust/Cargo.toml -- --check
  cargo test --locked --manifest-path sdk/rust/Cargo.toml --all-targets
  cargo clippy --locked --manifest-path sdk/rust/Cargo.toml --all-targets -- -D warnings

  # rust-context is intentionally a separate crate with a path dependency on
  # the native SDK. Exercise it directly so thread/task-local hardening cannot
  # disappear when the repository root is packaged as a polyglot target.
  cargo fmt --manifest-path sdk/rust-context/Cargo.toml -- --check
  cargo test --manifest-path sdk/rust-context/Cargo.toml --features tokio --all-targets
  cargo clippy --manifest-path sdk/rust-context/Cargo.toml --features tokio --all-targets -- -D warnings
)

mkdir -p "$RUNNER_TEMP/logger-consumer/src"
cat > "$RUNNER_TEMP/logger-consumer/Cargo.toml" <<EOF
[package]
name = "shared-auth-test-logger-consumer"
version = "0.0.0"
edition = "2021"

[dependencies]
next_loggers = { package = "oresoftware-next-loggers", git = "https://github.com/ores-otel/ores.otel.log.git", rev = "$ORES_LOGGER_SHA" }
EOF
cat > "$RUNNER_TEMP/logger-consumer/src/lib.rs" <<'EOF'
#[cfg(test)]
mod tests {
    use next_loggers::{Logger, Options, Value};

    #[test]
    fn exact_revision_emits_without_global_provider_install() {
        let logger = Logger::new(Options {
            app_name: "shared-auth-test".into(),
            console: false,
            ..Options::default()
        });
        let record = logger
            .info(vec![Value::String("certified".into())])
            .send_with_store(false)
            .expect("logger should emit")
            .expect("INFO should pass the default level");
        assert_eq!(record.app_name, "shared-auth-test");
        assert_eq!(record.message, "certified");
    }
}
EOF
cargo test --manifest-path "$RUNNER_TEMP/logger-consumer/Cargo.toml"
