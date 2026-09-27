#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
build_dir="$(mktemp -d)"
erlc -Werror -o "$build_dir" src/*.erl test/*.erl
erl -noshell -pa "$build_dir" -eval 'case eunit:test([shared_auth_gate_tests, shared_auth_introspection_tests], [verbose]) of ok -> halt(0); _ -> halt(1) end.'
