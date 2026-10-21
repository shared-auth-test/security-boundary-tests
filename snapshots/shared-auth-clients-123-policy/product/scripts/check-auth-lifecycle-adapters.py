#!/usr/bin/env python3
"""Fail-closed evidence checks for shared-auth reactive lifecycle adapters."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> int:
    errors: list[str] = []
    model = json.loads(read_text("formal/auth-lifecycle.json"))
    contract = json.loads(read_text("clients/auth-lifecycle-adapters.json"))

    fingerprint = hashlib.sha256(canonical(model)).hexdigest()
    if contract.get("schemaVersion") != 1:
        errors.append("adapter contract schemaVersion must be 1")
    if contract.get("lifecycleFingerprint") != fingerprint:
        errors.append("adapter contract lifecycle fingerprint does not match formal model")

    adapters = contract.get("adapters")
    if not isinstance(adapters, list):
        errors.append("adapters must be an array")
        adapters = []

    by_runtime: dict[str, dict[str, object]] = {}
    for adapter in adapters:
        if not isinstance(adapter, dict):
            errors.append("each adapter must be an object")
            continue
        runtime = adapter.get("runtime")
        if not isinstance(runtime, str) or not runtime:
            errors.append("adapter runtime must be a non-empty string")
            continue
        if runtime in by_runtime:
            errors.append(f"duplicate adapter runtime: {runtime}")
        by_runtime[runtime] = adapter
        for flag in (
            "replayCurrentState",
            "boundedReplay",
            "explicitRejectedTransitions",
            "serialDispatch",
        ):
            if adapter.get(flag) is not True:
                errors.append(f"{runtime}: {flag} must be true")

    required = {
        "typescript-core",
        "typescript-rxjs",
        "dart-core",
        "dart-rxdart",
    }
    missing = required - set(by_runtime)
    if missing:
        errors.append(f"missing required adapters: {sorted(missing)}")

    rx_channels = {
        "state",
        "transition",
        "allows-authenticated-api",
        "allows-privileged-api",
        "operation-in-flight",
    }
    for runtime, library in (
        ("typescript-rxjs", "rxjs"),
        ("dart-rxdart", "rxdart"),
    ):
        adapter = by_runtime.get(runtime, {})
        if adapter.get("library") != library:
            errors.append(f"{runtime}: expected library {library}")
        if "reactivex" not in set(adapter.get("delivery", [])):
            errors.append(f"{runtime}: reactivex delivery is required")
        if set(adapter.get("channels", [])) != rx_channels:
            errors.append(f"{runtime}: capability/state/transition channels are incomplete")
        if adapter.get("suppressDuplicateCapabilities") is not True:
            errors.append(f"{runtime}: capability streams must suppress duplicates")

    ts_package = json.loads(read_text("clients/ts/package.json"))
    if ts_package.get("dependencies", {}).get("rxjs") != "7.8.2":
        errors.append("clients/ts must pin RxJS 7.8.2")
    exports = ts_package.get("exports", {})
    for subpath in ("./lifecycle", "./reactive"):
        if subpath not in exports:
            errors.append(f"clients/ts package export missing {subpath}")

    ts_lock = json.loads(read_text("clients/ts/package-lock.json"))
    lock_packages = ts_lock.get("packages", {})
    root_lock = lock_packages.get("", {}) if isinstance(lock_packages, dict) else {}
    if root_lock.get("dependencies", {}).get("rxjs") != "7.8.2":
        errors.append("clients/ts package-lock root must pin RxJS 7.8.2")

    rxjs_lock = lock_packages.get("node_modules/rxjs", {}) if isinstance(lock_packages, dict) else {}
    expected_rxjs_lock = {
        "version": "7.8.2",
        "resolved": "https://registry.npmjs.org/rxjs/-/rxjs-7.8.2.tgz",
        "integrity": "sha512-dhKf903U/PQZY6boNNtAGdWbG85WAbjT/1xYoZIC7FAY0yWapOBQVsVrDl58W86//e1VpMNBtRV4MaXfdMySFA==",
        "license": "Apache-2.0",
    }
    for field, expected in expected_rxjs_lock.items():
        if rxjs_lock.get(field) != expected:
            errors.append(f"clients/ts package-lock RxJS {field} mismatch")
    if rxjs_lock.get("dependencies", {}).get("tslib") != "^2.1.0":
        errors.append("clients/ts package-lock RxJS must depend on tslib ^2.1.0")

    tslib_lock = lock_packages.get("node_modules/tslib", {}) if isinstance(lock_packages, dict) else {}
    expected_tslib_lock = {
        "version": "2.8.1",
        "resolved": "https://registry.npmjs.org/tslib/-/tslib-2.8.1.tgz",
        "integrity": "sha512-oJFu94HQb+KVduSUQL7wnpmqnfmLsOA/nAh6b6EH0wCEoK0/mPeXU6c3wKDV83MkOuHPRHtSXKKU99IBazS/2w==",
        "license": "0BSD",
    }
    for field, expected in expected_tslib_lock.items():
        if tslib_lock.get(field) != expected:
            errors.append(f"clients/ts package-lock tslib {field} mismatch")

    ts_rx = read_text("clients/ts/src/auth_lifecycle_rx.ts")
    for token in (
        'from "rxjs"',
        "distinctUntilChanged()",
        "shareReplay({ bufferSize: 1, refCount: true })",
        "allowsAuthenticatedApi$",
        "allowsPrivilegedApi$",
    ):
        if token not in ts_rx:
            errors.append(f"TypeScript RxJS adapter missing evidence token: {token}")

    ts_hooks = read_text("clients/ts/src/auth_lifecycle_hooks.ts")
    for token in (
        "Promise<AuthTransition>",
        "AsyncIterable<AuthTransition>",
        "onTransition(",
        "onState(",
        "emitCurrent: true",
    ):
        if token not in ts_hooks:
            errors.append(f"TypeScript non-Rx adapter missing evidence token: {token}")

    dart_pubspec = read_text("clients/dart/pubspec.yaml")
    if "rxdart: ^0.28.0" not in dart_pubspec:
        errors.append("clients/dart must depend on rxdart ^0.28.0")

    dart_rx = read_text("clients/dart/lib/src/auth_lifecycle_rx.dart")
    for token in (
        "package:rxdart/rxdart.dart",
        "implements ValueStream<T>",
        "stateChanges()",
        ".distinct()",
        "allowsAuthenticatedApi$",
        "allowsPrivilegedApi$",
        "StreamNotification<T>.data(_current())",
    ):
        if token not in dart_rx:
            errors.append(f"Dart RxDart adapter missing evidence token: {token}")
    if ".shareValueSeeded(" in dart_rx or ".shareValue(" in dart_rx:
        errors.append("Dart RxDart state must not rely on a ref-counted replay cache")

    dart_hooks = read_text("clients/dart/lib/src/auth_lifecycle_hooks.dart")
    for token in (
        "Stream<AuthTransition>",
        "Future<AuthTransition>",
        "Stream<AuthLifecycleState>.multi",
        "onTransition(",
        "onState(",
    ):
        if token not in dart_hooks:
            errors.append(f"Dart non-Rx adapter missing evidence token: {token}")

    for path in (
        "clients/auth-lifecycle-adapters.tsp",
        "clients/auth-lifecycle-adapters.schema.json",
    ):
        if not (ROOT / path).is_file():
            errors.append(f"missing independent contract authority: {path}")

    if errors:
        print("auth-lifecycle adapter contract: FAILED", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        "auth-lifecycle adapter contract: OK "
        f"({len(by_runtime)} runtime adapters, lifecycle {fingerprint})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
