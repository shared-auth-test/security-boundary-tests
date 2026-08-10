#!/usr/bin/env python3
"""Verify exact ORES repository templates, provenance, and security invariants."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

EXPECTED_LANGUAGES = {"rust", "typescript", "go", "python", "dart", "java", "swift"}
EXPECTED_METHODS = {
    "jwt",
    "oidc",
    "webauthn",
    "totp",
    "kerberos",
    "ssh",
    "openpgp",
    "platform_biometric",
    "recovery",
}
EXPECTED_CORE_DEPENDENCIES = {
    "ores-otel/ores-interfaces": "^0.1.0",
    "oresoftware/next-loggers": "^0.1.0",
}
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Linear token", re.compile(r"\blin_api_[A-Za-z0-9]{20,}\b")),
    ("Cloudflare token", re.compile(r"\bcfat_[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI-style token", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b")),
    (
        "private key material",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{32,}",
            re.DOTALL,
        ),
    ),
    ("age identity", re.compile(r"AGE-SECRET-KEY-1[A-Z0-9]{20,}")),
)


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON {path}: {error}") from error


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"invalid TOML {path}: {error}") from error


def verify_manifest(root: Path, expected_template: str) -> int:
    manifest_path = root / ".ores-template-manifest.json"
    document = load_json(manifest_path)
    require(document.get("schema") == "ores.otel.repository-template/v1", f"{root.name}: provenance schema drift")
    require(document.get("source") == "ores-otel/.github", f"{root.name}: provenance source drift")
    require(document.get("template") == expected_template, f"{root.name}: provenance template drift")
    files = document.get("files")
    require(isinstance(files, dict) and files, f"{root.name}: provenance file map missing")

    verified = 0
    for relative, expected_digest in sorted(files.items()):
        require(isinstance(relative, str) and relative, f"{root.name}: invalid provenance path")
        require(".." not in Path(relative).parts and not Path(relative).is_absolute(), f"{root.name}: unsafe provenance path {relative!r}")
        path = root / relative
        require(path.is_file() and not path.is_symlink(), f"{root.name}: provenance path missing or symlinked: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        require(actual == expected_digest, f"{root.name}: SHA-256 mismatch for {relative}: {actual} != {expected_digest}")
        verified += 1
    return verified


def verify_languages(root: Path) -> None:
    language_root = root / "languages"
    present = {path.name for path in language_root.iterdir() if path.is_dir()}
    require(EXPECTED_LANGUAGES <= present, f"{root.name}: missing languages {sorted(EXPECTED_LANGUAGES - present)}")
    for language in EXPECTED_LANGUAGES:
        require(any((language_root / language).rglob("*")), f"{root.name}: empty language target {language}")


def verify_interfaces(root: Path) -> None:
    package = load_toml(root / ".zpkg.toml")
    require(package.get("package", {}).get("org") == "ores-otel", "ores-interfaces: Zed org drift")
    require(package.get("package", {}).get("name") == "ores-interfaces", "ores-interfaces: Zed name drift")
    targets = package.get("targets", {})
    for language in EXPECTED_LANGUAGES:
        key = "golang" if language == "go" else language
        require(targets.get(key, {}).get("dir") == f"languages/{language}", f"ores-interfaces: target drift for {language}")

    schema = load_json(root / "contracts/ores-platform/v1/schema.json")
    definitions = schema.get("$defs", {})
    methods = set(definitions.get("AuthMethod", {}).get("enum", []))
    require(methods == EXPECTED_METHODS, f"ores-interfaces: auth-method drift: {sorted(methods)}")
    proof = definitions.get("PlatformBiometricProof", {})
    properties = proof.get("properties", {})
    required = set(proof.get("required", []))
    require(
        {"verifiedByPlatformAuthenticator", "userVerification", "rawBiometricMaterialPresent"} <= required,
        "ores-interfaces: platform biometric proof lacks required non-retention fields",
    )
    require(properties.get("verifiedByPlatformAuthenticator", {}).get("const") is True, "ores-interfaces: authenticator verdict must be true")
    require(properties.get("userVerification", {}).get("const") == "required", "ores-interfaces: user verification must be required")
    require(properties.get("rawBiometricMaterialPresent", {}).get("const") is False, "ores-interfaces: raw biometric material must be forbidden")


def verify_core(root: Path) -> None:
    package = load_toml(root / ".zpkg.toml")
    require(package.get("package", {}).get("org") == "ores-otel", "ores-lib-core: Zed org drift")
    require(package.get("package", {}).get("name") == "ores-lib-core", "ores-lib-core: Zed name drift")
    require(package.get("dependencies") == EXPECTED_CORE_DEPENDENCIES, "ores-lib-core: dependency graph drift")

    policy = load_json(root / "contracts/dependencies.json")
    dependencies = {entry.get("package"): entry for entry in policy.get("dependencies", [])}
    require(dependencies.get("oresoftware/next-loggers", {}).get("repository") == "ores-otel/ores.otel.log", "ores-lib-core: logger repository drift")
    require("ores-otel/ores-interfaces" in dependencies, "ores-lib-core: interfaces dependency missing")
    require(policy.get("globalProviderInstallationAllowed") is False, "ores-lib-core: global provider installation must be forbidden")
    require(policy.get("rawBiometricMaterialAllowed") is False, "ores-lib-core: raw biometric material must be forbidden")


def scan_tree(root: Path) -> int:
    scanned = 0
    forbidden_parts = {".git", "node_modules", "target", "__pycache__", ".dart_tool", ".build", "build", "dist"}
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or any(part in forbidden_parts for part in path.parts):
            continue
        require(path.stat().st_size <= 2_000_000, f"{root.name}: oversized source artifact {path.relative_to(root)}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError as error:
            raise VerificationError(f"{root.name}: non-UTF-8 source file {path.relative_to(root)}: {error}") from error
        for label, pattern in SECRET_PATTERNS:
            require(not pattern.search(text), f"{root.name}: possible {label} in {path.relative_to(root)}")
        scanned += 1
    return scanned


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interfaces", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    interfaces = args.interfaces.resolve()
    core = args.core.resolve()
    require(interfaces.is_dir(), f"interfaces checkout missing: {interfaces}")
    require(core.is_dir(), f"core checkout missing: {core}")

    verify_languages(interfaces)
    verify_languages(core)
    verify_interfaces(interfaces)
    verify_core(core)
    provenance_files = verify_manifest(interfaces, "repository-templates/ores-interfaces")
    provenance_files += verify_manifest(core, "repository-templates/ores-lib-core")
    scanned_files = scan_tree(interfaces) + scan_tree(core)

    print(
        "ORES foundations verified: "
        f"repositories=2 languages={len(EXPECTED_LANGUAGES)} auth_methods={len(EXPECTED_METHODS)} "
        f"provenance_files={provenance_files} scanned_files={scanned_files}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"ORES foundation verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
