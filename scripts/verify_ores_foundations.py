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
EXPECTED_SHARED_AUTH_ENTITIES = {
    "organization",
    "project",
    "user_account",
    "membership",
    "role",
    "role_binding",
    "session",
    "factor",
    "audit_event",
    "revocation_operation",
    "revocation_organization_result",
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


def verify_shared_auth_contract(root: Path) -> None:
    schema = load_json(root / "contracts/shared-auth/v1/schema.json")
    require(
        schema.get("$id") == "https://schemas.oresoftware.com/shared-auth/v1/schema.json",
        "ores-interfaces: Shared Auth v1 schema identity drift",
    )
    definitions = schema.get("$defs", {})
    required_definitions = {
        "Organization",
        "Project",
        "User",
        "Membership",
        "Role",
        "RoleBinding",
        "Session",
        "Factor",
        "AuditEvent",
        "OrganizationRevocationResult",
        "RevokeSessionsByEmailRequest",
        "RevokeSessionsByEmailResult",
    }
    require(
        required_definitions <= set(definitions),
        f"ores-interfaces: Shared Auth definitions missing {sorted(required_definitions - set(definitions))}",
    )
    for name in required_definitions:
        require(
            definitions[name].get("additionalProperties") is False,
            f"ores-interfaces: {name} must reject unknown fields",
        )

    session_properties = definitions["Session"].get("properties", {})
    require("sessionIdHash" in session_properties, "ores-interfaces: session digest projection missing")
    for forbidden in ("sessionId", "accessToken", "refreshToken", "cookie"):
        require(forbidden not in session_properties, f"ores-interfaces: unsafe Session field {forbidden}")

    factor_properties = definitions["Factor"].get("properties", {})
    require(
        factor_properties.get("privateKeyMaterialPresent", {}).get("const") is False,
        "ores-interfaces: Factor must forbid private-key material",
    )
    require(
        factor_properties.get("rawBiometricMaterialPresent", {}).get("const") is False,
        "ores-interfaces: Factor must forbid raw biometric material",
    )
    for forbidden in ("privateKey", "totpSeed", "biometricTemplate", "faceImage", "fingerprintImage"):
        require(forbidden not in factor_properties, f"ores-interfaces: unsafe Factor field {forbidden}")

    request = definitions["RevokeSessionsByEmailRequest"]
    request_properties = request.get("properties", {})
    normalized_email = request_properties.get("normalizedEmail", {})
    require(normalized_email.get("writeOnly") is True, "ores-interfaces: revocation email must be write-only")
    require(
        {"requestId", "idempotencyKey", "normalizedEmail", "scope", "reason", "dryRun"}
        <= set(request.get("required", [])),
        "ores-interfaces: revocation request security inputs must be required",
    )

    result_properties = definitions["RevokeSessionsByEmailResult"].get("properties", {})
    require("normalizedEmail" not in result_properties and "email" not in result_properties, "ores-interfaces: revocation result echoes email")
    require(
        result_properties.get("authorizationPolicy", {}).get("const")
        == "per_organization_sessions.revoke",
        "ores-interfaces: revocation authorization must be per organization",
    )
    require(
        result_properties.get("onlyAuthorizedOrganizationsProcessed", {}).get("const") is True,
        "ores-interfaces: unauthorized organizations may not be processed",
    )
    organization_result = definitions["OrganizationRevocationResult"].get("properties", {})
    require(
        organization_result.get("authorizationVerified", {}).get("const") is True,
        "ores-interfaces: organization revocation result must prove authorization",
    )

    request_example = load_json(root / "contracts/shared-auth/v1/examples/revoke-sessions-request.json")
    result_example = load_json(root / "contracts/shared-auth/v1/examples/revoke-sessions-result.json")
    require(
        request_example.get("normalizedEmail") == request_example.get("normalizedEmail", "").lower(),
        "ores-interfaces: revocation example email is not normalized",
    )
    require("normalizedEmail" not in result_example and "email" not in result_example, "ores-interfaces: revocation result example echoes email")
    organization_results = result_example.get("organizationResults")
    require(
        isinstance(organization_results, list) and organization_results,
        "ores-interfaces: revocation result example must include authorized evidence",
    )
    require(
        all(item.get("authorizationVerified") is True for item in organization_results),
        "ores-interfaces: revocation example contains an unauthorized organization result",
    )


def verify_shared_auth_persistence(root: Path) -> None:
    model = load_json(root / "contracts/shared-auth-data-model.json")
    require(
        model.get("wireContract") == "ores-otel/ores-interfaces/contracts/shared-auth/v1/schema.json",
        "ores-lib-core: Shared Auth wire-contract coordinate drift",
    )
    entities = set(model.get("entities", []))
    require(
        entities == EXPECTED_SHARED_AUTH_ENTITIES,
        f"ores-lib-core: Shared Auth entity drift: {sorted(entities)}",
    )

    email_lookup = model.get("emailLookup", {})
    require(email_lookup.get("persistence") == "hmac_sha256_only", "ores-lib-core: email lookup must use keyed HMAC")
    require(email_lookup.get("pepperAuthority") == "kms", "ores-lib-core: email HMAC pepper must be KMS-owned")
    require(email_lookup.get("rawOrNormalizedEmailPersisted") is False, "ores-lib-core: email persistence must be forbidden")
    require(email_lookup.get("rawOrNormalizedEmailLogged") is False, "ores-lib-core: email logging must be forbidden")

    credential_storage = model.get("credentialStorage", {})
    for field in (
        "privateKeysAllowed",
        "rawBiometricMaterialAllowed",
        "biometricTemplatesAllowed",
        "bearerTokensAllowed",
        "refreshTokensAllowed",
    ):
        require(credential_storage.get(field) is False, f"ores-lib-core: unsafe credential policy {field}")

    revocation = model.get("revocation", {})
    require(revocation.get("authorizationPermission") == "sessions.revoke", "ores-lib-core: revocation permission drift")
    require(revocation.get("authorizationGranularity") == "per_organization", "ores-lib-core: revocation authorization granularity drift")
    require(revocation.get("inaccessibleOrganizationIdentitiesDisclosed") is False, "ores-lib-core: inaccessible organization identities may not be disclosed")
    require(revocation.get("idempotencyScope") == ["actor_subject", "idempotency_key"], "ores-lib-core: idempotency scope drift")
    require(revocation.get("sameKeyDifferentRequest") == "conflict", "ores-lib-core: mismatched idempotency replay must conflict")
    require(revocation.get("transactionBoundary") == "one_authorized_organization", "ores-lib-core: revocation transaction boundary drift")

    database_access = model.get("databaseAccess", {})
    require(database_access.get("browserAccessAllowed") is False, "ores-lib-core: browser database access must be forbidden")
    require(database_access.get("rowLevelSecurityForced") is True, "ores-lib-core: database must force RLS")
    require(database_access.get("policiesInstalled") is False, "ores-lib-core: browser-facing RLS policies must not be installed")

    runtime = load_json(root / "contracts/shared-auth-dashboard-runtime.json")
    authorization = runtime.get("authorization", {})
    for field in ("requiresOnlineIntrospection", "exactAudienceRequired", "exactOrganizationMembershipRequired"):
        require(authorization.get(field) is True, f"ores-lib-core: runtime authorization policy {field} must be true")
    for field in ("crossOrganizationFallbackAllowed", "productRoleClaimsAuthoritative", "directAuthDatabaseAccessAllowed"):
        require(authorization.get(field) is False, f"ores-lib-core: runtime authorization policy {field} must be false")
    pagination = runtime.get("pagination", {})
    require(0 < pagination.get("defaultLimit", 0) <= pagination.get("maximumLimit", 0) <= 200, "ores-lib-core: pagination limits are unsafe")
    require(pagination.get("cursorOpaque") is True and pagination.get("offsetPaginationAllowed") is False, "ores-lib-core: pagination must use opaque cursors")
    logging = runtime.get("logging", {})
    for field in (
        "globalProviderInstallationAllowed",
        "highCardinalityIdentityLabelsAllowed",
        "bearerTokensAllowed",
        "cookiesAllowed",
        "privateKeysAllowed",
        "totpSeedsAllowed",
        "rawBiometricMaterialAllowed",
    ):
        require(logging.get(field) is False, f"ores-lib-core: unsafe dashboard logging policy {field}")
    capabilities = runtime.get("authenticationCapabilities", {})
    require(
        capabilities.get("candidateOrContractAdvertisedAsEnabledAllowed") is False,
        "ores-lib-core: contract-only authentication must not be advertised as enabled",
    )
    require(capabilities.get("sshRequiresOnlineIntrospection") is True, "ores-lib-core: SSH must require online introspection")
    require(capabilities.get("kerberosRequiresOnlineIntrospection") is True, "ores-lib-core: Kerberos must require online introspection")
    require(capabilities.get("openpgpAuthority") == "provenance_only", "ores-lib-core: OpenPGP must remain provenance-only")
    require(capabilities.get("rawBiometricRetentionAllowed") is False, "ores-lib-core: biometric retention must be forbidden")

    sql_path = root / model.get("postgresMigration", "")
    require(sql_path.is_file() and not sql_path.is_symlink(), "ores-lib-core: canonical Shared Auth migration missing")
    sql = sql_path.read_text(encoding="utf-8")
    sql_lower = sql.lower()
    require("normalized_email " not in sql_lower, "ores-lib-core: normalized email column must not exist")
    for statement in (
        "email_lookup_hmac bytea",
        "session_id_hmac bytea",
        "request_digest bytea",
        "UNIQUE (actor_subject, idempotency_key)",
        "authorization_verified boolean NOT NULL CHECK (authorization_verified)",
        "authorization_policy = 'per_organization_sessions.revoke'",
        "CHECK (NOT dry_run OR sessions_revoked = 0)",
        "CREATE TRIGGER audit_event_append_only",
        "REVOKE ALL ON ALL TABLES IN SCHEMA ores_shared_auth FROM PUBLIC;",
    ):
        require(statement in sql, f"ores-lib-core: persistence invariant missing: {statement}")
    require(
        re.search(r"(?im)^\s*CREATE\s+POLICY\b", sql) is None,
        "ores-lib-core: canonical migration must not install browser RLS policies",
    )
    for table in sorted(EXPECTED_SHARED_AUTH_ENTITIES):
        require(f"ALTER TABLE ores_shared_auth.{table} ENABLE ROW LEVEL SECURITY;" in sql, f"ores-lib-core: {table} does not enable RLS")
        require(f"ALTER TABLE ores_shared_auth.{table} FORCE ROW LEVEL SECURITY;" in sql, f"ores-lib-core: {table} does not force RLS")


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
    verify_shared_auth_contract(interfaces)
    verify_shared_auth_persistence(core)
    provenance_files = verify_manifest(interfaces, "repository-templates/ores-interfaces")
    provenance_files += verify_manifest(core, "repository-templates/ores-lib-core")
    scanned_files = scan_tree(interfaces) + scan_tree(core)

    print(
        "ORES foundations verified: "
        f"repositories=2 languages={len(EXPECTED_LANGUAGES)} auth_methods={len(EXPECTED_METHODS)} "
        f"provenance_files={provenance_files} scanned_files={scanned_files} "
        "shared_auth_contract=v1 shared_auth_persistence=v1"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"ORES foundation verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
