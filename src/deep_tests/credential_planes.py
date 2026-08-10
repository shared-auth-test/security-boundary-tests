from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


class CredentialBoundaryViolation(ValueError):
    """Raised when credential evidence is asked to carry unsafe authority."""


class CredentialKind(StrEnum):
    INTERACTIVE_JWT = "interactive_jwt"
    WEBAUTHN = "webauthn"
    SSH_KEY = "ssh_key"
    KERBEROS = "kerberos"
    OPENPGP_PROVENANCE = "openpgp_provenance"
    EXTERNAL_BIOMETRIC_RECOVERY = "external_biometric_recovery"


@dataclass(frozen=True)
class CredentialContext:
    kind: CredentialKind
    subject: str
    audience: str
    scopes: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    aal: int = 1
    auth_time: int | None = None
    opaque: bool = False
    delegable: bool = False
    local_verification_supported: bool = True


CONTROL_PLANE_SCOPE_PREFIXES = (
    "auth:credentials:",
    "auth:factors:",
    "auth:recovery:",
    "auth:roles:",
    "auth:realms:",
    "auth:delegate",
)


def _contains_control_plane_scope(scopes: frozenset[str]) -> bool:
    return any(scope.startswith(CONTROL_PLANE_SCOPE_PREFIXES) for scope in scopes)


def validate_credential_context(context: CredentialContext) -> None:
    if context.kind in {CredentialKind.SSH_KEY, CredentialKind.KERBEROS}:
        if context.aal != 1 or context.auth_time is not None:
            raise CredentialBoundaryViolation("sandbox credentials are fixed at LOA1 without auth_time")
        if context.roles:
            raise CredentialBoundaryViolation("sandbox credentials never inherit roles")
        if context.delegable:
            raise CredentialBoundaryViolation("sandbox credentials are non-delegable")
        if not context.opaque or context.local_verification_supported:
            raise CredentialBoundaryViolation("sandbox credentials require opaque online introspection")
        if _contains_control_plane_scope(context.scopes):
            raise CredentialBoundaryViolation("sandbox credentials cannot carry control-plane scopes")
    elif context.kind is CredentialKind.OPENPGP_PROVENANCE:
        if context.scopes or context.roles or context.delegable:
            raise CredentialBoundaryViolation("OpenPGP provenance never grants authority")
    elif context.kind is CredentialKind.EXTERNAL_BIOMETRIC_RECOVERY:
        if context.scopes or context.roles or context.delegable:
            raise CredentialBoundaryViolation("biometric recovery evidence is not an access credential")


def authorize_control_plane(context: CredentialContext, now: int, max_age_seconds: int = 600) -> None:
    validate_credential_context(context)
    if context.kind not in {CredentialKind.INTERACTIVE_JWT, CredentialKind.WEBAUTHN}:
        raise CredentialBoundaryViolation("control-plane access requires an interactive credential")
    if context.aal != 2 or context.auth_time is None:
        raise CredentialBoundaryViolation("fresh LOA2 is required")
    if context.auth_time > now + 30 or now - context.auth_time > max_age_seconds:
        raise CredentialBoundaryViolation("authentication ceremony is not fresh")


def create_sandbox_context(
    kind: CredentialKind,
    subject: str,
    audience: str,
    scopes: frozenset[str],
) -> CredentialContext:
    if kind not in {CredentialKind.SSH_KEY, CredentialKind.KERBEROS}:
        raise CredentialBoundaryViolation("only SSH and Kerberos issue sandbox credentials")
    context = CredentialContext(
        kind=kind,
        subject=subject,
        audience=audience,
        scopes=scopes,
        aal=1,
        auth_time=None,
        opaque=True,
        delegable=False,
        local_verification_supported=False,
    )
    validate_credential_context(context)
    return context


@dataclass(frozen=True)
class ProvenanceResult:
    principal_id: str
    fingerprint: str
    signed_at: int
    binding_valid_at_signing_time: bool
    grants_access: bool = False
    token: None = None
    scopes: tuple[()] = ()
    roles: tuple[()] = ()


def openpgp_attribution(
    principal_id: str,
    fingerprint: str,
    signed_at: int,
    valid_from: int,
    valid_until: int | None,
) -> ProvenanceResult:
    if not re.fullmatch(r"[0-9A-F]{40,64}", fingerprint):
        raise CredentialBoundaryViolation("full uppercase OpenPGP fingerprint is required")
    valid = signed_at >= valid_from and (valid_until is None or signed_at < valid_until)
    return ProvenanceResult(
        principal_id=principal_id,
        fingerprint=fingerprint,
        signed_at=signed_at,
        binding_valid_at_signing_time=valid,
    )


def map_kerberos_principal(
    full_principal: str,
    exact_mappings: Mapping[str, str],
    pac_groups: tuple[str, ...] = (),
) -> str:
    del pac_groups  # PAC/group membership is intentionally never an authority source.
    if "@" not in full_principal:
        raise CredentialBoundaryViolation("a full Kerberos principal including realm is required")
    name, realm = full_principal.rsplit("@", 1)
    if not name or not re.fullmatch(r"[A-Z0-9][A-Z0-9.-]{0,127}", realm):
        raise CredentialBoundaryViolation("Kerberos realm must be an exact canonical realm")
    try:
        return exact_mappings[full_principal]
    except KeyError as exc:
        raise CredentialBoundaryViolation(
            "unmapped Kerberos principals are rejected; JIT is forbidden"
        ) from exc


RAW_BIOMETRIC_KEYS = {
    "face_image",
    "face_frame",
    "face_template",
    "face_embedding",
    "fingerprint_image",
    "fingerprint_template",
    "thumbprint_template",
    "voice_audio",
    "voiceprint",
    "speaker_embedding",
    "government_id_image",
}


def reject_raw_biometric_material(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in RAW_BIOMETRIC_KEYS:
                raise CredentialBoundaryViolation(f"raw biometric field is forbidden: {normalized}")
            reject_raw_biometric_material(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            reject_raw_biometric_material(nested)


def platform_user_verification(method: str, verified: bool) -> dict[str, object]:
    if method != "webauthn" or not verified:
        raise CredentialBoundaryViolation(
            "face/thumbprint authentication must remain platform WebAuthn user verification"
        )
    # Deliberately omits modality: the server must not learn whether the device used face, thumbprint, or PIN.
    return {"amr": ["webauthn", "user_verification"], "aal": 2, "modality": None}


@dataclass
class OpaqueTokenStore:
    pepper: bytes
    records: dict[str, CredentialContext] = field(default_factory=dict)

    def _digest(self, token: str) -> str:
        return hmac.new(self.pepper, token.encode(), hashlib.sha256).hexdigest()

    def issue(self, context: CredentialContext) -> str:
        validate_credential_context(context)
        if not context.opaque:
            raise CredentialBoundaryViolation("only opaque credentials belong in this store")
        token = "sat_" + secrets.token_urlsafe(32)
        self.records[self._digest(token)] = context
        return token

    def introspect(self, token: str) -> CredentialContext:
        if not token.startswith("sat_"):
            raise CredentialBoundaryViolation("opaque sandbox token is required")
        try:
            return self.records[self._digest(token)]
        except KeyError as exc:
            raise CredentialBoundaryViolation("token is inactive or revoked") from exc

    def revoke(self, token: str) -> None:
        self.records.pop(self._digest(token), None)
