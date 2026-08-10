import unittest

from deep_tests.credential_planes import (
    CredentialBoundaryViolation,
    CredentialContext,
    CredentialKind,
    OpaqueTokenStore,
    authorize_control_plane,
    create_sandbox_context,
    map_kerberos_principal,
    openpgp_attribution,
    platform_user_verification,
    reject_raw_biometric_material,
    validate_credential_context,
)


class CredentialPlaneBoundaryTests(unittest.TestCase):
    def test_openpgp_is_provenance_only_and_never_authority(self) -> None:
        result = openpgp_attribution(
            principal_id="principal-1",
            fingerprint="A" * 40,
            signed_at=200,
            valid_from=100,
            valid_until=300,
        )
        self.assertTrue(result.binding_valid_at_signing_time)
        self.assertFalse(result.grants_access)
        self.assertIsNone(result.token)
        self.assertEqual(result.scopes, ())
        self.assertEqual(result.roles, ())
        with self.assertRaises(CredentialBoundaryViolation):
            validate_credential_context(
                CredentialContext(
                    kind=CredentialKind.OPENPGP_PROVENANCE,
                    subject="principal-1",
                    audience="artifact-verifier",
                    scopes=frozenset({"repo:write"}),
                )
            )

    def test_kerberos_requires_exact_full_principal_and_ignores_pac_groups(self) -> None:
        mappings = {"alice@CORP.EXAMPLE": "principal-alice"}
        self.assertEqual(
            map_kerberos_principal(
                "alice@CORP.EXAMPLE",
                mappings,
                pac_groups=("Domain Admins", "billing-admin"),
            ),
            "principal-alice",
        )
        for principal in ("alice", "alice@corp.example", "bob@CORP.EXAMPLE"):
            with self.subTest(principal=principal), self.assertRaises(CredentialBoundaryViolation):
                map_kerberos_principal(principal, mappings)

    def test_ssh_and_kerberos_are_opaque_loa1_nondelegable_sandbox_credentials(self) -> None:
        for kind in (CredentialKind.SSH_KEY, CredentialKind.KERBEROS):
            with self.subTest(kind=kind):
                context = create_sandbox_context(
                    kind,
                    subject="principal-1",
                    audience="repo-data-plane",
                    scopes=frozenset({"repo:read", "repo:write"}),
                )
                self.assertEqual(context.aal, 1)
                self.assertIsNone(context.auth_time)
                self.assertFalse(context.roles)
                self.assertFalse(context.delegable)
                self.assertFalse(context.local_verification_supported)
                with self.assertRaises(CredentialBoundaryViolation):
                    authorize_control_plane(context, now=1_700_000_000)

        with self.assertRaises(CredentialBoundaryViolation):
            create_sandbox_context(
                CredentialKind.SSH_KEY,
                subject="principal-1",
                audience="auth-control-plane",
                scopes=frozenset({"auth:credentials:write"}),
            )

    def test_opaque_token_revocation_is_immediate_and_store_keeps_only_digest(self) -> None:
        store = OpaqueTokenStore(pepper=b"test-pepper")
        context = create_sandbox_context(
            CredentialKind.SSH_KEY,
            subject="principal-1",
            audience="repo-data-plane",
            scopes=frozenset({"repo:read"}),
        )
        token = store.issue(context)
        self.assertRegex(token, r"^sat_[A-Za-z0-9_-]{43}$")
        self.assertNotIn(token, store.records)
        self.assertEqual(store.introspect(token), context)
        store.revoke(token)
        with self.assertRaises(CredentialBoundaryViolation):
            store.introspect(token)

    def test_raw_biometrics_are_rejected_but_nonretaining_provider_verdicts_are_allowed(self) -> None:
        reject_raw_biometric_material(
            {
                "provider_reference": "opaque-ref-1",
                "face_match": {"verdict": "pass", "confidence_band": "high"},
                "expires_at": "2030-01-01T00:00:00Z",
            }
        )
        for field in (
            "face_image",
            "face_template",
            "fingerprint_template",
            "thumbprint_template",
            "voice_audio",
            "voiceprint",
            "government_id_image",
        ):
            with self.subTest(field=field), self.assertRaises(CredentialBoundaryViolation):
                reject_raw_biometric_material({field: "raw-or-derived-biometric"})

    def test_face_or_thumbprint_stays_private_to_platform_webauthn(self) -> None:
        result = platform_user_verification("webauthn", verified=True)
        self.assertEqual(result["aal"], 2)
        self.assertIsNone(result["modality"])
        self.assertNotIn("face", repr(result).lower())
        self.assertNotIn("thumb", repr(result).lower())
        with self.assertRaises(CredentialBoundaryViolation):
            platform_user_verification("face-recognition-api", verified=True)

    def test_fresh_interactive_loa2_is_required_for_control_plane(self) -> None:
        now = 1_700_000_000
        authorize_control_plane(
            CredentialContext(
                kind=CredentialKind.WEBAUTHN,
                subject="principal-1",
                audience="shared-auth",
                aal=2,
                auth_time=now - 60,
            ),
            now=now,
        )
        with self.assertRaises(CredentialBoundaryViolation):
            authorize_control_plane(
                CredentialContext(
                    kind=CredentialKind.INTERACTIVE_JWT,
                    subject="principal-1",
                    audience="shared-auth",
                    aal=2,
                    auth_time=now - 601,
                ),
                now=now,
            )


if __name__ == "__main__":
    unittest.main()
