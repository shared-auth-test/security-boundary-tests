import tomllib
import unittest
from pathlib import Path

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, redact, validate_outbound_url


class CounterpartTipSecurityHardeningTests(unittest.TestCase):
    def test_mixed_case_and_double_encoded_parent_segments_fail_closed(self) -> None:
        for value in ("%2E%2E/secret", "%2e%2E/secret", "%252E%252E/secret", "safe/%2E%2E/secret"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_scheme_relative_and_authority_confusion_urls_are_rejected(self) -> None:
        allowed = {"api.example.test"}
        for value in ("//api.example.test/v1", "https://api.example.test@attacker.invalid/v1", "https://attacker.invalid/api.example.test"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)

    def test_redaction_is_idempotent_for_mixed_secret_shapes(self) -> None:
        github_shape = "gh" + "p_" + "A" * 32
        linear_shape = "lin_" + "api_" + "B" * 32
        source = f"Bearer opaque {github_shape} query={linear_shape}"
        once = redact(source)
        twice = redact(once)
        self.assertEqual(once, twice)
        self.assertNotIn(github_shape, once)
        self.assertNotIn(linear_shape, once)

    def test_zed_pkg_test_script_keeps_security_suite_and_verifier_coupled(self) -> None:
        config = tomllib.loads(Path(".zpkg.toml").read_text())
        script = config["scripts"]["test"]
        self.assertIn("unittest discover", script)
        self.assertIn("scripts/verify_repository.py", script)


if __name__ == "__main__":
    unittest.main()
