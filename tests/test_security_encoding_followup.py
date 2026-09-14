"""Regression matrix for encoded traversal and callback authority confusion."""

import unittest

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, validate_outbound_url


class SecurityEncodingFollowupTests(unittest.TestCase):
    def test_encoded_parent_segment_matrix_fails_closed(self):
        for value in ("tenant/%2e%2e/secret", "%2E%2e/%2e%2E/secret", "tenant/%252e%252e/secret", "%2e%2e%2fsecret"):
            with self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_auth_provider_authority_confusion_fails_closed(self):
        allowed = {"auth.example.test"}
        for value in ("https://auth.example.test.attacker.invalid/callback", "https://auth.example.test%40attacker.invalid/callback", "https://attacker.invalid/?next=https://auth.example.test", "//attacker.invalid/auth.example.test"):
            with self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)


if __name__ == "__main__":
    unittest.main()
