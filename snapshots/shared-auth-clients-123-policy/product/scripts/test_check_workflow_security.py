#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("check-workflow-security.py")
SPEC = importlib.util.spec_from_file_location("workflow_security", MODULE_PATH)
assert SPEC and SPEC.loader
workflow_security = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow_security)

PINNED_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
PINNED_REUSABLE = "ores-otel/.github/.github/workflows/source-policy-lint.yml@c417efc488bb4ca84e078fad9626f55b374913dd"


def workflow(*, uses: str = PINNED_CHECKOUT, permissions: str = "contents: read", timeout: bool = True, persist: str = "false", event: str = "pull_request:") -> str:
    timeout_line = "    timeout-minutes: 10\n" if timeout else ""
    persist_block = f"\n        with:\n          persist-credentials: {persist}" if uses.startswith("actions/checkout@") else ""
    return f"""name: fixture
on:
  {event}
permissions:
  {permissions}
jobs:
  check:
    runs-on: ubuntu-24.04
{timeout_line}    steps:
      - uses: {uses}{persist_block}
      - run: echo ok
"""


def reusable_workflow() -> str:
    return f"""name: reusable fixture
on:
  pull_request:
permissions:
  contents: read
jobs:
  source-policy:
    uses: {PINNED_REUSABLE}
    permissions:
      contents: read
"""


class WorkflowSecurityTests(unittest.TestCase):
    def validate(self, text: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / ".github" / "workflows"
            directory.mkdir(parents=True)
            (directory / "fixture.yml").write_text(text)
            return workflow_security.validate_workflows(root)

    def test_accepts_sha_pinned_action_with_bounded_read_only_workflow(self) -> None:
        self.assertEqual(self.validate(workflow()), [])

    def test_rejects_mutable_action_tag(self) -> None:
        errors = self.validate(workflow(uses="actions/checkout@v4"))
        self.assertTrue(any("mutable action reference" in error for error in errors))

    def test_rejects_missing_top_level_permissions(self) -> None:
        text = workflow().replace("permissions:\n  contents: read\n", "")
        errors = self.validate(text)
        self.assertTrue(any("missing top-level permissions" in error for error in errors))

    def test_rejects_unbounded_runner_job(self) -> None:
        errors = self.validate(workflow(timeout=False))
        self.assertTrue(any("missing bounded job timeout" in error for error in errors))

    def test_accepts_reusable_workflow_call_without_runner_timeout(self) -> None:
        self.assertEqual(self.validate(reusable_workflow()), [])

    def test_rejects_persisted_checkout_credentials(self) -> None:
        errors = self.validate(workflow(persist="true"))
        self.assertTrue(any("persist-credentials: true" in error for error in errors))

    def test_rejects_pull_request_target(self) -> None:
        errors = self.validate(workflow(event="pull_request_target:"))
        self.assertTrue(any("pull_request_target:" in error for error in errors))

    def test_accepts_digest_pinned_container_action(self) -> None:
        digest = "sha256:" + ("a" * 64)
        text = workflow(uses=f"docker://alpine@{digest}")
        self.assertEqual(self.validate(text), [])

    def test_rejects_mutable_container_action(self) -> None:
        errors = self.validate(workflow(uses="docker://alpine:3.22"))
        self.assertTrue(any("mutable container action" in error for error in errors))

    def test_accepts_local_actions_without_external_pin(self) -> None:
        self.assertEqual(self.validate(workflow(uses="./.github/actions/local")), [])


if __name__ == "__main__":
    unittest.main()
