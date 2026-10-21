#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
USES = re.compile(r"(?m)^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)")


def validate_workflows(root: Path) -> list[str]:
    errors: list[str] = []
    workflow_dir = root / ".github" / "workflows"

    for path in sorted(workflow_dir.glob("*.y*ml")):
        text = path.read_text()
        display = path.relative_to(root)
        if not re.search(r"(?m)^permissions:\s*(?:\n|\{)", text):
            errors.append(f"{display}: missing top-level permissions")
        # `timeout-minutes` is a runner-job boundary. A workflow containing only
        # reusable-workflow call jobs (`jobs.<id>.uses`) has no local runner to
        # bound and GitHub does not accept runner-only keys on that call job.
        if "runs-on:" in text and "timeout-minutes:" not in text:
            errors.append(f"{display}: missing bounded job timeout")
        if "actions/checkout@" in text and "persist-credentials: false" not in text:
            errors.append(f"{display}: checkout credentials are persisted or unspecified")
        for forbidden in (
            "pull_request_target:",
            "permissions: write-all",
            "secrets: inherit",
            "persist-credentials: true",
        ):
            if forbidden in text:
                errors.append(f"{display}: forbidden workflow boundary {forbidden}")
        for reference in USES.findall(text):
            if reference.startswith("./"):
                continue
            if reference.startswith("docker://"):
                digest = reference.rsplit("@", 1)[-1] if "@" in reference else ""
                if not DIGEST.fullmatch(digest):
                    errors.append(f"{display}: mutable container action {reference}")
                continue
            if "@" not in reference or not FULL_SHA.fullmatch(reference.rsplit("@", 1)[1]):
                errors.append(f"{display}: mutable action reference {reference}")

    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path.cwd()
    errors = validate_workflows(root)
    if errors:
        print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
        return 1
    print("workflow security policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
