"""Verify exact upstream Git blob identities before executing the snapshot."""
import hashlib
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "admission-source.json").read_text())
assert manifest["repository"] == "shared-auth/shared-auth-infra"
assert re.fullmatch(r"[0-9a-f]{40}", manifest["commit"])
source = root / "source-snapshots/admission"
expected = set()
for item in manifest["files"]:
    relative = Path(item["path"])
    assert not relative.is_absolute() and ".." not in relative.parts
    assert item["path"].startswith("runtime-auth/")
    assert item["path"] not in expected
    expected.add(item["path"])
    path = source / relative
    assert not path.is_symlink()
    assert path.resolve().is_relative_to(source.resolve())
    data = path.read_bytes()
    blob = b"blob " + str(len(data)).encode() + b"\0" + data
    assert hashlib.sha1(blob).hexdigest() == item["blob"], item["path"]
actual = {str(p.relative_to(source)) for p in source.rglob("*") if p.is_file()}
assert actual == expected
print(f"Verified {len(expected)} upstream blobs at {manifest['commit']}")
