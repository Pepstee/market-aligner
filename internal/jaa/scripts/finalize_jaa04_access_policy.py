#!/usr/bin/env python3
"""Finalize human-authored JAA-04 terms attestations outside the repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.public_access import (  # noqa: E402
    POLICY_SCHEMA,
    PublicAccessPolicy,
    policy_records_hash,
)


DRAFT_SCHEMA = "jaa04.public-access-policy-draft.v1"


def _external(path: Path, *, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise ValueError(f"{label} must be outside the product repository")


def finalize(draft: Path, output: Path) -> tuple[Path, str]:
    """Publish one immutable validated policy without deriving authority facts."""
    if draft.is_symlink():
        raise ValueError("access-policy draft must not be a symlink")
    if output.exists() or output.is_symlink():
        raise FileExistsError("access-policy output already exists")
    draft = _external(draft, label="access-policy draft")
    output = _external(output, label="access-policy output")
    if draft == output:
        raise ValueError("draft and output paths must differ")
    if not draft.is_file():
        raise ValueError("access-policy draft must be one regular file")
    if not output.parent.is_dir():
        raise ValueError("access-policy output parent must already exist")

    payload = json.loads(draft.read_bytes())
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "hosts"}:
        raise ValueError("access-policy draft has an invalid field set")
    if payload["schema_version"] != DRAFT_SCHEMA:
        raise ValueError(f"access-policy draft must use {DRAFT_SCHEMA}")
    records = payload["hosts"]
    if not isinstance(records, list) or not records:
        raise ValueError("access-policy draft requires human-authored host attestations")
    policy = {
        "schema_version": POLICY_SCHEMA,
        "hosts": records,
        "records_hash": policy_records_hash(records),
    }
    encoded = (
        json.dumps(
            policy,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        + b"\n"
    )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".jaa04-access-policy-",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        validated = PublicAccessPolicy.load(temporary)
        if validated.policy_sha256 != hashlib.sha256(encoded).hexdigest():
            raise RuntimeError("finalized access-policy identity is inconsistent")
        os.link(temporary, output)
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return output, hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Package exact human-authored terms attestations. This command "
            "does not review terms or create an authority determination."
        ),
    )
    parser.add_argument("--draft", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        output, digest = finalize(args.draft, args.output)
    except Exception as exc:
        print(f"JAA-04 access-policy finalization: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": "SUCCESS",
        "policy": str(output),
        "policy_sha256": digest,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
