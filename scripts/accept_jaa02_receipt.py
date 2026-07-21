#!/usr/bin/env python3
"""Non-mutating validation of the single checked-in JAA-02 receipt."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.certify_jaa02_runtime import (  # noqa: E402
    COMMANDS, EXPECTED_TEST_TOTALS, FORMAT, NEGATIVE_CONTROLS, certification_runtime,
)
from tracked_source_revision import source_content_revision_contract  # noqa: E402


class ValidationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _checked_in_receipts() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--", "runtime_evidence/jaa02/sha256-*.json"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    require(completed.returncode == 0, "cannot enumerate checked-in JAA-02 receipts")
    return [ROOT / line for line in completed.stdout.splitlines() if line]


def validate() -> Path:
    receipts = _checked_in_receipts()
    require(len(receipts) == 1,
            f"expected exactly one checked-in JAA-02 receipt, found {len(receipts)}")
    receipt = receipts[0]
    require(receipt.is_file() and not receipt.is_symlink(), "JAA-02 receipt is not a regular file")
    payload = receipt.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    require(receipt.name == f"sha256-{digest}.json", "JAA-02 receipt file hash mismatch")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid JAA-02 receipt JSON: {exc}") from exc
    require(isinstance(document, dict) and document.get("format") == FORMAT,
            "unsupported JAA-02 receipt format")
    require(document.get("runtime") == certification_runtime(),
            "JAA-02 runtime identity mismatch")
    require(document.get("source_content_revision_contract") == source_content_revision_contract(),
            "JAA-02 source revision contract mismatch")
    recorded_revision = document.get("source_content_revision")
    require(isinstance(recorded_revision, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", recorded_revision),
            "invalid historical JAA-02 source revision")
    require(document.get("negative_controls") == NEGATIVE_CONTROLS,
            "required JAA-02 negative-control declarations mismatch")
    commands = document.get("command_semantics")
    require(isinstance(commands, list) and len(commands) == 2,
            "JAA-02 command evidence must contain exactly two commands")
    for evidence, (role, argv) in zip(commands, COMMANDS, strict=True):
        require(isinstance(evidence, dict), "invalid JAA-02 command evidence")
        require(evidence.get("role") == role and evidence.get("argv") == argv and
                evidence.get("working_directory") == "repository-root" and
                evidence.get("exit_code") == 0,
                f"JAA-02 {role} command semantics mismatch")
        for prefix in ("stdout", "stderr"):
            require(isinstance(evidence.get(f"{prefix}_bytes"), int) and
                    evidence[f"{prefix}_bytes"] >= 0 and
                    isinstance(evidence.get(f"{prefix}_sha256"), str) and
                    re.fullmatch(r"[0-9a-f]{64}", evidence[f"{prefix}_sha256"]) is not None,
                    f"JAA-02 {role} {prefix} evidence shape mismatch")
        expected = ({"passed": 1, "failed": 0, "errors": 0, "skipped": 0}
                    if role == "acceptance_demo" else EXPECTED_TEST_TOTALS)
        require(evidence.get("parsed_test_totals") == expected,
                f"JAA-02 {role} test totals mismatch")
    return receipt


def main() -> int:
    try:
        receipt = validate()
    except (ValidationError, OSError) as exc:
        print(f"jaa02-receipt-acceptance: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"receipt": receipt.relative_to(ROOT).as_posix(), "status": "accepted"},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
