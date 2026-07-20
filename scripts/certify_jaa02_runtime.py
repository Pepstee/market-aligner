#!/usr/bin/env python3
"""Run and certify the complete JAA-02 acceptance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracked_source_revision import (  # noqa: E402
    TrackedSourceRevisionError,
    source_content_revision,
    source_content_revision_contract,
)

FORMAT = "jaa02-runtime-certification/v1"
EXPECTED_TEST_TOTALS = {"passed": 12, "failed": 0, "errors": 0, "skipped": 0}
NEGATIVE_CONTROLS = [
    "forward-only-migration-and-database-integrity",
    "unverified-and-fabricated-evidence-refused",
    "non-factual-and-unsupported-claims-refused",
    "stale-evidence-refused",
    "secret-and-private-content-excluded",
    "work-right-abstains-without-applicable-current-verification",
    "acceptance-declaration-fails-closed",
]
COMMANDS = (
    ("acceptance_demo", ["python3", "scripts/accept_jaa_02.py"]),
    ("independent_negative_controls", [
        "python3", "-m", "pytest", "-q", "test_jaa02_independent_acceptance.py",
    ]),
)


class CertificationError(RuntimeError):
    """JAA-02 could not be certified."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificationError(message)


def _unlinked(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        require(not component.is_symlink(), f"output path must not resolve through a symlink: {path}")
    require(absolute.resolve(strict=False) == absolute,
            f"output path must not resolve through a symlink: {path}")


def _totals(role: str, stdout: bytes) -> dict[str, int]:
    text = stdout.decode("utf-8", errors="strict")
    if role == "acceptance_demo":
        require(text == "JAA-02 acceptance: PASS\n", "acceptance demo emitted unexpected output")
        return {"passed": 1, "failed": 0, "errors": 0, "skipped": 0}
    totals = {name: 0 for name in ("passed", "failed", "errors", "skipped")}
    for count, name in re.findall(r"(\d+) (passed|failed|errors?|skipped)", text):
        totals["errors" if name.startswith("error") else name] += int(count)
    require(totals == EXPECTED_TEST_TOTALS,
            f"independent JAA-02 test totals were {totals}, expected {EXPECTED_TEST_TOTALS}")
    return totals


def _run(role: str, argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               check=False)
    require(completed.returncode == 0,
            f"{role} command failed with exit code {completed.returncode}: "
            f"{completed.stderr.decode(errors='replace').strip()}")
    return {
        "role": role,
        "argv": argv,
        "working_directory": "repository-root",
        "exit_code": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "parsed_test_totals": _totals(role, completed.stdout),
    }


def _publish(directory: Path, payload: bytes) -> Path:
    _unlinked(directory)
    directory.mkdir(parents=True, exist_ok=True)
    _unlinked(directory)
    digest = hashlib.sha256(payload).hexdigest()
    destination = directory / f"sha256-{digest}.json"
    _unlinked(destination)
    existing = sorted(directory.glob("*.json"))
    require(not existing or existing == [destination],
            "refusing to retain multiple JAA-02 certification receipts")
    if destination.exists():
        require(destination.is_file() and not destination.is_symlink() and
                destination.read_bytes() == payload,
                "content-addressed evidence file mismatch")
        return destination
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".jaa02-", dir=directory)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError:
        require(destination.is_file() and not destination.is_symlink() and
                destination.read_bytes() == payload,
                "content-addressed evidence file mismatch")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    _unlinked(destination)
    return destination


def certify(evidence_directory: Path) -> Path:
    try:
        revision = source_content_revision(ROOT)
    except TrackedSourceRevisionError as exc:
        raise CertificationError(str(exc)) from exc
    commands = [_run(role, list(argv)) for role, argv in COMMANDS]
    try:
        require(source_content_revision(ROOT) == revision,
                "tracked source content changed during certification")
    except TrackedSourceRevisionError as exc:
        raise CertificationError(str(exc)) from exc
    document = {
        "format": FORMAT,
        "source_content_revision": revision,
        "source_content_revision_contract": source_content_revision_contract(),
        "command_semantics": commands,
        "negative_controls": NEGATIVE_CONTROLS,
    }
    payload = (json.dumps(document, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode()
    return _publish(evidence_directory, payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", default="runtime_evidence/jaa02")
    args = parser.parse_args(argv)
    try:
        destination = certify(Path(args.evidence_directory))
    except (CertificationError, OSError, UnicodeError) as exc:
        print(f"jaa02-runtime-certification: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"receipt": destination.as_posix(), "status": "certified"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
