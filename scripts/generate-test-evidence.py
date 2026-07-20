#!/usr/bin/env python3
"""Run the declared test suites and publish a content-addressed receipt."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = ROOT / "requirements-test.lock"
COMPLETE_ARGV = ("python", "-m", "pytest", "-q")
CAREER_ARGV = COMPLETE_ARGV + ("career_automation",)
RECEIPT_DIRECTORY = ROOT / "runtime_evidence" / "pytest"
EVIDENCE_PREFIX = b"runtime_evidence/pytest/"
CONTENT_REVISION_DOMAIN = b"jaa-product-content-revision-v1\0"
LOCAL_IMPORT = "skeleton"

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SUMMARY_ITEM = re.compile(
    r"(?P<count>\d+) (?P<outcome>passed|failed|skipped|error|errors|"
    r"xfailed|xpassed|deselected)\b"
)
SUMMARY_LINE = re.compile(
    r"^(?:=+\s*)?(?P<body>.*?\b(?:passed|failed|skipped)\b.*?)"
    r"\s+in\s+[0-9.]+s(?:\s*=+)?$"
)
ALLOWED_OUTCOMES = frozenset({"passed", "failed", "skipped"})


class EvidenceError(RuntimeError):
    """The run is not suitable for an accepted evidence receipt."""


def display_command(command: tuple[str, ...]) -> str:
    """Return the fixed repository-relative command without shell ambiguity."""
    return " ".join(command)


def parse_summary(output: str) -> dict[str, int]:
    """Parse one and only one final pytest outcome summary."""
    clean_output = ANSI_ESCAPE.sub("", output)
    candidates: list[dict[str, int]] = []
    for line in clean_output.splitlines():
        match = SUMMARY_LINE.match(line.strip())
        if not match:
            continue
        items = list(SUMMARY_ITEM.finditer(match.group("body")))
        if not items:
            continue
        outcomes: dict[str, int] = {}
        for item in items:
            outcome = item.group("outcome")
            outcome = "error" if outcome == "errors" else outcome
            if outcome in outcomes:
                raise EvidenceError(f"duplicate pytest outcome in summary: {outcome}")
            outcomes[outcome] = int(item.group("count"))
        candidates.append(outcomes)

    if len(candidates) != 1:
        raise EvidenceError(
            f"expected exactly one parseable pytest summary, found {len(candidates)}"
        )

    outcomes = candidates[0]
    unsupported = set(outcomes) - ALLOWED_OUTCOMES
    if unsupported:
        raise EvidenceError(
            "pytest reported outcomes that prevent an internally consistent total: "
            + ", ".join(sorted(unsupported))
        )

    counts = {outcome: outcomes.get(outcome, 0) for outcome in ALLOWED_OUTCOMES}
    counts["collected"] = sum(counts.values())
    if counts["collected"] <= 0:
        raise EvidenceError("pytest collected no tests")
    if counts["failed"] != 0:
        raise EvidenceError("pytest reported failed tests")
    return {key: counts[key] for key in ("collected", "passed", "skipped", "failed")}


def locked_environment() -> dict[str, object]:
    """Validate and describe the activated, locked test environment without its path."""
    implementation = platform.python_implementation()
    version = platform.python_version()
    if implementation != "CPython" or sys.version_info[:2] != (3, 12):
        raise EvidenceError(
            f"test evidence requires CPython 3.12; active interpreter is {implementation} {version}"
        )
    try:
        lock_payload = LOCK_FILE.read_bytes()
    except OSError as exc:
        raise EvidenceError("requirements-test.lock is missing or unreadable") from exc

    locked: dict[str, tuple[str, str]] = {}
    for raw_line in lock_payload.decode("utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("==") != 1:
            raise EvidenceError(f"unsupported unlocked requirement: {line}")
        distribution, expected = line.split("==", 1)
        if not distribution or not expected:
            raise EvidenceError(f"unsupported unlocked requirement: {line}")
        normalized = re.sub(r"[-_.]+", "-", distribution).lower()
        if normalized in locked:
            previous_name, previous_version = locked[normalized]
            detail = "duplicate" if previous_version == expected else "conflicting"
            raise EvidenceError(
                f"{detail} locked requirement: {previous_name}=={previous_version} and {line}"
            )
        locked[normalized] = (distribution, expected)

    installed_versions: dict[str, set[str]] = {}
    for installed in importlib.metadata.distributions():
        name = installed.metadata.get("Name")
        if not name:
            continue
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized in locked:
            installed_versions.setdefault(normalized, set()).add(installed.version)

    missing: list[str] = []
    mismatched: list[str] = []
    conflicting: list[str] = []
    for normalized, (distribution, expected) in locked.items():
        try:
            actual = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            missing.append(distribution)
        else:
            if actual != expected:
                mismatched.append(f"{distribution}=={actual} (expected {expected})")
        versions = installed_versions.get(normalized, set())
        extras = sorted(versions - {expected})
        if extras:
            conflicting.append(f"{distribution}: " + ", ".join(extras))
    if missing or mismatched or conflicting:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if mismatched:
            details.append("wrong versions: " + ", ".join(mismatched))
        if conflicting:
            details.append("extra conflicting versions: " + "; ".join(conflicting))
        raise EvidenceError(
            "locked test dependencies are unavailable ("
            + "; ".join(details)
            + "); run ./scripts/bootstrap-test-env.sh and activate .venv"
        )

    repository_root = os.fspath(ROOT.resolve())
    if not sys.path or sys.path[0] != repository_root:
        sys.path.insert(0, repository_root)
    importlib.invalidate_caches()
    try:
        local_module = importlib.import_module(LOCAL_IMPORT)
        local_file = Path(local_module.__file__).resolve()
    except (ImportError, AttributeError, OSError, TypeError) as exc:
        raise EvidenceError(f"local project import {LOCAL_IMPORT!r} is unavailable") from exc
    try:
        local_file.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise EvidenceError(
            f"local project import {LOCAL_IMPORT!r} does not resolve to this repository"
        ) from exc

    lock_hash = hashlib.sha256(lock_payload).hexdigest()
    identity_source = f"{implementation}\0{version}\0{lock_hash}".encode()
    return {
        "interpreter": {"implementation": implementation, "version": version},
        "dependency_lock": {"path": "requirements-test.lock", "sha256": lock_hash},
        "environment_identity": "sha256:" + hashlib.sha256(identity_source).hexdigest(),
    }


def run_suite(name: str, argv: tuple[str, ...]) -> dict[str, object]:
    execution_command = (sys.executable, *argv[1:])
    execution_environment = os.environ.copy()
    execution_environment["PYTHONPATH"] = os.fspath(ROOT.resolve())
    try:
        completed = subprocess.run(
            execution_command,
            cwd=ROOT,
            env=execution_environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        raise EvidenceError(f"could not run {display_command(argv)}: {exc}") from exc

    if completed.returncode != 0:
        raise EvidenceError(
            f"{name} suite exited with status {completed.returncode}\n{completed.stdout}"
        )
    counts = parse_summary(completed.stdout)
    return {
        "name": name,
        "argv": list(argv),
        "counts": counts,
    }


def git(*arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode(errors="replace").strip()
        raise EvidenceError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def tested_git_parent() -> str:
    revision = git("rev-parse", "--verify", "HEAD").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
        raise EvidenceError("could not determine the tested Git parent")
    return revision


def product_content_revision() -> str:
    """Hash the exact tracked product tree, excluding generated pytest receipts."""
    entries: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    for record in git("ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise EvidenceError("malformed tracked path record")
        mode, _object_id, stage = fields
        if path in seen:
            raise EvidenceError(f"duplicate tracked path: {os.fsdecode(path)}")
        seen.add(path)
        if path.startswith(EVIDENCE_PREFIX):
            continue
        if stage != b"0":
            raise EvidenceError(f"unmerged tracked path: {os.fsdecode(path)}")
        if mode == b"120000":
            raise EvidenceError(f"symlink product file refused: {os.fsdecode(path)}")
        if mode not in {b"100644", b"100755"}:
            raise EvidenceError(
                f"unsupported product file mode {mode.decode()}: {os.fsdecode(path)}"
            )
        entries.append((path, mode))

    untracked = [
        path for path in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
        if path and not path.startswith(EVIDENCE_PREFIX)
    ]
    if untracked:
        raise EvidenceError(f"untracked product file: {os.fsdecode(sorted(untracked)[0])}")

    digest = hashlib.sha256(CONTENT_REVISION_DOMAIN)
    for path, mode in sorted(entries):
        file_path = ROOT / os.fsdecode(path)
        try:
            status = file_path.lstat()
            payload = file_path.read_bytes()
        except (OSError, ValueError) as exc:
            raise EvidenceError(f"missing or unreadable product file: {os.fsdecode(path)}") from exc
        if not stat.S_ISREG(status.st_mode):
            raise EvidenceError(f"non-regular product file refused: {os.fsdecode(path)}")
        actual_mode = b"100755" if status.st_mode & 0o111 else b"100644"
        if actual_mode != mode:
            raise EvidenceError(f"dirty product file mode: {os.fsdecode(path)}")
        for field in (path, mode, payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)

    product_pathspec = (".", ":(exclude)runtime_evidence/pytest/**")
    if git("diff", "--name-only", "-z", "--", *product_pathspec) or git(
        "diff", "--cached", "--name-only", "-z", "--", *product_pathspec
    ):
        raise EvidenceError("dirty tracked product tree")
    return f"sha256:{digest.hexdigest()}"


def canonical_json(receipt: dict[str, object]) -> bytes:
    return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> int:
    try:
        revision = product_content_revision()
        parent = tested_git_parent()
        environment = locked_environment()
        complete = run_suite("complete", COMPLETE_ARGV)
        career = run_suite("career_automation", CAREER_ARGV)
        if product_content_revision() != revision:
            raise EvidenceError("tracked product content changed during the test run")

        career["historical_baseline_passed"] = 65
        receipt: dict[str, object] = {
            "schema_version": 3,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
            "tested_product_content_revision": revision,
            "tested_git_parent": parent,
            **environment,
            "platform": platform.platform(),
            "suites": [complete, career],
        }
        payload = canonical_json(receipt)
        digest = hashlib.sha256(payload).hexdigest()
        RECEIPT_DIRECTORY.mkdir(parents=True, exist_ok=True)
        destination = RECEIPT_DIRECTORY / f"sha256-{digest}.json"
        destination.write_bytes(payload)
        print(destination.relative_to(ROOT))
        return 0
    except EvidenceError as exc:
        print(f"test evidence rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
