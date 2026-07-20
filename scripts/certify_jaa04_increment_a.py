#!/usr/bin/env python3
"""Certify the checked-in JAA-04 Increment A temporal authority evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import (  # noqa: E402
    ATS_AUTHORITY_CANARIES,
    Citation,
    PortableAuthorityRetriever,
    extract_publisher_timestamps,
)
from tracked_source_revision import (  # noqa: E402
    TrackedSourceRevisionError,
    source_content_revision,
    source_content_revision_contract,
)

FORMAT = "jaa04-increment-a-temporal-provenance-certification/v1"
CANARY_DIRECTORY = ROOT / "career_automation/fixtures/jaa04_authority_canaries"
INVENTORY_PATH = ROOT / "scripts/jaa04_increment_a_test_inventory.json"
INVENTORY_SHA256 = "4685a0b53ec15b89adce13fa2a30da54a5cc443aa49a7ba1d3bfb855e7f43a5d"
PYTEST_PLUGIN = ROOT / "scripts/jaa04_pytest_inventory_plugin.py"
PYTEST_PLUGIN_SHA256 = "4b167aa1ad974e772ad309f6d69c055a4912025ba9c4a0b0c78ba6f59d6487b3"
# Compatibility integrity sentinels. Discovery and expected outcomes come only
# from the content-pinned inventory; these make legacy count-reduction attacks
# explicit failures instead of harmless-looking certifier edits.
SUITES = (
    "test_jaa04_increment_a_authority_canaries.py",
    "test_jaa04_increment_a_temporal_authority_regression.py",
    "test_jaa04_sidecar_temporal_semantics.py",
    "test_jaa04_portable_authority_contract.py",
)
EXPECTED_TESTS = 47


class CertificationError(RuntimeError):
    """Increment A cannot be certified."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificationError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def git(*arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", *arguments), cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode:
        raise CertificationError(
            f"git {' '.join(arguments)} failed: "
            f"{completed.stderr.decode(errors='replace').strip()}"
        )
    return completed.stdout


def clean_source() -> tuple[str, str]:
    revision = git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    require(bool(re.fullmatch(r"[0-9a-f]{40,64}", revision)),
            "Git source revision is missing or invalid")
    dirty = []
    for row in git("status", "--porcelain=v1", "-z", "--untracked-files=all").split(b"\0"):
        if not row:
            continue
        # Runtime receipts are generated evidence, not product source. Rename
        # records have a second NUL-delimited path and are rejected conservatively.
        path = row[3:]
        if not path.startswith(b"runtime_evidence/"):
            dirty.append(row)
    require(not dirty, "dirty, missing, or added source input cannot be certified")
    try:
        content_revision = source_content_revision(ROOT)
    except TrackedSourceRevisionError as exc:
        raise CertificationError(str(exc)) from exc
    return revision, content_revision


def _safe_output(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        require(not component.is_symlink(),
                f"receipt path must not resolve through a symlink: {path}")
    require(absolute.resolve(strict=False) == absolute,
            f"receipt path must not resolve through a symlink: {path}")
    return absolute


def validate_canaries() -> dict[str, str]:
    require(CANARY_DIRECTORY.is_dir() and not CANARY_DIRECTORY.is_symlink(),
            "typed ATS canary directory is missing or unsafe")
    expected_names = {f"{record.job_key.split(':', 1)[0]}.json"
                      for record in ATS_AUTHORITY_CANARIES}
    entries = list(CANARY_DIRECTORY.iterdir())
    require({path.name for path in entries} == expected_names and len(entries) == 3,
            "typed ATS canaries must be exactly the three admitted artifacts")

    hashes: dict[str, str] = {}
    for record in ATS_AUTHORITY_CANARIES:
        path = CANARY_DIRECTORY / f"{record.job_key.split(':', 1)[0]}.json"
        require(path.is_file() and not path.is_symlink(),
                f"typed ATS canary is missing or unsafe: {path.name}")
        payload = path.read_bytes()
        hashes[path.relative_to(ROOT).as_posix()] = sha256(payload)
        try:
            artifact = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CertificationError(f"invalid typed ATS canary {path.name}: {exc}") from exc
        require(canonical(artifact) == payload,
                f"typed ATS canary is not canonical JSON: {path.name}")
        require(artifact.get("schema_version") == "jaa04.typed-authority-canary.v1",
                f"unsupported typed ATS canary schema: {path.name}")
        expected_identity = asdict(record)
        expected_identity["authority_hosts"] = list(record.authority_hosts)
        expected_identity["final_paths"] = list(record.final_paths)
        require(artifact.get("admitted_record") == expected_identity,
                f"admitted-record identity mismatch: {path.name}")
        captures = artifact.get("captures")
        require(isinstance(captures, list) and len(captures) == 1,
                f"typed ATS canary must contain one capture: {path.name}")
        row = captures[0]
        require(isinstance(row, dict), f"invalid capture record: {path.name}")
        require(row.get("raw_response_encoding") == "base64"
                and row.get("raw_response_ref") == "embedded:raw_response_base64",
                f"embedded raw-response declaration mismatch: {path.name}")
        try:
            raw = base64.b64decode(row.get("raw_response_base64", ""), validate=True)
        except (ValueError, TypeError) as exc:
            raise CertificationError(f"invalid embedded raw response: {path.name}") from exc
        digest = sha256(raw)
        require(row.get("content_sha256") == digest,
                f"embedded raw-response SHA-256 mismatch: {path.name}")
        require(row.get("sidecar_raw_response_ref") == f"sha256/{digest[:2]}/{digest}",
                f"sidecar raw-response reference mismatch: {path.name}")

        citation_fields = dict(row)
        for field in ("raw_response_base64", "raw_response_encoding",
                      "sidecar_raw_response_ref"):
            citation_fields.pop(field, None)
        try:
            citation = Citation(**citation_fields)
        except (TypeError, ValueError) as exc:
            raise CertificationError(f"invalid typed citation: {path.name}: {exc}") from exc
        published, updated, evidence = extract_publisher_timestamps(raw)
        require((citation.published_at, citation.updated_at,
                 citation.publisher_date_evidence) == (published, updated, evidence),
                f"publisher/update timestamp semantics mismatch: {path.name}")
        try:
            PortableAuthorityRetriever._validate_canary_capture(record, citation, raw)
        except (ValueError, UnicodeError) as exc:
            raise CertificationError(
                f"fail-closed canary validation failed for {path.name}: {exc}"
            ) from exc
    return dict(sorted(hashes.items()))


def canonical_inventory() -> tuple[list[str], int]:
    """Load the content-pinned inventory and verify every canonical suite byte."""
    require(INVENTORY_PATH.is_file() and not INVENTORY_PATH.is_symlink(),
            "canonical Increment A test inventory is missing or unsafe")
    payload = INVENTORY_PATH.read_bytes()
    require(sha256(payload) == INVENTORY_SHA256,
            "canonical Increment A test inventory was tampered")
    try:
        inventory = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CertificationError(f"invalid canonical test inventory: {exc}") from exc
    require(inventory.get("format") == "jaa04-increment-a-test-inventory/v1",
            "unsupported canonical Increment A test inventory")
    suites = inventory.get("suites")
    require(isinstance(suites, dict) and suites,
            "canonical Increment A suite inventory is incomplete")
    names = inventory.get("suite_order")
    require(isinstance(names, list) and all(isinstance(name, str) for name in names)
            and len(names) == len(set(names)) and set(names) == set(suites),
            "canonical Increment A suite ordering is incomplete")
    require(tuple(names) == SUITES and EXPECTED_TESTS == 47,
            "legacy Increment A inventory sentinels were changed")
    require("test_jaa04_sidecar_temporal_semantics.py" in names,
            "sidecar temporal-semantics suite is absent from canonical inventory")
    for name in names:
        require(Path(name).name == name and name.startswith("test_jaa04_")
                and name.endswith(".py"), f"unsafe canonical suite name: {name}")
        path = ROOT / name
        require(path.is_file() and not path.is_symlink(),
                f"canonical Increment A suite is missing or unsafe: {name}")
        require(sha256(path.read_bytes()) == suites[name],
                f"canonical Increment A suite bytes changed: {name}")
    collected = inventory.get("collected")
    require(type(collected) is int and collected == 47,
            "canonical Increment A inventory must contain exactly 47 tests")
    return names, collected


def run_suites() -> list[dict[str, Any]]:
    suites, expected = canonical_inventory()
    require(PYTEST_PLUGIN.is_file() and not PYTEST_PLUGIN.is_symlink()
            and sha256(PYTEST_PLUGIN.read_bytes()) == PYTEST_PLUGIN_SHA256,
            "JAA-04 pytest outcome reporter is missing or tampered")
    with tempfile.TemporaryDirectory(prefix=".jaa04-pytest-", dir=ROOT) as temporary:
        report_path = Path(temporary) / "report.json"
        argv = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                "-p", "scripts.jaa04_pytest_inventory_plugin", *suites]
        environment = os.environ.copy()
        environment["JAA04_PYTEST_REPORT"] = str(report_path)
        completed = subprocess.run(
            argv, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        error = completed.stderr.decode("utf-8", errors="replace")
        require(report_path.is_file() and not report_path.is_symlink(),
                f"pytest produced no trustworthy outcome report: {error or output}")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CertificationError(f"invalid pytest outcome report: {exc}") from exc

    outcomes = report.get("outcomes")
    require(isinstance(outcomes, dict), "pytest outcome report is incomplete")
    require(completed.returncode == report.get("exit_code") == 0,
            f"canonical Increment A pytest run failed: {error.strip() or output.strip()}")
    require(report.get("collected") == expected == 47,
            "pytest must collect exactly the 47 canonical Increment A tests")
    require(outcomes.get("passed") == expected,
            "pytest must report exactly 47 passed Increment A tests")
    for outcome in ("skipped", "xfailed", "xpassed", "failed", "error"):
        require(outcomes.get(outcome) == 0,
                f"pytest reported forbidden {outcome} outcomes")
    require(report.get("deselected") == 0,
            "pytest reported forbidden deselected outcomes")
    passed_by_suite = report.get("passed_by_suite")
    require(isinstance(passed_by_suite, dict)
            and set(passed_by_suite) == set(suites)
            and sum(passed_by_suite.values()) == expected,
            "pytest per-suite pass inventory does not match the canonical inventory")
    return [{
        "suite": suite,
        "argv": ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", suite],
        "exit_code": 0,
        "passed": passed_by_suite[suite],
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "deselected": 0,
    } for suite in suites]


def publish(directory: Path, payload: bytes) -> Path:
    directory = _safe_output(directory)
    directory.mkdir(parents=True, exist_ok=True)
    directory = _safe_output(directory)
    require(directory.is_dir(), "receipt destination is not a directory")
    digest = sha256(payload)
    destination = _safe_output(directory / f"sha256-{digest}.json")
    existing = list(directory.iterdir())
    require(not existing or (len(existing) == 1 and existing[0] == destination),
            "receipt directory must contain exactly one current canonical receipt")
    if destination.exists():
        require(destination.is_file() and not destination.is_symlink()
                and destination.read_bytes() == payload,
                "existing content-addressed receipt is invalid")
        return destination

    temporary: Path | None = None
    created_destination = False
    try:
        descriptor, name = tempfile.mkstemp(prefix=".jaa04-increment-a-", dir=directory)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
            created_destination = True
        except FileExistsError:
            require(destination.is_file() and not destination.is_symlink()
                    and destination.read_bytes() == payload,
                    "racing content-addressed receipt is invalid")
        temporary.unlink()
        temporary = None
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if created_destination and destination.exists() and destination.is_file() \
                and not destination.is_symlink():
            try:
                if destination.read_bytes() == payload:
                    destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    require(destination.read_bytes() == payload,
            "receipt changed after durable atomic publication")
    return destination


def certify(receipt_directory: Path) -> Path:
    revision_before, content_before = clean_source()
    artifacts_before = validate_canaries()
    suites = run_suites()
    artifacts_after = validate_canaries()
    revision_after, content_after = clean_source()
    require((revision_before, content_before, artifacts_before)
            == (revision_after, content_after, artifacts_after),
            "source or checked canary bytes changed during certification")
    document = {
        "format": FORMAT,
        "status": "SUCCESS",
        "source_revision": revision_before,
        "source_content_revision": content_before,
        "source_content_revision_contract": source_content_revision_contract(),
        "checked_artifact_hashes": artifacts_before,
        "executed_suite_results": suites,
    }
    return publish(receipt_directory, canonical(document))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path,
                        default=ROOT / "runtime_evidence/jaa04_increment_a")
    args = parser.parse_args(argv)
    try:
        destination = certify(args.receipt)
    except (CertificationError, OSError, UnicodeError, ValueError, TypeError,
            json.JSONDecodeError) as exc:
        print(f"JAA-04 Increment A certification: ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"JAA-04 Increment A certification: PASS ({destination})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
