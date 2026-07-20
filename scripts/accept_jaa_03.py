#!/usr/bin/env python3
"""Run JAA-03 acceptance and atomically certify the exact clean revision."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.opportunity_calibration import (  # noqa: E402
    DECISION_RULE_VERSION, LOCKED_METRICS, LOCKED_SET, LOCKED_SET_AUTHORITY_HASH,
    LOCKED_SET_ID, CalibrationPolicy, Confidence, Opportunity0Input, content_hash,
    decide_opportunity0, evaluate_locked_set, load_locked_set,
)
from tracked_source_revision import (  # noqa: E402
    TrackedSourceRevisionError, source_content_revision, source_content_revision_contract,
)

FORMAT = "jaa03-revision-certification/v1"
EVIDENCE_DIRECTORY = ROOT / "runtime_evidence" / "jaa03"


class AcceptanceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def git(*arguments: str) -> bytes:
    result = subprocess.run(
        ("git", *arguments), cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if result.returncode:
        raise AcceptanceError(
            f"unresolvable source revision: git {' '.join(arguments)}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def clean_revision() -> tuple[str, str]:
    revision = git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    require(len(revision) == 40 and all(c in "0123456789abcdef" for c in revision),
            "unresolvable source revision")
    status = git("status", "--porcelain=v1", "--untracked-files=all").splitlines()
    dirty = [line for line in status if not line[3:].startswith(b"runtime_evidence/")]
    require(not dirty, "dirty source revision cannot be certified")
    return revision, source_content_revision(ROOT)


def run_acceptance() -> dict[str, Any]:
    records, locked_hash = load_locked_set()
    metrics = evaluate_locked_set(records)
    expected = json.loads(LOCKED_METRICS.read_text(encoding="utf-8"))
    require(expected.get("locked_set_hash") == locked_hash, "locked metrics set hash mismatch")
    require(expected.get("metrics") == metrics, "locked metrics replay mismatch")
    require(expected.get("replay_mismatches") == 0, "locked replay mismatch declaration")

    attractive = Opportunity0Input.from_mapping({
        "market_demand_bp": 10_000, "role_quality_bp": 10_000,
        "accessibility_bp": 10_000,
    })
    high = Confidence(10_000, 10_000, 10_000, 10_000)
    negative_controls: list[str] = []
    for reason in ("expired", "inaccessible", "ineligible", "implausibly_senior"):
        rejected = decide_opportunity0(attractive, high, viability_reason=reason)
        require((rejected.decision, rejected.reason) == ("reject", reason),
                f"negative control failed: {reason}")
        negative_controls.append(reason)
    abstained = decide_opportunity0(
        attractive, Confidence(10_000, 10_000, 7_499, 10_000)
    )
    require((abstained.decision, abstained.reason, abstained.score_bp) ==
            ("abstain", "low_confidence_extraction", None),
            "negative control failed: low confidence")
    negative_controls.append("low_confidence_extraction")
    try:
        Opportunity0Input.from_mapping({
            "market_demand_bp": 0, "role_quality_bp": 0, "accessibility_bp": 0,
            "candidate_fit": 1.0, "interest": 1.0,
        })
    except ValueError:
        negative_controls.append("candidate_fit_and_interest_forbidden")
    else:
        raise AcceptanceError("negative control failed: candidate Fit rescued Opportunity-0")

    tampered = copy.deepcopy(json.loads(LOCKED_SET.read_text(encoding="utf-8")))
    tampered["records"][0]["labels"]["opportunity0_decision"]["decision"] = "reject"
    tampered["records_hash"] = content_hash(tampered["records"])
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
        json.dump(tampered, handle)
        handle.flush()
        try:
            load_locked_set(Path(handle.name))
        except ValueError as exc:
            require("authority mismatch" in str(exc),
                    "rehash negative control did not reach independent authority")
        else:
            raise AcceptanceError("changed label plus recomputed records_hash was accepted")
    negative_controls.append("label_change_with_recomputed_envelope_hash")

    require(evaluate_locked_set(records) == metrics, "non-deterministic replay")
    return {
        "status": "PASS",
        "locked_set_hash": locked_hash,
        "locked_set_authority_hash": LOCKED_SET_AUTHORITY_HASH,
        "metrics_hash": content_hash(metrics),
        "negative_controls": negative_controls,
    }


def canonical_receipt(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate_existing_receipts() -> list[tuple[Path, dict[str, Any]]]:
    if not EVIDENCE_DIRECTORY.exists():
        return []
    require(EVIDENCE_DIRECTORY.is_dir() and not EVIDENCE_DIRECTORY.is_symlink(),
            "unsafe JAA-03 evidence directory")
    receipts: list[tuple[Path, dict[str, Any]]] = []
    for path in EVIDENCE_DIRECTORY.iterdir():
        require(path.is_file() and not path.is_symlink() and path.name.startswith("sha256-")
                and path.name.endswith(".json"), "unexpected or unsafe JAA-03 receipt")
        payload = path.read_bytes()
        require(path.name == f"sha256-{sha256_bytes(payload)}.json",
                "JAA-03 receipt tampering detected")
        try:
            document = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AcceptanceError(f"invalid JAA-03 receipt: {exc}") from exc
        require(payload == canonical_receipt(document), "non-canonical JAA-03 receipt")
        require(document.get("format") == FORMAT and document.get("status") == "PASS",
                "unsupported JAA-03 receipt")
        receipts.append((path, document))
    return sorted(receipts, key=lambda item: item[0].name)


def reusable_receipt(
    source_revision: str,
    runtime_inputs: dict[str, str],
    configuration: dict[str, Any],
    acceptance_result: dict[str, Any],
) -> Path | None:
    """Reuse a certificate across commits which alter runtime evidence only.

    A checked-in content-addressed receipt necessarily changes Git HEAD.  The
    certified source-content revision excludes runtime_evidence/, so exact
    product bytes—not an impossible self-referential commit hash—are the
    authority for replay.
    """
    receipts = validate_existing_receipts()
    require(len(receipts) <= 1, "multiple JAA-03 receipts")
    matches: list[Path] = []
    for path, document in receipts:
        if (
            document.get("source_content_revision") == source_revision
            and document.get("source_content_revision_contract")
            == source_content_revision_contract()
            and document.get("runtime_inputs") == runtime_inputs
            and document.get("configuration") == configuration
            and document.get("acceptance_result") == acceptance_result
        ):
            origin = document.get("source_revision")
            require(isinstance(origin, str) and len(origin) == 40
                    and all(character in "0123456789abcdef" for character in origin),
                    "invalid JAA-03 origin revision")
            git("rev-parse", "--verify", f"{origin}^{{commit}}")
            matches.append(path)
    require(len(matches) <= 1, "multiple reusable JAA-03 receipts")
    if matches:
        return matches[0]
    require(not receipts,
            "stale JAA-03 receipt must be replaced before certification")
    return None


def write_receipt(document: dict[str, Any]) -> Path:
    payload = canonical_receipt(document)
    destination = EVIDENCE_DIRECTORY / f"sha256-{sha256_bytes(payload)}.json"
    EVIDENCE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    require(not validate_existing_receipts(),
            "refusing to retain multiple JAA-03 receipts")
    if destination.exists():
        require(destination.read_bytes() == payload, "conflicting JAA-03 PASS receipt")
        return destination
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        directory_fd = os.open(EVIDENCE_DIRECTORY, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    require(destination.read_bytes() == payload, "receipt changed after atomic creation")
    return destination


def main() -> int:
    try:
        revision_before, source_before = clean_revision()
        inputs_before = {
            "locked_set_file_sha256": sha256_bytes(LOCKED_SET.read_bytes()),
            "locked_metrics_file_sha256": sha256_bytes(LOCKED_METRICS.read_bytes()),
        }
        result = run_acceptance()
        revision_after, source_after = clean_revision()
        inputs_after = {
            "locked_set_file_sha256": sha256_bytes(LOCKED_SET.read_bytes()),
            "locked_metrics_file_sha256": sha256_bytes(LOCKED_METRICS.read_bytes()),
        }
        require((revision_before, source_before, inputs_before) ==
                (revision_after, source_after, inputs_after),
                "source or runtime inputs changed during acceptance")
        policy = CalibrationPolicy()
        configuration = {
            "locked_set_id": LOCKED_SET_ID,
            "decision_rule_version": DECISION_RULE_VERSION,
            "policy": vars(policy),
            "policy_hash": policy.policy_hash,
        }
        existing = reusable_receipt(source_before, inputs_before, configuration, result)
        if existing is not None:
            print(json.dumps({"receipt": existing.relative_to(ROOT).as_posix(), "status": "PASS"},
                             sort_keys=True))
            return 0
        receipt = {
            "format": FORMAT,
            "status": "PASS",
            "source_revision": revision_before,
            "source_content_revision": source_before,
            "source_content_revision_contract": source_content_revision_contract(),
            "runtime": {
                "python_implementation": platform.python_implementation(),
                "python_version": platform.python_version(),
            },
            "runtime_inputs": inputs_before,
            "configuration": configuration,
            "acceptance_result": result,
        }
        destination = write_receipt(receipt)
    except (AcceptanceError, TrackedSourceRevisionError, OSError, ValueError,
            KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"JAA-03 acceptance: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"receipt": destination.relative_to(ROOT).as_posix(), "status": "PASS"},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
