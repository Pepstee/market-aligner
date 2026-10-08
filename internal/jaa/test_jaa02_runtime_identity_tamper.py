"""Black-box JAA-02 receipt identity tamper tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest

import test_jaa04_increment_a_certifier_fail_closed as inplace_fixture


ROOT = Path(__file__).resolve().parent
VALIDATOR = "scripts/accept_jaa02_receipt.py"

_SCENARIOS = {
    "test_authentic_jaa02_historical_receipt_binds_runtime": (
        "jaa02-identity-authentic",
        frozenset(),
        None,
    ),
    "test_unrelated_source_change_does_not_rewrite_historical_runtime_evidence": (
        "jaa02-identity-unrelated-source",
        frozenset({"internal/jaa/README.md"}),
        None,
    ),
    "test_jaa02_validator_rejects_missing_receipt": (
        "jaa02-identity-missing-receipt",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH}),
        inplace_fixture.JAA02_DELETE_RECEIPT_SEQUENCE,
    ),
    "test_jaa02_validator_rejects_malformed_receipt": (
        "jaa02-identity-malformed-receipt",
        frozenset({inplace_fixture.JAA02_REHASHED_RECEIPT_COMMIT}),
        inplace_fixture.JAA02_REHASHED_RECEIPT_COMMIT_SEQUENCE,
    ),
    "test_jaa02_validator_rejects_rehashed_runtime_identity_mismatch": (
        "jaa02-identity-forged-runtime",
        frozenset({inplace_fixture.JAA02_REHASHED_RECEIPT_COMMIT}),
        inplace_fixture.JAA02_REHASHED_RECEIPT_COMMIT_SEQUENCE,
    ),
}


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *arguments),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _validate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, VALIDATOR),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


@pytest.fixture()
def certified_repository(
    request: pytest.FixtureRequest,
) -> Iterator[tuple[Path, inplace_fixture._FixtureBranch]]:
    node_name = getattr(request.node, "originalname", request.node.name)
    scenario = _SCENARIOS.get(node_name)
    if scenario is None:
        pytest.exit(
            "this JAA-02 identity case has not been adapted to the admitted in-place fixture",
            returncode=2,
        )
    case, allowed, commit_sequence = scenario
    with inplace_fixture._committed_inplace_branch(
        case,
        allowed_mutations=allowed,
        commit_sequence=commit_sequence,
    ) as state:
        expected_receipt = Path(
            inplace_fixture.JAA02_INITIAL_RECEIPT_PATH
        ).relative_to("internal/jaa").as_posix()
        tracked_receipts = _git(
            ROOT, "ls-files", "runtime_evidence/jaa02/sha256-*.json"
        ).stdout.splitlines()
        assert tracked_receipts == [expected_receipt]
        assert _receipt(ROOT).relative_to(ROOT).as_posix() == expected_receipt
        yield ROOT, state


def _receipt(root: Path) -> Path:
    receipts = list((root / "runtime_evidence" / "jaa02").glob("sha256-*.json"))
    assert len(receipts) == 1
    return receipts[0]


def test_authentic_jaa02_historical_receipt_binds_runtime(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, _state = certified_repository
    accepted = _validate(repository_root)
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(accepted.stdout)["status"] == "accepted"


def test_unrelated_source_change_does_not_rewrite_historical_runtime_evidence(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    readme = repository_root / "README.md"
    inplace_fixture._commit_mutation(
        state,
        "internal/jaa/README.md",
        readme.read_text(encoding="utf-8") + "\nunrelated documentation\n",
        "unrelated documentation",
    )
    accepted = _validate(repository_root)
    assert accepted.returncode == 0, accepted.stderr


def test_jaa02_validator_rejects_missing_receipt(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    receipt = _receipt(repository_root)
    relative_receipt = receipt.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix()
    assert relative_receipt == inplace_fixture.JAA02_INITIAL_RECEIPT_PATH
    inplace_fixture._commit_deleted_file(
        state,
        relative_receipt,
        "remove checked JAA-02 historical receipt",
    )
    rejected = _validate(repository_root)
    assert rejected.returncode == 2
    assert "expected exactly one checked-in JAA-02 receipt, found 0" in rejected.stderr


def test_jaa02_validator_rejects_malformed_receipt(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    receipt = _receipt(repository_root)
    malformed = b"{ this is not valid JSON\n"
    replacement = receipt.with_name(f"sha256-{hashlib.sha256(malformed).hexdigest()}.json")
    inplace_fixture._commit_rehashed_receipt_replacement(
        state,
        replacement.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix(),
        malformed,
        "malformed-receipt",
    )

    rejected = _validate(repository_root)
    assert rejected.returncode == 2
    assert "invalid JAA-02 receipt JSON" in rejected.stderr


def test_jaa02_validator_rejects_rehashed_runtime_identity_mismatch(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    receipt = _receipt(repository_root)
    document = json.loads(receipt.read_text(encoding="utf-8"))
    runtime = document["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "0.0.0-forged-runtime"
    forged = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    replacement = receipt.with_name(f"sha256-{hashlib.sha256(forged).hexdigest()}.json")
    inplace_fixture._commit_rehashed_receipt_replacement(
        state,
        replacement.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix(),
        forged,
        "forged-runtime-identity",
    )

    rejected = _validate(repository_root)
    assert rejected.returncode == 2
    assert "JAA-02 runtime identity mismatch" in rejected.stderr
