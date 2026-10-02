"""Black-box controls for the non-self-invalidating JAA-03 evidence validator."""

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
VALIDATOR = "scripts/accept_jaa03_receipt.py"


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *arguments), cwd=root, text=True, capture_output=True, check=False
    )


def _validate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, VALIDATOR),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.fixture()
def certified_repository(
    request: pytest.FixtureRequest,
) -> Iterator[tuple[Path, inplace_fixture._FixtureBranch]]:
    node_name = getattr(request.node, "originalname", request.node.name)
    if node_name == "test_authentic_historical_receipt_and_unrelated_change_remain_valid":
        case = "jaa03-historical-readme"
        allowed = {"internal/jaa/README.md"}
        sequence = inplace_fixture.JAA03_README_COMMIT_SEQUENCE
    elif node_name == "test_rehashed_runtime_substitution_is_rejected":
        case = "jaa03-rehashed-runtime"
        allowed = {inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT}
        sequence = inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT_SEQUENCE
    else:
        pytest.exit("JAA-03 receipt case is not admitted by the in-place fixture", returncode=2)
    with inplace_fixture._committed_inplace_branch(
        case,
        allowed_mutations=allowed,
        commit_sequence=sequence,
    ) as state:
        expected = Path(inplace_fixture.JAA03_INITIAL_RECEIPT_PATH).relative_to(
            "internal/jaa"
        ).as_posix()
        tracked = _git(ROOT, "ls-files", "runtime_evidence/jaa03/sha256-*.json")
        assert tracked.returncode == 0
        assert tracked.stdout.splitlines() == [expected]
        assert _receipt(ROOT).relative_to(ROOT).as_posix() == expected
        yield ROOT, state


def _receipt(root: Path) -> Path:
    receipts = list((root / "runtime_evidence" / "jaa03").glob("sha256-*.json"))
    assert len(receipts) == 1
    return receipts[0]


def test_authentic_historical_receipt_and_unrelated_change_remain_valid(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    assert _validate(repository_root).returncode == 0
    readme = repository_root / "README.md"
    source_path = readme.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix()
    assert source_path == "internal/jaa/README.md"
    inplace_fixture._commit_mutation(
        state,
        source_path,
        readme.read_text(encoding="utf-8") + "\nunrelated docs\n",
        "unrelated docs",
    )
    accepted = _validate(repository_root)
    assert accepted.returncode == 0, accepted.stderr


def test_rehashed_runtime_substitution_is_rejected(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    receipt = _receipt(repository_root)
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["runtime"]["python_version"] = "0.0.0-forged"
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    replacement = receipt.with_name(
        f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    )
    inplace_fixture._commit_rehashed_receipt_replacement(
        state,
        replacement.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix(),
        payload,
        "forge runtime",
        old_path=inplace_fixture.JAA03_INITIAL_RECEIPT_PATH,
        replacement_marker=inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT,
        receipt_marker=inplace_fixture.JAA03_RECEIPT_MUTATION,
    )
    rejected = _validate(repository_root)
    assert rejected.returncode == 2
    assert "runtime identity mismatch" in rejected.stderr
