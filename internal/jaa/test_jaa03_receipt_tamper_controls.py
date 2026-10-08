"""Independent black-box tamper controls for immutable JAA-03 runtime evidence."""

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
VALIDATOR = Path("scripts/accept_jaa03_receipt.py")


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, str(VALIDATOR)),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *argv),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _canonical(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


@pytest.fixture()
def certified_repository(
    request: pytest.FixtureRequest,
) -> Iterator[tuple[Path, inplace_fixture._FixtureBranch]]:
    node_name = getattr(request.node, "originalname", request.node.name)
    params = getattr(getattr(request.node, "callspec", None), "params", {})
    attack = params.get("attack")
    if node_name == "test_historical_receipt_acceptance_survives_a_later_source_revision":
        case = "jaa03-later-readme"
        allowed = {"internal/jaa/README.md"}
        sequence = inplace_fixture.JAA03_README_COMMIT_SEQUENCE
    elif node_name == "test_jaa03_rehashed_runtime_identity_substitution_fails_closed":
        case = "jaa03-runtime-identity"
        allowed = {inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT}
        sequence = inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT_SEQUENCE
    elif node_name == "test_jaa03_receipt_tampering_fails_closed" and attack == "byte_tamper":
        case = "jaa03-byte-tamper"
        allowed = {inplace_fixture.JAA03_INITIAL_RECEIPT_PATH}
        sequence = None
    elif node_name == "test_jaa03_receipt_tampering_fails_closed" and attack == "rehashed_result_tamper":
        case = "jaa03-result-tamper"
        allowed = {inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT}
        sequence = inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT_SEQUENCE
    else:
        pytest.exit("JAA-03 tamper case is not admitted by the in-place fixture", returncode=2)
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
        yield ROOT, state


def _replace_receipt(
    root: Path,
    state: inplace_fixture._FixtureBranch,
    document: dict[str, object],
    case: str,
) -> Path:
    evidence = root / "runtime_evidence" / "jaa03"
    originals = list(evidence.glob("sha256-*.json"))
    assert len(originals) == 1
    payload = _canonical(document)
    replacement = evidence / f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    inplace_fixture._commit_rehashed_receipt_replacement(
        state,
        replacement.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix(),
        payload,
        case,
        old_path=inplace_fixture.JAA03_INITIAL_RECEIPT_PATH,
        replacement_marker=inplace_fixture.JAA03_REHASHED_RECEIPT_COMMIT,
        receipt_marker=inplace_fixture.JAA03_RECEIPT_MUTATION,
    )
    return replacement


def test_historical_receipt_acceptance_survives_a_later_source_revision(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    accepted = _run(repository_root)
    assert accepted.returncode == 0, accepted.stderr
    readme = repository_root / "README.md"
    source_path = readme.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix()
    assert source_path == "internal/jaa/README.md"
    changed = (readme.read_bytes() + b"\nindependent source-revision drift\n").decode("utf-8")
    inplace_fixture._commit_mutation(
        state, source_path, changed, "later source revision"
    )
    accepted = _run(repository_root)
    assert accepted.returncode == 0, accepted.stderr


def test_jaa03_rehashed_runtime_identity_substitution_fails_closed(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
) -> None:
    repository_root, state = certified_repository
    receipt = next(
        (repository_root / "runtime_evidence" / "jaa03").glob("sha256-*.json")
    )
    document = json.loads(receipt.read_text(encoding="utf-8"))
    runtime = document["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "0.0.0-attacker"
    _replace_receipt(repository_root, state, document, "runtime identity substitution")
    rejected = _run(repository_root)
    assert rejected.returncode != 0, rejected.stdout


@pytest.mark.parametrize("attack", ["byte_tamper", "rehashed_result_tamper"])
def test_jaa03_receipt_tampering_fails_closed(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
    attack: str,
) -> None:
    repository_root, state = certified_repository
    receipt = next(
        (repository_root / "runtime_evidence" / "jaa03").glob("sha256-*.json")
    )
    if attack == "byte_tamper":
        receipt_path = receipt.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix()
        original = receipt.read_bytes()
        with inplace_fixture._temporarily_dirty_tracked_path_on_branch(
            state, receipt_path, b" "
        ) as tampered:
            rejected = _run(repository_root)
            assert tampered.read_bytes() == original + b" "
        assert receipt.read_bytes() == original
    else:
        document = json.loads(receipt.read_text(encoding="utf-8"))
        result = document["acceptance_result"]
        assert isinstance(result, dict)
        result["metrics_hash"] = "sha256:" + "0" * 64
        _replace_receipt(repository_root, state, document, "rehashed result tampering")
        rejected = _run(repository_root)
    assert rejected.returncode != 0, rejected.stdout
