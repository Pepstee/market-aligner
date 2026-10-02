"""Black-box JAA-04 certifier checks using the admitted in-place fixture."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterator

import pytest

from test_jaa04_increment_a_certifier_fail_closed import (
    BASE_BRANCH,
    _abort_suite,
    _assert_admission,
    _certify as certify_in_place,
    _commit_added_file,
    _commit_deleted_file,
    _commit_mutation,
    _committed_inplace_branch,
    _git_blob_sha256,
    _rejects,
    _uncommitted_control_file,
)


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
CANARY_DIRECTORY = "internal/jaa/career_automation/fixtures/jaa04_authority_canaries"
GREENHOUSE_PATH = f"{CANARY_DIRECTORY}/greenhouse.json"
ASHBY_PATH = f"{CANARY_DIRECTORY}/ashby.json"
UNEXPECTED_CANARY_PATH = f"{CANARY_DIRECTORY}/unexpected.json"
DIRTY_CONTROL_PATH = "internal/jaa/career_automation/dirty-certifier-control.txt"
FOCUSED_SUITES = (
    "test_jaa04_increment_a_authority_canaries.py",
    "test_jaa04_increment_a_temporal_authority_regression.py",
    "test_jaa04_sidecar_temporal_semantics.py",
    "test_jaa04_portable_authority_contract.py",
)


def _run(directory: Path, *argv: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=directory, text=True, capture_output=True,
                          check=False, timeout=timeout)


def _assert_rejected_without_receipt(
    result: subprocess.CompletedProcess[str],
    receipt_directory: Path,
) -> None:
    assert result.returncode != 0
    assert "JAA-04 Increment A certification: ERROR:" in result.stderr
    assert not receipt_directory.exists() or not list(receipt_directory.glob("sha256-*.json"))


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def _mutated_canary_content(mutate: Callable[[dict[str, object]], None]) -> str:
    path = REPOSITORY_ROOT / GREENHOUSE_PATH
    if not path.is_file() or path.is_symlink():
        _abort_suite("admitted Greenhouse canary is not a regular file")
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    return _canonical(document).decode("utf-8")


@pytest.fixture(autouse=True)
def _admit_certification_surface() -> Iterator[None]:
    base_head = os.environ.get("MA_JAA04_INPLACE_BASE_HEAD", "")
    try:
        _assert_admission(BASE_BRANCH, base_head, False)
    except pytest.exit.Exception:
        raise
    except Exception:
        _abort_suite("certification-surface admission failed at test start")
    yield
    try:
        _assert_admission(BASE_BRANCH, base_head, False)
    except pytest.exit.Exception:
        raise
    except Exception:
        _abort_suite("certification-surface admission failed at test completion; preserving state")


def test_current_temporal_contract_and_focused_suites_pass_in_clean_canon() -> None:
    result = _run(
        ROOT,
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "test_jaa04_increment_a_temporal_provenance_certification.py",
        *FOCUSED_SUITES,
        timeout=360,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_clean_certifier_emits_one_content_addressed_revision_bound_receipt_and_pass_marker(
    tmp_path: Path,
) -> None:
    base_head = os.environ["MA_JAA04_INPLACE_BASE_HEAD"]
    result, receipt_directory = certify_in_place(tmp_path, BASE_BRANCH, base_head)
    assert result.returncode == 0, result.stderr
    receipts = list(receipt_directory.glob("sha256-*.json"))
    assert len(receipts) == 1
    payload = receipts[0].read_bytes()
    document = json.loads(payload)
    assert receipts[0].name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert document["status"] == "SUCCESS"
    assert document["source_revision"] == base_head
    assert document["executed_suite_results"]
    assert {row["suite"] for row in document["executed_suite_results"]} == set(FOCUSED_SUITES)
    assert "JAA-04 Increment A certification: PASS" in result.stdout


@pytest.mark.parametrize("attack", (
    "embedded-byte-tampering",
    "digest-mismatch",
    "reference-mismatch",
    "timestamp-field-substitution",
    "sidecar-body-disagreement",
))
def test_committed_canary_tampering_fails_closed_and_suppresses_receipt(
    tmp_path: Path,
    attack: str,
) -> None:
    with _committed_inplace_branch(
        "surface-canary-tamper",
        allowed_mutations={GREENHOUSE_PATH},
    ) as state:
        def mutate(document: dict[str, object]) -> None:
            row = document["captures"][0]  # type: ignore[index]
            assert isinstance(row, dict)
            if attack == "embedded-byte-tampering":
                raw = base64.b64decode(row["raw_response_base64"])
                row["raw_response_base64"] = base64.b64encode(raw + b" ").decode("ascii")
            elif attack == "digest-mismatch":
                row["content_sha256"] = "0" * 64
            elif attack == "reference-mismatch":
                row["sidecar_raw_response_ref"] = "sha256/00/" + "0" * 64
            elif attack == "timestamp-field-substitution":
                row["published_at"], row["updated_at"] = row.get("updated_at"), row.get("published_at")
            else:
                raw = base64.b64decode(row["raw_response_base64"])
                row["content_sha256"] = hashlib.sha256(raw + b"different sidecar body").hexdigest()
                row["sidecar_raw_response_ref"] = (
                    "sha256/" + row["content_sha256"][:2] + "/" + row["content_sha256"]
                )

        _commit_mutation(
            state,
            GREENHOUSE_PATH,
            _mutated_canary_content(mutate),
            attack,
        )
        _rejects(tmp_path, state.branch, state.head)


@pytest.mark.parametrize("attack", ("missing", "extra"))
def test_canary_cardinality_controls_fail_closed_and_suppress_receipt(
    tmp_path: Path,
    attack: str,
) -> None:
    if attack == "missing":
        mutation_path = ASHBY_PATH
    else:
        mutation_path = UNEXPECTED_CANARY_PATH
    with _committed_inplace_branch(
        f"surface-canary-{attack}",
        allowed_mutations={mutation_path},
    ) as state:
        if attack == "missing":
            _commit_deleted_file(state, ASHBY_PATH, "missing-canary")
        else:
            greenhouse = REPOSITORY_ROOT / GREENHOUSE_PATH
            original = greenhouse.read_bytes()
            expected = _git_blob_sha256(f"{state.base_head}:{GREENHOUSE_PATH}")
            if hashlib.sha256(original).hexdigest() != expected:
                _abort_suite("duplicate-canary source bytes differ from the admitted base blob")
            _commit_added_file(state, UNEXPECTED_CANARY_PATH, original, "extra-canary")
        _rejects(tmp_path, state.branch, state.head)


def test_dirty_source_state_fails_closed_and_suppresses_receipt(tmp_path: Path) -> None:
    with _committed_inplace_branch(
        "surface-dirty-marker",
        allowed_mutations={DIRTY_CONTROL_PATH},
    ) as state:
        with _uncommitted_control_file(state, DIRTY_CONTROL_PATH, b"uncommitted\n"):
            result, receipt_directory = certify_in_place(
                tmp_path,
                state.branch,
                state.head,
                expected_dirty=True,
            )
            assert result.returncode != 0
            assert "JAA-04 Increment A certification: ERROR:" in result.stderr
            assert not receipt_directory.exists() or not list(receipt_directory.glob("sha256-*.json"))


def test_failed_focused_suite_suppresses_receipt(tmp_path: Path) -> None:
    plugin_directory = tmp_path / "pytest-plugins"
    plugin_directory.mkdir(mode=0o700)
    plugin_path = plugin_directory / "ma_certifier_failure_plugin.py"
    plugin_path.write_text(
        "import pytest\n"
        "_failed = False\n"
        "def pytest_runtest_call(item):\n"
        "    global _failed\n"
        "    if not _failed and item.nodeid.startswith(\n"
        "        'test_jaa04_increment_a_authority_canaries.py::'\n"
        "    ):\n"
        "        _failed = True\n"
        "        pytest.fail('synthetic certifier suite failure')\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(plugin_directory), existing_pythonpath) if item
    )
    environment["PYTEST_ADDOPTS"] = "-p ma_certifier_failure_plugin"
    base_head = environment["MA_JAA04_INPLACE_BASE_HEAD"]
    result, receipt_directory = certify_in_place(
        tmp_path,
        BASE_BRANCH,
        base_head,
        env=environment,
    )
    _assert_rejected_without_receipt(result, receipt_directory)


def test_full_jaa04_gate_fails_closed_without_external_capture_and_policy(tmp_path: Path) -> None:
    manifest = json.loads((ROOT / "ASSURANCE_MANIFEST.json").read_text(encoding="utf-8"))
    corpus = next(
        row for row in manifest["components"]["JAA-04"]["evidence"]
        if row["scope"] == "JAA-04-corpus"
    )
    assert corpus["argv"] == [
        "{python}",
        "scripts/accept_jaa_04.py",
        "--capture",
        "{external_jaa04_corpus}",
        "--access-policy",
        "{external_jaa04_access_policy}",
        "--receipt",
        "{external_jaa04_receipts}",
    ]
    receipt = tmp_path / "receipt"
    absent = tmp_path / "deliberately-absent-external-input.json"
    assert not receipt.exists() and not absent.exists()
    for supplied, required in (
        (("--capture", str(absent)), "--access-policy"),
        (("--access-policy", str(absent)), "--capture"),
        (("--capture", str(absent), "--access-policy", str(absent)), "--receipt"),
    ):
        receipt_args = () if required == "--receipt" else ("--receipt", str(receipt))
        result = _run(
            ROOT,
            sys.executable,
            "scripts/accept_jaa_04.py",
            *supplied,
            *receipt_args,
        )
        assert result.returncode != 0
        assert required in result.stderr
        assert "PASS" not in result.stdout
        assert not receipt.exists()
