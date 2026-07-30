"""Positive controls for the bounded network-witnessed browser fixture."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

import career_automation.linux_network_namespace_witness as witness_module
import career_automation.network_witnessed_fixture as fixture_module
from career_automation.linux_network_namespace_witness import (
    AF_UNIX_PATH_CAPACITY,
    CHROMIUM_RUNTIME_TMP_SUFFIX_BYTES,
    RUNTIME_TMP_ROOT_MAX_BYTES,
    SCHEMA_VERSION,
    NetworkNamespaceWitnessReceipt,
)
from career_automation.network_witnessed_fixture import (
    COMPOSITE_SCHEMA_VERSION,
    LIMITATIONS,
    STRONGEST_CLAIM,
    NetworkWitnessedFixtureObservationReceipt,
    run_network_witnessed_fixture,
)


ROOT = Path(__file__).resolve().parent
DESIGN_BASE = "01c4417c0301d69c2303f8f2d585acd6ede9a74c"
ALLOWLIST = {
    "career_automation/linux_network_namespace_witness.py",
    "career_automation/network_witnessed_fixture.py",
    "test_jaa10_linux_network_namespace_witness.py",
    "test_jaa10_linux_network_namespace_witness_negative_controls.py",
    "test_jaa10_network_witnessed_fixture.py",
    "test_jaa10_network_witnessed_fixture_negative_controls.py",
}


def _chromium() -> Path:
    values = sorted(
        Path("/home/gutua/.cache/ms-playwright").glob(
            "chromium-*/chrome-linux64/chrome"
        )
    )
    if len(values) != 1:
        raise AssertionError("exactly one pinned Playwright Chromium is required")
    return values[0].resolve(strict=True)


@pytest.fixture(scope="module")
def accepted_integration(tmp_path_factory: pytest.TempPathFactory):
    before_bytecode = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.name == "__pycache__" or path.suffix == ".pyc"
    }
    anchor_token = hashlib.sha256(
        os.fsencode(tmp_path_factory.getbasetemp())
    ).hexdigest()[:5]
    test_anchor = Path("/tmp") / f"j{anchor_token}"
    assert len(os.fsencode(test_anchor)) <= 11
    assert not test_anchor.exists()
    assert not test_anchor.is_symlink()
    test_anchor.mkdir(mode=0o700)
    assert stat.S_IMODE(test_anchor.stat().st_mode) == 0o700
    production_before = tuple(
        (
            path.name,
            path.lstat().st_dev,
            path.lstat().st_ino,
            path.lstat().st_mode,
            path.lstat().st_size,
        )
        for path in sorted(Path("/home/gutua").glob(".jaa10rt-*"))
    )
    patcher = pytest.MonkeyPatch()
    patcher.setattr(
        witness_module,
        "RUNTIME_TMP_HOME_ANCHOR",
        test_anchor,
    )
    real_witness_call = witness_module.run_isolated_network_witness
    delegated_argv: list[tuple[tuple[str, ...], tuple[str, ...], str]] = []

    def test_witness_delegate(
        command,
        **keywords,
    ):
        incoming = tuple(str(value) for value in command)
        assert len(incoming) == 6
        assert incoming[1:4] == (
            "-m",
            "career_automation.network_witnessed_fixture",
            "--worker",
        )
        bootstrap = (
            "from pathlib import Path;"
            "import runpy;"
            "import career_automation.linux_network_namespace_witness as w;"
            f"w.RUNTIME_TMP_HOME_ANCHOR=Path({str(test_anchor)!r});"
            "runpy.run_module("
            "'career_automation.network_witnessed_fixture',"
            "run_name='__main__')"
        )
        assert str(test_anchor) in bootstrap
        assert "/home/gutua" not in bootstrap
        assert "environ" not in bootstrap
        assert "getenv" not in bootstrap
        wrapped = (
            incoming[0],
            "-c",
            bootstrap,
            *incoming[3:],
        )
        assert wrapped[3:] == incoming[3:]
        delegated_argv.append((incoming, wrapped, bootstrap))
        return real_witness_call(wrapped, **keywords)

    patcher.setattr(
        fixture_module,
        "run_isolated_network_witness",
        test_witness_delegate,
    )
    execution_root = (
        tmp_path_factory.mktemp("network-witnessed-browser") / "execution"
    )
    try:
        receipt, witness, network_receipt = run_network_witnessed_fixture(
            repository_root=ROOT,
            execution_root=execution_root,
            python_executable=ROOT / ".venv/bin/python",
            chromium_executable=_chromium(),
            timeout_seconds=240,
        )
        after_bytecode = {
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.name == "__pycache__" or path.suffix == ".pyc"
        }
        assert after_bytecode == before_bytecode
        assert not any(
            path.name == "__pycache__" or path.suffix == ".pyc"
            for path in execution_root.rglob("*")
        )
        assert len(delegated_argv) == 1
        yield execution_root, receipt, witness, network_receipt
    finally:
        production_after = tuple(
            (
                path.name,
                path.lstat().st_dev,
                path.lstat().st_ino,
                path.lstat().st_mode,
                path.lstat().st_size,
            )
            for path in sorted(Path("/home/gutua").glob(".jaa10rt-*"))
        )
        assert production_after == production_before
        patcher.undo()


def test_complete_fixture_flow_is_mutually_bound_and_noncertifying(
    accepted_integration,
) -> None:
    execution_root, receipt, witness, network_receipt = accepted_integration
    document = receipt.document()
    controls = witness.document()["cooperative_browser_controls"]

    assert isinstance(receipt, NetworkWitnessedFixtureObservationReceipt)
    assert isinstance(network_receipt, NetworkNamespaceWitnessReceipt)
    assert document["schema_version"] == COMPOSITE_SCHEMA_VERSION
    assert witness.document()["schema_version"] == SCHEMA_VERSION
    assert document["integration_status"] == (
        "network_witnessed_local_fixture_single_execution"
    )
    assert document["worker_result_sha256"] == (
        controls["worker_result_sha256"]
    )
    assert document["request_sha256"] == controls["request_sha256"]
    assert document["integration_nonce_sha256"] == (
        controls["integration_nonce_sha256"]
    )
    assert document["cooperative_policy_sha256"] == (
        controls["cooperative_policy_sha256"]
    )
    assert document["runtime_tmp_root"] == controls["runtime_tmp_root"]
    assert document["runtime_tmp_root_derivation"] == (
        controls["runtime_tmp_root_derivation"]
    )
    assert document["socket_budget"] == controls["socket_budget"]
    runtime_tmp_root = Path(document["runtime_tmp_root"])
    assert runtime_tmp_root.is_dir()
    assert not runtime_tmp_root.is_symlink()
    assert stat.S_IMODE(runtime_tmp_root.stat().st_mode) == 0o700
    assert runtime_tmp_root.parent != Path("/home/gutua")
    assert runtime_tmp_root.parent.name.startswith("j")
    assert len(os.fsencode(runtime_tmp_root.parent)) <= 11
    assert __import__("re").fullmatch(
        r"\.jaa10rt-[0-9a-f]{16}",
        runtime_tmp_root.name,
    )
    assert document["socket_budget"]["observed_root_bytes"] == len(
        os.fsencode(runtime_tmp_root)
    )
    assert document["socket_budget"]["observed_total_bytes"] == (
        len(os.fsencode(runtime_tmp_root))
        + CHROMIUM_RUNTIME_TMP_SUFFIX_BYTES
    )
    assert (
        document["socket_budget"]["observed_total_bytes"]
        <= AF_UNIX_PATH_CAPACITY
    )
    assert RUNTIME_TMP_ROOT_MAX_BYTES == 62
    assert document["network_witness_sha256"] == witness.witness_sha256
    assert document["network_receipt_sha256"] == (
        network_receipt.receipt_sha256
    )
    assert document["strongest_claim"] == STRONGEST_CLAIM
    assert tuple(document["limitations"]) == LIMITATIONS
    assert document["evidence_kind"] == "synthetic_shadow"
    assert document["execution_claim"] == "structural_lineage_only"
    assert document["objective_satisfied"] is False
    assert document["certifies_slice"] is False
    assert document["external_actions"] == 0
    assert document["real_applications_submitted"] == 0
    assert (execution_root / "composite-receipt.json").read_bytes() == (
        receipt.canonical_document
    )


def test_worker_browser_and_kernel_artifact_inventory_is_complete(
    accepted_integration,
) -> None:
    execution_root, receipt, witness, _network_receipt = accepted_integration
    document = receipt.document()
    relative_paths = {
        row["relative_path"] for row in document["component_inventory"]
    }
    required = {
        "integration-request.json",
        "worker-output/worker-result.json",
        "worker-output/workflow.sqlite3",
        "worker-output/screenshot.png",
        "worker-output/fixture-receipt.json",
        "worker-output/submission-proof.json",
        "worker-output/normalized-submit-event.json",
        "worker-output/durable-submit-event.json",
        "worker-output/browser-launch-receipt.json",
        "worker-output/browser-runtime-identities.json",
        "network-evidence/network-witness.json",
        "network-evidence/network-witness-receipt.json",
        "network-evidence/command.stdout.log",
        "network-evidence/command.stderr.log",
        "reconstruction.json",
    }
    assert required <= relative_paths
    for row in document["component_inventory"]:
        path = execution_root / row["relative_path"]
        assert path.is_file()
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
    result = json.loads(
        (execution_root / "worker-output/worker-result.json").read_bytes()
    )
    assert result["fixture_receipt"]["receipt_id"] == (
        result["submission_proof"]["receipt_id"]
    )
    assert result["observation"]["submission_proof"] == (
        result["submission_proof"]
    )
    assert result["observation"]["fixture_receipt"] == (
        result["fixture_receipt"]
    )
    finalization = result["worker_database_finalization"]
    assert finalization["journal_mode"] == "wal"
    assert finalization["checkpoint_mode"] == "truncate"
    assert finalization["busy"] == 0
    assert finalization["log_frames"] == (
        finalization["checkpointed_frames"]
    )
    assert not (execution_root / "worker-output/workflow.sqlite3-wal").exists()
    assert not (execution_root / "worker-output/workflow.sqlite3-shm").exists()
    inventory_by_path = {
        row["relative_path"]: row
        for row in result["artifact_inventory"]
    }
    assert "workflow.sqlite3-wal" not in inventory_by_path
    assert "workflow.sqlite3-shm" not in inventory_by_path
    database = execution_root / "worker-output/workflow.sqlite3"
    assert inventory_by_path["workflow.sqlite3"]["sha256"] == (
        hashlib.sha256(database.read_bytes()).hexdigest()
    )
    launch = json.loads(
        (
            execution_root
            / "worker-output/browser-launch-receipt.json"
        ).read_bytes()
    )
    assert launch["sandbox_truth"] == (
        "disabled_by_playwright_in_user_namespace"
    )
    assert launch["main_process"]["executable"] == str(_chromium())
    assert witness.document()["inherited_socket_count"] == 0
    assert witness.document()["post_execution_socket_count"] == 0


def test_integration_diff_is_confined_to_exact_fable_allowlist() -> None:
    changed = set(
        subprocess.run(
            ["git", "diff", "--name-only", DESIGN_BASE],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    )
    assert changed == ALLOWLIST
    assert "ASSURANCE_MANIFEST.json" not in changed
    assert "test_assurance_manifest_truth.py" not in changed


def test_old_cohort_surfaces_do_not_accept_composite_type(
    accepted_integration,
) -> None:
    _execution_root, receipt, _witness, _network_receipt = accepted_integration
    for relative in (
        "career_automation/shadow_observation_ledger.py",
        "career_automation/shadow_fixture_measures.py",
        "career_automation/shadow_elapsed_cohort.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "NetworkWitnessedFixtureObservationReceipt" not in source
        assert receipt.document()["schema_version"] not in source
    assert os.environ.get("TMPDIR") != str(
        Path(receipt.document()["runtime_tmp_root"])
    )
    assert not (accepted_integration[0] / "integration-tmp").exists()
