"""Adversarial, independent certification tests for JAA-04 Increment A."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest
import test_jaa04_increment_a_certifier_fail_closed as inplace_fixture


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
CERTIFIER = inplace_fixture.CERTIFIER
INVENTORY = "scripts/jaa04_increment_a_test_inventory.json"
TEMPORAL_SUITE = "test_jaa04_sidecar_temporal_semantics.py"


def _run(
    directory: Path,
    *argv: str,
    timeout: int = 240,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=directory,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env=env,
    )


def _certify(
    tmp_path: Path,
    branch: str,
    head: str,
    *,
    env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    return inplace_fixture._certify(tmp_path, branch, head, env=env)


def _assert_rejected(
    tmp_path: Path,
    branch: str,
    head: str,
    *,
    env: dict[str, str] | None = None,
) -> None:
    result, receipt = _certify(tmp_path, branch, head, env=env)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "JAA-04 Increment A certification: ERROR:" in result.stderr
    assert not list(receipt.glob("sha256-*.json"))


def _outcome_environment(tmp_path: Path, outcome: str) -> dict[str, str]:
    module_name = f"ma_jaa04_outcome_{outcome}_{uuid.uuid4().hex}"
    plugin = tmp_path / f"{module_name}.py"
    plugin.write_text(
        f'''\
import pytest

MODE = {outcome!r}

def _target(item):
    return item.nodeid.startswith("test_jaa04_increment_a_authority_canaries.py::")

def pytest_collection_modifyitems(config, items):
    target = next(item for item in items if _target(item))
    if MODE == "xpassed":
        target.add_marker(pytest.mark.xfail(reason="independent xpass control"))
    elif MODE == "deselected":
        items.remove(target)
        config.hook.pytest_deselected(items=[target])

def pytest_runtest_setup(item):
    if _target(item) and MODE == "skipped":
        pytest.skip("independent skip control")

def pytest_runtest_call(item):
    if not _target(item):
        return
    if MODE == "xfailed":
        pytest.xfail("independent xfail control")
    if MODE == "failed":
        pytest.fail("independent failure control")
    if MODE == "error":
        raise RuntimeError("independent error control")
''',
        encoding="utf-8",
    )
    environment = os.environ.copy()
    existing_plugins = environment.get("PYTEST_PLUGINS", "")
    environment["PYTEST_PLUGINS"] = ",".join(
        value for value in (existing_plugins, module_name) if value
    )
    existing_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in (str(tmp_path), existing_pythonpath) if value
    )
    return environment


@pytest.mark.parametrize(
    "outcome", ("skipped", "xfailed", "xpassed", "failed", "error", "deselected")
)
def test_every_non_passing_pytest_outcome_reaches_and_is_rejected_by_certifier(
    tmp_path: Path, outcome: str
) -> None:
    """Inject one real pytest outcome without changing the pinned 47-suite bytes."""
    with inplace_fixture._committed_inplace_branch(
        f"independent-outcome-{outcome}", allowed_mutations=frozenset()
    ) as state:
        _assert_rejected(
            tmp_path,
            state.branch,
            state.head,
            env=_outcome_environment(tmp_path, outcome),
        )


def test_omitting_temporal_semantics_and_lowering_legacy_count_cannot_mint_success(
    tmp_path: Path,
) -> None:
    path = f"internal/jaa/{CERTIFIER}"
    with inplace_fixture._committed_inplace_branch(
        "independent-omitted-suite", allowed_mutations=frozenset({path})
    ) as state:
        certifier = ROOT / CERTIFIER
        source = certifier.read_text(encoding="utf-8")
        source = source.replace(f'    "{TEMPORAL_SUITE}",\n', "")
        changed = source.replace("EXPECTED_TESTS = 47", "EXPECTED_TESTS = 44")
        inplace_fixture._commit_mutation(state, path, changed, "independent-omitted-suite")
        _assert_rejected(tmp_path, state.branch, state.head)


@pytest.mark.parametrize("target", ("inventory", "source"))
def test_committed_inventory_and_canonical_suite_tampering_are_rejected(
    tmp_path: Path, target: str
) -> None:
    changed_path = (
        f"internal/jaa/{INVENTORY}"
        if target == "inventory"
        else f"internal/jaa/{TEMPORAL_SUITE}"
    )
    with inplace_fixture._committed_inplace_branch(
        f"independent-{target}-tamper", allowed_mutations=frozenset({changed_path})
    ) as state:
        path = ROOT / (INVENTORY if target == "inventory" else TEMPORAL_SUITE)
        if target == "inventory":
            changed = (path.read_bytes() + b"\n").decode("utf-8")
        else:
            changed = path.read_text(encoding="utf-8") + "\n# committed control\n"
        inplace_fixture._commit_mutation(
            state, changed_path, changed, f"independent-{target}-tamper"
        )
        _assert_rejected(tmp_path, state.branch, state.head)


def test_authentic_run_is_revision_bound_content_addressed_and_rejects_receipt_tampering(
    tmp_path: Path,
) -> None:
    with inplace_fixture._committed_inplace_branch(
        "independent-authentic-receipt", allowed_mutations=frozenset()
    ) as state:
        result, receipt_directory = _certify(tmp_path, state.branch, state.head)
        assert result.returncode == 0, result.stdout + result.stderr
        receipts = list(receipt_directory.glob("sha256-*.json"))
        assert len(receipts) == 1
        receipt = receipts[0]
        payload = receipt.read_bytes()
        document = json.loads(payload)
        assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
        assert document["status"] == "SUCCESS"
        assert document["source_revision"] == _run(
            REPOSITORY_ROOT, "git", "rev-parse", "HEAD"
        ).stdout.strip()
        tampered = payload + b"tampered"
        receipt.write_bytes(tampered)
        rejected, _ = _certify(tmp_path, state.branch, state.head)
        assert rejected.returncode != 0, rejected.stdout + rejected.stderr
        assert "JAA-04 Increment A certification: ERROR:" in rejected.stderr
        assert receipt.read_bytes() == tampered


def test_each_root_acceptance_declaration_is_executable_from_root_and_directly_when_supported(
    tmp_path: Path,
) -> None:
    """The declaration is data: extracted lines receive a root working directory."""
    # Root acceptance runs the complete pytest suite. Mark that child so this
    # test becomes a successful leaf instead of recursively invoking acceptance.
    if (
        os.environ.get("JAA04_ACCEPTANCE_DECLARATION_CHILD") == "1"
        or os.environ.get("AGENTIC_PROJECT_TEST_GATE_ACTIVE") == "1"
        or os.environ.get("AGENTIC_ACCEPTANCE_GATE_ACTIVE") == "1"
    ):
        return
    child_environment = os.environ.copy()
    child_environment["JAA04_ACCEPTANCE_DECLARATION_CHILD"] = "1"
    declaration = ROOT / "acceptance"
    commands = [
        line.strip()
        for line in declaration.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert commands
    for command in commands:
        extracted = _run(
            ROOT, "bash", "-c", command, timeout=900, env=child_environment
        )
        # Increment B's receipt is intentionally absent; a declaration may therefore
        # fail closed, but it must run rather than fail due to shell/path syntax.
        assert "No such file or directory" not in extracted.stderr
        direct = subprocess.run(
            [str(declaration)],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            check=False,
            timeout=900,
            env=child_environment,
        )
        assert direct.returncode == extracted.returncode
        assert "No such file or directory" not in direct.stderr
