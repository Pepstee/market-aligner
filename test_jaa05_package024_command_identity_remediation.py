"""Package 024 offline command-identity remediation controls."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from career_automation.holdout_firewall import load_quarantine_bundle
from career_automation.official_cohort import build


ROOT = Path(__file__).resolve().parent
CONTROL = Path(
    "/home/gutua/software-factory/.control/resumed-dual-lane-20260728/"
    "jaa/jaa05-next-cycle"
)
BUILDER = CONTROL / "package-024-build-command-identity-remediation.py"
AMENDMENT = (
    CONTROL
    / "package-024-command-identity-remediation.json.canary-amendment"
)
CONTRACT = CONTROL / "package-022-liveness-canary-contract.json.canary-contract"
PACKAGE023_AMENDMENT = (
    CONTROL / "package-023-canary-execution-amendment.json.canary-amendment"
)
PACKAGE023_RECEIPT = CONTROL / "package-023-receipt-d98506a.json.receipt"
VOID_ACTIVATION = CONTROL / "fable-package-023-return-raw.json.ruling"
PREFLIGHT_LOG = CONTROL / "package-023-activation-preflight-failure.log"
PREFLIGHT_RECEIPT = (
    CONTROL
    / "package-023-activation-preflight-failure.json.failure-receipt"
)
DISPOSITION = (
    CONTROL
    / "fable-package-023-preflight-failure-disposition-raw.json.ruling"
)
BUNDLE = CONTROL / "combined-quarantine-bundle.json"
EXECUTOR = ROOT / "scripts/run_jaa05_liveness_canary.py"
POLICY = Path(
    "/home/gutua/software-factory/.control/jaa-12h-supervisor-20260727/"
    "runtime/recruitee-authority-provenance-v1/"
    "public-access-policy-17-host-v2.json"
)
BUILDER_SHA256 = hashlib.sha256(BUILDER.read_bytes()).hexdigest()
AMENDMENT_SHA256 = hashlib.sha256(AMENDMENT.read_bytes()).hexdigest()
EXECUTOR_SHA256 = "a2e6b3d6c29ad4cb1e012e1ec90752f88595f965fbe8ff5fba9c82c701657daf"
CONTRACT_SHA256 = "c43fd61eee5b950f9a9e80fcfe60fa9008f582c31b265685e440485b06f34323"
PACKAGE023_AMENDMENT_SHA256 = (
    "35a8ae8ca6b1adb6d30dea717e77bfd3c1d77ff24495122f807dabf0bd340fcf"
)
BUNDLE_SHA256 = "ad380445efd62019fe970ee1d775e48a5e5f58639bd385823e31780547f1a6c4"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _head() -> str:
    return subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _tree() -> str:
    return subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    return _load_module("package024_builder", BUILDER)


@pytest.fixture(scope="module")
def runner() -> ModuleType:
    return _load_module("package024_runner", EXECUTOR)


@pytest.fixture(scope="module")
def amendment(builder: ModuleType) -> dict:
    return builder.validate_amendment(
        AMENDMENT,
        AMENDMENT_SHA256,
        rerun=True,
    )


def test_frozen_builder_amendment_and_executor_bind_exactly() -> None:
    assert _sha256(BUILDER) == BUILDER_SHA256
    assert _sha256(AMENDMENT) == AMENDMENT_SHA256
    assert _sha256(EXECUTOR) == EXECUTOR_SHA256
    assert BUILDER.stat().st_mode & 0o777 == 0o444
    assert AMENDMENT.stat().st_mode & 0o777 == 0o444


def test_amendment_is_canonical_deterministic_and_current(
    builder: ModuleType,
    amendment: dict,
) -> None:
    assert amendment["schema_version"] == (
        "jaa05.package024-command-identity-remediation.v1"
    )
    assert builder.canonical_json(builder.build_amendment()) == AMENDMENT.read_bytes()
    assert builder.canonical_json(builder.build_amendment()) == AMENDMENT.read_bytes()
    assert amendment["authority"]["source_commit"] == _head()
    assert amendment["authority"]["source_tree"] == _tree()
    assert amendment["future_executor"]["sha256"] == EXECUTOR_SHA256


def test_package023_failure_and_disposition_are_exactly_bound(
    amendment: dict,
) -> None:
    authority = amendment["authority"]
    assert amendment["predecessor_amendment_sha256"] == (
        PACKAGE023_AMENDMENT_SHA256
    )
    assert authority["package_023_receipt_sha256"] == _sha256(PACKAGE023_RECEIPT)
    assert authority["void_activation_wrapper_sha256"] == _sha256(
        VOID_ACTIVATION
    )
    assert authority["preflight_failure_log_sha256"] == _sha256(PREFLIGHT_LOG)
    assert authority["preflight_failure_receipt_sha256"] == _sha256(
        PREFLIGHT_RECEIPT
    )
    assert authority["package_024_disposition_sha256"] == _sha256(DISPOSITION)
    failure = json.loads(PREFLIGHT_RECEIPT.read_bytes())
    assert failure["network_requests"] == 0
    assert failure["command_executed"] is False
    assert failure["activation_consumed"] is False
    result = json.loads(DISPOSITION.read_bytes())["result"]
    assert "EXACTLY_ONE_BOUNDED_OFFLINE_ONLY_REMEDIATION_PACKAGE" in result
    assert '"live_authority_granted_by_this_ruling": false' in result


def test_remediation_preserves_invoked_absolute_symlink_spelling(
    runner: ModuleType,
    amendment: dict,
) -> None:
    python = str(ROOT / ".venv/bin/python")
    first = runner._runtime_argv(["--offline"], executable=python)
    second = runner._runtime_argv(["--offline"], executable=python)
    assert first == second
    assert first[0] == python
    assert first[0] != str(Path(python).resolve())
    remediation = amendment["command_identity_remediation"]
    assert remediation["required_runtime_interpreter_identity"] == python
    assert remediation["scope"] == "interpreter argv spelling only"
    assert remediation["resolved_interpreter_substitution_permitted"] is False
    assert "absolute()" in remediation["implementation"]


def test_changed_interpreter_path_changes_command_digest(
    runner: ModuleType,
) -> None:
    arguments = ["--activation-sha256", "1" * 64]
    frozen = runner._runtime_argv(
        arguments,
        executable=str(ROOT / ".venv/bin/python"),
    )
    changed = runner._runtime_argv(
        arguments,
        executable="/different/python",
    )
    assert runner._command_identity(frozen) != runner._command_identity(changed)


def _instantiated_argv(amendment: dict, *, activation_path: Path) -> list[str]:
    replacements = {
        "{PACKAGE_024_AMENDMENT_SHA256}": AMENDMENT_SHA256,
        "{FABLE_ACTIVATION_RULING_PATH}": str(activation_path),
        "{FABLE_ACTIVATION_RULING_SHA256}": "1" * 64,
    }
    return [
        replacements.get(value, value)
        for value in amendment["future_executor"]["command_argv_template"]
    ]


def _activation(
    runner: ModuleType,
    *,
    command_sha256: str,
    amendment_sha256: str = AMENDMENT_SHA256,
) -> dict:
    return {
        "ruling_id": "synthetic-package024-offline-activation-shape",
        "verdict": "AUTHORISE_LIVE_CANARY_ONCE",
        "source_commit": _head(),
        "contract_sha256": CONTRACT_SHA256,
        "amendment_sha256": amendment_sha256,
        "policy_sha256": runner.POLICY_SHA256,
        "quarantine_sha256": BUNDLE_SHA256,
        "command_sha256": command_sha256,
        "maximum_content_gets": 9,
        "maximum_robots_gets": 2,
        "maximum_total_network_sends": 11,
        "retry_count": 0,
        "resume_permitted": False,
        "frozen_input_permitted": False,
    }


def test_exact_future_argv_passes_offline_activation_validator(
    runner: ModuleType,
    amendment: dict,
    tmp_path: Path,
) -> None:
    activation_path = tmp_path / "future-fable-wrapper.json"
    template = _instantiated_argv(amendment, activation_path=activation_path)
    runtime = runner._runtime_argv(template[2:], executable=template[0])
    assert runtime == template
    command_sha = runner._command_identity(runtime)
    ruling = _activation(runner, command_sha256=command_sha)
    wrapper = {"result": f"```json\n{json.dumps(ruling)}\n```"}
    assert runner._validate_activation(
        wrapper,
        wrapper_sha256="1" * 64,
        amendment_sha256=AMENDMENT_SHA256,
        source_commit=_head(),
        command_sha256=command_sha,
    ) == ruling


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command_sha256", "0" * 64),
        ("maximum_total_network_sends", 12),
        ("retry_count", 1),
        ("resume_permitted", True),
        ("frozen_input_permitted", True),
    ],
)
def test_tampered_activation_is_rejected(
    runner: ModuleType,
    amendment: dict,
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    runtime = _instantiated_argv(
        amendment,
        activation_path=tmp_path / "ruling.json",
    )
    command_sha = runner._command_identity(runtime)
    ruling = _activation(runner, command_sha256=command_sha)
    ruling[field] = value
    wrapper = {"result": f"```json\n{json.dumps(ruling)}\n```"}
    with pytest.raises(runner.LivenessCanaryFailure, match=field):
        runner._validate_activation(
            wrapper,
            wrapper_sha256="1" * 64,
            amendment_sha256=AMENDMENT_SHA256,
            source_commit=_head(),
            command_sha256=command_sha,
        )


def test_wrong_command_authority_fails_before_client_and_workspace(
    runner: ModuleType,
    amendment: dict,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    def forbidden_client(*_args: object, **_kwargs: object) -> None:
        nonlocal constructed
        constructed = True
        raise AssertionError("client must not be constructed")

    monkeypatch.setattr(runner, "ScraplingClient", forbidden_client)
    paths = [
        tmp_path / "workspace",
        tmp_path / "success",
        tmp_path / "failure",
    ]
    cli = _instantiated_argv(
        amendment,
        activation_path=tmp_path / "activation.json",
    )[2:]
    runtime = runner._runtime_argv(
        cli,
        executable=str(ROOT / ".venv/bin/python"),
    )
    ruling = _activation(runner, command_sha256="0" * 64)
    wrapper_path = tmp_path / "activation.json"
    wrapper_path.write_text(
        json.dumps({"result": f"```json\n{json.dumps(ruling)}\n```"}) + "\n"
    )
    wrapper_sha = _sha256(wrapper_path)
    cli[cli.index("--activation-sha256") + 1] = wrapper_sha
    args = SimpleNamespace(
        contract=CONTRACT,
        amendment=AMENDMENT,
        amendment_sha256=AMENDMENT_SHA256,
        policy=POLICY,
        quarantine=BUNDLE,
        activation_ruling=wrapper_path,
        activation_sha256=wrapper_sha,
        workspace=paths[0],
        output=paths[1],
        failure_output=paths[2],
    )
    runtime = runner._runtime_argv(
        cli,
        executable=str(ROOT / ".venv/bin/python"),
    )
    with pytest.raises(
        runner.LivenessCanaryFailure,
        match="command_sha256 differs",
    ):
        runner.execute(args, argv=runtime)
    assert constructed is False
    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("predecessor_amendment_sha256",), "0" * 64),
        (("command_identity_remediation", "void_activation_reusable"), True),
        (
            (
                "command_identity_remediation",
                "resolved_interpreter_substitution_permitted",
            ),
            True,
        ),
        (("request_budget", "total_network_send_maximum"), 12),
        (("request_budget", "retry_count"), 1),
    ],
)
def test_amendment_tamper_fails_closed(
    builder: ModuleType,
    amendment: dict,
    path: tuple[str, ...],
    value: object,
) -> None:
    attacked = copy.deepcopy(amendment)
    target = attacked
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(builder.AmendmentFailure, match="differs"):
        builder.validate_amendment_document(attacked)


def test_fresh_v11_paths_are_absent(amendment: dict) -> None:
    paths = amendment["external_paths"]
    values = [
        Path(paths["workspace"]),
        Path(paths["success_output"]),
        Path(paths["failure_output"]),
    ]
    assert all(
        f"jaa05-canary-v11-{_head()[:7]}-" in str(path)
        for path in values
    )
    assert len(set(values)) == 3
    assert len({path.parent for path in values}) == 1
    assert all(not path.exists() and not path.is_symlink() for path in values)


def test_all_markers_remain_inert_and_no_live_authority(amendment: dict) -> None:
    assert amendment["proposal_only"] is True
    assert amendment["requests_specified_not_performed"] is True
    assert amendment["network_requests"] == 0
    assert amendment["consequential_external_actions"] == 0
    for key in (
        "executable",
        "execution_authorized",
        "configuration_active",
        "live_authority_granted",
        "runtime_resolvable_path",
        "may_be_loaded_or_executed",
        "canary_executed",
    ):
        assert amendment[key] is False


def test_builder_and_amendment_cannot_be_runtime_loaded(
    builder: ModuleType,
    runner: ModuleType,
    amendment: dict,
) -> None:
    assert builder._network_imports(BUILDER.read_text()) == []
    with pytest.raises(builder.AmendmentFailure, match="inert"):
        builder.load_for_execution(AMENDMENT)
    runner._validate_amendment(
        amendment,
        executor_sha256=EXECUTOR_SHA256,
    )
    old = json.loads(PACKAGE023_AMENDMENT.read_bytes())
    with pytest.raises(
        runner.LivenessCanaryFailure,
        match="Package 024 amendment markers differ",
    ):
        runner._validate_amendment(old, executor_sha256=EXECUTOR_SHA256)


def test_official_cohort_refuses_package024_before_side_effect(
    tmp_path: Path,
) -> None:
    controller = SimpleNamespace(
        policy=SimpleNamespace(
            policy_sha256="1" * 64,
            attestations={
                "boards-api.greenhouse.io": {},
                "api.lever.co": {},
            },
        ),
    )
    raw = tmp_path / "raw"
    output = tmp_path / "queue.json"
    with pytest.raises(RuntimeError, match="proposal-only"):
        build(
            AMENDMENT,
            output,
            raw,
            quarantine_index=load_quarantine_bundle(BUNDLE, BUNDLE_SHA256),
            access_controller=controller,
        )
    assert not raw.exists()
    assert not output.exists()
    assert not (tmp_path / "request-journal.jsonl").exists()
