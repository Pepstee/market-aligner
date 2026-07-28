"""Package 023 offline canary execution-preparation amendment controls."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from career_automation.employer_research import RawResponseCache
from career_automation.holdout_firewall import load_quarantine_bundle
from career_automation.official_cohort import build


ROOT = Path(__file__).resolve().parent
CONTROL = Path(
    "/home/gutua/software-factory/.control/resumed-dual-lane-20260728/"
    "jaa/jaa05-next-cycle"
)
BUILDER = CONTROL / "package-023-build-canary-execution-amendment.py"
AMENDMENT = (
    CONTROL / "package-023-canary-execution-amendment.json.canary-amendment"
)
CONTRACT = CONTROL / "package-022-liveness-canary-contract.json.canary-contract"
BUNDLE = CONTROL / "combined-quarantine-bundle.json"
EXECUTOR = ROOT / "scripts/run_jaa05_liveness_canary.py"
PACKAGE020_SCRIPT = CONTROL / "package-020-audit-preserved-supply.py"
PACKAGE020_REPORT = CONTROL / "package-020-preserved-supply-exhaustion-audit.json"
PACKAGE021_SCRIPT = CONTROL / "package-021-build-nonexecutable-config-v4.py"
PACKAGE021_PROPOSAL = (
    CONTROL
    / "package-021-authorized-production-config-v4-proposal.yaml.proposal"
)
PACKAGE022_SCRIPT = (
    CONTROL
    / "package-022-build-nonexecutable-liveness-canary-contract.py"
)
BUILDER_SHA256 = hashlib.sha256(BUILDER.read_bytes()).hexdigest()
AMENDMENT_SHA256 = hashlib.sha256(AMENDMENT.read_bytes()).hexdigest()
CONTRACT_SHA256 = "c43fd61eee5b950f9a9e80fcfe60fa9008f582c31b265685e440485b06f34323"
EXECUTOR_SHA256 = "db932ff4aedc55cb2fca8aa4499422acabbfbe888d0ee73424bd6acd82592208"
BUNDLE_SHA256 = "ad380445efd62019fe970ee1d775e48a5e5f58639bd385823e31780547f1a6c4"
PACKAGE021_PROPOSAL_SHA256 = (
    "fd9cff6246fc5d2b153bb7d37a667f20c5fc1b15192daa2968f70bf59f94f9e2"
)


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_historical_runner() -> ModuleType:
    source = subprocess.run(
        (
            "git",
            "show",
            "d98506a5e8529d1aa2a6f996ab6428d13049acdb:"
            "scripts/run_jaa05_liveness_canary.py",
        ),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    module = ModuleType("package023_historical_runner")
    module.__file__ = str(EXECUTOR)
    exec(compile(source, str(EXECUTOR), "exec"), module.__dict__)
    current_executor = EXECUTOR.read_bytes()
    historical_digest = module._digest

    def digest_with_historical_executor(value: bytes) -> str:
        if value == current_executor:
            return EXECUTOR_SHA256
        return historical_digest(value)

    module._digest = digest_with_historical_executor
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


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    module = _load_module("package023_builder", BUILDER)
    historical_executor = subprocess.run(
        (
            "git",
            "show",
            "d98506a5e8529d1aa2a6f996ab6428d13049acdb:"
            "scripts/run_jaa05_liveness_canary.py",
        ),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    read_regular = module._read_regular

    def read_with_historical_executor(path: Path) -> bytes:
        if path == EXECUTOR:
            return historical_executor
        return read_regular(path)

    module._read_regular = read_with_historical_executor
    return module


@pytest.fixture(scope="module")
def runner() -> ModuleType:
    return _load_historical_runner()


@pytest.fixture(scope="module")
def amendment(builder: ModuleType) -> dict:
    return builder.validate_amendment(
        AMENDMENT,
        AMENDMENT_SHA256,
        rerun=True,
    )


def test_frozen_builder_amendment_and_executor_hashes_match() -> None:
    assert _sha256(BUILDER) == BUILDER_SHA256
    assert _sha256(AMENDMENT) == AMENDMENT_SHA256
    historical = subprocess.run(
        (
            "git",
            "show",
            "d98506a5e8529d1aa2a6f996ab6428d13049acdb:"
            "scripts/run_jaa05_liveness_canary.py",
        ),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    assert hashlib.sha256(historical).hexdigest() == EXECUTOR_SHA256
    assert BUILDER.stat().st_mode & 0o777 == 0o444
    assert AMENDMENT.stat().st_mode & 0o777 == 0o444


def test_amendment_strictly_validates_and_reproduces(amendment: dict) -> None:
    assert amendment["schema_version"] == (
        "jaa05.package023-canary-execution-amendment.v1"
    )


def test_two_builds_are_byte_identical(builder: ModuleType) -> None:
    first = builder.canonical_json(builder.build_amendment())
    second = builder.canonical_json(builder.build_amendment())
    assert first == second == AMENDMENT.read_bytes()


def test_amendment_references_without_restating_content_routes(
    amendment: dict,
) -> None:
    assert amendment["contract_sha256"] == CONTRACT_SHA256
    assert "routes" not in amendment
    contract = json.loads(CONTRACT.read_bytes())
    assert len(contract["routes"]) == 9


def test_exact_robots_and_total_request_budgets(amendment: dict) -> None:
    assert amendment["request_budget"] == {
        "content_get_maximum": 9,
        "robots_get_maximum": 2,
        "total_network_send_maximum": 11,
        "retry_count": 0,
        "redirects_permitted": False,
        "resume_permitted": False,
        "frozen_input_permitted": False,
    }
    robots = amendment["robots_policy_traffic"]
    assert robots["routes"] == [
        {
            "host": "api.lever.co",
            "url": "https://api.lever.co/robots.txt",
        },
        {
            "host": "boards-api.greenhouse.io",
            "url": "https://boards-api.greenhouse.io/robots.txt",
        },
    ]
    assert robots["method"] == "GET"
    assert robots["timeout_seconds_maximum"] == 45
    assert robots["maximum_response_bytes"] == 8 * 1024 * 1024
    assert robots["retry_count"] == 0
    assert robots["redirects_permitted"] is False
    assert robots["waiver_permitted"] is False
    assert "without retry, substitution" in robots["disallow_semantics"]


def test_all_amendment_markers_are_inert(amendment: dict) -> None:
    assert amendment["proposal_only"] is True
    for key in (
        "executable",
        "execution_authorized",
        "configuration_active",
        "live_authority_granted",
        "runtime_resolvable_path",
        "may_be_loaded_or_executed",
        "live_capacity_known",
        "proves_live_availability",
        "canary_executed",
    ):
        assert amendment[key] is False
    assert amendment["requests_specified_not_performed"] is True
    assert amendment["network_requests"] == 0
    assert amendment["consequential_external_actions"] == 0


def test_executor_is_exactly_revision_and_hash_bound(amendment: dict) -> None:
    executor = amendment["future_executor"]
    assert executor["path"] == str(EXECUTOR)
    assert executor["sha256"] == EXECUTOR_SHA256
    assert executor["source_commit"] == (
        "d98506a5e8529d1aa2a6f996ab6428d13049acdb"
    )
    assert executor["source_tree"] == subprocess.run(
        (
            "git",
            "rev-parse",
            "d98506a5e8529d1aa2a6f996ab6428d13049acdb^{tree}",
        ),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    assert executor["command_argv_template"][0] == str(ROOT / ".venv/bin/python")
    assert executor["command_argv_template"][1] == str(EXECUTOR)
    assert hashlib.sha256(
        json.dumps(
            executor["command_argv_template"],
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        + b"\n"
    ).hexdigest() == executor["command_argv_template_sha256"]


def test_exact_fresh_runtime_paths_are_currently_absent(amendment: dict) -> None:
    paths = amendment["external_paths"]
    assert paths["all_must_be_absent_before_run"] is True
    assert paths["all_are_distinct_siblings"] is True
    assert paths["all_are_outside_repository"] is True
    values = [
        Path(paths["workspace"]),
        Path(paths["success_output"]),
        Path(paths["failure_output"]),
    ]
    assert len(set(values)) == 3
    assert len({path.parent for path in values}) == 1
    assert all(not path.exists() and not path.is_symlink() for path in values)


def test_response_cap_is_transport_boundary_fail_not_accept(
    amendment: dict,
) -> None:
    byte = amendment["byte_enforcement"]
    assert byte["maximum_response_bytes"] == 8 * 1024 * 1024
    assert byte["applies_to_robots_and_content"] is True
    assert byte["truncate_and_accept"] is False
    assert "BudgetedClient" in byte["enforcement_point"]
    assert "fail the entire run" in byte["over_limit_action"]


def test_success_and_failure_receipt_schemas_are_explicit(
    amendment: dict,
) -> None:
    receipts = amendment["future_run_receipts"]
    assert receipts["schema_version"] == "jaa05.liveness-canary-run-receipt.v1"
    assert receipts["success"] == {
        "status": "success",
        "required_route_status": "live_schema_valid",
        "exact_route_outcome_count": 9,
        "failure_field_permitted": False,
    }
    assert receipts["failure"]["status"] == "failure"
    assert receipts["failure"]["failure_field_required"] is True
    assert receipts["failure"]["retry_or_resume_permitted"] is False
    assert "raw_inventory" in receipts["common_required_fields"]
    assert {
        "bytes_received",
        "bytes_preserved",
        "robots_receipt",
        "status",
    }.issubset(receipts["per_route_required_fields"])


def test_terminal_inventory_binds_relative_paths_bytes_and_hashes(
    runner: ModuleType,
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw" / "sha256"
    raw.mkdir(parents=True)
    first = raw / "a"
    second = tmp_path / "rate-ledger.json"
    first.write_bytes(b"raw response")
    second.write_bytes(b"{}")
    assert runner._inventory(tmp_path) == [
        {
            "path": "rate-ledger.json",
            "byte_count": 2,
            "sha256": hashlib.sha256(b"{}").hexdigest(),
        },
        {
            "path": "raw/sha256/a",
            "byte_count": 12,
            "sha256": hashlib.sha256(b"raw response").hexdigest(),
        },
    ]
    source = EXECUTOR.read_text()
    assert source.count('receipt["raw_inventory"] = _inventory(workspace)') == 2


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("request_budget", "robots_get_maximum"), 3),
        (("request_budget", "total_network_send_maximum"), 12),
        (("request_budget", "retry_count"), 1),
        (("request_budget", "resume_permitted"), True),
        (("request_budget", "frozen_input_permitted"), True),
        (("robots_policy_traffic", "waiver_permitted"), True),
        (("robots_policy_traffic", "method"), "POST"),
    ],
)
def test_budget_waiver_retry_nonget_resume_or_frozen_tamper_rejected(
    builder: ModuleType,
    amendment: dict,
    path: tuple[str, str],
    value: object,
) -> None:
    attacked = copy.deepcopy(amendment)
    attacked[path[0]][path[1]] = value
    with pytest.raises(builder.AmendmentFailure, match="differs"):
        builder.validate_amendment_document(attacked)


def test_new_robots_host_is_rejected(
    builder: ModuleType,
    amendment: dict,
) -> None:
    attacked = copy.deepcopy(amendment)
    attacked["robots_policy_traffic"]["routes"][0] = {
        "host": "example.invalid",
        "url": "https://example.invalid/robots.txt",
    }
    with pytest.raises(builder.AmendmentFailure, match="differs"):
        builder.validate_amendment_document(attacked)


@pytest.mark.parametrize("target", ["contract", "bundle", "executor"])
def test_tampered_bound_hash_fails_before_amendment(
    builder: ModuleType,
    target: str,
) -> None:
    attacked = dict(builder.EXPECTED_SHA256)
    path = {
        "contract": builder.CONTRACT,
        "bundle": builder.BUNDLE,
        "executor": builder.EXECUTOR,
    }[target]
    attacked[str(path)] = "0" * 64
    with pytest.raises(
        builder.AmendmentFailure,
        match="bound input hash mismatch",
    ):
        builder.build_amendment(expected_hashes=attacked)


@pytest.mark.parametrize(
    "source",
    [
        "import requests",
        "from urllib.parse import urlsplit",
        "import socket",
        "import http.client",
        "from playwright.sync_api import sync_playwright",
    ],
)
def test_network_primitive_import_is_detected(
    builder: ModuleType,
    source: str,
) -> None:
    assert builder._network_imports(source)


def test_actual_amendment_builder_has_no_network_import(
    builder: ModuleType,
) -> None:
    assert builder._network_imports(BUILDER.read_text()) == []


class _FakeDelegate:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.calls: list[tuple[str, str, dict]] = []

    def fetch(self, engine: str, url: str, **kwargs: object) -> dict:
        self.calls.append((engine, url, dict(kwargs)))
        response = dict(self.response)
        response["url"] = response.get("url") or url
        return response


def _response(body: bytes, *, url: str = "") -> dict:
    return {
        "status": 200,
        "url": url,
        "history": [],
        "body_bytes": len(body),
        "body_base64": base64.b64encode(body).decode(),
    }


def test_budgeted_client_refuses_third_robots_before_delegate(
    runner: ModuleType,
    tmp_path: Path,
) -> None:
    delegate = _FakeDelegate(_response(b"User-agent: *\nAllow: /\n"))
    client = runner.BudgetedClient(delegate, RawResponseCache(tmp_path / "raw"))
    for host in ("api.lever.co", "boards-api.greenhouse.io"):
        client.fetch(
            "static",
            f"https://{host}/robots.txt",
            timeout=45,
            headers={},
        )
    with pytest.raises(runner.LivenessCanaryFailure, match="budget exhausted"):
        client.fetch(
            "static",
            "https://third.example/robots.txt",
            timeout=45,
            headers={},
        )
    assert len(delegate.calls) == 2


def test_budgeted_client_refuses_tenth_content_before_delegate(
    runner: ModuleType,
    tmp_path: Path,
) -> None:
    delegate = _FakeDelegate(_response(b"[]"))
    client = runner.BudgetedClient(delegate, RawResponseCache(tmp_path / "raw"))
    for index in range(9):
        client.fetch(
            "static",
            f"https://api.lever.co/v0/postings/t{index}",
            timeout=45,
            headers={},
        )
    with pytest.raises(runner.LivenessCanaryFailure, match="budget exhausted"):
        client.fetch(
            "static",
            "https://api.lever.co/v0/postings/t9",
            timeout=45,
            headers={},
        )
    assert len(delegate.calls) == 9


def test_oversize_is_capped_preserved_and_failed(
    runner: ModuleType,
    tmp_path: Path,
) -> None:
    body = b"x" * (runner.MAX_RESPONSE_BYTES + 1)
    cache = RawResponseCache(tmp_path / "raw")
    client = runner.BudgetedClient(_FakeDelegate(_response(body)), cache)
    with pytest.raises(
        runner.LivenessCanaryFailure,
        match="exceeded 8 MiB",
    ):
        client.fetch(
            "static",
            "https://api.lever.co/v0/postings/large",
            timeout=45,
            headers={},
        )
    event = client.events[-1]
    assert event["outcome"] == "response_too_large"
    assert event["bytes_received"] == runner.MAX_RESPONSE_BYTES + 1
    assert event["bytes_preserved"] == runner.MAX_RESPONSE_BYTES
    assert len(
        cache.resolve(event["raw_response_ref"], event["content_sha256"])
    ) == runner.MAX_RESPONSE_BYTES


def test_redirect_is_preserved_and_failed(
    runner: ModuleType,
    tmp_path: Path,
) -> None:
    url = "https://api.lever.co/v0/postings/binance"
    response = _response(b"[]", url="https://api.lever.co/other")
    response["history"] = [{"url": url, "status": 302}]
    cache = RawResponseCache(tmp_path / "raw")
    client = runner.BudgetedClient(_FakeDelegate(response), cache)
    with pytest.raises(
        runner.LivenessCanaryFailure,
        match="redirected response",
    ):
        client.fetch("static", url, timeout=45, headers={})
    event = client.events[-1]
    assert event["outcome"] == "redirect_prohibited"
    assert cache.resolve(
        event["raw_response_ref"],
        event["content_sha256"],
    ) == b"[]"


def _activation(runner: ModuleType, *, command_sha256: str) -> dict:
    return {
        "ruling_id": "synthetic-offline-activation-shape",
        "verdict": "AUTHORISE_LIVE_CANARY_ONCE",
        "source_commit": _head(),
        "contract_sha256": CONTRACT_SHA256,
        "amendment_sha256": AMENDMENT_SHA256,
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


def test_activation_ruling_requires_every_exact_binding(
    runner: ModuleType,
) -> None:
    command_hash = "1" * 64
    ruling = _activation(runner, command_sha256=command_hash)
    wrapper = {"result": f"```json\n{json.dumps(ruling)}\n```"}
    assert runner._validate_activation(
        wrapper,
        wrapper_sha256="2" * 64,
        amendment_sha256=AMENDMENT_SHA256,
        source_commit=ruling["source_commit"],
        command_sha256=command_hash,
    ) == ruling
    attacked = copy.deepcopy(wrapper)
    value = json.loads(attacked["result"].splitlines()[1])
    value["maximum_total_network_sends"] = 12
    attacked["result"] = f"```json\n{json.dumps(value)}\n```"
    with pytest.raises(
        runner.LivenessCanaryFailure,
        match="maximum_total_network_sends",
    ):
        runner._validate_activation(
            attacked,
            wrapper_sha256="2" * 64,
            amendment_sha256=AMENDMENT_SHA256,
            source_commit=ruling["source_commit"],
            command_sha256=command_hash,
        )


def test_command_identity_normalizes_only_activation_wrapper_hash(
    runner: ModuleType,
) -> None:
    first = [
        "/python",
        "/runner",
        "--activation-ruling",
        "/fixed/ruling.json",
        "--activation-sha256",
        "1" * 64,
        "--workspace",
        "/fixed/workspace",
    ]
    second = list(first)
    second[5] = "2" * 64
    assert runner._command_identity(first) == runner._command_identity(second)
    changed_path = list(first)
    changed_path[3] = "/other/ruling.json"
    assert runner._command_identity(first) != runner._command_identity(changed_path)
    with pytest.raises(
        runner.LivenessCanaryFailure,
        match="lacks activation hash",
    ):
        runner._command_identity(["/python", "/runner"])


def test_invalid_activation_fails_before_client_or_workspace(
    runner: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    def forbidden_client(*_args: object, **_kwargs: object) -> None:
        nonlocal constructed
        constructed = True
        raise AssertionError("client must not be constructed")

    monkeypatch.setattr(runner, "ScraplingClient", forbidden_client)
    ruling = _activation(runner, command_sha256="0" * 64)
    ruling["verdict"] = "REJECT"
    wrapper_path = tmp_path / "activation.json"
    wrapper_path.write_text(
        json.dumps({"result": f"```json\n{json.dumps(ruling)}\n```"}) + "\n"
    )
    wrapper_sha = _sha256(wrapper_path)
    paths = [
        tmp_path / "workspace",
        tmp_path / "success",
        tmp_path / "failure",
    ]
    args = SimpleNamespace(
        contract=CONTRACT,
        amendment=AMENDMENT,
        amendment_sha256=AMENDMENT_SHA256,
        policy=runner.Path(
            "/home/gutua/software-factory/.control/jaa-12h-supervisor-20260727/"
            "runtime/recruitee-authority-provenance-v1/"
            "public-access-policy-17-host-v2.json"
        ),
        quarantine=BUNDLE,
        activation_ruling=wrapper_path,
        activation_sha256=wrapper_sha,
        workspace=paths[0],
        output=paths[1],
        failure_output=paths[2],
    )
    with pytest.raises(
        runner.LivenessCanaryFailure,
        match="activation ruling field verdict differs",
    ):
        runner.execute(
            args,
            argv=[
                "synthetic",
                "offline",
                "--activation-sha256",
                wrapper_sha,
            ],
        )
    assert constructed is False
    assert all(not path.exists() for path in paths)


def test_builder_loader_refuses_amendment(builder: ModuleType) -> None:
    with pytest.raises(builder.AmendmentFailure, match="inert"):
        builder.load_for_execution(AMENDMENT)


def test_official_cohort_refuses_amendment_before_journal(
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


def test_all_predecessor_evidence_still_reproduces() -> None:
    package020 = _load_module("package020_after_023", PACKAGE020_SCRIPT)
    report = package020.validate_report(
        PACKAGE020_REPORT,
        _sha256(PACKAGE020_REPORT),
        rerun=True,
    )
    assert report["structured_input_count"] == 110
    package021 = _load_module("package021_after_023", PACKAGE021_SCRIPT)
    package021.validate_proposal(
        PACKAGE021_PROPOSAL,
        PACKAGE021_PROPOSAL_SHA256,
        rerun=True,
    )
    package022 = _load_module("package022_after_023", PACKAGE022_SCRIPT)
    package022.validate_contract(
        CONTRACT,
        CONTRACT_SHA256,
        rerun=True,
    )
