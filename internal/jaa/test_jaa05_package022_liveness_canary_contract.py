"""Package 022 offline, non-executable liveness-canary contract controls."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
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
SCRIPT = (
    CONTROL
    / "package-022-build-nonexecutable-liveness-canary-contract.py"
)
CONTRACT = CONTROL / "package-022-liveness-canary-contract.json.canary-contract"
PACKAGE020_SCRIPT = CONTROL / "package-020-audit-preserved-supply.py"
PACKAGE020_REPORT = CONTROL / "package-020-preserved-supply-exhaustion-audit.json"
PACKAGE021_SCRIPT = CONTROL / "package-021-build-nonexecutable-config-v4.py"
PACKAGE021_PROPOSAL = (
    CONTROL
    / "package-021-authorized-production-config-v4-proposal.yaml.proposal"
)
BUNDLE = CONTROL / "combined-quarantine-bundle.json"
BUNDLE_SHA256 = "ad380445efd62019fe970ee1d775e48a5e5f58639bd385823e31780547f1a6c4"
SCRIPT_SHA256 = "67a3270badfaacf1afd2897c676665e4e2a55890b54cde29064718a701848013"
CONTRACT_SHA256 = "c43fd61eee5b950f9a9e80fcfe60fa9008f582c31b265685e440485b06f34323"
PACKAGE021_PROPOSAL_SHA256 = (
    "fd9cff6246fc5d2b153bb7d37a667f20c5fc1b15192daa2968f70bf59f94f9e2"
)
EXPECTED = [
    (
        "greenhouse",
        "accesso",
        "boards-api.greenhouse.io",
        "https://boards-api.greenhouse.io/v1/boards/accesso/jobs?content=true",
    ),
    (
        "greenhouse",
        "clickhouse",
        "boards-api.greenhouse.io",
        "https://boards-api.greenhouse.io/v1/boards/clickhouse/jobs?content=true",
    ),
    (
        "greenhouse",
        "commvault",
        "boards-api.greenhouse.io",
        "https://boards-api.greenhouse.io/v1/boards/commvault/jobs?content=true",
    ),
    (
        "greenhouse",
        "lightningai",
        "boards-api.greenhouse.io",
        "https://boards-api.greenhouse.io/v1/boards/lightningai/jobs?content=true",
    ),
    (
        "greenhouse",
        "metropolis",
        "boards-api.greenhouse.io",
        "https://boards-api.greenhouse.io/v1/boards/metropolis/jobs?content=true",
    ),
    (
        "greenhouse",
        "sharkninjaoperatingllc",
        "boards-api.greenhouse.io",
        (
            "https://boards-api.greenhouse.io/v1/boards/"
            "sharkninjaoperatingllc/jobs?content=true"
        ),
    ),
    (
        "greenhouse",
        "smartsheet",
        "boards-api.greenhouse.io",
        "https://boards-api.greenhouse.io/v1/boards/smartsheet/jobs?content=true",
    ),
    (
        "lever",
        "binance",
        "api.lever.co",
        "https://api.lever.co/v0/postings/binance?mode=json&limit=100&skip=0",
    ),
    (
        "lever",
        "gearset",
        "api.lever.co",
        "https://api.lever.co/v0/postings/gearset?mode=json&limit=100&skip=0",
    ),
]


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def module() -> ModuleType:
    return _load_module("package022_canary_contract", SCRIPT)


@pytest.fixture(scope="module")
def contract(module: ModuleType) -> dict:
    return module.validate_contract(CONTRACT, CONTRACT_SHA256, rerun=True)


def _context(module: ModuleType) -> tuple[frozenset[str], frozenset[str]]:
    policy = module._json(module.POLICY_V2, module.EXPECTED_SHA256)
    return (
        module._attested_hosts(policy),
        module._quarantine_url_hashes(module.EXPECTED_SHA256),
    )


def _validate_attacked(module: ModuleType, attacked: dict) -> None:
    hosts, quarantine = _context(module)
    module.validate_contract_document(
        attacked,
        attested_hosts=hosts,
        quarantine_url_hashes=quarantine,
    )


def test_frozen_builder_and_contract_hashes_match() -> None:
    assert _sha256(SCRIPT) == SCRIPT_SHA256
    assert _sha256(CONTRACT) == CONTRACT_SHA256
    assert SCRIPT.stat().st_mode & 0o777 == 0o444
    assert CONTRACT.stat().st_mode & 0o777 == 0o444


def test_contract_strictly_validates_and_reproduces(contract: dict) -> None:
    assert contract["schema_version"] == (
        "jaa05.package022-nonexecutable-liveness-canary-contract.v1"
    )


def test_two_offline_builds_are_byte_identical(module: ModuleType) -> None:
    first = module.canonical_json(module.build_contract())
    second = module.canonical_json(module.build_contract())
    assert first == second == CONTRACT.read_bytes()


def test_exact_nine_routes_and_order(contract: dict) -> None:
    actual = [
        (row["provider"], row["tenant"], row["host"], row["url"])
        for row in contract["routes"]
    ]
    assert actual == EXPECTED
    assert len({row["url"] for row in contract["routes"]}) == 9


def test_each_route_is_one_bounded_get(contract: dict) -> None:
    for route in contract["routes"]:
        assert route["method"] == "GET"
        assert route["timeout_seconds"] == 45
        assert route["retry_count"] == 0
        assert route["follow_redirects"] is False
        assert route["fallback_engines"] == []
        assert route["maximum_response_bytes"] == 8 * 1024 * 1024
        assert route["canonical_url_sha256"] == hashlib.sha256(
            route["url"].encode()
        ).hexdigest()
    limits = contract["bounded_execution_specification"]
    assert limits["maximum_requests_per_run"] == 9
    assert limits["maximum_routes"] == 9
    assert limits["resume_permitted"] is False
    assert limits["frozen_input_permitted"] is False


def test_expected_response_schemas_are_provider_specific(contract: dict) -> None:
    greenhouse = contract["routes"][:7]
    lever = contract["routes"][7:]
    assert all(
        row["expected_response_schema"] == {
            "media_type": "application/json",
            "root_type": "object",
            "required_top_level": {"jobs": "array"},
        }
        for row in greenhouse
    )
    assert all(
        row["expected_response_schema"] == {
            "media_type": "application/json",
            "root_type": "array",
            "array_item_type": "object",
        }
        for row in lever
    )


def test_all_inert_and_nonexecution_markers(contract: dict) -> None:
    assert contract["proposal_only"] is True
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
        assert contract[key] is False
    assert contract["requests_specified_not_performed"] is True
    assert contract["network_requests"] == 0
    assert contract["consequential_external_actions"] == 0


def test_authority_inputs_are_exactly_hash_bound(contract: dict) -> None:
    assert contract["authority"] == {
        "clean_base_commit": "96d9558d657234d4e5c76c5b49c9bfc5c07a1d37",
        "package_021_proposal_sha256": PACKAGE021_PROPOSAL_SHA256,
        "package_021_receipt_sha256": (
            "6ba8be37e652ffeb9d489e0ef9af345f4e326dea3cbc1b9415d7efb74a3222a0"
        ),
        "package_021_acceptance_ruling_sha256": (
            "5947e88addb0a78d51386b576f05ce168e2f100acd5390c4ee246cc50ac5de95"
        ),
        "combined_quarantine_bundle_sha256": BUNDLE_SHA256,
        "policy_v2_sha256": (
            "95e09b38821efa3f2e82df3b7587d74381d4ae5548dc7adb00416883dad9068e"
        ),
        "recovery_contract_sha256": (
            "e4499c79062723fd7e71eb6acd3cc92b1027b3ff0951822cc7a50f6211917351"
        ),
        "future_live_execution_requires_separate_fable_ruling": True,
    }


def test_quarantine_overlap_is_zero_and_scope_is_honest(contract: dict) -> None:
    assert contract["quarantine_crosscheck"][
        "route_canonical_url_overlap_count"
    ] == 0
    assert contract["quarantine_crosscheck"][
        "route_canonical_url_overlaps"
    ] == []
    assert "no response" in contract["quarantine_crosscheck"]["scope_note"]


@pytest.mark.parametrize(
    ("marker", "attacked_value"),
    [
        ("proposal_only", False),
        ("executable", True),
        ("execution_authorized", True),
        ("configuration_active", True),
        ("canary_executed", True),
        ("requests_specified_not_performed", False),
    ],
)
def test_active_or_executed_marker_is_rejected(
    module: ModuleType,
    contract: dict,
    marker: str,
    attacked_value: bool,
) -> None:
    attacked = copy.deepcopy(contract)
    attacked[marker] = attacked_value
    with pytest.raises(module.CanaryContractFailure, match="inert marker"):
        _validate_attacked(module, attacked)


def test_tampered_bound_input_hash_fails_closed(module: ModuleType) -> None:
    attacked = dict(module.EXPECTED_SHA256)
    attacked[str(module.PROPOSAL)] = "0" * 64
    with pytest.raises(
        module.CanaryContractFailure,
        match="bound input hash mismatch",
    ):
        module.build_contract(expected_hashes=attacked)


def test_tampered_quarantine_bundle_fails_closed(module: ModuleType) -> None:
    attacked = dict(module.EXPECTED_SHA256)
    attacked[str(module.BUNDLE)] = "0" * 64
    with pytest.raises(
        module.CanaryContractFailure,
        match="bound input hash mismatch",
    ):
        module.build_contract(expected_hashes=attacked)


def test_quarantine_route_overlap_is_rejected(
    module: ModuleType,
    contract: dict,
) -> None:
    attacked = copy.deepcopy(contract)
    digest = attacked["routes"][0]["canonical_url_sha256"]
    hosts, quarantine = _context(module)
    with pytest.raises(
        module.CanaryContractFailure,
        match="overlaps quarantine",
    ):
        module.validate_contract_document(
            attacked,
            attested_hosts=hosts,
            quarantine_url_hashes=quarantine | {digest},
        )


@pytest.mark.parametrize("attack", ["other_host", "too_many", "retry", "post"])
def test_route_expansion_retry_or_nonget_is_rejected(
    module: ModuleType,
    contract: dict,
    attack: str,
) -> None:
    attacked = copy.deepcopy(contract)
    if attack == "other_host":
        attacked["routes"][0]["host"] = "example.invalid"
    elif attack == "too_many":
        attacked["routes"].append(copy.deepcopy(attacked["routes"][0]))
    elif attack == "retry":
        attacked["routes"][0]["retry_count"] = 1
    else:
        attacked["routes"][0]["method"] = "POST"
    with pytest.raises(module.CanaryContractFailure):
        _validate_attacked(module, attacked)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maximum_requests_per_run", 10),
        ("maximum_routes", 10),
        ("retry_count", 1),
        ("timeout_seconds_per_request", 46),
        ("maximum_response_bytes_per_request", 0),
        ("resume_permitted", True),
        ("frozen_input_permitted", True),
    ],
)
def test_bounded_run_limit_tamper_is_rejected(
    module: ModuleType,
    contract: dict,
    field: str,
    value: object,
) -> None:
    attacked = copy.deepcopy(contract)
    attacked["bounded_execution_specification"][field] = value
    with pytest.raises(
        module.CanaryContractFailure,
        match="bounded execution",
    ):
        _validate_attacked(module, attacked)


def test_contract_loader_refuses_execution_before_client(
    module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    def forbidden_client(*_args: object, **_kwargs: object) -> None:
        nonlocal constructed
        constructed = True
        raise AssertionError("network client must not be constructed")

    monkeypatch.setattr(
        "scraper.scrapling_client.ScraplingClient.__init__",
        forbidden_client,
    )
    with pytest.raises(
        module.CanaryContractFailure,
        match="non-executable",
    ):
        module.load_for_execution(CONTRACT)
    assert constructed is False


def test_runtime_cohort_builder_refuses_before_journal_or_access(
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
            CONTRACT,
            output,
            raw,
            quarantine_index=load_quarantine_bundle(BUNDLE, BUNDLE_SHA256),
            access_controller=controller,
        )
    assert not raw.exists()
    assert not (tmp_path / "request-journal.jsonl").exists()
    assert not output.exists()


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
    module: ModuleType,
    source: str,
) -> None:
    assert module._network_imports(source)


def test_actual_builder_has_no_network_primitive_import(module: ModuleType) -> None:
    assert module._network_imports(SCRIPT.read_text()) == []


def test_inert_suffix_and_runtime_nonreference() -> None:
    assert CONTRACT.name.endswith(".json.canary-contract")
    assert CONTRACT.parent == CONTROL
    assert not CONTRACT.is_symlink()
    for path in (
        ROOT / "skeleton/config.yaml",
        ROOT / "skeleton/config.additional.yaml",
        ROOT / "skeleton/config.overnight.yaml",
        ROOT / "career_automation/official_cohort.py",
        ROOT / "scripts/build_jaa04_official_cohort.py",
    ):
        assert str(CONTRACT) not in path.read_text()


def test_package020_and_package021_evidence_still_reproduce() -> None:
    package020 = _load_module("package020_after_022", PACKAGE020_SCRIPT)
    report_hash = package020.sha256_bytes(PACKAGE020_REPORT.read_bytes())
    report = package020.validate_report(
        PACKAGE020_REPORT,
        report_hash,
        rerun=True,
    )
    assert report["structured_input_count"] == 110
    package021 = _load_module("package021_after_022", PACKAGE021_SCRIPT)
    proposal = package021.validate_proposal(
        PACKAGE021_PROPOSAL,
        PACKAGE021_PROPOSAL_SHA256,
        rerun=True,
    )
    assert proposal["proposal_only"] is True
