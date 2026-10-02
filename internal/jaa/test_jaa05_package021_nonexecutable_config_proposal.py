"""Package 021 non-executable config-v4 proposal controls."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml

from career_automation.holdout_firewall import load_quarantine_bundle
from career_automation.official_cohort import build
from testing_repository import (
    historical_path,
    operator_control_path,
    rebind_historical_control_paths,
)


ROOT = Path(__file__).resolve().parent
CONTROL = operator_control_path("resumed-dual-lane-20260728", "jaa", "jaa05-next-cycle")
SCRIPT = CONTROL / "package-021-build-nonexecutable-config-v4.py"
PROPOSAL = (
    CONTROL / "package-021-authorized-production-config-v4-proposal.yaml.proposal"
)
REPORT = CONTROL / "package-020-preserved-supply-exhaustion-audit.json"
PACKAGE020_SCRIPT = CONTROL / "package-020-audit-preserved-supply.py"
BUNDLE = CONTROL / "combined-quarantine-bundle.json"
BUNDLE_SHA256 = "ad380445efd62019fe970ee1d775e48a5e5f58639bd385823e31780547f1a6c4"
SCRIPT_SHA256 = "120b1cbfa2a82a22117b09e9eaf78c1bbff021aac9089e03772dcdb8b5b1c894"
PROPOSAL_SHA256 = "fd9cff6246fc5d2b153bb7d37a667f20c5fc1b15192daa2968f70bf59f94f9e2"
EXPECTED = [
    ("greenhouse", "accesso", "boards-api.greenhouse.io"),
    ("greenhouse", "clickhouse", "boards-api.greenhouse.io"),
    ("greenhouse", "commvault", "boards-api.greenhouse.io"),
    ("greenhouse", "lightningai", "boards-api.greenhouse.io"),
    ("greenhouse", "metropolis", "boards-api.greenhouse.io"),
    ("greenhouse", "sharkninjaoperatingllc", "boards-api.greenhouse.io"),
    ("greenhouse", "smartsheet", "boards-api.greenhouse.io"),
    ("lever", "binance", "api.lever.co"),
    ("lever", "gearset", "api.lever.co"),
]


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return rebind_historical_control_paths(module)


@pytest.fixture(scope="module")
def proposal_module() -> ModuleType:
    return _load_module("package021_proposal", SCRIPT)


@pytest.fixture(scope="module")
def proposal() -> dict:
    document = yaml.safe_load(PROPOSAL.read_bytes())
    assert isinstance(document, dict)
    return document


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _context(module: ModuleType) -> tuple[dict, dict, frozenset[str]]:
    report = module._json(module.PACKAGE_020_REPORT, module.EXPECTED_SHA256)
    policy = module._json(module.POLICY_V2, module.EXPECTED_SHA256)
    resolved, _ = module._resolve_config(
        module.CONFIG_V3,
        module.EXPECTED_SHA256,
    )
    return report, resolved, module._attested_hosts(policy)


def test_frozen_builder_and_proposal_hashes_match() -> None:
    assert _sha256(SCRIPT) == SCRIPT_SHA256
    assert _sha256(PROPOSAL) == PROPOSAL_SHA256


def test_proposal_strictly_validates_and_reproduces(
    proposal_module: ModuleType,
) -> None:
    document = proposal_module.validate_proposal(
        PROPOSAL,
        PROPOSAL_SHA256,
        rerun=True,
    )
    assert document["schema_version"] == (
        "jaa05.package021-nonexecutable-config-v4-proposal.v1"
    )


def test_two_fresh_builds_are_byte_identical(
    proposal_module: ModuleType,
) -> None:
    first = proposal_module.proposal_bytes(proposal_module.build_proposal())
    second = proposal_module.proposal_bytes(proposal_module.build_proposal())
    assert first == second == PROPOSAL.read_bytes()


def test_exact_nine_tenant_set_and_order(proposal: dict) -> None:
    actual = [
        (row["provider"], row["tenant"], row["provider_api_host"])
        for row in proposal["eligible_tenants"]
    ]
    assert actual == EXPECTED
    assert proposal["derivation"]["eligible_input_count"] == 9
    assert proposal["derivation"]["eligible_output_count"] == 9
    assert proposal["derivation"]["ranking_sampling_scoring_or_judgment_used"] is False


def test_all_execution_markers_are_inert(proposal: dict) -> None:
    assert proposal["proposal_only"] is True
    assert proposal["executable"] is False
    assert proposal["execution_authorized"] is False
    assert proposal["configuration_active"] is False
    assert proposal["authority"]["live_authority_granted"] is False
    assert proposal["output_constraints"]["may_be_loaded_or_executed"] is False
    assert proposal["output_constraints"]["runtime_resolvable_path"] is False
    assert proposal["output_constraints"]["network_requests"] == 0
    assert proposal["output_constraints"]["consequential_external_actions"] == 0


def test_inert_artifact_path_preserves_package020_inventory(
    proposal_module: ModuleType,
) -> None:
    assert PROPOSAL.suffix == ".proposal"
    assert PROPOSAL.parent == CONTROL
    assert not PROPOSAL.is_symlink()
    for path in (
        proposal_module.CONFIG_ROOT,
        proposal_module.CONFIG_ADDITIONAL,
        proposal_module.CONFIG_OVERNIGHT,
        proposal_module.CONFIG_V2,
        proposal_module.CONFIG_V3,
    ):
        assert str(PROPOSAL) not in path.read_text()
    package020 = _load_module("package020_recheck", PACKAGE020_SCRIPT)
    report = package020.validate_report(
        REPORT,
        package020.sha256_bytes(REPORT.read_bytes()),
        rerun=True,
    )
    assert report["structured_input_count"] == 110


def test_resolved_counts_and_historical_capacity_are_honest(
    proposal: dict,
) -> None:
    capacity = proposal["offline_capacity_assessment"]
    assert capacity["v3_tenant_counts"] == {
        "ashby": 11,
        "greenhouse": 25,
        "lever": 9,
        "recruitee": 2,
        "smartrecruiters": 12,
        "workable": 11,
        "total": 70,
    }
    assert capacity["proposal_tenant_counts"] == {
        "ashby": 11,
        "greenhouse": 32,
        "lever": 11,
        "recruitee": 2,
        "smartrecruiters": 12,
        "workable": 11,
        "total": 79,
    }
    assert capacity["added_provider_counts"] == {"greenhouse": 7, "lever": 2}
    assert capacity["added_tenant_count"] == 9
    assert capacity["historical_observation_count"] == 14
    assert capacity["observation_age_classification"] == (
        "historical_control_plane_metadata"
    )
    assert capacity["live_capacity_known"] is False
    assert capacity["proves_live_availability"] is False
    assert capacity["execution_authorized"] is False


def test_source_documents_and_quarantine_are_hash_bound(proposal: dict) -> None:
    sources = proposal["offline_capacity_assessment"]["historical_source_documents"]
    assert sources == [
        {
            "path": (
                "/home/gutua/software-factory/.control/"
                "jaa-12h-supervisor-20260727/runtime/"
                "ats-search-index-discovery-recovery-v1/result.json"
            ),
            "sha256": (
                "a727e707fa0100da0c053847151d06cd6a49b4b40a5562affd25021359df2ab8"
            ),
        },
        {
            "path": (
                "/home/gutua/software-factory/.control/"
                "jaa-12h-supervisor-20260727/runtime/"
                "ats-search-index-discovery-v1/result.json"
            ),
            "sha256": (
                "44ce8084f43eadcd56eda0d73af7984030957bd25c0e5fb1e1d0339c46577c3f"
            ),
        },
    ]
    for source in sources:
        assert _sha256(historical_path(source["path"])) == source["sha256"]
    quarantine = proposal["quarantine_crosscheck"]
    assert quarantine["eligible_candidate_overlap_count"] == 0
    assert quarantine["union_counts"] == {
        "canonical_url_sha256": 54,
        "content_sha256": 49,
        "job_key": 57,
        "payload_hash": 82,
    }
    assert all(
        row["quarantine_identity_overlaps"] == []
        for row in proposal["eligible_tenants"]
    )


def test_display_labels_are_mechanical_not_fabricated(proposal: dict) -> None:
    for overlay in proposal["provider_overlays"].values():
        assert overlay["companies"] == {
            tenant: tenant for tenant in overlay["companies"]
        }
        assert "not a verified company display name" in overlay["display_label_rule"]


@pytest.mark.parametrize(
    ("marker", "attacked_value"),
    [
        ("proposal_only", False),
        ("executable", True),
        ("execution_authorized", True),
        ("configuration_active", True),
    ],
)
def test_active_or_executable_marker_is_rejected(
    proposal_module: ModuleType,
    proposal: dict,
    marker: str,
    attacked_value: bool,
) -> None:
    report, resolved, hosts = _context(proposal_module)
    attacked = copy.deepcopy(proposal)
    attacked[marker] = attacked_value
    with pytest.raises(
        proposal_module.ProposalFailure,
        match="proposal marker",
    ):
        proposal_module.validate_proposal_document(
            attacked,
            report=report,
            resolved_config=resolved,
            attested_hosts=hosts,
        )


@pytest.mark.parametrize("attack", ["omission", "addition", "reorder"])
def test_omission_addition_or_reordering_is_rejected(
    proposal_module: ModuleType,
    proposal: dict,
    attack: str,
) -> None:
    report, resolved, hosts = _context(proposal_module)
    attacked = copy.deepcopy(proposal)
    if attack == "omission":
        attacked["eligible_tenants"].pop()
    elif attack == "addition":
        attacked["eligible_tenants"].append(
            {
                "provider": "greenhouse",
                "tenant": "fabricated",
                "provider_api_host": "boards-api.greenhouse.io",
                "observation_count": 1,
                "observation_records_sha256": "0" * 64,
                "source_documents": ["/fabricated.json"],
                "quarantine_identity_overlaps": [],
            }
        )
    else:
        attacked["eligible_tenants"].reverse()
    with pytest.raises(
        proposal_module.ProposalFailure,
        match="tenant set/order differs",
    ):
        proposal_module.validate_proposal_document(
            attacked,
            report=report,
            resolved_config=resolved,
            attested_hosts=hosts,
        )


def test_ranking_or_sampling_field_is_rejected(
    proposal_module: ModuleType,
    proposal: dict,
) -> None:
    report, resolved, hosts = _context(proposal_module)
    attacked = copy.deepcopy(proposal)
    attacked["eligible_tenants"][0]["rank"] = 1
    with pytest.raises(
        proposal_module.ProposalFailure,
        match="ranking, sampling or scoring",
    ):
        proposal_module.validate_proposal_document(
            attacked,
            report=report,
            resolved_config=resolved,
            attested_hosts=hosts,
        )


@pytest.mark.parametrize("attack", ["nonattested", "quarantined", "fabricated"])
def test_tampered_package020_candidate_fails_closed(
    proposal_module: ModuleType,
    attack: str,
) -> None:
    report = proposal_module._json(
        proposal_module.PACKAGE_020_REPORT,
        proposal_module.EXPECTED_SHA256,
    )
    attacked = copy.deepcopy(report)
    eligible = next(
        row
        for row in attacked["candidates"]
        if row["status"] == "eligible_preserved_metadata_absent_from_v3"
    )
    if attack == "nonattested":
        eligible["exact_api_host_attested"] = False
        eligible["provider_api_host"] = "unattested.example"
    elif attack == "quarantined":
        eligible["quarantine_identity_overlaps"] = ["canonical_url_sha256"]
    else:
        fabricated = copy.deepcopy(eligible)
        fabricated["tenant_compare_key"] = "fabricated"
        fabricated["tenant_observed"] = "fabricated"
        attacked["candidates"].append(fabricated)
        attacked["eligible_preserved_tenant_count"] = 10
    with pytest.raises(proposal_module.ProposalFailure):
        proposal_module._eligible_candidates(attacked)


def test_tampered_config_chain_hash_fails_before_proposal(
    proposal_module: ModuleType,
) -> None:
    attacked = dict(proposal_module.EXPECTED_SHA256)
    attacked[str(proposal_module.CONFIG_V3)] = "0" * 64
    with pytest.raises(
        proposal_module.ProposalFailure,
        match="bound input hash mismatch",
    ):
        proposal_module.build_proposal(expected_hashes=attacked)


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
    proposal_module: ModuleType,
    source: str,
) -> None:
    assert proposal_module._network_imports(source)


def test_actual_builder_has_no_network_primitive_import(
    proposal_module: ModuleType,
) -> None:
    assert proposal_module._network_imports(SCRIPT.read_text()) == []


def test_runtime_builder_refuses_proposal_before_journal_or_access(
    proposal: dict,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert proposal["proposal_only"] is True
    import skeleton.configuration as configuration

    monkeypatch.setattr(configuration, "Path", type(historical_path("/")))
    controller = SimpleNamespace(
        policy=SimpleNamespace(policy_sha256="1" * 64),
    )
    with pytest.raises(RuntimeError, match="proposal-only"):
        build(
            PROPOSAL,
            tmp_path / "queue.json",
            tmp_path / "raw",
            quarantine_index=load_quarantine_bundle(BUNDLE, BUNDLE_SHA256),
            access_controller=controller,
        )
    assert not (tmp_path / "raw").exists()
    assert not (tmp_path / "request-journal.jsonl").exists()
    assert not (tmp_path / "queue.json").exists()
