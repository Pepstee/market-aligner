"""Package 020 offline preserved-supply exhaustion audit controls."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from testing_repository import (
    operator_control_path,
    rebind_historical_control_paths,
)

CONTROL = operator_control_path("resumed-dual-lane-20260728", "jaa", "jaa05-next-cycle")
SCRIPT = CONTROL / "package-020-audit-preserved-supply.py"
REPORT = CONTROL / "package-020-preserved-supply-exhaustion-audit.json"
SCRIPT_SHA256 = "33ab676ecfbcc3ce818b406ddd6055f12cb4c5e0021c971990b2c60bc0ce4caa"
REPORT_SHA256 = "e53c37c84fe8bc5def798b662936c2ed30725a6a62c6e118e891e9c3631b8805"
EXPECTED_ELIGIBLE = [
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


@pytest.fixture(scope="module")
def audit_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("package020_audit", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return rebind_historical_control_paths(module)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_frozen_script_and_report_hashes_match() -> None:
    assert _digest(SCRIPT) == SCRIPT_SHA256
    assert _digest(REPORT) == REPORT_SHA256


def test_report_strictly_validates_and_reproduces(
    audit_module: ModuleType,
) -> None:
    report = audit_module.validate_report(
        REPORT,
        REPORT_SHA256,
        rerun=True,
    )
    assert report["structured_input_count"] == 110
    assert report["tenant_observation_count"] == 17_135
    assert report["candidate_count"] == 68
    assert report["eligible_preserved_tenant_count"] == 9
    assert report["inactive_pending_human_terms_review_count"] == 0
    assert report["blocked_by_quarantine_count"] == 0
    assert report["whole_estate_exhausted"] is False
    assert report["execution_authorized"] is False
    assert report["configuration_emitted"] is False
    assert report["proves_live_availability"] is False


def test_exact_eligible_tenant_set_is_mechanical() -> None:
    report = json.loads(REPORT.read_text())
    actual = [
        (
            row["provider"],
            row["tenant_observed"],
            row["provider_api_host"],
        )
        for row in report["eligible_preserved_tenants_absent_from_v3"]
    ]
    assert actual == EXPECTED_ELIGIBLE
    eligible_candidates = [
        row
        for row in report["candidates"]
        if row["status"] == "eligible_preserved_metadata_absent_from_v3"
    ]
    assert len(eligible_candidates) == 9
    assert all(row["already_in_config_v3"] is False for row in eligible_candidates)
    assert all(row["exact_api_host_attested"] is True for row in eligible_candidates)
    assert all(not row["quarantine_identity_overlaps"] for row in eligible_candidates)


def test_report_is_byte_deterministic(audit_module: ModuleType) -> None:
    first = audit_module.canonical_bytes(audit_module.audit())
    second = audit_module.canonical_bytes(audit_module.audit())
    assert first == second == REPORT.read_bytes()


def test_scope_excludes_all_raw_and_failed_acquisition_content() -> None:
    report = json.loads(REPORT.read_text())
    failed_root = report["scope"]["excluded_failed_acquisition_root"]
    for record in report["structured_input_inventory"]:
        path = Path(record["path"])
        assert "raw" not in path.parts
        assert not str(path).startswith(f"{failed_root}/")
    assert report["scope"]["raw_response_bodies_read"] == 0
    assert (
        report["scope"]["failed_acquisition_metadata_used_for_tenant_derivation"]
        is False
    )


@pytest.mark.parametrize(
    ("value", "provider", "tenant", "api_host"),
    [
        (
            "https://job-boards.greenhouse.io/example/jobs/123",
            "greenhouse",
            "example",
            "boards-api.greenhouse.io",
        ),
        (
            "https://boards-api.greenhouse.io/v1/boards/example/jobs",
            "greenhouse",
            "example",
            "boards-api.greenhouse.io",
        ),
        (
            "https://jobs.lever.co/example/uuid",
            "lever",
            "example",
            "api.lever.co",
        ),
        (
            "https://api.lever.co/v0/postings/example?mode=json",
            "lever",
            "example",
            "api.lever.co",
        ),
        (
            "https://jobs.ashbyhq.com/example/uuid",
            "ashby",
            "example",
            "api.ashbyhq.com",
        ),
        (
            "https://api.ashbyhq.com/posting-api/job-board/example",
            "ashby",
            "example",
            "api.ashbyhq.com",
        ),
        (
            "https://jobs.smartrecruiters.com/Example/123",
            "smartrecruiters",
            "Example",
            "api.smartrecruiters.com",
        ),
        (
            "https://api.smartrecruiters.com/v1/companies/Example/postings",
            "smartrecruiters",
            "Example",
            "api.smartrecruiters.com",
        ),
        (
            "https://apply.workable.com/api/v1/widget/accounts/example?details=true",
            "workable",
            "example",
            "apply.workable.com",
        ),
        (
            "example.recruitee.com",
            "recruitee",
            "example",
            "example.recruitee.com",
        ),
    ],
)
def test_exact_route_grammars(
    audit_module: ModuleType,
    value: str,
    provider: str,
    tenant: str,
    api_host: str,
) -> None:
    assert audit_module._extract_tenant(value) == {
        "provider": provider,
        "tenant_observed": tenant,
        "tenant_compare_key": tenant.casefold(),
        "provider_api_host": api_host,
    }


@pytest.mark.parametrize(
    "value",
    [
        "The job is at https://jobs.lever.co/fabricated/uuid",
        "https://jobs.ashbyhq.com/robots.txt",
        "https://job-boards.greenhouse.io/robots.txt",
        "https://docs.recruitee.com/reference/offers",
        "https://apply.workable.com/fabricated/jobs/uuid",
        "https://unattested.example/jobs/fabricated",
    ],
)
def test_ambiguous_reserved_and_unsupported_values_are_not_candidates(
    audit_module: ModuleType,
    value: str,
) -> None:
    assert audit_module._extract_tenant(value) is None


def test_nonattested_host_cannot_be_promoted(
    audit_module: ModuleType,
) -> None:
    document = json.loads(REPORT.read_text())
    attacked = copy.deepcopy(document)
    candidate = next(
        row
        for row in attacked["candidates"]
        if row["status"] == "eligible_preserved_metadata_absent_from_v3"
    )
    candidate["provider_api_host"] = "unattested.example"
    candidate["exact_api_host_attested"] = False
    with pytest.raises(
        audit_module.AuditFailure,
        match="candidate status is not fail-closed",
    ):
        audit_module.validate_report_document(attacked)


def test_quarantined_identity_cannot_be_readmitted(
    audit_module: ModuleType,
) -> None:
    document = json.loads(REPORT.read_text())
    attacked = copy.deepcopy(document)
    candidate = next(
        row
        for row in attacked["candidates"]
        if row["status"] == "eligible_preserved_metadata_absent_from_v3"
    )
    candidate["quarantine_identity_overlaps"] = ["canonical_url_sha256"]
    with pytest.raises(
        audit_module.AuditFailure,
        match="candidate status is not fail-closed",
    ):
        audit_module.validate_report_document(attacked)


def test_quarantine_overlap_is_classified_before_existing_authority(
    audit_module: ModuleType,
) -> None:
    url = "https://job-boards.greenhouse.io/fabricated/jobs/123"
    quarantine = {
        "job_key": frozenset(),
        "payload_hash": frozenset(),
        "content_sha256": frozenset(),
        "canonical_url_sha256": frozenset({hashlib.sha256(url.encode()).hexdigest()}),
    }
    extracted = audit_module._extract_tenant(url)
    assert extracted
    observations = [
        {
            **extracted,
            "source_path": "/frozen/result.json",
            "json_pointer": "/results/0/url",
            "scalar_sha256": hashlib.sha256(url.encode()).hexdigest(),
            "quarantine_identity_overlaps": audit_module._identity_overlaps(
                url,
                None,
                quarantine,
            ),
        }
    ]
    configured = {provider: frozenset() for provider in audit_module.PROVIDERS}
    candidates = audit_module._summarize_candidates(
        observations,
        configured,
        frozenset({"boards-api.greenhouse.io"}),
    )
    assert candidates[0]["status"] == "blocked_quarantine_overlap"
    assert candidates[0]["executable_configuration_emitted"] is False


def test_fabricated_candidate_breaks_report_reproduction(
    audit_module: ModuleType,
    tmp_path: Path,
) -> None:
    attacked = json.loads(REPORT.read_text())
    template = copy.deepcopy(
        next(
            row
            for row in attacked["candidates"]
            if row["status"] == "eligible_preserved_metadata_absent_from_v3"
        )
    )
    template["tenant_observed"] = "fabricated"
    template["tenant_compare_key"] = "fabricated"
    template["source_documents"] = ["/not/a/bound/input.json"]
    template["observation_records_sha256"] = "0" * 64
    attacked["candidates"].append(template)
    attacked["candidates"].sort(
        key=lambda row: (row["provider"], row["tenant_compare_key"])
    )
    attacked["candidate_count"] += 1
    attacked["eligible_preserved_tenant_count"] += 1
    attacked["eligible_preserved_tenants_absent_from_v3"].append(
        {
            "provider": template["provider"],
            "tenant_observed": template["tenant_observed"],
            "provider_api_host": template["provider_api_host"],
        }
    )
    attacked["eligible_preserved_tenants_absent_from_v3"].sort(
        key=lambda row: (row["provider"], row["tenant_observed"])
    )
    path = tmp_path / REPORT.name
    path.write_bytes(audit_module.canonical_bytes(attacked))
    with pytest.raises(
        audit_module.AuditFailure,
        match="does not reproduce",
    ):
        audit_module.validate_report(
            path,
            _digest(path),
            rerun=True,
        )


def test_tampered_bound_input_hash_fails_closed(
    audit_module: ModuleType,
    tmp_path: Path,
) -> None:
    path = tmp_path / "bound.json"
    path.write_text('{"tenant": "fabricated"}\n')
    with pytest.raises(
        audit_module.AuditFailure,
        match="bound input hash mismatch",
    ):
        audit_module._read_bound(path, "0" * 64)
