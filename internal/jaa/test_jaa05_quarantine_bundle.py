"""Package 019 combined failed-cycle quarantine controls."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from career_automation.holdout_firewall import (
    HoldoutFirewallFailure,
    load_acquisition_quarantine_index,
    load_quarantine_bundle,
    load_quarantine_index,
    validate_post_acquisition_holdout,
    validate_quarantine_binding,
)
from career_automation.official_cohort import (
    _select_candidates,
    _validate_package019_supply_config,
    build,
)
from skeleton.configuration import load_config


ROOT = Path(__file__).resolve().parent
CONTROL = Path(
    "/home/gutua/software-factory/.control/resumed-dual-lane-20260728/"
    "jaa/jaa05-next-cycle"
)
SEALED_EVIDENCE = Path(
    "/home/gutua/software-factory/.control/resumed-dual-lane-20260728/"
    "jaa/runtime/fresh-jaa05-holdout-v1-0c90c73/capture-evidence.json"
)
OLD = CONTROL / "failed-holdout-quarantine-index.json"
ACQUISITION = CONTROL / "failed-cycle-acquisition-quarantine-index.json"
BUNDLE = CONTROL / "combined-quarantine-bundle.json"
FAILURE = CONTROL / "official-cohort-failure-v1-0c90c73.json"
BUILDER = CONTROL / "build_failed_cycle_acquisition_quarantine_index.py"
V4 = CONTROL / "authorized-production-config-v4-proposal.yaml"
ACQUISITION_SHA = "a6cb70d876a4fa54089212ff7332be26dd121c8fa64eaf344783fadd69f93a41"
BUNDLE_SHA = "ad380445efd62019fe970ee1d775e48a5e5f58639bd385823e31780547f1a6c4"
OLD_SHA = "00352f85941456d0ca3893b9e6855f3806e6e4ae5031d6ac7a42b615dfbc76b0"


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        + b"\n"
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _candidate(number: int) -> dict[str, Any]:
    return {
        "job_key": f"greenhouse:new:{number}",
        "url": f"https://jobs.example.test/{number}",
        "content_sha256": _digest(f"new-content-{number}"),
        "payload_hash": _digest(f"new-payload-{number}"),
        "opportunity0_decision": {"score_bp": 10_000 - number},
        "temporal_admission": {"publisher_time": "2026-07-28T00:00:00Z"},
        "raw_response_refs": [{"sha256": _digest(f"response-{number}")}],
    }


def _copy_bundle(tmp_path: Path) -> tuple[Path, str]:
    shutil.copyfile(OLD, tmp_path / OLD.name)
    shutil.copyfile(ACQUISITION, tmp_path / ACQUISITION.name)
    target = tmp_path / BUNDLE.name
    shutil.copyfile(BUNDLE, target)
    return target, hashlib.sha256(target.read_bytes()).hexdigest()


def test_authorised_bundle_loads_and_covers_all_57_trace_rows() -> None:
    bundle = load_quarantine_bundle(BUNDLE, BUNDLE_SHA)
    assert bundle.acquisition_index.entry_count == 57
    assert len(bundle.acquisition_index.job_keys) == 57
    assert len(bundle.acquisition_index.payload_hashes) == 57
    assert len(bundle.acquisition_index.content_hashes) == 49
    assert len(bundle.acquisition_index.canonical_url_hashes) == 54
    assert len(bundle.job_keys) == 57
    assert len(bundle.payload_hashes) == 82
    assert bundle.requirement_index.sha256 == OLD_SHA


def test_trace_overlap_cross_checks_match_the_terminal_failure() -> None:
    trace = json.loads(SEALED_EVIDENCE.read_text())["selection_trace"]
    old = load_quarantine_index(OLD, OLD_SHA)
    selected = [row for row in trace if row["disposition"] == "selected"]
    previously_quarantined = [
        row for row in trace
        if row["disposition"] == "quarantined_job_key"
    ]
    assert not old.job_keys.intersection(row["job_key"] for row in selected)
    assert not old.payload_hashes.intersection(
        row["payload_hash"] for row in selected
    )
    assert {
        row["job_key"] for row in previously_quarantined
    }.issubset(old.job_keys)


def test_builder_is_byte_deterministic_and_uses_all_trace_rows(
    tmp_path: Path,
) -> None:
    spec = importlib.util.spec_from_file_location("package019_builder", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    outputs = []
    for number in range(2):
        run = tmp_path / str(number)
        run.mkdir()
        index = run / ACQUISITION.name
        bundle = run / BUNDLE.name
        module.build(SEALED_EVIDENCE, FAILURE, index, bundle)
        outputs.append((index.read_bytes(), bundle.read_bytes()))
    assert outputs[0] == outputs[1]
    assert hashlib.sha256(outputs[0][0]).hexdigest() == ACQUISITION_SHA
    document = json.loads(outputs[0][0])
    assert document["entry_count"] == len(document["entries"]) == 57


def test_cross_schema_loaders_fail_closed() -> None:
    with pytest.raises(HoldoutFirewallFailure, match="schema differs"):
        load_quarantine_index(ACQUISITION, ACQUISITION_SHA)
    with pytest.raises(HoldoutFirewallFailure, match="schema differs"):
        load_acquisition_quarantine_index(OLD, OLD_SHA)


@pytest.mark.parametrize(
    "attack",
    ("wrong_sha", "missing", "extra", "reordered", "noncanonical"),
)
def test_bundle_member_and_byte_tampering_fails_closed(
    tmp_path: Path,
    attack: str,
) -> None:
    path, _ = _copy_bundle(tmp_path)
    document = json.loads(path.read_text())
    if attack == "wrong_sha":
        document["members"][1]["sha256"] = "0" * 64
        path.write_bytes(_canonical(document))
    elif attack == "missing":
        (tmp_path / ACQUISITION.name).unlink()
    elif attack == "extra":
        document["members"].append(copy.deepcopy(document["members"][1]))
        path.write_bytes(_canonical(document))
    elif attack == "reordered":
        document["members"].reverse()
        path.write_bytes(_canonical(document))
    else:
        path.write_bytes(path.read_bytes() + b" ")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(HoldoutFirewallFailure):
        load_quarantine_bundle(path, digest)


def test_acquisition_requirement_field_fabrication_fails_closed(
    tmp_path: Path,
) -> None:
    document = json.loads(ACQUISITION.read_text())
    document["entries"][0]["requirement_id"] = "fabricated"
    path = tmp_path / ACQUISITION.name
    path.write_bytes(_canonical(document))
    with pytest.raises(HoldoutFirewallFailure, match="forbidden fields"):
        load_acquisition_quarantine_index(
            path,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )


def test_acquisition_sealed_root_is_bound_without_shipping_host_path(
    tmp_path: Path,
) -> None:
    document = json.loads(ACQUISITION.read_text())
    document["derived_from"]["sealed_root"] = "/different/control/root"
    path = tmp_path / ACQUISITION.name
    path.write_bytes(_canonical(document))
    with pytest.raises(HoldoutFirewallFailure, match="sealed-root binding"):
        load_acquisition_quarantine_index(
            path,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )


def test_runtime_union_excludes_all_four_acquisition_identity_classes() -> None:
    bundle = load_quarantine_bundle(BUNDLE, BUNDLE_SHA)
    trace = json.loads(SEALED_EVIDENCE.read_text())["selection_trace"]
    candidates = [_candidate(number) for number in range(34)]
    candidates[0]["job_key"] = next(iter(bundle.job_keys))
    candidates[1]["payload_hash"] = next(iter(bundle.payload_hashes))
    candidates[2]["content_sha256"] = next(iter(bundle.content_hashes))
    candidates[3]["url"] = trace[0]["canonical_url"]
    selected, audit = _select_candidates(candidates, bundle)
    assert len(selected) == 30
    assert [row["disposition"] for row in audit[:4]] == [
        "quarantined_job_key",
        "quarantined_payload_hash",
        "quarantined_content_hash",
        "quarantined_canonical_url_hash",
    ]
    assert all(row["quarantine_bundle_sha256"] == BUNDLE_SHA for row in audit)


def test_bundle_binding_and_post_extraction_roles_are_distinct() -> None:
    bundle = load_quarantine_bundle(BUNDLE, BUNDLE_SHA)
    binding = {"failed_holdout_quarantine_bundle": bundle.binding()}
    validate_quarantine_binding(binding, bundle, label="capture evidence")
    text = "A genuinely fresh requirement."
    body = f"Intro. {text} End."
    start = body.index(text)
    dossier = {
        "job_key": "greenhouse:genuinely-fresh:1",
        "payload_hash": _digest("genuinely-fresh-payload"),
        "content_sha256": _digest(body),
        "canonical_url": "https://jobs.example.test/genuinely-fresh/1",
        "viability_decision": {"decision": "include"},
        "opportunity0_decision": {"decision": "pass"},
        "temporal_admission": {"admitted": True},
        "payload": {"body": body},
    }
    requirement = {
        "requirement_id": "genuinely-fresh-requirement",
        "job_key": dossier["job_key"],
        "payload_hash": dossier["payload_hash"],
        "source_span": [start, start + len(text)],
        "text": text,
    }
    receipt = validate_post_acquisition_holdout(
        [dossier],
        [requirement],
        bundle,
        required_dossiers=1,
    )
    assert receipt["failed_holdout_quarantine_bundle"] == bundle.binding()
    attacked = copy.deepcopy(requirement)
    attacked["requirement_id"] = next(iter(bundle.requirement_ids))
    with pytest.raises(HoldoutFirewallFailure, match="requirement ID reused"):
        validate_post_acquisition_holdout(
            [dossier],
            [attacked],
            bundle,
            required_dossiers=1,
        )


def test_legacy_cli_flags_are_rejected_before_acquisition(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(ROOT / "scripts/build_jaa04_official_cohort.py"),
            "--config",
            str(V4),
            "--output",
            str(tmp_path / "queue.json"),
            "--raw-root",
            str(tmp_path / "raw"),
            "--evidence-output",
            str(tmp_path / "evidence.json"),
            "--access-policy",
            str(
                Path(
                    "/home/gutua/software-factory/.control/"
                    "jaa-12h-supervisor-20260727/runtime/"
                    "recruitee-authority-provenance-v1/"
                    "public-access-policy-17-host-v2.json"
                )
            ),
            "--quarantine-bundle",
            str(BUNDLE),
            "--quarantine-bundle-sha256",
            BUNDLE_SHA,
            "--quarantine-index",
            str(OLD),
            "--quarantine-index-sha256",
            OLD_SHA,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "unrecognized arguments" in result.stderr


def test_proposal_only_config_fails_before_journal_or_access(tmp_path: Path) -> None:
    controller = SimpleNamespace(
        policy=SimpleNamespace(policy_sha256="1" * 64),
    )
    with pytest.raises(RuntimeError, match="proposal-only"):
        build(
            V4,
            tmp_path / "queue.json",
            tmp_path / "raw",
            quarantine_index=load_quarantine_bundle(BUNDLE, BUNDLE_SHA),
            access_controller=controller,
        )
    assert not (tmp_path / "raw").exists()
    assert not (tmp_path / "request-journal.jsonl").exists()


def test_config_v4_mechanically_exhausts_preserved_metadata_without_claiming_supply() -> None:
    proposal = yaml.safe_load(V4.read_text())
    resolved_v3 = load_config(
        Path(
            "/home/gutua/software-factory/.control/"
            "jaa-12h-supervisor-20260727/runtime/"
            "ats-search-index-discovery-recovery-v1/"
            "authorized-production-config-v3-proposal.yaml"
        )
    )
    metadata = json.loads(
        Path(
            "/home/gutua/software-factory/.control/"
            "jaa-12h-supervisor-20260727/runtime/"
            "ats-search-index-discovery-recovery-v1/result.json"
        ).read_text()
    )["proposal_only_unactivated"]
    absent = {
        provider: sorted(
            set(tenants) - set(resolved_v3[provider]["companies"])
        )
        for provider, tenants in metadata.items()
    }
    assert absent == {"greenhouse": [], "lever": []}
    derivation = proposal["package_019_supply_derivation"]
    assert proposal["execution_authorized"] is False
    assert derivation["executable_tenants_added"] == []
    assert derivation["inactive_pending_human_terms_review"] == []
    assert derivation["proves_live_availability"] is False
    report = json.loads(
        (CONTROL / "config-v4-offline-capacity-report.json").read_text()
    )
    assert report["capacity"]["new_tenant_headroom_from_preserved_metadata"] == 0
    assert report["capacity"]["offline_capacity_sufficient_for_another_live_gate"] is False
    assert report["proves_live_availability"] is False


def test_package019_tenants_cannot_bypass_exact_host_terms_authority() -> None:
    active = {
        "package_019_supply_derivation": {
            "executable_tenants_added": [{
                "provider": "personio",
                "tenant": "unreviewed",
                "api_host": "unreviewed.jobs.personio.test",
            }],
            "inactive_pending_human_terms_review": [],
        }
    }
    with pytest.raises(RuntimeError, match="lacks exact host attestation"):
        _validate_package019_supply_config(
            active,
            {"boards-api.greenhouse.io"},
        )
    inactive = copy.deepcopy(active)
    block = inactive["package_019_supply_derivation"]
    block["executable_tenants_added"] = []
    block["inactive_pending_human_terms_review"] = [{
        "api_host": "unreviewed.test",
        "executable": True,
    }]
    with pytest.raises(RuntimeError, match="must remain inactive"):
        _validate_package019_supply_config(inactive, set())
