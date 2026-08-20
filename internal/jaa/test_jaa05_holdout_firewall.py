"""Package 017 fail-closed fresh-holdout contamination controls."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from career_automation.holdout_firewall import (
    HoldoutFirewallFailure,
    QuarantineIndex,
    load_quarantine_index,
    validate_post_acquisition_holdout,
    validate_quarantine_binding,
)
from career_automation.official_cohort import _select_candidates


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _identity(
    job_key: str,
    payload_hash: str,
    span: list[int],
    text_hash: str,
) -> str:
    value = {
        "job_key": job_key,
        "payload_hash": payload_hash,
        "source_span": span,
        "source_text_sha256": text_hash,
    }
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _index_document() -> dict[str, Any]:
    entries = []
    for number in range(2):
        job_key = f"greenhouse:failed:{number}"
        payload_hash = _digest(f"failed-payload-{number}")
        text_hash = _digest(f"failed text {number}")
        span = [number, number + 1]
        entries.append({
            "requirement_id": f"failed-requirement-{number}",
            "job_key": job_key,
            "payload_hash": payload_hash,
            "source_span": span,
            "source_text_sha256": text_hash,
            "source_identity_sha256": _identity(
                job_key,
                payload_hash,
                span,
                text_hash,
            ),
        })
    return {
        "schema_version": "jaa05.failed-holdout-quarantine-index.v1",
        "authority": {
            "corrected_terminal_ruling_wrapper_sha256": _digest("ruling"),
            "verdict": "REJECT_JAA05_CALIBRATION",
        },
        "failed_holdout_sha256": _digest("failed-holdout"),
        "failed_queue_sha256": _digest("failed-queue"),
        "decision_fields_included": False,
        "rationales_included": False,
        "source_text_included": False,
        "entry_count": len(entries),
        "job_keys": sorted({row["job_key"] for row in entries}),
        "payload_hashes": sorted({row["payload_hash"] for row in entries}),
        "source_text_sha256": sorted(
            {row["source_text_sha256"] for row in entries}
        ),
        "source_identity_sha256": sorted(
            {row["source_identity_sha256"] for row in entries}
        ),
        "entries": entries,
        "purpose": (
            "Disjointness enforcement only. This index may not be used for "
            "prompt, model, label, threshold or scoring-rule tuning."
        ),
    }


def _write_index(path: Path, document: dict[str, Any]) -> tuple[Path, str]:
    raw = (
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        + b"\n"
    )
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def _quarantine(tmp_path: Path) -> QuarantineIndex:
    path, digest = _write_index(tmp_path / "quarantine.json", _index_document())
    return load_quarantine_index(path, digest)


def _candidate(number: int) -> dict[str, Any]:
    return {
        "job_key": f"greenhouse:fresh:{number:02d}",
        "url": f"https://jobs.example.test/fresh/{number:02d}",
        "content_sha256": _digest(f"content-{number}"),
        "payload_hash": _digest(f"payload-{number}"),
        "opportunity0_decision": {"score_bp": 10_000 - number},
        "temporal_admission": {
            "publisher_time": "2026-07-28T00:00:00+00:00",
        },
        "raw_response_refs": [{"sha256": _digest(f"response-{number}")}],
    }


def _holdout() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    dossiers: list[dict[str, Any]] = []
    requirements: list[dict[str, Any]] = []
    for number in range(30):
        job_key = f"greenhouse:fresh:{number:02d}"
        text = f"Fresh requirement text {number}"
        body = f"Intro {number}. {text}. Closing."
        start = body.index(text)
        payload_hash = _digest(f"fresh-payload-{number}")
        dossiers.append({
            "job_key": job_key,
            "payload_hash": payload_hash,
            "content_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "viability_decision": {"decision": "include"},
            "opportunity0_decision": {"decision": "pass"},
            "temporal_admission": {"admitted": True},
            "payload": {"body": body},
        })
        requirements.append({
            "requirement_id": f"fresh-requirement-{number:02d}",
            "job_key": job_key,
            "payload_hash": payload_hash,
            "source_span": [start, start + len(text)],
            "text": text,
        })
    return dossiers, requirements


def test_valid_canonical_index_loads_and_binds_exact_bytes(tmp_path: Path) -> None:
    quarantine = _quarantine(tmp_path)
    assert quarantine.entry_count == 2
    assert len(quarantine.job_keys) == 2
    assert quarantine.binding()["sha256"] == quarantine.sha256
    assert quarantine.binding()["selection_use"] == "exclusion_only"


def test_missing_index_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(HoldoutFirewallFailure, match="missing or unreadable"):
        load_quarantine_index(tmp_path / "absent.json", _digest("absent"))


@pytest.mark.parametrize(
    ("attack", "message"),
    (
        ("malformed", "not valid JSON"),
        ("decision_field", "top-level schema differs"),
        ("source_text_field", "entry schema differs"),
        ("noncanonical", "bytes are not canonical"),
    ),
)
def test_malformed_or_decision_bearing_index_fails_closed(
    tmp_path: Path,
    attack: str,
    message: str,
) -> None:
    document = _index_document()
    path = tmp_path / f"{attack}.json"
    if attack == "malformed":
        raw = b"{"
    elif attack == "decision_field":
        document["decision"] = "matched"
        raw = (
            json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
    elif attack == "source_text_field":
        document["entries"][0]["source_text"] = "leaked source"
        raw = (
            json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
    else:
        raw = json.dumps(document, sort_keys=True).encode("utf-8")
    path.write_bytes(raw)
    with pytest.raises(HoldoutFirewallFailure, match=message):
        load_quarantine_index(path, hashlib.sha256(raw).hexdigest())


def test_quarantine_index_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    path, _ = _write_index(tmp_path / "quarantine.json", _index_document())
    with pytest.raises(HoldoutFirewallFailure, match="SHA-256 mismatch"):
        load_quarantine_index(path, _digest("wrong"))


def test_selection_excludes_job_and_payload_before_exact_30_cut(
    tmp_path: Path,
) -> None:
    quarantine = _quarantine(tmp_path)
    candidates = [_candidate(number) for number in range(32)]
    candidates[0]["job_key"] = sorted(quarantine.job_keys)[0]
    candidates[1]["payload_hash"] = sorted(quarantine.payload_hashes)[0]
    selected, trace = _select_candidates(candidates, quarantine)
    assert len(selected) == 30
    assert trace[0]["disposition"] == "quarantined_job_key"
    assert trace[1]["disposition"] == "quarantined_payload_hash"
    assert all(
        row["quarantine_index_sha256"] == quarantine.sha256
        for row in trace
    )
    assert not quarantine.job_keys.intersection(
        row["job_key"] for row in selected
    )
    assert not quarantine.payload_hashes.intersection(
        row["payload_hash"] for row in selected
    )


def test_post_acquisition_firewall_accepts_exactly_30_disjoint_dossiers(
    tmp_path: Path,
) -> None:
    quarantine = _quarantine(tmp_path)
    dossiers, requirements = _holdout()
    receipt = validate_post_acquisition_holdout(
        dossiers,
        requirements,
        quarantine,
    )
    assert receipt["result"] == "PASS"
    assert receipt["dossier_count"] == 30
    assert receipt["requirement_count"] == 30
    assert len(receipt["per_dossier"]) == 30
    assert receipt["failed_holdout_quarantine"] == quarantine.binding()
    assert len(receipt["receipt_sha256"]) == 64


@pytest.mark.parametrize(
    ("attack", "message"),
    (
        ("job", "job key reused"),
        ("payload", "payload reused"),
        ("requirement", "requirement ID reused"),
        ("text", "source text reused"),
        ("identity", "source identity reused"),
        ("below_floor", "exactly 30 dossiers"),
        ("duplicate_job", "job keys must be non-empty and unique"),
        ("duplicate_payload", "payload duplicated"),
        ("duplicate_content", "content duplicated"),
        ("ineligible", "not viability-eligible"),
        ("uncovered_dossier", "every holdout dossier"),
    ),
)
def test_post_acquisition_overlap_and_cardinality_controls_fail_closed(
    tmp_path: Path,
    attack: str,
    message: str,
) -> None:
    quarantine = _quarantine(tmp_path)
    dossiers, requirements = _holdout()
    if attack == "job":
        dossiers[0]["job_key"] = sorted(quarantine.job_keys)[0]
        requirements[0]["job_key"] = dossiers[0]["job_key"]
    elif attack == "payload":
        dossiers[0]["payload_hash"] = sorted(quarantine.payload_hashes)[0]
        requirements[0]["payload_hash"] = dossiers[0]["payload_hash"]
    elif attack == "requirement":
        requirements[0]["requirement_id"] = sorted(quarantine.requirement_ids)[0]
    elif attack == "text":
        text = requirements[0]["text"]
        quarantine = QuarantineIndex(
            **{
                **quarantine.__dict__,
                "source_text_sha256": frozenset({
                    hashlib.sha256(text.encode("utf-8")).hexdigest()
                }),
            }
        )
    elif attack == "identity":
        requirement = requirements[0]
        text_hash = hashlib.sha256(requirement["text"].encode("utf-8")).hexdigest()
        identity = _identity(
            requirement["job_key"],
            requirement["payload_hash"],
            requirement["source_span"],
            text_hash,
        )
        quarantine = QuarantineIndex(
            **{
                **quarantine.__dict__,
                "source_identity_sha256": frozenset({identity}),
            }
        )
    elif attack == "below_floor":
        dossiers.pop()
        requirements.pop()
    elif attack == "duplicate_job":
        dossiers[1]["job_key"] = dossiers[0]["job_key"]
    elif attack == "duplicate_payload":
        dossiers[1]["payload_hash"] = dossiers[0]["payload_hash"]
    elif attack == "duplicate_content":
        dossiers[1]["content_sha256"] = dossiers[0]["content_sha256"]
    elif attack == "ineligible":
        dossiers[0]["viability_decision"]["decision"] = "exclude"
    else:
        requirements.pop()

    with pytest.raises(HoldoutFirewallFailure, match=message):
        validate_post_acquisition_holdout(
            dossiers,
            requirements,
            quarantine,
        )


def test_requirement_source_binding_mismatch_fails_closed(tmp_path: Path) -> None:
    quarantine = _quarantine(tmp_path)
    dossiers, requirements = _holdout()
    requirements[0]["text"] = "fabricated replacement"
    with pytest.raises(HoldoutFirewallFailure, match="source binding differs"):
        validate_post_acquisition_holdout(dossiers, requirements, quarantine)


def test_evidence_or_output_omission_of_quarantine_binding_fails_closed(
    tmp_path: Path,
) -> None:
    quarantine = _quarantine(tmp_path)
    valid = {"failed_holdout_quarantine": quarantine.binding()}
    validate_quarantine_binding(valid, quarantine, label="capture evidence")
    for attacked in ({}, {"failed_holdout_quarantine": {
        **quarantine.binding(),
        "sha256": _digest("substituted"),
    }}):
        with pytest.raises(HoldoutFirewallFailure, match="omits or changes"):
            validate_quarantine_binding(
                copy.deepcopy(attacked),
                quarantine,
                label="capture evidence",
            )
