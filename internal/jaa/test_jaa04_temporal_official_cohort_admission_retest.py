"""Independent temporal admission retest for the JAA-04 official cohort."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from career_automation.official_cohort import VACANCY_FRESHNESS_DAYS, _temporal_admission
from career_automation.opportunity_calibration import (
    DECISION_RULE_VERSION, CalibrationPolicy, Confidence, Opportunity0Input,
    calibration_policy_json, decide_opportunity0,
)
from scraper.viability import Vacancy


ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / "scripts" / "capture_jaa_04.py"
AS_OF = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)


def _capture() -> Any:
    spec = importlib.util.spec_from_file_location("temporal_cohort_capture", CAPTURE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _response(stamp: datetime | None, *, malformed: bool = False) -> bytes:
    value = "not-a-date" if malformed else (stamp.isoformat() if stamp else "")
    metadata = f'<meta property="datePosted" content="{value}">' if value else ""
    return ("<html><head>" + metadata + "</head><body>Official vacancy detail.</body></html>").encode()


def _ref(raw_root: Path, body: bytes, *, observed_at: datetime = AS_OF,
         digest: str | None = None) -> dict[str, object]:
    actual = hashlib.sha256(body).hexdigest()
    digest = digest or actual
    relative = f"{actual[:2]}/{actual}.response"
    path = raw_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    url = "https://official.example.test/jobs/temporal"
    return {"sha256": digest, "raw_response": relative, "requested_url": url,
            "final_url": url, "response_url": url, "status": 200,
            "redirect_sequence": 0, "redirect_chain": [url],
            "observed_at": observed_at.isoformat()}


@pytest.mark.parametrize(
    ("body", "observed_at", "rehash", "expected"),
    [
        (_response(AS_OF - timedelta(days=45)), AS_OF, False, "publisher_time_current"),
        (_response(AS_OF - timedelta(days=45, seconds=1)), AS_OF, False, "publisher_time_stale"),
        (_response(AS_OF + timedelta(seconds=1)), AS_OF, False, "publisher_time_in_future"),
        (_response(None), AS_OF, False, "publisher_time_missing_or_malformed"),
        (_response(None, malformed=True), AS_OF, False, "publisher_time_missing_or_malformed"),
        # Receipt time is never a substitute for an absent publisher timestamp.
        (_response(None), AS_OF + timedelta(days=100), False, "publisher_time_missing_or_malformed"),
        # A rehashed attacker change is classified from its new bytes, not trusted as current.
        (_response(AS_OF - timedelta(days=46)), AS_OF, True, "publisher_time_stale"),
    ],
    ids=("exact-45-days", "45-days-plus-one-second", "future", "missing", "malformed",
         "retrieval-time-substitution", "attacker-rehashed-stale"),
)
def test_only_final_hash_verified_publisher_bytes_control_temporal_admission(
        tmp_path: Path, body: bytes, observed_at: datetime, rehash: bool, expected: str) -> None:
    raw_root = tmp_path / "raw"
    ref = _ref(raw_root, body, observed_at=observed_at)
    if rehash:
        # The changed bytes and matching digest simulate an attacker who rehashes every receipt field.
        ref["sha256"] = hashlib.sha256(body).hexdigest()
    decision = _temporal_admission([ref], raw_root, AS_OF)
    assert decision["reason"] == expected
    assert decision["admitted"] is (expected == "publisher_time_current")
    assert decision["freshness_days"] == VACANCY_FRESHNESS_DAYS == 45
    if decision["admitted"]:
        assert decision["publisher_date_evidence"] in body.decode()


def test_hash_mismatch_and_stale_but_still_listed_vacancy_cannot_enter_snapshot(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    stale = _response(AS_OF - timedelta(days=46))
    stale_ref = _ref(raw_root, stale, digest="0" * 64)
    mismatch = _temporal_admission([stale_ref], raw_root, AS_OF)
    listed_stale = _temporal_admission([_ref(raw_root, stale)], raw_root, AS_OF)
    assert mismatch["reason"] == "publisher_time_missing_or_malformed"
    assert listed_stale == {**listed_stale, "admitted": False, "reason": "publisher_time_stale"}


def _record(number: int, raw_root: Path, policy: CalibrationPolicy) -> dict[str, object]:
    key = f"greenhouse:current-{number:02d}"
    url = f"https://official.example.test/jobs/current-{number:02d}"
    body = (f"Official Software Engineer vacancy {number} in London, UK. "
            "Build secure Python cloud services with a collaborative platform team. " * 2)
    response = _response(AS_OF - timedelta(days=45))
    ref = _ref(raw_root, response)
    temporal = _temporal_admission([ref], raw_root, AS_OF)
    assert temporal["admitted"]
    vacancy = Vacancy(key=key, board="greenhouse", job_id=f"current-{number:02d}", url=url,
                      posted_at=AS_OF.date().isoformat(), raw_text=body, raw_json={},
                      title="Software Engineer", company=f"Official Employer {number}",
                      location="London, UK", body=body, expiry="")
    inputs, confidence = Opportunity0Input(8500, 8000, 9000), Confidence(9000, 9000, 9000, 9000)
    decision = vars(decide_opportunity0(inputs, confidence, viability_reason="viable", policy=policy))
    payload = vars(vacancy)
    payload_hash = hashlib.sha256(_json({"source_identity": key,
        "official_response_hashes": [ref["sha256"]], "vacancy": payload})).hexdigest()
    return {"job_key": key, "board": "greenhouse", "company": vacancy.company,
            "title": vacancy.title, "url": url, "payload_hash": payload_hash,
            "content_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "observed_at": ref["observed_at"],
            "source": {"identity": key, "adapter": "greenhouse",
                       "authority": "official-public-employer-or-ats"},
            "raw_response_refs": [ref], "payload": payload,
            "viability_decision": {"decision": "include", "reason": "viable"},
            "opportunity0_input": vars(inputs), "confidence": vars(confidence),
            "opportunity0_decision": decision, "temporal_admission": temporal}


def test_exact_30_byte_backed_current_snapshot_admits_and_bootstraps_without_temporal_overage(
        tmp_path: Path) -> None:
    policy, raw_root = CalibrationPolicy(), tmp_path / "raw"
    records = [_record(number, raw_root, policy) for number in range(30)]
    assert all(row["temporal_admission"]["admitted"] for row in records)
    assert all(datetime.fromisoformat(row["temporal_admission"]["publisher_time"]) >= AS_OF - timedelta(days=45)
               for row in records)
    envelope = {"schema_version": "jaa04.official-admitted-queue.v2", "records": records,
                "raw_store": {"root": str(raw_root)},
                "policy": {"identity": DECISION_RULE_VERSION, "hash": policy.policy_hash,
                           "parameters": calibration_policy_json(policy)}}
    envelope["records_hash"] = hashlib.sha256(_json(records)).hexdigest()
    snapshot = tmp_path / "official-cohort.json"
    snapshot.write_bytes(_json(envelope))
    capture = _capture()
    admitted = capture._admitted_input(snapshot)
    assert set(admitted) == {row["job_key"] for row in records}
    work_db = tmp_path / "queue.sqlite3"
    capture._bootstrap_json_database(work_db, records, policy)
    with sqlite3.connect(work_db) as connection:
        states = connection.execute("SELECT state FROM pipeline_jobs").fetchall()
    assert len(states) == 30
    assert {state for state, in states} == {"employer_research_queued"}
