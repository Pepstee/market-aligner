"""Independent boundary and interrupted-bootstrap retest for JAA-04."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from career_automation.database import CareerDatabase
from career_automation.engine import scored_job_from_payload
from career_automation.lifecycle import PipelineState, PolicyIdentity
from career_automation.opportunity_calibration import (
    CalibrationPolicy, Confidence, DECISION_RULE_VERSION, Opportunity0Input,
    calibration_policy_digest, calibration_policy_json, decide_opportunity0,
)
from scraper.viability import Vacancy


ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / "scripts" / "capture_jaa_04.py"


def _capture() -> Any:
    spec = importlib.util.spec_from_file_location("independent_jaa04_capture", CAPTURE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def _snapshot(tmp_path: Path) -> tuple[Path, list[dict[str, object]], CalibrationPolicy]:
    policy, today, root = CalibrationPolicy(), date.today().isoformat(), tmp_path / "raw"
    records: list[dict[str, object]] = []
    for number in range(30):
        board, job_id = ("greenhouse", f"official-{number:02d}")
        key, url = f"{board}:{job_id}", f"https://official.example.test/jobs/{job_id}"
        body = f"Official platform software engineering vacancy {number}; London UK; Python cloud services. " * 3
        response = _json({"key": key, "body": body})
        raw_hash = hashlib.sha256(response).hexdigest()
        rel = f"{raw_hash[:2]}/{raw_hash}.response"
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(response)
        vacancy = Vacancy(key=key, board=board, job_id=job_id, url=url, posted_at=today,
                          raw_text=body, raw_json={}, title="Software Engineer",
                          company=f"Official {number}", location="London, UK", body=body, expiry="")
        inputs, confidence = Opportunity0Input(8500, 8000, 9000), Confidence(9000, 9000, 9000, 9000)
        decision = vars(decide_opportunity0(inputs, confidence, policy=policy))
        payload = vars(vacancy)
        payload_hash = hashlib.sha256(_json({"source_identity": key,
            "official_response_hashes": [raw_hash], "vacancy": payload})).hexdigest()
        records.append({"job_key": key, "board": board, "company": vacancy.company,
            "title": vacancy.title, "url": url, "payload_hash": payload_hash,
            "content_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "observed_at": f"{today}T00:00:00+00:00",
            "source": {"identity": key, "adapter": board,
                       "authority": "official-public-employer-or-ats"},
            "raw_response_refs": [{"sha256": raw_hash, "raw_response": rel,
                "requested_url": url, "final_url": url, "response_url": url, "status": 200,
                "redirect_sequence": 0, "redirect_chain": [url],
                "observed_at": f"{today}T00:00:00+00:00"}], "payload": payload,
            "opportunity0_input": vars(inputs), "confidence": vars(confidence),
            "opportunity0_decision": decision})
    envelope = {"schema_version": "jaa04.official-admitted-queue.v2", "records": records,
        "records_hash": hashlib.sha256(_json(records)).hexdigest(), "raw_store": {"root": str(root)},
        "policy": {"identity": DECISION_RULE_VERSION, "hash": policy.policy_hash,
                   "parameters": calibration_policy_json(policy)}}
    path = tmp_path / "official.json"
    path.write_bytes(_json(envelope))
    return path, records, policy


def test_exact_official_snapshot_bootstraps_30_prefixed_records_with_digest_receipts(tmp_path: Path) -> None:
    snapshot, records, policy = _snapshot(tmp_path)
    capture, work_db = _capture(), tmp_path / "workspace" / "queue.sqlite3"
    assert set(capture._admitted_input(snapshot)) == {row["job_key"] for row in records}
    capture._bootstrap_json_database(work_db, records, policy)
    with sqlite3.connect(work_db) as conn:
        jobs = conn.execute("SELECT job_key,policy_hash,opportunity,opportunity_decision,opportunity_reason FROM pipeline_jobs").fetchall()
        queues = conn.execute("SELECT job_key FROM employer_research_queue").fetchall()
        receipts = conn.execute("SELECT job_key,policy_hash FROM lifecycle_transition_receipts WHERE policy_id='career.opportunity-gate'").fetchall()
        events = conn.execute("SELECT job_key FROM pipeline_events WHERE event_type='lifecycle_transition_committed'").fetchall()
    expected = {str(row["job_key"]) for row in records}
    assert {row[0] for row in jobs} == {row[0] for row in queues} == {row[0] for row in receipts} == expected
    assert len(jobs) == len(queues) == len(receipts) == len(events) == 30
    assert {row[1] for row in jobs} == {policy.policy_hash}
    assert {(row[0], round(row[2] * 10_000), row[3], row[4]) for row in jobs} == {
        (row["job_key"], row["opportunity0_decision"]["score_bp"],
         row["opportunity0_decision"]["decision"], row["opportunity0_decision"]["reason"])
        for row in records
    }
    assert {row[1] for row in receipts} == {calibration_policy_digest(policy.policy_hash, policy)}
    assert all(not row[1].startswith("sha256:") for row in receipts)


def test_interrupted_import_then_apply_retries_same_workspace_as_one_exact_cohort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, records, policy = _snapshot(tmp_path)
    capture, work_db = _capture(), tmp_path / "workspace" / "queue.sqlite3"
    original, calls = capture.CareerDatabase.apply_opportunity_result, 0

    def interrupt(database: CareerDatabase, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 11:
            raise InterruptedError("test interruption after import")
        original(database, **kwargs)

    monkeypatch.setattr(capture.CareerDatabase, "apply_opportunity_result", interrupt)
    with pytest.raises(InterruptedError):
        capture._bootstrap_json_database(work_db, records, policy)
    assert not work_db.exists()
    monkeypatch.setattr(capture.CareerDatabase, "apply_opportunity_result", original)
    capture._bootstrap_json_database(work_db, records, policy)
    with sqlite3.connect(work_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 30
        assert conn.execute("SELECT COUNT(*) FROM employer_research_queue").fetchone()[0] == 30
        assert conn.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts WHERE policy_id='career.opportunity-gate'").fetchone()[0] == 30
        assert conn.execute("SELECT COUNT(*) FROM pipeline_events WHERE event_type='lifecycle_transition_committed'").fetchone()[0] == 30
        assert conn.execute("SELECT COUNT(*) FROM pipeline_jobs WHERE opportunity_decision!='pass' OR state!='employer_research_queued'").fetchone()[0] == 0


def test_policy_identity_boundary_rejects_noncanonical_and_wrong_prefixed_values(tmp_path: Path) -> None:
    policy, digest = CalibrationPolicy(), CalibrationPolicy().policy_hash[7:]
    invalid = (digest, "SHA256:" + digest, "sha256:" + digest.upper(),
               "sha256:" + digest[:-1], "sha256:" + "g" * 64,
               CalibrationPolicy(minimum_confidence_bp=7600).policy_hash)
    for identity in invalid:
        with pytest.raises(ValueError):
            calibration_policy_digest(identity, policy)
    database = CareerDatabase(tmp_path / "ledger.sqlite3")
    job = scored_job_from_payload({"board": "official", "job_id": "one", "url": "https://example.test/one",
        "job_title": "Engineer", "company": "Example", "opportunity": 0.9, "extraction_confidence": 0.9})
    database.upsert_scored_job(job)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        database.lifecycle.commit(job_key=job.key, to_state=PipelineState.EMPLOYER_RESEARCH_QUEUED,
            policy=PolicyIdentity("independent", "1", policy.policy_hash), inputs={}, outputs={}, idempotency_key="prefixed-is-not-ledger-digest")
