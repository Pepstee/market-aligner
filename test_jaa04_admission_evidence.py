"""Portable Opportunity-0 admission evidence publication controls."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from career_automation.admission_evidence import (
    publish_admission_evidence,
    raw_evidence_hash,
    source_snapshot_hash,
    validate_admission_evidence,
)
from career_automation.public_access import (
    PublicAccessPolicy,
    RobotsReceipt,
    TermsAttestation,
    USER_AGENT,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _json_evidence(tmp_path: Path):
    raw = tmp_path / "external-raw"
    page = b"official vacancy bytes"
    robots = b"User-agent: *\nAllow: /\n"
    page_hash = hashlib.sha256(page).hexdigest()
    robots_hash = hashlib.sha256(robots).hexdigest()
    page_ref = Path("sha256") / page_hash[:2] / page_hash
    robots_ref = Path("sha256") / robots_hash[:2] / robots_hash
    for relative, body in ((page_ref, page), (robots_ref, robots)):
        target = raw / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    stamp = "2026-07-26T00:00:00+00:00"
    attestation = TermsAttestation(
        host="jobs.example.test",
        terms_url="https://jobs.example.test/terms",
        determination="public_read_only_research_permitted",
        reviewed_at="2026-07-25T00:00:00+00:00",
        reviewed_by="Offline Test Operator",
        reviewer_type="human_operator",
        notes="Synthetic offline fixture; not production authority.",
    )
    policy_hash = hashlib.sha256(b"synthetic-policy-bytes").hexdigest()
    policy = PublicAccessPolicy(
        {attestation.host: attestation},
        policy_sha256=policy_hash,
        now=datetime(2026, 7, 26, tzinfo=timezone.utc),
    )
    access = asdict(RobotsReceipt(
        host=attestation.host,
        robots_url="https://jobs.example.test/robots.txt",
        final_url="https://jobs.example.test/robots.txt",
        status_code=200,
        content_sha256=robots_hash,
        raw_response_ref=robots_ref.as_posix(),
        redirect_history=[],
        retrieved_at=stamp,
        user_agent=USER_AGENT,
        requested_url="https://jobs.example.test/1",
        allowed=True,
        crawl_delay_seconds=10.0,
        terms_policy_sha256=policy_hash,
        terms_attestation=asdict(attestation),
    ))
    raw_refs = [{
        "sha256": page_hash,
        "raw_response": page_ref.as_posix(),
        "requested_url": "https://jobs.example.test/1",
        "final_url": "https://jobs.example.test/1",
        "redirect_chain": ["https://jobs.example.test/1"],
        "observed_at": stamp,
        "access_receipt": access,
    }]
    source_record = {
        "job_key": "greenhouse:example:1",
        "url": "https://jobs.example.test/1",
        "company": "Example",
        "title": "Platform Engineer",
        "payload_hash": "payload-hash",
        "opportunity0_input": {
            "market_demand_bp": 9000,
            "role_quality_bp": 8500,
            "application_accessibility_bp": 9000,
        },
        "confidence": {
            "vacancy_completeness_bp": 9000,
            "market_demand_bp": 9000,
            "role_quality_bp": 9000,
            "application_accessibility_bp": 9000,
        },
        "opportunity0_decision": {
            "score_bp": 8750,
            "decision": "pass",
            "reason": "viable",
            "policy_hash": "policy-hash",
        },
        "source": {
            "identity": "greenhouse:example:1",
            "adapter": "greenhouse",
            "authority": "official-public-employer-or-ats",
        },
        "observed_at": stamp,
        "raw_response_refs": raw_refs,
    }
    snapshot = tmp_path / "queue.json"
    snapshot_payload = {
        "schema_version": "jaa04.official-admitted-queue.v2",
        "raw_store": {"root": str(raw)},
        "records": [source_record],
        "records_hash": hashlib.sha256(_canonical([source_record])).hexdigest(),
    }
    snapshot.write_bytes(_canonical(snapshot_payload))
    manifest_record = {
        "job_key": source_record["job_key"],
        "vacancy_url": source_record["url"],
        "company": source_record["company"],
        "role": source_record["title"],
        "admitted_payload_hash": source_record["payload_hash"],
        "opportunity0_input": source_record["opportunity0_input"],
        "opportunity0_confidence": source_record["confidence"],
        "opportunity0_decision": source_record["opportunity0_decision"],
        "opportunity0_source": source_record["source"],
        "opportunity0_observed_at": source_record["observed_at"],
        "opportunity0_raw_response_refs": raw_refs,
        "opportunity1_reassessment": {"opportunity0_score_bp": 8750},
    }
    return snapshot, source_record, manifest_record, {policy_hash: policy}


def test_json_admission_snapshot_and_only_referenced_raw_bytes_are_portable(
    tmp_path: Path,
) -> None:
    snapshot, source, manifest, policies = _json_evidence(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    descriptor = publish_admission_evidence(snapshot, [source], stage)
    expected_snapshot_hash = hashlib.sha256(
        (stage / "admission/queue_snapshot.json").read_bytes()
    ).hexdigest()
    assert descriptor["mode"] == "official-json-v2"
    assert descriptor["source_snapshot_sha256"] == descriptor["snapshot_sha256"]
    assert len(descriptor["referenced_files"]) == 2
    validate_admission_evidence(
        stage,
        descriptor,
        [manifest],
        expected_snapshot_sha256=expected_snapshot_hash,
        access_policies=policies,
    )
    assert raw_evidence_hash(stage) != hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize(
    "attack",
    ("snapshot", "raw", "extra", "manifest-ref", "descriptor-hash"),
)
def test_json_admission_tampering_fails_closed(
    tmp_path: Path,
    attack: str,
) -> None:
    snapshot, source, manifest, policies = _json_evidence(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    descriptor = publish_admission_evidence(snapshot, [source], stage)
    if attack == "snapshot":
        (stage / descriptor["snapshot_path"]).write_bytes(b"changed")
    elif attack == "raw":
        relative = descriptor["referenced_files"][0]["path"]
        (stage / "admission/raw" / relative).write_bytes(b"changed")
    elif attack == "extra":
        (stage / "admission/raw/extra").write_bytes(b"extra")
    elif attack == "manifest-ref":
        manifest["opportunity0_raw_response_refs"][0]["sha256"] = "0" * 64
    else:
        descriptor["referenced_files_hash"] = "0" * 64
    with pytest.raises(ValueError):
        validate_admission_evidence(
            stage,
            descriptor,
            [manifest],
            expected_snapshot_sha256=descriptor["snapshot_sha256"],
            access_policies=policies,
        )


@pytest.mark.parametrize(
    "attack",
    (
        "vacancy",
        "company",
        "role",
        "input",
        "confidence",
        "decision",
        "source",
        "observed-at",
        "opportunity-score",
    ),
)
def test_json_admission_binds_complete_opportunity0_authority(
    tmp_path: Path,
    attack: str,
) -> None:
    snapshot, source, manifest, policies = _json_evidence(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    descriptor = publish_admission_evidence(snapshot, [source], stage)
    if attack == "vacancy":
        manifest["vacancy_url"] = "https://jobs.example.test/substituted"
    elif attack == "company":
        manifest["company"] = "Substituted Employer"
    elif attack == "role":
        manifest["role"] = "Substituted Role"
    elif attack == "input":
        manifest["opportunity0_input"] = {"market_demand_bp": 1000}
    elif attack == "confidence":
        manifest["opportunity0_confidence"] = {"vacancy_completeness_bp": 1000}
    elif attack == "decision":
        manifest["opportunity0_decision"] = {
            **manifest["opportunity0_decision"],
            "reason": "substituted",
        }
    elif attack == "source":
        manifest["opportunity0_source"] = {
            **manifest["opportunity0_source"],
            "identity": "substituted:identity",
        }
    elif attack == "observed-at":
        manifest["opportunity0_observed_at"] = "2020-01-01T00:00:00+00:00"
    else:
        manifest["opportunity1_reassessment"]["opportunity0_score_bp"] = 1000
    with pytest.raises(ValueError, match="JSON snapshot|admission|Opportunity-0"):
        validate_admission_evidence(
            stage,
            descriptor,
            [manifest],
            expected_snapshot_sha256=descriptor["snapshot_sha256"],
            access_policies=policies,
        )


def test_json_admission_rejects_duplicate_snapshot_job_keys(tmp_path: Path) -> None:
    snapshot, source, manifest, policies = _json_evidence(tmp_path)
    payload = json.loads(snapshot.read_text(encoding="utf-8"))
    payload["records"].append(json.loads(json.dumps(source)))
    payload["records_hash"] = hashlib.sha256(
        _canonical(payload["records"])
    ).hexdigest()
    snapshot.write_bytes(_canonical(payload))
    stage = tmp_path / "stage"
    stage.mkdir()
    descriptor = publish_admission_evidence(snapshot, [source], stage)
    with pytest.raises(ValueError, match="duplicate|identity|snapshot"):
        validate_admission_evidence(
            stage,
            descriptor,
            [manifest],
            expected_snapshot_sha256=descriptor["snapshot_sha256"],
            access_policies=policies,
        )


def test_sqlite_admission_uses_consistent_backup_and_replays_passed_keys(
    tmp_path: Path,
) -> None:
    source = tmp_path / "queue.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """CREATE TABLE pipeline_jobs(
                 job_key TEXT PRIMARY KEY,url TEXT,company TEXT,title TEXT,
                 payload_hash TEXT,opportunity REAL,opportunity_decision TEXT
               )"""
        )
        connection.execute(
            "CREATE TABLE employer_research_queue(job_key TEXT PRIMARY KEY)"
        )
        connection.execute(
            """INSERT INTO pipeline_jobs VALUES(
                 'greenhouse:example:1','https://jobs.example.test/1','Example',
                 'Platform Engineer','payload-sha',0.9,'pass'
               )"""
        )
        connection.execute(
            "INSERT INTO employer_research_queue VALUES('greenhouse:example:1')"
        )
    stage = tmp_path / "stage"
    stage.mkdir()
    descriptor = publish_admission_evidence(
        source,
        [{"job_key": "greenhouse:example:1"}],
        stage,
    )
    assert descriptor["mode"] == "sqlite-lifecycle-snapshot"
    expected_snapshot_hash = hashlib.sha256(
        (stage / "admission/queue_snapshot.sqlite3").read_bytes()
    ).hexdigest()
    validate_admission_evidence(
        stage,
        descriptor,
        [{
            "job_key": "greenhouse:example:1",
            "vacancy_url": "https://jobs.example.test/1",
            "company": "Example",
            "role": "Platform Engineer",
            "admitted_payload_hash": "payload-sha",
            "opportunity0_raw_response_refs": None,
            "opportunity1_reassessment": {"opportunity0_score_bp": 9000},
        }],
        expected_snapshot_sha256=expected_snapshot_hash,
        access_policies={},
    )
    assert descriptor["source_snapshot_sha256"] == source_snapshot_hash(source)


@pytest.mark.parametrize(
    "attack",
    (
        "vacancy",
        "company",
        "role",
        "payload",
        "opportunity-score",
        "raw-response-refs",
    ),
)
def test_sqlite_admission_binds_manifest_identity_and_opportunity0_score(
    tmp_path: Path,
    attack: str,
) -> None:
    source = tmp_path / "queue.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute(
            """CREATE TABLE pipeline_jobs(
                 job_key TEXT PRIMARY KEY,url TEXT,company TEXT,title TEXT,
                 payload_hash TEXT,opportunity REAL,opportunity_decision TEXT
               )"""
        )
        connection.execute(
            "CREATE TABLE employer_research_queue(job_key TEXT PRIMARY KEY)"
        )
        connection.execute(
            """INSERT INTO pipeline_jobs VALUES(
                 'greenhouse:example:1','https://jobs.example.test/1','Example',
                 'Platform Engineer','payload-sha',0.9,'pass'
               )"""
        )
        connection.execute(
            "INSERT INTO employer_research_queue VALUES('greenhouse:example:1')"
        )
    stage = tmp_path / "stage"
    stage.mkdir()
    descriptor = publish_admission_evidence(
        source,
        [{"job_key": "greenhouse:example:1"}],
        stage,
    )
    manifest = {
        "job_key": "greenhouse:example:1",
        "vacancy_url": "https://jobs.example.test/1",
        "company": "Example",
        "role": "Platform Engineer",
        "admitted_payload_hash": "payload-sha",
        "opportunity0_raw_response_refs": None,
        "opportunity1_reassessment": {"opportunity0_score_bp": 9000},
    }
    if attack == "vacancy":
        manifest["vacancy_url"] = "https://jobs.example.test/substituted"
    elif attack == "company":
        manifest["company"] = "Substituted Employer"
    elif attack == "role":
        manifest["role"] = "Substituted Role"
    elif attack == "payload":
        manifest["admitted_payload_hash"] = "substituted-payload"
    elif attack == "raw-response-refs":
        manifest["opportunity0_raw_response_refs"] = [{
            "raw_response": "substituted/private/bytes",
        }]
    else:
        manifest["opportunity1_reassessment"]["opportunity0_score_bp"] = 1000

    with pytest.raises(ValueError, match="SQLite snapshot|admission"):
        validate_admission_evidence(
            stage,
            descriptor,
            [manifest],
            expected_snapshot_sha256=descriptor["snapshot_sha256"],
            access_policies={},
        )


def test_sqlite_admission_replays_deterministic_sorted_cohort_selection(
    tmp_path: Path,
) -> None:
    source = tmp_path / "queue.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute(
            """CREATE TABLE pipeline_jobs(
                 job_key TEXT PRIMARY KEY,url TEXT,company TEXT,title TEXT,
                 payload_hash TEXT,opportunity REAL,opportunity_decision TEXT
               )"""
        )
        connection.execute(
            "CREATE TABLE employer_research_queue(job_key TEXT PRIMARY KEY)"
        )
        for key in ("a:first", "z:favourable"):
            connection.execute(
                "INSERT INTO pipeline_jobs VALUES(?,?,?,?,?,?,?)",
                (
                    key,
                    f"https://jobs.example.test/{key}",
                    "Example",
                    "Platform Engineer",
                    f"payload-{key}",
                    0.9,
                    "pass",
                ),
            )
            connection.execute(
                "INSERT INTO employer_research_queue VALUES(?)",
                (key,),
            )
    stage = tmp_path / "stage"
    stage.mkdir()
    descriptor = publish_admission_evidence(
        source,
        [{"job_key": "z:favourable"}],
        stage,
    )
    with pytest.raises(ValueError, match="selection|cohort|admission"):
        validate_admission_evidence(
            stage,
            descriptor,
            [{
                "job_key": "z:favourable",
                "vacancy_url": "https://jobs.example.test/z:favourable",
                "company": "Example",
                "role": "Platform Engineer",
                "admitted_payload_hash": "payload-z:favourable",
                "opportunity0_raw_response_refs": None,
                "opportunity1_reassessment": {"opportunity0_score_bp": 9000},
            }],
            expected_snapshot_sha256=descriptor["snapshot_sha256"],
            access_policies={},
        )


def test_sqlite_source_identity_includes_uncheckpointed_wal_state(
    tmp_path: Path,
) -> None:
    source = tmp_path / "queue.sqlite3"
    connection = sqlite3.connect(source)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE evidence(value TEXT)")
        connection.commit()
        before = source_snapshot_hash(source)
        connection.execute("INSERT INTO evidence VALUES('WAL-only change')")
        connection.commit()
        after = source_snapshot_hash(source)
        assert after != before
        assert Path(str(source) + "-wal").is_file()
    finally:
        connection.close()


def test_raw_reference_escape_is_rejected_before_publication(tmp_path: Path) -> None:
    snapshot, source, _, _ = _json_evidence(tmp_path)
    source["raw_response_refs"][0]["raw_response"] = "../outside"
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(ValueError, match="identity|relative|escapes"):
        publish_admission_evidence(snapshot, [source], stage)
