"""Independent, byte-backed adversarial retest of JAA-04 queue admission."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from dataclasses import asdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from career_automation.opportunity_calibration import (
    CalibrationPolicy,
    Confidence,
    DECISION_RULE_VERSION,
    Opportunity0Input,
    calibration_policy_json,
    decide_opportunity0,
)
from career_automation.public_access import (
    PublicAccessPolicy,
    RobotsReceipt,
    TermsAttestation,
    USER_AGENT,
)
from scraper.viability import Vacancy


ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / "scripts" / "capture_jaa_04.py"
ATS = ("greenhouse", "smartrecruiters", "workable", "ashby")


def _capture_module() -> Any:
    spec = importlib.util.spec_from_file_location("jaa04_capture_input_retest", CAPTURE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def _rehash(envelope: dict[str, Any]) -> dict[str, Any]:
    envelope["records_hash"] = hashlib.sha256(_canonical(envelope["records"])).hexdigest()
    return envelope


def _cohort(tmp_path: Path) -> tuple[Path, dict[str, dict[str, object]]]:
    """Make 30 unique local, official-ATS response bodies and their v2 envelope."""
    raw_root = tmp_path / "authority-bytes"
    policy = CalibrationPolicy()
    records: list[dict[str, object]] = []
    original: dict[str, dict[str, object]] = {}
    today = date.today().isoformat()
    for number in range(30):
        board = ATS[number % len(ATS)]
        job_id = f"local-{number + 1:02d}"
        identity = f"{board}:{job_id}"
        url = f"https://{board}.authority.example.test/jobs/{job_id}"
        body = (f"Official {board} authority response {number + 1}: this software engineering "
                f"vacancy in London, UK builds secure cloud platform services with Python. "
                f"Applications are open for the current role and the team welcomes candidates.")
        response = _canonical({"authority": board, "job_id": job_id, "body": body})
        digest = hashlib.sha256(response).hexdigest()
        relative = f"{digest[:2]}/{digest}.response"
        raw_path = raw_root / relative
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_bytes(response)
        vacancy = Vacancy(
            key=identity, board=board, job_id=job_id, url=url, posted_at=today,
            raw_text=body, raw_json={"authority": board}, title="Software Engineer",
            company=f"Official {board.title()} {number + 1}", location="London, UK", body=body,
            expiry="",
        )
        inputs = Opportunity0Input(8500, 8000, 9000)
        confidence = Confidence(9000, 9000, 9000, 9000)
        decision = vars(decide_opportunity0(inputs, confidence, viability_reason="viable", policy=policy))
        raw = [{"sha256": digest, "raw_response": relative, "requested_url": url,
                "final_url": url, "response_url": url, "status": 200,
                "redirect_sequence": 0, "redirect_chain": [url],
                "observed_at": f"{today}T00:00:00+00:00"}]
        payload = vars(vacancy)
        payload_hash = hashlib.sha256(_canonical({
            "source_identity": identity, "official_response_hashes": [digest], "vacancy": payload,
        })).hexdigest()
        record = {
            "job_key": identity, "board": board, "company": vacancy.company, "title": vacancy.title,
            "url": url, "payload_hash": payload_hash,
            "canonical_vacancy_key": f"local-{number + 1}",
            "content_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "observed_at": raw[0]["observed_at"],
            "source": {"identity": identity, "adapter": board,
                       "authority": "official-public-employer-or-ats"},
            "raw_response_refs": raw, "payload": payload,
            "viability_decision": {"decision": "include", "reason": "viable"},
            "opportunity0_input": vars(inputs), "confidence": vars(confidence),
            "opportunity0_decision": decision,
        }
        records.append(record)
        original[identity] = decision
    envelope: dict[str, Any] = {
        "schema_version": "jaa04.official-admitted-queue.v2", "created_at": f"{today}T00:00:00+00:00",
        "selection": "local official authority responses; exact 30",
        "policy": {"identity": DECISION_RULE_VERSION, "hash": policy.policy_hash,
                   "parameters": calibration_policy_json(policy)},
        "raw_store": {"layout": "sha256-prefix/content-sha256.response", "root": str(raw_root)},
        "records": records,
    }
    snapshot = tmp_path / "official-cohort.json"
    snapshot.write_bytes(_canonical(_rehash(envelope)) + b"\n")
    return snapshot, original


def _policy_bound_cohort(
    tmp_path: Path,
    retrieval_engine: str,
) -> tuple[Path, dict[str, PublicAccessPolicy]]:
    snapshot, _ = _cohort(tmp_path)
    envelope = json.loads(snapshot.read_text(encoding="utf-8"))
    raw_root = Path(envelope["raw_store"]["root"])
    stamp = str(envelope["created_at"])
    hosts = {
        str(record["url"]).split("/", 3)[2]
        for record in envelope["records"]
    }
    attestations = {
        host: TermsAttestation(
            host=host,
            terms_url=f"https://{host}/terms",
            determination="public_read_only_research_permitted",
            reviewed_at=stamp,
            reviewed_by="Offline Test Operator",
            reviewer_type="human_operator",
            notes="Synthetic offline fixture; not production authority.",
        )
        for host in hosts
    }
    policy_hash = hashlib.sha256(b"admission-engine-policy").hexdigest()
    policy = PublicAccessPolicy(
        attestations,
        policy_sha256=policy_hash,
        now=datetime.fromisoformat(stamp).astimezone(timezone.utc),
    )
    robots = b"User-agent: *\nAllow: /\n"
    robots_hash = hashlib.sha256(robots).hexdigest()
    robots_ref = f"{robots_hash[:2]}/{robots_hash}.response"
    robots_path = raw_root / robots_ref
    robots_path.parent.mkdir(parents=True, exist_ok=True)
    robots_path.write_bytes(robots)
    for record in envelope["records"]:
        reference = record["raw_response_refs"][0]
        requested_url = str(reference["requested_url"])
        host = requested_url.split("/", 3)[2]
        reference["retrieval_engine"] = retrieval_engine
        reference["access_receipt"] = asdict(RobotsReceipt(
            host=host,
            robots_url=f"https://{host}/robots.txt",
            final_url=f"https://{host}/robots.txt",
            status_code=200,
            content_sha256=robots_hash,
            raw_response_ref=robots_ref,
            redirect_history=[],
            retrieved_at=stamp,
            user_agent=USER_AGENT,
            requested_url=requested_url,
            allowed=True,
            crawl_delay_seconds=10.0,
            terms_policy_sha256=policy_hash,
            terms_attestation=asdict(attestations[host]),
        ))
    snapshot.write_bytes(_canonical(_rehash(envelope)) + b"\n")
    return snapshot, {policy_hash: policy}


def _mutated_snapshot(tmp_path: Path, attack: str) -> Path:
    source, _ = _cohort(tmp_path / attack)
    envelope = json.loads(source.read_text(encoding="utf-8"))
    row = envelope["records"][0]
    if attack == "missing-threshold":
        del envelope["policy"]["parameters"]["minimum_confidence_bp"]
    elif attack == "extra-threshold":
        envelope["policy"]["parameters"]["unexpected_threshold"] = 1
    elif attack == "typed-threshold":
        envelope["policy"]["parameters"]["minimum_opportunity_bp"] = True
    elif attack == "typed-weight":
        envelope["policy"]["parameters"]["weights"][1] = "35"
    elif attack == "policy-identity":
        envelope["policy"]["identity"] = "attacker-policy"
    elif attack == "policy-hash":
        envelope["policy"]["hash"] = "sha256:" + "0" * 64
    elif attack == "source-identity":
        row["source"]["identity"] = "greenhouse:substituted"
    elif attack == "score":
        row["opportunity0_decision"]["score_bp"] += 1
    elif attack == "reason":
        row["opportunity0_decision"]["reason"] = "below_opportunity_threshold"
    elif attack == "payload":
        row["payload"]["title"] = "Attacker title"
    elif attack == "source":
        row["source"]["authority"] = "aggregator"
    elif attack == "raw-hash":
        row["raw_response_refs"][0]["sha256"] = "0" * 64
    elif attack == "duplicate-url":
        envelope["records"][1]["url"] = row["url"]
        envelope["records"][1]["payload"]["url"] = row["url"]
    elif attack == "duplicate-body":
        envelope["records"][1]["content_sha256"] = row["content_sha256"]
    elif attack == "duplicate-identity":
        envelope["records"][1]["job_key"] = row["job_key"]
    elif attack == "stale":
        row["payload"]["posted_at"] = "2020-01-01"
    elif attack == "closed":
        row["payload"]["expiry"] = "2020-01-01"
    elif attack == "inaccessible":
        row["url"] = row["payload"]["url"] = "mailto:closed@authority.example.test"
    elif attack == "legacy-schema":
        envelope["schema_version"] = "jaa04.official-admitted-queue.v1"
    else:
        raise AssertionError(attack)
    output = tmp_path / f"{attack}.json"
    output.write_bytes(_canonical(_rehash(envelope)) + b"\n")
    return output


def test_exact_local_four_ats_cohort_is_accepted_with_original_opportunity_zero_decisions(tmp_path: Path) -> None:
    snapshot, original = _cohort(tmp_path)
    portable_raw = tmp_path / "portable-authority-bytes"
    source_raw = Path(json.loads(snapshot.read_text(encoding="utf-8"))["raw_store"]["root"])
    shutil.copytree(source_raw, portable_raw)
    admitted = _capture_module().load_admitted_input(
        snapshot,
        raw_root_override=portable_raw,
    )
    assert len(admitted) == 30
    assert {record["board"] for record in admitted.values()} == set(ATS)
    assert {key: value["opportunity0_decision"] for key, value in admitted.items()} == original


def test_policy_replay_accepts_requests_static_admission_evidence(
    tmp_path: Path,
) -> None:
    snapshot, policies = _policy_bound_cohort(tmp_path, "requests-static")
    admitted = _capture_module().load_admitted_input(
        snapshot,
        access_policies=policies,
    )
    assert len(admitted) == 30


def test_policy_replay_rejects_unknown_admission_engine(tmp_path: Path) -> None:
    snapshot, policies = _policy_bound_cohort(tmp_path, "browser")
    with pytest.raises(RuntimeError, match="invalid authentic decision material"):
        _capture_module().load_admitted_input(
            snapshot,
            access_policies=policies,
        )


@pytest.mark.parametrize("attack", (
    "missing-threshold", "extra-threshold", "typed-threshold", "typed-weight",
    "policy-identity", "policy-hash", "source-identity", "score", "reason", "payload",
    "source", "raw-hash", "duplicate-url", "duplicate-body", "duplicate-identity",
    "stale", "closed", "inaccessible", "legacy-schema",
))
def test_rehashed_policy_and_cohort_tampering_fails_closed(tmp_path: Path, attack: str) -> None:
    with pytest.raises(RuntimeError):
        _capture_module()._admitted_input(_mutated_snapshot(tmp_path, attack))
