#!/usr/bin/env python3
"""Fail-closed JAA-04 production-path acceptance and revision certificate."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.database import CareerDatabase  # noqa: E402
from career_automation.employer_research import (  # noqa: E402
    Citation, EmployerResearchWorker, Opportunity1Coordinator, RawResponseCache,
    build_reconnaissance_dossier, content_hash, load_frozen_dossiers, validate_dossier,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload  # noqa: E402
from career_automation.models import PipelineState  # noqa: E402
from tracked_source_revision import (  # noqa: E402
    TrackedSourceRevisionError, source_content_revision,
    source_content_revision_contract,
)

FORMAT = "jaa04-revision-certification/v1"
CAPTURE = ROOT / "career_automation/fixtures/jaa04_capture"
MANIFEST = CAPTURE / "research_manifest.json"
FROZEN = CAPTURE / "frozen_dossiers.json"
FROZEN_RAW = CAPTURE / "raw"
CAPTURE_RECEIPT = CAPTURE / "capture_receipt.json"
EVIDENCE = ROOT / "runtime_evidence/jaa04"
COMMANDS = [
    "python3 scripts/accept_jaa_04.py",
    "python3 -m pytest -q test_jaa04_independent_acceptance.py",
]


class AcceptanceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def git(*arguments: str) -> str:
    result = subprocess.run(("git", *arguments), cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0, f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def clean_revision() -> tuple[str, str]:
    revision = git("rev-parse", "--verify", "HEAD^{commit}")
    require(len(revision) == 40 and all(c in "0123456789abcdef" for c in revision),
            "unresolvable Git revision")
    dirty = [line for line in git("status", "--porcelain=v1", "--untracked-files=all").splitlines()
             if not line[3:].startswith("runtime_evidence/jaa04/")]
    require(not dirty, "dirty source or stale evidence relationship cannot be certified")
    return revision, source_content_revision(ROOT)


def _job(job_id: str, opportunity: float = .9):
    return scored_job_from_payload({
        "board": "jaa04-certification", "job_id": job_id,
        "url": f"https://jobs.example.test/{job_id}", "job_title": "Engineer",
        "company": "Example", "fit": .8, "opportunity": opportunity,
        "final": 80.0, "extraction_confidence": .99,
    })


def _runtime_dossier(cache: RawResponseCache, job_key: str) -> dict[str, Any]:
    body = (f"<p>The company operates a technology product platform and service for customers. "
            f"Its employee team has role responsibilities and duties. The careers vacancy invites "
            f"each candidate to apply through the hiring application. In 2026 it reported current "
            f"operational revenue and profit performance for {job_key}.</p>").encode()
    digest, reference = cache.store(body)
    timestamp = "2026-07-20T00:00:00+00:00"
    citation = Citation("source", "https://8.8.8.8/public", timestamp, timestamp,
                        digest, reference, 200)
    return build_reconnaissance_dossier(
        SimpleNamespace(job_key=job_key, company="Example", title="Engineer"),
        citation, cache, observed_at=timestamp,
    )


def exercise_runtime(work: Path) -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    frozen = load_frozen_dossiers(FROZEN, RawResponseCache(FROZEN_RAW), strict_corpus=True)
    require(len(frozen) == 30, "frozen corpus cardinality mismatch")
    require(manifest.get("schema_version") == "jaa04.research-manifest.v2"
            and content_hash(manifest["records"]) == manifest.get("records_hash"),
            "captured research manifest is invalid")
    by_key = {dossier["job_key"]: dossier for dossier in frozen}
    for record in manifest["records"]:
        dossier = by_key[record["job_key"]]
        source = dossier["sources"][0]
        require(record["content_sha256"] == source["content_sha256"]
                and record["url"] == source["url"]
                and record["status_code"] == source["status_code"]
                and record["retrieved_at"] == source["retrieved_at"]
                and record["redirect_history"] == source["redirect_history"],
                "manifest is not bound to frozen dossier provenance")
        require(record.get("sources") == dossier["sources"]
                and record.get("source_plan") == dossier["source_plan"]
                and record.get("source_ids") == [item["id"] for item in dossier["sources"]],
                "manifest does not exactly cover dossier sources and source plan")
    source_hashes = {source["content_sha256"] for dossier in frozen for source in dossier["sources"]}
    require(len(source_hashes) == 30, "identical synthetic responses cannot certify JAA-04")
    expected_kinds = {"company", "role", "product", "hiring", "operational_health"}
    for dossier in frozen:
        require({claim["kind"] for claim in dossier["claims"]} == expected_kinds,
                "dossier lacks substantive kind coverage")
        require({claim["classification"] for claim in dossier["claims"]}
                == {"fact", "inference", "hypothesis"},
                "dossier does not distinguish fact, inference, and hypothesis")
        require(any(edge["relation"] in {"qualifies", "contradicts"}
                    for edge in dossier["edges"]),
                "dossier lacks a typed qualification or contradiction")

    # Dossier claim failures must be rejected before durable completion.
    negative_controls = []
    for attack in ("uncited", "hallucinated", "stale-as-current", "protected", "private-person"):
        cache = RawResponseCache(work / f"negative-{attack}")
        dossier = _runtime_dossier(cache, attack)
        claim = dossier["claims"][0]
        if attack == "uncited": claim["source_ids"] = []
        elif attack == "hallucinated": claim["source_ids"] = ["invented"]
        elif attack == "stale-as-current": claim["observed_at"] = "2020-01-01T00:00:00+00:00"
        elif attack == "protected": claim["religion"] = "forbidden"
        else: claim["subject_type"] = "private_person"
        try:
            validate_dossier(dossier, cache, as_of=__import__("datetime").date(2026, 7, 20))
        except ValueError:
            negative_controls.append(attack)
        else:
            raise AcceptanceError(f"unsafe dossier accepted: {attack}")

    database = CareerDatabase(work / "career.sqlite3")
    strong = _job("strong")
    rejected = _job("rejected", .1)
    OpportunityGate(database).bootstrap([strong, rejected])
    try:
        database.enqueue_research(rejected.key, 999)
    except sqlite3.IntegrityError:
        negative_controls.append("rejected-opportunity-0")
    else:
        raise AcceptanceError("rejected Opportunity-0 entered research queue")

    cache = RawResponseCache(work / "worker-cache")

    class FailingRetriever:
        def retrieve(self, source_id: str, url: str) -> Citation:
            raise RuntimeError("simulated interruption after atomic claim")

    interrupted = EmployerResearchWorker(database, "interrupted", cache,
                                         retriever=FailingRetriever(), lease_seconds=1)
    try:
        interrupted.run_once()
    except RuntimeError:
        pass
    else:
        raise AcceptanceError("interrupted retrieval did not fail closed")
    with database.connection() as connection:
        leased = connection.execute(
            "SELECT status,lease_owner FROM employer_research_queue WHERE job_key=?", (strong.key,)
        ).fetchone()
        require(tuple(leased) == ("leased", "interrupted"),
                "interruption did not preserve a resumable lease")
        connection.execute("UPDATE employer_research_queue SET lease_until='2000-01-01T00:00:00+00:00' WHERE job_key=?", (strong.key,))

    class CapturedRetriever:
        def retrieve(self, source_id: str, url: str) -> Citation:
            body = (b"<p>The company operates a technology product platform and service for customers. "
                    b"Its employee team has role responsibilities and duties. The careers vacancy invites "
                    b"each candidate to apply through the hiring application. In 2026 it reported current "
                    b"operational revenue and profit performance.</p>")
            digest, reference = cache.store(body)
            timestamp = "2026-07-20T00:00:00+00:00"
            return Citation(source_id, "https://8.8.8.8/public", timestamp, timestamp,
                            digest, reference, 200)

    resumed_worker = EmployerResearchWorker(database, "resumer", cache,
                                            retriever=CapturedRetriever(), lease_seconds=60)
    coordinator = Opportunity1Coordinator(
        database, resumed_worker,
        signal_deriver=lambda dossier: [
            {"claim_id": "health-inference", "reason": "Funding was withdrawn.", "delta_bp": -2000},
            {"claim_id": "role-hypothesis", "reason": "Role scope narrowed.", "delta_bp": -2000},
        ],
    )
    result = coordinator.run_once()
    require(result is not None, "expired lease was not processed")
    with database.connection() as connection:
        queue = connection.execute(
            "SELECT status,attempts FROM employer_research_queue WHERE job_key=?", (strong.key,)
        ).fetchone()
        dossier = json.loads(connection.execute(
            "SELECT dossier_json FROM employer_dossiers WHERE job_key=?", (strong.key,)
        ).fetchone()[0])
    require(tuple(queue) == ("completed", 2), "resumed worker did not complete exactly once")
    require(result["decision"] == "reject" and result["opportunity0_score_bp"] == 9000
            and result["score_bp"] == 5000, "Opportunity-1 demotion failed")
    require(database.lifecycle.replay()[strong.key] is PipelineState.OPPORTUNITY_REJECTED_AFTER_RESEARCH,
            "durable lifecycle replay mismatch")
    return {"status": "PASS", "validation_mode": "offline-corpus-validation",
            "capture_provenance": "external-jaa04.capture-receipt.v1",
            "dossier_count": 30, "distinct_source_bytes": 30,
            "negative_controls": negative_controls,
            "lease_resume_attempts": 2,
            "queue_worker": "retrieval-validation-completion",
            "intelligence_kinds": sorted(expected_kinds),
            "opportunity1": result}


def canonical(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def raw_corpus_hash() -> str:
    files = sorted(path for path in FROZEN_RAW.rglob("*") if path.is_file())
    require(len(files) == 30, "raw response corpus cardinality mismatch")
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(CAPTURE).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def publish(document: dict[str, Any]) -> Path:
    payload = canonical(document)
    destination = EVIDENCE / f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    existing = sorted(EVIDENCE.glob("*.json"))
    require(not existing or existing == [destination], "tampered or stale JAA-04 evidence relationship")
    if destination.exists():
        require(destination.is_file() and not destination.is_symlink()
                and destination.read_bytes() == payload, "JAA-04 receipt tampering detected")
        return destination
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return destination


def main() -> int:
    work: Path | None = None
    try:
        revision_before, content_before = clean_revision()
        capture_receipt = json.loads(CAPTURE_RECEIPT.read_text(encoding="utf-8"))
        require(capture_receipt.get("schema_version") == "jaa04.capture-receipt.v1"
                and capture_receipt.get("status") == "SUCCESS"
                and capture_receipt.get("captured_count") == 30,
                "authentic capture receipt is missing")
        hashes = {
            "research_manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
            "frozen_dossiers_sha256": hashlib.sha256(FROZEN.read_bytes()).hexdigest(),
            "capture_receipt_sha256": hashlib.sha256(CAPTURE_RECEIPT.read_bytes()).hexdigest(),
            "raw_corpus_sha256": capture_receipt["raw_corpus_sha256"],
        }
        require(hashes["research_manifest_sha256"] == capture_receipt["manifest_sha256"]
                and hashes["frozen_dossiers_sha256"] == capture_receipt["dossiers_sha256"]
                and hashes["raw_corpus_sha256"] == raw_corpus_hash(),
                "capture components are not hash-bound")
        work = Path(tempfile.mkdtemp(prefix="jaa04-acceptance-"))
        result = exercise_runtime(work)
        revision_after, content_after = clean_revision()
        require((revision_before, content_before) == (revision_after, content_after),
                "revision changed during JAA-04 acceptance")
        receipt = publish({
            "format": FORMAT, "status": "PASS", "source_revision": revision_before,
            "source_content_revision": content_before,
            "source_content_revision_contract": source_content_revision_contract(),
            "acceptance_commands": COMMANDS,
            "capture_component_hashes": hashes,
            "frozen_corpus_hash": json.loads(FROZEN.read_text(encoding="utf-8"))["dossiers_hash"],
            "runtime": {"python_implementation": platform.python_implementation(),
                        "python_version": platform.python_version()},
            "runtime_evidence": result,
        })
    except (AcceptanceError, TrackedSourceRevisionError, OSError, ValueError, KeyError,
            TypeError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"JAA-04 acceptance: ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"receipt": receipt.relative_to(ROOT).as_posix(), "status": "PASS"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
