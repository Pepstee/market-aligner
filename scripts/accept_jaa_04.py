#!/usr/bin/env python3
"""Fail-closed JAA-04 production-path acceptance and revision certificate."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.database import CareerDatabase  # noqa: E402
from career_automation.employer_research import (  # noqa: E402
    RawResponseCache, content_hash, ingest_frozen_manifest,
    load_frozen_dossiers, validate_dossier,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload  # noqa: E402
from career_automation.models import PipelineState  # noqa: E402
from tracked_source_revision import (  # noqa: E402
    TrackedSourceRevisionError, source_content_revision,
    source_content_revision_contract,
)

FORMAT = "jaa04-revision-certification/v1"
MANIFEST = ROOT / "career_automation/fixtures/jaa04_research_manifest.json"
FROZEN = ROOT / "career_automation/fixtures/jaa04_frozen_dossiers.json"
FROZEN_RAW = ROOT / "career_automation/fixtures/jaa04_raw"
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
    body = f"Cited public company evidence for {job_key}.".encode()
    digest, reference = cache.store(body)
    timestamp = "2026-07-20T00:00:00+00:00"
    return {
        "schema_version": "jaa04.dossier.v1", "job_key": job_key,
        "raw_cache_root": str(cache.root),
        "sources": [{"id": "source", "url": "https://8.8.8.8/public", "captured_at": timestamp,
                     "retrieved_at": timestamp, "content_sha256": digest,
                     "raw_response_ref": reference, "status_code": 200}],
        "claims": [{"id": "claim", "kind": "company", "classification": "fact",
                    "text": body.decode(), "observed_at": timestamp,
                    "freshness_classification": "current", "source_ids": ["source"]}],
        "edges": [],
    }


def replay_production_retrieval(records: list[dict[str, Any]], destination: Path) -> list[dict[str, Any]]:
    bodies = {record["url"]: (FROZEN_RAW / record["raw_response_ref"]).read_bytes()
              for record in records}

    class Fetcher:
        @staticmethod
        def get(url: str, timeout: int):
            require(timeout == 45 and url in bodies, "unexpected production retrieval request")
            return types.SimpleNamespace(status=200, url=url, body=bodies[url])

    scrapling = types.ModuleType("scrapling")
    fetchers = types.ModuleType("scrapling.fetchers")
    fetchers.Fetcher = Fetcher
    previous_scrapling = sys.modules.get("scrapling")
    previous_fetchers = sys.modules.get("scrapling.fetchers")
    original_resolver = socket.getaddrinfo
    try:
        sys.modules["scrapling"] = scrapling
        sys.modules["scrapling.fetchers"] = fetchers
        socket.getaddrinfo = lambda *args, **kwargs: [(2, 1, 6, "", ("8.8.8.8", 443))]
        return ingest_frozen_manifest(MANIFEST, RawResponseCache(destination),
                                      enforce_reviewed_bytes=True)
    finally:
        socket.getaddrinfo = original_resolver
        if previous_scrapling is None:
            sys.modules.pop("scrapling", None)
        else:
            sys.modules["scrapling"] = previous_scrapling
        if previous_fetchers is None:
            sys.modules.pop("scrapling.fetchers", None)
        else:
            sys.modules["scrapling.fetchers"] = previous_fetchers


def exercise_runtime(work: Path) -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    frozen = load_frozen_dossiers(FROZEN, RawResponseCache(FROZEN_RAW), strict_corpus=True)
    require(len(frozen) == 30, "frozen corpus cardinality mismatch")
    replayed = replay_production_retrieval(manifest["records"], work / "retrieval-cache")
    require(len(replayed) == len(frozen), "production retrieval cardinality mismatch")
    for actual, expected in zip(replayed, frozen, strict=True):
        require(actual["job_key"] == expected["job_key"]
                and actual["claims"] == expected["claims"]
                and actual["sources"][0]["url"] == expected["sources"][0]["url"]
                and actual["sources"][0]["content_sha256"] == expected["sources"][0]["content_sha256"],
                "production retrieval did not reproduce frozen evidence")
    source_hashes = {source["content_sha256"] for dossier in frozen for source in dossier["sources"]}
    require(len(source_hashes) == 30, "identical synthetic responses cannot certify JAA-04")

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

    first = database.claim_research("interrupted", lease_seconds=1)
    require(first is not None and first.job_key == strong.key, "passed vacancy was not leased")
    with database.connection() as connection:
        connection.execute("UPDATE employer_research_queue SET lease_until='2000-01-01T00:00:00+00:00' WHERE job_key=?", (strong.key,))
    resumed = database.claim_research("resumer", lease_seconds=60)
    require(resumed is not None and resumed.attempts == 2, "expired lease was not resumed")
    cache = RawResponseCache(work / "worker-cache")
    dossier = _runtime_dossier(cache, strong.key)
    digest = content_hash(dossier)
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(database.complete_research, job_key=strong.key,
                                   worker_id="resumer", dossier=dossier,
                                   dossier_hash=digest) for _ in range(2)]:
            future.result()
    result = database.apply_opportunity1(job_key=strong.key, signals=[
        {"claim_id": "zeta", "reason": "Funding was withdrawn.", "delta_bp": -2000},
        {"claim_id": "alpha", "reason": "Role scope narrowed.", "delta_bp": -2000},
    ])
    require(result["decision"] == "reject" and result["opportunity0_score_bp"] == 9000
            and result["score_bp"] == 5000, "Opportunity-1 demotion failed")
    require(database.lifecycle.replay()[strong.key] is PipelineState.OPPORTUNITY_REJECTED_AFTER_RESEARCH,
            "durable lifecycle replay mismatch")
    return {"status": "PASS", "dossier_count": 30, "distinct_source_bytes": 30,
            "negative_controls": negative_controls,
            "lease_resume_attempts": resumed.attempts,
            "opportunity1": result}


def canonical(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


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
        corpus_hash = hashlib.sha256(FROZEN.read_bytes()).hexdigest()
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
            "frozen_corpus_file_sha256": corpus_hash,
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
