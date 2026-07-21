#!/usr/bin/env python3
"""Acquire a JAA-04 corpus from an Opportunity-0 queue snapshot.

The authority plan locates sources; it is never evidence.  Every accepted byte
is obtained by the production reconnaissance worker and is validated before an
atomic, content-addressed corpus is published.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.database import CareerDatabase  # noqa: E402
from career_automation.corpus_publication import sha256_file, write_inventory  # noqa: E402
from career_automation.employer_research import (  # noqa: E402
    EmployerResearchWorker, Opportunity1Coordinator, PortableAuthorityRetriever, RawResponseCache,
    ScraplingPublicRetriever, content_hash, load_frozen_dossiers,
)
from career_automation.engine import OpportunityGate  # noqa: E402
from career_automation.models import ScoredJob  # noqa: E402
from career_automation.opportunity_calibration import (  # noqa: E402
    DECISION_RULE_VERSION, CalibrationPolicy, Confidence, Opportunity0Input,
    calibration_policy_from_json, decide_opportunity0,
)
from scraper.viability import Vacancy, local_decision  # noqa: E402
from tracked_source_revision import source_content_revision  # noqa: E402

CORPUS_SIZE = 30


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def _revision() -> str:
    result = subprocess.run(("git", "rev-parse", "HEAD^{commit}"), cwd=ROOT,
                            text=True, capture_output=True, check=True)
    return result.stdout.strip()


def _admitted(connection: sqlite3.Connection) -> dict[str, dict[str, str]]:
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """SELECT j.job_key,j.url,j.company,j.title
           FROM employer_research_queue q JOIN pipeline_jobs j USING(job_key)
           WHERE j.opportunity_decision='pass' ORDER BY j.job_key"""
    ).fetchall()
    if len(rows) < CORPUS_SIZE:
        raise RuntimeError(f"Opportunity-0 queue must contain at least {CORPUS_SIZE} admitted vacancies")
    return {str(row["job_key"]): dict(row) for row in rows}


def _admitted_input(path: Path) -> dict[str, dict[str, str]]:
    if path.suffix.casefold() != ".json":
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as source:
            return _admitted(source)
    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("records")
    if payload.get("schema_version") != "jaa04.official-admitted-queue.v2":
        raise RuntimeError("untrusted admitted queue JSON: authentic v2 decision evidence is required")
    if not isinstance(records, list) or len(records) != CORPUS_SIZE:
        raise RuntimeError("official admitted queue JSON must contain exactly 30 records")
    if content_hash(records) != payload.get("records_hash"):
        raise RuntimeError("admitted queue JSON hash mismatch")
    raw_store = payload.get("raw_store")
    if not isinstance(raw_store, dict) or not raw_store.get("root"):
        raise RuntimeError("official admitted queue lacks its raw response store")
    raw_root = Path(str(raw_store["root"])).resolve()
    policy = payload.get("policy")
    if not isinstance(policy, dict) or not policy.get("identity") or not policy.get("hash"):
        raise RuntimeError("official admitted queue lacks policy identity/hash")
    calibrated = CalibrationPolicy()
    try:
        snapshot_policy = calibration_policy_from_json(policy.get("parameters"))
    except ValueError as exc:
        raise RuntimeError("official admitted queue policy does not match JAA-03") from exc
    if (set(policy) != {"identity", "hash", "parameters"}
            or policy.get("identity") != DECISION_RULE_VERSION
            or policy.get("hash") != calibrated.policy_hash
            or snapshot_policy != calibrated
            or snapshot_policy.policy_hash != policy.get("hash")):
        raise RuntimeError("official admitted queue policy does not match JAA-03")
    result = {}
    urls: set[str] = set()
    bodies: set[str] = set()
    for row in records:
        decision = row.get("opportunity0_decision")
        source = row.get("source")
        raw = row.get("raw_response_refs")
        if (not isinstance(decision, dict) or decision.get("decision") != "pass"
                or decision.get("reason") != "viable"
                or not isinstance(decision.get("score_bp"), int)
                or decision.get("policy_hash") != policy["hash"]
                or not isinstance(row.get("opportunity0_input"), dict)
                or not isinstance(row.get("confidence"), dict)
                or not isinstance(source, dict) or not source.get("identity")
                or not source.get("authority") or not isinstance(raw, list) or not raw
                or not row.get("payload_hash") or not row.get("observed_at")):
            raise RuntimeError(f"untrusted Opportunity-0 evidence for {row.get('job_key', '<unknown>')}")
        if (source.get("identity") != row.get("job_key")
                or source.get("adapter") != row.get("board")
                or source.get("authority") != "official-public-employer-or-ats"):
            raise RuntimeError(f"official source identity mismatch for {row.get('job_key', '<unknown>')}")
        try:
            vacancy = Vacancy(**row["payload"])
            viability = local_decision(vacancy)
            inputs = Opportunity0Input.from_mapping(row["opportunity0_input"])
            confidence = Confidence(**row["confidence"])
            replay = decide_opportunity0(inputs, confidence,
                                         viability_reason="viable", policy=calibrated)
            official_hashes = sorted({str(ref["sha256"]) for ref in raw})
            for ref in raw:
                relative = Path(str(ref["raw_response"]))
                response_path = (raw_root / relative).resolve()
                if (raw_root not in response_path.parents or not response_path.is_file()
                        or hashlib.sha256(response_path.read_bytes()).hexdigest() != ref["sha256"]
                        or not ref.get("requested_url") or not ref.get("final_url")
                        or not isinstance(ref.get("redirect_chain"), list)
                        or not ref.get("observed_at")):
                    raise ValueError("raw response reference or provenance is invalid")
            expected_payload_hash = hashlib.sha256(json.dumps({
                "source_identity": source["identity"],
                "official_response_hashes": official_hashes,
                "vacancy": row["payload"],
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                allow_nan=False).encode()).hexdigest()
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid authentic decision material for {row.get('job_key', '<unknown>')}") from exc
        if (viability.decision != "include" or viability.reason != "viable"
                or vars(replay) != decision or expected_payload_hash != row["payload_hash"]
                or row.get("url") != vacancy.url
                or row.get("content_sha256") != hashlib.sha256(vacancy.body.encode("utf-8")).hexdigest()):
            raise RuntimeError(f"Opportunity-0 replay mismatch for {row.get('job_key', '<unknown>')}")
        url_identity = str(row["url"]).casefold().rstrip("/")
        body_identity = str(row.get("content_sha256") or "")
        if not body_identity or url_identity in urls or body_identity in bodies:
            raise RuntimeError("official admitted queue contains duplicate URL or content body")
        urls.add(url_identity); bodies.add(body_identity)
        result[str(row["job_key"])] = dict(row)
    if len(result) != CORPUS_SIZE:
        raise RuntimeError("official admitted queue contains duplicate vacancy identities")
    return result


def capture(database_path: Path, destination: Path, *, workspace: Path | None = None,
            maximum_routes: int = 12, timeout_seconds: int = 45) -> None:
    if destination.exists():
        raise RuntimeError("capture destination already exists")
    if not database_path.is_file():
        raise RuntimeError("frozen Opportunity-0 database snapshot is missing")
    admitted = _admitted_input(database_path)
    selected = set(sorted(admitted)[:CORPUS_SIZE])
    records = [admitted[key] for key in sorted(selected)]

    destination.parent.mkdir(parents=True, exist_ok=True)
    workspace = (workspace or destination.with_name(f".{destination.name}.inflight")).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    work_db = workspace / "queue.sqlite3"
    state_path = workspace / "acquisition_state.json"
    snapshot_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()
    state = {"schema_version": "jaa04.acquisition-state.v1", "queue_snapshot_sha256": snapshot_sha256,
             "selected_job_keys": sorted(selected), "status": "in_flight"}
    if state_path.exists():
        if json.loads(state_path.read_text(encoding="utf-8")) != state:
            raise RuntimeError("in-flight workspace belongs to a different admitted cohort")
    else:
        state_path.write_bytes(canonical(state))
    if not work_db.exists():
        if database_path.suffix.casefold() != ".json":
            shutil.copyfile(database_path, work_db)
        else:
            jobs = [
                ScoredJob(key=record["job_key"], board=record["board"],
                          job_id=record["job_key"].split(":", 1)[1],
                          url=record["url"], title=record["title"], company=record["company"],
                          fit=None, opportunity=record["opportunity0_decision"]["score_bp"] / 10_000,
                          final_score=None,
                          extraction_confidence=min(record["confidence"].values()) / 10_000,
                          payload={"official_snapshot_record": record},
                          payload_hash=record["payload_hash"])
                for record in records
            ]
            database = CareerDatabase(work_db)
            gate = OpportunityGate(database)
            gate.import_jobs(jobs)
            for record in records:
                score = record["opportunity0_decision"]["score_bp"]
                database.apply_opportunity_result(
                    job_key=record["job_key"], passed=True,
                    reason=record["opportunity0_decision"]["reason"],
                    policy_hash=record["opportunity0_decision"]["policy_hash"],
                    priority=(2 if score >= 7500 else 1) * 1_000_000 + score * 10,
                )
    stage: Path | None = None
    try:
        with sqlite3.connect(work_db) as connection:
            placeholders = ",".join("?" for _ in selected)
            connection.execute(
                f"DELETE FROM employer_research_queue WHERE job_key NOT IN ({placeholders})",
                tuple(sorted(selected)),
            )
            # A process interruption leaves a visible lease. Explicit resume
            # makes it claimable without waiting while completed rows remain
            # immutable and are never processed twice.
            connection.execute(
                """UPDATE employer_research_queue
                   SET status='queued',available_at=datetime('now','-1 second'),
                       lease_owner=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE status='leased'"""
            )
        cache = RawResponseCache(workspace / "raw")
        # Increment A keeps exact canaries as its default contract. Production
        # acquisition is queue-bound instead: all admitted records may proceed,
        # while the same byte, authority, purpose and temporal validators remain.
        transport = ScraplingPublicRetriever(cache, timeout_seconds=timeout_seconds, root=ROOT)
        retriever = PortableAuthorityRetriever(cache, retriever=transport,
                                               maximum_routes=maximum_routes,
                                               exact_canaries=False)
        database = CareerDatabase(work_db)
        worker = EmployerResearchWorker(database, "jaa04-corpus-acquisition", cache,
                                        retriever=retriever)
        coordinator = Opportunity1Coordinator(database, worker)
        # Each selected non-completed row is attempted at most once per
        # invocation. A retrieval failure remains visibly leased with its
        # error, allowing lower-priority rows to drain; the next invocation
        # deterministically requeues every such interrupted lease above.
        for _ in range(CORPUS_SIZE):
            try:
                if coordinator.run_once() is None:
                    break
            except Exception:
                continue
        with sqlite3.connect(work_db) as connection:
            connection.row_factory = sqlite3.Row
            placeholders = ",".join("?" for _ in selected)
            queue_rows = connection.execute(
                f"""SELECT job_key,status,attempts,last_error,lease_owner,lease_until
                    FROM employer_research_queue WHERE job_key IN ({placeholders})
                    ORDER BY job_key""",
                tuple(sorted(selected)),
            ).fetchall()
        states = {str(row["job_key"]): str(row["status"]) for row in queue_rows}
        incomplete = {key: states.get(key, "missing") for key in sorted(selected)
                      if states.get(key) != "completed"}
        if incomplete:
            details = []
            by_key = {str(row["job_key"]): row for row in queue_rows}
            for key, status in incomplete.items():
                row = by_key.get(key)
                suffix = ""
                if row is not None:
                    suffix = (f" attempts={row['attempts']}"
                              f" lease_owner={row['lease_owner'] or '-'}"
                              f" lease_until={row['lease_until'] or '-'}"
                              f" error={row['last_error'] or '-'}")
                details.append(f"{key}:{status}{suffix}")
            raise RuntimeError(
                "research queue did not drain; retry with the same workspace: " + "; ".join(details)
            )
        completed = {key for key in selected if database.post_research_dossier(key) is not None}
        if completed != selected or len(completed) != CORPUS_SIZE:
            raise RuntimeError("production worker did not complete the selected admitted cohort")

        dossiers = []
        manifest_records = []
        for record in records:
            job_key = str(record["job_key"])
            result = database.post_research_dossier(job_key)
            if result is None:
                raise RuntimeError(f"missing completed dossier for {job_key}")
            dossier, _ = result
            reassessment = database.opportunity1_reassessment(
                job_key, expected_dossier_hash=content_hash(dossier),
            )
            if reassessment is None:
                raise RuntimeError(f"missing Opportunity-1 reassessment for {job_key}")
            dossier["raw_cache_root"] = "raw"
            dossier_hash = content_hash(dossier)
            # The persisted dossier contains an absolute in-flight cache root;
            # bind the published reassessment to the portable dossier identity.
            reassessment = {**reassessment, "dossier_hash": dossier_hash}
            dossiers.append(dossier)
            manifest_records.append({
                "job_key": job_key, "vacancy_url": record["url"],
                "company": record["company"], "role": record["title"],
                "dossier_hash": dossier_hash,
                "admitted_payload_hash": record.get("payload_hash"),
                "opportunity0_input": record.get("opportunity0_input"),
                "opportunity0_confidence": record.get("confidence"),
                "opportunity0_decision": record.get("opportunity0_decision"),
                "opportunity0_source": record.get("source"),
                "opportunity0_observed_at": record.get("observed_at"),
                "opportunity0_raw_response_refs": record.get("raw_response_refs"),
                "content_sha256": dossier["sources"][0]["content_sha256"],
                "source_ids": [source["id"] for source in dossier["sources"]],
                "capture_identities": [
                    {"url": source["url"], "sha256": source["content_sha256"]}
                    for source in dossier["sources"]
                ],
                "opportunity1_reassessment": reassessment,
            })
        envelope = {"schema_version": "jaa04.frozen-dossiers.v4", "dossiers": dossiers,
                    "dossiers_hash": content_hash(dossiers)}
        manifest = {"schema_version": "jaa04.research-manifest.v4",
                    "opportunity0_queue_size": len(admitted),
                    "records": manifest_records,
                    "records_hash": content_hash(manifest_records)}
        stage = Path(tempfile.mkdtemp(prefix="jaa04-complete-", dir=destination.parent))
        (stage / "frozen_dossiers.json").write_bytes(canonical(envelope))
        (stage / "research_manifest.json").write_bytes(canonical(manifest))
        shutil.copytree(workspace / "raw", stage / "raw", copy_function=os.link)
        staged_cache = RawResponseCache(stage / "raw")
        validated = load_frozen_dossiers(stage / "frozen_dossiers.json", staged_cache, strict_corpus=True)
        if len(validated) != CORPUS_SIZE:
            raise RuntimeError("publication requires exactly 30 validated dossiers")
        # Capture uniqueness is a corpus admission rule, not merely a retrieval
        # optimisation. URL aliases and repeated bodies cannot masquerade as
        # independently acquired authority.
        identities: set[tuple[str, str]] = set()
        body_hashes: set[str] = set()
        source_ids: set[str] = set()
        for dossier in validated:
            for source in dossier["sources"]:
                identity = (str(source["url"]), str(source["content_sha256"]))
                if (identity in identities or source["content_sha256"] in body_hashes
                        or source["id"] in source_ids):
                    raise RuntimeError("duplicated authority capture in staged corpus")
                identities.add(identity)
                body_hashes.add(str(source["content_sha256"]))
                source_ids.add(str(source["id"]))
        files = sorted(path for path in (stage / "raw").rglob("*") if path.is_file())
        corpus_hash = hashlib.sha256(b"".join(
            path.relative_to(stage).as_posix().encode() + b"\0" + path.read_bytes()
            for path in files)).hexdigest()
        inventory_path = write_inventory(stage)
        receipt = {
            "schema_version": "jaa04.capture-receipt.v4", "status": "SUCCESS",
            "captured_count": CORPUS_SIZE,
            "source_count": sum(len(row["sources"]) for row in dossiers),
            "queue_snapshot_sha256": snapshot_sha256,
            "discovery_mode": "typed-ats-and-official-route-validation",
            "manifest_sha256": hashlib.sha256((stage / "research_manifest.json").read_bytes()).hexdigest(),
            "dossiers_sha256": hashlib.sha256((stage / "frozen_dossiers.json").read_bytes()).hexdigest(),
            "raw_corpus_sha256": corpus_hash, "source_revision": _revision(),
            "source_content_revision": source_content_revision(ROOT),
            "inventory_sha256": sha256_file(inventory_path),
        }
        (stage / "capture_receipt.json").write_bytes(canonical(receipt))
        os.rename(stage, destination)
        stage = None
    except BaseException:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-snapshot", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True,
                        help="stable external in-flight queue and content-addressed byte store")
    parser.add_argument("--maximum-routes", type=int, default=12)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    args = parser.parse_args()
    try:
        if args.maximum_routes < 1 or args.timeout_seconds < 1:
            raise ValueError("retrieval limits must be positive")
        capture(args.queue_snapshot.resolve(), args.destination.resolve(), workspace=args.workspace.resolve(),
                maximum_routes=args.maximum_routes, timeout_seconds=args.timeout_seconds)
    except Exception as exc:
        print(f"JAA-04 capture: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "capture": str(args.destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
