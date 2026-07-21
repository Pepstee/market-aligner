"""Generated-fixture adversarial checks for JAA-04 authority and resumption."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from career_automation.database import CareerDatabase
from career_automation.employer_research import Citation, PortableAuthorityRetriever, RawResponseCache, content_hash
from career_automation.engine import OpportunityGate, scored_job_from_payload


ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / "scripts" / "capture_jaa_04.py"
STAMP = "2026-07-20T00:00:00+00:00"


def _task():
    return type("Task", (), {
        "job_key": "aggregate:1", "url": "https://remotive.com/aggregate/1",
        "company": "Acme", "title": "Senior Platform Engineer",
    })()


class _GeneratedRoutes:
    def __init__(self, cache: RawResponseCache, pages: dict[str, bytes]) -> None:
        self.cache, self.pages, self.calls = cache, pages, []

    def retrieve(self, source_id: str, url: str, *, source_kind: str | None = None, **_: object) -> Citation:
        self.calls.append(url)
        body = self.pages[url]
        digest, reference = self.cache.store(body)
        host = url.split("/")[2]
        published = STAMP if b"article:published_time" in body else None
        evidence = (f'<meta property="article:published_time" content="{STAMP}">'
                    if published else None)
        return Citation(source_id, url, STAMP, STAMP, digest, reference, 200, url, [],
                        published, None, source_kind, host, url, evidence, "generated")


@pytest.mark.parametrize("candidate_count", (0, 2))
def test_aggregator_evaluates_the_entire_bounded_route_set_and_refuses_non_unique_official_vacancy(
    tmp_path: Path, candidate_count: int,
) -> None:
    """A zero/multiple result cannot leak an official-vacancy citation."""
    cache = RawResponseCache(tmp_path / "raw")
    routes = [f"https://jobs.acme.example.test/jobs/{number}" for number in range(3)]
    seed = "".join(f'<a href="{route}">published job</a>' for route in routes).encode()
    pages = {"https://remotive.com/aggregate/1": seed}
    for number, route in enumerate(routes):
        metadata = (f'<meta property="article:published_time" content="{STAMP}">' if number < candidate_count else "")
        pages[route] = (metadata + "<main>Acme Senior Platform Engineer vacancy is open.</main>").encode()
    transport = _GeneratedRoutes(cache, pages)
    retriever = PortableAuthorityRetriever(cache, retriever=transport, maximum_routes=3,
                                           exact_canaries=False)

    with pytest.raises(ValueError, match="exactly one validated official vacancy route"):
        retriever.retrieve_plan(_task())

    # Every published route inside the configured bound was fetched before the
    # ambiguity decision; retrieve_plan raised rather than returning a citation.
    assert transport.calls == ["https://remotive.com/aggregate/1", *routes]


def _capture_module():
    spec = importlib.util.spec_from_file_location("generated_capture_jaa04", CAPTURE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _snapshot(path: Path) -> list[dict[str, str]]:
    records = [{"job_key": f"generated:{number:02d}",
                "url": f"https://jobs.generated.test/{number:02d}",
                "company": f"Generated {number:02d}", "title": "Platform Engineer",
                "payload_hash": hashlib.sha256(str(number).encode()).hexdigest()}
               for number in range(1, 31)]
    path.write_text(json.dumps({"records": records, "records_hash": content_hash(records)}), encoding="utf-8")
    return records


def _bootstrap(work_db: Path, records: list[dict[str, str]]) -> CareerDatabase:
    database = CareerDatabase(work_db)
    OpportunityGate(database).bootstrap([
        scored_job_from_payload({"board": "generated", "job_id": row["job_key"].split(":")[1],
                                 "url": row["url"], "company": row["company"],
                                 "job_title": row["title"], "fit": .8, "opportunity": .9,
                                 "final": 90, "extraction_confidence": 1})
        for row in records
    ])
    return database


def test_stable_workspace_resumes_four_completed_plus_stale_lease_and_publishes_exactly_thirty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Completed dossiers are immutable; only the remaining 26 are fetched once."""
    module = _capture_module()
    snapshot = tmp_path / "admitted.json"
    records = _snapshot(snapshot)
    workspace, destination = tmp_path / "workspace", tmp_path / "published"
    workspace.mkdir()
    database = _bootstrap(workspace / "queue.sqlite3", records)
    cache = RawResponseCache(workspace / "raw")
    fetched: list[str] = []

    class GeneratedWorker:
        def __init__(self, db, _worker_id, worker_cache, **_):
            self.database, self.cache = db, worker_cache

        def run_once(self):
            task = self.database.claim_research("generated-worker")
            if task is None:
                return None
            fetched.append(task.job_key)
            body = f"generated evidence {task.job_key}".encode()
            digest, ref = self.cache.store(body)
            dossier = {"schema_version": "generated.fixture.v1", "job_key": task.job_key,
                       "raw_cache_root": str(self.cache.root),
                       "sources": [{"id": f"source:{task.job_key}", "url": task.url,
                                    "content_sha256": digest, "raw_response_ref": ref, "status_code": 200}],
                       "claims": [], "edges": []}
            self.database.complete_research(job_key=task.job_key, worker_id="generated-worker",
                                            dossier=dossier, dossier_hash=content_hash(dossier))
            return task.job_key

    class GeneratedCoordinator:
        def __init__(self, _database, worker): self.worker = worker
        def run_once(self): return self.worker.run_once()

    # Establish four durable completed dossiers before the resumed invocation.
    seed_worker = GeneratedWorker(database, "seed", cache)
    for _ in range(4):
        assert seed_worker.run_once()
    stale = database.claim_research("dead-worker")
    assert stale and stale.job_key == "generated:05"
    with database.connection() as connection:
        connection.execute("UPDATE employer_research_queue SET lease_until='2000-01-01T00:00:00+00:00' WHERE job_key=?", (stale.job_key,))
    fetched.clear()

    def generated_loader(path: Path, _cache: RawResponseCache, **_):
        return json.loads(path.read_text(encoding="utf-8"))["dossiers"]

    monkeypatch.setattr(module, "EmployerResearchWorker", GeneratedWorker)
    monkeypatch.setattr(module, "Opportunity1Coordinator", GeneratedCoordinator)
    monkeypatch.setattr(module, "load_frozen_dossiers", generated_loader)
    monkeypatch.setattr(module, "_revision", lambda: "generated-revision")
    monkeypatch.setattr(module, "source_content_revision", lambda _root: "generated-content")
    module.capture(snapshot, destination, workspace=workspace, timeout_seconds=1)

    assert fetched == [f"generated:{number:02d}" for number in range(5, 31)]
    assert len(fetched) == len(set(fetched)) == 26
    assert destination.is_dir() and not list(destination.parent.glob("jaa04-complete-*"))
    envelope = json.loads((destination / "frozen_dossiers.json").read_text(encoding="utf-8"))
    receipt = json.loads((destination / "capture_receipt.json").read_text(encoding="utf-8"))
    assert len(envelope["dossiers"]) == receipt["captured_count"] == 30
    assert len(list(destination.glob("capture_receipt.json"))) == 1


def test_failing_retry_keeps_prior_pointer_publication_and_exposes_actionable_queue_state(tmp_path: Path) -> None:
    """A failed staged retry cannot replace an already published corpus pointer."""
    from career_automation.corpus_publication import publish_by_pointer, write_inventory

    previous = tmp_path / "previous"
    previous.mkdir()
    (previous / "frozen_dossiers.json").write_text("{}", encoding="utf-8")
    (previous / "research_manifest.json").write_text("{}", encoding="utf-8")
    write_inventory(previous)
    pointer = tmp_path / "corpus"
    publish_by_pointer(previous, pointer, lambda _: None)
    before = pointer.resolve()

    retry = tmp_path / "retry"
    retry.mkdir()
    (retry / "frozen_dossiers.json").write_text("partial", encoding="utf-8")
    write_inventory(retry)
    with pytest.raises(ValueError, match="inventory"):
        publish_by_pointer(retry, pointer, lambda _: None)
    assert pointer.resolve() == before

    database = _bootstrap(tmp_path / "retry.sqlite3", _snapshot(tmp_path / "retry-input.json")[:1])
    task = database.claim_research("failing-worker")
    assert task is not None
    database.record_research_failure(job_key=task.job_key, worker_id="failing-worker", error="RuntimeError: generated transport failed")
    with database.connection() as connection:
        row = connection.execute("SELECT status,attempts,last_error FROM employer_research_queue").fetchone()
    assert tuple(row) == ("leased", 1, "RuntimeError: generated transport failed")
