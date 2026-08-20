from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from market_aligner.assessment.opportunity import apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, score
from market_aligner.cli import build_parser
from market_aligner.collectors.engine import Collector
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.domain.contracts import JobUrl, RawPosting, write_jsonl
from market_aligner.research.public_provider import (
    CanonicalCollectorVacancyLoader, PlannedCitation, PlannedClaim, PlannedSupport,
    PublicResearchError, PublicResearchPlan, ScraplingPublicSourceFetcher,
    SourceBoundResearchProvider, _safe_public_url,
)
from market_aligner.research.models import ResearchDossier
from market_aligner.research.store import AssessmentStore
from market_aligner.research.worker import ResearchWorker
from market_aligner.service.api import CollectionService
from market_aligner.state.vacancies import (
    JobDatabase,
    VacancyRefreshConflict,
    raw_posting_bytes,
    raw_posting_content_sha256,
    raw_posting_from_bytes,
)

DIGEST = "a" * 64
PROMOTION = "b" * 64
BODY = b"Build agentic software systems."
URL = "https://apply.workable.com/cogna/j/847CFBC5F4"
JOB_KEY = "workable:cogna:847CFBC5F4"


def _collector(path: Path) -> tuple[CanonicalCollectorVacancyLoader, str]:
    database = JobDatabase(path)
    database.upsert_discovered(JobUrl("workable", "cogna:847CFBC5F4", URL))
    database.store_raw(
        RawPosting(
            "workable", "cogna:847CFBC5F4", URL,
            "2026-08-21T00:00:00+00:00", BODY.decode(), None,
        )
    )
    with database.connect() as connection:
        digest = connection.execute(
            "SELECT content_hash FROM postings WHERE key=?", (JOB_KEY,)
        ).fetchone()[0]
    return CanonicalCollectorVacancyLoader(path), digest


def _legacy_bridge_collector(
    path: Path,
) -> tuple[CanonicalCollectorVacancyLoader, str, str]:
    database = JobDatabase(path)
    database.upsert_discovered(JobUrl("workable", "cogna:847CFBC5F4", URL))
    raw = RawPosting(
        "workable", "cogna:847CFBC5F4", URL,
        "2026-08-21T00:00:00+00:00", BODY.decode(), {"z": 1, "a": 2},
    )
    database.store_raw(raw)
    with database.connect() as connection:
        legacy_digest = connection.execute(
            "SELECT content_hash FROM postings WHERE key=?", (JOB_KEY,)
        ).fetchone()[0]
    canonical_raw = raw_posting_from_bytes(raw_posting_bytes(raw))
    canonical_digest = raw_posting_content_sha256(canonical_raw)
    assert legacy_digest != canonical_digest
    return CanonicalCollectorVacancyLoader(path), legacy_digest, canonical_digest


def _canonical_collection_refresh(
    root: Path,
    *,
    raw_text: str = BODY.decode(),
    operation_id: str = "unchanged-research-refresh",
) -> tuple[Path, JobDatabase, Path]:
    database_relative = Path("scraper/data_overnight/jobs.sqlite3")
    database = JobDatabase(root / database_relative, data_home=root)
    with database.connect() as connection:
        stored = connection.execute(
            """SELECT url,fetched_at,raw_text,raw_json
               FROM postings WHERE key=?""",
            (JOB_KEY,),
        ).fetchone()
    old = RawPosting(
        "workable", "cogna:847CFBC5F4", str(stored[0]), str(stored[1]),
        stored[2], None if stored[3] is None else json.loads(str(stored[3])),
    )
    write_jsonl(
        root / "raw" / "vacancies" / "workable" / "cogna_847CFBC5F4.json",
        [old],
    )
    config = root / "collect.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "boards": {"enabled": ["workable"]},
                "collection": {"fetch_workers": 1, "source_workers": 1},
                "io": {
                    "database": str(database_relative),
                    "job_urls": "scraper/data_overnight/job_urls.jsonl",
                    "raw_cache": "raw/vacancies",
                },
                "search_terms": [],
                "workable": {"companies": {"cogna": "Cogna"}},
            }
        ),
        encoding="utf-8",
    )

    class Adapter:
        board = "workable"

        @staticmethod
        def owns(job: JobUrl) -> bool:
            return job.key == JOB_KEY

        @staticmethod
        def fetch(job: JobUrl, live: bool = False) -> RawPosting:
            assert live is True
            return RawPosting(
                job.board, job.job_id, job.url,
                "2026-08-21T01:00:00+00:00", raw_text, old.raw_json,
            )

    def factory(loaded, data_home, log=print):
        return Collector(
            loaded,
            data_home,
            log=log,
            adapter_loader=lambda board, *, config: Adapter(),
        )

    _job, expected, _fetched_at = database.fetched_posting(JOB_KEY)
    receipt = CollectionService(root, collector_factory=factory).refresh_vacancy(
        config,
        job_key=JOB_KEY,
        expected_content_sha256=expected,
        operation_id=operation_id,
        log=lambda _message: None,
    )
    return Path(str(receipt["receipt_path"])), database, config


def _queued_store(path: Path, source_digest: str) -> tuple[AssessmentStore, str]:
    profile = CandidateProfile(
        new_profile_id(), "v1", {"track": TrackProfile(8, 7, 0.8, 6, rationale="fixture")}
    )
    store = AssessmentStore(path)
    result = score(profile, JOB_KEY, "track", AssessmentAxes(8, 8, 9, 1, 9))
    store.upsert_score(
        result, url=URL, title="Software Engineer", company="Cogna",
        extraction_confidence=0.95,
    )
    apply_gate(store, profile.profile_id, result.job_key)
    with store.connection() as connection:
        connection.execute(
            """INSERT INTO assessment_promotions(
                 profile_id,job_key,track,authority_sha256,source_content_sha256,
                 processing_config_sha256,processing_receipt_sha256,
                 processing_result_sha256,score_payload_hash,policy_hash,
                 receipt_bytes,receipt_sha256
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (profile.profile_id, JOB_KEY, "track", "c" * 64, source_digest, "d" * 64,
             "e" * 64, "f" * 64, "2" * 64, "1" * 64, b"{}", PROMOTION),
        )
    return store, profile.profile_id


def _task_and_reset(store: AssessmentStore):
    task = store.claim_research("plan-preview")
    assert task is not None
    with store.connection() as connection:
        connection.execute(
            """UPDATE employer_research_queue SET status='queued',attempts=0,
                 lease_owner=NULL,lease_until=NULL WHERE profile_id=? AND job_key=?""",
            (task.profile_id, task.job_key),
        )
    return task


def _plan(task, source, *, excerpt: str = BODY.decode(), final_url: str = URL):
    start = source.body.index(BODY)
    return PublicResearchPlan(
        task.profile_id, task.job_key, task.company, task.title,
        (PlannedCitation(
            "official_job", URL, "Canonical collector vacancy",
            hashlib.sha256(source.body).hexdigest(), final_url, "canonical_vacancy",
        ),),
        (PlannedClaim(
            BODY.decode(), ("official_job",), 1.0,
            (PlannedSupport(
                "official_job", f"bytes:{start}-{start + len(BODY)}", excerpt
            ),),
        ),),
        task.source_content_sha256, task.vacancy_snapshot_sha256,
        task.promotion_receipt_sha256, ("Hiring manager is unknown.",),
    )


def test_v2_archives_verbatim_claim_and_persists_reconciled_store_binding(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    loader, source_digest = _collector(collector_path)
    store, _ = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    archive = tmp_path / "state" / "public-employer-research-v2"
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source), repository_root=repository, archive_root=archive,
        canonical_vacancy_loader=loader,
    )
    run = ResearchWorker(store, provider, "worker-v2").run_one()
    assert run.status == "completed", run.error
    result = provider.last_materialization
    assert result is not None
    assert result.semantic_receipt_sha256 != result.receipt_file_sha256
    assert hashlib.sha256(result.receipt_path.read_bytes()).hexdigest() == result.receipt_file_sha256
    with store.connection() as connection:
        dossier = connection.execute(
            "SELECT dossier_json,dossier_hash FROM employer_dossiers"
        ).fetchone()
        evidence = connection.execute("SELECT * FROM employer_research_evidence").fetchone()
    document = json.loads(dossier["dossier_json"])
    assert document["schema_version"] == "market-aligner.employer-dossier.v2"
    assert document["claims"][0]["supports"][0]["excerpt"] == BODY.decode()
    assert evidence["dossier_hash"] == dossier["dossier_hash"]
    assert evidence["archive_root_identity"] == "state/public-employer-research-v2"
    assert evidence["semantic_receipt_sha256"] == result.semantic_receipt_sha256
    assert store.research_evidence(task.profile_id, task.job_key)["dossier_hash"] == dossier[
        "dossier_hash"
    ]
    assert store.refresh_completed_research_if_needed(task.profile_id, task.job_key) is False
    result.receipt_path.unlink()
    assert store.refresh_completed_research_if_needed(task.profile_id, task.job_key) is True
    with store.connection() as connection:
        queue = connection.execute(
            "SELECT status,last_error FROM employer_research_queue"
        ).fetchone()
        assert queue["status"] == "queued"
        assert "valid current v2 evidence" in queue["last_error"]
        assert connection.execute(
            "SELECT COUNT(*) FROM employer_research_evidence"
        ).fetchone()[0] == 0


def test_canonical_unchanged_refresh_requeues_and_same_worker_rebuilds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    loader, source_digest = _collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    first_task = _task_and_reset(store)
    first_source = loader(first_task)
    archive = tmp_path / "state" / "public-employer-research-v2"
    first_provider = SourceBoundResearchProvider(
        plan=_plan(first_task, first_source),
        repository_root=repository,
        archive_root=archive,
        canonical_vacancy_loader=loader,
    )
    assert ResearchWorker(store, first_provider, "worker-old").run_one().status == "completed"
    first_materialization = first_provider.last_materialization
    assert first_materialization is not None

    receipt_path, database, config = _canonical_collection_refresh(tmp_path)
    original_verify = JobDatabase.verify_vacancy_refresh_receipt
    lock_observed = False

    def verify_with_lock_probe(self, *args, **kwargs):
        nonlocal lock_observed
        if not lock_observed and kwargs.get("schema") == "collector":
            with sqlite3.connect(self.path, timeout=0) as contender:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    contender.execute("BEGIN IMMEDIATE")
            lock_observed = True
        return original_verify(self, *args, **kwargs)

    monkeypatch.setattr(
        JobDatabase, "verify_vacancy_refresh_receipt", verify_with_lock_probe
    )
    assert store.refresh_completed_research_if_needed(
        profile_id,
        JOB_KEY,
        collection_refresh_receipt_path=receipt_path,
        collection_config_path=config,
    ) is True
    assert lock_observed
    assert store.refresh_completed_research_if_needed(
        profile_id,
        JOB_KEY,
        collection_refresh_receipt_path=receipt_path,
        collection_config_path=config,
    ) is False

    second_task = _task_and_reset(store)
    refreshed_loader = CanonicalCollectorVacancyLoader(
        data_home=tmp_path, collection_config_path=config
    )
    second_source = refreshed_loader(second_task)
    assert second_source.accessed_at == "2026-08-21T01:00:00+00:00"
    second_provider = SourceBoundResearchProvider(
        plan=_plan(second_task, second_source),
        repository_root=repository,
        archive_root=archive,
        canonical_vacancy_loader=refreshed_loader,
    )
    run = ResearchWorker(store, second_provider, "worker-new").run_one()
    assert run.status == "completed", run.error
    second_materialization = second_provider.last_materialization
    assert second_materialization is not None
    assert (
        first_materialization.dossier.canonical_vacancy_object_sha256
        != second_materialization.dossier.canonical_vacancy_object_sha256
    )
    assert store.refresh_completed_research_if_needed(
        profile_id,
        JOB_KEY,
        collection_refresh_receipt_path=receipt_path,
        collection_config_path=config,
    ) is False
    with store.connection() as connection:
        event = connection.execute(
            """SELECT payload_json FROM assessment_events
               WHERE event_type='employer_research_collection_refresh_queued'"""
        ).fetchone()
        assert connection.execute(
            "SELECT COUNT(*) FROM employer_research_evidence"
        ).fetchone()[0] == 1
    payload = json.loads(event["payload_json"])
    receipt = json.loads(receipt_path.read_bytes())
    assert payload["collection_operation_id"] == "unchanged-research-refresh"
    assert payload["collection_transition_sha256"] == receipt["transition_sha256"]


def test_dual_identity_v3_accepts_legacy_promotion_without_relabeling(
    tmp_path: Path,
) -> None:
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    loader, legacy_digest, canonical_digest = _legacy_bridge_collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", legacy_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    repository = tmp_path / "repo"
    repository.mkdir()
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source),
        repository_root=repository,
        archive_root=tmp_path / "state" / "public-employer-research-v2",
        canonical_vacancy_loader=loader,
    )
    assert ResearchWorker(store, provider, "legacy-worker").run_one().status == "completed"

    receipt_path, _database, config = _canonical_collection_refresh(tmp_path)
    receipt = json.loads(receipt_path.read_bytes())
    assert receipt["changed"] is False
    assert receipt["old_content_sha256"] == legacy_digest
    assert receipt["old_canonical_content_sha256"] == canonical_digest
    assert receipt["new_content_sha256"] == canonical_digest
    assert store.refresh_completed_research_if_needed(
        profile_id,
        JOB_KEY,
        collection_refresh_receipt_path=receipt_path,
        collection_config_path=config,
    ) is True
    with store.connection() as connection:
        promotion = connection.execute(
            """SELECT source_content_sha256 FROM assessment_promotions
               WHERE profile_id=? AND job_key=?""",
            (profile_id, JOB_KEY),
        ).fetchone()[0]
        event = json.loads(connection.execute(
            """SELECT payload_json FROM assessment_events
               WHERE event_type='employer_research_collection_refresh_queued'"""
        ).fetchone()[0])
    assert promotion == legacy_digest
    assert event["source_content_sha256"] == legacy_digest
    assert event["old_collector_content_sha256"] == legacy_digest
    assert event["old_canonical_content_sha256"] == canonical_digest

    refreshed_task = _task_and_reset(store)
    assert refreshed_task.source_content_sha256 == legacy_digest
    assert refreshed_task.refresh_event_id is not None
    assert refreshed_task.refresh_legacy_content_sha256 == legacy_digest
    assert refreshed_task.refresh_canonical_content_sha256 == canonical_digest
    assert refreshed_task.refresh_receipt_sha256 == receipt["receipt_sha256"]
    assert refreshed_task.refresh_transition_sha256 == receipt["transition_sha256"]
    assert refreshed_task.refresh_promotion_receipt_sha256 == PROMOTION

    bridge_loader = CanonicalCollectorVacancyLoader(
        data_home=tmp_path, collection_config_path=config
    )
    refreshed_source = bridge_loader(refreshed_task)
    envelope = json.loads(refreshed_source.body)
    assert envelope["schema_version"] == "market-aligner.canonical-collector-vacancy.v2"
    assert envelope["authority_source_content_sha256"] == legacy_digest
    assert envelope["canonical_current_content_sha256"] == canonical_digest
    assert refreshed_source.authority_source_content_sha256 == legacy_digest

    provider = SourceBoundResearchProvider(
        plan=_plan(refreshed_task, refreshed_source),
        repository_root=repository,
        archive_root=tmp_path / "state" / "public-employer-research-v2",
        canonical_vacancy_loader=bridge_loader,
    )
    rebuilt = ResearchWorker(store, provider, "bridge-worker").run_one()
    assert rebuilt.status == "completed", rebuilt.error
    assert provider.last_materialization is not None
    assert provider.last_materialization.dossier.source_content_sha256 == legacy_digest
    with store.connection() as connection:
        assert connection.execute(
            "SELECT source_content_sha256 FROM employer_research_evidence"
        ).fetchone()[0] == legacy_digest
    apply_gate(store, profile_id, JOB_KEY)
    with store.connection() as connection:
        assert connection.execute(
            "SELECT refresh_event_id FROM employer_research_queue"
        ).fetchone()[0] is None


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("refresh_event_id", None),
        ("refresh_event_id", 999999),
        ("refresh_receipt_sha256", "9" * 64),
        ("refresh_receipt_file_sha256", "8" * 64),
        ("refresh_transition_sha256", "7" * 64),
        ("refresh_id", "substituted-refresh"),
        ("refresh_context_sha256", "6" * 64),
        ("refresh_operation_id", "substituted-operation"),
        ("refresh_legacy_content_sha256", "5" * 64),
        ("refresh_canonical_content_sha256", "4" * 64),
        ("refresh_raw_object_sha256", "3" * 64),
        ("refresh_fetched_at", "2026-08-21T09:00:00+00:00"),
        ("refresh_promotion_receipt_sha256", "2" * 64),
    ),
)
def test_refresh_worker_bridge_rejects_task_identity_substitution(
    tmp_path: Path, field: str, replacement: object
) -> None:
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    loader, legacy_digest, _canonical_digest = _legacy_bridge_collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", legacy_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    repository = tmp_path / "repo"
    repository.mkdir()
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source), repository_root=repository,
        archive_root=tmp_path / "state" / "public-employer-research-v2",
        canonical_vacancy_loader=loader,
    )
    assert ResearchWorker(store, provider, "legacy-worker").run_one().status == "completed"
    receipt_path, _database, config = _canonical_collection_refresh(tmp_path)
    assert store.refresh_completed_research_if_needed(
        profile_id, JOB_KEY,
        collection_refresh_receipt_path=receipt_path,
        collection_config_path=config,
    ) is True
    refreshed_task = _task_and_reset(store)
    bridge = CanonicalCollectorVacancyLoader(
        data_home=tmp_path, collection_config_path=config
    )
    with pytest.raises(PublicResearchError):
        bridge(replace(refreshed_task, **{field: replacement}))


def test_ordinary_research_task_has_no_refresh_bridge_and_v1_envelope(
    tmp_path: Path,
) -> None:
    loader, digest = _collector(tmp_path / "collector.sqlite3")
    store, _profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", digest
    )
    task = _task_and_reset(store)
    assert task.refresh_event_id is None
    assert task.refresh_receipt_sha256 is None
    source = loader(task)
    assert json.loads(source.body)["schema_version"] == (
        "market-aligner.canonical-collector-vacancy.v1"
    )


def test_refresh_worker_bridge_reads_receipt_and_posting_in_one_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    loader, legacy_digest, _canonical_digest = _legacy_bridge_collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", legacy_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    repository = tmp_path / "repo"
    repository.mkdir()
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source), repository_root=repository,
        archive_root=tmp_path / "state" / "public-employer-research-v2",
        canonical_vacancy_loader=loader,
    )
    assert ResearchWorker(store, provider, "legacy-worker").run_one().status == "completed"
    receipt_path, database, config = _canonical_collection_refresh(tmp_path)
    assert store.refresh_completed_research_if_needed(
        profile_id, JOB_KEY,
        collection_refresh_receipt_path=receipt_path,
        collection_config_path=config,
    ) is True
    refreshed_task = _task_and_reset(store)
    original_verify = JobDatabase.verify_vacancy_refresh_receipt
    raced = False

    def verify_then_race(self, *args, **kwargs):
        nonlocal raced
        verified = original_verify(self, *args, **kwargs)
        if not raced and kwargs.get("schema", "main") == "main":
            with sqlite3.connect(self.path) as contender:
                contender.execute(
                    "UPDATE postings SET fetched_at=? WHERE key=?",
                    ("2026-08-21T09:00:00+00:00", JOB_KEY),
                )
            raced = True
        return verified

    monkeypatch.setattr(JobDatabase, "verify_vacancy_refresh_receipt", verify_then_race)
    bridge = CanonicalCollectorVacancyLoader(
        data_home=tmp_path, collection_config_path=config
    )
    result = bridge(refreshed_task)
    assert raced
    assert result.accessed_at == refreshed_task.refresh_fetched_at
    assert json.loads(result.body)["fetched_at"] == refreshed_task.refresh_fetched_at
    with pytest.raises(PublicResearchError):
        bridge(refreshed_task)


def test_refresh_worker_bridge_rejects_canonical_event_substitution(
    tmp_path: Path,
) -> None:
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    loader, legacy_digest, _canonical_digest = _legacy_bridge_collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", legacy_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    repository = tmp_path / "repo"
    repository.mkdir()
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source), repository_root=repository,
        archive_root=tmp_path / "state" / "public-employer-research-v2",
        canonical_vacancy_loader=loader,
    )
    assert ResearchWorker(store, provider, "legacy-worker").run_one().status == "completed"
    receipt_path, _database, config = _canonical_collection_refresh(tmp_path)
    assert store.refresh_completed_research_if_needed(
        profile_id, JOB_KEY,
        collection_refresh_receipt_path=receipt_path,
        collection_config_path=config,
    ) is True
    refreshed_task = _task_and_reset(store)
    with store.connection() as connection:
        payload = json.loads(connection.execute(
            "SELECT payload_json FROM assessment_events WHERE id=?",
            (refreshed_task.refresh_event_id,),
        ).fetchone()[0])
        payload["new_fetched_at"] = "2026-08-21T09:00:00+00:00"
        connection.execute(
            "UPDATE assessment_events SET payload_json=? WHERE id=?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),
             refreshed_task.refresh_event_id),
        )
    bridge = CanonicalCollectorVacancyLoader(
        data_home=tmp_path, collection_config_path=config
    )
    with pytest.raises(PublicResearchError, match="event differs"):
        bridge(refreshed_task)


def test_dual_identity_v3_rejects_relabelled_promotion_and_canonical_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    _loader, legacy_digest, canonical_digest = _legacy_bridge_collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", canonical_digest
    )
    with store.connection() as connection:
        connection.execute(
            """UPDATE employer_research_queue SET status='completed'
               WHERE profile_id=? AND job_key=?""",
            (profile_id, JOB_KEY),
        )
    receipt_path, _database, config = _canonical_collection_refresh(tmp_path)
    with pytest.raises(ValueError, match="current assessment promotion"):
        store.refresh_completed_research_if_needed(
            profile_id,
            JOB_KEY,
            collection_refresh_receipt_path=receipt_path,
            collection_config_path=config,
        )

    with store.connection() as connection:
        connection.execute(
            """UPDATE assessment_promotions SET source_content_sha256=?
               WHERE profile_id=? AND job_key=?""",
            (legacy_digest, profile_id, JOB_KEY),
        )
    original_verify = JobDatabase.verify_vacancy_refresh_receipt

    def verify_with_semantic_drift(self, *args, **kwargs):
        verified = original_verify(self, *args, **kwargs)
        return replace(verified, old_canonical_content_sha256="f" * 64)

    monkeypatch.setattr(
        JobDatabase, "verify_vacancy_refresh_receipt", verify_with_semantic_drift
    )
    with pytest.raises(ValueError, match="changed vacancy content"):
        store.refresh_completed_research_if_needed(
            profile_id,
            JOB_KEY,
            collection_refresh_receipt_path=receipt_path,
            collection_config_path=config,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "receipt", "receipt_symlink", "receipt_hardlink", "receipt_directory_symlink",
        "wrong_path", "object", "object_symlink", "object_hardlink", "journal",
        "current_row",
    ),
)
def test_canonical_refresh_admission_rejects_substitution(
    tmp_path: Path, mutation: str
) -> None:
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    _loader, source_digest = _collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    receipt_path, database, config = _canonical_collection_refresh(tmp_path)
    receipt = json.loads(receipt_path.read_bytes())
    if mutation == "receipt_symlink":
        real = receipt_path.with_suffix(".real")
        receipt_path.rename(real)
        receipt_path.symlink_to(real)
    elif mutation == "receipt_hardlink":
        receipt_path.with_suffix(".alias").hardlink_to(receipt_path)
    elif mutation == "receipt_directory_symlink":
        directory = receipt_path.parent
        real_directory = directory.with_name("collection-refresh-receipts-real")
        directory.rename(real_directory)
        directory.symlink_to(real_directory, target_is_directory=True)
    elif mutation == "wrong_path":
        outside = tmp_path / "outside" / receipt_path.name
        outside.parent.mkdir()
        outside.write_bytes(receipt_path.read_bytes())
        outside.chmod(0o600)
        receipt_path = outside
    elif mutation == "object_symlink":
        object_path = tmp_path / str(receipt["new_raw_object_path"])
        real = object_path.with_suffix(".real")
        object_path.rename(real)
        object_path.symlink_to(real)
    elif mutation == "object_hardlink":
        object_path = tmp_path / str(receipt["new_raw_object_path"])
        object_path.with_suffix(".alias").hardlink_to(object_path)
    elif mutation == "object":
        (tmp_path / str(receipt["new_raw_object_path"])).write_bytes(b"substituted")
    elif mutation == "journal":
        with sqlite3.connect(database.path) as connection:
            connection.execute(
                "UPDATE vacancy_refreshes SET transition_sha256=? WHERE operation_id=?",
                ("f" * 64, "unchanged-research-refresh"),
            )
            connection.commit()
    elif mutation == "current_row":
        with sqlite3.connect(database.path) as connection:
            connection.execute(
                "UPDATE postings SET fetched_at=? WHERE key=?",
                ("2026-08-21T02:00:00+00:00", JOB_KEY),
            )
            connection.commit()
    else:
        receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    with pytest.raises(VacancyRefreshConflict):
        store.refresh_completed_research_if_needed(
            profile_id,
            JOB_KEY,
            collection_refresh_receipt_path=receipt_path,
            collection_config_path=config,
        )
    with store.connection() as connection:
        assert connection.execute(
            "SELECT status FROM employer_research_queue"
        ).fetchone()[0] == "queued"
        assert connection.execute(
            """SELECT COUNT(*) FROM assessment_events
               WHERE event_type='employer_research_collection_refresh_queued'"""
        ).fetchone()[0] == 0


def test_changed_refresh_wrong_data_home_and_noncanonical_store_are_rejected(
    tmp_path: Path,
) -> None:
    collector_path = tmp_path / "scraper" / "data_overnight" / "jobs.sqlite3"
    _loader, source_digest = _collector(collector_path)
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    changed_receipt, _database, config = _canonical_collection_refresh(
        tmp_path, raw_text="Changed official vacancy content."
    )
    with pytest.raises(ValueError, match="changed vacancy content"):
        store.refresh_completed_research_if_needed(
            profile_id,
            JOB_KEY,
            collection_refresh_receipt_path=changed_receipt,
            collection_config_path=config,
        )

    substituted_config = tmp_path / "substituted.yaml"
    substituted = yaml.safe_load(config.read_text(encoding="utf-8"))
    substituted["io"]["database"] = "state/attacker.sqlite3"
    substituted_config.write_text(yaml.safe_dump(substituted), encoding="utf-8")
    with pytest.raises(VacancyRefreshConflict, match="config identity"):
        store.refresh_completed_research_if_needed(
            profile_id,
            JOB_KEY,
            collection_refresh_receipt_path=changed_receipt,
            collection_config_path=substituted_config,
        )
    absolute_config = tmp_path / "absolute.yaml"
    absolute = yaml.safe_load(config.read_text(encoding="utf-8"))
    absolute["io"]["database"] = str(tmp_path / "elsewhere.sqlite3")
    absolute_config.write_text(yaml.safe_dump(absolute), encoding="utf-8")
    with pytest.raises(VacancyRefreshConflict, match="config identity"):
        store.refresh_completed_research_if_needed(
            profile_id,
            JOB_KEY,
            collection_refresh_receipt_path=changed_receipt,
            collection_config_path=absolute_config,
        )


def test_refresh_research_cli_requires_receipt_and_has_no_force() -> None:
    parsed = build_parser().parse_args(
        [
            "refresh-research",
            "--profile-id", "prf_" + "1" * 32,
            "--job-key", JOB_KEY,
            "--collection-refresh-receipt", "/tmp/receipt.json",
            "--collection-config", "/tmp/collection.yaml",
        ]
    )
    assert parsed.collection_refresh_receipt == Path("/tmp/receipt.json")
    assert parsed.collection_config == Path("/tmp/collection.yaml")
    assert "force" not in vars(parsed)


def test_v2_rejects_loader_shell_or_any_claim_without_exact_support(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    loader, source_digest = _collector(tmp_path / "state" / "vacancies.sqlite3")
    store, _ = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source, excerpt="The shell does not contain this claim."),
        repository_root=repository, archive_root=tmp_path / "state" / "research",
        canonical_vacancy_loader=loader,
    )
    run = ResearchWorker(store, provider, "unsupported").run_one()
    assert run.status == "retry_scheduled"
    assert "unsupported by archived bytes" in (run.error or "")
    with store.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM employer_dossiers").fetchone()[0] == 0


def test_v2_rejects_final_url_substitution_before_store_completion(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    loader, source_digest = _collector(tmp_path / "state" / "vacancies.sqlite3")
    store, _ = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source, final_url="https://example.com/substituted"),
        repository_root=repository,
        archive_root=tmp_path / "state" / "research",
        canonical_vacancy_loader=loader,
    )
    run = ResearchWorker(store, provider, "substitution").run_one()
    assert run.status == "retry_scheduled"
    assert "final source" in (run.error or "")


def test_url_gate_rejects_dns_private_targets_and_malformed_or_nonstandard_ports() -> None:
    def private_dns(*_args, **_kwargs):
        return ((None, None, None, None, ("127.0.0.1", 443)),)
    with pytest.raises(PublicResearchError, match="non-public"):
        _safe_public_url("https://localtest.me/path", resolver=private_dns)
    with pytest.raises(PublicResearchError, match="port"):
        _safe_public_url("https://example.com:bad/path")
    with pytest.raises(PublicResearchError, match="credential-free"):
        _safe_public_url("https://example.com:444/path")


def test_archive_rejects_symlink_ancestor_and_component_escape(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    loader, source_digest = _collector(tmp_path / "state" / "vacancies.sqlite3")
    store, _ = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    task = _task_and_reset(store)
    source = loader(task)
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "linked-parent"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(PublicResearchError, match="unsafe component"):
        SourceBoundResearchProvider(
            plan=_plan(task, source), repository_root=repository,
            archive_root=link / "research", canonical_vacancy_loader=loader,
        )
    root = tmp_path / "state" / "safe-research"
    provider = SourceBoundResearchProvider(
        plan=_plan(task, source), repository_root=repository, archive_root=root,
        canonical_vacancy_loader=loader,
    )
    escape = tmp_path / "escape"
    escape.mkdir()
    (root / "objects").symlink_to(escape, target_is_directory=True)
    with pytest.raises(PublicResearchError, match="component is unsafe"):
        provider.materialize(task)
    assert not any(escape.iterdir())


def test_scrapling_contract_uses_safe_redirect_mode_when_dependency_is_installed(
    monkeypatch,
) -> None:
    scrapling = pytest.importorskip("scrapling.fetchers")
    calls = {}
    class Page:
        url = URL
        history = ()
        headers = {"content-type": "text/plain"}
        status = 200
        body = BODY
    def fake_get(url, **kwargs):
        calls.update(kwargs)
        return Page()
    def public_dns(*_args, **_kwargs):
        return ((None, None, None, None, ("93.184.216.34", 443)),)
    monkeypatch.setattr(scrapling.Fetcher, "get", fake_get)
    result = ScraplingPublicSourceFetcher(resolver=public_dns)(URL)
    assert calls["follow_redirects"] == "safe"
    assert result.redirect_chain == (URL,)


def test_legacy_dossier_has_no_v2_store_binding(tmp_path: Path) -> None:
    _, source_digest = _collector(tmp_path / "state" / "vacancies.sqlite3")
    store, profile_id = _queued_store(
        tmp_path / "state" / "assessments.sqlite3", source_digest
    )
    with pytest.raises(KeyError):
        store.research_evidence(profile_id, JOB_KEY)
    task = store.claim_research("legacy-worker")
    assert task is not None
    store.complete_research(
        ResearchDossier(
            task.profile_id, task.job_key, task.company, task.title, (), ()
        ),
        "legacy-worker",
    )
    assert store.refresh_completed_research_if_needed(profile_id, JOB_KEY) is True
    assert store.refresh_completed_research_if_needed(profile_id, JOB_KEY) is False
    with store.connection() as connection:
        queue = connection.execute(
            "SELECT status,lease_owner,lease_until FROM employer_research_queue"
        ).fetchone()
        event_count = connection.execute(
            """SELECT COUNT(*) FROM assessment_events
               WHERE event_type='employer_research_v2_refresh_queued'"""
        ).fetchone()[0]
    assert queue["status"] == "queued"
    assert queue["lease_owner"] is None and queue["lease_until"] is None
    assert event_count == 1
