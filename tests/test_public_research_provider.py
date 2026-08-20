from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from market_aligner.assessment.opportunity import apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, score
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.domain.contracts import JobUrl, RawPosting
from market_aligner.research.public_provider import (
    CanonicalCollectorVacancyLoader, PlannedCitation, PlannedClaim, PlannedSupport,
    PublicResearchError, PublicResearchPlan, ScraplingPublicSourceFetcher,
    SourceBoundResearchProvider, _safe_public_url,
)
from market_aligner.research.store import AssessmentStore
from market_aligner.research.worker import ResearchWorker
from market_aligner.state.vacancies import JobDatabase

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
    loader, source_digest = _collector(tmp_path / "state" / "vacancies.sqlite3")
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
