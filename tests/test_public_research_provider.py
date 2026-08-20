from __future__ import annotations

import hashlib
import json
from pathlib import Path

from market_aligner.assessment.opportunity import apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, score
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.research.public_provider import (
    FetchedPublicSource,
    PlannedCitation,
    PlannedClaim,
    PublicResearchPlan,
    SourceBoundResearchProvider,
)
from market_aligner.research.store import AssessmentStore
from market_aligner.research.worker import ResearchWorker


def _queued_store(path: Path) -> tuple[AssessmentStore, str]:
    profile = CandidateProfile(
        new_profile_id(),
        "v1",
        {"track": TrackProfile(8, 7, 0.8, 6, rationale="fixture")},
    )
    store = AssessmentStore(path)
    result = score(profile, "workable:cogna:1", "track", AssessmentAxes(8, 8, 9, 1, 9))
    store.upsert_score(
        result,
        url="https://apply.workable.com/cogna/j/1",
        title="Software Engineer",
        company="Cogna",
        extraction_confidence=0.95,
    )
    apply_gate(store, profile.profile_id, result.job_key)
    return store, profile.profile_id


def test_source_bound_provider_archives_and_completes_canonical_research(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    store, profile_id = _queued_store(tmp_path / "state.sqlite3")
    bodies = {
        "https://cogna.example/job": b"<html>role source</html>",
        "https://cogna.example/customers": b"<html>customer source</html>",
    }

    def fetch(url: str) -> FetchedPublicSource:
        return FetchedPublicSource(
            url,
            url,
            200,
            bodies[url],
            "text/html; charset=utf-8",
            "2026-08-21T00:00:00+00:00",
        )

    plan = PublicResearchPlan(
        profile_id,
        "workable:cogna:1",
        "Cogna",
        "Software Engineer",
        (
            PlannedCitation("job", "https://cogna.example/job", "Official role"),
            PlannedCitation(
                "customers", "https://cogna.example/customers", "Customer results"
            ),
        ),
        (
            PlannedClaim("The role covers agentic software systems.", ("job",), 1.0),
            PlannedClaim(
                "Cogna publishes operational customer case studies.",
                ("customers",),
                1.0,
            ),
        ),
        ("Hiring manager is unknown.",),
    )
    archive = tmp_path / "external" / "research"
    provider = SourceBoundResearchProvider(
        plan=plan,
        repository_root=repository,
        archive_root=archive,
        fetcher=fetch,
    )
    run = ResearchWorker(store, provider, "worker-1").run_one()
    assert run.status == "completed"
    assert provider.last_materialization is not None
    assert run.dossier_sha256 == provider.last_materialization.dossier_sha256
    receipt = json.loads(provider.last_materialization.receipt_path.read_bytes())
    assert receipt["application_authority"] is False
    assert receipt["release_authority"] is False
    assert receipt["receipt_sha256"] == provider.last_materialization.receipt_sha256
    for url, body in bodies.items():
        digest = hashlib.sha256(body).hexdigest()
        assert (archive / "objects" / digest).read_bytes() == body
        assert (archive / "objects" / digest).stat().st_mode & 0o077 == 0
    with store.connection() as connection:
        queue = connection.execute(
            "SELECT status FROM employer_research_queue WHERE profile_id=? AND job_key=?",
            (profile_id, "workable:cogna:1"),
        ).fetchone()
        dossier = connection.execute(
            "SELECT dossier_hash,dossier_json FROM employer_dossiers WHERE profile_id=? AND job_key=?",
            (profile_id, "workable:cogna:1"),
        ).fetchone()
    assert queue["status"] == "completed"
    assert dossier["dossier_hash"] == run.dossier_sha256
    assert json.loads(dossier["dossier_json"])["claims"][0]["citation_ids"] == ["job"]
    assert ResearchWorker(store, provider, "worker-2").run_one().status == "idle"


def test_source_bound_provider_requeues_on_task_or_source_substitution(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    store, profile_id = _queued_store(tmp_path / "state.sqlite3")
    plan = PublicResearchPlan(
        profile_id,
        "workable:cogna:1",
        "Different Company",
        "Software Engineer",
        (PlannedCitation("job", "https://cogna.example/job", "Official role"),),
        (PlannedClaim("Claim", ("job",), 1.0),),
    )
    provider = SourceBoundResearchProvider(
        plan=plan,
        repository_root=repository,
        archive_root=tmp_path / "external",
        fetcher=lambda url: FetchedPublicSource(
            url,
            "https://other.example/substituted",
            200,
            b"source",
            "text/html",
            "2026-08-21T00:00:00+00:00",
        ),
    )
    run = ResearchWorker(store, provider, "worker").run_one()
    assert run.status == "retry_scheduled"
    assert "leased task" in (run.error or "")
    with store.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM employer_dossiers").fetchone()[0] == 0
