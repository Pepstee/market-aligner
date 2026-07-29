"""Independent acceptance tests for the bounded offline JAA-06 contract."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

from career_automation.application_strategy import (
    ELEMENT_KINDS,
    ApplicationStrategyStore,
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
)
from career_automation.candidate_graph import CandidateGraph
from career_automation.database import CareerDatabase
from career_automation.employer_research import (
    FRESHNESS_DAYS,
    Citation,
    EmployerResearchWorker,
    Opportunity1Coordinator,
    RawResponseCache,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload
from career_automation.evidence_matching import (
    InferenceReceipt,
    MatchProposal,
    MatchResult,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    evidence_projection_hash,
    matching_input_hash,
)
from career_automation.gap_optimizer import FitAssessmentStore
from career_automation.lifecycle import IdempotencyConflict
from career_automation.migrations import (
    JAA_06_MIGRATIONS,
    apply_jaa_06_migrations,
    verify_jaa06_installed_schema,
)
from career_automation.models import IntelligenceKind, PipelineState


AS_OF = date(2030, 1, 2)
DIGEST = hashlib.sha256(b"jaa06-acceptance").hexdigest()
POLICY = MatchingPolicy()
ROOT = Path(__file__).resolve().parent


class _CapturedResearch:
    def __init__(self, cache: RawResponseCache) -> None:
        self.cache = cache

    def retrieve_plan(
        self,
        task: object,
    ) -> tuple[list[Citation], list[dict[str, object]]]:
        body = (
            b"<p>Example product service platform provides documented public "
            b"value to customers through reliable engineering technology.</p>"
        )
        digest, reference = self.cache.store(body)
        captured_at = date.today().isoformat() + "T00:00:00+00:00"
        source = Citation(
            f"source:{getattr(task, 'job_key')}:product",
            "https://8.8.8.8/product",
            captured_at,
            captured_at,
            digest,
            reference,
            200,
            source_kind="official_product",
            canonical_publisher="8.8.8.8",
            canonical_article="https://8.8.8.8/product",
            retrieval_engine="deterministic-retriever",
        )
        excerpt = body.decode("utf-8")
        plan: list[dict[str, object]] = []
        for kind in IntelligenceKind:
            base: dict[str, object] = {
                "id": f"plan:{kind.value}",
                "kind": kind.value,
                "permitted_purposes": [kind.value],
                "freshness_days": FRESHNESS_DAYS[kind],
            }
            if kind is IntelligenceKind.PRODUCT:
                plan.append({
                    **base,
                    "outcome": "supported",
                    "source_id": source.id,
                    "source_type": "official_product",
                    "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
                    "excerpt_byte_start": 0,
                    "excerpt_byte_length": len(body),
                })
            else:
                plan.append({
                    **base,
                    "outcome": "unknown",
                    "reason": "No purpose-specific authority was captured.",
                })
        return [source], plan


def _fit_database(
    tmp_path: Path,
    *,
    matched: bool,
) -> tuple[CareerDatabase, object, Requirement]:
    database = CareerDatabase(tmp_path / "career.sqlite3")
    body = "Deliver product engineering."
    job = scored_job_from_payload({
        "board": "jaa06-synthetic",
        "job_id": "strategy-job",
        "url": "https://jobs.example.test/strategy-job",
        "job_title": "Engineer",
        "company": "Example",
        "fit": 0.8,
        "opportunity": 0.9,
        "final": 80.0,
        "extraction_confidence": 0.99,
        "body": body,
    })
    assert OpportunityGate(database).bootstrap([job]).queued == 1
    cache = RawResponseCache(tmp_path / "raw")
    coordinator = Opportunity1Coordinator(
        database,
        EmployerResearchWorker(
            database,
            "jaa06-worker",
            cache,
            retriever=_CapturedResearch(cache),
        ),
        signal_deriver=lambda _dossier: [],
    )
    assert coordinator.run_once() is not None
    with database.connection() as connection:
        payload_hash = str(connection.execute(
            "SELECT payload_hash FROM pipeline_jobs WHERE job_key=?",
            (job.key,),
        ).fetchone()[0])
    requirement = Requirement(
        "product-delivery",
        "claim-product-delivery",
        body,
        False,
        "evidence",
        "build_evidence",
        ("portfolio_artifact",),
        9000,
        f"vacancy:{job.key}:{payload_hash}",
        (0, len(body)),
    )
    evidence = ()
    if matched:
        graph = CandidateGraph(database.path)
        graph.add_evidence(
            "evidence-product-delivery",
            statement="Content-addressed product delivery evidence.",
            source_identity="test:portfolio",
            state="evidence",
            evidence_kind="portfolio_artifact",
            valid_until=(date.today().replace(year=date.today().year + 1).isoformat()),
        )
        graph.verify_evidence(
            "evidence-product-delivery",
            1,
            decision="approved",
            verifier_kind="deterministic",
            policy_id="test:portfolio-review",
            policy_version="1",
            policy_hash=DIGEST,
            reason="tests and artefact verified",
            source_identity="test:independent-reviewer",
        )
        graph.add_claim(
            requirement.criterion,
            statement="Delivered a tested product capability.",
            claim_type="achievement",
            state="evidence",
            source_identity="test:claim",
            valid_until=(date.today().replace(year=date.today().year + 1).isoformat()),
        )
        graph.link_claim_evidence(
            requirement.criterion,
            "evidence-product-delivery",
            source_identity="test:edge",
            edge_type="demonstrated_by",
        )
        graph.approve_claim(requirement.criterion)
        evidence = candidate_graph_evidence(database.path, as_of=date.today())
    profile_hash = evidence_projection_hash(evidence)
    proposal = MatchProposal(
        requirement.requirement_id,
        tuple(row.evidence_id for row in evidence),
        9000,
        "direct" if evidence else "none",
        "Exact reviewed fit input.",
        InferenceReceipt(
            "test",
            "strategy-fit-v1",
            DIGEST,
            POLICY.policy_hash,
            profile_hash,
            matching_input_hash(
                requirement,
                candidate_profile_sha256=profile_hash,
                as_of=date.today(),
            ),
        ),
    )
    run = FitAssessmentStore(database.path).assess(
        job_key=job.key,
        requirements=(requirement,),
        proposals=(proposal,),
        as_of=date.today(),
    )
    return database, run, requirement


def _requirement(
    requirement_id: str,
    *,
    essential: bool = True,
    gap_kind: str = "evidence",
) -> Requirement:
    bridge = "fatal" if gap_kind == "structural" else "build_evidence"
    proofs = ("verified_claim",) if gap_kind == "structural" else ("portfolio_artifact",)
    return Requirement(
        requirement_id,
        f"claim-{requirement_id}",
        f"Atomic requirement {requirement_id}.",
        essential,
        gap_kind,
        bridge,
        proofs,
        8000,
        "vacancy:locked",
        (0, 10),
    )


def _matched(requirement: Requirement) -> MatchResult:
    return MatchResult(
        requirement.requirement_id,
        "matched",
        (f"evidence-{requirement.requirement_id}",),
        9000,
        "approved evidence",
        POLICY.policy_hash,
        None,
    )


def _support(requirement: Requirement) -> CandidateSupport:
    return CandidateSupport(
        requirement.requirement_id,
        requirement.criterion,
        1,
        f"evidence-{requirement.requirement_id}",
        1,
        requirement.accepted_proof_classes[0],
        "approved",
        "evidence",
        "approved",
        "evidence",
        "approved",
        date(2035, 1, 1),
    )


def _fact(
    claim_id: str = "research-role",
    source_ids: tuple[str, ...] = (
        "source:official-vacancy",
        "source:official-role",
    ),
) -> EmployerResearchFact:
    return EmployerResearchFact(
        claim_id,
        "role",
        "fact",
        source_ids,
        DIGEST,
        "current",
    )


def test_apply_now_strategy_is_complete_linked_and_reproducible() -> None:
    requirements = (_requirement("python"), _requirement("delivery"))
    results = tuple(_matched(row) for row in requirements)
    supports = tuple(_support(row) for row in requirements)
    arguments = {
        "fit_run_id": DIGEST,
        "dossier_hash": hashlib.sha256(b"dossier").hexdigest(),
        "candidate_profile_hash": hashlib.sha256(b"profile").hexdigest(),
        "requirements": requirements,
        "match_results": results,
        "candidate_support": supports,
        "employer_facts": (_fact(),),
        "as_of": AS_OF,
    }
    strategy = compile_application_strategy(**arguments)
    assert strategy == compile_application_strategy(**{
        **arguments,
        "requirements": tuple(reversed(requirements)),
        "match_results": tuple(reversed(results)),
        "candidate_support": tuple(reversed(supports)),
        "employer_facts": (_fact(
            source_ids=(
                "source:official-role",
                "source:official-vacancy",
            ),
        ),),
    })
    assert strategy.decision == "apply_now"
    assert strategy.certifies_slice is False
    assert strategy.dependency_gate == "JAA-05"
    assert len(strategy.coverage) == 2
    assert len(strategy.elements) == 2 * len(ELEMENT_KINDS)
    assert {row.kind for row in strategy.elements} == set(ELEMENT_KINDS)
    for element in strategy.elements:
        assert element.requirement_id
        assert element.candidate_claim_id
        assert element.candidate_evidence_id
        assert element.employer_research_claim_id == "research-role"
        assert element.employer_fact_sha256 == DIGEST
    document = strategy.document()
    assert document["schema_version"] == "jaa06.application-strategy.v1"
    assert document["strategy_id"] == strategy.strategy_id
    assert document["document_sha256"] == strategy.document_sha256


def test_bridgeable_gap_selects_close_gap_without_document_directives() -> None:
    mandatory = _requirement("mandatory")
    optional = _requirement("optional", essential=False)
    results = (
        _matched(mandatory),
        MatchResult(
            optional.requirement_id,
            "no_match",
            (),
            9000,
            "not demonstrated",
            POLICY.policy_hash,
            None,
        ),
    )
    strategy = compile_application_strategy(
        fit_run_id=DIGEST,
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(mandatory, optional),
        match_results=results,
        candidate_support=(_support(mandatory),),
        employer_facts=(),
        as_of=AS_OF,
    )
    assert strategy.decision == "close_gap_first"
    assert [row.state for row in strategy.coverage] == ["covered", "absent"]
    assert strategy.elements == ()


def test_uncovered_structural_requirement_rejects_candidacy() -> None:
    structural = _requirement("work-right", gap_kind="structural")
    strategy = compile_application_strategy(
        fit_run_id=DIGEST,
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(structural,),
        match_results=(MatchResult(
            structural.requirement_id,
            "no_match",
            (),
            9900,
            "mandatory right absent",
            POLICY.policy_hash,
            None,
        ),),
        candidate_support=(),
        employer_facts=(),
        as_of=AS_OF,
    )
    assert strategy.decision == "reject_candidacy"
    assert strategy.coverage[0].state == "release_blocking"
    assert strategy.elements == ()


def test_jaa06_migration_is_forward_only_and_exact_schema_checked(
    tmp_path: Path,
) -> None:
    path = tmp_path / "migration.sqlite3"
    assert apply_jaa_06_migrations(path) == tuple(
        migration.version for migration in JAA_06_MIGRATIONS
    )
    assert apply_jaa_06_migrations(path) == ()
    with sqlite3.connect(path) as connection:
        assert verify_jaa06_installed_schema(connection)
        tables = {
            row[0]
            for row in connection.execute(
                """SELECT name FROM sqlite_schema
                   WHERE type='table' AND name IN (
                     'application_strategies',
                     'strategy_requirement_coverage',
                     'strategy_elements'
                   )"""
            )
        }
        coverage_foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(strategy_requirement_coverage)"
        ).fetchall()
        element_foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(strategy_elements)"
        ).fetchall()
    assert len(tables) == 3
    assert {
        (row[2], row[3], row[4])
        for row in coverage_foreign_keys
    }.issuperset({
        ("application_strategies", "strategy_id", "strategy_id"),
        ("application_strategies", "fit_run_id", "fit_run_id"),
    })
    assert {
        (row[2], row[3], row[4])
        for row in element_foreign_keys
    }.issuperset({
        ("application_strategies", "strategy_id", "strategy_id"),
        ("application_strategies", "job_key", "job_key"),
        ("application_strategies", "fit_run_id", "fit_run_id"),
    })


def test_ready_fit_compiles_persists_and_routes_strategy_atomically(
    tmp_path: Path,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=True)
    store = ApplicationStrategyStore(database.path)
    strategy = store.compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    assert strategy.decision == "apply_now"
    assert store.compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    ) == strategy
    assert store.load(strategy.strategy_id, as_of=date.today()) == strategy
    with store._connect() as connection:
        persisted = connection.execute(
            """SELECT decision,lifecycle_receipt_id,document_hash,job_key
               FROM application_strategies"""
        ).fetchone()
        assert persisted["decision"] == "apply_now"
        assert isinstance(persisted["lifecycle_receipt_id"], int)
        assert persisted["document_hash"] == strategy.document_sha256
        job_key = str(persisted["job_key"])
        assert connection.execute(
            "SELECT COUNT(*) FROM strategy_requirement_coverage"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM strategy_elements"
        ).fetchone()[0] == len(ELEMENT_KINDS)
        for table in (
            "application_strategies",
            "strategy_requirement_coverage",
            "strategy_elements",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                connection.execute(f"DELETE FROM {table}")
    assert database.lifecycle.replay()[job_key] is PipelineState.STRATEGY_READY


def test_gap_strategy_persists_without_advancing_to_strategy_ready(
    tmp_path: Path,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=False)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    assert strategy.decision == "close_gap_first"
    assert strategy.elements == ()
    with database.connection() as connection:
        assert connection.execute(
            "SELECT lifecycle_receipt_id FROM application_strategies"
        ).fetchone()[0] is None
        job_key = str(connection.execute(
            "SELECT job_key FROM fit_assessment_runs WHERE run_id=?",
            (run.run_id,),
        ).fetchone()[0])
    assert database.lifecycle.replay()[job_key] is PipelineState.GAP_IDENTIFIED


def test_candidate_graph_drift_after_fit_suppresses_strategy_receipt(
    tmp_path: Path,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=True)
    graph = CandidateGraph(database.path)
    graph.add_evidence(
        "later-evidence",
        statement="A later approved profile addition.",
        source_identity="test:later",
        state="evidence",
        evidence_kind="portfolio_artifact",
        valid_until=date.today().replace(year=date.today().year + 1).isoformat(),
    )
    graph.verify_evidence(
        "later-evidence",
        1,
        decision="approved",
        verifier_kind="deterministic",
        policy_id="test:later-review",
        policy_version="1",
        policy_hash=hashlib.sha256(b"later").hexdigest(),
        reason="later artefact reviewed",
        source_identity="test:later-reviewer",
    )
    graph.add_claim(
        "later-claim",
        statement="Later approved candidate claim.",
        claim_type="achievement",
        state="evidence",
        source_identity="test:later-claim",
        valid_until=date.today().replace(year=date.today().year + 1).isoformat(),
    )
    graph.link_claim_evidence(
        "later-claim",
        "later-evidence",
        source_identity="test:later-edge",
        edge_type="demonstrated_by",
    )
    graph.approve_claim("later-claim")
    store = ApplicationStrategyStore(database.path)
    with pytest.raises(ValueError, match="candidate graph changed"):
        store.compile_and_record(fit_run_id=run.run_id, as_of=date.today())
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM application_strategies"
        ).fetchone()[0] == 0
        state = str(connection.execute(
            """SELECT job.state FROM fit_assessment_runs run
               JOIN pipeline_jobs job ON job.job_key=run.job_key
               WHERE run.run_id=?""",
            (run.run_id,),
        ).fetchone()[0])
    assert state == "fit_assessed"


def test_strategy_commit_rejects_candidate_drift_after_compilation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=True)
    original_compile = compile_application_strategy
    injected = False

    def compile_with_interleaved_drift(**arguments: object):
        nonlocal injected
        strategy = original_compile(**arguments)
        if not injected:
            injected = True
            graph = CandidateGraph(database.path)
            graph.add_evidence(
                "interleaved-evidence",
                statement="A newly approved profile fact.",
                source_identity="test:interleaved-evidence",
                state="evidence",
                evidence_kind="portfolio_artifact",
                valid_until="2035-01-01",
            )
            graph.verify_evidence(
                "interleaved-evidence",
                1,
                decision="approved",
                verifier_kind="deterministic",
                policy_id="test:interleaved-review",
                policy_version="1",
                policy_hash=DIGEST,
                reason="interleaved artefact reviewed",
                source_identity="test:interleaved-reviewer",
            )
            graph.add_claim(
                "interleaved-claim",
                statement="Newly approved candidate claim.",
                claim_type="achievement",
                state="evidence",
                source_identity="test:interleaved-claim",
                valid_until="2035-01-01",
            )
            graph.link_claim_evidence(
                "interleaved-claim",
                "interleaved-evidence",
                source_identity="test:interleaved-edge",
                edge_type="demonstrated_by",
            )
            graph.approve_claim("interleaved-claim")
        return strategy

    monkeypatch.setattr(
        "career_automation.application_strategy.compile_application_strategy",
        compile_with_interleaved_drift,
    )
    store = ApplicationStrategyStore(database.path)
    with pytest.raises(
        ValueError,
        match="candidate graph changed before strategy commit",
    ):
        store.compile_and_record(fit_run_id=run.run_id, as_of=date.today())
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM application_strategies"
        ).fetchone()[0] == 0
        state = str(connection.execute(
            """SELECT job.state FROM fit_assessment_runs run
               JOIN pipeline_jobs job ON job.job_key=run.job_key
               WHERE run.run_id=?""",
            (run.run_id,),
        ).fetchone()[0])
    assert state == "fit_assessed"


def test_strategy_commit_rejects_employer_fact_drift_after_compilation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=True)
    original_compile = compile_application_strategy
    injected = False

    def compile_with_interleaved_drift(**arguments: object):
        nonlocal injected
        strategy = original_compile(**arguments)
        if not injected:
            injected = True
            with database.connection() as connection:
                connection.execute(
                    """UPDATE employer_intelligence
                       SET claim_json='{"classification":"fact","kind":"role"}'"""
                )
        return strategy

    monkeypatch.setattr(
        "career_automation.application_strategy.compile_application_strategy",
        compile_with_interleaved_drift,
    )
    store = ApplicationStrategyStore(database.path)
    with pytest.raises(
        ValueError,
        match="employer fact differs from the durable dossier",
    ):
        store.compile_and_record(fit_run_id=run.run_id, as_of=date.today())
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM application_strategies"
        ).fetchone()[0] == 0
        state = str(connection.execute(
            """SELECT job.state FROM fit_assessment_runs run
               JOIN pipeline_jobs job ON job.job_key=run.job_key
               WHERE run.run_id=?""",
            (run.run_id,),
        ).fetchone()[0])
    assert state == "fit_assessed"


def test_dossier_tamper_after_fit_suppresses_strategy_and_transition(
    tmp_path: Path,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=True)
    with database.connection() as connection:
        connection.execute(
            "UPDATE employer_dossiers SET dossier_hash=?",
            ("0" * 64,),
        )
    store = ApplicationStrategyStore(database.path)
    with pytest.raises(RuntimeError, match="dossier"):
        store.compile_and_record(fit_run_id=run.run_id, as_of=date.today())
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM application_strategies"
        ).fetchone()[0] == 0


def test_changed_strategy_retry_conflicts_without_mutating_original(
    tmp_path: Path,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=True)
    store = ApplicationStrategyStore(database.path)
    original = store.compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    with pytest.raises(IdempotencyConflict):
        store.compile_and_record(
            fit_run_id=run.run_id,
            as_of=date.today() + timedelta(days=1),
        )
    with store._connect() as connection:
        persisted = connection.execute(
            "SELECT strategy_id,document_hash FROM application_strategies"
        ).fetchone()
    assert tuple(persisted) == (
        original.strategy_id,
        original.document_sha256,
    )


def test_offline_strategy_element_tamper_fails_durable_read(
    tmp_path: Path,
) -> None:
    database, run, _requirement_row = _fit_database(tmp_path, matched=True)
    store = ApplicationStrategyStore(database.path)
    strategy = store.compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    with database.connection() as connection:
        connection.execute("DROP TRIGGER strategy_elements_immutable_update")
        connection.execute(
            """UPDATE strategy_elements SET directive='forged-directive'
               WHERE element_id=(
                 SELECT element_id FROM strategy_elements LIMIT 1
               )"""
        )
    with pytest.raises(ValueError, match="kind and directive"):
        store.load(strategy.strategy_id, as_of=date.today())
    with pytest.raises(ValueError, match="children differ"):
        store.compile_and_record(
            fit_run_id=run.run_id,
            as_of=date.today(),
        )


def test_synthetic_locked_strategy_evaluation_is_noncertifying() -> None:
    completed = subprocess.run(
        (sys.executable, "scripts/evaluate_jaa06_locked_strategies.py"),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["status"] == "SOFTWARE_CONTRACT_PASS"
    assert result["certifies_slice"] is False
    assert result["dependency_gate"] == "JAA-05"
    assert result["transitive_dependency_gate"] == "JAA-04"
    assert sorted(result["limitations"]) == sorted([
        "synthetic software vectors are not production calibration",
        (
            "does not certify JAA-06 as the offline evaluator covers only "
            "synthetic software vectors"
        ),
        "does not measure generated document quality or employer outcomes",
    ])
    assert result["metrics"] == {
        "exact_accuracy_bp": 10_000,
        "linkage_completeness_bp": 10_000,
        "reproducibility_bp": 10_000,
        "examples": 3,
    }
