"""Phase-A acceptance for one real frozen vacancy in the local JAA-09 browser."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import platform
import stat
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from career_automation.application_artifacts import publish_application_artifacts
from career_automation.application_compiler import (
    CandidateContact,
    ProductionApplicationCompiler,
)
from career_automation.application_strategy import ApplicationStrategyStore
from career_automation.ats_fixture import FixtureVacancy, LocalATSFixture
from career_automation.browser_executor import LocalBrowserExecutor
from career_automation.browser_workflows import (
    ActionKind,
    BrowserWorkflowStore,
    fixture_submit_event_sha256,
)
from career_automation.candidate_graph import CandidateGraph
from career_automation.database import CareerDatabase
from career_automation.employer_research import (
    Citation,
    EmployerResearchWorker,
    Opportunity1Coordinator,
    RawResponseCache,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload
from career_automation.evidence_matching import (
    InferenceReceipt,
    MatchProposal,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    evidence_projection_hash,
    matching_input_hash,
)
from career_automation.gap_optimizer import FitAssessmentStore
from career_automation.jaa04_corpus_authority import (
    CORPUS_IDENTITY,
    DOSSIER_SHA256,
    GRAPHCORE_JOB_KEY,
    RAW_RESPONSE_SHA256,
    ROBOTS_RESPONSE_SHA256,
    FrozenVacancyAuthority,
    verify_graphcore_corpus,
)
from career_automation.jaa09_real_vacancy_certifier import (
    write_real_vacancy_receipt,
)
from career_automation.release_gate import (
    ApplicationCompilationStore,
    OfficialRouteBinding,
    ReleaseGateStore,
)
from career_automation.rendering import render_pdf_artifacts
from test_jaa08_independent_acceptance import _fixture_date, _fixture_now
from test_jaa09_independent_acceptance import (
    FORM_TOKEN,
    NONCE,
    _released_browser_inputs,
)


ROOT = Path(__file__).resolve().parent
CERTIFIED_CORPUS = Path(
    "/home/gutua/software-factory/.control/jaa-12h-supervisor-20260727/"
    "runtime/.jaa04-corpus-v3-a4f4490-releases/"
    "sha256-f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258"
)
TRACKED_SEED = ROOT / "career_automation/fixtures/jaa04_admitted_queue.json"
DIGEST = hashlib.sha256(b"jaa09-real-vacancy-phase-a").hexdigest()
POLICY = MatchingPolicy()
CANDIDATE_FIXTURE_DISCLOSURE = (
    "deterministic approved fixture candidate projection; not a real person"
)


class _FrozenCorpusResearch:
    """Replay the verified official response without any network operation."""

    def __init__(
        self,
        cache: RawResponseCache,
        authority: FrozenVacancyAuthority,
    ) -> None:
        self.cache = cache
        self.authority = authority

    def retrieve_plan(
        self,
        task: object,
    ) -> tuple[list[Citation], list[dict[str, object]]]:
        if (
            getattr(task, "job_key", None) != self.authority.job_key
            or getattr(task, "company", None) != self.authority.company
            or str(getattr(task, "title", "")).strip() != self.authority.title
            or getattr(task, "url", None) != self.authority.vacancy_url
        ):
            raise ValueError("research task differs from the verified frozen vacancy")
        digest, reference = self.cache.store(self.authority.raw_response_bytes)
        if digest != RAW_RESPONSE_SHA256:
            raise ValueError("replayed official response identity changed")
        robots_digest, robots_reference = self.cache.store(
            self.authority.robots_response_bytes
        )
        if (
            robots_digest != ROBOTS_RESPONSE_SHA256
            or robots_reference
            != f"sha256/0b/{ROBOTS_RESPONSE_SHA256}"
        ):
            raise ValueError("replayed robots response identity changed")
        source_document = self.authority.dossier["sources"][0]
        source = Citation(
            **{
                **source_document,
                "raw_response_ref": reference,
            }
        )
        source_plan = self.authority.dossier.get("source_plan")
        if not isinstance(source_plan, list) or not all(
            isinstance(row, dict) for row in source_plan
        ):
            raise ValueError("verified frozen dossier source plan is missing")
        plan = [
            {
                **row,
                **(
                    {
                        "raw_response_ref": reference,
                        "source_content_sha256": RAW_RESPONSE_SHA256,
                    }
                    if row.get("outcome") == "supported"
                    else {}
                ),
            }
            for row in source_plan
        ]
        return [source], plan


def _real_scored_payload(authority: FrozenVacancyAuthority) -> dict[str, Any]:
    payload = dict(authority.queue_payload)
    payload.update(
        {
            "board": "greenhouse",
            "job_id": "graphcore:8420314002",
            "job_title": authority.title,
            "company": authority.company,
            "url": authority.vacancy_url,
            "fit": 0.8,
            "opportunity": authority.opportunity_score_bp / 10_000,
            "final": authority.opportunity_score_bp / 100,
            "extraction_confidence": 0.9,
            "body": authority.raw_response_bytes.decode("utf-8"),
            "jaa04_corpus_binding": {
                "corpus_inventory_sha256": authority.inventory_sha256,
                "files_hash": authority.inventory_files_sha256,
                "official_response_sha256": authority.raw_response_sha256,
                "dossier_sha256": authority.dossier_sha256,
                "queue_content_sha256": authority.queue_body_content_sha256,
                "queue_payload_hash": authority.admitted_queue_payload_sha256,
                "tracked_seed_payload_hash": (
                    authority.tracked_seed_payload_sha256
                ),
            },
            "jaa04_requirement_anchors": [
                {
                    "text": anchor.text,
                    "byte_start": anchor.byte_start,
                    "byte_length": anchor.byte_length,
                    "source_content_sha256": anchor.source_content_sha256,
                }
                for anchor in authority.requirement_anchors
            ],
        }
    )
    return payload


def _real_fit_database(
    tmp_path: Path,
    authority: FrozenVacancyAuthority,
) -> tuple[CareerDatabase, object, tuple[Requirement, ...]]:
    database = CareerDatabase(tmp_path / "career.sqlite3")
    job = scored_job_from_payload(_real_scored_payload(authority))
    assert job.key == GRAPHCORE_JOB_KEY
    assert OpportunityGate(database).bootstrap([job]).queued == 1
    cache = RawResponseCache(tmp_path / "raw")
    coordinator = Opportunity1Coordinator(
        database,
        EmployerResearchWorker(
            database,
            "jaa09-frozen-corpus-worker",
            cache,
            retriever=_FrozenCorpusResearch(cache, authority),
        ),
        signal_deriver=lambda _dossier: [],
    )
    result = coordinator.run_once()
    assert result is not None
    assert result["job_key"] == authority.job_key
    assert result["decision"] == "pass"
    completed = database.post_research_dossier(authority.job_key)
    assert completed is not None
    assert completed[0]["sources"][0]["content_sha256"] == RAW_RESPONSE_SHA256

    with database.connection() as connection:
        payload_hash = str(
            connection.execute(
                "SELECT payload_hash FROM pipeline_jobs WHERE job_key=?",
                (job.key,),
            ).fetchone()[0]
        )
    body = authority.raw_response_bytes.decode("utf-8")
    requirements = tuple(
        Requirement(
            f"graphcore-{index}",
            f"fixture-claim-{index}",
            anchor.text,
            True,
            "evidence",
            "build_evidence",
            ("portfolio_artifact",),
            9000,
            f"vacancy:{job.key}:{payload_hash}",
            (
                body.index(anchor.text),
                body.index(anchor.text) + len(anchor.text),
            ),
        )
        for index, anchor in enumerate(authority.requirement_anchors, 1)
    )
    assert tuple(
        authority.raw_response_bytes[
            anchor.byte_start:anchor.byte_start + anchor.byte_length
        ].decode("utf-8")
        for anchor in authority.requirement_anchors
    ) == tuple(requirement.text for requirement in requirements)

    graph = CandidateGraph(database.path)
    for index, requirement in enumerate(requirements, 1):
        evidence_id = f"fixture-evidence-{index}"
        graph.add_evidence(
            evidence_id,
            statement=(
                f"Approved synthetic fixture support for {requirement.text}; "
                f"{CANDIDATE_FIXTURE_DISCLOSURE}."
            ),
            source_identity=f"fixture:candidate-evidence:{index}",
            state="evidence",
            evidence_kind="portfolio_artifact",
            valid_until=date.today().replace(
                year=date.today().year + 1
            ).isoformat(),
        )
        graph.verify_evidence(
            evidence_id,
            1,
            decision="approved",
            verifier_kind="deterministic",
            policy_id="jaa09.fixture-candidate-review",
            policy_version="1",
            policy_hash=DIGEST,
            reason=CANDIDATE_FIXTURE_DISCLOSURE,
            source_identity="fixture:independent-reviewer",
        )
        graph.add_claim(
            requirement.criterion,
            statement=(
                f"Fixture claim for {requirement.text}; "
                f"{CANDIDATE_FIXTURE_DISCLOSURE}."
            ),
            claim_type="achievement",
            state="evidence",
            source_identity=f"fixture:candidate-claim:{index}",
            valid_until=date.today().replace(
                year=date.today().year + 1
            ).isoformat(),
        )
        graph.link_claim_evidence(
            requirement.criterion,
            evidence_id,
            source_identity="fixture:claim-evidence-edge",
            edge_type="demonstrated_by",
        )
        graph.approve_claim(requirement.criterion)

    evidence = candidate_graph_evidence(database.path, as_of=date.today())
    profile_hash = evidence_projection_hash(evidence)
    proposals = tuple(
        MatchProposal(
            requirement.requirement_id,
            (f"fixture-evidence-{index}",),
            9000,
            "direct",
            CANDIDATE_FIXTURE_DISCLOSURE,
            InferenceReceipt(
                "deterministic-fixture",
                "jaa09-real-vacancy-fit-v1",
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
        for index, requirement in enumerate(requirements, 1)
    )
    run = FitAssessmentStore(database.path).assess(
        job_key=job.key,
        requirements=requirements,
        proposals=proposals,
        as_of=date.today(),
    )
    assert run.status == "ready"
    return database, run, requirements


def _real_issued_release_inputs(
    tmp_path: Path,
    authority: FrozenVacancyAuthority,
):
    database, run, requirements = _real_fit_database(tmp_path, authority)
    as_of = _fixture_date(database)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=as_of,
    )
    graph = CandidateGraph(database.path)
    contact_value = {
        "full_name": "Alex Fixture",
        "email": "alex.fixture@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
    }
    graph.add_record(
        "fixture-contact-primary",
        kind="fact",
        subject="contact",
        value=contact_value,
        state="fact",
        source_identity="fixture:verified-contact",
    )
    graph.verify_record(
        "fixture-contact-primary",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="jaa09.fixture-contact",
        policy_version="1",
        policy_hash=DIGEST,
        reason=CANDIDATE_FIXTURE_DISCLOSURE,
        source_identity="fixture:contact-verifier",
    )
    with database.connection() as connection:
        source_hash = str(
            connection.execute(
                """SELECT provenance.source_hash
                   FROM candidate_records record
                   JOIN candidate_provenance provenance
                     ON provenance.provenance_id=record.provenance_id
                   WHERE record.record_id='fixture-contact-primary'"""
            ).fetchone()[0]
        )
    contact = CandidateContact(
        record_id="fixture-contact-primary",
        record_version=1,
        provenance_sha256=source_hash,
        **contact_value,
    )
    questions = {
        requirement.requirement_id: (
            f"fixture-example-{index}",
            requirement.text,
        )
        for index, requirement in enumerate(requirements, 1)
    }
    source = ProductionApplicationCompiler(database.path).compile(
        strategy.strategy_id,
        as_of=as_of,
        contact=contact,
        questions=questions,
    )
    assert source.job_key == authority.job_key
    assert source.role_title == authority.title
    assert source.company_name == authority.company
    artifacts = render_pdf_artifacts(source)
    artifact_root = tmp_path / "published"
    publication = publish_application_artifacts(
        source,
        artifacts,
        root=artifact_root,
        repository_root=ROOT,
    )

    graph.add_record(
        "fixture-work-right-gb",
        kind="work_right",
        subject="permission",
        value={"permitted": True},
        state="fact",
        source_identity="fixture:operator-work-right",
        jurisdiction="GB",
        contract_type="employee",
        valid_from=as_of.replace(year=as_of.year - 1).isoformat(),
        valid_until=as_of.replace(year=as_of.year + 1).isoformat(),
    )
    graph.verify_record(
        "fixture-work-right-gb",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="jaa09.fixture-work-right",
        policy_version="1",
        policy_hash=DIGEST,
        reason=CANDIDATE_FIXTURE_DISCLOSURE,
        source_identity="fixture:work-right-verifier",
    )
    compilation = ApplicationCompilationStore(database.path).register(
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        as_of=as_of,
    )
    gate = ReleaseGateStore(
        database.path,
        clock=lambda: _fixture_now(database),
    )
    route = gate.register_official_route(
        job_key=source.job_key,
        route=OfficialRouteBinding(
            "route:graphcore-local-fixture",
            "offline-test-adapter",
            "1",
            "fixture:local-route-policy",
            DIGEST,
            as_of,
            as_of.replace(year=as_of.year + 1),
            True,
        ),
    )
    issued = gate.evaluate_and_issue(
        compilation_id=compilation.compilation_id,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        jurisdiction="GB",
        contract_type="employee",
        evaluated_at=as_of,
    )
    return (
        database,
        strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        publication,
        compilation,
        gate,
        route,
        issued,
    )


def _write_evidence_receipt_if_requested(
    *,
    authority: FrozenVacancyAuthority,
    release_inputs: tuple[object, ...],
    workflow: object,
    run_id: str,
    fixture_receipt: object,
    outputs: dict[str, object],
    chromium_version: str,
    submit_count: int,
    non_loopback_requests: int,
) -> Path | None:
    target_root = os.environ.get("JAA09_EVIDENCE_CONTROL_ROOT")
    if not target_root:
        return None
    required_environment = (
        "JAA09_SOURCE_GIT_REVISION",
        "JAA09_SOURCE_TREE",
        "JAA09_SOURCE_CONTENT_REVISION",
    )
    missing = [name for name in required_environment if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "receipt evidence environment is incomplete: " + ",".join(missing)
        )
    source_git_revision = os.environ["JAA09_SOURCE_GIT_REVISION"]
    source_tree = os.environ["JAA09_SOURCE_TREE"]
    source_content_revision = os.environ["JAA09_SOURCE_CONTENT_REVISION"]
    strategy = release_inputs[1]
    source = release_inputs[4]
    artifacts = release_inputs[5]
    publication = release_inputs[7]
    issued = release_inputs[11]
    projection_sha256 = getattr(strategy, "candidate_profile_hash")
    document = {
        "schema_version": "jaa09.real-vacancy-local-receipt.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "certifies_slice": False,
        "corpus_binding": {
            "corpus_root": str(authority.corpus_root),
            "corpus_inventory_sha256": authority.inventory_sha256,
            "files_hash": authority.inventory_files_sha256,
            "official_response_sha256": authority.raw_response_sha256,
            "official_response_size": authority.raw_response_path.stat().st_size,
            "official_response_mode": format(
                stat.S_IMODE(authority.raw_response_path.stat().st_mode),
                "04o",
            ),
            "dossier_sha256": authority.dossier_sha256,
            "queue_content_sha256": authority.queue_body_content_sha256,
            "queue_payload_hash": authority.admitted_queue_payload_sha256,
            "tracked_seed_payload_hash": authority.tracked_seed_payload_sha256,
            "hash_domains": {
                "queue_content_sha256": "normalized-vacancy-body-utf8",
                "queue_payload_hash": "admitted-queue-record",
                "tracked_seed_payload_hash": "repo-tracked-seed-record",
            },
        },
        "vacancy_identity": {
            "job_key": authority.job_key,
            "company": authority.company,
            "title": authority.title,
            "url": authority.vacancy_url,
            "observed_at": authority.observed_at,
            "opportunity0_score_bp": authority.opportunity_score_bp,
            "opportunity1_reassessment": "no_changes",
        },
        "candidate_boundary": {
            "candidate_projection": "fixture",
            "projection_content_sha256": projection_sha256,
            "disclosure": CANDIDATE_FIXTURE_DISCLOSURE,
        },
        "release_binding": {
            "release_manifest_sha256": (
                issued.manifest.release_manifest_sha256
            ),
            "release_token_sha256": issued.token_sha256,
            "application_source_sha256": source.content_sha256,
            "vacancy_sha256": source.vacancy_sha256,
            "artifact_set_sha256": artifacts.artifact_set_sha256,
            "artifact_receipt_sha256": publication.receipt_sha256,
        },
        "browser_evidence": {
            "workflow_sha256": workflow.content_hash,
            "run_id": run_id,
            "receipt_id": fixture_receipt.receipt_id,
            "receipt_payload_sha256": fixture_receipt.payload_sha256,
            "screenshot_sha256": outputs["screenshot_sha256"],
            "field_map_sha256": outputs["field_map_sha256"],
            "submit_event_sha256": outputs["submit_event_sha256"],
            "submit_count": submit_count,
            "non_loopback_requests": non_loopback_requests,
        },
        "source_environment": {
            "source_git_revision": source_git_revision,
            "source_tree": source_tree,
            "source_content_revision": source_content_revision,
            "interpreter_path": str(ROOT / ".venv/bin/python"),
            "implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "playwright_version": importlib.metadata.version("playwright"),
            "chromium_version": chromium_version,
            "platform": platform.platform(),
        },
        "disclosures": {
            "candidate_projection_scope": "fixture_only",
            "receipt_authenticity_scope": (
                "in_process_fixture_receipt_forgery_residual"
            ),
            "ats_scope": "local_simulated_ats_only",
            "filesystem_trust_limit": (
                "operator_control_root_local_filesystem"
            ),
            "real_application_submitted": False,
            "external_authority_granted": False,
        },
    }
    target = write_real_vacancy_receipt(document, target_root)
    print(f"JAA09_REAL_VACANCY_RECEIPT={target}")
    return target


def test_verified_graphcore_authority_precedes_real_browser_execution(
    tmp_path: Path,
) -> None:
    authority = verify_graphcore_corpus(CERTIFIED_CORPUS, TRACKED_SEED)
    assert authority.corpus_identity == CORPUS_IDENTITY
    assert authority.dossier_sha256 == DOSSIER_SHA256
    assert authority.raw_response_sha256 == RAW_RESPONSE_SHA256
    assert tuple(
        authority.raw_response_bytes[
            anchor.byte_start:anchor.byte_start + anchor.byte_length
        ].decode()
        for anchor in authority.requirement_anchors
    ) == tuple(anchor.text for anchor in authority.requirement_anchors)

    release_inputs = _real_issued_release_inputs(tmp_path, authority)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "graphcore-build-engineer",
        authority.job_key,
        authority.title,
        authority.company,
        authority.requirement_anchors[0].text,
    )
    with LocalATSFixture(
        vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        (
            database,
            workflow,
            approvals,
            values,
            execution_authority,
            issued,
        ) = _released_browser_inputs(
            fixture,
            tmp_path,
            release_inputs,
        )
        assert execution_authority.job_key == authority.job_key
        assert execution_authority.source.role_title == authority.title
        assert execution_authority.source.company_name == authority.company
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(
            workflow,
            idempotency_key=(
                f"jaa09-real-vacancy:{authority.admitted_queue_payload_sha256}"
            ),
        )
        assert store.claim_run(
            "jaa09-real-vacancy-worker",
            run_id=run_id,
        ) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        chromium_version = ""
        non_loopback_request_urls: list[str] = []
        fixture_url = urlsplit(fixture.application_url)
        fixture_origin = (
            fixture_url.scheme,
            fixture_url.hostname,
            fixture_url.port or 80,
        )
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            chromium_version = browser.version
            page = browser.new_page()
            page.on(
                "request",
                lambda request: (
                    non_loopback_request_urls.append(request.url)
                    if (
                        (
                            urlsplit(request.url).scheme,
                            urlsplit(request.url).hostname,
                            urlsplit(request.url).port or 80,
                        )
                        != fixture_origin
                    )
                    else None
                ),
            )
            completed = tuple(
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa09-real-vacancy-worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=execution_authority,
                )
                for _action in workflow.actions
            )
            assert page.get_by_role(
                "heading",
                name="Application received",
            ).is_visible()
            browser.close()
        receipt = fixture.receipt
        assert receipt is not None
        receipt.verify()
        assert receipt.job_key == authority.job_key
        assert receipt.certifies_slice is False
        assert completed[-1] is not None
        assert completed[-1].action_kind is ActionKind.SUBMIT
        outputs = store.checkpoint_outputs(run_id)["submit"]
        assert outputs["receipt_id"] == receipt.receipt_id
        assert outputs["submit_event_sha256"] == fixture_submit_event_sha256(
            run_id=run_id,
            workflow_sha256=workflow.content_hash,
            step_id="submit",
            release_manifest_sha256=(
                issued.manifest.release_manifest_sha256
            ),
            receipt_id=receipt.receipt_id,
            receipt_payload_sha256=receipt.payload_sha256,
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
        )
        assert store.run_snapshot(run_id)["status"] == "completed"
        with database.connection() as connection:
            submit_count = int(
                connection.execute(
                    """SELECT COUNT(*) FROM browser_submit_dispatches
                       WHERE run_id=?""",
                    (run_id,),
                ).fetchone()[0]
            )
        assert submit_count == 1
        assert non_loopback_request_urls == []
        receipt_path = _write_evidence_receipt_if_requested(
            authority=authority,
            release_inputs=release_inputs,
            workflow=workflow,
            run_id=run_id,
            fixture_receipt=receipt,
            outputs=outputs,
            chromium_version=chromium_version,
            submit_count=submit_count,
            non_loopback_requests=len(non_loopback_request_urls),
        )
        if receipt_path is not None:
            assert receipt_path.stat().st_mode & 0o777 == 0o444


def test_real_vacancy_post_click_interruption_recovers_one_receipt(
    tmp_path: Path,
) -> None:
    authority = verify_graphcore_corpus(CERTIFIED_CORPUS, TRACKED_SEED)
    release_inputs = _real_issued_release_inputs(tmp_path, authority)
    vacancy = FixtureVacancy(
        "graphcore-build-recovery",
        authority.job_key,
        authority.title,
        authority.company,
        authority.requirement_anchors[0].text,
    )
    with LocalATSFixture(
        vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        (
            database,
            workflow,
            approvals,
            values,
            execution_authority,
            issued,
        ) = _released_browser_inputs(
            fixture,
            tmp_path,
            release_inputs,
        )
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow)
        assert store.claim_run(
            "jaa09-real-vacancy-worker",
            run_id=run_id,
        ) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        original_complete = store.complete_step
        interrupted = False

        def interrupt_submit(*args: object, **kwargs: object):
            nonlocal interrupted
            if kwargs.get("step_id") == "submit" and not interrupted:
                interrupted = True
                raise RuntimeError("injected real-vacancy post-click interruption")
            return original_complete(*args, **kwargs)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa09-real-vacancy-worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=execution_authority,
                )
            store.complete_step = interrupt_submit  # type: ignore[method-assign]
            try:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa09-real-vacancy-worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=execution_authority,
                )
            except RuntimeError as exc:
                assert "post-click interruption" in str(exc)
            else:  # pragma: no cover - explicit failure signal
                raise AssertionError("post-click interruption was not injected")
            browser.close()
            first_receipt = fixture.receipt
            assert first_receipt is not None
            assert store.submit_dispatch(run_id)["state"] == "click_started"  # type: ignore[index]

            store.complete_step = original_complete  # type: ignore[method-assign]
            resumed_browser = playwright.chromium.launch(headless=True)
            resumed_page = resumed_browser.new_page()
            completed = LocalBrowserExecutor(
                store,
                repository_root=ROOT,
            ).execute_next(
                resumed_page,
                run_id=run_id,
                worker_id="jaa09-real-vacancy-worker",
                approved_values=approvals,
                materialized_values=values,
                release_authority=execution_authority,
            )
            resumed_browser.close()
        assert completed is not None
        assert completed.action_kind is ActionKind.SUBMIT
        assert fixture.receipt is first_receipt
        assert fixture.receipt.job_key == GRAPHCORE_JOB_KEY
        assert store.run_snapshot(run_id)["status"] == "completed"
        assert sum(
            event["event_type"] == "submit_click_started"
            for event in store.events(run_id)
        ) == 1
        with database.connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM browser_submit_dispatches WHERE run_id=?",
                (run_id,),
            ).fetchone()[0] == 1
