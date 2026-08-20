"""Production-only localhost full-submit producer for bounded JAA-10 evidence.

The producer executes no public request and cannot certify JAA-10.  It
replays the frozen JAA-04 corpus, builds a fresh JAA-08 release, submits to the
cooperative loopback ATS fixture, and compiles exactly two synthetic-time
observations after runtime negative-control receipts have been supplied.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from time import perf_counter_ns
from types import MappingProxyType
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from playwright.sync_api import sync_playwright

from .application_artifacts import publish_application_artifacts
from .application_compiler import CandidateContact, ProductionApplicationCompiler
from cv_generation.service import validate_application_cv
from .application_strategy import ApplicationStrategyStore
from .ats_fixture import FixtureReceipt, FixtureVacancy, LocalATSFixture
from .browser_executor import (
    LocalBrowserExecutor,
    MaterializedValue,
    ReleaseExecutionAuthority,
    SubmissionIndeterminateError,
)
from .browser_workflows import (
    ActionKind,
    ApprovedValue,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    SelectorCandidate,
    SelectorPlan,
    SelectorStrategy,
    SubmissionProof,
    ValueReference,
    ValueSource,
    fixture_submit_event_sha256,
)
from .candidate_graph import CandidateGraph
from .database import CareerDatabase
from .employer_research import (
    Citation,
    EmployerResearchWorker,
    Opportunity1Coordinator,
    RawResponseCache,
)
from .engine import OpportunityGate, scored_job_from_payload
from .evidence_matching import (
    InferenceReceipt,
    MatchProposal,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    evidence_projection_hash,
    matching_input_hash,
)
from .external_document_assurance import (
    IntendedVacancy,
    assert_application_artifacts,
)
from .gap_optimizer import FitAssessmentStore
from .testing_application_archive import fixture_release_archive_receipt
from .jaa04_corpus_authority import (
    GRAPHCORE_JOB_KEY,
    RAW_RESPONSE_SHA256,
    ROBOTS_RESPONSE_SHA256,
    FrozenVacancyAuthority,
    verify_graphcore_corpus,
)
from .release_gate import (
    ApplicationCompilationStore,
    OfficialRouteBinding,
    ReleaseGateStore,
)
from .rendering import render_pdf_artifacts
from .shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    REQUIRED_INTERRUPTION_POINTS,
    InterruptionObservation,
    ShadowObservation,
    WithheldShadowEvidence,
    compile_withheld_shadow_evidence,
    normalized_submit_event_sha256,
    normalized_workflow_sha256,
)
from .shadow_mutation_runtime import (
    RUNTIME_CONTROL_IDS,
    RuntimeControlReceipt,
    mutation_observations_from_runtime,
    record_fixture_http_rejection,
    record_store_state_invariance,
)
from .testing_sanity_review import fixture_pass_receipt


ROOT = Path(__file__).resolve().parents[1]
CERTIFIED_CORPUS = Path(
    os.environ.get(
        "JAA_CERTIFIED_CORPUS_ROOT",
        "__JAA_CERTIFIED_CORPUS_ROOT_REQUIRED__",
    )
)
TRACKED_SEED = ROOT / "career_automation/fixtures/jaa04_admitted_queue.json"
NONCE = "fixture-review-nonce-00000001"
FORM_TOKEN = "fixture-form-token-00000000001"
POLICY_DIGEST = hashlib.sha256(b"jaa09-real-vacancy-phase-a").hexdigest()
CANDIDATE_FIXTURE_DISCLOSURE = (
    "deterministic approved fixture candidate projection; not a real person"
)
P4_SUMMARY_SHA256 = (
    "e489ac40f4d0342223b5794946e2890e75a2a05730c56bfe580ba73bedc70840"
)
POLICY = MatchingPolicy()
FIXTURE_PDF = b"%PDF-1.4\nsynthetic fixture PDF\n%%EOF\n"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _control_vacancy() -> FixtureVacancy:
    return FixtureVacancy(
        "platform-engineer",
        "fixture:platform-engineer",
        "Platform Engineer",
        "Example Systems Ltd",
    )


def _fixture_state(
    fixture: LocalATSFixture,
    *,
    submit_click_count: int,
    event_count: int,
    dispatch_state: str,
) -> dict[str, object]:
    return {
        "receipt_count": int(fixture.receipt is not None),
        "submit_click_count": submit_click_count,
        "dispatch_state": dispatch_state,
        "event_count": event_count,
    }


def _fixture_multipart() -> tuple[bytes, str]:
    boundary = "jaa10-runtime-fixture-boundary"
    fields = {
        "fixture_token": FORM_TOKEN,
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
        "work_authorisation": "authorised",
        "sponsorship_details": "",
        "cover_note": "Delivered a synthetic migration example.",
    }
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            (
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            )
        )
    for name, filename in (
        ("cv", "alex-cv.pdf"),
        ("cover_letter", "alex-cover-letter.pdf"),
    ):
        chunks.extend(
            (
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"; '
                    f'filename="{filename}"\r\n'
                ).encode(),
                b"Content-Type: application/pdf\r\n\r\n",
                FIXTURE_PDF,
                b"\r\n",
            )
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _fixture_review(fixture: LocalATSFixture) -> str:
    body, content_type = _fixture_multipart()
    request = Request(
        fixture.application_url + "/review",
        data=body,
        headers={"Content-Type": content_type},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("fixture review did not succeed")
        return response.read().decode("utf-8")


def observe_local_origin_drift(
    *,
    assertion_result_sha256: str,
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> RuntimeControlReceipt:
    """Observe both wrong-loopback-authority requests returning exact 403s."""

    with LocalATSFixture(
        _control_vacancy(), nonce=lambda: NONCE, form_token=FORM_TOKEN
    ) as fixture:
        before = _fixture_state(
            fixture,
            submit_click_count=0,
            event_count=0,
            dispatch_state="fixture_started",
        )
        parsed = urlsplit(fixture.application_url)
        wrong_port = int(parsed.port or 0) + 1
        statuses: list[int] = []
        for headers in (
            {"Host": f"{parsed.hostname}:{wrong_port}"},
            {"Origin": f"http://{parsed.hostname}:{wrong_port}"},
        ):
            try:
                urlopen(Request(fixture.application_url, headers=headers), timeout=5)
            except HTTPError as error:
                statuses.append(error.code)
            else:
                raise RuntimeError("wrong loopback authority was accepted")
        after = _fixture_state(
            fixture,
            submit_click_count=0,
            event_count=0,
            dispatch_state="fixture_started",
        )
    result_sha256 = _content_hash(
        {
            "assertion_result_sha256": assertion_result_sha256,
            "http_statuses": statuses,
            "request_variants": ("host_wrong_port", "origin_wrong_port"),
            "before_state": before,
            "after_state": after,
        }
    )
    return record_fixture_http_rejection(
        executable_identity=(
            "test_jaa09_negative_controls.py::"
            "test_fixture_refuses_other_loopback_host_port_or_origin"
        ),
        http_statuses=tuple(statuses),
        request_variants=("host_wrong_port", "origin_wrong_port"),
        result_sha256=result_sha256,
        before_state=before,
        after_state=after,
        source_git_revision=source_git_revision,
        source_tree=source_tree,
        source_content_revision=source_content_revision,
    )


def observe_duplicate_submit(
    *,
    assertion_result_sha256: str,
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> RuntimeControlReceipt:
    """Observe duplicate submit/review 409s with exactly one receipt retained."""

    with LocalATSFixture(
        _control_vacancy(), nonce=lambda: NONCE, form_token=FORM_TOKEN
    ) as fixture:
        review = _fixture_review(fixture)
        nonce = re.search(r'name="review_nonce" value="([^"]+)"', review)
        if nonce is None:
            raise RuntimeError("fixture review nonce is missing")
        data = (
            f"review_nonce={nonce.group(1)}&fixture_token={FORM_TOKEN}"
        ).encode()

        def submit() -> int:
            request = Request(
                fixture.application_url + "/submit",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urlopen(request, timeout=5) as response:
                return response.status

        if submit() != 201 or fixture.receipt is None:
            raise RuntimeError("fixture baseline submit did not create one receipt")
        first_receipt = fixture.receipt
        before = _fixture_state(
            fixture,
            submit_click_count=1,
            event_count=1,
            dispatch_state="receipt_recorded",
        )
        statuses: list[int] = []
        for operation in (submit, lambda: _fixture_review(fixture)):
            try:
                operation()
            except HTTPError as error:
                statuses.append(error.code)
            else:
                raise RuntimeError("duplicate fixture operation was accepted")
        if fixture.receipt is not first_receipt:
            raise RuntimeError("duplicate fixture operation replaced the receipt")
        after = _fixture_state(
            fixture,
            submit_click_count=1,
            event_count=1,
            dispatch_state="receipt_recorded",
        )
    result_sha256 = _content_hash(
        {
            "assertion_result_sha256": assertion_result_sha256,
            "http_statuses": statuses,
            "request_variants": ("duplicate_submit", "duplicate_review"),
            "before_state": before,
            "after_state": after,
            "receipt_id": first_receipt.receipt_id,
        }
    )
    return record_store_state_invariance(
        executable_identity=(
            "test_jaa09_negative_controls.py::"
            "test_duplicate_submit_and_second_review_produce_no_second_receipt"
        ),
        http_statuses=tuple(statuses),
        request_variants=("duplicate_submit", "duplicate_review"),
        result_sha256=result_sha256,
        before_state=before,
        after_state=after,
        source_git_revision=source_git_revision,
        source_tree=source_tree,
        source_content_revision=source_content_revision,
    )


def _fixture_date(database: CareerDatabase) -> date:
    with database.connection() as connection:
        value = connection.execute(
            """SELECT as_of FROM fit_assessment_runs
               ORDER BY rowid DESC LIMIT 1"""
        ).fetchone()[0]
    return date.fromisoformat(str(value))


def _fixture_now(database: CareerDatabase) -> datetime:
    value = _fixture_date(database)
    return datetime(value.year, value.month, value.day, 12, tzinfo=timezone.utc)


class _FrozenCorpusResearch:
    def __init__(self, cache: RawResponseCache, authority: FrozenVacancyAuthority):
        self.cache = cache
        self.authority = authority

    def retrieve_plan(
        self, task: object
    ) -> tuple[list[Citation], list[dict[str, object]]]:
        if (
            getattr(task, "job_key", None) != self.authority.job_key
            or getattr(task, "company", None) != self.authority.company
            or str(getattr(task, "title", "")).strip() != self.authority.title
            or getattr(task, "url", None) != self.authority.vacancy_url
        ):
            raise ValueError("research task differs from verified frozen vacancy")
        digest, reference = self.cache.store(self.authority.raw_response_bytes)
        if digest != RAW_RESPONSE_SHA256:
            raise ValueError("replayed official response identity changed")
        robots_digest, robots_reference = self.cache.store(
            self.authority.robots_response_bytes
        )
        if (
            robots_digest != ROBOTS_RESPONSE_SHA256
            or robots_reference != f"sha256/0b/{ROBOTS_RESPONSE_SHA256}"
        ):
            raise ValueError("replayed robots response identity changed")
        source_document = self.authority.dossier["sources"][0]
        source = Citation(**{**source_document, "raw_response_ref": reference})
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


def _scored_payload(authority: FrozenVacancyAuthority) -> dict[str, Any]:
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
                "tracked_seed_payload_hash": authority.tracked_seed_payload_sha256,
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


def _fit_database(
    work_root: Path, authority: FrozenVacancyAuthority
) -> tuple[CareerDatabase, object, tuple[Requirement, ...]]:
    database = CareerDatabase(work_root / "career.sqlite3")
    job = scored_job_from_payload(_scored_payload(authority))
    if job.key != GRAPHCORE_JOB_KEY:
        raise ValueError("verified vacancy key changed")
    if OpportunityGate(database).bootstrap([job]).queued != 1:
        raise ValueError("verified vacancy was not queued exactly once")
    cache = RawResponseCache(work_root / "raw")
    coordinator = Opportunity1Coordinator(
        database,
        EmployerResearchWorker(
            database,
            "jaa10-frozen-corpus-worker",
            cache,
            retriever=_FrozenCorpusResearch(cache, authority),
        ),
        signal_deriver=lambda _dossier: [],
    )
    result = coordinator.run_once()
    if result is None or result["job_key"] != authority.job_key or result["decision"] != "pass":
        raise ValueError("frozen vacancy research replay did not pass")
    completed = database.post_research_dossier(authority.job_key)
    if completed is None or completed[0]["sources"][0]["content_sha256"] != RAW_RESPONSE_SHA256:
        raise ValueError("frozen research dossier changed")
    with database.connection() as connection:
        payload_hash = str(
            connection.execute(
                "SELECT payload_hash FROM pipeline_jobs WHERE job_key=?", (job.key,)
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
            (body.index(anchor.text), body.index(anchor.text) + len(anchor.text)),
        )
        for index, anchor in enumerate(authority.requirement_anchors, 1)
    )
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
            valid_until=date.today().replace(year=date.today().year + 1).isoformat(),
        )
        graph.verify_evidence(
            evidence_id,
            1,
            decision="approved",
            verifier_kind="deterministic",
            policy_id="jaa10.fixture-candidate-review",
            policy_version="1",
            policy_hash=POLICY_DIGEST,
            reason=CANDIDATE_FIXTURE_DISCLOSURE,
            source_identity="fixture:independent-reviewer",
        )
        graph.add_claim(
            requirement.criterion,
            statement=(
                f"Fixture claim for {requirement.text}; "
                f"{CANDIDATE_FIXTURE_DISCLOSURE}."
            ),
            claim_type=("capability", "project", "education")[(index - 1) % 3],
            state="evidence",
            source_identity=f"fixture:candidate-claim:{index}",
            valid_until=date.today().replace(year=date.today().year + 1).isoformat(),
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
                "jaa10-real-vacancy-fit-v1",
                POLICY_DIGEST,
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
    if run.status != "ready":
        raise ValueError("frozen fixture fit assessment is not ready")
    return database, run, requirements


def _release_inputs(work_root: Path, authority: FrozenVacancyAuthority):
    database, run, requirements = _fit_database(work_root, authority)
    as_of = _fixture_date(database)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id, as_of=as_of
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
        policy_id="jaa10.fixture-contact",
        policy_version="1",
        policy_hash=POLICY_DIGEST,
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
        requirement.requirement_id: (f"fixture-example-{index}", requirement.text)
        for index, requirement in enumerate(requirements, 1)
    }
    source = ProductionApplicationCompiler(database.path).compile(
        strategy.strategy_id,
        as_of=as_of,
        contact=contact,
        questions=questions,
        cv_layout="four_section",
    )
    if (
        source.job_key != authority.job_key
        or source.role_title != authority.title
        or source.company_name != authority.company
    ):
        raise ValueError("compiled application differs from frozen vacancy")
    artifacts = render_pdf_artifacts(source)
    cv_constraint = validate_application_cv(source, artifacts)
    artifact_root = work_root / "published"
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
        policy_id="jaa10.fixture-work-right",
        policy_version="1",
        policy_hash=POLICY_DIGEST,
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
    gate = ReleaseGateStore(database.path, clock=lambda: _fixture_now(database))
    gate.register_official_route(
        job_key=source.job_key,
        route=OfficialRouteBinding(
            "route:graphcore-local-fixture",
            "offline-test-adapter",
            "1",
            "fixture:local-route-policy",
            POLICY_DIGEST,
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
        cv_constraint_receipt=cv_constraint.document(),
        expected_cv_policy_sha256=cv_constraint.policy_sha256,
    )
    return (
        database,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        publication,
        gate,
        issued,
    )


def _browser_inputs(
    fixture: LocalATSFixture,
    work_root: Path,
    release_inputs: tuple[object, ...],
):
    (
        database,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        publication,
        gate,
        issued,
    ) = release_inputs
    definitions = (
        ("full_name", ActionKind.FILL, "Full name", "Alex Example"),
        ("email", ActionKind.FILL, "Email address", "alex@example.test"),
        ("phone", ActionKind.FILL, "Phone number", "+44 7700 900123"),
        ("city", ActionKind.FILL, "Current city", "London"),
        (
            "work_authorisation",
            ActionKind.SELECT_OPTION,
            "UK work authorisation",
            "authorised",
        ),
        (
            "cover_note",
            ActionKind.FILL,
            fixture.state.vacancy.question,
            "Delivered a synthetic migration example.",
        ),
        ("cv", ActionKind.UPLOAD, "CV (PDF)", work_root / "cv.pdf"),
        (
            "cover_letter",
            ActionKind.UPLOAD,
            "Cover letter (PDF)",
            work_root / "cover-letter.pdf",
        ),
    )
    (work_root / "cv.pdf").write_bytes(b"%PDF-cv")
    (work_root / "cover-letter.pdf").write_bytes(b"%PDF-letter")
    actions: list[BrowserAction] = [
        BrowserAction("open", ActionKind.NAVIGATE, target_url=fixture.application_url)
    ]
    approvals: list[ApprovedValue] = []
    values: dict[str, MaterializedValue] = {}
    for identifier, kind, label, value in definitions:
        reference = ValueReference(ValueSource.EVIDENCE, f"EV_{identifier.upper()}")
        candidates = (
            (
                SelectorCandidate(SelectorStrategy.LABEL, "Missing full-name label"),
                SelectorCandidate(SelectorStrategy.CSS, "#full_name"),
            )
            if identifier == "full_name"
            else (SelectorCandidate(SelectorStrategy.LABEL, label),)
        )
        required = (
            ("field_status", "upload_sha256")
            if kind is ActionKind.UPLOAD
            else ("field_status",)
        )
        actions.append(
            BrowserAction(
                identifier,
                kind,
                selectors=SelectorPlan(candidates),
                value_reference=reference,
                required_output_keys=required,
            )
        )
        authorization = f"APPROVAL_{identifier.upper()}"
        approvals.append(ApprovedValue(reference, authorization))
        digest = hashlib.sha256(value.read_bytes()).hexdigest() if isinstance(value, Path) else None
        values[reference.key] = MaterializedValue(
            reference, authorization, value, digest
        )
    actions.append(
        BrowserAction(
            "review",
            ActionKind.CLICK,
            selectors=SelectorPlan(
                (SelectorCandidate(SelectorStrategy.ROLE, "button:Review application"),)
            ),
        )
    )
    artifact_directory = artifact_root / publication.relative_directory

    def bind(reference_key: str, value: str | Path, digest: str | None) -> None:
        prior = values[reference_key]
        values[reference_key] = MaterializedValue(
            prior.reference, prior.authorization_reference, value, digest
        )

    bind("evidence:EV_FULL_NAME", contact.full_name, None)
    bind("evidence:EV_EMAIL", contact.email, None)
    bind("evidence:EV_PHONE", contact.phone, None)
    bind("evidence:EV_CITY", contact.city, None)
    bind("evidence:EV_WORK_AUTHORISATION", "authorised", None)
    bind("evidence:EV_COVER_NOTE", artifacts.editable.answers_text.strip(), None)
    bind("evidence:EV_CV", artifact_directory / "cv.pdf", artifacts.cv_pdf.pdf_sha256)
    bind(
        "evidence:EV_COVER_LETTER",
        artifact_directory / "cover-letter.pdf",
        artifacts.cover_letter_pdf.pdf_sha256,
    )
    actions.append(
        BrowserAction(
            "submit",
            ActionKind.SUBMIT,
            selectors=SelectorPlan(
                (SelectorCandidate(SelectorStrategy.TEST_ID, "final-submit"),)
            ),
            required_output_keys=(
                "receipt_id",
                "receipt_payload_sha256",
                "screenshot_sha256",
                "field_map_sha256",
                "submit_event_sha256",
            ),
        )
    )
    workflow = BrowserWorkflow("released_local_fixture_application", tuple(actions))
    document_assurance_receipts = assert_application_artifacts(
        cv_pdf_bytes=artifacts.cv_pdf.pdf_bytes,
        cover_letter_pdf_bytes=artifacts.cover_letter_pdf.pdf_bytes,
        answers_text=artifacts.editable.answers_text,
        intended_vacancy=IntendedVacancy(
            job_key=source.job_key,
            vacancy_sha256=source.vacancy_sha256,
            role_title=source.role_title,
            company_name=source.company_name,
        ),
    )
    sanity_review_receipt = fixture_pass_receipt(
        source=source,
        artifacts=artifacts,
        questions=questions,
        state_root=work_root,
    )
    archive_receipt, archive_root = fixture_release_archive_receipt(
        source=source,
        artifacts=artifacts,
        questions=questions,
        document_assurance_receipts=document_assurance_receipts,
        sanity_review_receipt=sanity_review_receipt,
        artifact_root=artifact_root,
        repository_root=ROOT,
        finalized_at=_fixture_now(database),
    )
    authority = ReleaseExecutionAuthority(
        gate=gate,
        release_token=issued.release_token,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        document_assurance_receipts=document_assurance_receipts,
        sanity_review_receipt=sanity_review_receipt,
        archive_receipt=archive_receipt,
        archive_root=archive_root,
        artifact_root=artifact_root,
        repository_root=ROOT,
        ats_provider="jaa_loopback",
        application_url=fixture.application_url,
        attached_roles=("cv", "cover_letter"),
        upload_field_names=(),
        field_authority_names=(),
        consent_states=(),
        success_evidence=None,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=_fixture_now(database),
        receipt_url=fixture.receipt_url,
        application_id=fixture.state.vacancy.application_id,
        job_key=source.job_key,
    )
    return database, workflow, tuple(approvals), values, authority, issued


def _claim_population(
    authority: FrozenVacancyAuthority,
    release_manifest_sha256: str,
) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    claims = authority.dossier.get("claims")
    if not isinstance(claims, list):
        raise ValueError("frozen dossier claim inventory is missing")
    for claim in claims:
        if not isinstance(claim, dict) or claim.get("outcome") != "supported":
            continue
        excerpt = claim.get("citation_excerpt")
        source_ids = claim.get("source_ids")
        if (
            not isinstance(excerpt, str)
            or not excerpt.strip()
            or not isinstance(source_ids, list)
            or not source_ids
            or not all(isinstance(value, str) and value for value in source_ids)
        ):
            raise ValueError("supported employer claim lacks exact citation evidence")
        rows.append(
            {
                "release_manifest_sha256": release_manifest_sha256,
                "claim_id": str(claim["id"]),
                "kind": str(claim["kind"]),
                "claim_text_sha256": hashlib.sha256(
                    str(claim["text"]).encode("utf-8")
                ).hexdigest(),
                "citation_excerpt_sha256": hashlib.sha256(
                    excerpt.encode("utf-8")
                ).hexdigest(),
                "source_ids": tuple(source_ids),
                "supported": True,
                "cited": True,
            }
        )
    if not rows:
        raise ValueError("release claim denominator may not be empty")
    return tuple(rows)


def _must_raise(operation, expected_type: type[Exception], message: str) -> Exception:
    try:
        operation()
    except expected_type as error:
        if message not in str(error):
            raise AssertionError("runtime exception message differs from injection") from error
        return error
    raise AssertionError("injected operation returned normally")


def execute_frozen_loopback_interruption(
    work_root: Path,
    injection_point: str,
) -> InterruptionObservation:
    """Execute one accepted crash boundary and derive its observed outcome."""

    if injection_point not in REQUIRED_INTERRUPTION_POINTS:
        raise ValueError("interruption point is outside the frozen contract")
    work_root.mkdir(parents=True, exist_ok=False)
    corpus = verify_graphcore_corpus(CERTIFIED_CORPUS, TRACKED_SEED)
    release_inputs = _release_inputs(work_root, corpus)
    vacancy = FixtureVacancy(
        FROZEN_SHADOW_CONTRACT.application_id,
        corpus.job_key,
        corpus.title,
        corpus.company,
        corpus.requirement_anchors[0].text,
    )
    with LocalATSFixture(vacancy, nonce=lambda: NONCE, form_token=FORM_TOKEN) as fixture:
        database, workflow, approvals, values, authority, issued = _browser_inputs(
            fixture, work_root, release_inputs
        )
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow, run_id=f"jaa10-{injection_point}")
        if store.claim_run("jaa10_worker", run_id=run_id) is None:
            raise RuntimeError("interruption workflow could not be claimed")
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=f"JAA08:{issued.manifest.release_manifest_sha256}",
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )

            if injection_point == "post_prepare_pre_consume":
                original = authority.gate.consume_release_token

                def injected(**_kwargs):
                    raise RuntimeError("injected before consume")

                authority.gate.consume_release_token = injected
                _must_raise(
                    lambda: executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    ),
                    RuntimeError,
                    "before consume",
                )
                authority.gate.consume_release_token = original
            elif injection_point == "post_consume_pre_reconcile":
                original = store.reconcile_release_consumed

                def injected(*_args, **_kwargs):
                    raise RuntimeError("injected before consumption reconcile")

                store.reconcile_release_consumed = injected  # type: ignore[method-assign]
                _must_raise(
                    lambda: executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    ),
                    RuntimeError,
                    "before consumption reconcile",
                )
                store.reconcile_release_consumed = original  # type: ignore[method-assign]
            elif injection_point == "post_consume_pre_click":
                original = store.mark_submit_started

                def injected(*_args, **_kwargs):
                    raise RuntimeError("injected before click")

                store.mark_submit_started = injected  # type: ignore[method-assign]
                _must_raise(
                    lambda: executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    ),
                    RuntimeError,
                    "before click",
                )
                store.mark_submit_started = original  # type: ignore[method-assign]
            elif injection_point == "post_mark_pre_click":
                original = store.mark_submit_started

                def injected(*args, **kwargs):
                    original(*args, **kwargs)
                    raise RuntimeError("injected after click intent")

                store.mark_submit_started = injected  # type: ignore[method-assign]
                _must_raise(
                    lambda: executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    ),
                    RuntimeError,
                    "after click intent",
                )
                store.mark_submit_started = original  # type: ignore[method-assign]
            else:
                original = store.complete_step
                interrupted = False

                def injected(*args, **kwargs):
                    nonlocal interrupted
                    if kwargs.get("step_id") == "submit" and not interrupted:
                        interrupted = True
                        raise RuntimeError("injected after click")
                    return original(*args, **kwargs)

                store.complete_step = injected  # type: ignore[method-assign]
                _must_raise(
                    lambda: executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    ),
                    RuntimeError,
                    "after click",
                )
                store.complete_step = original  # type: ignore[method-assign]
            browser.close()

            resumed = LocalBrowserExecutor(store, repository_root=ROOT)
            resumed_browser = playwright.chromium.launch(headless=True)
            resumed_page = resumed_browser.new_page()
            if injection_point == "post_mark_pre_click":
                _must_raise(
                    lambda: resumed.execute_next(
                        resumed_page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    ),
                    SubmissionIndeterminateError,
                    "no recoverable official receipt",
                )
                resumed_browser.close()
                if fixture.receipt is not None:
                    raise AssertionError("indeterminate interruption fabricated a receipt")
                result = InterruptionObservation(injection_point, "fail_closed", 0, 0)
            else:
                first_receipt = fixture.receipt
                resumed.execute_next(
                    resumed_page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
                resumed_browser.close()
                if fixture.receipt is None:
                    raise AssertionError("recoverable interruption produced no receipt")
                if first_receipt is not None and fixture.receipt is not first_receipt:
                    raise AssertionError("restart created a second receipt")
                result = InterruptionObservation(injection_point, "recovered", 1, 1)
        click_intents = sum(
            row["event_type"] == "submit_click_started" for row in store.events(run_id)
        )
        if click_intents != 1:
            raise AssertionError("interruption did not preserve one submit intent")
        return result


@dataclass(frozen=True)
class ExecutedLoopbackObservation:
    observation: ShadowObservation
    claim_population: tuple[Mapping[str, object], ...]
    non_loopback_requests: int = 0
    real_applications_submitted: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.observation, ShadowObservation):
            raise TypeError("executed result requires a typed shadow observation")
        rows = tuple(MappingProxyType(dict(row)) for row in self.claim_population)
        object.__setattr__(self, "claim_population", rows)
        if not rows or any(
            row.get("release_manifest_sha256")
            != self.observation.release_manifest_sha256
            or row.get("supported") is not True
            or row.get("cited") is not True
            for row in rows
        ):
            raise ValueError("release claim population is empty or not fully grounded")
        if self.non_loopback_requests != 0 or self.real_applications_submitted != 0:
            raise ValueError("shadow execution cannot record an external action")


def execute_frozen_loopback_observation(
    work_root: Path,
    *,
    observation_id: str,
    observed_at: datetime,
    interruptions: tuple[InterruptionObservation, ...],
    runtime_receipts: tuple[RuntimeControlReceipt, ...],
) -> ExecutedLoopbackObservation:
    """Execute one complete release and submit against the loopback fixture."""

    work_root.mkdir(parents=True, exist_ok=False)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("synthetic observation time must be timezone aware")
    if tuple(row.injection_point for row in interruptions) != REQUIRED_INTERRUPTION_POINTS:
        raise ValueError("interruption inventory is incomplete or unordered")
    mutations = mutation_observations_from_runtime(runtime_receipts)
    authority = verify_graphcore_corpus(CERTIFIED_CORPUS, TRACKED_SEED)
    if (
        authority.corpus_identity != FROZEN_SHADOW_CONTRACT.corpus_inventory_sha256
        or authority.raw_response_sha256
        != FROZEN_SHADOW_CONTRACT.official_response_sha256
        or authority.dossier_sha256 != FROZEN_SHADOW_CONTRACT.dossier_sha256
    ):
        raise ValueError("frozen corpus differs from the shadow contract")
    release_inputs = _release_inputs(work_root, authority)
    vacancy = FixtureVacancy(
        FROZEN_SHADOW_CONTRACT.application_id,
        authority.job_key,
        authority.title,
        authority.company,
        authority.requirement_anchors[0].text,
    )
    with LocalATSFixture(vacancy, nonce=lambda: NONCE, form_token=FORM_TOKEN) as fixture:
        database, workflow, approvals, values, release_authority, issued = _browser_inputs(
            fixture, work_root, release_inputs
        )
        workflow_sha256 = normalized_workflow_sha256(workflow.to_dict())
        if workflow_sha256 != FROZEN_SHADOW_CONTRACT.workflow_sha256:
            raise ValueError("loopback workflow differs from the frozen contract")
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow, run_id="jaa10-frozen-run-1")
        if store.claim_run("jaa10_worker", run_id=run_id) is None:
            raise RuntimeError("loopback workflow could not be claimed")
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=f"JAA08:{issued.manifest.release_manifest_sha256}",
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        elapsed: dict[str, int] = {}
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for action in workflow.actions:
                started = perf_counter_ns()
                completed = executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=release_authority,
                )
                elapsed[action.step_id] = (perf_counter_ns() - started) // 1_000_000
                if completed is None:
                    raise RuntimeError("loopback workflow did not complete an action")
            screenshot_bytes = len(page.screenshot(full_page=True))
            browser.close()
        outputs = store.checkpoint_outputs(run_id)["submit"]
        for key, expected in (
            ("field_map_sha256", FROZEN_SHADOW_CONTRACT.field_map_sha256),
            ("receipt_id", FROZEN_SHADOW_CONTRACT.receipt_id),
            (
                "receipt_payload_sha256",
                FROZEN_SHADOW_CONTRACT.receipt_payload_sha256,
            ),
            ("screenshot_sha256", FROZEN_SHADOW_CONTRACT.screenshot_sha256),
        ):
            if outputs[key] != expected:
                raise ValueError(f"loopback output {key} differs from golden contract")
        dispatch = store.submit_dispatch(run_id)
        if dispatch is None:
            raise RuntimeError("loopback submit dispatch is missing")
        release_manifest = str(dispatch["release_manifest_hash"])
        actual_submit_event = str(outputs["submit_event_sha256"])
        expected_submit_event = fixture_submit_event_sha256(
            run_id=run_id,
            workflow_sha256=workflow.content_hash,
            step_id="submit",
            release_manifest_sha256=release_manifest,
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(outputs["receipt_payload_sha256"]),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
        )
        if actual_submit_event != expected_submit_event:
            raise ValueError("durable submit event differs from exact runtime lineage")
        normalized_event = normalized_submit_event_sha256(
            workflow_sha256=workflow_sha256,
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(outputs["receipt_payload_sha256"]),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
        )
        if normalized_event != FROZEN_SHADOW_CONTRACT.submit_event_sha256:
            raise ValueError("normalized submit event differs from golden contract")
        observation = ShadowObservation(
            observation_id=observation_id,
            observed_at=observed_at.isoformat(),
            run_id=run_id,
            step_id="submit",
            workflow_sha256=workflow_sha256,
            durable_workflow_sha256=workflow.content_hash,
            release_manifest_sha256=release_manifest,
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(outputs["receipt_payload_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            submit_event_sha256=actual_submit_event,
            normalized_submit_event_sha256=normalized_event,
            submission_proof=SubmissionProof(
                release_manifest_sha256=release_manifest,
                token_sha256=issued.token_sha256,
                receipt_id=str(outputs["receipt_id"]),
                receipt_payload_sha256=str(outputs["receipt_payload_sha256"]),
                screenshot_sha256=str(outputs["screenshot_sha256"]),
                field_map_sha256=str(outputs["field_map_sha256"]),
                submit_event_sha256=actual_submit_event,
            ),
            fixture_receipt=FixtureReceipt(
                receipt_id=str(outputs["receipt_id"]),
                application_id=FROZEN_SHADOW_CONTRACT.application_id,
                job_key=FROZEN_SHADOW_CONTRACT.job_key,
                payload_sha256=str(outputs["receipt_payload_sha256"]),
            ),
            action_elapsed_ms=elapsed,
            browser_launch_count=1,
            database_bytes=database.path.stat().st_size,
            screenshot_bytes=screenshot_bytes,
            interruptions=interruptions,
            mutations=mutations,
        )
        return ExecutedLoopbackObservation(
            observation,
            _claim_population(authority, release_manifest),
        )


@dataclass(frozen=True)
class ModelCallAccounting:
    model_version: str = "deterministic:none"
    prompt_version: str = "deterministic:none"
    invocation_count: int = 0
    cost_microusd: int = 0
    accounting_status: str = "abstained_no_model_invocation"

    def __post_init__(self) -> None:
        if (
            self.model_version != "deterministic:none"
            or self.prompt_version != "deterministic:none"
            or self.invocation_count != 0
            or self.cost_microusd != 0
            or self.accounting_status != "abstained_no_model_invocation"
        ):
            raise ValueError("shadow cohort model accounting must record abstention")

    def document(self) -> dict[str, object]:
        return {
            "model_version": self.model_version,
            "prompt_version": self.prompt_version,
            "invocation_count": self.invocation_count,
            "cost_microusd": self.cost_microusd,
            "accounting_status": self.accounting_status,
        }


@dataclass(frozen=True)
class FullSubmitCohortEvidence:
    withheld_shadow: WithheldShadowEvidence
    runtime_receipts: tuple[RuntimeControlReceipt, ...]
    claim_populations: tuple[tuple[Mapping[str, object], ...], ...]
    source_git_revision: str
    source_tree: str
    source_content_revision: str
    cohort_id: str
    p4_summary_sha256: str = P4_SUMMARY_SHA256
    model_call_accounting: ModelCallAccounting = ModelCallAccounting()
    metrics_evaluated: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    live_time_separated_execution: str = "not_collected"
    external_action_capability: bool = False
    real_applications_submitted: int = 0
    schema_version: str = "jaa10.full-submit-cohort.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "source_identity": {
                "git_revision": self.source_git_revision,
                "tree": self.source_tree,
                "source_content_revision": self.source_content_revision,
            },
            "p4_interval_provenance": {
                "summary_sha256": self.p4_summary_sha256,
                "use": "authenticated_interval_only_not_submissions",
            },
            "withheld_shadow_evidence_id": self.withheld_shadow.evidence_id,
            "observation_sha256s": self.withheld_shadow.observation_sha256s,
            "release_manifest_sha256s": self.withheld_shadow.release_manifest_sha256s,
            "runtime_control_receipts": [
                receipt.document() for receipt in self.runtime_receipts
            ],
            "runtime_control_receipt_sha256s": [
                receipt.receipt_sha256 for receipt in self.runtime_receipts
            ],
            "claim_populations": [
                [dict(claim) for claim in population]
                for population in self.claim_populations
            ],
            "derived_counts": {
                "successful_loopback_submissions": len(
                    self.withheld_shadow.observations
                ),
                "released_claims": sum(map(len, self.claim_populations)),
                "released_employer_claims": sum(
                    len(population) for population in self.claim_populations
                ),
                "runtime_negative_controls": len(self.runtime_receipts),
            },
            "hard_quality_targets": dict(sorted(HARD_QUALITY_TARGETS.items())),
            "model_call_accounting": self.model_call_accounting.document(),
            "metrics_evaluated": False,
            "production_certification": "withheld",
            "certifies_slice": False,
            "live_time_separated_execution": "not_collected",
            "external_action_capability": False,
            "real_applications_submitted": 0,
        }
        if include_identity:
            result["cohort_id"] = self.cohort_id
        return result

    def verify(self) -> None:
        self.withheld_shadow.verify()
        if len(self.withheld_shadow.observations) != 2:
            raise ValueError("full-submit cohort requires exactly two observations")
        if len(set(self.withheld_shadow.release_manifest_sha256s)) != 2:
            raise ValueError("full-submit cohort requires two distinct releases")
        if tuple(receipt.control_id for receipt in self.runtime_receipts) != (
            RUNTIME_CONTROL_IDS
        ):
            raise ValueError("runtime control inventory is incomplete or unordered")
        if len({row.receipt_sha256 for row in self.runtime_receipts}) != len(
            self.runtime_receipts
        ):
            raise ValueError("runtime control receipt identity is duplicated")
        if not re.fullmatch(r"[0-9a-f]{40}", self.source_git_revision):
            raise ValueError("cohort source revision is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", self.source_tree):
            raise ValueError("cohort source tree is invalid")
        if not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.source_content_revision
        ):
            raise ValueError("cohort source-content revision is invalid")
        if any(
            (
                receipt.source_git_revision,
                receipt.source_tree,
                receipt.source_content_revision,
            )
            != (
                self.source_git_revision,
                self.source_tree,
                self.source_content_revision,
            )
            for receipt in self.runtime_receipts
        ):
            raise ValueError("runtime receipt crosses the cohort source identity")
        if self.p4_summary_sha256 != P4_SUMMARY_SHA256:
            raise ValueError("cohort cites a different P4 interval witness")
        if len(self.claim_populations) != 2:
            raise ValueError("claim populations must match the two releases")
        for release, population in zip(
            self.withheld_shadow.release_manifest_sha256s,
            self.claim_populations,
            strict=True,
        ):
            if not population or any(
                row.get("release_manifest_sha256") != release
                or row.get("supported") is not True
                or row.get("cited") is not True
                for row in population
            ):
                raise ValueError("release claim population is vacuous or ungrounded")
        if (
            self.metrics_evaluated is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
            or self.live_time_separated_execution != "not_collected"
            or self.external_action_capability is not False
            or self.real_applications_submitted != 0
        ):
            raise ValueError("full-submit cohort cannot claim certification or live action")
        if self.schema_version != "jaa10.full-submit-cohort.v1":
            raise ValueError("full-submit cohort schema is unsupported")
        if self.cohort_id != _content_hash(self.document(include_identity=False)):
            raise ValueError("full-submit cohort differs from its content identity")


def compile_full_submit_cohort(
    executions: tuple[ExecutedLoopbackObservation, ...],
    runtime_receipts: tuple[RuntimeControlReceipt, ...],
    *,
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> FullSubmitCohortEvidence:
    """Compile exactly two loopback executions; all verdicts stay withheld."""

    if len(executions) != 2 or not all(
        isinstance(row, ExecutedLoopbackObservation) for row in executions
    ):
        raise ValueError("full-submit cohort requires exactly two typed executions")
    withheld = compile_withheld_shadow_evidence(
        FROZEN_SHADOW_CONTRACT,
        tuple(row.observation for row in executions),
    )
    values = {
        "withheld_shadow": withheld,
        "runtime_receipts": runtime_receipts,
        "claim_populations": tuple(row.claim_population for row in executions),
        "source_git_revision": source_git_revision,
        "source_tree": source_tree,
        "source_content_revision": source_content_revision,
    }
    accounting = ModelCallAccounting()
    claim_populations = values["claim_populations"]
    body = {
        "schema_version": "jaa10.full-submit-cohort.v1",
        "source_identity": {
            "git_revision": source_git_revision,
            "tree": source_tree,
            "source_content_revision": source_content_revision,
        },
        "p4_interval_provenance": {
            "summary_sha256": P4_SUMMARY_SHA256,
            "use": "authenticated_interval_only_not_submissions",
        },
        "withheld_shadow_evidence_id": withheld.evidence_id,
        "observation_sha256s": withheld.observation_sha256s,
        "release_manifest_sha256s": withheld.release_manifest_sha256s,
        "runtime_control_receipts": [
            receipt.document() for receipt in runtime_receipts
        ],
        "runtime_control_receipt_sha256s": [
            receipt.receipt_sha256 for receipt in runtime_receipts
        ],
        "claim_populations": [
            [dict(claim) for claim in population]
            for population in claim_populations
        ],
        "derived_counts": {
            "successful_loopback_submissions": len(withheld.observations),
            "released_claims": sum(map(len, claim_populations)),
            "released_employer_claims": sum(
                len(population) for population in claim_populations
            ),
            "runtime_negative_controls": len(runtime_receipts),
        },
        "hard_quality_targets": dict(sorted(HARD_QUALITY_TARGETS.items())),
        "model_call_accounting": accounting.document(),
        "metrics_evaluated": False,
        "production_certification": "withheld",
        "certifies_slice": False,
        "live_time_separated_execution": "not_collected",
        "external_action_capability": False,
        "real_applications_submitted": 0,
    }
    identity = _content_hash(body)
    return FullSubmitCohortEvidence(cohort_id=identity, **values)
