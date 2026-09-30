"""Focused contract tests for the production-only JAA-10 cohort producer."""

from __future__ import annotations

import hashlib
import inspect

import pytest
import career_automation.network_witnessed_fixture as fixture_module
from datetime import datetime, timedelta, timezone

from career_automation.ats_fixture import FixtureReceipt
from career_automation.browser_workflows import (
    SubmissionProof,
    fixture_submit_event_sha256,
)
from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    MUTATION_TEST_NODES,
    REQUIRED_ACTIONS,
    REQUIRED_INTERRUPTION_POINTS,
    REQUIRED_MUTATION_CONTROLS,
    InterruptionObservation,
    ShadowObservation,
    normalized_submit_event_sha256,
)
from career_automation.shadow_full_submit_cohort import (
    ExecutedLoopbackObservation,
    compile_full_submit_cohort,
)
from career_automation.shadow_mutation_runtime import (
    REQUIRED_OUTCOME_KIND,
    RUNTIME_CONTROL_IDS,
    RuntimeControlReceipt,
    mutation_observations_from_runtime,
    observe_fail_closed_control,
    record_fixture_http_rejection,
    record_store_state_invariance,
)


REVISION = "1" * 40
TREE = "2" * 40
SOURCE_CONTENT = "sha256:" + "3" * 64


def _state() -> dict[str, object]:
    return {
        "receipt_count": 0,
        "submit_click_count": 0,
        "dispatch_state": "prepared",
        "event_count": 1,
    }


def _receipts() -> tuple[RuntimeControlReceipt, ...]:
    rows = []
    for control_id in RUNTIME_CONTROL_IDS:
        executable = MUTATION_TEST_NODES.get(control_id) or f"runtime-twin:{control_id}"
        if control_id == "local_origin_drift":
            rows.append(
                record_fixture_http_rejection(
                    executable_identity=executable,
                    http_statuses=(403, 403),
                    request_variants=("host_wrong_port", "origin_wrong_port"),
                    result_sha256=hashlib.sha256(control_id.encode()).hexdigest(),
                    before_state=_state(),
                    after_state=_state(),
                    source_git_revision=REVISION,
                    source_tree=TREE,
                    source_content_revision=SOURCE_CONTENT,
                )
            )
            continue
        if control_id == "duplicate_submit":
            duplicate_state = {
                "receipt_count": 1,
                "submit_click_count": 1,
                "dispatch_state": "receipt_recorded",
                "event_count": 1,
            }
            rows.append(
                record_store_state_invariance(
                    executable_identity=executable,
                    http_statuses=(409, 409),
                    request_variants=("duplicate_submit", "duplicate_review"),
                    result_sha256=hashlib.sha256(control_id.encode()).hexdigest(),
                    before_state=duplicate_state,
                    after_state=duplicate_state,
                    source_git_revision=REVISION,
                    source_tree=TREE,
                    source_content_revision=SOURCE_CONTENT,
                )
            )
            continue

        def blocked(control: str = control_id) -> None:
            raise ValueError(f"blocked:{control}")

        rows.append(
            observe_fail_closed_control(
                control_id=control_id,
                executable_identity=executable,
                operation=blocked,
                state_probe=_state,
                source_git_revision=REVISION,
                source_tree=TREE,
                source_content_revision=SOURCE_CONTENT,
            )
        )
    return tuple(rows)


def _observation(
    identifier: str,
    observed_at: datetime,
    release_manifest_sha256: str,
    runtime_receipts: tuple[RuntimeControlReceipt, ...],
) -> ShadowObservation:
    golden = FROZEN_SHADOW_CONTRACT
    run_id = f"full-submit-{identifier}"
    actual_event = fixture_submit_event_sha256(
        run_id=run_id,
        workflow_sha256=golden.workflow_sha256,
        step_id="submit",
        release_manifest_sha256=release_manifest_sha256,
        receipt_id=golden.receipt_id,
        receipt_payload_sha256=golden.receipt_payload_sha256,
        screenshot_sha256=golden.screenshot_sha256,
        field_map_sha256=golden.field_map_sha256,
    )
    return ShadowObservation(
        observation_id=identifier,
        observed_at=observed_at.isoformat(),
        run_id=run_id,
        step_id="submit",
        workflow_sha256=golden.workflow_sha256,
        durable_workflow_sha256=golden.workflow_sha256,
        release_manifest_sha256=release_manifest_sha256,
        receipt_id=golden.receipt_id,
        receipt_payload_sha256=golden.receipt_payload_sha256,
        field_map_sha256=golden.field_map_sha256,
        screenshot_sha256=golden.screenshot_sha256,
        submit_event_sha256=actual_event,
        normalized_submit_event_sha256=normalized_submit_event_sha256(
            workflow_sha256=golden.workflow_sha256,
            receipt_id=golden.receipt_id,
            receipt_payload_sha256=golden.receipt_payload_sha256,
            screenshot_sha256=golden.screenshot_sha256,
            field_map_sha256=golden.field_map_sha256,
        ),
        submission_proof=SubmissionProof(
            release_manifest_sha256=release_manifest_sha256,
            token_sha256=hashlib.sha256(f"token:{identifier}".encode()).hexdigest(),
            receipt_id=golden.receipt_id,
            receipt_payload_sha256=golden.receipt_payload_sha256,
            screenshot_sha256=golden.screenshot_sha256,
            field_map_sha256=golden.field_map_sha256,
            submit_event_sha256=actual_event,
        ),
        fixture_receipt=FixtureReceipt(
            receipt_id=golden.receipt_id,
            application_id=golden.application_id,
            job_key=golden.job_key,
            payload_sha256=golden.receipt_payload_sha256,
        ),
        action_elapsed_ms={action: 1 for action in REQUIRED_ACTIONS},
        browser_launch_count=1,
        database_bytes=4096,
        screenshot_bytes=2048,
        interruptions=tuple(
            InterruptionObservation(
                point,
                "fail_closed" if point == "post_mark_pre_click" else "recovered",
                0 if point == "post_mark_pre_click" else 1,
                0 if point == "post_mark_pre_click" else 1,
            )
            for point in REQUIRED_INTERRUPTION_POINTS
        ),
        mutations=mutation_observations_from_runtime(runtime_receipts),
    )


def test_exact_two_runtime_bound_executions_compile_but_do_not_certify() -> None:
    receipts = _receipts()
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    releases = (
        hashlib.sha256(b"release:one").hexdigest(),
        hashlib.sha256(b"release:two").hexdigest(),
    )
    executions = tuple(
        ExecutedLoopbackObservation(
            _observation(
                f"observation-{index}",
                first_time + timedelta(days=index - 1),
                release,
                receipts,
            ),
            (
                {
                    "release_manifest_sha256": release,
                    "claim_id": "outcome:role",
                    "supported": True,
                    "cited": True,
                },
            ),
        )
        for index, release in enumerate(releases, 1)
    )
    cohort = compile_full_submit_cohort(
        executions,
        receipts,
        source_git_revision=REVISION,
        source_tree=TREE,
        source_content_revision=SOURCE_CONTENT,
    )
    cohort.verify()
    assert len(cohort.withheld_shadow.observations) == 2
    assert len(set(cohort.withheld_shadow.release_manifest_sha256s)) == 2
    assert tuple(row.control_id for row in receipts) == RUNTIME_CONTROL_IDS
    assert tuple(row.observed_outcome.kind for row in receipts) == tuple(
        REQUIRED_OUTCOME_KIND[control_id] for control_id in RUNTIME_CONTROL_IDS
    )
    assert cohort.document()["derived_counts"] == {
        "successful_loopback_submissions": 2,
        "released_claims": 2,
        "released_employer_claims": 2,
        "runtime_negative_controls": len(RUNTIME_CONTROL_IDS),
    }
    assert cohort.metrics_evaluated is False
    assert cohort.production_certification == "withheld"
    assert cohort.certifies_slice is False
    assert cohort.live_time_separated_execution == "not_collected"
    assert cohort.real_applications_submitted == 0


def test_production_cohort_has_no_test_module_imports() -> None:
    from career_automation import shadow_full_submit_cohort

    source = inspect.getsource(shadow_full_submit_cohort)
    assert "from test_" not in source
    assert "import test_" not in source
    assert tuple(MUTATION_TEST_NODES) == REQUIRED_MUTATION_CONTROLS


def _network_fit_inputs(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from career_automation import shadow_full_submit_cohort as cohort
    from career_automation.jaa04_corpus_authority import RawRequirementAnchor
    from test_jaa06_independent_acceptance import (
        SYNTHETIC_PRODUCT_SOURCE,
        _CapturedResearch,
    )

    body = SYNTHETIC_PRODUCT_SOURCE
    digest = hashlib.sha256(body).hexdigest()
    anchors = tuple(
        RawRequirementAnchor(text, body.index(text.encode()), len(text), digest)
        for text in ("product service", "reliable engineering", "technology")
    )
    frozen = SimpleNamespace(
        synthetic_fixture_id=fixture_module.SYNTHETIC_FIXTURE_ID,
        candidate_profile_id=fixture_module.SYNTHETIC_PROFILE_ID,
        job_key=fixture_module.GRAPHCORE_JOB_KEY,
        title="Synthetic Engineer",
        company="Example",
        vacancy_url="https://jobs.example.test/synthetic",
        opportunity_score_bp=9000,
        queue_payload={},
        raw_response_bytes=body,
        raw_response_sha256=digest,
        inventory_sha256=digest,
        inventory_files_sha256=digest,
        dossier_sha256=digest,
        queue_body_content_sha256=digest,
        admitted_queue_payload_sha256=digest,
        tracked_seed_payload_sha256=digest,
        requirement_anchors=anchors,
        dossier={"sources": [{"captured_at": datetime.now(timezone.utc).isoformat()}]},
    )
    with monkeypatch.context() as synthetic_research:
        synthetic_research.setattr(
            fixture_module,
            "_FrozenCorpusResearch",
            lambda cache, authority: _CapturedResearch(cache),
        )
        synthetic_research.setattr(fixture_module, "RAW_RESPONSE_SHA256", digest)
        return fixture_module._issued_release_inputs(tmp_path, cohort.ROOT, frozen)


def test_network_fit_documents_synthetic_facts_without_wrappers_or_duplicate_research(
    tmp_path, monkeypatch
):
    from career_automation.application_compiler import (
        verify_application_source,
    )
    from career_automation.rendering import render_editable_text

    inputs = _network_fit_inputs(tmp_path, monkeypatch)
    database, source = inputs[0], inputs[4]
    verify_application_source(source)
    rendered = render_editable_text(source)
    candidate_facts = {
        row.text for row in source.facts if row.fact_kind == "candidate"
    }
    assert candidate_facts == {
        claim_statement
        for _evidence_statement, claim_statement, _claim_type
        in fixture_module.SYNTHETIC_CANDIDATE_FACTS
    }
    assert all(fixture_module.DISCLOSURE not in row.text for row in source.facts)
    assert all("Fixture claim" not in row.text for row in source.facts)
    assert "not a real person" not in rendered.cv_text
    assert "not a real person" not in rendered.cover_letter_text
    employer_facts = [row for row in source.facts if row.fact_kind == "employer"]
    assert len(employer_facts) == 1
    assert rendered.cover_letter_text.count(employer_facts[0].text) == 1
    assert employer_facts[0].text == (
        "Example: Example's product service platform provides reliable engineering "
        "and technology for customer workflows."
    )
    with database.connection() as connection:
        provenance = connection.execute(
            """SELECT evidence.source_identity,decision.reason
               FROM candidate_evidence evidence
               JOIN candidate_verification_decisions decision
                 ON decision.target_kind='evidence'
                AND decision.target_id=evidence.evidence_id
                AND decision.target_version=evidence.version
               WHERE evidence.source_identity LIKE 'fixture:candidate-evidence:%'
               ORDER BY evidence.evidence_id"""
        ).fetchall()
    assert len(provenance) == len(fixture_module.SYNTHETIC_CANDIDATE_FACTS)
    assert all(row[0].startswith("fixture:candidate-evidence:") for row in provenance)
    assert all(row[1] == fixture_module.DISCLOSURE for row in provenance)


def test_network_fit_rejects_mismatched_synthetic_profile_anchors(tmp_path):
    from types import SimpleNamespace

    from career_automation.jaa04_corpus_authority import RawRequirementAnchor

    digest = hashlib.sha256(b"synthetic vacancy").hexdigest()
    authority = SimpleNamespace(
        synthetic_fixture_id=fixture_module.SYNTHETIC_FIXTURE_ID,
        candidate_profile_id=fixture_module.SYNTHETIC_PROFILE_ID,
        job_key=fixture_module.GRAPHCORE_JOB_KEY,
        raw_response_sha256=digest,
        requirement_anchors=tuple(
            RawRequirementAnchor(text, 0, len(text), digest)
            for text in (
                "product service",
                "unrelated requirement",
                "technology",
            )
        ),
    )
    with pytest.raises(
        fixture_module.NetworkWitnessedFixtureError,
        match="declared vacancy anchor identity",
    ):
        fixture_module._fit_database(
            tmp_path,
            authority,
            candidate_profile_id=fixture_module.SYNTHETIC_PROFILE_ID,
        )
    assert not (tmp_path / "workflow.sqlite3").exists()


def test_distinct_employer_facts_from_one_source_are_retained_by_hash():
    from career_automation.application_compiler import (
        _employer_fact_is_new,
        content_hash,
    )

    source_ids = ["fixture:official-product"]
    fact_hashes = tuple(
        content_hash({
            "classification": "fact",
            "id": claim_id,
            "source_ids": source_ids,
            "text": text,
        })
        for claim_id, text in (
            ("product-service", "Example offers a service platform."),
            ("product-technology", "Example serves users with technology."),
        )
    )
    seen_hashes: set[str] = set()
    assert _employer_fact_is_new(fact_hashes[0], seen_hashes)
    assert _employer_fact_is_new(fact_hashes[1], seen_hashes)
    assert not _employer_fact_is_new(fact_hashes[0], seen_hashes)


@pytest.mark.parametrize("release_builder", ["acceptance_fixture", "cohort", "cohort_fit", "network_fit", "network_live_review"])
def test_cohort_browser_inputs_execute_synthetic_release(tmp_path, monkeypatch, release_builder):
    """Run the canonical cohort browser builder with an actual synthetic release."""
    from playwright.sync_api import sync_playwright
    from career_automation import shadow_full_submit_cohort as cohort
    from career_automation import network_witnessed_fixture as network
    from career_automation.ats_fixture import FixtureVacancy, LocalATSFixture
    from career_automation.browser_executor import LocalBrowserExecutor
    from career_automation.browser_workflows import BrowserWorkflowStore
    from test_jaa08_independent_acceptance import _issued_release_inputs

    if release_builder == "acceptance_fixture":
        rows = _issued_release_inputs(tmp_path)
        database, _, contact, questions, source, artifacts, artifact_root, publication, _, gate, _, issued = rows
        inputs = (database, contact, questions, source, artifacts, artifact_root, publication, gate, issued)
    elif release_builder in ("cohort_fit", "network_fit", "network_live_review"):
        from types import SimpleNamespace
        from test_jaa06_independent_acceptance import (
            SYNTHETIC_PRODUCT_SOURCE,
            _CapturedResearch,
        )
        from career_automation.jaa04_corpus_authority import RawRequirementAnchor
        builder = network if release_builder in ("network_fit", "network_live_review") else cohort
        body = SYNTHETIC_PRODUCT_SOURCE
        digest = hashlib.sha256(body).hexdigest()
        anchors = tuple(RawRequirementAnchor(text, body.index(text.encode()), len(text), digest)
                        for text in ("product service", "reliable engineering", "technology"))
        frozen = SimpleNamespace(
            synthetic_fixture_id=network.SYNTHETIC_FIXTURE_ID,
            candidate_profile_id=network.SYNTHETIC_PROFILE_ID,
            job_key=cohort.GRAPHCORE_JOB_KEY, title="Synthetic Engineer", company="Example",
            vacancy_url="https://jobs.example.test/synthetic", opportunity_score_bp=9000,
            queue_payload={}, raw_response_bytes=body, raw_response_sha256=digest,
            inventory_sha256=digest, inventory_files_sha256=digest, dossier_sha256=digest,
            queue_body_content_sha256=digest, admitted_queue_payload_sha256=digest,
            tracked_seed_payload_sha256=digest, requirement_anchors=anchors,
            dossier={"sources": [{"captured_at": datetime.now(timezone.utc).isoformat()}]},
        )
        # Only captured research and its expected digest are synthetic. The canonical
        # fit builder, SQLite transitions, compiler, release gate and browser all run.
        with monkeypatch.context() as synthetic_research:
            synthetic_research.setattr(builder, "_FrozenCorpusResearch", lambda cache, authority: _CapturedResearch(cache))
            synthetic_research.setattr(builder, "RAW_RESPONSE_SHA256", digest)
            inputs = (network._issued_release_inputs(tmp_path, cohort.ROOT, frozen)
                      if release_builder in ("network_fit", "network_live_review") else cohort._release_inputs(tmp_path, frozen))
        source = inputs[4] if release_builder in ("network_fit", "network_live_review") else inputs[3]
    else:
        # Substitute only frozen-corpus ingestion with a real synthetic fit database.
        # Compilation, PDFs, publication, release issuance and browser execution are real.
        from types import SimpleNamespace
        from test_jaa06_independent_acceptance import _fit_database
        from career_automation.gap_optimizer import FitAssessmentStore
        captured = []
        assess = FitAssessmentStore.assess

        def record_requirements(self, **kwargs):
            captured.extend(kwargs["requirements"])
            return assess(self, **kwargs)

        with monkeypatch.context() as capture:
            capture.setattr(FitAssessmentStore, "assess", record_requirements)
            database, fit, _ = _fit_database(tmp_path, matched=True, claims=(
                ("capability", "Build reliable services.", "capability"),
                ("project", "Deliver tested projects.", "project"),
                ("education", "Study software engineering.", "education"),
            ))
        with database.connection() as connection:
            job = connection.execute("SELECT job_key,title,company FROM pipeline_jobs").fetchone()
        frozen = SimpleNamespace(job_key=job["job_key"], title=job["title"], company=job["company"])
        with monkeypatch.context() as synthetic_ingestion:
            synthetic_ingestion.setattr(cohort, "_fit_database", lambda root, authority: (database, fit, tuple(captured)))
            inputs = cohort._release_inputs(tmp_path, frozen)
        source = inputs[3]
    vacancy = FixtureVacancy("synthetic-cohort", source.job_key, source.role_title,
                             source.company_name, source.answers[0].question)
    review_receipts = []
    network_review_options = {
        "review_mode": network.SanityReviewMode.OFFLINE,
    }
    if release_builder == "network_live_review":
        from llm.client import LLMClient
        from career_automation.application_sanity_review import review_application_package
        from career_automation.testing_sanity_review import FixturePassBackend

        def live_reviewer(review_package):
            receipt = review_application_package(
                review_package,
                client=LLMClient(
                    backend=FixturePassBackend(),
                    model="scripted-fixture-v1",
                    temperature=0,
                    max_retries=1,
                    cache_enabled=False,
                    cache_dir=tmp_path / "review-cache",
                    usage_log=tmp_path / "review-usage.jsonl",
                ),
            )
            review_receipts.append(receipt)
            return receipt

        network_review_options = {
            "review_mode": network.SanityReviewMode.LIVE,
            "live_reviewer": live_reviewer,
        }
    with LocalATSFixture(vacancy, nonce=lambda: cohort.NONCE, form_token=cohort.FORM_TOKEN) as fixture:
        if release_builder in ("network_fit", "network_live_review"):
            database, workflow, approvals, values, authority, issued = network._browser_inputs(
                fixture, inputs, cohort.ROOT, **network_review_options
            )
        else:
            database, workflow, approvals, values, authority, issued = cohort._browser_inputs(
                fixture, tmp_path, inputs
            )
        if release_builder == "network_live_review":
            assert len(review_receipts) == 1
            assert authority.sanity_review_receipt is review_receipts[0]
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow)
        assert store.claim_run("cohort_worker", run_id=run_id) is not None
        store.authorize_release(run_id, token=issued.release_token,
                                authorization_reference=f"JAA08:{issued.manifest.release_manifest_sha256}",
                                idempotency_key=issued.manifest.release_manifest_sha256)
        executor = LocalBrowserExecutor(store, repository_root=cohort.ROOT,
                                        clock=lambda: authority.consumed_at)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                for action in workflow.actions:
                    assert executor.execute_next(page, run_id=run_id, worker_id="cohort_worker",
                                                 approved_values=approvals, materialized_values=values,
                                                 release_authority=authority) is not None
                assert page.get_by_role("heading", name="Application received").is_visible()
            finally:
                browser.close()
        assert fixture.receipt is not None
        assert store.run_snapshot(run_id)["status"] == "completed"
        assert store.submit_dispatch(run_id)["state"] == "receipt_recorded"
        assert authority.sanity_review_receipt is not None
        assert authority.archive_receipt is not None


def _fixture_review(package, tmp_path):
    from llm.client import LLMClient
    from career_automation.application_sanity_review import review_application_package
    from career_automation.testing_sanity_review import FixturePassBackend

    return review_application_package(
        package,
        client=LLMClient(
            backend=FixturePassBackend(),
            model="scripted-fixture-v1",
            temperature=0,
            max_retries=1,
            cache_enabled=False,
            cache_dir=tmp_path / "review-cache",
            usage_log=tmp_path / "review-usage.jsonl",
        ),
    )


def test_live_review_resolver_invokes_once_and_returns_bound_receipt(tmp_path):
    from test_application_sanity_review import package as build_package

    reviewed_package = build_package()
    calls = []
    receipts = []
    offline_calls = []

    def live_reviewer(package):
        calls.append(package)
        receipt = _fixture_review(package, tmp_path)
        receipts.append(receipt)
        return receipt

    def offline_reviewer(package):
        offline_calls.append(package)
        return _fixture_review(package, tmp_path)

    result = fixture_module._resolve_sanity_review_receipt(
        reviewed_package,
        mode=fixture_module.SanityReviewMode.LIVE,
        live_reviewer=live_reviewer,
        offline_reviewer=offline_reviewer,
    )

    assert calls == [reviewed_package]
    assert calls[0] is reviewed_package
    assert result is receipts[0]
    assert offline_calls == []


def test_live_review_failure_never_falls_back_to_offline(tmp_path):
    from test_application_sanity_review import package as build_package

    reviewed_package = build_package()
    failure = RuntimeError("synthetic reviewer failure")
    live_calls = []
    offline_calls = []

    def live_reviewer(package):
        live_calls.append(package)
        raise failure

    def offline_reviewer(package):
        offline_calls.append(package)
        return _fixture_review(package, tmp_path)

    with pytest.raises(RuntimeError) as raised:
        fixture_module._resolve_sanity_review_receipt(
            reviewed_package,
            mode=fixture_module.SanityReviewMode.LIVE,
            live_reviewer=live_reviewer,
            offline_reviewer=offline_reviewer,
        )

    assert raised.value is failure
    assert live_calls == [reviewed_package]
    assert offline_calls == []


def test_live_review_missing_or_empty_result_fails_closed(tmp_path):
    from test_application_sanity_review import package as build_package

    reviewed_package = build_package()
    offline_calls = []

    def offline_reviewer(package):
        offline_calls.append(package)
        return _fixture_review(package, tmp_path)

    with pytest.raises(RuntimeError, match="live sanity reviewer is required"):
        fixture_module._resolve_sanity_review_receipt(
            reviewed_package,
            mode=fixture_module.SanityReviewMode.LIVE,
            live_reviewer=None,
            offline_reviewer=offline_reviewer,
        )

    with pytest.raises(RuntimeError, match="returned no receipt"):
        fixture_module._resolve_sanity_review_receipt(
            reviewed_package,
            mode=fixture_module.SanityReviewMode.LIVE,
            live_reviewer=lambda _package: None,
            offline_reviewer=offline_reviewer,
        )

    assert offline_calls == []


def test_live_review_rejects_receipt_bound_to_another_package(tmp_path):
    from test_application_sanity_review import package as build_package

    reviewed_package = build_package()
    other_package = build_package(letter="A different synthetic application.")
    receipt = _fixture_review(reviewed_package, tmp_path)
    offline_calls = []

    def offline_reviewer(package):
        offline_calls.append(package)
        return _fixture_review(package, tmp_path)

    with pytest.raises(ValueError, match="differs from its sanity-review receipt"):
        fixture_module._resolve_sanity_review_receipt(
            other_package,
            mode=fixture_module.SanityReviewMode.LIVE,
            live_reviewer=lambda _package: receipt,
            offline_reviewer=offline_reviewer,
        )

    assert offline_calls == []


def test_offline_mode_selects_only_its_explicit_reviewer(tmp_path):
    from test_application_sanity_review import package as build_package

    reviewed_package = build_package()
    live_calls = []
    offline_calls = []
    receipts = []

    def live_reviewer(package):
        live_calls.append(package)
        return _fixture_review(package, tmp_path)

    def offline_reviewer(package):
        offline_calls.append(package)
        receipt = _fixture_review(package, tmp_path)
        receipts.append(receipt)
        return receipt

    result = fixture_module._resolve_sanity_review_receipt(
        reviewed_package,
        mode=fixture_module.SanityReviewMode.OFFLINE,
        live_reviewer=live_reviewer,
        offline_reviewer=offline_reviewer,
    )

    assert result is receipts[0]
    assert live_calls == []
    assert offline_calls == [reviewed_package]
