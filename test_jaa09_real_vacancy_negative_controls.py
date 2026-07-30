"""Negative controls for the exact JAA-04 authority used by JAA-09."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

from career_automation.ats_fixture import FixtureVacancy, LocalATSFixture
from career_automation.browser_executor import (
    LocalBrowserBoundaryError,
    LocalBrowserExecutor,
)
from career_automation.browser_workflows import (
    ActionKind,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    ReleaseGateError,
)
from career_automation.jaa04_corpus_authority import (
    ADMITTED_QUEUE_PAYLOAD_SHA256,
    CORPUS_DIRECTORY,
    GRAPHCORE_COMPANY,
    GRAPHCORE_JOB_KEY,
    GRAPHCORE_TITLE,
    GRAPHCORE_URL,
    LINEAGE_FILES,
    QUEUE_BODY_CONTENT_SHA256,
    TRACKED_SEED_PAYLOAD_SHA256,
    CorpusAuthorityError,
    _validate_hash_domains,
    _validate_vacancy_identity,
    verify_graphcore_corpus,
)
from career_automation.jaa09_real_vacancy_certifier import (
    RealVacancyReceiptError,
    validate_real_vacancy_receipt,
    write_real_vacancy_receipt,
)
from test_jaa09_independent_acceptance import (
    FORM_TOKEN,
    NONCE,
    _released_browser_inputs,
)
from test_jaa09_real_vacancy_acceptance import (
    _real_issued_release_inputs,
    _write_evidence_receipt_if_requested,
)


ROOT = Path(__file__).resolve().parent
CERTIFIED_CORPUS = Path(
    "/home/gutua/software-factory/.control/jaa-12h-supervisor-20260727/"
    "runtime/.jaa04-corpus-v3-a4f4490-releases/"
    "sha256-f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258"
)
TRACKED_SEED = ROOT / "career_automation/fixtures/jaa04_admitted_queue.json"


def _lineage_copy(tmp_path: Path) -> Path:
    root = tmp_path / CORPUS_DIRECTORY
    root.mkdir(parents=True)
    shutil.copy2(
        CERTIFIED_CORPUS / "corpus_inventory.json",
        root / "corpus_inventory.json",
    )
    for relative in LINEAGE_FILES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CERTIFIED_CORPUS / relative, target)
    return root


def _queue_record() -> dict[str, object]:
    return {
        "job_key": GRAPHCORE_JOB_KEY,
        "company": GRAPHCORE_COMPANY,
        "title": GRAPHCORE_TITLE,
        "url": GRAPHCORE_URL,
        "payload_hash": ADMITTED_QUEUE_PAYLOAD_SHA256,
        "content_sha256": QUEUE_BODY_CONTENT_SHA256,
        "opportunity0_decision": {
            "decision": "pass",
            "score_bp": 8425,
        },
    }


def _manifest_record() -> dict[str, object]:
    return {
        "job_key": GRAPHCORE_JOB_KEY,
        "company": GRAPHCORE_COMPANY,
        "role": GRAPHCORE_TITLE,
        "vacancy_url": GRAPHCORE_URL,
        "admitted_payload_hash": ADMITTED_QUEUE_PAYLOAD_SHA256,
    }


def _valid_receipt() -> dict[str, object]:
    digest = "a" * 64
    return {
        "schema_version": "jaa09.real-vacancy-local-receipt.v1",
        "created_at": "2026-07-30T12:00:00+00:00",
        "certifies_slice": False,
        "corpus_binding": {
            "corpus_root": str(CERTIFIED_CORPUS),
            "corpus_inventory_sha256": (
                "f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258"
            ),
            "files_hash": (
                "e3c155f02a76b150334f1efa555f727b20a9bb7520dbb6e69e8ecb53ed95c726"
            ),
            "official_response_sha256": (
                "49097938daa0a352cbbf6e26de54c355dcc0090060e1fd2fde2288a32d26a061"
            ),
            "official_response_size": 27_826,
            "official_response_mode": "0444",
            "dossier_sha256": (
                "bf8692e5977cf20f18b2fe7ba3a19f29678a21c4b428dd91cf937ac580b8da4a"
            ),
            "queue_content_sha256": QUEUE_BODY_CONTENT_SHA256,
            "queue_payload_hash": ADMITTED_QUEUE_PAYLOAD_SHA256,
            "tracked_seed_payload_hash": TRACKED_SEED_PAYLOAD_SHA256,
            "hash_domains": {
                "queue_content_sha256": "normalized-vacancy-body-utf8",
                "queue_payload_hash": "admitted-queue-record",
                "tracked_seed_payload_hash": "repo-tracked-seed-record",
            },
        },
        "vacancy_identity": {
            "job_key": GRAPHCORE_JOB_KEY,
            "company": GRAPHCORE_COMPANY,
            "title": GRAPHCORE_TITLE,
            "url": GRAPHCORE_URL,
            "observed_at": "2026-07-27T15:42:25.937720+00:00",
            "opportunity0_score_bp": 8425,
            "opportunity1_reassessment": "no_changes",
        },
        "candidate_boundary": {
            "candidate_projection": "fixture",
            "projection_content_sha256": digest,
            "disclosure": (
                "deterministic approved fixture candidate projection; "
                "not a real person"
            ),
        },
        "release_binding": {
            "release_manifest_sha256": digest,
            "release_token_sha256": digest,
            "application_source_sha256": digest,
            "vacancy_sha256": digest,
            "artifact_set_sha256": digest,
            "artifact_receipt_sha256": digest,
        },
        "browser_evidence": {
            "workflow_sha256": digest,
            "run_id": "run-fixture",
            "receipt_id": digest,
            "receipt_payload_sha256": digest,
            "screenshot_sha256": digest,
            "field_map_sha256": digest,
            "submit_event_sha256": digest,
            "submit_count": 1,
            "non_loopback_requests": 0,
        },
        "source_environment": {
            "source_git_revision": "b" * 40,
            "source_tree": "c" * 40,
            "source_content_revision": f"sha256:{digest}",
            "interpreter_path": str(ROOT / ".venv/bin/python"),
            "implementation": "CPython",
            "python_version": "3.12.13",
            "playwright_version": "1.61.0",
            "chromium_version": "149.0.7827.55",
            "platform": "test-platform",
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


def test_missing_certified_corpus_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(CorpusAuthorityError, match="unavailable"):
        verify_graphcore_corpus(tmp_path / CORPUS_DIRECTORY, TRACKED_SEED)


def test_wrong_self_address_or_inventory_identity_fails_closed(
    tmp_path: Path,
) -> None:
    root = _lineage_copy(tmp_path)
    wrong_name = tmp_path / f"{CORPUS_DIRECTORY}-substituted"
    root.rename(wrong_name)
    with pytest.raises(CorpusAuthorityError, match="directory identity"):
        verify_graphcore_corpus(wrong_name, TRACKED_SEED)

    root = _lineage_copy(tmp_path / "second")
    inventory = json.loads((root / "corpus_inventory.json").read_bytes())
    inventory["files_hash"] = "0" * 64
    (root / "corpus_inventory.json").write_text(
        json.dumps(inventory),
        encoding="utf-8",
    )
    with pytest.raises(CorpusAuthorityError, match="inventory identity"):
        verify_graphcore_corpus(root, TRACKED_SEED)


@pytest.mark.parametrize("relative", tuple(LINEAGE_FILES))
def test_missing_lineage_file_fails_closed(
    tmp_path: Path,
    relative: str,
) -> None:
    root = _lineage_copy(tmp_path)
    (root / relative).unlink()
    with pytest.raises(CorpusAuthorityError, match="unavailable"):
        verify_graphcore_corpus(root, TRACKED_SEED)


@pytest.mark.parametrize(
    "relative",
    (
        "research_manifest.json",
        "frozen_dossiers.json",
        "admission/queue_snapshot.json",
        next(path for path in LINEAGE_FILES if path.startswith("raw/")),
    ),
)
def test_changed_lineage_bytes_fail_before_projection(
    tmp_path: Path,
    relative: str,
) -> None:
    root = _lineage_copy(tmp_path)
    target = root / relative
    target.chmod(0o644)
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(CorpusAuthorityError, match="lineage bytes"):
        verify_graphcore_corpus(root, TRACKED_SEED)


@pytest.mark.parametrize(
    "relative",
    tuple(path for path in LINEAGE_FILES if path.startswith("raw/")),
)
def test_raw_capture_must_remain_read_only(
    tmp_path: Path,
    relative: str,
) -> None:
    root = _lineage_copy(tmp_path)
    raw = root / relative
    raw.chmod(0o644)
    with pytest.raises(CorpusAuthorityError, match="mode must be 0444"):
        verify_graphcore_corpus(root, TRACKED_SEED)


@pytest.mark.parametrize(
    ("target", "field", "substitute"),
    (
        ("seed", "payload_hash", ADMITTED_QUEUE_PAYLOAD_SHA256),
        ("queue", "payload_hash", TRACKED_SEED_PAYLOAD_SHA256),
        ("queue", "content_sha256", ADMITTED_QUEUE_PAYLOAD_SHA256),
        ("manifest", "admitted_payload_hash", QUEUE_BODY_CONTENT_SHA256),
    ),
)
def test_hash_domain_substitution_is_rejected(
    target: str,
    field: str,
    substitute: str,
) -> None:
    queue = _queue_record()
    manifest = _manifest_record()
    seed: dict[str, object] = {
        "job_key": GRAPHCORE_JOB_KEY,
        "payload_hash": TRACKED_SEED_PAYLOAD_SHA256,
    }
    {"seed": seed, "queue": queue, "manifest": manifest}[target][field] = substitute
    with pytest.raises(CorpusAuthorityError, match="hash mismatch"):
        _validate_hash_domains(queue, manifest, seed)


@pytest.mark.parametrize(
    ("target", "field", "substitute"),
    (
        ("queue", "company", "Substitute Employer"),
        ("queue", "title", "Substitute Role"),
        ("queue", "url", "https://example.test/substitute"),
        ("manifest", "company", "Substitute Employer"),
        ("manifest", "role", "Substitute Role"),
        ("manifest", "vacancy_url", "https://example.test/substitute"),
    ),
)
def test_vacancy_identity_substitution_is_rejected(
    target: str,
    field: str,
    substitute: str,
) -> None:
    queue = _queue_record()
    manifest = _manifest_record()
    {"queue": queue, "manifest": manifest}[target][field] = substitute
    with pytest.raises(CorpusAuthorityError, match="vacancy identity"):
        _validate_vacancy_identity(queue, manifest)


def test_truncated_dossier_hash_is_rejected_by_receipt_contract() -> None:
    receipt = _valid_receipt()
    corpus = receipt["corpus_binding"]
    assert isinstance(corpus, dict)
    corpus["dossier_sha256"] = (
        "bf8692e5977cf20f18b2fe7ba3a19f29678a21c4b428dd91cf937ac580b8da4"
    )
    with pytest.raises(RealVacancyReceiptError, match="corpus binding"):
        validate_real_vacancy_receipt(receipt)


def test_receipt_writer_freezes_exact_non_certifying_bytes(
    tmp_path: Path,
) -> None:
    target = write_real_vacancy_receipt(_valid_receipt(), tmp_path)
    assert target.stat().st_mode & 0o777 == 0o444
    assert write_real_vacancy_receipt(_valid_receipt(), tmp_path) == target


def test_receipt_contract_rejects_pii_fields() -> None:
    receipt = _valid_receipt()
    receipt["email"] = "fixture@example.test"
    with pytest.raises(RealVacancyReceiptError, match="PII"):
        validate_real_vacancy_receipt(receipt)


def test_incomplete_receipt_environment_has_an_explicit_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JAA09_EVIDENCE_CONTROL_ROOT", str(tmp_path))
    for name in (
        "JAA09_SOURCE_GIT_REVISION",
        "JAA09_SOURCE_TREE",
        "JAA09_SOURCE_CONTENT_REVISION",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="environment is incomplete"):
        _write_evidence_receipt_if_requested(
            authority=object(),  # type: ignore[arg-type]
            release_inputs=(),
            workflow=object(),
            run_id="not-reached",
            fixture_receipt=object(),
            outputs={},
            chromium_version="not-reached",
            submit_count=0,
            non_loopback_requests=0,
        )


def test_verified_real_vacancy_path_still_refuses_external_navigation(
    tmp_path: Path,
) -> None:
    authority = verify_graphcore_corpus(CERTIFIED_CORPUS, TRACKED_SEED)
    vacancy = FixtureVacancy(
        "graphcore-external-refusal",
        authority.job_key,
        authority.title,
        authority.company,
    )
    workflow = BrowserWorkflow(
        "graphcore_external_navigation_control",
        (
            BrowserAction(
                "open",
                ActionKind.NAVIGATE,
                target_url="https://external.example/apply",
            ),
        ),
    )
    with LocalATSFixture(
        vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        store = BrowserWorkflowStore(tmp_path / "external.sqlite3")
        run_id = store.create_run(workflow)
        assert store.claim_run(
            "jaa09-real-vacancy-worker",
            run_id=run_id,
        ) is not None
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            with pytest.raises(LocalBrowserBoundaryError, match="not loopback"):
                LocalBrowserExecutor(
                    store,
                    repository_root=ROOT,
                ).execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa09-real-vacancy-worker",
                )
            browser.close()
        assert fixture.receipt is None
        assert store.run_snapshot(run_id)["checkpoint_count"] == 0


def test_tampered_jaa08_token_on_real_vacancy_produces_no_receipt(
    tmp_path: Path,
) -> None:
    authority = verify_graphcore_corpus(CERTIFIED_CORPUS, TRACKED_SEED)
    release_inputs = _real_issued_release_inputs(tmp_path, authority)
    vacancy = FixtureVacancy(
        "graphcore-invalid-token",
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
            _issued,
        ) = _released_browser_inputs(
            fixture,
            tmp_path,
            release_inputs,
        )
        replacement = "0" if execution_authority.release_token[-1] != "0" else "1"
        invalid_token = execution_authority.release_token[:-1] + replacement
        invalid_authority = replace(
            execution_authority,
            release_token=invalid_token,
        )
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow)
        assert store.claim_run(
            "jaa09-real-vacancy-worker",
            run_id=run_id,
        ) is not None
        store.authorize_release(
            run_id,
            token=invalid_token,
            authorization_reference="JAA08:REAL_VACANCY_INVALID_TOKEN",
            idempotency_key="jaa09-real-vacancy-invalid-token",
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
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
                    release_authority=invalid_authority,
                )
            with pytest.raises(ReleaseGateError, match="not issued"):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa09-real-vacancy-worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=invalid_authority,
                )
            browser.close()
        assert fixture.receipt is None
        assert store.submit_dispatch(run_id) is None


def test_consumed_jaa08_token_cannot_submit_real_vacancy_twice(
    tmp_path: Path,
) -> None:
    authority = verify_graphcore_corpus(CERTIFIED_CORPUS, TRACKED_SEED)
    release_inputs = _real_issued_release_inputs(tmp_path, authority)
    first_vacancy = FixtureVacancy(
        "graphcore-token-first",
        authority.job_key,
        authority.title,
        authority.company,
        authority.requirement_anchors[0].text,
    )
    with LocalATSFixture(
        first_vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as first_fixture:
        (
            database,
            first_workflow,
            first_approvals,
            first_values,
            first_authority,
            issued,
        ) = _released_browser_inputs(
            first_fixture,
            tmp_path,
            release_inputs,
        )
        first_store = BrowserWorkflowStore(database.path)
        first_run = first_store.create_run(first_workflow)
        assert first_store.claim_run(
            "jaa09-real-vacancy-worker",
            run_id=first_run,
        ) is not None
        first_store.authorize_release(
            first_run,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key="jaa09-real-vacancy-first-consumption",
        )
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            executor = LocalBrowserExecutor(first_store, repository_root=ROOT)
            for _action in first_workflow.actions:
                executor.execute_next(
                    page,
                    run_id=first_run,
                    worker_id="jaa09-real-vacancy-worker",
                    approved_values=first_approvals,
                    materialized_values=first_values,
                    release_authority=first_authority,
                )
            browser.close()
        assert first_fixture.receipt is not None

    second_vacancy = FixtureVacancy(
        "graphcore-token-second",
        authority.job_key,
        authority.title,
        authority.company,
        authority.requirement_anchors[0].text,
    )
    with LocalATSFixture(
        second_vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as second_fixture:
        (
            database,
            second_workflow,
            second_approvals,
            second_values,
            second_authority,
            issued,
        ) = _released_browser_inputs(
            second_fixture,
            tmp_path,
            release_inputs,
        )
        second_store = BrowserWorkflowStore(database.path)
        second_run = second_store.create_run(
            second_workflow,
            idempotency_key="jaa09-real-vacancy-second-run",
        )
        assert second_store.claim_run(
            "jaa09-real-vacancy-worker",
            run_id=second_run,
        ) is not None
        second_store.authorize_release(
            second_run,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key="jaa09-real-vacancy-second-consumption",
        )
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            executor = LocalBrowserExecutor(second_store, repository_root=ROOT)
            for _action in second_workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=second_run,
                    worker_id="jaa09-real-vacancy-worker",
                    approved_values=second_approvals,
                    materialized_values=second_values,
                    release_authority=second_authority,
                )
            with pytest.raises(ReleaseGateError):
                executor.execute_next(
                    page,
                    run_id=second_run,
                    worker_id="jaa09-real-vacancy-worker",
                    approved_values=second_approvals,
                    materialized_values=second_values,
                    release_authority=second_authority,
                )
            browser.close()
        assert second_fixture.receipt is None
        assert not any(
            event["event_type"] == "submit_click_started"
            for event in second_store.events(second_run)
        )
