from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from career_automation.application_archive import (
    RELEASE_REQUIRED_ROLES,
    REVIEW_REQUIRED_ROLES,
    ApplicationArchive,
    ApplicationArchiveError,
    ApplicationArchiveReceipt,
    VacancyArchiveIdentity,
    export_application_packet,
    verify_application_archive_receipt,
    verify_complete_attempt,
)


ATTEMPT_ID = "jaa-20260805T220000Z-0123456789abcdef"


def _review_preparation(tmp_path, *, forensic_method="GET", begin=True):
    from types import SimpleNamespace
    from career_automation.production_attempt import GreenhouseAttemptRecorder, ProductionIdentity
    from career_automation.production_runner import PreparedGreenhouseReview
    from career_automation.application_sanity_review import review_application_package
    from career_automation.external_document_assurance import assert_application_artifacts
    from form_filling.ats_forensics import ATSForensicRecorder, runtime_fingerprint
    from test_application_sanity_review import package, client, ScriptedBackend, PASS

    reviewed = package(fields=(("cover_note", "Cover note", ""),))
    repository, root = _roots(tmp_path)
    vacancy = VacancyArchiveIdentity(
        reviewed.intended_vacancy.job_key, reviewed.intended_vacancy.vacancy_sha256,
        reviewed.intended_vacancy.role_title, reviewed.intended_vacancy.company_name,
        "https://job-boards.greenhouse.io/example/jobs/123",
    )
    recorder = GreenhouseAttemptRecorder.create(
        archive_root=root, repository_root=repository, vacancy=vacancy,
        complete_vacancy=b"vacancy", structured_vacancy={}, assessment={},
    )
    if begin:
        recorder.begin_review_only()
    recorder._add("browser.prefill_snapshot", b"{}", "application/json")
    recorder._add("vacancy.visible_listing_capture", reviewed.vacancy_review_material.visible_listing_text_bytes, "text/plain", disposition="observed")
    source = SimpleNamespace(
        source_id=reviewed.application_source_identity,
        job_key=vacancy.job_key, vacancy_sha256=vacancy.vacancy_sha256,
        role_title=vacancy.role_title, company_name=vacancy.company_name,
        document=lambda: {"source_id": reviewed.application_source_identity},
        facts=(SimpleNamespace(fact_kind="candidate", authority=SimpleNamespace(
            candidate_claim_id="CLAIM-1", candidate_claim_version=1,
            candidate_evidence_id="EVIDENCE-1", candidate_evidence_version=1,
        )),),
    )
    artifacts = SimpleNamespace(
        artifact_set_sha256="a" * 64,
        cv_pdf=SimpleNamespace(pdf_bytes=reviewed.cv_pdf_bytes),
        cover_letter_pdf=SimpleNamespace(pdf_bytes=reviewed.cover_letter_pdf_bytes),
        editable=SimpleNamespace(answers_text=""),
    )
    forensics = ATSForensicRecorder(
        root / "passive-forensics", attempt_id=recorder.attempt.attempt_id,
        application_id="123", application_url=vacancy.source_url, ats_name="greenhouse",
        artifact_set_sha256=artifacts.artifact_set_sha256,
        runtime=runtime_fingerprint(browser_name="synthetic", browser_version="1", headless=True, user_agent="synthetic"),
    )
    forensics.record_checkpoint("greenhouse_preflight_inventory", inventory_sha256="b" * 64, boundary_signal_count=0, passive_inventory=True)
    forensics.record_request(method=forensic_method, url=vacancy.source_url,
                             resource_type="document", headers={}, post_data=None)
    forensics.record_screenshot(b"synthetic screenshot", label="preflight")
    receipt = forensics.finalize(outcome="prepared")
    prepared = PreparedGreenhouseReview(
        source, artifacts,
        assert_application_artifacts(cv_pdf_bytes=reviewed.cv_pdf_bytes,
                                     cover_letter_pdf_bytes=reviewed.cover_letter_pdf_bytes,
                                     answers_text="", intended_vacancy=reviewed.intended_vacancy),
        review_application_package(reviewed, client=client(ScriptedBackend(PASS), tmp_path)),
        ProductionIdentity("c" * 40, "d" * 64, "e" * 64),
        None, reviewed.vacancy_review_material, reviewed.vacancy_requirements,
        forensics.root, receipt,
    )
    return recorder, prepared


def test_review_only_terminal_is_complete_and_immutable(tmp_path):
    recorder, prepared = _review_preparation(tmp_path)
    digest = recorder.finalize_review_only(prepared)
    verified = verify_complete_attempt(recorder.attempt.attempt_id, root=recorder.attempt.archive.root,
                                       repository_root=recorder.attempt.archive.repository_root)
    assert verified["outcome"] == "review_only"
    assert verified["terminal_manifest_sha256"] == digest
    manifest = json.loads((recorder.attempt.path / "terminal-manifest.json").read_bytes())
    assert manifest["mode"] == "review_only"
    for flag in ("submission_attempted", "release_authority", "submission_authority"):
        assert manifest[flag] is False
    assert manifest["release_manifest_sha256"] is None
    assert recorder.attempt.finalize_terminal(outcome="review_only", selected={}) == digest
    with pytest.raises(ApplicationArchiveError):
        recorder.attempt.finalize_release(selected={})
    with pytest.raises(ApplicationArchiveError):
        recorder._add("review.extra", b"extra", "text/plain")


def _resume_review_recorder(recorder):
    from career_automation.production_attempt import GreenhouseAttemptRecorder

    return GreenhouseAttemptRecorder.resume(
        archive_root=recorder.attempt.archive.root,
        repository_root=recorder.attempt.archive.repository_root,
        attempt_id=recorder.attempt.attempt_id,
    )


def _queue_base_recorder(tmp_path):
    from career_automation.production_attempt import GreenhouseAttemptRecorder

    repository, root = _roots(tmp_path)
    return GreenhouseAttemptRecorder.create(
        archive_root=root, repository_root=repository, vacancy=_vacancy(),
        complete_vacancy=b"complete vacancy", structured_vacancy={}, assessment={},
    )


def test_review_only_resume_keeps_exact_intent_and_evidence(tmp_path):
    recorder, _ = _review_preparation(tmp_path)
    original = recorder.attempt._events()
    resumed = _resume_review_recorder(recorder)
    resumed.begin_review_only()
    resumed.begin_review_only()
    resumed._add("browser.prefill_snapshot", b"{}", "application/json")
    assert resumed.attempt.attempt_id == recorder.attempt.attempt_id
    assert resumed.attempt._events() == original
    with pytest.raises(ApplicationArchiveError, match="replay evidence differs"):
        resumed._add("browser.prefill_snapshot", b'{"changed":true}', "application/json")
    assert resumed.attempt._events() == original


@pytest.mark.parametrize("extra", [None, "artifact", "navigation"])
def test_review_only_new_admission_requires_exact_queue_base(tmp_path, extra):
    recorder = _queue_base_recorder(tmp_path)
    if extra == "artifact":
        recorder._add("vacancy.assessment", b"{}", "application/json")
    elif extra == "navigation":
        recorder._record_evidence("navigation", result="completed", details={"method": "GET"})
    original = recorder.attempt._events()
    if extra is None:
        recorder.begin_review_only()
        assert len(recorder.attempt._events()) == len(original) + 1
    else:
        with pytest.raises(ApplicationArchiveError, match="queue-created base"):
            recorder.begin_review_only()
        assert recorder.attempt._events() == original


def test_review_only_cannot_convert_resumed_pristine_live_base(tmp_path):
    recorder = _queue_base_recorder(tmp_path)
    original = recorder.attempt._events()
    with pytest.raises(ApplicationArchiveError, match="no review-only intent"):
        _resume_review_recorder(recorder).begin_review_only()
    assert recorder.attempt._events() == original


@pytest.mark.parametrize("invalid", ["mismatch", "duplicate"])
def test_review_only_resume_refuses_invalid_intent(tmp_path, invalid):
    recorder = _queue_base_recorder(tmp_path)
    if invalid == "mismatch":
        recorder._add("review.intent", b'{"mode":"live"}', "application/json")
    else:
        recorder.begin_review_only()
        intent = recorder.attempt._objects(recorder.attempt._events())[-1]
        recorder._add("review.intent", recorder.attempt.read_artifact(intent), "application/json")
    original = recorder.attempt._events()
    with pytest.raises(ApplicationArchiveError, match="intent"):
        _resume_review_recorder(recorder).begin_review_only()
    assert recorder.attempt._events() == original


@pytest.mark.parametrize("role", ["release.issued", "submission.result", "candidate.gate", "candidate.release_token"])
def test_review_only_resume_refuses_consequential_archive_artifacts(tmp_path, monkeypatch, role):
    import career_automation.application_archive as archive_module

    recorder, _ = _review_preparation(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(archive_module, "_review_event_allowed", lambda *args: None)
        recorder._add(role, b"{}", "application/json")
    original = recorder.attempt._events()
    with pytest.raises(ApplicationArchiveError, match="consequential"):
        _resume_review_recorder(recorder).begin_review_only()
    assert recorder.attempt._events() == original


@pytest.mark.parametrize("kind", ["field_filled", "field_selected", "file_uploaded", "click"])
def test_review_only_resume_refuses_archived_mutation_events(tmp_path, monkeypatch, kind):
    import career_automation.application_archive as archive_module

    recorder, _ = _review_preparation(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(archive_module, "_review_event_allowed", lambda *args: None)
        recorder._record_evidence(kind, result="completed")
    original = recorder.attempt._events()
    with pytest.raises(ApplicationArchiveError, match="mutation"):
        _resume_review_recorder(recorder).begin_review_only()
    assert recorder.attempt._events() == original


@pytest.mark.parametrize("filename", ["terminal-manifest.json", "release-manifest.json", "release-receipt.json", "release-token.json"])
def test_review_only_resume_refuses_terminal_or_release_files(tmp_path, filename):
    recorder, _ = _review_preparation(tmp_path)
    (recorder.attempt.path / filename).write_text("{}")
    original = recorder.attempt._events()
    with pytest.raises(ApplicationArchiveError, match="terminal|release"):
        _resume_review_recorder(recorder).begin_review_only()
    assert recorder.attempt._events() == original


def test_review_only_completed_attempt_cannot_resume(tmp_path):
    recorder, prepared = _review_preparation(tmp_path)
    recorder.finalize_review_only(prepared)
    original = recorder.attempt._events()
    manifest = (recorder.attempt.path / "terminal-manifest.json").read_bytes()
    with pytest.raises(ApplicationArchiveError, match="terminal"):
        _resume_review_recorder(recorder).begin_review_only()
    assert recorder.attempt._events() == original
    assert (recorder.attempt.path / "terminal-manifest.json").read_bytes() == manifest


@pytest.mark.parametrize("interrupted", [False, True])
def test_review_only_semantic_review_is_not_repeated_on_recovery(tmp_path, interrupted):
    from career_automation.application_sanity_review import package_from_application

    recorder, prepared = _review_preparation(tmp_path)
    package = package_from_application(
        source=prepared.source, artifacts=prepared.artifacts, questions=None,
        vacancy_requirements=prepared.vacancy_requirements,
        vacancy_review_material=prepared.vacancy_review_material,
    )
    calls = []

    def review():
        calls.append("review")
        if interrupted:
            raise TimeoutError("synthetic interruption")
        return prepared.sanity_review_receipt

    if interrupted:
        with pytest.raises(TimeoutError):
            recorder.review_once(package, review)
    else:
        assert recorder.review_once(package, review) == prepared.sanity_review_receipt
    original = recorder.attempt._events()
    resumed = _resume_review_recorder(recorder)
    if interrupted:
        with pytest.raises(ValueError, match="second review is forbidden"):
            resumed.review_once(package, review)
    else:
        assert resumed.review_once(package, review) == prepared.sanity_review_receipt
    assert calls == ["review"]
    assert recorder.attempt._events() == original


@pytest.mark.parametrize("kind", ["field_filled", "field_selected", "file_uploaded", "click", "release"])
def test_review_only_refuses_mutation_events(tmp_path, kind):
    recorder, _ = _review_preparation(tmp_path)
    with pytest.raises(ApplicationArchiveError, match="mutation"):
        recorder._record_evidence(kind, result="completed")


@pytest.mark.parametrize("role", ["release.issued", "release.consumed", "submission.click_intent", "browser.upload_mapping"])
def test_review_only_refuses_release_and_submit_artifacts(tmp_path, role):
    recorder, _ = _review_preparation(tmp_path)
    with pytest.raises(ApplicationArchiveError, match="consequential"):
        recorder._add(role, b"{}", "application/json")


def test_review_only_refuses_post_and_nonzero_counts(tmp_path):
    recorder, _ = _review_preparation(tmp_path)
    with pytest.raises(ApplicationArchiveError, match="GET"):
        recorder._record_evidence("request", result="observed", details={"method": "POST"})
    with pytest.raises(ApplicationArchiveError, match="zero"):
        recorder._record_evidence("terminal", result="completed", details={"interaction_counts": {"submit_clicks": 1}})


def test_review_only_requires_all_evidence_and_rejects_pdf_substitution(tmp_path):
    recorder, prepared = _review_preparation(tmp_path)
    recorder._record_evidence("terminal", result="completed")
    with pytest.raises(ApplicationArchiveError, match="missing roles"):
        recorder.attempt.finalize_terminal(outcome="review_only", selected=recorder._selected())
    recorder, prepared = _review_preparation(tmp_path / "substitution")
    prepared.artifacts.cv_pdf.pdf_bytes = prepared.artifacts.cover_letter_pdf.pdf_bytes
    with pytest.raises(ValueError, match="sanity-review"):
        recorder.finalize_review_only(prepared)


@pytest.mark.parametrize("missing", sorted(REVIEW_REQUIRED_ROLES))
def test_review_only_rejects_each_missing_required_member(tmp_path, monkeypatch, missing):
    recorder, prepared = _review_preparation(tmp_path)
    finalize = recorder.attempt.finalize_terminal

    def omit_member(*, outcome, selected, finalized_at):
        return finalize(outcome=outcome, selected={role: digest for role, digest in selected.items() if role != missing}, finalized_at=finalized_at)

    monkeypatch.setattr(recorder.attempt, "finalize_terminal", omit_member)
    with pytest.raises(ApplicationArchiveError, match="missing roles"):
        recorder.finalize_review_only(prepared)
    assert not (recorder.attempt.path / "terminal-manifest.json").exists()


def test_review_only_rejects_post_in_passive_forensics(tmp_path):
    recorder, prepared = _review_preparation(tmp_path, forensic_method="POST")
    with pytest.raises(ApplicationArchiveError, match="must use GET"):
        recorder.finalize_review_only(prepared)
    assert not (recorder.attempt.path / "terminal-manifest.json").exists()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _vacancy(suffix: str = "") -> VacancyArchiveIdentity:
    return VacancyArchiveIdentity(
        job_key=f"job-weakest-eligible{suffix}",
        vacancy_sha256=_sha(f"complete vacancy{suffix}".encode()),
        role_title="Junior Software Engineer",
        company_name="Example Employer",
        source_url="https://jobs.example.test/roles/123",
    )


def _greenhouse_vacancy() -> VacancyArchiveIdentity:
    return VacancyArchiveIdentity(
        job_key="greenhouse:example:1234567",
        vacancy_sha256=_sha(b"complete Greenhouse vacancy"),
        role_title="Junior Software Engineer",
        company_name="Example Employer",
        source_url="https://job-boards.greenhouse.io/example/jobs/1234567",
    )


def _click_intent(vacancy: VacancyArchiveIdentity) -> bytes:
    return (
        json.dumps(
            {
                "provider": "greenhouse",
                "application_url": vacancy.source_url,
                "confirmation_url": vacancy.source_url.rstrip("/") + "/confirmation",
                "release_manifest_sha256": _sha(b"release manifest"),
                "archive_manifest_sha256": _sha(b"archive manifest"),
                "recorded_at": "2026-08-05T22:02:00Z",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def _reconciliation(
    vacancy: VacancyArchiveIdentity,
    *,
    click_intent_sha256: str,
    screenshot_sha256: str,
    visible_text_sha256: str,
    network_evidence_sha256: str,
    outcome: str = "indeterminate",
    success_observed: bool = False,
) -> bytes:
    application_id = vacancy.source_url.rstrip("/").rsplit("/", 1)[-1]
    document = {
        "schema_version": "jaa.submission-reconciliation.v2",
        "provider": "greenhouse",
        "job_key": vacancy.job_key,
        "vacancy_sha256": vacancy.vacancy_sha256,
        "application_url": vacancy.source_url,
        "confirmation_url": vacancy.source_url.rstrip("/") + "/confirmation",
        "click_intent_sha256": click_intent_sha256,
        "network_evidence_sha256": network_evidence_sha256,
        "checked_at": "2026-08-05T22:03:00Z",
        "click_replay_attempted": False,
        "provider_state": {
            "url": (
                vacancy.source_url.rstrip("/") + "/confirmation"
                if success_observed
                else vacancy.source_url
            ),
            "title": "Application status",
            "visible_text_sha256": visible_text_sha256,
            "screenshot_sha256": screenshot_sha256,
            "success_observed": success_observed,
        },
        "confirmation_email": {
            "provider": "gmail",
            "checked": True,
            "schema_version": "jaa.gmail-confirmation-evidence.v1",
            "collector_identity": (
                "jaa.gmail-api-metadata-reconciler.v1+source-sha256:" + "a" * 64
            ),
            "checked_at": "2026-08-05T22:03:00Z",
            "result": "no_match",
            "query": {
                "job_key": vacancy.job_key,
                "application_id": application_id,
                "company_name_sha256": _sha(vacancy.company_name.encode()),
                "role_title_sha256": _sha(vacancy.role_title.encode()),
                "not_before": "2026-08-05T22:02:00Z",
                "not_after": "2026-08-05T22:03:00Z",
            },
            "query_receipt": {
                "schema_version": "jaa.gmail-api-query-receipt.v1",
                "collector_source_sha256": "a" * 64,
                "job_key_sha256": _sha(vacancy.job_key.encode()),
                "application_id_sha256": _sha(application_id.encode()),
                "company_name_sha256": _sha(vacancy.company_name.encode()),
                "role_title_sha256": _sha(vacancy.role_title.encode()),
                "not_before": "2026-08-05T22:02:00+00:00",
                "not_after": "2026-08-05T22:03:00+00:00",
                "events": [
                    {
                        "path": "messages",
                        "parameters_sha256": "b" * 64,
                        "request_url_sha256": "c" * 64,
                        "response_sha256": "d" * 64,
                        "response_byte_length": 16,
                    }
                ],
            },
            "matched_message_metadata": [],
            "match_reasons": [],
        },
        "conclusion": outcome,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    archive = tmp_path / "application-artifacts"
    repository.mkdir(parents=True)
    return repository, archive


def _media_type(role: str) -> str:
    if role.endswith("final_pdf"):
        return "application/pdf"
    if role.endswith("screenshot"):
        return "image/png"
    if role.endswith("text") or role.endswith("source"):
        return "text/plain"
    return "application/json"


def _release_archive(
    tmp_path: Path,
    *,
    vacancy: VacancyArchiveIdentity | None = None,
) -> tuple[ApplicationArchive, object, ApplicationArchiveReceipt, dict[str, str]]:
    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(vacancy or _vacancy(), attempt_id=ATTEMPT_ID)
    rejected = attempt.add_artifact(
        "document.cv.source",
        b"rejected CV revision",
        media_type="text/plain",
        disposition="rejected",
    )
    selected: dict[str, str] = {}
    for role in sorted(RELEASE_REQUIRED_ROLES):
        value = f"approved:{role}".encode()
        if role == "provider.success_semantics":
            value = (
                json.dumps(
                    {
                        "schema_version": "jaa.greenhouse-success-evidence.v1",
                        "observation_sha256": _sha(b"provider observation"),
                        "observed_at": "2026-08-05T22:00:00Z",
                        "confirmation_url": attempt.vacancy.source_url.rstrip("/")
                        + "/confirmation",
                        "required_visible_markers": ["application received"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        if role == "document.cv.source":
            lineage = (rejected.sha256,)
        else:
            lineage = ()
        row = attempt.add_artifact(
            role,
            value,
            media_type=_media_type(role),
            lineage=lineage,
            disposition="approved",
            metadata={"fixture": True, "secret_step_occurred": False},
        )
        selected[role] = row.sha256
    receipt = attempt.finalize_release(
        selected=selected,
        finalized_at="2026-08-05T22:01:00Z",
    )
    return archive, attempt, receipt, selected


def test_complete_attempt_verifies_and_exports_every_revision(tmp_path: Path) -> None:
    archive, _attempt, receipt, selected = _release_archive(tmp_path)
    verified = verify_application_archive_receipt(
        receipt,
        root=archive.root,
        repository_root=archive.repository_root,
        expected_vacancy=_vacancy(),
        expected_selected_sha256=selected,
    )
    assert verified == receipt
    destination = tmp_path / "packet"
    export_application_packet(
        receipt.attempt_id,
        root=archive.root,
        repository_root=archive.repository_root,
        destination=destination,
    )
    exported = tuple((destination / "objects").iterdir())
    assert len(exported) == receipt.object_count
    assert len([path for path in exported if path.name.startswith("document.cv.source")]) == 2
    assert (destination / "release-manifest.json").is_file()


def test_rejected_revision_is_preserved_but_not_selected(tmp_path: Path) -> None:
    archive, attempt, receipt, selected = _release_archive(tmp_path)
    manifest = json.loads((attempt.path / "release-manifest.json").read_text())
    cv_rows = [row for row in manifest["objects"] if row["role"] == "document.cv.source"]
    assert [row["disposition"] for row in cv_rows] == ["rejected", "approved"]
    assert cv_rows[1]["lineage"] == [cv_rows[0]["sha256"]]
    assert manifest["selected"]["document.cv.source"] == cv_rows[1]["sha256"]
    assert manifest["selected"] == selected
    verify_application_archive_receipt(
        receipt, root=archive.root, repository_root=archive.repository_root
    )


@pytest.mark.parametrize(
    "missing_role",
    sorted(RELEASE_REQUIRED_ROLES),
)
def test_every_mandatory_release_role_fails_closed(
    tmp_path: Path, missing_role: str
) -> None:
    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    selected = {}
    for role in sorted(RELEASE_REQUIRED_ROLES - {missing_role}):
        row = attempt.add_artifact(
            role,
            role.encode(),
            media_type=_media_type(role),
            disposition="approved",
        )
        selected[role] = row.sha256
    with pytest.raises(ApplicationArchiveError, match="missing roles"):
        attempt.finalize_release(selected=selected)


def test_wrong_pdf_answer_and_upload_hashes_fail_closed(tmp_path: Path) -> None:
    archive, _attempt, receipt, selected = _release_archive(tmp_path)
    for role in (
        "document.cv.final_pdf",
        "document.cover_letter.final_pdf",
        "form.answers",
        "browser.upload_mapping",
    ):
        expected = dict(selected)
        expected[role] = _sha(f"wrong:{role}".encode())
        with pytest.raises(ApplicationArchiveError, match="selected bytes differ"):
            verify_application_archive_receipt(
                receipt,
                root=archive.root,
                repository_root=archive.repository_root,
                expected_selected_sha256=expected,
            )


def test_wrong_vacancy_fails_closed(tmp_path: Path) -> None:
    archive, _attempt, receipt, _selected = _release_archive(tmp_path)
    with pytest.raises(ApplicationArchiveError, match="wrong vacancy"):
        verify_application_archive_receipt(
            receipt,
            root=archive.root,
            repository_root=archive.repository_root,
            expected_vacancy=_vacancy("-other"),
        )


def test_stale_release_archive_fails_closed(tmp_path: Path) -> None:
    archive, _attempt, receipt, _selected = _release_archive(tmp_path)
    with pytest.raises(ApplicationArchiveError, match="stale"):
        verify_application_archive_receipt(
            receipt,
            root=archive.root,
            repository_root=archive.repository_root,
            verified_at=datetime(2026, 8, 7, 0, 2, tzinfo=timezone.utc),
        )


def test_mutated_object_manifest_receipt_and_event_fail_closed(tmp_path: Path) -> None:
    mutators = ("object", "manifest", "receipt", "event")
    for index, kind in enumerate(mutators):
        case = tmp_path / str(index)
        case.mkdir()
        archive, attempt, receipt, selected = _release_archive(case)
        if kind == "object":
            digest = selected["form.answers"]
            target = archive.root / "objects" / digest[:2] / digest
        elif kind == "manifest":
            target = attempt.path / "release-manifest.json"
        elif kind == "receipt":
            target = attempt.path / "release-receipt.json"
        else:
            target = attempt.path / "events" / "00000002.json"
        target.write_bytes(target.read_bytes() + b"mutation")
        with pytest.raises(ApplicationArchiveError):
            verify_application_archive_receipt(
                receipt, root=archive.root, repository_root=archive.repository_root
            )


def test_forged_receipt_fails_against_durable_receipt(tmp_path: Path) -> None:
    archive, _attempt, receipt, _selected = _release_archive(tmp_path)
    preimage = receipt.document(False)
    preimage["finalized_at"] = "2026-08-05T22:02:00Z"
    forged = ApplicationArchiveReceipt(
        attempt_id=receipt.attempt_id,
        vacancy=receipt.vacancy,
        manifest_relative_path=receipt.manifest_relative_path,
        manifest_sha256=receipt.manifest_sha256,
        event_head_sha256=receipt.event_head_sha256,
        object_count=receipt.object_count,
        finalized_at=str(preimage["finalized_at"]),
        receipt_sha256=_sha((json.dumps(preimage, separators=(",", ":"), sort_keys=True) + "\n").encode()),
    )
    with pytest.raises(ApplicationArchiveError, match="durable receipt"):
        verify_application_archive_receipt(
            forged, root=archive.root, repository_root=archive.repository_root
        )


def test_symlink_roots_objects_and_path_traversal_fail_closed(tmp_path: Path) -> None:
    repository, root = _roots(tmp_path)
    symlink = tmp_path / "archive-link"
    symlink.symlink_to(root, target_is_directory=True)
    with pytest.raises(ApplicationArchiveError, match="symlink"):
        ApplicationArchive(symlink, repository_root=repository)

    archive, attempt, receipt, selected = _release_archive(tmp_path / "object-case")
    digest = selected["form.answers"]
    object_path = archive.root / "objects" / digest[:2] / digest
    original = object_path.read_bytes()
    object_path.unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(original)
    object_path.symlink_to(outside)
    with pytest.raises(ApplicationArchiveError, match="symlink"):
        verify_application_archive_receipt(
            receipt, root=archive.root, repository_root=archive.repository_root
        )
    object_path.unlink()
    object_path.write_bytes(original)

    manifest_path = attempt.path / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["summary"]["relative_path"] = "../outside"
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n")
    forged_document = receipt.document(False)
    forged_document["manifest_sha256"] = _sha(manifest_path.read_bytes())
    forged = ApplicationArchiveReceipt(
        receipt.attempt_id,
        receipt.vacancy,
        receipt.manifest_relative_path,
        str(forged_document["manifest_sha256"]),
        receipt.event_head_sha256,
        receipt.object_count,
        receipt.finalized_at,
        _sha((json.dumps(forged_document, separators=(",", ":"), sort_keys=True) + "\n").encode()),
    )
    (attempt.path / "release-receipt.json").write_text(
        json.dumps(forged.document(), separators=(",", ":"), sort_keys=True) + "\n"
    )
    with pytest.raises(ApplicationArchiveError, match="canonical relative path"):
        verify_application_archive_receipt(
            forged, root=archive.root, repository_root=archive.repository_root
        )


@pytest.mark.parametrize(
    "media_type,value",
    (
        ("text/plain", b"Authorization: Bearer abcdefghijklmnop"),
        ("text/plain", b"Cookie: session=secret-value"),
        ("text/plain", b"-----BEGIN PRIVATE KEY-----\nsecret"),
        ("application/json", b'{"token":"eyJabcdef.ghijklmn.opqrstuv"}'),
    ),
)
def test_secret_values_are_rejected(
    tmp_path: Path, media_type: str, value: bytes
) -> None:
    repository, root = _roots(tmp_path)
    attempt = ApplicationArchive(root, repository_root=repository).create_attempt(
        _vacancy(), attempt_id=ATTEMPT_ID
    )
    with pytest.raises(ApplicationArchiveError, match="secret-like"):
        attempt.add_artifact("technical.boundary", value, media_type=media_type)
    with pytest.raises(ApplicationArchiveError, match="secret-bearing metadata"):
        attempt.add_artifact(
            "technical.boundary",
            b"a secret step occurred",
            media_type="text/plain",
            metadata={"password": "redacted"},
        )


def test_release_receipt_survives_append_only_terminal_extension(tmp_path: Path) -> None:
    archive, attempt, receipt, selected = _release_archive(tmp_path)
    intent = attempt.add_artifact(
        "submission.click_intent",
        _click_intent(_vacancy()),
        media_type="application/json",
    )
    post = attempt.add_artifact(
        "browser.post_submit_screenshot",
        b"post-submit PNG",
        media_type="image/png",
    )
    visible = attempt.add_artifact(
        "browser.post_submit_visible_text",
        b"No confirmation was visible",
        media_type="text/plain",
    )
    network = attempt.add_artifact(
        "browser.redirect_http_evidence",
        b'{"availability":"observed","capture_phase":"after_click_intent",'
        b'"events":[{"method":"GET","redirected_from":null,"status":200,'
        b'"url":"https://jobs.example.test/roles/123/confirmation"}],'
        b'"schema_version":"jaa.browser-http-evidence.v1"}\n',
        media_type="application/json",
    )
    result = attempt.add_artifact(
        "submission.result",
        b'{"state":"indeterminate"}',
        media_type="application/json",
    )
    reconciliation = attempt.add_artifact(
        "submission.reconciliation",
        _reconciliation(
            _vacancy(),
            click_intent_sha256=intent.sha256,
            screenshot_sha256=post.sha256,
            visible_text_sha256=visible.sha256,
            network_evidence_sha256=network.sha256,
        ),
        media_type="application/json",
    )
    terminal_selected = {
        "vacancy.source_identity": selected["vacancy.source_identity"],
        "vacancy.capture": selected["vacancy.capture"],
        "provider.success_semantics": selected["provider.success_semantics"],
        "submission.click_intent": intent.sha256,
        "browser.post_submit_screenshot": post.sha256,
        "browser.post_submit_visible_text": visible.sha256,
        "browser.redirect_http_evidence": network.sha256,
        "submission.reconciliation": reconciliation.sha256,
        "submission.result": result.sha256,
    }
    terminal_hash = attempt.finalize_terminal(
        outcome="indeterminate", selected=terminal_selected
    )
    assert len(terminal_hash) == 64
    verify_application_archive_receipt(
        receipt, root=archive.root, repository_root=archive.repository_root
    )
    assert verify_complete_attempt(
        receipt.attempt_id,
        root=archive.root,
        repository_root=archive.repository_root,
    )["outcome"] == "indeterminate"
    with pytest.raises(ApplicationArchiveError, match="immutable"):
        attempt.add_artifact(
            "submission.result",
            b"retry",
            media_type="application/json",
        )


@pytest.mark.parametrize(
    ("event", "message"),
    (
        (
            {
                "method": "GET",
                "redirected_from": None,
                "status": 200,
                "url": "https://unrelated.example/1234567/confirmation",
            },
            "submit or confirmation action",
        ),
        (
            {
                "method": "POST",
                "redirected_from": None,
                "status": 204,
                "url": (
                    "https://boards.greenhouse.io/example/jobs/"
                    "1234567/analytics"
                ),
            },
            "submit or confirmation action",
        ),
        (
            {
                "method": "GET",
                "redirected_from": None,
                "status": 200,
                "url": "https://job-boards.greenhouse.io/example/jobs/1234567",
            },
            "submit or confirmation action",
        ),
    ),
)
def test_submit_network_rejects_unrelated_host_and_ordinary_vacancy_get(
    tmp_path: Path,
    event: dict[str, object],
    message: str,
) -> None:
    archive, attempt, _receipt, selected = _release_archive(
        tmp_path, vacancy=_greenhouse_vacancy()
    )
    rows = {}
    for role, value, media_type in (
        (
            "submission.click_intent",
            _click_intent(_greenhouse_vacancy()),
            "application/json",
        ),
        ("browser.post_submit_screenshot", b"screenshot", "image/png"),
        ("browser.post_submit_visible_text", b"visible", "text/plain"),
        (
            "browser.redirect_http_evidence",
            (json.dumps(
                {
                    "availability": "observed",
                    "capture_phase": "after_click_intent",
                    "events": [event],
                    "schema_version": "jaa.browser-http-evidence.v1",
                },
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n").encode(),
            "application/json",
        ),
        ("submission.result", b'{"state":"indeterminate"}\n', "application/json"),
    ):
        rows[role] = attempt.add_artifact(role, value, media_type=media_type)
    terminal_selected = {
        "vacancy.source_identity": selected["vacancy.source_identity"],
        "vacancy.capture": selected["vacancy.capture"],
        "provider.success_semantics": selected["provider.success_semantics"],
        **{role: row.sha256 for role, row in rows.items()},
    }
    reconciliation = attempt.add_artifact(
        "submission.reconciliation",
        _reconciliation(
            _greenhouse_vacancy(),
            click_intent_sha256=rows["submission.click_intent"].sha256,
            screenshot_sha256=rows["browser.post_submit_screenshot"].sha256,
            visible_text_sha256=rows["browser.post_submit_visible_text"].sha256,
            network_evidence_sha256=rows["browser.redirect_http_evidence"].sha256,
        ),
        media_type="application/json",
    )
    terminal_selected["submission.reconciliation"] = reconciliation.sha256
    with pytest.raises(ApplicationArchiveError, match=message):
        attempt.finalize_terminal(
            outcome="indeterminate", selected=terminal_selected
        )
    assert not (attempt.path / "terminal-manifest.json").exists()
    assert archive.root.is_dir()


def test_empty_submit_network_requires_explicit_reconciliation(tmp_path: Path) -> None:
    _archive, attempt, _receipt, selected = _release_archive(
        tmp_path, vacancy=_greenhouse_vacancy()
    )
    rows = {}
    for role, value, media_type in (
        (
            "submission.click_intent",
            _click_intent(_greenhouse_vacancy()),
            "application/json",
        ),
        ("browser.post_submit_screenshot", b"screenshot", "image/png"),
        ("browser.post_submit_visible_text", b"visible", "text/plain"),
        (
            "browser.redirect_http_evidence",
            b'{"availability":"no_response_event_observed_after_listener_started",'
            b'"capture_phase":"after_click_intent","events":[],'
            b'"schema_version":"jaa.browser-http-evidence.v1"}\n',
            "application/json",
        ),
        ("submission.result", b'{"state":"indeterminate"}\n', "application/json"),
    ):
        rows[role] = attempt.add_artifact(role, value, media_type=media_type)
    with pytest.raises(ApplicationArchiveError, match="submission.reconciliation"):
        attempt.finalize_terminal(
            outcome="indeterminate",
            selected={
                "vacancy.source_identity": selected["vacancy.source_identity"],
                "vacancy.capture": selected["vacancy.capture"],
                "provider.success_semantics": selected[
                    "provider.success_semantics"
                ],
                **{role: row.sha256 for role, row in rows.items()},
            },
        )


def test_nonempty_submit_network_still_requires_reconciliation(tmp_path: Path) -> None:
    _archive, attempt, _receipt, selected = _release_archive(
        tmp_path, vacancy=_greenhouse_vacancy()
    )
    rows = {}
    for role, value, media_type in (
        (
            "submission.click_intent",
            _click_intent(_greenhouse_vacancy()),
            "application/json",
        ),
        ("browser.post_submit_screenshot", b"screenshot", "image/png"),
        ("browser.post_submit_visible_text", b"visible", "text/plain"),
        (
            "browser.redirect_http_evidence",
            b'{"availability":"observed","capture_phase":"after_click_intent",'
            b'"events":[{"method":"POST","redirected_from":null,"status":200,'
            b'"url":"https://boards.greenhouse.io/example/jobs/1234567"}],'
            b'"schema_version":"jaa.browser-http-evidence.v1"}\n',
            "application/json",
        ),
        ("submission.result", b'{"state":"indeterminate"}\n', "application/json"),
    ):
        rows[role] = attempt.add_artifact(role, value, media_type=media_type)
    with pytest.raises(ApplicationArchiveError, match="submission.reconciliation"):
        attempt.finalize_terminal(
            outcome="indeterminate",
            selected={
                "vacancy.source_identity": selected["vacancy.source_identity"],
                "vacancy.capture": selected["vacancy.capture"],
                "provider.success_semantics": selected[
                    "provider.success_semantics"
                ],
                **{role: row.sha256 for role, row in rows.items()},
            },
        )


@pytest.mark.parametrize("mismatch", ("screenshot", "visible", "network"))
def test_reconciliation_is_bound_to_exact_archived_provider_evidence(
    tmp_path: Path, mismatch: str
) -> None:
    _archive, attempt, _receipt, selected = _release_archive(
        tmp_path, vacancy=_greenhouse_vacancy()
    )
    intent = attempt.add_artifact(
        "submission.click_intent",
        _click_intent(_greenhouse_vacancy()),
        media_type="application/json",
    )
    screenshot = attempt.add_artifact(
        "browser.post_submit_screenshot", b"screenshot", media_type="image/png"
    )
    visible = attempt.add_artifact(
        "browser.post_submit_visible_text", b"visible", media_type="text/plain"
    )
    network = attempt.add_artifact(
        "browser.redirect_http_evidence",
        b'{"availability":"observed","capture_phase":"after_click_intent",'
        b'"events":[{"method":"POST","redirected_from":null,"status":200,'
        b'"url":"https://boards.greenhouse.io/example/jobs/1234567"}],'
        b'"schema_version":"jaa.browser-http-evidence.v1"}\n',
        media_type="application/json",
    )
    hashes = {
        "screenshot": screenshot.sha256,
        "visible": visible.sha256,
        "network": network.sha256,
    }
    hashes[mismatch] = "f" * 64
    reconciliation = attempt.add_artifact(
        "submission.reconciliation",
        _reconciliation(
            _greenhouse_vacancy(),
            click_intent_sha256=intent.sha256,
            screenshot_sha256=hashes["screenshot"],
            visible_text_sha256=hashes["visible"],
            network_evidence_sha256=hashes["network"],
        ),
        media_type="application/json",
    )
    result = attempt.add_artifact(
        "submission.result", b'{"state":"indeterminate"}\n', media_type="application/json"
    )
    with pytest.raises(ApplicationArchiveError):
        attempt.finalize_terminal(
            outcome="indeterminate",
            selected={
                "vacancy.source_identity": selected["vacancy.source_identity"],
                "vacancy.capture": selected["vacancy.capture"],
                "provider.success_semantics": selected[
                    "provider.success_semantics"
                ],
                "submission.click_intent": intent.sha256,
                "browser.post_submit_screenshot": screenshot.sha256,
                "browser.post_submit_visible_text": visible.sha256,
                "browser.redirect_http_evidence": network.sha256,
                "submission.reconciliation": reconciliation.sha256,
                "submission.result": result.sha256,
            },
        )


def test_blocked_attempt_finalizes_without_release_authority(tmp_path: Path) -> None:
    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    selected = {}
    for role, value in (
        ("vacancy.source_identity", b"source"),
        ("vacancy.capture", b"capture"),
        ("technical.boundary", b'{"kind":"captcha","secret_value":null}'),
        ("submission.result", b'{"state":"blocked"}'),
        ("browser.blocked_screenshot", b"blocked screenshot"),
        ("browser.blocked_visible_text", b"captcha visible"),
        ("browser.blocked_state_evidence", b'{"state":"captcha"}'),
        (
            "browser.redirect_http_evidence",
            b'{"availability":"listener_not_started_before_boundary",'
            b'"events":[],"schema_version":"jaa.browser-http-evidence.v1"}\n',
        ),
    ):
        row = attempt.add_artifact(
            role,
            value,
            media_type="application/json",
            metadata={"secret_step_occurred": role == "technical.boundary"},
        )
        selected[role] = row.sha256
    attempt.finalize_terminal(outcome="blocked", selected=selected)
    assert not (attempt.path / "release-receipt.json").exists()
    assert json.loads((attempt.path / "terminal-manifest.json").read_text())["outcome"] == "blocked"
    verification = verify_complete_attempt(
        attempt.attempt_id,
        root=archive.root,
        repository_root=archive.repository_root,
    )
    assert verification["outcome"] == "blocked"
    assert verification["release_manifest_sha256"] is None
    destination = tmp_path / "blocked-packet"
    export_application_packet(
        attempt.attempt_id,
        root=archive.root,
        repository_root=archive.repository_root,
        destination=destination,
    )
    assert (destination / "terminal-summary.txt").is_file()
    assert len(tuple((destination / "events").glob("*.json"))) == 9
    (attempt.path / "terminal-summary.txt").write_text("mutated")
    with pytest.raises(ApplicationArchiveError, match="summary"):
        verify_complete_attempt(
            attempt.attempt_id,
            root=archive.root,
            repository_root=archive.repository_root,
        )


def test_terminal_verifier_reapplies_outcome_specific_roles(tmp_path: Path) -> None:
    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    selected = {}
    for role, value in (
        ("vacancy.source_identity", b"source"),
        ("vacancy.capture", b"capture"),
        ("technical.boundary", b'{"kind":"captcha"}'),
        ("submission.result", b'{"state":"blocked"}'),
        ("browser.blocked_state_evidence", b'{"state":"captcha"}'),
        (
            "browser.redirect_http_evidence",
            b'{"availability":"listener_not_started_before_boundary",'
            b'"events":[],"schema_version":"jaa.browser-http-evidence.v1"}\n',
        ),
    ):
        row = attempt.add_artifact(role, value, media_type="application/json")
        selected[role] = row.sha256
    attempt.finalize_terminal(outcome="blocked", selected=selected)
    terminal_path = attempt.path / "terminal-manifest.json"
    terminal = json.loads(terminal_path.read_text())
    terminal["selected"].pop("browser.blocked_state_evidence")
    terminal_path.write_text(
        json.dumps(terminal, sort_keys=True, separators=(",", ":")) + "\n"
    )
    with pytest.raises(ApplicationArchiveError, match="missing roles"):
        verify_complete_attempt(
            attempt.attempt_id,
            root=archive.root,
            repository_root=archive.repository_root,
        )


def test_empty_network_object_without_reason_fails_closed(tmp_path: Path) -> None:
    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    selected = {}
    for role, value in (
        ("vacancy.source_identity", b"source"),
        ("vacancy.capture", b"capture"),
        ("technical.boundary", b'{"kind":"captcha"}'),
        ("submission.result", b'{"state":"blocked"}'),
        ("browser.blocked_state_evidence", b'{"state":"captcha"}'),
        (
            "browser.redirect_http_evidence",
            b'{"events":[],"schema_version":"jaa.browser-http-evidence.v1"}\n',
        ),
    ):
        row = attempt.add_artifact(role, value, media_type="application/json")
        selected[role] = row.sha256
    with pytest.raises(ApplicationArchiveError, match="availability reason"):
        attempt.finalize_terminal(outcome="blocked", selected=selected)


def test_nonempty_terminal_network_must_bind_to_vacancy(tmp_path: Path) -> None:
    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    selected = {}
    network = (
        b'{"availability":"observed","events":[{"method":"GET",'
        b'"redirected_from":null,"status":200,'
        b'"url":"https://unrelated.example/receipt"}],'
        b'"schema_version":"jaa.browser-http-evidence.v1"}\n'
    )
    for role, value in (
        ("vacancy.source_identity", b"source"),
        ("vacancy.capture", b"capture"),
        ("technical.boundary", b'{"kind":"captcha"}'),
        ("submission.result", b'{"state":"blocked"}'),
        ("browser.blocked_state_evidence", b'{"state":"captcha"}'),
        ("browser.redirect_http_evidence", network),
    ):
        row = attempt.add_artifact(role, value, media_type="application/json")
        selected[role] = row.sha256
    with pytest.raises(ApplicationArchiveError, match="unrelated"):
        attempt.finalize_terminal(outcome="blocked", selected=selected)


def test_query_distinguishes_incomplete_release_and_terminal_attempts(tmp_path: Path) -> None:
    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    assert archive.query() == (
        {
            "attempt_id": ATTEMPT_ID,
            "vacancy": _vacancy().document(),
            "release_finalized": False,
            "terminal_finalized": False,
            "outcome": None,
        },
    )


def test_archive_root_must_be_absolute_and_outside_worktree(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    with pytest.raises(ApplicationArchiveError, match="absolute"):
        ApplicationArchive("relative", repository_root=repository)
    with pytest.raises(ApplicationArchiveError, match="outside"):
        ApplicationArchive(repository / "artifacts", repository_root=repository)


def test_export_is_create_only(tmp_path: Path) -> None:
    archive, _attempt, receipt, _selected = _release_archive(tmp_path)
    destination = tmp_path / "existing"
    destination.mkdir()
    marker = destination / "keep.txt"
    marker.write_text("keep")
    with pytest.raises(ApplicationArchiveError, match="must not already exist"):
        export_application_packet(
            receipt.attempt_id,
            root=archive.root,
            repository_root=archive.repository_root,
            destination=destination,
        )
    assert marker.read_text() == "keep"


def test_private_evidence_event_is_ordered_recoverable_and_redacted_from_view(
    tmp_path: Path,
) -> None:
    from career_automation.application_archive import (
        load_complete_attempt_view,
        render_complete_attempt_view,
    )

    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    kwargs = {
        "event_id": "field.email.0001",
        "event_kind": "field_filled",
        "occurred_at": "2026-08-05T22:00:00Z",
        "result": "completed",
        "details": {
            "field_id": "email",
            "field_type": "email",
            "required": True,
            "options": [],
            "provenance": "synthetic-test-profile",
        },
        "private_value": b"synthetic@example.test",
        "private_media_type": "text/plain",
    }
    first = attempt.record_evidence_event(**kwargs)
    second = attempt.record_evidence_event(**kwargs)
    assert first == second
    private_objects = [
        row
        for row in attempt._objects(attempt._events())
        if row.role == "evidence.private.field.email.0001"
    ]
    assert len(private_objects) == 1
    private_path = archive.root / private_objects[0].relative_path
    assert private_path.stat().st_mode & 0o777 == 0o600
    view = load_complete_attempt_view(
        ATTEMPT_ID, root=archive.root, repository_root=repository
    )
    rendered = render_complete_attempt_view(
        ATTEMPT_ID, root=archive.root, repository_root=repository
    )
    assert view["evidence_events"][0]["payload"]["member_sha256s"]
    assert "synthetic@example.test" not in json.dumps(view)
    assert "synthetic@example.test" not in rendered
    with pytest.raises(ApplicationArchiveError, match="replay differs"):
        attempt.record_evidence_event(**{**kwargs, "result": "failed"})


def test_private_evidence_event_rejects_secret_bytes(tmp_path: Path) -> None:
    repository, root = _roots(tmp_path)
    attempt = ApplicationArchive(root, repository_root=repository).create_attempt(
        _vacancy(), attempt_id=ATTEMPT_ID
    )
    with pytest.raises(ApplicationArchiveError, match="secret-like"):
        attempt.record_evidence_event(
            event_id="field.password.0001",
            event_kind="field_filled",
            occurred_at="2026-08-05T22:00:00Z",
            result="refused",
            private_value=b"Authorization: Bearer secret-secret",
            private_media_type="text/plain",
        )


def test_exact_artifact_read_survives_reopen_and_refuses_substitution(tmp_path):
    from dataclasses import replace

    repository, root = _roots(tmp_path)
    archive = ApplicationArchive(root, repository_root=repository)
    attempt = archive.create_attempt(_vacancy(), attempt_id=ATTEMPT_ID)
    original = attempt.add_artifact("vacancy.visible_listing_capture", b"original", media_type="text/plain")
    attempt.add_artifact("vacancy.visible_listing_capture", b"newer", media_type="text/plain")
    reopened = archive.open_attempt(ATTEMPT_ID)
    assert reopened.read_artifact(original) == b"original"
    for changed in (replace(original, role="vacancy.capture"), replace(original, lineage=("a" * 64,)), replace(original, event_sha256="b" * 64)):
        with pytest.raises(ApplicationArchiveError, match="recorded event"):
            reopened.read_artifact(changed)
    other = archive.create_attempt(_vacancy("other"))
    with pytest.raises(ApplicationArchiveError, match="recorded event"):
        other.read_artifact(original)
    (root / original.relative_path).write_bytes(b"tampered")
    with pytest.raises(ApplicationArchiveError, match="bytes differ"):
        reopened.read_artifact(original)
