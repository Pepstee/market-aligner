from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from career_automation.application_archive import (
    RELEASE_REQUIRED_ROLES,
    ApplicationArchive,
    ApplicationArchiveError,
    ApplicationArchiveReceipt,
    VacancyArchiveIdentity,
    export_application_packet,
    verify_application_archive_receipt,
    verify_complete_attempt,
)


ATTEMPT_ID = "jaa-20260805T220000Z-0123456789abcdef"


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
