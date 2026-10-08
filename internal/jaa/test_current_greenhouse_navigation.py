import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import career_automation.current_greenhouse_navigation as navigation
import career_automation.browser_executor as browser_executor
import career_automation.production_attempt as production_attempt
import pytest
from career_automation.application_archive import (
    ApplicationArchive,
    ApplicationArchiveError,
    ApplicationArchiveReceipt,
    VacancyArchiveIdentity,
)
from career_automation.current_greenhouse_navigation import (
    CurrentGreenhouseNavigationCapture,
    _redacted_loader_capture,
    bind_current_greenhouse_navigation,
)
from career_automation.browser_executor import GreenhouseSuccessEvidence
from career_automation.production_attempt import GreenhouseAttemptRecorder
from career_automation.greenhouse_loader_contract import (
    parse_current_greenhouse_loader,
)


def test_redacted_loader_config_keeps_original_and_archived_hash_domains_distinct():
    source_url = "https://job-boards.eu.greenhouse.io/example/jobs/12345"
    payload = {
        "state": {
            "loaderData": {
                "routes/$url_token_.jobs_.$job_post_id": {
                    "jobPostId": "12345",
                    "urlToken": "nontrivial-private-token",
                    "jobPost": {
                        "public_url": source_url,
                        "confirmation_message": "<p>Received.</p>",
                    },
                    "submitPath": (
                        "https://boards.eu.greenhouse.io/example/jobs/12345"
                    ),
                    "confirmationPath": (
                        "/example/jobs/12345/confirmation"
                    ),
                }
            }
        }
    }
    response = (
        "<html><script>window.__remixContext = "
        + json.dumps(payload)
        + ";</script></html>"
    ).encode("utf-8")

    original_sha256, redacted_response, config_bytes = _redacted_loader_capture(
        response, source_url=source_url
    )

    config = json.loads(config_bytes)
    assert original_sha256 == hashlib.sha256(response).hexdigest()
    assert original_sha256 != hashlib.sha256(redacted_response).hexdigest()
    assert config["primary_response_sha256"] == hashlib.sha256(
        redacted_response
    ).hexdigest()
    assert b"nontrivial-private-token" not in redacted_response
    archived_parse = parse_current_greenhouse_loader(
        redacted_response, source_url=source_url
    )
    assert config["primary_response_sha256"] == archived_parse[
        "primary_response_sha256"
    ]
    assert config["submitPath"] == archived_parse["submitPath"]


def test_navigation_capture_can_bind_to_only_one_attempt():
    source_url = "https://job-boards.eu.greenhouse.io/example/jobs/12345"
    payload = {
        "state": {
            "loaderData": {
                "routes/$url_token_.jobs_.$job_post_id": {
                    "jobPostId": "12345",
                    "urlToken": "nontrivial-private-token",
                    "jobPost": {
                        "public_url": source_url,
                        "confirmation_message": "Received.",
                    },
                    "submitPath": "https://boards.eu.greenhouse.io/example/jobs/12345",
                    "confirmationPath": "/example/jobs/12345/confirmation",
                }
            }
        }
    }
    response = (
        "<html><script>window.__remixContext = "
        + json.dumps(payload)
        + ";</script></html>"
    ).encode("utf-8")
    original_sha256, redacted_response, config_bytes = _redacted_loader_capture(
        response, source_url=source_url
    )
    market_binding = {
        "application_id": "app_" + "1" * 32,
        "raw_listing_sha256": "a" * 64,
        "source_job_key": "greenhouse:example:12345",
        "source_url": source_url,
    }
    page = object()

    def make_capture():
        return CurrentGreenhouseNavigationCapture(
            page_identity=id(page),
            source_url=source_url,
            response_url=source_url,
            method="GET",
            status=200,
            observed_at="2026-10-07T10:00:00Z",
            primary_response_sha256=original_sha256,
            redacted_response=redacted_response,
            redacted_response_sha256=hashlib.sha256(redacted_response).hexdigest(),
            loader_config=config_bytes,
            loader_config_sha256=hashlib.sha256(config_bytes).hexdigest(),
            market_context_sha256="b" * 64,
            market_binding=tuple(sorted(market_binding.items())),
            repository_head="c" * 40,
            code_source_sha256s=(("current_greenhouse_navigation.py", "d" * 64),),
            _issuer=navigation._CAPTURE_ISSUER,
        )

    vacancy = SimpleNamespace(
        source_url=source_url,
        vacancy_sha256=market_binding["raw_listing_sha256"],
        job_key=market_binding["source_job_key"],
    )

    class _Attempt:
        def __init__(self, attempt_id):
            self.attempt_id = attempt_id
            self.vacancy = vacancy
            self.rows = []
            self.events = []

        def _events(self):
            return self.events

        def _objects(self, _events):
            return self.rows

        def next_evidence_event_id(self, event_kind):
            return f"{event_kind}-{self.attempt_id}"

        def add_artifact(self, role, value, **_kwargs):
            row = SimpleNamespace(
                role=role, sha256=hashlib.sha256(value).hexdigest()
            )
            self.rows.append(row)
            return row

        def record_evidence_event(self, *, event_id, event_kind, details, member_sha256s, **_kwargs):
            event_sha256 = hashlib.sha256(event_id.encode()).hexdigest()
            self.events.append(
                {
                    "event_sha256": event_sha256,
                    "payload": {
                        "event_kind": event_kind,
                        "details": details,
                        "member_sha256s": member_sha256s,
                    },
                }
            )
            return event_sha256

    def make_recorder(attempt_id):
        recorder = object.__new__(GreenhouseAttemptRecorder)
        recorder.attempt = _Attempt(attempt_id)
        recorder.current_provider_proof = None
        recorder._review_only_active = False
        return recorder

    capture = make_capture()
    first_recorder = make_recorder("attempt-one")
    evidence = {
        "url": source_url,
        "method": "GET",
        "status": 200,
        "_current_navigation_capture": capture,
    }
    first_recorder.record_navigation(
        evidence,
        page=page,
    )
    assert first_recorder.current_provider_proof.attempt_id == "attempt-one"

    second_recorder = make_recorder("attempt-two")
    with pytest.raises(ValueError, match="already bound"):
        second_recorder.record_navigation(
            evidence,
            page=page,
        )
    assert second_recorder.attempt.rows == []
    assert second_recorder.attempt.events == []

    fresh_recorder = make_recorder("attempt-two")
    fresh_recorder.record_navigation(
        {**evidence, "_current_navigation_capture": make_capture()},
        page=page,
    )
    assert fresh_recorder.current_provider_proof.attempt_id == "attempt-two"


def test_current_navigation_details_use_real_closed_archive_schema(tmp_path):
    source_url = "https://job-boards.eu.greenhouse.io/example/jobs/12345"
    payload = {
        "state": {
            "loaderData": {
                "routes/$url_token_.jobs_.$job_post_id": {
                    "jobPostId": "12345",
                    "urlToken": "synthetic-private-token",
                    "jobPost": {
                        "public_url": source_url,
                        "confirmation_message": "Received.",
                    },
                    "submitPath": "https://boards.eu.greenhouse.io/example/jobs/12345",
                    "confirmationPath": "/example/jobs/12345/confirmation",
                }
            }
        }
    }
    original_response = (
        "<html><script>window.__remixContext = "
        + json.dumps(payload)
        + ";</script></html>"
    ).encode("utf-8")
    original_sha256, redacted_response, loader_config = _redacted_loader_capture(
        original_response, source_url=source_url
    )
    vacancy_bytes = b'{"synthetic_public_vacancy":true}'
    vacancy = VacancyArchiveIdentity(
        job_key="greenhouse:example:12345",
        vacancy_sha256=hashlib.sha256(vacancy_bytes).hexdigest(),
        role_title="Synthetic role",
        company_name="Synthetic employer",
        source_url=source_url,
    )
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    archive = ApplicationArchive(
        tmp_path / "archive", repository_root=repository_root
    )
    attempt = archive.create_attempt(vacancy)
    attempt.add_artifact(
        "vacancy.structured", vacancy_bytes, media_type="application/json"
    )
    page = object()
    market_binding = {
        "application_id": "app_" + "1" * 32,
        "raw_listing_sha256": vacancy.vacancy_sha256,
        "source_job_key": vacancy.job_key,
        "source_url": source_url,
    }
    capture = CurrentGreenhouseNavigationCapture(
        page_identity=id(page),
        source_url=source_url,
        response_url=source_url,
        method="GET",
        status=200,
        observed_at="2026-10-07T10:00:00Z",
        primary_response_sha256=original_sha256,
        redacted_response=redacted_response,
        redacted_response_sha256=hashlib.sha256(redacted_response).hexdigest(),
        loader_config=loader_config,
        loader_config_sha256=hashlib.sha256(loader_config).hexdigest(),
        market_context_sha256="b" * 64,
        market_binding=tuple(sorted(market_binding.items())),
        repository_head="c" * 40,
        code_source_sha256s=(("current_greenhouse_navigation.py", "d" * 64),),
        _issuer=navigation._CAPTURE_ISSUER,
    )
    recorder = object.__new__(GreenhouseAttemptRecorder)
    recorder.attempt = attempt
    recorder.current_provider_proof = None
    recorder._review_only_active = False

    recorder.record_navigation(
        {
            "url": source_url,
            "method": "GET",
            "status": 200,
            "_current_navigation_capture": capture,
        },
        page=page,
    )

    assert recorder.current_provider_proof.attempt_id == attempt.attempt_id
    navigation_events = [
        event
        for event in attempt._events()
        if event.get("event_type") == "evidence_recorded"
        and event.get("payload", {}).get("event_kind") == "navigation"
    ]
    assert len(navigation_events) == 1
    details = navigation_events[0]["payload"]["details"]
    assert details["provider_response_sha256"] == original_sha256
    assert details["provider_redacted_response_sha256"] == capture.redacted_response_sha256
    assert details["provider_loader_config_sha256"] == capture.loader_config_sha256
    assert details["current_market_context_sha256"] == capture.market_context_sha256

    with pytest.raises(ApplicationArchiveError, match="detail keys are invalid"):
        attempt.record_evidence_event(
            event_id=attempt.next_evidence_event_id("navigation"),
            event_kind="navigation",
            occurred_at="2026-10-07T10:00:01Z",
            result="completed",
            details={"unapproved_detail": "still rejected"},
        )


def test_review_only_resume_appends_passive_navigation_without_reissuing_proof(
    tmp_path,
):
    source_url = "https://job-boards.eu.greenhouse.io/example/jobs/12345"
    vacancy_bytes = b"<html>synthetic public vacancy</html>"
    vacancy = VacancyArchiveIdentity(
        job_key="greenhouse:example:12345",
        vacancy_sha256=hashlib.sha256(vacancy_bytes).hexdigest(),
        role_title="Synthetic role",
        company_name="Synthetic employer",
        source_url=source_url,
    )
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    archive_root = tmp_path / "archive"
    market_binding = {
        "application_id": "app_" + "1" * 32,
        "raw_listing_sha256": vacancy.vacancy_sha256,
        "source_job_key": vacancy.job_key,
        "source_url": source_url,
    }
    page = object()
    loader_payload = {
        "state": {
            "loaderData": {
                "routes/$url_token_.jobs_.$job_post_id": {
                    "jobPostId": "12345",
                    "urlToken": "synthetic-passive-token",
                    "jobPost": {
                        "public_url": source_url,
                        "confirmation_message": "Received.",
                    },
                    "submitPath": "https://boards.eu.greenhouse.io/example/jobs/12345",
                    "confirmationPath": "/example/jobs/12345/confirmation",
                }
            }
        }
    }
    original_response = (
        "<html><script>window.__remixContext = "
        + json.dumps(loader_payload)
        + ";</script></html>"
    ).encode("utf-8")
    original_sha256, redacted_response, loader_config = _redacted_loader_capture(
        original_response, source_url=source_url
    )

    def make_capture(
        *,
        binding=market_binding,
        capture_page=page,
        capture_source_url=source_url,
        observed_at="2026-10-07T13:00:00Z",
    ):
        return CurrentGreenhouseNavigationCapture(
            page_identity=id(capture_page),
            source_url=capture_source_url,
            response_url=capture_source_url,
            method="GET",
            status=200,
            observed_at=observed_at,
            primary_response_sha256=original_sha256,
            redacted_response=redacted_response,
            redacted_response_sha256=hashlib.sha256(redacted_response).hexdigest(),
            loader_config=loader_config,
            loader_config_sha256=hashlib.sha256(loader_config).hexdigest(),
            market_context_sha256="b" * 64,
            market_binding=tuple(sorted(binding.items())),
            repository_head="c" * 40,
            code_source_sha256s=(("current_greenhouse_navigation.py", "d" * 64),),
            _issuer=navigation._CAPTURE_ISSUER,
        )

    def make_navigation_event(capture, *, url=source_url):
        return {
            "url": url,
            "method": "GET",
            "status": 200,
            "_current_navigation_capture": capture,
        }

    fresh = GreenhouseAttemptRecorder.create(
        archive_root=tmp_path / "fresh-archive",
        repository_root=repository_root,
        vacancy=vacancy,
        complete_vacancy=vacancy_bytes,
        structured_vacancy={"source_url": source_url},
        assessment={"result": "synthetic"},
    )
    fresh.begin_review_only()
    fresh.record_navigation(make_navigation_event(make_capture()), page=page)
    assert fresh.current_provider_proof is None
    fresh_rows = fresh.attempt._objects(fresh.attempt._events())
    assert any(row.role == "provider.passive_navigation_response.0001" for row in fresh_rows)
    assert not any(
        row.role in {
            "provider.current_loader_response",
            "provider.current_loader_config",
        }
        for row in fresh_rows
    )
    fresh.begin_review_only()

    initial = GreenhouseAttemptRecorder.create(
        archive_root=archive_root,
        repository_root=repository_root,
        vacancy=vacancy,
        complete_vacancy=vacancy_bytes,
        structured_vacancy={"source_url": source_url},
        assessment={"result": "synthetic"},
    )
    initial.begin_review_only()
    legacy_capture = make_capture()
    legacy_response = initial.attempt.add_artifact(
        "provider.current_loader_response",
        legacy_capture.redacted_response,
        media_type="text/html",
        lineage=(vacancy.vacancy_sha256,),
        disposition="approved",
        metadata={
            "capture": "redacted_current_primary_navigation_response",
            "primary_response_sha256": legacy_capture.primary_response_sha256,
        },
    )
    legacy_config = initial.attempt.add_artifact(
        "provider.current_loader_config",
        legacy_capture.loader_config,
        media_type="application/json",
        lineage=(legacy_response.sha256,),
        disposition="approved",
        metadata={"capture": "parsed_current_navigation_loader"},
    )
    initial._record_evidence(
        "navigation",
        result="completed",
        members={
            "provider.current_loader_response": legacy_response.sha256,
            "provider.current_loader_config": legacy_config.sha256,
        },
        details={
            "method": "GET",
            "status": 200,
            "url_sha256": initial._url_sha256(source_url),
            "provider_response_sha256": legacy_capture.primary_response_sha256,
            "provider_redacted_response_sha256": legacy_capture.redacted_response_sha256,
            "provider_loader_config_sha256": legacy_capture.loader_config_sha256,
            "current_market_context_sha256": legacy_capture.market_context_sha256,
        },
    )
    assert initial.current_provider_proof is None
    prior_provider_rows = {
        row.role: row.sha256
        for row in initial.attempt._objects(initial.attempt._events())
        if row.role
        in {
            "provider.current_loader_response",
            "provider.current_loader_config",
        }
    }
    assert set(prior_provider_rows) == {
        "provider.current_loader_response",
        "provider.current_loader_config",
    }
    prior_provider_bytes = {
        row.role: initial.attempt.read_artifact(row)
        for row in initial.attempt._objects(initial.attempt._events())
        if row.role in prior_provider_rows
    }

    resumed = GreenhouseAttemptRecorder.resume(
        archive_root=archive_root,
        repository_root=repository_root,
        attempt_id=initial.attempt.attempt_id,
    )
    resumed.begin_review_only()
    assert resumed.current_provider_proof is None
    fresh_capture = make_capture()
    event_sha256 = resumed.record_navigation(
        make_navigation_event(fresh_capture), page=page
    )
    assert resumed.current_provider_proof is None

    rows = resumed.attempt._objects(resumed.attempt._events())
    assert {
        row.role: row.sha256
        for row in rows
        if row.role
        in {
            "provider.current_loader_response",
            "provider.current_loader_config",
        }
    } == prior_provider_rows
    assert {
        row.role: resumed.attempt.read_artifact(row)
        for row in rows
        if row.role in prior_provider_rows
    } == prior_provider_bytes
    passive_response = [
        row for row in rows if row.role == "provider.passive_navigation_response.0001"
    ]
    passive_config = [
        row for row in rows if row.role == "provider.passive_navigation_config.0001"
    ]
    assert len(passive_response) == len(passive_config) == 1
    assert passive_response[0].disposition == passive_config[0].disposition == "observed"
    assert resumed.attempt.read_artifact(passive_response[0]) == redacted_response
    assert resumed.attempt.read_artifact(passive_config[0]) == loader_config
    passive_event = next(
        event
        for event in resumed.attempt._events()
        if event.get("event_sha256") == event_sha256
    )
    assert passive_event["payload"]["member_sha256s"] == {
        "provider.passive_navigation_config.0001": passive_config[0].sha256,
        "provider.passive_navigation_response.0001": passive_response[0].sha256,
    }
    assert passive_event["payload"]["details"]["current_market_context_sha256"] == "b" * 64
    resumed.begin_review_only()

    before_reuse = len(resumed.attempt._events())
    with pytest.raises(ValueError, match="already bound"):
        resumed.record_navigation(make_navigation_event(fresh_capture), page=page)
    assert len(resumed.attempt._events()) == before_reuse

    mismatched_binding = {
        **market_binding,
        "raw_listing_sha256": "e" * 64,
        "source_job_key": "greenhouse:other:99999",
    }
    with pytest.raises(ValueError, match="cannot bind to this vacancy"):
        resumed.record_navigation(
            make_navigation_event(make_capture(binding=mismatched_binding)), page=page
        )
    with pytest.raises(ValueError, match="lacks its admitted application"):
        resumed.record_navigation(
            make_navigation_event(
                make_capture(binding={**market_binding, "application_id": "invalid"})
            ),
            page=page,
        )
    with pytest.raises(ValueError, match="not bound to this page"):
        resumed.record_navigation(
            make_navigation_event(make_capture(capture_page=object())), page=page
        )
    mismatched_source = "https://job-boards.eu.greenhouse.io/other/jobs/99999"
    with pytest.raises(ValueError, match="cannot bind to this vacancy"):
        resumed.record_navigation(
            make_navigation_event(
                make_capture(
                    binding={**market_binding, "source_url": mismatched_source},
                    capture_source_url=mismatched_source,
                ),
                url=mismatched_source,
            ),
            page=page,
        )
    assert len(resumed.attempt._events()) == before_reuse

    second_event_sha256 = resumed.record_navigation(
        make_navigation_event(
            make_capture(observed_at="2026-10-07T13:01:00Z")
        ),
        page=page,
    )
    rows = resumed.attempt._objects(resumed.attempt._events())
    assert any(row.role == "provider.passive_navigation_response.0002" for row in rows)
    assert any(row.role == "provider.passive_navigation_config.0002" for row in rows)
    assert {
        row.role: row.sha256
        for row in rows
        if row.role
        in {
            "provider.current_loader_response",
            "provider.current_loader_config",
        }
    } == prior_provider_rows
    assert {
        row.role: resumed.attempt.read_artifact(row)
        for row in rows
        if row.role in prior_provider_rows
    } == prior_provider_bytes
    assert any(
        event.get("event_sha256") == second_event_sha256
        for event in resumed.attempt._events()
    )
    resumed.begin_review_only()

    live = GreenhouseAttemptRecorder.create(
        archive_root=tmp_path / "live-archive",
        repository_root=repository_root,
        vacancy=vacancy,
        complete_vacancy=vacancy_bytes,
        structured_vacancy={"source_url": source_url},
        assessment={"result": "synthetic"},
    )
    live.record_navigation(make_navigation_event(make_capture()), page=page)
    live_proof = live.current_provider_proof
    live_resumed = GreenhouseAttemptRecorder.resume(
        archive_root=tmp_path / "live-archive",
        repository_root=repository_root,
        attempt_id=live.attempt.attempt_id,
    )
    before_live_duplicate = live_resumed.attempt._events()
    with pytest.raises(ValueError, match="proof already exists"):
        live_resumed.record_navigation(
            make_navigation_event(make_capture()), page=page
        )
    assert live.current_provider_proof is live_proof
    assert live_resumed.current_provider_proof is None
    assert live_resumed.attempt._events() == before_live_duplicate


def test_current_proof_is_consumed_by_release_and_archive_boundaries(
    tmp_path, monkeypatch
):
    source_url = "https://job-boards.eu.greenhouse.io/example/jobs/12345"
    payload = {
        "state": {
            "loaderData": {
                "routes/$url_token_.jobs_.$job_post_id": {
                    "jobPostId": "12345",
                    "urlToken": "synthetic-private-token",
                    "jobPost": {
                        "public_url": source_url,
                        "confirmation_message": "<h1>Received.</h1>",
                    },
                    "submitPath": "https://boards.eu.greenhouse.io/example/jobs/12345",
                    "confirmationPath": "/example/jobs/12345/confirmation",
                }
            }
        }
    }
    original_response = (
        "<html><script>window.__remixContext = "
        + json.dumps(payload)
        + ";</script></html>"
    ).encode("utf-8")
    original_sha256, archived_response, loader_config = _redacted_loader_capture(
        original_response, source_url=source_url
    )
    page = SimpleNamespace()
    market_binding = {
        "application_id": "app_" + "1" * 32,
        "raw_listing_sha256": "a" * 64,
        "source_job_key": "greenhouse:example:12345",
        "source_url": source_url,
    }
    capture = CurrentGreenhouseNavigationCapture(
        page_identity=id(page),
        source_url=source_url,
        response_url=source_url,
        method="GET",
        status=200,
        observed_at="2026-10-07T10:00:00Z",
        primary_response_sha256=original_sha256,
        redacted_response=archived_response,
        redacted_response_sha256=hashlib.sha256(archived_response).hexdigest(),
        loader_config=loader_config,
        loader_config_sha256=hashlib.sha256(loader_config).hexdigest(),
        market_context_sha256="b" * 64,
        market_binding=tuple(sorted(market_binding.items())),
        repository_head="c" * 40,
        code_source_sha256s=(("synthetic-current-module.py", "d" * 64),),
        _issuer=navigation._CAPTURE_ISSUER,
    )
    vacancy = SimpleNamespace(
        source_url=source_url,
        vacancy_sha256=market_binding["raw_listing_sha256"],
        job_key=market_binding["source_job_key"],
        role_title="Synthetic role",
        company_name="Synthetic employer",
    )
    attempt_id = "attempt-current-proof"
    event_sha256 = "e" * 64
    proof = bind_current_greenhouse_navigation(
        capture,
        attempt_id=attempt_id,
        navigation_event_sha256=event_sha256,
        vacancy=vacancy,
    )
    observation = proof.observation_bytes()
    loader = proof.loader_document()
    evidence = GreenhouseSuccessEvidence(
        observation_sha256=hashlib.sha256(observation).hexdigest(),
        observed_at=proof.observed_at,
        confirmation_url=loader["confirmation_url"],
        required_visible_markers=loader["required_visible_markers"],
    )
    event = {
        "event_sha256": event_sha256,
        "payload": {
            "event_kind": "navigation",
            "details": {
                "provider_response_sha256": proof.primary_response_sha256,
                "provider_loader_config_sha256": proof.loader_config_sha256,
            },
            "member_sha256s": {
                "provider.current_loader_config": proof.loader_config_sha256,
            },
        },
    }
    response_row = SimpleNamespace(role="provider.current_loader_response")
    config_row = SimpleNamespace(role="provider.current_loader_config")
    artifacts = {
        response_row.role: archived_response,
        config_row.role: loader_config,
    }
    archive_root = tmp_path / "archive"
    repository_root = tmp_path / "repository"

    class _Attempt:
        def __init__(self):
            self.attempt_id = attempt_id
            self.vacancy = vacancy
            self.archive = SimpleNamespace(
                root=archive_root, repository_root=repository_root
            )

        def _events(self):
            return [event]

        def _objects(self, _events):
            return [response_row, config_row]

        def read_artifact(self, row):
            return artifacts[row.role]

        def finalize_release(self, **_kwargs):
            return "finalized-current-release-fixture"

    monkeypatch.setattr(
        navigation,
        "_code_identity",
        lambda _root: (
            proof.repository_head,
            proof.code_source_sha256s,
        ),
    )
    recorder = object.__new__(GreenhouseAttemptRecorder)
    recorder.attempt = _Attempt()
    recorder.current_provider_proof = proof
    recorded_objects = {}

    def add_artifact(role, value, _media_type, *, metadata=None):
        recorded_objects[role] = value
        return SimpleNamespace(sha256=hashlib.sha256(value).hexdigest())

    monkeypatch.setattr(recorder, "_selected", lambda: {"browser.prefill_snapshot": "f" * 64})
    monkeypatch.setattr(recorder, "_add", add_artifact)
    monkeypatch.setattr(recorder, "_record_evidence", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(production_attempt, "_approved_fact_authorities", lambda _source: [])
    monkeypatch.setattr(production_attempt.importlib.metadata, "version", lambda _name: "test")
    monkeypatch.setattr(production_attempt, "approved_form_mapping_bytes", lambda **_kwargs: b"{}")
    monkeypatch.setattr(production_attempt, "release_upload_mapping_bytes", lambda *_args, **_kwargs: b"{}")
    monkeypatch.setattr(production_attempt, "canonical_non_secret_form_state", lambda _page: b"{}")
    page.screenshot = lambda **_kwargs: b"synthetic screenshot"
    source = SimpleNamespace(
        job_key=vacancy.job_key,
        vacancy_sha256=vacancy.vacancy_sha256,
        source_id="synthetic-source",
        role_title=vacancy.role_title,
        company_name=vacancy.company_name,
        document=lambda: {"source_id": "synthetic-source"},
    )
    empty_receipt = SimpleNamespace(
        document=lambda: {},
        policy_sha256="1" * 64,
    )
    semantic_receipt = SimpleNamespace(
        document=lambda: {},
        backend_identity="synthetic-backend",
        model_identity="synthetic-model",
        policy_sha256="2" * 64,
        prompt_sha256="3" * 64,
        schema_sha256="4" * 64,
    )
    artifacts_for_release = SimpleNamespace(
        editable=SimpleNamespace(cv_text="cv", cover_letter_text="letter", answers_text=""),
        cv_pdf=SimpleNamespace(
            pdf_bytes=b"cv-pdf",
            pdf_sha256=hashlib.sha256(b"cv-pdf").hexdigest(),
            page_count=1,
            extracted_text="cv",
        ),
        cover_letter_pdf=SimpleNamespace(
            pdf_bytes=b"letter-pdf",
            pdf_sha256=hashlib.sha256(b"letter-pdf").hexdigest(),
            page_count=1,
            extracted_text="letter",
        ),
    )
    finalized_at = datetime(2026, 10, 7, 10, 1, tzinfo=timezone.utc)
    result = recorder.finalize_release(
        page,
        source=source,
        artifacts=artifacts_for_release,
        questions=None,
        document_assurance_receipts=(empty_receipt, empty_receipt),
        sanity_review_receipt=semantic_receipt,
        production_identity=SimpleNamespace(document=lambda: {}),
        field_authority_names=(),
        consent_states=(),
        success_evidence=evidence,
        success_observation=observation,
        current_provider_proof=proof,
        finalized_at=finalized_at,
    )
    assert result == "finalized-current-release-fixture"
    assert json.loads(recorded_objects["provider.success_authority"]) == proof.document()

    archive_receipt = object.__new__(ApplicationArchiveReceipt)
    object.__setattr__(archive_receipt, "attempt_id", attempt_id)
    authority = object.__new__(browser_executor.ReleaseExecutionAuthority)
    authority_values = {
        "archive_receipt": archive_receipt,
        "archive_root": archive_root,
        "repository_root": repository_root,
        "ats_provider": "greenhouse",
        "success_evidence": evidence,
        "current_provider_proof": proof,
        "application_url": source_url,
        "application_id": "12345",
        "source": source,
        "consumed_at": finalized_at,
    }
    for name, value in authority_values.items():
        object.__setattr__(authority, name, value)

    monkeypatch.setattr(
        browser_executor,
        "selected_archive_object_bytes",
        lambda _receipt, role, **_kwargs: {
            "provider.success_observation": observation,
            "provider.current_loader_response": archived_response,
            "provider.current_loader_config": loader_config,
        }[role],
    )

    class _OpenedArchive:
        def __init__(self, *_args, **_kwargs):
            pass

        def open_attempt(self, requested_attempt_id):
            assert requested_attempt_id == attempt_id
            return recorder.attempt

    class _ReachedVerifiedArchiveBoundary(Exception):
        pass

    monkeypatch.setattr(browser_executor, "ApplicationArchive", _OpenedArchive)
    monkeypatch.setattr(
        browser_executor,
        "VacancyArchiveIdentity",
        lambda **_kwargs: (_ for _ in ()).throw(_ReachedVerifiedArchiveBoundary()),
    )
    with pytest.raises(_ReachedVerifiedArchiveBoundary):
        authority.verify_archive_receipt(verified_at=finalized_at)
