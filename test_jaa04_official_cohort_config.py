"""Canonical configuration contracts for the JAA-04 official cohort."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from urllib.parse import urlsplit

import pytest
import requests

from career_automation.employer_research import (
    ATS_AUTHORITY_CANARIES,
    Citation,
    DEFAULT_ATS_ROUTE_ADAPTERS,
    LIVE_ATS_AUTHORITY_CANARIES,
    PublicRetrievalAttempt,
    PublicRetrievalExhausted,
    RawResponseCache,
    _canonical_public_url,
    _public_transport_url,
)
from career_automation.official_cohort import (
    AGGREGATORS,
    OFFICIAL_ADAPTERS,
    AuditedAccessController,
    AuditedRobotsClient,
    DurableRequestJournal,
    ResponseRecorder,
    _canonical,
    _select_candidates,
    _timing_evidence,
    _validate_config,
    build,
)
from career_automation.holdout_firewall import QuarantineIndex
from career_automation.public_access import (
    PublicAccessDenied,
    PublicAccessController,
    PublicAccessPolicy,
    RobotsReceipt,
    TermsAttestation,
    USER_AGENT,
    replay_access_receipt,
)
import scripts.capture_jaa04_authority_canaries as canary_capture
from skeleton.configuration import load_config


ROOT = Path(__file__).resolve().parent
OVERNIGHT = ROOT / "skeleton" / "config.overnight.yaml"
EMPTY_TEST_QUARANTINE = QuarantineIndex(
    path=Path("/offline-test/empty-quarantine-index.json"),
    sha256="f" * 64,
    entry_count=0,
    job_keys=frozenset(),
    payload_hashes=frozenset(),
    requirement_ids=frozenset(),
    source_text_sha256=frozenset(),
    source_identity_sha256=frozenset(),
)


def _public_resolver(_host: str, port: int) -> tuple[tuple[object, ...], ...]:
    return ((None, None, None, None, ("93.184.216.34", port)),)


def _transport_receipt(url: str) -> RobotsReceipt:
    host = urlsplit(url).hostname or ""
    return RobotsReceipt(
        host=host,
        robots_url=f"https://{host}/robots.txt",
        final_url=f"https://{host}/robots.txt",
        status_code=200,
        content_sha256="0" * 64,
        raw_response_ref="sha256/00/" + "0" * 64 + ".response",
        redirect_history=[],
        retrieved_at="2026-07-27T12:00:00+00:00",
        user_agent=USER_AGENT,
        requested_url=url,
        allowed=True,
        crawl_delay_seconds=10.0,
        terms_policy_sha256="1" * 64,
        terms_attestation={},
    )


@pytest.mark.parametrize(
    "url",
    (
        "https://api.ashbyhq.com/posting-api/job-board/acme?includeCompensation=true",
        "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
        "https://api.lever.co/v0/postings/acme?mode=json&limit=100&skip=0",
        "https://api.smartrecruiters.com/v1/companies/acme/postings?limit=100&offset=0",
        "https://www.workable.com/api/accounts/acme?details=true",
    ),
)
def test_official_api_transport_queries_are_public_but_not_evidence_identities(
    url: str,
) -> None:
    _public_transport_url(url, resolver=_public_resolver)
    with pytest.raises(ValueError, match="canonical evidence URL"):
        _canonical_public_url(url)


@pytest.mark.parametrize(
    "url",
    (
        "https://user:secret@api.ashbyhq.com/posting-api/job-board/acme?includeCompensation=true",
        "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true#fragment",
        "https://127.0.0.1/jobs?content=true",
        "https://169.254.169.254/latest/meta-data?role=jobs",
    ),
)
def test_official_transport_rejects_credentials_fragments_and_private_literals(
    url: str,
) -> None:
    with pytest.raises(ValueError):
        _public_transport_url(url, resolver=_public_resolver)


def test_official_transport_rejects_a_private_dns_answer() -> None:
    def private_resolver(
        _host: str,
        port: int,
    ) -> tuple[tuple[object, ...], ...]:
        return ((None, None, None, None, ("127.0.0.1", port)),)

    with pytest.raises(ValueError, match="public addresses"):
        _public_transport_url(
            "https://api.lever.co/v0/postings/acme?mode=json",
            resolver=private_resolver,
        )


def test_official_transport_resolves_the_scheme_default_port() -> None:
    resolved: list[tuple[str, int]] = []

    def recording_resolver(
        host: str,
        port: int,
    ) -> tuple[tuple[object, ...], ...]:
        resolved.append((host, port))
        return _public_resolver(host, port)

    _public_transport_url(
        "http://api.lever.co/v0/postings/acme?mode=json",
        resolver=recording_resolver,
    )
    _public_transport_url(
        "https://api.lever.co/v0/postings/acme?mode=json",
        resolver=recording_resolver,
    )
    assert resolved == [("api.lever.co", 80), ("api.lever.co", 443)]


def test_official_transport_returns_the_exact_validated_dns_set() -> None:
    assert _public_transport_url(
        "https://api.lever.co/v0/postings/acme?mode=json",
        resolver=_public_resolver,
    ) == ("93.184.216.34",)


@pytest.mark.parametrize(
    ("url", "denial"),
    (
        (
            "https://unreviewed.example/jobs?content=true",
            "TERMS_AUTHORITY_MISSING: unreviewed.example",
        ),
        (
            "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
            "ROBOTS_DISALLOWED: /v1/boards/acme/jobs",
        ),
    ),
)
def test_transport_policy_or_robots_denial_stops_before_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    denial: str,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    content_calls: list[str] = []

    class DenyingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            assert requested_url == url
            raise PublicAccessDenied(denial)

    def content_send(
        _session: object,
        request: requests.PreparedRequest,
        **_kwargs: object,
    ) -> object:
        content_calls.append(str(request.url))
        raise AssertionError("content transport must not run after denial")

    monkeypatch.setattr(requests.sessions.Session, "send", content_send)
    recorder = ResponseRecorder(tmp_path / "raw", DenyingController())  # type: ignore[arg-type]
    prepared = requests.Request("GET", url).prepare()
    with recorder.installed(), pytest.raises(PublicAccessDenied, match=denial):
        requests.Session().send(prepared)
    assert content_calls == []
    assert recorder.records == []


def test_transport_revalidates_an_unsafe_redirect_before_second_content_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    first = "https://api.lever.co/v0/postings/acme?mode=json"
    unsafe = "https://127.0.0.1/private?mode=json"
    content_calls: list[str] = []

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    def redirecting_send(
        session: requests.Session,
        request: requests.PreparedRequest,
        **kwargs: object,
    ) -> object:
        content_calls.append(str(request.url))
        redirected = requests.Request("GET", unsafe).prepare()
        return session.send(redirected, **kwargs)

    monkeypatch.setattr(requests.sessions.Session, "send", redirecting_send)
    recorder = ResponseRecorder(tmp_path / "raw", AllowingController())  # type: ignore[arg-type]
    prepared = requests.Request("GET", first).prepare()
    with recorder.installed(), pytest.raises(ValueError, match="private transport"):
        requests.Session().send(prepared)
    assert content_calls == [first]
    assert recorder.records == []


def test_response_recorder_preserves_query_transport_url_and_exact_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    url = "https://api.ashbyhq.com/posting-api/job-board/acme?includeCompensation=true"
    body = b'{"jobs":[{"id":"vacancy-1","publishedAt":"2026-07-27T10:00:00Z"}]}'

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    def content_send(
        _session: requests.Session,
        request: requests.PreparedRequest,
        **_kwargs: object,
    ) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response._content = body
        response.url = str(request.url)
        response.request = request
        response.history = []
        return response

    monkeypatch.setattr(requests.sessions.Session, "send", content_send)
    recorder = ResponseRecorder(tmp_path / "raw", AllowingController())  # type: ignore[arg-type]
    prepared = requests.Request("GET", url).prepare()
    with recorder.installed():
        response = requests.Session().send(prepared)
    assert response.content == body
    assert len(recorder.records) == 1
    record = recorder.records[0]
    assert record["requested_url"] == url
    assert record["response_url"] == url
    assert record["byte_count"] == len(body)
    assert record["dns_addresses"] == ["93.184.216.34"]
    assert record["access_receipt"]["requested_url"] == url
    raw = tmp_path / "raw" / str(record["raw_response"])
    assert raw.read_bytes() == body
    assert hashlib.sha256(body).hexdigest() == record["sha256"]
    assert recorder.send_events == [
        {
            **recorder.send_events[0],
            "send_sequence": 0,
            "requested_url": url,
            "validated_dns_addresses": ["93.184.216.34"],
            "outcome": "response",
            "status": 200,
            "byte_count": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "raw_response": record["raw_response"],
        }
    ]


def _request_journal(
    run_root: Path,
    *,
    resume: bool,
    policy_sha256: str = "3" * 64,
    quarantine_index_sha256: str = EMPTY_TEST_QUARANTINE.sha256,
    source_head: str = "a" * 40,
) -> DurableRequestJournal:
    config = run_root.parent / f"{run_root.name}-config.yaml"
    if not config.exists():
        config.write_text("exact fixture configuration\n", encoding="utf-8")
    return DurableRequestJournal.open(
        config_path=config,
        policy_sha256=policy_sha256,
        quarantine_index_sha256=quarantine_index_sha256,
        source_head=source_head,
        raw_root=run_root / "raw",
        resume=resume,
    )


def _journalled_fixture_response(
    calls: list[str],
    bodies: dict[str, bytes],
) -> Callable[..., requests.Response]:
    def send(
        _session: requests.Session,
        request: requests.PreparedRequest,
        **_kwargs: object,
    ) -> requests.Response:
        url = str(request.url)
        calls.append(url)
        response = requests.Response()
        response.status_code = 200
        response._content = bodies[url]
        response.url = url
        response.request = request
        response.history = []
        return response

    return send


def test_durable_request_journal_resumes_without_duplicate_issuance_and_matches_uninterrupted_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    first = "https://api.lever.co/v0/postings/acme?mode=json"
    second = "https://api.lever.co/v0/postings/other?mode=json"
    bodies = {
        first: b'{"publishedAt":"2026-07-27T10:00:00Z","id":"first"}',
        second: b'{"publishedAt":"2026-07-27T10:00:00Z","id":"second"}',
    }
    interrupted_root = tmp_path / "interrupted"
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _journalled_fixture_response(calls, bodies),
    )
    first_journal = _request_journal(interrupted_root, resume=False)
    first_recorder = ResponseRecorder(
        interrupted_root / "raw",
        AllowingController(),  # type: ignore[arg-type]
        journal=first_journal,
    )
    with first_recorder.installed():
        requests.Session().send(requests.Request("GET", first).prepare())

    resumed_journal = _request_journal(interrupted_root, resume=True)
    resumed_recorder = ResponseRecorder(
        interrupted_root / "raw",
        AllowingController(),  # type: ignore[arg-type]
        journal=resumed_journal,
    )
    with resumed_recorder.installed():
        assert (
            requests.Session().send(
                requests.Request("GET", first).prepare()
            ).content
            == bodies[first]
        )
        requests.Session().send(requests.Request("GET", second).prepare())
    resumed_journal.assert_replay_consumed()
    assert calls == [first, second]

    uninterrupted_root = tmp_path / "uninterrupted"
    uninterrupted_journal = _request_journal(
        uninterrupted_root,
        resume=False,
    )
    uninterrupted_clock = _ImmediateSendClock()
    uninterrupted_recorder = ResponseRecorder(
        uninterrupted_root / "raw",
        AllowingController(),  # type: ignore[arg-type]
        journal=uninterrupted_journal,
        clock_ns=uninterrupted_clock.monotonic_ns,
        sleeper=uninterrupted_clock.sleep,
    )
    uninterrupted_calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _journalled_fixture_response(uninterrupted_calls, bodies),
    )
    with uninterrupted_recorder.installed():
        requests.Session().send(requests.Request("GET", first).prepare())
        requests.Session().send(requests.Request("GET", second).prepare())
    assert uninterrupted_calls == [first, second]
    assert (
        resumed_journal.evidence()["raw_inventory_sha256"]
        == uninterrupted_journal.evidence()["raw_inventory_sha256"]
    )


def test_build_resume_after_simulated_kill_matches_uninterrupted_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    first = "https://api.lever.co/v0/postings/acme?mode=json"
    second = (
        "https://boards-api.greenhouse.io/v1/boards/acme/jobs"
        "?content=true"
    )
    bodies = {
        first: b'{"publishedAt":"2026-07-27T10:00:00Z","id":"first"}',
        second: b'{"updated_at":"2026-07-27T10:00:00Z","id":"second"}',
    }
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _journalled_fixture_response(calls, bodies),
    )
    monkeypatch.setattr(
        "career_automation.official_cohort.load_config",
        lambda _path: {
            "boards": {"enabled": ["greenhouse"]},
            "greenhouse": {"companies": {}},
            "search_terms": ["software"],
        },
    )
    phase = {"interrupt": True}

    class InterruptibleAdapter:
        def discover(self, _terms: list[str], *, live: bool) -> list[object]:
            assert live is True
            requests.Session().send(
                requests.Request("GET", first).prepare()
            )
            if phase["interrupt"]:
                raise KeyboardInterrupt("simulated supervisor boundary")
            requests.Session().send(
                requests.Request("GET", second).prepare()
            )
            return []

    monkeypatch.setattr(
        "career_automation.official_cohort.load_adapter",
        lambda _board, config: InterruptibleAdapter(),
    )

    class AllowingController:
        policy = SimpleNamespace(
            source_path=tmp_path / "policy.json",
            policy_sha256="3" * 64,
        )
        robots_events: tuple[object, ...] = ()

        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    config = tmp_path / "interrupted-config.yaml"
    config.write_text("exact build fixture\n", encoding="utf-8")
    interrupted = tmp_path / "interrupted-build"
    with pytest.raises(KeyboardInterrupt, match="supervisor boundary"):
        build(
            config,
            interrupted / "queue.json",
            interrupted / "raw",
            quarantine_index=EMPTY_TEST_QUARANTINE,
            access_controller=AllowingController(),
            evidence_output=interrupted / "capture-evidence.json",
            source_head="a" * 40,
        )
    assert calls == [first]
    assert not (interrupted / "capture-evidence.json").exists()

    phase["interrupt"] = False
    with pytest.raises(RuntimeError, match="only 0 current unique"):
        build(
            config,
            interrupted / "queue.json",
            interrupted / "raw",
            quarantine_index=EMPTY_TEST_QUARANTINE,
            access_controller=AllowingController(),
            evidence_output=interrupted / "capture-evidence.json",
            resume=True,
            source_head="a" * 40,
        )
    assert calls == [first, second]

    uninterrupted = tmp_path / "uninterrupted-build"
    uninterrupted_calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _journalled_fixture_response(uninterrupted_calls, bodies),
    )
    uninterrupted_config = tmp_path / "uninterrupted-config.yaml"
    uninterrupted_config.write_text(
        "exact build fixture\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="only 0 current unique"):
        build(
            uninterrupted_config,
            uninterrupted / "queue.json",
            uninterrupted / "raw",
            quarantine_index=EMPTY_TEST_QUARANTINE,
            access_controller=AllowingController(),
            evidence_output=uninterrupted / "capture-evidence.json",
            source_head="a" * 40,
        )
    assert uninterrupted_calls == [first, second]
    resumed_evidence = json.loads(
        (interrupted / "capture-evidence.json").read_text(
            encoding="utf-8"
        )
    )
    uninterrupted_evidence = json.loads(
        (uninterrupted / "capture-evidence.json").read_text(
            encoding="utf-8"
        )
    )
    assert (
        resumed_evidence["raw_store"]["inventory_sha256"]
        == uninterrupted_evidence["raw_store"]["inventory_sha256"]
    )
    assert resumed_evidence["request_journal"]["journal_sha256"]
    assert resumed_evidence["request_journal"]["identity_sha256"]


@pytest.mark.parametrize("tamper", ("raw", "journal"))
def test_durable_request_journal_refuses_raw_or_journal_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    url = "https://api.lever.co/v0/postings/acme?mode=json"
    body = b'{"publishedAt":"2026-07-27T10:00:00Z"}'

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    run_root = tmp_path / f"tamper-{tamper}"
    journal = _request_journal(run_root, resume=False)
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _journalled_fixture_response([], {url: body}),
    )
    recorder = ResponseRecorder(
        run_root / "raw",
        AllowingController(),  # type: ignore[arg-type]
        journal=journal,
    )
    with recorder.installed():
        requests.Session().send(requests.Request("GET", url).prepare())
    if tamper == "raw":
        target = next((run_root / "raw").rglob("*.response"))
        target.chmod(0o600)
        target.write_bytes(body + b"tampered")
        expected = "raw inventory hash mismatch"
    else:
        path = run_root / "request-journal.jsonl"
        payload = path.read_bytes().replace(b"api.lever.co", b"api.xever.co", 1)
        path.write_bytes(payload)
        expected = "hash chain"
    with pytest.raises(RuntimeError, match=expected):
        _request_journal(run_root, resume=True)


@pytest.mark.parametrize(
    "mismatch",
    ("configuration", "policy", "quarantine", "head"),
)
def test_durable_request_journal_refuses_run_identity_mismatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    run_root = tmp_path / f"identity-{mismatch}"
    _request_journal(run_root, resume=False)
    if mismatch == "configuration":
        config = run_root.parent / f"{run_root.name}-config.yaml"
        config.write_text("changed fixture configuration\n", encoding="utf-8")
        policy, quarantine, head = "3" * 64, "f" * 64, "a" * 40
    elif mismatch == "policy":
        policy, quarantine, head = "4" * 64, "f" * 64, "a" * 40
    elif mismatch == "quarantine":
        policy, quarantine, head = "3" * 64, "e" * 64, "a" * 40
    else:
        policy, quarantine, head = "3" * 64, "f" * 64, "b" * 40
    with pytest.raises(
        RuntimeError,
        match="configuration, policy, quarantine index, HEAD",
    ):
        _request_journal(
            run_root,
            resume=True,
            policy_sha256=policy,
            quarantine_index_sha256=quarantine,
            source_head=head,
        )


def test_content_send_stops_if_dns_changes_during_authority_throttle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(("93.184.216.34", "93.184.216.35"))

    def changing_resolver(
        _host: str,
        port: int,
    ) -> tuple[tuple[object, ...], ...]:
        return ((None, None, None, None, (next(answers), port)),)

    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        changing_resolver,
    )
    content_calls: list[str] = []

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    def content_send(
        _session: requests.Session,
        request: requests.PreparedRequest,
        **_kwargs: object,
    ) -> requests.Response:
        content_calls.append(str(request.url))
        raise AssertionError("changed DNS must stop before content transport")

    monkeypatch.setattr(requests.sessions.Session, "send", content_send)
    recorder = ResponseRecorder(
        tmp_path / "raw",
        AllowingController(),  # type: ignore[arg-type]
    )
    url = "https://api.lever.co/v0/postings/acme?mode=json"
    with recorder.installed(), pytest.raises(ValueError, match="DNS changed"):
        requests.Session().send(requests.Request("GET", url).prepare())
    assert content_calls == []
    assert recorder.send_events == []


class _ImmediateSendClock:
    def __init__(self) -> None:
        self.nanoseconds = 0
        self.sleeps: list[float] = []

    def monotonic_ns(self) -> int:
        return self.nanoseconds

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.nanoseconds += round(seconds * 1_000_000_000)


def _successful_content_send(
    calls: list[str],
) -> Callable[..., requests.Response]:
    def send(
        _session: requests.Session,
        request: requests.PreparedRequest,
        **_kwargs: object,
    ) -> requests.Response:
        calls.append(str(request.url))
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"publishedAt":"2026-07-27T10:00:00Z"}'
        response.url = str(request.url)
        response.request = request
        response.history = []
        return response

    return send


def test_immediate_send_tops_up_only_the_residual_same_host_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _successful_content_send(calls),
    )

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    clock = _ImmediateSendClock()
    recorder = ResponseRecorder(
        tmp_path / "raw",
        AllowingController(),  # type: ignore[arg-type]
        clock_ns=clock.monotonic_ns,
        sleeper=clock.sleep,
    )
    first = "https://api.lever.co/v0/postings/acme?mode=json"
    second = "https://api.lever.co/v0/postings/other?mode=json"
    with recorder.installed():
        requests.Session().send(requests.Request("GET", first).prepare())
        clock.nanoseconds = 9_750_000_000
        requests.Session().send(requests.Request("GET", second).prepare())
    assert calls == [first, second]
    assert clock.sleeps == [0.25]
    assert recorder.send_events[1]["immediate_send_top_up_seconds"] == 0.25
    timing = _timing_evidence(recorder.send_events, [])
    assert timing[1]["elapsed_seconds"] == 10.0
    assert timing[1]["compliant"] is True


def test_first_content_send_enforces_the_audited_robots_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _successful_content_send(calls),
    )
    clock = _ImmediateSendClock()
    host = "api.lever.co"

    class RobotsAwareController:
        def __init__(self) -> None:
            self.robots_events: list[dict[str, object]] = []

        def before_request(self, requested_url: str) -> RobotsReceipt:
            self.robots_events.append({
                "host": host,
                "requested_monotonic_ns": clock.monotonic_ns(),
            })
            return _transport_receipt(requested_url)

    controller = RobotsAwareController()
    recorder = ResponseRecorder(
        tmp_path / "raw",
        controller,
        clock_ns=clock.monotonic_ns,
        sleeper=clock.sleep,
    )
    content = f"https://{host}/v0/postings/acme?mode=json"
    with recorder.installed():
        requests.Session().send(
            requests.Request("GET", content).prepare()
        )
    assert calls == [content]
    assert clock.sleeps == [10.0]
    assert recorder.send_events[0]["immediate_send_top_up_seconds"] == 10.0
    timing = _timing_evidence(
        recorder.send_events,
        controller.robots_events,
    )
    assert timing == [{
        "send_sequence": 0,
        "host": host,
        "sent_at": recorder.send_events[0]["sent_at"],
        "prior_event": "robots",
        "elapsed_seconds": 10.0,
        "required_interval_seconds": 10.0,
        "compliant": True,
    }]


def test_timing_harness_detects_the_pre_fix_unenforced_robots_edge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _successful_content_send(calls),
    )

    class PreFixController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    clock = _ImmediateSendClock()
    recorder = ResponseRecorder(
        tmp_path / "raw",
        PreFixController(),  # type: ignore[arg-type]
        clock_ns=clock.monotonic_ns,
        sleeper=clock.sleep,
    )
    host = "api.lever.co"
    content = f"https://{host}/v0/postings/acme?mode=json"
    robots = [{
        "host": host,
        "requested_monotonic_ns": clock.monotonic_ns(),
    }]
    with recorder.installed():
        requests.Session().send(
            requests.Request("GET", content).prepare()
        )
    assert calls == [content]
    assert clock.sleeps == []
    timing = _timing_evidence(recorder.send_events, robots)
    assert timing[0]["prior_event"] == "robots"
    assert timing[0]["elapsed_seconds"] == 0.0
    assert timing[0]["compliant"] is False


def test_first_content_send_hard_fails_if_rate_top_up_remains_short(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _successful_content_send(calls),
    )
    host = "api.lever.co"
    readings = iter((0, 10_000_000_000, 10_000_000_000, 9_999_999_999))
    sleeps: list[float] = []

    class RobotsAwareController:
        robots_events = [{
            "host": host,
            "requested_monotonic_ns": 0,
        }]

        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    recorder = ResponseRecorder(
        tmp_path / "raw",
        RobotsAwareController(),  # type: ignore[arg-type]
        clock_ns=lambda: next(readings),
        sleeper=sleeps.append,
    )
    content = f"https://{host}/v0/postings/acme?mode=json"
    with recorder.installed(), pytest.raises(
        RuntimeError,
        match="immediate-send rate interval remains below policy",
    ):
        requests.Session().send(
            requests.Request("GET", content).prepare()
        )
    assert sleeps == [10.0]
    assert calls == []
    assert recorder.send_events == []


def test_immediate_send_does_not_sleep_when_actual_interval_is_compliant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _successful_content_send(calls),
    )

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    clock = _ImmediateSendClock()
    recorder = ResponseRecorder(
        tmp_path / "raw",
        AllowingController(),  # type: ignore[arg-type]
        clock_ns=clock.monotonic_ns,
        sleeper=clock.sleep,
    )
    first = "https://api.lever.co/v0/postings/acme?mode=json"
    second = "https://api.lever.co/v0/postings/other?mode=json"
    with recorder.installed():
        requests.Session().send(requests.Request("GET", first).prepare())
        clock.nanoseconds = 10_500_000_000
        requests.Session().send(requests.Request("GET", second).prepare())
    assert calls == [first, second]
    assert clock.sleeps == []
    assert recorder.send_events[1]["immediate_send_top_up_seconds"] == 0.0


def test_immediate_send_dns_drift_after_top_up_stops_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver_calls = 0

    def changing_resolver(
        _host: str,
        port: int,
    ) -> tuple[tuple[object, ...], ...]:
        nonlocal resolver_calls
        resolver_calls += 1
        address = "93.184.216.34" if resolver_calls <= 4 else "93.184.216.35"
        return ((None, None, None, None, (address, port)),)

    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        changing_resolver,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        requests.sessions.Session,
        "send",
        _successful_content_send(calls),
    )

    class AllowingController:
        def before_request(self, requested_url: str) -> RobotsReceipt:
            return _transport_receipt(requested_url)

    clock = _ImmediateSendClock()
    recorder = ResponseRecorder(
        tmp_path / "raw",
        AllowingController(),  # type: ignore[arg-type]
        clock_ns=clock.monotonic_ns,
        sleeper=clock.sleep,
    )
    first = "https://api.lever.co/v0/postings/acme?mode=json"
    second = "https://api.lever.co/v0/postings/other?mode=json"
    with recorder.installed():
        requests.Session().send(requests.Request("GET", first).prepare())
        clock.nanoseconds = 9_750_000_000
        with pytest.raises(ValueError, match="DNS changed after immediate-send"):
            requests.Session().send(requests.Request("GET", second).prepare())
    assert calls == [first]
    assert clock.sleeps == [0.25]
    assert len(recorder.send_events) == 1


def test_denied_robots_response_is_preserved_before_content_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    host = "careersdeltacapita.recruitee.com"
    robots = b"authentication required"

    class DeniedRobots:
        def fetch(self, _engine: str, url: str, **_kwargs: object) -> dict[str, object]:
            assert url == f"https://{host}/robots.txt"
            return {
                "url": url,
                "status": 401,
                "body_base64": base64.b64encode(robots).decode(),
                "body_bytes": len(robots),
                "history": [],
            }

    attestation = TermsAttestation(
        host=host,
        terms_url="https://tellent.com/terms",
        determination="public_read_only_research_permitted",
        reviewed_at="2026-07-26T18:00:00+00:00",
        reviewed_by="Test Operator",
        reviewer_type="human_operator",
        notes="Offline exact-host test.",
    )
    policy = PublicAccessPolicy(
        {host: attestation},
        policy_sha256="2" * 64,
        now=datetime(2026, 7, 27, 12, tzinfo=timezone.utc),
    )
    cache = RawResponseCache(tmp_path / "raw")
    robots_client = AuditedRobotsClient(DeniedRobots(), cache)
    controller = AuditedAccessController(
        PublicAccessController(policy, robots_client, cache),
        robots_client,
    )
    content = f"https://{host}/api/offers/"
    with pytest.raises(PublicAccessDenied, match="ROBOTS_DISALLOWED: HTTP 401"):
        controller.before_request(content)
    assert len(controller.robots_events) == 1
    event = controller.robots_events[0]
    assert event["decision"] == "denied"
    assert event["status"] == 401
    assert event["byte_count"] == len(robots)
    assert cache.resolve(str(event["raw_response"]), str(event["sha256"])) == robots


def test_resume_revalidates_journalled_robots_without_reissuing_robots_or_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "career_automation.employer_research.socket.getaddrinfo",
        _public_resolver,
    )
    host = "api.lever.co"
    content_url = f"https://{host}/v0/postings/acme?mode=json"
    robots_body = b"User-agent: *\nAllow: /\n"
    content_body = b'{"publishedAt":"2026-07-27T10:00:00Z"}'
    calls = {"robots": 0, "content": 0}

    class AllowedRobots:
        def fetch(
            self,
            _engine: str,
            url: str,
            **_kwargs: object,
        ) -> dict[str, object]:
            calls["robots"] += 1
            return {
                "url": url,
                "status": 200,
                "body_base64": base64.b64encode(robots_body).decode(),
                "body_bytes": len(robots_body),
                "history": [],
                "text": robots_body.decode(),
            }

    def content_send(
        _session: requests.Session,
        request: requests.PreparedRequest,
        **_kwargs: object,
    ) -> requests.Response:
        calls["content"] += 1
        response = requests.Response()
        response.status_code = 200
        response._content = content_body
        response.url = str(request.url)
        response.request = request
        response.history = []
        return response

    monkeypatch.setattr(requests.sessions.Session, "send", content_send)
    attestation = TermsAttestation(
        host=host,
        terms_url="https://www.lever.co/legal/terms-of-service",
        determination="public_read_only_research_permitted",
        reviewed_at="2026-07-26T18:00:00+00:00",
        reviewed_by="Test Operator",
        reviewer_type="human_operator",
        notes="Offline exact-host resume test.",
    )
    policy = PublicAccessPolicy(
        {host: attestation},
        policy_sha256="3" * 64,
        now=datetime(2026, 7, 27, 12, tzinfo=timezone.utc),
    )
    run_root = tmp_path / "robots-resume"
    journal = _request_journal(run_root, resume=False)
    cache = RawResponseCache(run_root / "raw")
    robots = AuditedRobotsClient(
        AllowedRobots(),
        cache,
        journal=journal,
    )
    elapsed = {"seconds": 0.0}

    def clock() -> float:
        return elapsed["seconds"]

    def sleep(seconds: float) -> None:
        elapsed["seconds"] += seconds

    controller = AuditedAccessController(
        PublicAccessController(
            policy,
            robots,
            cache,
            clock=clock,
            sleeper=sleep,
        ),
        robots,
    )
    recorder = ResponseRecorder(
        run_root / "raw",
        controller,
        journal=journal,
    )
    with recorder.installed():
        requests.Session().send(
            requests.Request("GET", content_url).prepare()
        )
    assert calls == {"robots": 1, "content": 1}

    resumed_journal = _request_journal(run_root, resume=True)
    resumed_cache = RawResponseCache(run_root / "raw")
    resumed_robots = AuditedRobotsClient(
        AllowedRobots(),
        resumed_cache,
        journal=resumed_journal,
    )
    resumed_controller = AuditedAccessController(
        PublicAccessController(
            policy,
            resumed_robots,
            resumed_cache,
            clock=clock,
            sleeper=sleep,
        ),
        resumed_robots,
    )
    resumed_recorder = ResponseRecorder(
        run_root / "raw",
        resumed_controller,
        journal=resumed_journal,
    )
    with resumed_recorder.installed():
        response = requests.Session().send(
            requests.Request("GET", content_url).prepare()
        )
    assert response.content == content_body
    assert calls == {"robots": 1, "content": 1}
    assert resumed_robots.events[0]["decision"] == "allowed"
    resumed_journal.assert_replay_consumed()


def test_timing_evidence_binds_robots_and_content_to_ten_second_floor() -> None:
    robots = [{
        "host": "jobs.example.test",
        "requested_monotonic_ns": 1_000_000_000,
    }]
    sends = [
        {
            "send_sequence": 0,
            "host": "jobs.example.test",
            "sent_at": "2026-07-27T12:00:11+00:00",
            "sent_monotonic_ns": 11_000_000_000,
            "required_interval_seconds": 10.0,
        },
        {
            "send_sequence": 1,
            "host": "jobs.example.test",
            "sent_at": "2026-07-27T12:00:21+00:00",
            "sent_monotonic_ns": 21_000_000_000,
            "required_interval_seconds": 10.0,
        },
    ]
    evidence = _timing_evidence(sends, robots)
    assert [row["prior_event"] for row in evidence] == ["robots", "content"]
    assert [row["elapsed_seconds"] for row in evidence] == [10.0, 10.0]
    assert all(row["compliant"] is True for row in evidence)


def test_selection_trace_covers_duplicates_and_rows_below_exact_cut() -> None:
    candidates = []
    for number in range(32):
        candidates.append({
            "job_key": f"greenhouse:{number:02d}",
            "url": f"https://jobs.example.test/{number:02d}",
            "content_sha256": f"{number:064x}",
            "payload_hash": f"{number + 100:064x}",
            "opportunity0_decision": {"score_bp": 9000 - number},
            "temporal_admission": {
                "publisher_time": "2026-07-27T12:00:00+00:00",
            },
            "raw_response_refs": [{"sha256": f"{number:064x}"}],
        })
    candidates.insert(1, {
        **candidates[0],
        "job_key": "greenhouse:duplicate-url",
    })
    selected, trace = _select_candidates(candidates, EMPTY_TEST_QUARANTINE)
    assert len(selected) == 30
    assert len(trace) == 33
    assert trace[1]["disposition"] == "duplicate_url"
    assert [row["disposition"] for row in trace].count("selected") == 30
    assert [row["disposition"] for row in trace].count("below_exact_30_cut") == 2


def test_below_floor_run_writes_evidence_but_no_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("test-only exact bytes\n", encoding="utf-8")
    output = tmp_path / "queue.json"
    evidence = tmp_path / "capture-evidence.json"
    raw = tmp_path / "raw"

    monkeypatch.setattr(
        "career_automation.official_cohort.load_config",
        lambda _path: {
            "boards": {"enabled": ["greenhouse"]},
            "greenhouse": {"companies": {}},
            "search_terms": ["software"],
        },
    )

    class EmptyAdapter:
        def discover(self, _terms: list[str], *, live: bool) -> list[object]:
            assert live is True
            return []

    monkeypatch.setattr(
        "career_automation.official_cohort.load_adapter",
        lambda _board, config: EmptyAdapter(),
    )
    controller = SimpleNamespace(
        policy=SimpleNamespace(
            source_path=tmp_path / "policy.json",
            policy_sha256="3" * 64,
        ),
        robots_events=(),
    )
    with pytest.raises(RuntimeError, match="only 0 current unique"):
        build(
            config,
            output,
            raw,
            quarantine_index=EMPTY_TEST_QUARANTINE,
            access_controller=controller,
            evidence_output=evidence,
        )
    assert not output.exists()
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["result_status"] == "rejected_below_admission_floor"
    assert payload["selected_count"] == 0
    assert payload["raw_store"]["inventory"] == []
    assert (
        payload["failed_holdout_quarantine"]
        == EMPTY_TEST_QUARANTINE.binding()
    )
    assert evidence.stat().st_mode & 0o777 == 0o600
    claimed = payload.pop("evidence_sha256")
    assert claimed == hashlib.sha256(_canonical(payload)).hexdigest()


def test_overnight_config_projects_one_canonical_official_interface() -> None:
    config = load_config(OVERNIGHT)
    assert "official_sources" not in config

    names, sections, terms = _validate_config(config)
    enabled = set(config["boards"]["enabled"])
    assert names == sorted(enabled & OFFICIAL_ADAPTERS)
    assert set(names) == OFFICIAL_ADAPTERS, (
        "config.overnight.yaml must enable every supported official adapter"
    )
    assert set(names).isdisjoint(AGGREGATORS)
    assert sections == {name: config.get(name, {}) for name in names}
    assert sections["greenhouse"]["companies"]["anthropic"] == "Anthropic"
    assert sections["lever"]["companies"]["palantir"] == "Palantir Technologies"
    assert terms == config["search_terms"]


def test_discovery_boards_are_filtered_without_becoming_authorities() -> None:
    config = {
        "boards": {
            "enabled": [
                "himalayas", "greenhouse", "jobicy", "workable", "remotefirst",
            ]
        },
        "greenhouse": {"companies": {"example": "Example"}},
        "workable": {"companies": {"example": "Example"}},
        "search_terms": ["software engineer"],
    }
    names, sections, terms = _validate_config(config)
    assert names == ["greenhouse", "workable"]
    assert set(sections) == set(names)
    assert terms == ["software engineer"]


def test_live_official_cohort_refuses_to_start_without_access_authority(
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="requires public access authority"):
        build(
            tmp_path / "not-read-without-authority.yaml",
            tmp_path / "output.json",
            tmp_path / "raw",
            quarantine_index=EMPTY_TEST_QUARANTINE,
        )


def test_live_greenhouse_authority_uses_current_public_job_board_api_host() -> None:
    frozen = next(
        row for row in ATS_AUTHORITY_CANARIES
        if row.job_key.startswith("greenhouse:")
    )
    live = next(
        row for row in LIVE_ATS_AUTHORITY_CANARIES
        if row.job_key == frozen.job_key
    )
    assert frozen.authority_url.startswith("https://api.greenhouse.io/")
    assert live.authority_url == (
        "https://boards-api.greenhouse.io/v1/boards/anthropic/jobs/5030244008"
    )
    assert live.authority_hosts == (
        "job-boards.greenhouse.io",
        "boards-api.greenhouse.io",
    )
    assert DEFAULT_ATS_ROUTE_ADAPTERS["greenhouse"].authority_hosts == (
        "boards-api.greenhouse.io",
    )


@pytest.mark.parametrize(
    "admitted_host",
    ("job-boards.greenhouse.io", "job-boards.eu.greenhouse.io"),
)
def test_greenhouse_admitted_identity_hosts_transform_to_current_api(
    admitted_host: str,
) -> None:
    task = SimpleNamespace(
        job_key="greenhouse:jetbrains:4695363101",
        url=f"https://{admitted_host}/jetbrains/jobs/4695363101",
    )
    adapter = DEFAULT_ATS_ROUTE_ADAPTERS["greenhouse"]

    assert adapter.admitted_hosts == (
        "job-boards.greenhouse.io",
        "job-boards.eu.greenhouse.io",
    )
    assert adapter.authority_hosts == ("boards-api.greenhouse.io",)
    authority_url = adapter.authority_url(task)
    assert authority_url == (
        "https://boards-api.greenhouse.io/v1/boards/jetbrains/jobs/4695363101"
    )
    assert urlsplit(authority_url).hostname == "boards-api.greenhouse.io"
    assert "job-boards.eu.greenhouse.io" not in adapter.authority_hosts
    assert "job-boards.eu.greenhouse.io" not in authority_url
    adapter._validate_route(task, task.url)
    adapter._validate_route(task, authority_url, final=True)


@pytest.mark.parametrize(
    "url",
    (
        "https://job-boards.us.greenhouse.io/jetbrains/jobs/4695363101",
        "https://evil.job-boards.eu.greenhouse.io/jetbrains/jobs/4695363101",
        "https://job-boards.eu.greenhouse.io/physicsx/jobs/4695363101",
        "https://job-boards.eu.greenhouse.io/jetbrains/jobs/1234567890",
        "https://job-boards.eu.greenhouse.io/jetbrains/jobs/4695363101?source=test",
        "https://job-boards.eu.greenhouse.io/jetbrains/jobs/4695363101#details",
        "ftp://job-boards.eu.greenhouse.io/jetbrains/jobs/4695363101",
        "https://user:pass@job-boards.eu.greenhouse.io/jetbrains/jobs/4695363101",
        "https://job-boards.eu.greenhouse.io/jetbrains/job/4695363101",
    ),
)
def test_greenhouse_eu_admitted_identity_host_rejects_route_confusion(
    url: str,
) -> None:
    task = SimpleNamespace(
        job_key="greenhouse:jetbrains:4695363101",
        url=url,
    )

    with pytest.raises(ValueError):
        DEFAULT_ATS_ROUTE_ADAPTERS["greenhouse"]._validate_route(task, url)


def test_live_workable_authority_uses_tenant_bound_markdown_route() -> None:
    task = SimpleNamespace(
        job_key="workable:suade:67D795D3DE",
        url="https://apply.workable.com/j/67D795D3DE",
    )
    adapter = DEFAULT_ATS_ROUTE_ADAPTERS["workable"]
    assert adapter.authority_url(task) == (
        "https://apply.workable.com/suade/jobs/view/67D795D3DE.md"
    )
    adapter._validate_route(task, adapter.authority_url(task), final=True)


def test_live_smartrecruiters_authority_remains_on_public_job_page() -> None:
    task = SimpleNamespace(
        job_key="smartrecruiters:Entain:744000133551599",
        url=(
            "https://jobs.smartrecruiters.com/Entain/"
            "744000133551599-platform-engineer-i"
        ),
    )
    adapter = DEFAULT_ATS_ROUTE_ADAPTERS["smartrecruiters"]
    assert adapter.authority_url(task) == task.url
    assert urlsplit(adapter.authority_url(task)).hostname == (
        "jobs.smartrecruiters.com"
    )
    adapter._validate_route(task, adapter.authority_url(task), final=True)


@pytest.mark.parametrize(
    ("job_key", "url"),
    (
        ("workable:suade:OTHER", "https://apply.workable.com/j/67D795D3DE"),
        ("workable:suade:67D795D3DE", "https://apply.workable.com/suade/jobs/view/67D795D3DE.md"),
    ),
)
def test_live_workable_authority_rejects_noncanonical_admitted_identity(
    job_key: str,
    url: str,
) -> None:
    task = SimpleNamespace(job_key=job_key, url=url)
    with pytest.raises(ValueError, match="admitted path"):
        DEFAULT_ATS_ROUTE_ADAPTERS["workable"].authority_url(task)


@pytest.mark.parametrize(
    "attack",
    (None, "wrong-policy", "existing-quarantine", "quarantine-failure"),
)
def test_canary_publication_retains_replayable_content_and_robots_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str | None,
) -> None:
    stamp = "2026-07-27T02:00:00+00:00"
    attestations = {}
    for record in LIVE_ATS_AUTHORITY_CANARIES:
        host = urlsplit(record.authority_url).hostname or ""
        attestations[host] = TermsAttestation(
            host=host,
            terms_url=f"https://{host}/terms",
            determination="public_read_only_research_permitted",
            reviewed_at="2026-07-26T18:00:00+00:00",
            reviewed_by="Offline Test Operator",
            reviewer_type="human_operator",
            notes="Synthetic offline canary portability test.",
        )
    policy_hash = hashlib.sha256(b"offline-canary-policy").hexdigest()
    policy = PublicAccessPolicy(
        attestations,
        policy_sha256=policy_hash,
        now=datetime(2026, 7, 27, 2, tzinfo=timezone.utc),
    )

    class FakeTransport:
        def __init__(self, cache: RawResponseCache, **_: object) -> None:
            self.cache = cache

    class FakeRetriever:
        def __init__(
            self,
            cache: RawResponseCache,
            *,
            retriever: FakeTransport,
        ) -> None:
            self.cache = cache

        def retrieve_plan(
            self,
            task: object,
        ) -> tuple[list[Citation], list[dict[str, object]]]:
            job_key = str(getattr(task, "job_key"))
            record = next(
                row for row in LIVE_ATS_AUTHORITY_CANARIES
                if row.job_key == job_key
            )
            body = (
                f'<meta property="article:published_time" content="{stamp}">'
                f"<main>{record.company} — {record.title}</main>"
            ).encode()
            content_hash, content_ref = self.cache.store(body)
            robots = b"User-agent: *\nAllow: /\n"
            robots_hash, robots_ref = self.cache.store(robots)
            host = urlsplit(record.authority_url).hostname or ""
            receipt = RobotsReceipt(
                host=host,
                robots_url=f"https://{host}/robots.txt",
                final_url=f"https://{host}/robots.txt",
                status_code=200,
                content_sha256=robots_hash,
                raw_response_ref=robots_ref,
                redirect_history=[],
                retrieved_at=stamp,
                user_agent=USER_AGENT,
                requested_url=record.authority_url,
                allowed=True,
                crawl_delay_seconds=10.0,
                terms_policy_sha256=policy_hash,
                terms_attestation=asdict(attestations[host]),
            )
            citation = Citation(
                id=f"source:{job_key}",
                url=record.authority_url,
                captured_at=stamp,
                retrieved_at=stamp,
                content_sha256=content_hash,
                raw_response_ref=content_ref,
                status_code=200,
                requested_url=record.authority_url,
                published_at=stamp,
                source_kind="official_vacancy",
                canonical_publisher=host,
                canonical_article=record.authority_url,
                publisher_date_evidence=(
                    f'<meta property="article:published_time" content="{stamp}">'
                ),
                retrieval_engine="scrapling-static",
                access_receipt={
                    **asdict(receipt),
                    **(
                        {"terms_policy_sha256": "0" * 64}
                        if attack in {"wrong-policy", "quarantine-failure"} else {}
                    ),
                },
            )
            if record.job_key.startswith("greenhouse:"):
                assert record.admitted_url != record.authority_url
                assert citation.requested_url == record.authority_url
                assert citation.access_receipt["requested_url"] == record.authority_url
            return [citation], []

    monkeypatch.setattr(canary_capture, "ScraplingPublicRetriever", FakeTransport)
    monkeypatch.setattr(canary_capture, "PortableAuthorityRetriever", FakeRetriever)
    destination = tmp_path / "canaries"
    quarantine = tmp_path / "canary-failure"
    command = ["python", "capture-canaries", "--offline-test"]
    if attack == "existing-quarantine":
        quarantine.mkdir()
        sentinel = quarantine / "sentinel"
        sentinel.write_text("do not overwrite", encoding="utf-8")
        with pytest.raises(RuntimeError, match="quarantine already exists"):
            canary_capture.capture(
                destination,
                policy,
                failure_quarantine=quarantine,
                command=command,
            )
        assert sentinel.read_text(encoding="utf-8") == "do not overwrite"
        assert not destination.exists()
        return
    if attack == "wrong-policy":
        with pytest.raises(ValueError, match="operator-presented policy"):
            canary_capture.capture(
                destination,
                policy,
                failure_quarantine=quarantine,
                command=command,
            )
        assert not destination.exists()
        stage = quarantine / "stage"
        manifest = json.loads(
            (stage / "canary-failure-manifest.json").read_text(encoding="utf-8")
        )
        assert manifest["schema_version"] == "jaa04.canary-failure-quarantine.v2"
        assert manifest["accepted"] is False
        assert manifest["source_commit"]
        assert manifest["access_policy_sha256"] == policy_hash
        assert manifest["command"] == command
        assert manifest["failing_job_key"] == LIVE_ATS_AUTHORITY_CANARIES[0].job_key
        assert manifest["exception_type"] == "ValueError"
        assert "operator-presented policy" in manifest["exception_message"]
        assert [row["status"] for row in manifest["canary_progress"]] == [
            "started", "pending", "pending",
        ]
        assert len(list((stage / ".raw" / "sha256").glob("*/*"))) == 2
        return
    if attack == "quarantine-failure":
        def fail_quarantine(*_: object, **__: object) -> None:
            raise OSError("injected quarantine failure")

        monkeypatch.setattr(canary_capture, "_quarantine_failure", fail_quarantine)
        with pytest.raises(ValueError, match="operator-presented policy") as raised:
            canary_capture.capture(
                destination,
                policy,
                failure_quarantine=quarantine,
                command=command,
            )
        notes = getattr(raised.value, "__notes__", [])
        assert len(notes) == 1
        assert "injected quarantine failure" in notes[0]
        preserved = next(tmp_path.glob("jaa04-canaries-*"))
        assert str(preserved) in notes[0]
        assert len(list((preserved / ".raw" / "sha256").glob("*/*"))) == 2
        assert not destination.exists()
        return
    canary_capture.capture(
        destination,
        policy,
        failure_quarantine=quarantine,
        command=command,
    )
    assert not quarantine.exists()

    cache = RawResponseCache(destination / ".raw")
    assert (destination / ".raw" / "sha256").is_dir()
    assert sorted(path.name for path in destination.glob("*.json")) == [
        "ashby.json",
        "greenhouse.json",
        "workable.json",
    ]
    for artifact_path in destination.glob("*.json"):
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        row = artifact["captures"][0]
        embedded = base64.b64decode(row["raw_response_base64"], validate=True)
        assert cache.resolve(
            row["sidecar_raw_response_ref"],
            row["content_sha256"],
        ) == embedded
        replay_access_receipt(
            row["access_receipt"],
            cache,
            content_urls=(row["requested_url"], row["url"]),
            content_retrieved_at=row["retrieved_at"],
            policies={policy_hash: policy},
        )


def test_canary_failure_manifest_serializes_typed_retrieval_attempts(
    tmp_path: Path,
) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    quarantine = tmp_path / "failure"
    quarantine.mkdir(mode=0o700)
    cache = RawResponseCache(stage / ".raw")
    body = b"<html><noscript>Please enable JavaScript.</noscript></html>"
    digest, reference = cache.store(body)
    robots = b"User-agent: *\nAllow: /\n"
    robots_digest, robots_reference = cache.store(robots)
    policy_hash = hashlib.sha256(b"offline-attempt-policy").hexdigest()
    host = "jobs.example.test"
    stamp = "2026-07-27T02:00:00+00:00"
    attestation = TermsAttestation(
        host=host,
        terms_url=f"https://{host}/terms",
        determination="public_read_only_research_permitted",
        reviewed_at="2026-07-26T18:00:00+00:00",
        reviewed_by="Offline Test Operator",
        reviewer_type="human_operator",
        notes="Synthetic offline failed-attempt test.",
    )
    policy = PublicAccessPolicy(
        {host: attestation},
        policy_sha256=policy_hash,
        now=datetime(2026, 7, 27, 2, tzinfo=timezone.utc),
    )
    requested_url = f"https://{host}/jobs/engineer"
    receipt = RobotsReceipt(
        host=host,
        robots_url=f"https://{host}/robots.txt",
        final_url=f"https://{host}/robots.txt",
        status_code=200,
        content_sha256=robots_digest,
        raw_response_ref=robots_reference,
        redirect_history=[],
        retrieved_at=stamp,
        user_agent=USER_AGENT,
        requested_url=requested_url,
        allowed=True,
        crawl_delay_seconds=10.0,
        terms_policy_sha256=policy_hash,
        terms_attestation=asdict(attestation),
    )
    attempt = PublicRetrievalAttempt(
        engine="dynamic",
        requested_url=requested_url,
        final_url=requested_url,
        status_code=200,
        body_bytes=len(body),
        content_sha256=digest,
        raw_response_ref=reference,
        access_receipt_json=json.dumps(
            asdict(receipt),
            sort_keys=True,
            separators=(",", ":"),
        ),
        renderer_shell=True,
        retrieved_at=stamp,
    )
    failure = PublicRetrievalExhausted(
        "static and dynamic public retrieval were exhausted",
        (attempt,),
    )
    canary_capture._quarantine_failure(
        stage,
        quarantine,
        destination=tmp_path / "success",
        access_policy=policy,
        command=["python", "capture-canaries", "--offline-test"],
        progress=[{"job_key": "ashby:test:vacancy", "status": "started"}],
        failing_job_key="ashby:test:vacancy",
        failure=failure,
    )
    manifest = json.loads(
        (quarantine / "stage" / "canary-failure-manifest.json").read_bytes()
    )
    assert manifest["schema_version"] == "jaa04.canary-failure-quarantine.v2"
    assert manifest["exception_type"] == "PublicRetrievalExhausted"
    assert manifest["retrieval_attempts"] == [{
        "job_key": "ashby:test:vacancy",
        "attempt": attempt.as_dict(),
    }]
    assert RawResponseCache(quarantine / "stage" / ".raw").resolve(
        reference,
        digest,
    ) == body
    replay_access_receipt(
        manifest["retrieval_attempts"][0]["attempt"]["access_receipt"],
        RawResponseCache(quarantine / "stage" / ".raw"),
        content_urls=(requested_url,),
        content_retrieved_at=stamp,
        policies={policy_hash: policy},
    )


@pytest.mark.parametrize(
    ("failure_kind", "message"),
    (
        ("validation", "ATS authority bytes do not identify"),
        ("planning", "injected planning failure after retrieval"),
    ),
)
def test_canary_post_retrieval_failures_preserve_replayable_typed_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    message: str,
) -> None:
    record = LIVE_ATS_AUTHORITY_CANARIES[0]
    host = urlsplit(record.authority_url).hostname or ""
    stamp = "2026-07-27T02:00:00+00:00"
    policy_hash = hashlib.sha256(b"post-retrieval-policy").hexdigest()
    attestation = TermsAttestation(
        host=host,
        terms_url=f"https://{host}/terms",
        determination="public_read_only_research_permitted",
        reviewed_at="2026-07-26T18:00:00+00:00",
        reviewed_by="Offline Test Operator",
        reviewer_type="human_operator",
        notes="Synthetic offline post-retrieval failure test.",
    )
    policy = PublicAccessPolicy(
        {host: attestation},
        policy_sha256=policy_hash,
        now=datetime(2026, 7, 27, 2, tzinfo=timezone.utc),
    )
    production_retriever = canary_capture.PortableAuthorityRetriever

    class FakeTransport:
        def __init__(self, cache: RawResponseCache, **_: object) -> None:
            self.cache = cache
            self.retrieval_attempts: list[PublicRetrievalAttempt] = []

        def retrieve(self, task: object) -> Citation:
            body = b"<html><main>Job not found. The requested job was not found.</main></html>"
            digest, reference = self.cache.store(body)
            robots_digest, robots_reference = self.cache.store(
                b"User-agent: *\nAllow: /\n"
            )
            receipt = RobotsReceipt(
                host=host,
                robots_url=f"https://{host}/robots.txt",
                final_url=f"https://{host}/robots.txt",
                status_code=200,
                content_sha256=robots_digest,
                raw_response_ref=robots_reference,
                redirect_history=[],
                retrieved_at=stamp,
                user_agent=USER_AGENT,
                requested_url=record.authority_url,
                allowed=True,
                crawl_delay_seconds=10.0,
                terms_policy_sha256=policy_hash,
                terms_attestation=asdict(attestation),
            )
            self.retrieval_attempts.append(PublicRetrievalAttempt(
                engine="dynamic",
                requested_url=record.authority_url,
                final_url=record.authority_url,
                status_code=200,
                body_bytes=len(body),
                content_sha256=digest,
                raw_response_ref=reference,
                access_receipt_json=json.dumps(
                    asdict(receipt),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                renderer_shell=False,
                retrieved_at=stamp,
            ))
            return Citation(
                id=f"source:{record.job_key}",
                url=record.authority_url,
                captured_at=stamp,
                retrieved_at=stamp,
                content_sha256=digest,
                raw_response_ref=reference,
                status_code=200,
                requested_url=record.authority_url,
                source_kind="official_vacancy",
                canonical_publisher=host,
                canonical_article=record.authority_url,
                retrieval_engine="scrapling-dynamic",
                access_receipt=asdict(receipt),
            )

    class FakeRetriever:
        def __init__(
            self,
            cache: RawResponseCache,
            *,
            retriever: FakeTransport,
        ) -> None:
            self.cache = cache
            self.retriever = retriever

        def retrieve_plan(
            self,
            task: object,
        ) -> tuple[list[Citation], list[dict[str, object]]]:
            citation = self.retriever.retrieve(task)
            if failure_kind == "validation":
                production_retriever._validate_canary_capture(
                    record,
                    citation,
                    self.cache,
                )
            raise RuntimeError(message)

    monkeypatch.setattr(canary_capture, "ScraplingPublicRetriever", FakeTransport)
    monkeypatch.setattr(canary_capture, "PortableAuthorityRetriever", FakeRetriever)
    destination = tmp_path / "canaries"
    quarantine = tmp_path / "canary-failure"
    expected = ValueError if failure_kind == "validation" else RuntimeError
    with pytest.raises(expected, match=message):
        canary_capture.capture(
            destination,
            policy,
            failure_quarantine=quarantine,
            command=["python", "capture-canaries", "--offline-test"],
        )
    assert not destination.exists()
    manifest = json.loads(
        (quarantine / "stage" / "canary-failure-manifest.json").read_bytes()
    )
    assert manifest["schema_version"] == "jaa04.canary-failure-quarantine.v2"
    assert manifest["exception_type"] == expected.__name__
    assert len(manifest["retrieval_attempts"]) == 1
    preserved = manifest["retrieval_attempts"][0]
    assert preserved["job_key"] == record.job_key
    attempt = preserved["attempt"]
    cache = RawResponseCache(quarantine / "stage" / ".raw")
    assert len(cache.resolve(
        attempt["raw_response_ref"],
        attempt["content_sha256"],
    )) == attempt["body_bytes"]
    replay_access_receipt(
        attempt["access_receipt"],
        cache,
        content_urls=(attempt["requested_url"], attempt["final_url"]),
        content_retrieved_at=attempt["retrieved_at"],
        policies={policy_hash: policy},
    )


def test_canary_failure_quarantine_rejects_tampered_attempt_bytes(
    tmp_path: Path,
) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    quarantine = tmp_path / "failure"
    quarantine.mkdir(mode=0o700)
    cache = RawResponseCache(stage / ".raw")
    body = b"<html><main>Captured vacancy bytes.</main></html>"
    digest, reference = cache.store(body)
    target = stage / ".raw" / reference
    target.chmod(0o600)
    target.write_bytes(body + b"tampered")
    policy_hash = hashlib.sha256(b"tamper-attempt-policy").hexdigest()
    host = "jobs.example.test"
    stamp = "2026-07-27T02:00:00+00:00"
    attestation = TermsAttestation(
        host=host,
        terms_url=f"https://{host}/terms",
        determination="public_read_only_research_permitted",
        reviewed_at="2026-07-26T18:00:00+00:00",
        reviewed_by="Offline Test Operator",
        reviewer_type="human_operator",
        notes="Synthetic offline tampered-attempt test.",
    )
    policy = PublicAccessPolicy(
        {host: attestation},
        policy_sha256=policy_hash,
        now=datetime(2026, 7, 27, 2, tzinfo=timezone.utc),
    )
    robots_digest, robots_reference = cache.store(b"User-agent: *\nAllow: /\n")
    requested_url = f"https://{host}/jobs/engineer"
    receipt = RobotsReceipt(
        host=host,
        robots_url=f"https://{host}/robots.txt",
        final_url=f"https://{host}/robots.txt",
        status_code=200,
        content_sha256=robots_digest,
        raw_response_ref=robots_reference,
        redirect_history=[],
        retrieved_at=stamp,
        user_agent=USER_AGENT,
        requested_url=requested_url,
        allowed=True,
        crawl_delay_seconds=10.0,
        terms_policy_sha256=policy_hash,
        terms_attestation=asdict(attestation),
    )
    attempt = PublicRetrievalAttempt(
        engine="static",
        requested_url=requested_url,
        final_url=requested_url,
        status_code=200,
        body_bytes=len(body),
        content_sha256=digest,
        raw_response_ref=reference,
        access_receipt_json=json.dumps(
            asdict(receipt),
            sort_keys=True,
            separators=(",", ":"),
        ),
        renderer_shell=False,
        retrieved_at=stamp,
    )
    with pytest.raises(ValueError, match="raw response hash mismatch"):
        canary_capture._quarantine_failure(
            stage,
            quarantine,
            destination=tmp_path / "success",
            access_policy=policy,
            command=["python", "capture-canaries", "--offline-test"],
            progress=[{"job_key": "greenhouse:test:vacancy", "status": "started"}],
            failing_job_key="greenhouse:test:vacancy",
            failure=ValueError("post-retrieval validation failed"),
            retrieval_attempts=[("greenhouse:test:vacancy", attempt)],
        )
    assert stage.exists()
    assert not (quarantine / "stage").exists()


@pytest.mark.parametrize(
    ("config", "message"),
    (
        (
            {"official_sources": {"greenhouse": {}}},
            "official_sources is retired",
        ),
        (
            {"boards": {"enabled": ["himalayas", "jobicy"]}},
            "no supported official adapters",
        ),
        (
            {"boards": {"enabled": "greenhouse"}},
            "boards.enabled must be a non-empty list",
        ),
        (
            {"boards": {"enabled": ["greenhouse"]}, "greenhouse": []},
            "greenhouse configuration must be a mapping",
        ),
        (
            {
                "boards": {"enabled": ["greenhouse"]},
                "search_terms": ["software", ""],
            },
            "search_terms entries must be non-empty strings",
        ),
        (
            {
                "boards": {"enabled": ["greenhouse"]},
                "search_terms": [],
            },
            "search_terms must be a non-empty list",
        ),
    ),
)
def test_competing_or_malformed_config_fails_explicitly(
    config: dict[str, object], message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _validate_config(config)


@pytest.mark.parametrize("extends", (False, 7, [], ""))
def test_inherited_config_rejects_non_path_extends(
    tmp_path: Path, extends: object,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(f"extends: {extends!r}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="extends must be a non-empty string path"):
        load_config(path)


def test_inherited_config_rejects_cycles(tmp_path: Path) -> None:
    first, second = tmp_path / "first.yaml", tmp_path / "second.yaml"
    first.write_text("extends: second.yaml\n", encoding="utf-8")
    second.write_text("extends: first.yaml\n", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration extends cycle"):
        load_config(first)


@pytest.mark.parametrize("payload", ("[]\n", "false\n", "'scalar'\n"))
def test_config_root_must_be_a_mapping(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "invalid-root.yaml"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError, match="configuration must be a mapping"):
        load_config(path)
