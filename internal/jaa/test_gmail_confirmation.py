from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

import career_automation.gmail_confirmation as gmail_module
from career_automation.production_ats_executor import GmailConfirmationEvidence
from career_automation.gmail_confirmation import GmailAPIConfirmationChecker


ROOT = Path(__file__).resolve().parent
START = datetime(2026, 8, 6, 10, 0, tzinfo=timezone.utc)
END = datetime(2026, 8, 6, 10, 5, tzinfo=timezone.utc)


def _checker(monkeypatch: pytest.MonkeyPatch, metadata: dict[str, object]):
    calls: list[tuple[str, dict[str, str]]] = []

    def get(url: str, headers):
        calls.append((url, dict(headers)))
        if urlsplit(url).path.endswith("/messages"):
            return {"messages": [{"id": "gmail-message-1"}]}
        return metadata

    checker = GmailAPIConfirmationChecker(repository_root=ROOT, http_get=get)
    monkeypatch.setattr(checker, "_assert_collector_identity", lambda: "a" * 64)
    monkeypatch.setenv("JAA_GMAIL_OAUTH_ACCESS_TOKEN", "test-only-oauth-secret")
    return checker, calls


def _metadata(
    *,
    sender: str = "Greenhouse <no-reply@greenhouse.io>",
    subject: str = "We received your Backend Platform application at Graphcore",
    received_at: datetime = datetime(2026, 8, 6, 10, 2, tzinfo=timezone.utc),
) -> dict[str, object]:
    return {
        "internalDate": str(int(received_at.timestamp() * 1000)),
        "payload": {
            "headers": [
                {"name": "From", "value": sender},
                {"name": "Subject", "value": subject},
            ]
        },
    }


def _check(checker: GmailAPIConfirmationChecker):
    return checker.check_confirmation(
        job_key="greenhouse:graphcore:1234567",
        application_id="1234567",
        company_name="Graphcore",
        role_title="Backend Platform Engineer",
        not_before=START,
        not_after=END,
    )


def test_narrow_gmail_match_archives_only_hashed_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checker, calls = _checker(monkeypatch, _metadata())
    evidence = _check(checker)
    with pytest.raises(ValueError, match="owned HTTPS transport"):
        checker.verify_evidence(evidence)
    assert evidence.result == "match"
    assert evidence.match_reasons == (
        "positive_confirmation",
        "provider_sender",
        "vacancy_identity",
        "post_intent_time",
    )
    assert evidence.checked_at == END.isoformat()
    document = evidence.document()
    serialized = str(document)
    assert "Your Backend Platform application" not in serialized
    assert "gmail-message-1" not in serialized
    assert "test-only-oauth-secret" not in serialized
    listing_query = parse_qs(urlsplit(calls[0][0]).query)["q"][0]
    assert "Graphcore" in listing_query
    assert "Backend Platform Engineer" in listing_query
    assert "1234567" in listing_query
    assert all("test-only-oauth-secret" not in url for url, _headers in calls)
    assert all(
        headers["Authorization"] == "Bearer test-only-oauth-secret"
        for _url, headers in calls
    )
    receipt = document["query_receipt"]
    assert receipt["schema_version"] == "jaa.gmail-api-query-receipt.v1"
    assert len(receipt["events"]) == 2
    assert all("gmail-message-1" not in str(event) for event in receipt["events"])


def test_collector_source_is_bound_to_exact_clean_head() -> None:
    checker = GmailAPIConfirmationChecker(repository_root=ROOT)
    source_sha256 = checker._assert_collector_identity()
    assert len(source_sha256) == 64


@pytest.mark.parametrize(
    "metadata",
    (
        _metadata(sender="Recruiter <person@example.com>"),
        _metadata(subject="Your unrelated application at Another Company"),
        _metadata(subject="Unrelated role at Another Company 1234567"),
        _metadata(subject="Graphcore Frontend Platform Director 9999999"),
        _metadata(
            subject="Update on your Backend Platform Engineer application at Graphcore"
        ),
        _metadata(received_at=datetime(2026, 8, 6, 9, 59, tzinfo=timezone.utc)),
    ),
)
def test_sender_vacancy_and_time_must_all_match(
    monkeypatch: pytest.MonkeyPatch, metadata: dict[str, object]
) -> None:
    checker, _calls = _checker(monkeypatch, metadata)
    evidence = _check(checker)
    assert evidence.result == "no_match"
    assert evidence.matched_message_metadata == ()
    assert evidence.match_reasons == ()


def test_missing_oauth_token_fails_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    checker = GmailAPIConfirmationChecker(
        repository_root=ROOT,
        http_get=lambda url, _headers: calls.append(url) or {},
    )
    monkeypatch.setattr(checker, "_assert_collector_identity", lambda: "a" * 64)
    monkeypatch.delenv("JAA_GMAIL_OAUTH_ACCESS_TOKEN", raising=False)
    with pytest.raises(ValueError, match="is required"):
        _check(checker)
    assert calls == []


def test_replacing_mutable_default_transport_does_not_gain_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gmail_module,
        "_default_http_get",
        lambda _url, _headers: {"messages": []},
    )
    checker = GmailAPIConfirmationChecker(repository_root=ROOT)
    monkeypatch.setattr(checker, "_assert_collector_identity", lambda: "a" * 64)
    assert checker.assert_production_authority() == "a" * 64
    assert checker._http_get is gmail_module._OWNED_HTTP_GET


def test_structurally_valid_caller_evidence_lacks_owned_query_issuance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checker = GmailAPIConfirmationChecker(repository_root=ROOT)
    monkeypatch.setattr(checker, "_assert_collector_identity", lambda: "a" * 64)
    forged = GmailConfirmationEvidence(
        collector_identity=(
            "jaa.gmail-api-metadata-reconciler.v1+source-sha256:" + "a" * 64
        ),
        checked_at=END.isoformat(),
        result="match",
        matched_message_metadata=(
            {
                "message_id_sha256": "b" * 64,
                "received_at": START.isoformat(),
                "sender_domain": "greenhouse.io",
                "subject_sha256": "c" * 64,
            },
        ),
        match_reasons=(
            "positive_confirmation",
            "provider_sender",
            "vacancy_identity",
            "post_intent_time",
        ),
        query_receipt={
            "schema_version": "jaa.gmail-api-query-receipt.v1",
            "collector_source_sha256": "a" * 64,
            "events": [{"fabricated": True}],
        },
    )
    with pytest.raises(ValueError, match="owned query receipt"):
        checker.verify_evidence(forged)
