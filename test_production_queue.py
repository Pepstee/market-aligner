from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.application_archive import (
    ApplicationArchive,
    VacancyArchiveIdentity,
)
from career_automation.production_queue import (
    LiveVacancy,
    PriorAttempt,
    ProductionCheckpointLedger,
    ProductionQueueError,
    build_ascending_queue,
    prior_attempts_from_archive,
)


ROOT = Path(__file__).resolve().parent
NOW = datetime(2026, 8, 5, 12, tzinfo=timezone.utc)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _vacancy(label: str) -> VacancyArchiveIdentity:
    return VacancyArchiveIdentity(
        job_key=f"greenhouse:example:{label}",
        vacancy_sha256=_digest(f"vacancy-{label}"),
        role_title=f"Engineer {label}",
        company_name="Example",
        source_url=f"https://job-boards.greenhouse.io/example/jobs/{label}",
    )


def _candidate(
    label: str,
    fit: str,
    *,
    provider: str = "greenhouse",
    live: bool = True,
    eligible: bool = True,
    duplicate: bool = False,
    verified_at: datetime = NOW,
) -> LiveVacancy:
    return LiveVacancy.create(
        vacancy=_vacancy(label),
        provider=provider,
        fit_score=fit,
        live=live,
        eligible=eligible,
        duplicate=duplicate,
        live_verified_at=verified_at.isoformat(),
        scoring_inputs_sha256=_digest(f"score-{label}"),
    )


def test_queue_orders_weakest_viable_fit_first_with_stable_ranks() -> None:
    queue = build_ascending_queue(
        (_candidate("30", "0.9"), _candidate("10", "0.2"), _candidate("20", "0.2")),
        as_of=NOW,
    )
    assert [row.vacancy.vacancy.job_key for row in queue.ready] == [
        "greenhouse:example:10",
        "greenhouse:example:20",
        "greenhouse:example:30",
    ]
    assert [row.queue_rank for row in queue.ready] == [1, 2, 3]
    assert all(row.action == "create_attempt" for row in queue.ready)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"live": False}, "not_live"),
        ({"eligible": False}, "ineligible"),
        ({"duplicate": True}, "declared_duplicate"),
        ({"provider": "workable"}, "unsupported_provider"),
        (
            {"verified_at": NOW - timedelta(hours=7)},
            "stale_live_verification",
        ),
    ],
)
def test_queue_excludes_nonadmitted_candidates(changes, reason: str) -> None:
    queue = build_ascending_queue((_candidate("10", "0.2", **changes),), as_of=NOW)
    assert not queue.ready
    assert queue.excluded[0].reason == reason


@pytest.mark.parametrize(
    "outcome",
    ["submitted_success", "submitted_failure", "indeterminate", "blocked"],
)
def test_prior_consequential_or_blocked_attempt_is_quarantined(outcome: str) -> None:
    candidate = _candidate("10", "0.2")
    prior = PriorAttempt(
        candidate.vacancy,
        "jaa-20260805T120000Z-0123456789abcdef",
        outcome,
        _digest("terminal"),
    )
    queue = build_ascending_queue((candidate,), prior_attempts=(prior,), as_of=NOW)
    assert not queue.ready
    assert queue.excluded[0].reason == f"prior_{outcome}"


def test_explicit_retry_policy_admits_only_repairable_preclick_block() -> None:
    candidate = _candidate("10", "0.2")
    prior = PriorAttempt(
        candidate.vacancy,
        "jaa-20260805T120000Z-0123456789abcdef",
        "blocked",
        _digest("terminal"),
        repairable_preclick_human_verification=True,
    )
    queue = build_ascending_queue(
        (candidate,),
        prior_attempts=(prior,),
        as_of=NOW,
        retry_repairable_preclick_blocks=True,
    )
    assert queue.next_action is not None
    assert queue.next_action.action == "create_attempt"


def test_retry_policy_never_admits_a_repairable_block_with_click_intent() -> None:
    candidate = _candidate("10", "0.2")
    prior = PriorAttempt(
        candidate.vacancy,
        "jaa-20260805T120000Z-0123456789abcdef",
        "blocked",
        _digest("terminal"),
        click_intent_present=True,
        repairable_preclick_human_verification=True,
    )
    queue = build_ascending_queue(
        (candidate,),
        prior_attempts=(prior,),
        as_of=NOW,
        retry_repairable_preclick_blocks=True,
    )
    assert not queue.ready
    assert queue.excluded[0].reason == "prior_click_intent"


def test_incomplete_attempt_is_resumed_without_creating_a_duplicate() -> None:
    candidate = _candidate("10", "0.2")
    prior = PriorAttempt(
        candidate.vacancy,
        "jaa-20260805T120000Z-0123456789abcdef",
        None,
        None,
    )
    queue = build_ascending_queue((candidate,), prior_attempts=(prior,), as_of=NOW)
    assert queue.next_action is not None
    assert queue.next_action.action == "resume_attempt"
    assert queue.next_action.attempt_id == prior.attempt_id


@pytest.mark.parametrize("outcome", (None, "crashed", "timed_out", "abandoned"))
def test_click_intent_quarantines_regardless_of_terminal_state(
    outcome: str | None,
) -> None:
    candidate = _candidate("10", "0.2")
    prior = PriorAttempt(
        candidate.vacancy,
        "jaa-20260805T120000Z-0123456789abcdef",
        outcome,
        _digest("terminal") if outcome is not None else None,
        click_intent_present=True,
    )
    queue = build_ascending_queue((candidate,), prior_attempts=(prior,), as_of=NOW)
    assert not queue.ready
    assert queue.excluded[0].reason == "prior_click_intent"


def test_checkpoint_ledger_binds_attempt_start_and_terminal_manifest(
    tmp_path: Path,
) -> None:
    archive = ApplicationArchive(tmp_path / "archive", repository_root=ROOT)
    attempt = archive.create_attempt(_vacancy("10"))
    ledger = ProductionCheckpointLedger(archive)
    ledger.record_attempt_started(attempt.attempt_id)
    source_identity = attempt.add_artifact(
        "vacancy.source_identity", b"identity", media_type="text/plain"
    )
    capture = attempt.add_artifact(
        "vacancy.capture", b"vacancy", media_type="text/plain"
    )
    result = attempt.add_artifact(
        "submission.result", b'{"state":"crashed"}', media_type="application/json"
    )
    attempt.finalize_terminal(
        outcome="crashed",
        selected={
            "vacancy.source_identity": source_identity.sha256,
            "vacancy.capture": capture.sha256,
            "submission.result": result.sha256,
        },
    )
    ledger.record_attempt_terminal(attempt.attempt_id)
    rows = ledger.verify()
    assert [row["event_type"] for row in rows] == [
        "attempt_started",
        "attempt_terminal",
    ]
    prior = prior_attempts_from_archive(archive)
    assert prior[0].outcome == "crashed"
    assert prior[0].terminal_manifest_sha256 == rows[-1]["terminal_manifest_sha256"]
    assert prior[0].click_intent_present is False


def test_archive_loader_detects_click_intent_for_duplicate_quarantine(
    tmp_path: Path,
) -> None:
    archive = ApplicationArchive(tmp_path / "archive", repository_root=ROOT)
    attempt = archive.create_attempt(_vacancy("10"))
    attempt.add_artifact(
        "submission.click_intent",
        b'{"click_may_occur":true}',
        media_type="application/json",
    )
    prior = prior_attempts_from_archive(archive)
    assert prior[0].click_intent_present is True
    queue = build_ascending_queue(
        (_candidate("10", "0.2"),), prior_attempts=prior, as_of=NOW
    )
    assert not queue.ready
    assert queue.excluded[0].reason == "prior_click_intent"


def test_archive_loader_marks_legacy_preclick_human_verification_as_repairable(
    tmp_path: Path,
) -> None:
    archive = ApplicationArchive(tmp_path / "archive", repository_root=ROOT)
    attempt = archive.create_attempt(_vacancy("10"))
    source = attempt.add_artifact(
        "vacancy.source_identity", b"identity", media_type="text/plain"
    )
    capture = attempt.add_artifact(
        "vacancy.capture", b"vacancy", media_type="text/plain"
    )
    boundary_value = (
        json.dumps(
            {
                "classification": "human_verification_boundary",
                "future_queue": "technical_boundary",
                "phase": "before_generation_or_fill",
                "signals": ["captcha", "recaptcha"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    boundary = attempt.add_artifact(
        "technical.boundary", boundary_value, media_type="application/json"
    )
    result = attempt.add_artifact(
        "submission.result",
        b'{"click_intent_recorded":false,"state":"blocked"}',
        media_type="application/json",
    )
    network = attempt.add_artifact(
        "browser.redirect_http_evidence",
        b'{"availability":"listener_not_started_before_boundary","events":[],"schema_version":"jaa.browser-http-evidence.v1"}\n',
        media_type="application/json",
    )
    blocked_state = attempt.add_artifact(
        "browser.blocked_state_evidence",
        b'{"fields":[]}',
        media_type="application/json",
    )
    attempt.finalize_terminal(
        outcome="blocked",
        selected={
            "vacancy.source_identity": source.sha256,
            "vacancy.capture": capture.sha256,
            "technical.boundary": boundary.sha256,
            "submission.result": result.sha256,
            "browser.redirect_http_evidence": network.sha256,
            "browser.blocked_state_evidence": blocked_state.sha256,
        },
    )
    prior = prior_attempts_from_archive(archive)
    assert prior[0].click_intent_present is False
    assert prior[0].repairable_preclick_human_verification is True


def test_cancelled_record_never_erases_durable_click_intent(
    tmp_path: Path,
) -> None:
    archive = ApplicationArchive(tmp_path / "archive", repository_root=ROOT)
    attempt = archive.create_attempt(_vacancy("10"))
    attempt.add_artifact(
        "submission.click_intent",
        b'{"click_may_occur":true}',
        media_type="application/json",
    )
    attempt.add_artifact(
        "submission.click_cancelled",
        b'{"click_may_have_occurred":false}',
        media_type="application/json",
    )
    prior = prior_attempts_from_archive(archive)
    assert prior[0].click_intent_present is True
    queue = build_ascending_queue(
        (_candidate("10", "0.2"),), prior_attempts=prior, as_of=NOW
    )
    assert not queue.ready
    assert queue.excluded[0].reason == "prior_click_intent"


def test_checkpoint_mutation_and_symlink_fail_closed(tmp_path: Path) -> None:
    archive = ApplicationArchive(tmp_path / "archive", repository_root=ROOT)
    attempt = archive.create_attempt(_vacancy("10"))
    ledger = ProductionCheckpointLedger(archive)
    ledger.record_attempt_started(attempt.attempt_id)
    event = ledger.events / "00000001.json"
    event.write_bytes(
        event.read_bytes().replace(b"attempt_started", b"attempt_spoofed")
    )
    with pytest.raises(ProductionQueueError, match="canonical|hash chain"):
        ledger.verify()


def test_duplicate_candidates_and_nonfinite_fit_fail_closed() -> None:
    candidate = _candidate("10", "0.2")
    with pytest.raises(ProductionQueueError, match="duplicate vacancy"):
        build_ascending_queue((candidate, candidate), as_of=NOW)
    with pytest.raises(ProductionQueueError, match="finite"):
        _candidate("20", "NaN")


@pytest.mark.parametrize("equivalence", ("job_key", "vacancy_sha256", "source_url"))
def test_current_batch_same_vacancy_equivalence_fails_closed(
    equivalence: str,
) -> None:
    first = _candidate("10", "0.2")
    second = _candidate("20", "0.3")
    if equivalence == "job_key":
        vacancy = replace(second.vacancy, job_key=first.vacancy.job_key)
    elif equivalence == "vacancy_sha256":
        vacancy = replace(
            second.vacancy,
            vacancy_sha256=first.vacancy.vacancy_sha256,
        )
    else:
        vacancy = replace(
            second.vacancy,
            source_url=first.vacancy.source_url + "?utm_source=duplicate-test",
        )
    with pytest.raises(ProductionQueueError, match="duplicate vacancy equivalence"):
        build_ascending_queue(
            (first, replace(second, vacancy=vacancy)),
            as_of=NOW,
        )


def test_current_batch_greenhouse_wrapper_and_direct_url_are_equivalent() -> None:
    first = _candidate("8624759002", "0.2")
    second = _candidate("20", "0.3")
    wrapped = replace(
        second.vacancy,
        source_url="https://wayve.firststage.co/jobs?gh_jid=8624759002",
    )
    with pytest.raises(ProductionQueueError, match="duplicate vacancy equivalence"):
        build_ascending_queue(
            (first, replace(second, vacancy=wrapped)),
            as_of=NOW,
        )


def test_historical_redirect_with_greenhouse_id_in_key_is_quarantined() -> None:
    candidate = _candidate("8624759002", "0.2")
    historical = replace(
        candidate.vacancy,
        job_key="legacy:Wayve__Software_Engineer__8624759002",
        vacancy_sha256=_digest("historical-vacancy"),
        source_url="https://wayve.firststage.co/jobs/fZ_fake/view",
    )
    prior = PriorAttempt(
        historical,
        "jaa-20260805T120000Z-0123456789abcdef",
        "historical_submitted_success",
        _digest("terminal"),
    )
    queue = build_ascending_queue((candidate,), prior_attempts=(prior,), as_of=NOW)
    assert not queue.ready
    assert queue.excluded[0].reason == "prior_historical_submitted_success"


def test_unrelated_number_inside_historical_identity_does_not_match() -> None:
    candidate = _candidate("8624759002", "0.2")
    historical = replace(
        candidate.vacancy,
        job_key="legacy:unrelated-186247590029",
        vacancy_sha256=_digest("historical-vacancy"),
        source_url="https://example.invalid/jobs/unrelated",
    )
    prior = PriorAttempt(
        historical,
        "jaa-20260805T120000Z-0123456789abcdef",
        "historical_submitted_success",
        _digest("terminal"),
    )
    queue = build_ascending_queue((candidate,), prior_attempts=(prior,), as_of=NOW)
    assert queue.next_action is not None


@pytest.mark.parametrize(
    ("provider", "first_url", "second_url"),
    (
        (
            "ashby",
            "https://jobs.ashbyhq.com/lendable/68e876da-fa27-4b9e-ad09-ca4805efa8a5",
            "https://jobs.ashbyhq.com/other/68E876DA-FA27-4B9E-AD09-CA4805EFA8A5/application",
        ),
        (
            "lever",
            "https://jobs.lever.co/example/68e876da-fa27-4b9e-ad09-ca4805efa8a5",
            "https://jobs.lever.co/renamed/68E876DA-FA27-4B9E-AD09-CA4805EFA8A5/apply",
        ),
        (
            "workable",
            "https://apply.workable.com/j/EA27D81554",
            "https://apply.workable.com/example/j/EA27D81554/?utm_source=test",
        ),
        (
            "smartrecruiters",
            "https://jobs.smartrecruiters.com/Example/744000125090731",
            "https://jobs.smartrecruiters.com/Renamed/744000125090731?utm_source=test",
        ),
    ),
)
def test_current_batch_provider_identity_variants_are_equivalent(
    provider: str, first_url: str, second_url: str
) -> None:
    first = replace(
        _candidate("10", "0.2", provider=provider),
        vacancy=replace(_vacancy("10"), source_url=first_url),
    )
    second = replace(
        _candidate("20", "0.3", provider=provider),
        vacancy=replace(_vacancy("20"), source_url=second_url),
    )
    with pytest.raises(ProductionQueueError, match="duplicate vacancy equivalence"):
        build_ascending_queue((first, second), as_of=NOW)


def test_historical_ashby_identity_is_quarantined_across_company_slug() -> None:
    candidate = replace(
        _candidate("10", "0.2", provider="ashby"),
        vacancy=replace(
            _vacancy("10"),
            job_key="ashby:lendable:68e876da-fa27-4b9e-ad09-ca4805efa8a5",
            source_url="https://jobs.ashbyhq.com/lendable/68e876da-fa27-4b9e-ad09-ca4805efa8a5",
        ),
    )
    historical = replace(
        candidate.vacancy,
        job_key="legacy:ashby:68E876DA-FA27-4B9E-AD09-CA4805EFA8A5",
        vacancy_sha256=_digest("historical-ashby"),
        source_url="https://example.invalid/archive/role",
    )
    prior = PriorAttempt(
        historical,
        "jaa-20260805T120000Z-0123456789abcdef",
        "blocked",
        _digest("terminal"),
    )
    queue = build_ascending_queue((candidate,), prior_attempts=(prior,), as_of=NOW)
    assert not queue.ready
    assert queue.excluded[0].reason == "prior_blocked"
