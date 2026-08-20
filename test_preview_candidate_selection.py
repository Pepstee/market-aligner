from datetime import datetime, timedelta, timezone

import pytest

from scripts.preview_candidate_application import (
    _assert_live_decision_binding,
    _live_vacancy_index,
    _select_decision,
)


def _decision(
    job_key: str,
    fit: str,
    *,
    matched_essential: int = 1,
    matched_desirable: int = 0,
    decision: str = "eligible",
) -> dict[str, object]:
    matrix = [
        {
            "classification": "essential",
            "status": "matched",
            "evidence_ids": [f"E-{index:03d}"],
        }
        for index in range(1, matched_essential + 1)
    ]
    matrix.extend(
        {
            "classification": "desirable",
            "status": "matched",
            "evidence_ids": [f"E-{index:03d}"],
        }
        for index in range(50, 50 + matched_desirable)
    )
    matrix.append(
        {
            "classification": "essential",
            "status": "gap",
            "evidence_ids": [],
        }
    )
    return {
        "receipt": {
            "job_key": job_key,
            "fit": fit,
            "decision": decision,
            "evidence_matrix": matrix,
        }
    }


def test_default_selects_highest_fit_instead_of_weakest_viable_role() -> None:
    authority = {
        "decisions": [
            _decision("role:weak", "0.050000"),
            _decision("role:best", "0.420000"),
            _decision("role:middle", "0.210000"),
        ]
    }
    live = frozenset({"role:weak", "role:best", "role:middle"})
    assert (
        _select_decision(authority, None, live_job_keys=live)["job_key"]
        == "role:best"
    )


def test_ties_prefer_more_matched_essential_requirements_then_job_key() -> None:
    authority = {
        "decisions": [
            _decision("role:z", "0.250000", matched_essential=1),
            _decision("role:b", "0.250000", matched_essential=2),
            _decision("role:a", "0.250000", matched_essential=2),
        ]
    }
    live = frozenset({"role:z", "role:b", "role:a"})
    assert (
        _select_decision(authority, None, live_job_keys=live)["job_key"]
        == "role:a"
    )


def test_explicit_job_key_remains_deliberate_stretch_override() -> None:
    authority = {
        "decisions": [
            _decision("role:best", "0.500000"),
            _decision("role:stretch", "0.050000"),
        ]
    }
    assert (
        _select_decision(
            authority, "role:stretch", live_job_keys=frozenset({"role:stretch"})
        )["job_key"]
        == "role:stretch"
    )


def test_zero_match_ineligible_and_missing_explicit_roles_are_not_viable() -> None:
    authority = {
        "decisions": [
            _decision("role:ineligible", "0.900000", decision="ineligible"),
            _decision("role:zero", "0.000000", matched_essential=0),
        ]
    }
    with pytest.raises(ValueError, match="no requested viable"):
        _select_decision(authority, None, live_job_keys=frozenset({"role:zero"}))
    with pytest.raises(ValueError, match="no requested viable"):
        _select_decision(authority, "role:missing", live_job_keys=frozenset())


@pytest.mark.parametrize("fit", ("not-a-number", "NaN", "1.1", "-0.1"))
def test_invalid_fit_fails_closed(fit: str) -> None:
    authority = {"decisions": [_decision("role:bad-fit", fit)]}
    with pytest.raises(ValueError, match="fit"):
        _select_decision(authority, None, live_job_keys=frozenset({"role:bad-fit"}))


def test_closed_highest_fit_is_excluded_before_selection() -> None:
    authority = {
        "decisions": [
            _decision("role:closed", "0.900000"),
            _decision("role:live", "0.300000"),
        ]
    }
    selected = _select_decision(
        authority, None, live_job_keys=frozenset({"role:live"})
    )
    assert selected["job_key"] == "role:live"


def _discovery(observed_at: str) -> dict[str, object]:
    pending = {
        "job_key": "role:live",
        "role_title": "Software Engineer",
        "company_name": "Example Ltd",
        "source_url": "https://job-boards.greenhouse.io/example/jobs/123456",
    }
    return {
        "schema_version": "jaa.greenhouse-live-discovery.v2",
        "observed_at": observed_at,
        "interaction": {
            "fields_filled": 0,
            "files_uploaded": 0,
            "submit_clicks": 0,
        },
        "observations": [
            {
                **pending,
                "requested_url": pending["source_url"],
                "verdict": {"live": True},
            }
        ],
        "live_pending_eligibility": [pending],
    }


def test_live_discovery_is_fresh_read_only_and_identity_bound() -> None:
    now = datetime(2026, 8, 19, 12, tzinfo=timezone.utc)
    index = _live_vacancy_index(
        _discovery("2026-08-19T11:30:00Z"),
        now=now,
        max_age=timedelta(hours=24),
    )
    assert set(index) == {"role:live"}


def test_stale_live_discovery_fails_closed() -> None:
    now = datetime(2026, 8, 19, 12, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="freshness"):
        _live_vacancy_index(
            _discovery("2026-08-18T11:59:59Z"),
            now=now,
            max_age=timedelta(hours=24),
        )


def test_live_discovery_rejects_non_read_only_interaction() -> None:
    document = _discovery("2026-08-19T11:30:00Z")
    document["interaction"] = {
        "fields_filled": 1,
        "files_uploaded": 0,
        "submit_clicks": 0,
    }
    with pytest.raises(ValueError, match="read-only"):
        _live_vacancy_index(
            document,
            now=datetime(2026, 8, 19, 12, tzinfo=timezone.utc),
            max_age=timedelta(hours=24),
        )


def test_candidate_decision_must_match_live_identity() -> None:
    live = _discovery("2026-08-19T11:30:00Z")["live_pending_eligibility"][0]
    decision = {**live, "company_name": "Wrong Company"}
    with pytest.raises(ValueError, match="company_name"):
        _assert_live_decision_binding(decision, live)
