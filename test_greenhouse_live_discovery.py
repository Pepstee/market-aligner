from career_automation.greenhouse_live_discovery import (
    classify_greenhouse_response,
    greenhouse_requisition_id,
)


URL = "https://job-boards.greenhouse.io/example/jobs/8624759002"


def test_requisition_identity_supports_direct_and_wrapped_urls() -> None:
    assert greenhouse_requisition_id(URL) == "8624759002"
    assert (
        greenhouse_requisition_id(
            "https://wayve.firststage.co/jobs?gh_jid=8624759002"
        )
        == "8624759002"
    )


def test_active_response_requires_title_requisition_and_form_marker() -> None:
    verdict = classify_greenhouse_response(
        requested_url=URL,
        final_url=URL,
        status=200,
        body=(
            b"<html><h1>Infrastructure Engineer</h1>"
            b"<div>Apply for this job</div><form class='application-form'>"
            b"<button>Submit Application</button></form></html>"
        ),
        expected_title="Infrastructure Engineer",
    )
    assert verdict.live is True
    assert verdict.reason == "live_application_form_observed"


def test_closed_marker_wins_even_when_stale_form_markup_remains() -> None:
    verdict = classify_greenhouse_response(
        requested_url=URL,
        final_url=URL,
        status=200,
        body=(
            b"<h1>Infrastructure Engineer</h1><p>This job is no longer open.</p>"
            b"<form class='application-form'></form>"
        ),
        expected_title="Infrastructure Engineer",
    )
    assert verdict.live is False
    assert verdict.reason == "provider_closed_marker"


def test_wrong_title_or_requisition_fails_closed() -> None:
    body = b"<h1>Different Role</h1><p>Apply for this job</p>"
    wrong_title = classify_greenhouse_response(
        requested_url=URL,
        final_url=URL,
        status=200,
        body=body,
        expected_title="Infrastructure Engineer",
    )
    assert wrong_title.reason == "vacancy_title_mismatch"
    wrong_id = classify_greenhouse_response(
        requested_url=URL,
        final_url="https://job-boards.greenhouse.io/example/jobs/9999999",
        status=200,
        body=b"<h1>Infrastructure Engineer</h1><p>Apply for this job</p>",
        expected_title="Infrastructure Engineer",
    )
    assert wrong_id.reason == "requisition_identity_mismatch"
