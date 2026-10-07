import hashlib
import json

import pytest

from career_automation.greenhouse_loader_contract import (
    LoaderContractError,
    parse_current_greenhouse_loader,
)


EU_SOURCE = "https://job-boards.eu.greenhouse.io/example/jobs/12345"
US_SOURCE = "https://job-boards.greenhouse.io/example/jobs/12345"
EU_ROUTE = {
    "jobPostId": "12345",
    "urlToken": "[REDACTED]",
    "jobPost": {
        "public_url": EU_SOURCE,
        "confirmation_message": (
            "<h1>Received.</h1><p>We will be in touch.</p><p>&nbsp;</p>"
        ),
    },
    "submitPath": "https://boards.eu.greenhouse.io/example/jobs/12345",
    "confirmationPath": "/example/jobs/12345/confirmation",
}
US_ROUTE = {
    "jobPostId": "12345",
    "urlToken": "[REDACTED]",
    "jobPost": {
        "public_url": US_SOURCE,
        "confirmation_message": "<h2>Applied.</h2>",
    },
    "submitPath": "https://boards.greenhouse.io/example/jobs/12345/",
    "confirmationPath": (
        "https://job-boards.greenhouse.io/example/jobs/12345/confirmation"
    ),
}
RESULT_KEYS = {
    "source_url",
    "job_post_id",
    "primary_response_sha256",
    "confirmationPath",
    "submitPath",
    "confirmation_message",
    "confirmation_url",
    "required_visible_markers",
}


def _wrap(payload, *, prelude="", tail=""):
    return (
        "<!doctype html><html><head><title>Job</title></head><body>"
        + prelude
        + "<script>window.__remixContext = "
        + payload.replace("</", "<\\/")
        + ";</script>"
        + tail
        + "</body></html>"
    ).encode("utf-8")


def _payload(route):
    return json.dumps(
        {
            "basename": "/",
            "state": {
                "loaderData": {
                    "routes/$url_token_.jobs_.$job_post_id": route,
                }
            },
        }
    )


def _raw_route_payload(route_json):
    return (
        '{"basename": "/", "state": {"loaderData": '
        '{"routes/$url_token_.jobs_.$job_post_id": ' + route_json + "}}}"
    )


def _parse(response, source_url=EU_SOURCE):
    return parse_current_greenhouse_loader(response, source_url=source_url)


def test_eu_success_exact_fields_and_original_response_hash():
    response = _wrap(_payload(EU_ROUTE))
    result = _parse(response)
    assert set(result) == RESULT_KEYS
    assert result["source_url"] == EU_SOURCE
    assert result["job_post_id"] == "12345"
    assert result["primary_response_sha256"] == hashlib.sha256(response).hexdigest()
    assert result["submitPath"] == EU_ROUTE["submitPath"]
    assert result["confirmationPath"] == EU_ROUTE["confirmationPath"]
    assert result["confirmation_message"] == EU_ROUTE["jobPost"]["confirmation_message"]
    assert result["confirmation_url"] == (
        "https://job-boards.eu.greenhouse.io/example/jobs/12345/confirmation"
    )
    assert result["required_visible_markers"] == ("Received. We will be in touch.",)


def test_us_success_trailing_slash_and_absolute_confirmation():
    result = _parse(_wrap(_payload(US_ROUTE)), US_SOURCE)
    assert result["job_post_id"] == "12345"
    assert result["confirmation_url"] == (
        "https://job-boards.greenhouse.io/example/jobs/12345/confirmation"
    )
    assert result["required_visible_markers"] == ("Applied.",)


def test_entity_and_whitespace_normalization():
    job_post = dict(
        EU_ROUTE["jobPost"],
        confirmation_message="<p>  Alpha&nbsp;&amp;&nbsp;Beta\n&lt;ok&gt;  </p>",
    )
    result = _parse(_wrap(_payload(dict(EU_ROUTE, jobPost=job_post))))
    assert result["required_visible_markers"] == ("Alpha & Beta <ok>",)


def test_marker_omits_script_and_style_content():
    job_post = dict(
        EU_ROUTE["jobPost"],
        confirmation_message="<p>Keep</p><script>drop()</script><style>.a{}</style>",
    )
    result = _parse(_wrap(_payload(dict(EU_ROUTE, jobPost=job_post))))
    assert result["required_visible_markers"] == ("Keep",)


def test_decoy_text_outside_script_is_ignored():
    decoy = (
        "<div>jobPostId 67890 submitPath "
        "https://boards.eu.greenhouse.io/example/jobs/67890 "
        "confirmationPath /example/jobs/67890/confirmation</div>"
    )
    result = _parse(_wrap(_payload(EU_ROUTE), prelude=decoy, tail=decoy))
    assert result["job_post_id"] == "12345"


def test_decoy_assignment_outside_script_is_rejected():
    with pytest.raises(LoaderContractError):
        _parse(b'<div>window.__remixContext = {"jobPostId": "67890"};</div>')


def test_missing_assignment_is_rejected():
    with pytest.raises(LoaderContractError):
        _parse(b"<html><body><script>var other = 1;</script></body></html>")


def test_multiple_valid_assignments_are_rejected():
    payload = _payload(EU_ROUTE)
    response = (
        "<script>window.__remixContext = "
        + payload
        + ";</script><script>window.__remixContext = "
        + payload
        + ";</script>"
    ).encode("utf-8")
    with pytest.raises(LoaderContractError):
        _parse(response)


def test_malformed_second_assignment_is_rejected():
    payload = _payload(EU_ROUTE)
    response = (
        "<script>window.__remixContext = "
        + payload
        + ";</script><script>window.__remixContext = JSON.parse('{}');</script>"
    ).encode("utf-8")
    with pytest.raises(LoaderContractError):
        _parse(response)


def test_json_parse_wrapper_and_executable_tail_are_rejected():
    with pytest.raises(LoaderContractError):
        _parse(b'<script>window.__remixContext = JSON.parse("{}");</script>')
    response = (
        "<script>window.__remixContext = "
        + _payload(EU_ROUTE)
        + "; alert(1)</script>"
    ).encode("utf-8")
    with pytest.raises(LoaderContractError):
        _parse(response)


def test_external_script_source_is_rejected():
    response = (
        '<script src="https://example.invalid/t.js"></script>'
        "<script>window.__remixContext = "
        + _payload(EU_ROUTE)
        + ";</script>"
    ).encode("utf-8")
    with pytest.raises(LoaderContractError):
        _parse(response)


def test_truncated_script_is_rejected():
    response = (
        "<html><script>window.__remixContext = " + _payload(EU_ROUTE) + ";"
    ).encode("utf-8")
    with pytest.raises(LoaderContractError):
        _parse(response)


@pytest.mark.parametrize(
    "route_json",
    [
        '{"jobPostId": "12345", "jobPostId": "12345"}',
        '{"jobPostId": "12345", "jobPostI\\u0064": "12345"}',
        '{"x": NaN}',
        '{"x": Infinity}',
        '{"x": 1e999}',
        '{"jobPostId": "\\ud800"}',
    ],
)
def test_duplicate_nonfinite_and_surrogate_json_is_rejected(route_json):
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_raw_route_payload(route_json)))


def test_invalid_utf8_and_bom_are_rejected():
    response = _wrap(_payload(EU_ROUTE)).replace(b"example", b"ex\xffample", 1)
    with pytest.raises(LoaderContractError):
        _parse(response)
    with pytest.raises(LoaderContractError):
        _parse(b"\xef\xbb\xbf" + _wrap(_payload(EU_ROUTE)))


def test_non_bytes_input_is_rejected():
    with pytest.raises(LoaderContractError):
        parse_current_greenhouse_loader(_payload(EU_ROUTE), source_url=EU_SOURCE)


def test_redacted_url_token_is_accepted():
    assert _parse(_wrap(_payload(EU_ROUTE)))["job_post_id"] == "12345"


@pytest.mark.parametrize(
    "route",
    [
        dict(EU_ROUTE, jobPostId="67890"),
        dict(
            EU_ROUTE,
            jobPost={
                **EU_ROUTE["jobPost"],
                "public_url": "https://job-boards.eu.greenhouse.io/other/jobs/12345",
            },
        ),
        dict(
            EU_ROUTE,
            jobPost={
                **EU_ROUTE["jobPost"],
                "public_url": "https://boards.eu.greenhouse.io/example/jobs/12345",
            },
        ),
    ],
)
def test_job_id_board_and_exact_public_url_binding(route):
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_payload(route)))


def test_public_url_trailing_slash_equivalence_is_allowed():
    route = dict(
        EU_ROUTE,
        jobPost={
            **EU_ROUTE["jobPost"],
            "public_url": EU_SOURCE + "/",
        },
    )
    assert _parse(_wrap(_payload(route)))["job_post_id"] == "12345"


def test_cross_region_source_and_submit_are_rejected():
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_payload(EU_ROUTE)), US_SOURCE)
    route = dict(
        EU_ROUTE,
        submitPath="https://boards.greenhouse.io/example/jobs/12345",
    )
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_payload(route)))


@pytest.mark.parametrize(
    "submit_path",
    [
        "https://example.invalid/example/jobs/12345",
        "//boards.eu.greenhouse.io/example/jobs/12345",
        "http://boards.eu.greenhouse.io/example/jobs/12345",
        "https://boards.eu.greenhouse.io/example/jobs/../12345",
        "https://boards.eu.greenhouse.io/example/jobs/12345?next=x",
    ],
)
def test_unsafe_submit_path_is_rejected(submit_path):
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_payload(dict(EU_ROUTE, submitPath=submit_path))))


@pytest.mark.parametrize(
    "confirmation_path",
    [
        "//boards.eu.greenhouse.io/example/jobs/12345/confirmation",
        "/example/jobs/../12345/confirmation",
        "/example/jobs/%2e%2e/12345/confirmation",
        "/example/jobs/12345/confirmation?x=1",
        "/example/jobs/12345/confirmation#fragment",
        "/example/jobs/12345/confirmation\n",
        "https://job-boards.eu.greenhouse.io/example/jobs/67890/confirmation",
    ],
)
def test_unsafe_confirmation_path_is_rejected(confirmation_path):
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_payload(dict(EU_ROUTE, confirmationPath=confirmation_path))))


def test_exact_absolute_confirmation_path_is_allowed():
    route = dict(
        EU_ROUTE,
        confirmationPath=(
            "https://job-boards.eu.greenhouse.io/example/jobs/12345/confirmation"
        ),
    )
    assert _parse(_wrap(_payload(route)))["job_post_id"] == "12345"


@pytest.mark.parametrize(
    "message",
    ["<p><br></p>", "<script>alert(1)</script>", "<style>.empty{}</style>"],
)
def test_empty_or_nonvisible_confirmation_message_is_rejected(message):
    job_post = dict(EU_ROUTE["jobPost"], confirmation_message=message)
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_payload(dict(EU_ROUTE, jobPost=job_post))))


@pytest.mark.parametrize(
    "source_url",
    [
        "http://job-boards.eu.greenhouse.io/example/jobs/12345",
        "https://job-boards.eu.greenhouse.io:443/example/jobs/12345",
        "https://user:pw@job-boards.eu.greenhouse.io/example/jobs/12345",
        "https://job-boards.eu.greenhouse.io/example/jobs/12345?x=1",
        "https://job-boards.eu.greenhouse.io/example/jobs/12345#frag",
        "https://job-boards.eu.greenhouse.io/example/jobs/../12345",
        "https://example.invalid/example/jobs/12345",
    ],
)
def test_unsafe_or_untrusted_source_url_is_rejected(source_url):
    with pytest.raises(LoaderContractError):
        _parse(_wrap(_payload(EU_ROUTE)), source_url)
