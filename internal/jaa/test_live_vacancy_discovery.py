import hashlib

import pytest

from career_automation.live_vacancy_discovery import (
    AuthorityDestinationResponse,
    bind_authority_destinations,
    classify_live_vacancy_response,
    provider_for_url,
    verify_vacancy_body_equivalence,
)


def _response(
    url: str,
    body: bytes,
    *,
    final_url: str | None = None,
    status: int = 200,
) -> AuthorityDestinationResponse:
    return AuthorityDestinationResponse(
        requested_url=url,
        final_url=final_url or url,
        status=status,
        body=body,
        response_artifact_sha256=hashlib.sha256(body).hexdigest(),
        network_evidence_sha256=hashlib.sha256(b"network evidence").hexdigest(),
    )


def test_resolves_exact_ashby_authority_from_aggregator() -> None:
    verdict = classify_live_vacancy_response(
        requested_url="https://example.test/jobs/role",
        final_url="https://example.test/jobs/role",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Build reliable Python data pipelines "
            b"and tested cloud services for customers.</p><p>Apply now</p>"
            b"<a href='https://jobs.ashbyhq.com/acme/"
            b"68e876da-fa27-4b9e-ad09-ca4805efa8a5'>Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    assert verdict.live is False
    assert verdict.reason == "live_source_requires_ats_destination_fetch"
    assert verdict.authority_urls == ()
    assert verdict.authority_candidates == (
        "https://jobs.ashbyhq.com/acme/68e876da-fa27-4b9e-ad09-ca4805efa8a5",
    )
    destination_body = (
        b"<h1>Graduate Engineer</h1><p>Acme</p>"
        b"<p>Build reliable Python data pipelines and tested cloud services "
        b"for customers.</p>"
        b"<button>Apply now</button>"
    )
    bound = bind_authority_destinations(
        verdict,
        responses=(
            _response(verdict.authority_candidates[0], destination_body),
        ),
        expected_title="Graduate Engineer",
        expected_company="Acme",
    )
    assert bound.live is True
    assert bound.reason == "live_with_verified_ats_authority"
    assert bound.authority_providers == ("ashby",)
    assert bound.destination_evidence[0]["body_sha256"] == hashlib.sha256(
        destination_body
    ).hexdigest()
    assert bound.destination_evidence[0]["description_bound"] is True


def test_same_title_company_cannot_substitute_different_requirements() -> None:
    source = classify_live_vacancy_response(
        requested_url="https://careers.example.test/graduate-engineer",
        final_url="https://careers.example.test/graduate-engineer",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Acme</p>"
            b"<p>Build Python data pipelines, analyse datasets, and maintain "
            b"reliable cloud services.</p>"
            b"<a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
            b"Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    substituted = bind_authority_destinations(
        source,
        responses=(
            _response(
                source.authority_candidates[0],
                (
                    b"<h1>Graduate Engineer</h1><p>Acme</p>"
                    b"<p>Requires five years of C++ embedded hardware, firmware "
                    b"debugging, and circuit design experience.</p>"
                    b"<button>Apply for this job</button>"
                ),
            ),
        ),
        expected_title="Graduate Engineer",
        expected_company="Acme",
    )
    evidence = substituted.destination_evidence[0]
    assert substituted.live is False
    assert evidence["title_bound"] is True
    assert evidence["company_bound"] is True
    assert evidence["description_bound"] is False
    assert evidence["reason"] == "destination_description_mismatch"


def test_matching_source_terms_cannot_hide_added_conflicting_requirements() -> None:
    description = (
        b"Build Python data pipelines, analyse datasets, and maintain reliable "
        b"cloud services."
    )
    source = classify_live_vacancy_response(
        requested_url="https://careers.example.test/graduate-engineer",
        final_url="https://careers.example.test/graduate-engineer",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Acme</p><p>"
            + description
            + b"</p><a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
            b"Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    injected = bind_authority_destinations(
        source,
        responses=(
            _response(
                source.authority_candidates[0],
                (
                    b"<h1>Graduate Engineer</h1><p>Acme</p><p>"
                    + description
                    + b"</p><p>Mandatory five years C++ embedded hardware, "
                    b"firmware debugging, circuit design, and security clearance."
                    b"</p><button>Apply now</button>"
                ),
            ),
        ),
        expected_title="Graduate Engineer",
        expected_company="Acme",
    )
    evidence = injected.destination_evidence[0]
    assert evidence["semantic_overlap_basis_points"] >= 8_000
    assert evidence["semantic_jaccard_basis_points"] < 6_500
    assert evidence["reason"] == "destination_description_mismatch"


def test_immediate_browser_body_reverification_rejects_requirement_swap() -> None:
    source = (
        b"<h1>Graduate Engineer</h1><p>Build Python data pipelines, analyse "
        b"datasets, and maintain reliable cloud services.</p>"
    )
    equivalent = verify_vacancy_body_equivalence(
        source,
        b"<main><h1>Graduate Engineer</h1><p>Build Python data pipelines, "
        b"analyse datasets, and maintain reliable cloud services.</p></main>",
    )
    assert equivalent["equivalent"] is True
    with pytest.raises(ValueError, match="description differs"):
        verify_vacancy_body_equivalence(
            source,
            b"<h1>Graduate Engineer</h1><p>Requires C++ embedded firmware, "
            b"hardware debugging, circuit design, and security clearance.</p>",
        )


def test_long_common_body_cannot_hide_critical_requirement_replacement() -> None:
    common = " ".join(
        [
            "Join a collaborative engineering team delivering reliable products "
            "for customers through thoughtful design, testing, and operations."
        ]
        * 12
    )
    source = (
        f"<main><p>{common}</p><p>Current UK security clearance is required. "
        "Build Python cloud services.</p></main>"
    ).encode()
    destination = (
        f"<main><p>{common}</p><p>Five years of commercial CUDA experience is "
        "required. Build Python cloud services.</p></main>"
    ).encode()
    with pytest.raises(ValueError, match="description differs"):
        verify_vacancy_body_equivalence(source, destination)


def test_unknown_mandatory_technology_replacement_fails_closed() -> None:
    common = " ".join(
        [
            "Join a collaborative team delivering reliable products through "
            "thoughtful design, testing, documentation, and operations."
        ]
        * 12
    )
    source = (
        f"<main><p>{common}</p><p>Mandatory <strong>Redis</strong> experience is required. "
        "Build Python cloud services.</p></main>"
    ).encode()
    destination = (
        f"<main><p>{common}</p><p>Mandatory <strong>Kafka</strong> experience is required. "
        "Build Python cloud services.</p></main>"
    ).encode()
    with pytest.raises(ValueError, match="description differs"):
        verify_vacancy_body_equivalence(source, destination)


def test_exact_nontechnical_description_requires_no_known_atom() -> None:
    body = (
        b"<main><p>Coordinate stakeholder meetings, prepare concise reports, "
        b"and support customer enquiries.</p></main>"
    )
    receipt = verify_vacancy_body_equivalence(body, body)
    assert receipt["material_requirement_bound"] is True
    assert receipt["equivalent"] is True


@pytest.mark.parametrize(
    ("source_requirement", "destination_requirement"),
    (
        ("No Redis experience is required.", "Redis experience is required."),
        (
            "Either Redis or Kafka experience is required.",
            "Redis and Kafka experience are both required.",
        ),
        ("Three to five years of Python experience.", "Three years of Python experience."),
    ),
)
def test_negation_alternatives_and_ranges_are_material(
    source_requirement: str,
    destination_requirement: str,
) -> None:
    with pytest.raises(ValueError, match="description differs"):
        verify_vacancy_body_equivalence(
            f"<main><p>{source_requirement}</p></main>".encode(),
            f"<main><p>{destination_requirement}</p></main>".encode(),
        )


def test_ats_legal_and_navigation_boilerplate_does_not_change_requirements() -> None:
    source = (
        b"<main><h1>Engineer</h1><p>Build Python data pipelines and cloud "
        b"services.</p></main>"
    )
    destination = (
        b"<nav>Home Teams Careers Help</nav><main><h1>Engineer</h1>"
        b"<p>Build Python data pipelines and cloud services.</p></main>"
        b"<footer>We are an equal opportunity employer and value inclusion. "
        b"Read our privacy notice and cookie policy. Our careers site runs on "
        b"React and the footer team is based in London.</footer>"
    )
    receipt = verify_vacancy_body_equivalence(source, destination)
    assert receipt["material_requirement_bound"] is True
    assert receipt["equivalent"] is True


def test_nonmaterial_destination_truncation_preserves_atomic_requirements() -> None:
    source = (
        b"<main><p>Build Python data pipelines and cloud services.</p>"
        b"<p>You will join a supportive team with mentoring, social events, "
        b"learning resources, and a broad benefits package.</p></main>"
    )
    destination = b"<main><p>Build Python data pipelines and cloud services.</p></main>"
    receipt = verify_vacancy_body_equivalence(source, destination)
    assert receipt["material_requirement_bound"] is True
    assert receipt["equivalent"] is True


def test_semantic_paraphrase_maps_to_identical_material_constraints() -> None:
    source = (
        b"<main><p>You must have three years of Python experience and be "
        b"eligible to work in the UK. This is a hybrid role requiring two "
        b"days in our London office each week.</p></main>"
    )
    destination = (
        b"<main><p>Applicants need 3 years of experience using Python, an "
        b"existing UK right to work, and must attend the London office 2 days "
        b"each week.</p></main>"
    )
    receipt = verify_vacancy_body_equivalence(source, destination)
    assert receipt["material_requirement_bound"] is True
    assert receipt["equivalent"] is True


@pytest.mark.parametrize(
    ("source", "destination"),
    (
        (
            "Redis required; Kafka not required.",
            "Kafka required; Redis not required.",
        ),
        (
            "Python required. Comfortable with Redis.",
            "Python required. Comfortable with Kafka.",
        ),
        ("Capacity of 100 requests/sec is required.", "Capacity of 1000 requests/sec is required."),
    ),
)
def test_entity_polarity_unflagged_capability_and_capacity_are_material(
    source: str,
    destination: str,
) -> None:
    with pytest.raises(ValueError, match="description differs"):
        verify_vacancy_body_equivalence(
            f"<main><p>{source}</p></main>".encode(),
            f"<main><p>{destination}</p></main>".encode(),
        )


def test_known_compound_normalization_preserves_equivalence() -> None:
    receipt = verify_vacancy_body_equivalence(
        b"<main><p>CouchDB experience is required.</p></main>",
        b"<main><p>Couch DB experience is required.</p></main>",
    )
    assert receipt["equivalent"] is True


def test_cookie_banner_requirement_text_is_not_a_vacancy_constraint() -> None:
    source = b"<main><p>Python experience is required.</p></main>"
    destination = (
        b"<main><p>Python experience is required.</p></main>"
        b"<div class='cookie-banner'>Cookies are required.</div>"
    )
    assert verify_vacancy_body_equivalence(source, destination)["equivalent"] is True


@pytest.mark.parametrize(
    "provider_chrome",
    (
        "Create alert",
        "Create a job alert",
        "Create alert Required",
    ),
)
def test_greenhouse_create_alert_chrome_is_not_a_vacancy_constraint(
    provider_chrome: str,
) -> None:
    source = b"<main><p>Python experience is required.</p></main>"
    destination = (
        "<main><p>Python experience is required.</p>"
        f"<div class='job-alert'>{provider_chrome}</div></main>"
    ).encode()
    assert verify_vacancy_body_equivalence(source, destination)["equivalent"] is True


def test_create_responsibility_is_not_mistaken_for_provider_chrome() -> None:
    source = b"<main><p>Python experience is required.</p></main>"
    destination = (
        b"<main><p>Python experience is required.</p>"
        b"<p>Create alert pipelines for production incidents.</p></main>"
    )
    with pytest.raises(ValueError, match="description differs"):
        verify_vacancy_body_equivalence(source, destination)


@pytest.mark.parametrize(
    ("source", "destination"),
    (
        (
            b"<main><p>Capacity of 100 requests/sec is required.</p></main>",
            b"<main><p>Capacity of 100 requests per second is required.</p></main>",
        ),
        (
            b"<main><p>CouchDB experience is required.</p></main>",
            b"<main><p>  couch db   EXPERIENCE is required! </p></main>",
        ),
    ),
)
def test_benign_unit_case_whitespace_and_punctuation_normalization(
    source: bytes, destination: bytes
) -> None:
    assert verify_vacancy_body_equivalence(source, destination)["equivalent"] is True


def test_closed_and_title_mismatch_fail_closed() -> None:
    closed = classify_live_vacancy_response(
        requested_url="https://example.test/jobs/role",
        final_url="https://example.test/jobs/role",
        status=200,
        body=b"<h1>Graduate Engineer</h1><p>This job is no longer open.</p><p>Apply now</p>",
        expected_title="Graduate Engineer",
    )
    assert closed.reason == "provider_closed_marker"
    mismatch = classify_live_vacancy_response(
        requested_url="https://example.test/jobs/role",
        final_url="https://example.test/jobs/role",
        status=200,
        body=b"<h1>Senior Lawyer</h1><p>Apply now</p>",
        expected_title="Graduate Engineer",
    )
    assert mismatch.reason == "vacancy_title_mismatch"


def test_closed_source_cannot_be_revived_by_an_active_destination() -> None:
    closed = classify_live_vacancy_response(
        requested_url="https://careers.example.test/graduate-engineer",
        final_url="https://careers.example.test/graduate-engineer",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>This job is no longer open.</p>"
            b"<a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
            b"Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    with pytest.raises(ValueError, match="not eligible"):
        bind_authority_destinations(
            closed,
            responses=(
                _response(
                    closed.authority_candidates[0],
                    b"<h1>Graduate Engineer</h1><p>Acme</p><p>Apply now</p>",
                ),
            ),
            expected_title="Graduate Engineer",
            expected_company="Acme",
        )


def test_known_provider_detection_is_exact() -> None:
    assert provider_for_url("https://jobs.lever.co/acme/id") == "lever"
    assert provider_for_url("https://jobs.lever.co.evil.test/acme/id") is None
    assert (
        provider_for_url("https://acme.wd3.myworkdayjobs.com/en-US/jobs/job/x_R1")
        == "workday"
    )


def test_provider_home_and_email_links_are_not_vacancy_authority() -> None:
    verdict = classify_live_vacancy_response(
        requested_url="https://jobs.lever.co/acme/68e876da-fa27-4b9e-ad09-ca4805efa8a5",
        final_url="https://jobs.lever.co/acme/68e876da-fa27-4b9e-ad09-ca4805efa8a5",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Apply now</p>"
            b"<a href='/acme'>Company jobs</a>"
            b"<a href='/cdn-cgi/l/email-protection'>Email</a>"
        ),
        expected_title="Graduate Engineer",
    )
    assert verdict.live is False
    assert verdict.reason == "live_source_requires_ats_destination_fetch"
    assert verdict.authority_urls == ()
    assert verdict.authority_candidates == (
        "https://jobs.lever.co/acme/68e876da-fa27-4b9e-ad09-ca4805efa8a5",
    )


def test_unrelated_valid_ats_job_link_substitution_fails_destination_binding() -> None:
    source = classify_live_vacancy_response(
        requested_url="https://careers.example.test/graduate-engineer",
        final_url="https://careers.example.test/graduate-engineer",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Acme</p><p>Apply now</p>"
            b"<a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
            b"Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    substituted = bind_authority_destinations(
        source,
        responses=(
            _response(
                source.authority_candidates[0],
                (
                    b"<h1>Senior Graduate Engineer</h1><p>Acme</p>"
                    b"<button>Apply for this job</button>"
                ),
            ),
        ),
        expected_title="Graduate Engineer",
        expected_company="Acme",
    )
    assert substituted.live is False
    assert substituted.authority_urls == ()
    assert substituted.reason == "ats_destination_identity_unverified"
    assert substituted.destination_evidence[0]["reason"] == "destination_title_mismatch"


def test_company_name_must_be_exact_visible_or_provider_structured_evidence() -> None:
    source = classify_live_vacancy_response(
        requested_url="https://careers.example.test/graduate-engineer",
        final_url="https://careers.example.test/graduate-engineer",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Apply now</p>"
            b"<a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
            b"Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    result = bind_authority_destinations(
        source,
        responses=(
            _response(
                source.authority_candidates[0],
                (
                    b"<h1>Graduate Engineer</h1><p>Acme Holdings</p>"
                    b"<button>Apply for this job</button>"
                ),
            ),
        ),
        expected_title="Graduate Engineer",
        expected_company="Acme",
    )
    assert result.live is False
    assert result.destination_evidence[0]["reason"] == "destination_company_mismatch"


def test_redirect_to_different_provider_job_identity_fails_closed() -> None:
    source = classify_live_vacancy_response(
        requested_url="https://careers.example.test/graduate-engineer",
        final_url="https://careers.example.test/graduate-engineer",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Apply now</p>"
            b"<a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
            b"Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    result = bind_authority_destinations(
        source,
        responses=(
            _response(
                source.authority_candidates[0],
                b"<h1>Graduate Engineer</h1><p>Acme</p><p>Apply now</p>",
                final_url="https://job-boards.greenhouse.io/acme/jobs/9999999",
            ),
        ),
        expected_title="Graduate Engineer",
        expected_company="Acme",
    )
    assert result.live is False
    assert result.destination_evidence[0]["reason"] == (
        "destination_vacancy_identity_mismatch"
    )


def test_destination_binding_requires_exact_archive_hash_and_candidate_coverage() -> None:
    source = classify_live_vacancy_response(
        requested_url="https://careers.example.test/graduate-engineer",
        final_url="https://careers.example.test/graduate-engineer",
        status=200,
        body=(
            b"<h1>Graduate Engineer</h1><p>Apply now</p>"
            b"<a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
            b"Apply now</a>"
        ),
        expected_title="Graduate Engineer",
    )
    body = b"<h1>Graduate Engineer</h1><p>Acme</p><p>Apply now</p>"
    with pytest.raises(ValueError, match="malformed"):
        AuthorityDestinationResponse(
            requested_url=source.authority_candidates[0],
            final_url=source.authority_candidates[0],
            status=200,
            body=body,
            response_artifact_sha256="0" * 64,
            network_evidence_sha256=hashlib.sha256(b"network").hexdigest(),
        )
    with pytest.raises(ValueError, match="exactly cover"):
        bind_authority_destinations(
            source,
            responses=(),
            expected_title="Graduate Engineer",
            expected_company="Acme",
        )
