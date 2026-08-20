"""Hermetic tests for the read-only non-Greenhouse ascending-fit projection.

These use a synthetic discovery document and a synthetic immutable jobs database
so no external discovery snapshot is required. The audited candidate evidence,
schema, and policy sources are the real approved inputs (the same ones the
release path pins), matching the established candidate-authority test pattern.

Because the synthetic discovery/jobs-database bytes are deliberately NOT the
approved production artifacts, every advisory build here passes
``require_approved_sources=False``; the authoritative-source gate itself is
exercised by dedicated adversarial tests below.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import textwrap
from decimal import Decimal
from pathlib import Path

import pytest

from career_automation import candidate_authority as ca
from career_automation.nongreenhouse_fit_projection import (
    LEVER_NATIVE_BODY_FIELD,
    PROJECTION_SCHEMA_VERSION,
    PROVIDER_AUTHORITY_HOSTS,
    QUARANTINE_AUTHORITY_URL,
    QUARANTINE_IDENTITY,
    QUARANTINE_LEVER_MALFORMED,
    QUARANTINE_NATIVE_IDENTITY,
    QUARANTINE_NO_HTML,
    QUARANTINE_NO_REQUIREMENTS,
    RETRY_BLOCKED_REQUIRES_OPERATOR,
    RETRY_INDETERMINATE_QUARANTINE,
    RETRY_PERMANENT_NO_RESUBMIT,
    ROUTE_PRIOR_ATTEMPT,
    STATUS_ALIAS_CAPTURE_PENDING,
    STATUS_FIT,
    UNRESOLVED_LIVE_REQUIRES_CAPTURE,
    _UNRESOLVED_SOURCE_FIELDS,
    _bounded_job_key,
    _bounded_sha256,
    _bounded_status,
    _canonical_host,
    _clean_text,
    _LEVER_DESIRABLE_MARKERS,
    _LeverAdapterError,
    _classify_lever_section,
    _enforce_unresolved_allowlist,
    _final_url_host,
    _lever_native_body,
    _validated_lever_heading,
    _live_partition_proof,
    _unresolved_live_record,
    build_nongreenhouse_fit_projection,
    materialize_nongreenhouse_fit_projection,
)

ASHBY_HTML = (
    "<h2>Requirements</h2><ul>"
    "<li>Experience building distributed backend systems in Python</li>"
    "<li>Comfortable owning container orchestration and deployment</li>"
    "<li>Strong written communication across an engineering team</li>"
    "</ul>"
)
# HTML present but with no requirement structure the audited extractor accepts.
LEVER_HTML = "<div>Join a friendly team and enjoy generous benefits.</div>"


def _build(discovery_path, jobs_db, **kwargs):
    kwargs.setdefault("require_approved_sources", False)
    return build_nongreenhouse_fit_projection(
        discovery_path=discovery_path, jobs_database=jobs_db, **kwargs
    )


# A Lever posting mirrors the real provider structure: the opening lives in
# ``description``, each requirement section is a ``lists`` entry pairing a ``text``
# heading with a ``content`` HTML fragment of ``<li>`` bullets, and benefits live
# in ``additional``. None of these fields is a single HTML description, so the
# projection must reassemble them before the audited extractor can score the role.
def _lever_posting(role_title):
    return {
        "content_text": "About Beta. What you'll do and who you are.",
        "description": "<h2>About Beta</h2><div>We build behavioural simulations.</div>",
        "lists": [
            {
                "text": "What You'll Do",
                "content": (
                    "<ul>"
                    "<li>Build distributed backend systems in Python</li>"
                    "<li>Own container orchestration and deployment</li>"
                    "</ul>"
                ),
            },
            {
                "text": "Who You Are",
                "content": (
                    "<ul>"
                    "<li>Strong written communication across an engineering team</li>"
                    "<li>Experience deploying LLM agent systems in Python on AWS</li>"
                    "</ul>"
                ),
            },
        ],
        "additional": (
            "<h3>What We Offer</h3><ul>"
            "<li>Competitive compensation and meaningful equity</li>"
            "</ul>"
        ),
    }


def _observation(job_key, role_title, company, providers, url, *, live=True, fit="0.10"):
    return {
        "job_key": job_key,
        "role_title": role_title,
        "company_name": company,
        "body_sha256": "0" * 64,
        "fit": fit,
        "verdict": {
            "live": live,
            "authority_providers": list(providers),
            "authority_urls": [url] if url else [],
        },
    }


def _discovery(observations, *, interaction=None):
    return {
        "schema_version": "jaa.multi-provider-live-discovery.v1",
        "snapshot_sha256": "a" * 64,
        "observed_at": "2026-08-05T23:21:08.736558Z",
        "interaction": interaction
        or {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0},
        "observations": observations,
    }


def _write_discovery(tmp_path: Path, document) -> Path:
    path = tmp_path / "discovery.json"
    path.write_text(json.dumps(document, indent=1), encoding="utf-8")
    return path


def _bind_native(job_key: str, posting: dict) -> dict:
    """Inject the provider-native immutable identity a real posting carries.

    Provider-hosted Ashby/Lever postings in the real jobs database carry a native
    ``id`` equal to the job identity and a native apply URL on the provider host.
    Synthetic fixtures that model a genuine posting get those fields derived from
    the ``job_key`` so they pass the identity gates; adversarial fixtures opt out
    with ``bind_identity=False`` and set their own (or no) identity fields.
    """

    parts = job_key.split(":")
    if len(parts) != 3 or parts[0] not in PROVIDER_AUTHORITY_HOSTS:
        return posting
    provider, slug, job_id = parts
    host = PROVIDER_AUTHORITY_HOSTS[provider]
    suffix = "/apply" if provider == "lever" else ""
    posting = dict(posting)
    posting.setdefault("id", job_id)
    posting.setdefault("jobUrl", f"https://{host}/{slug}/{job_id}{suffix}")
    return posting


def _write_jobs_db(tmp_path: Path, postings, *, bind_identity=True) -> Path:
    path = tmp_path / "jobs.sqlite3"
    if bind_identity:
        postings = {key: _bind_native(key, value) for key, value in postings.items()}
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE postings (key TEXT PRIMARY KEY, raw_json TEXT)")
        connection.executemany(
            "INSERT INTO postings (key, raw_json) VALUES (?, ?)",
            [(key, json.dumps(value)) for key, value in postings.items()],
        )
        connection.commit()
    finally:
        connection.close()
    return path


def _write_terminal_attempt(archive_root: Path, job_key: str, outcome: str, *, release=None):
    """Write a minimal finalized terminal attempt manifest for ``job_key``."""

    attempt_id = f"jaa-{outcome}-{job_key.replace(':', '_')}"
    attempt_dir = archive_root / "attempts" / attempt_id
    attempt_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "attempt_id": attempt_id,
        "phase": "terminal",
        "outcome": outcome,
        "vacancy": {"job_key": job_key},
        "release_manifest_sha256": release,
    }
    (attempt_dir / "terminal-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )


def _standard_case(tmp_path: Path):
    observations = [
        _observation(
            "ashby:acme:high",
            "Senior AI Engineer",
            "Acme",
            ["ashby"],
            "https://jobs.ashbyhq.com/acme/high",
            fit="0.42",
        ),
        _observation(
            "ashby:acme:low",
            "Backend Engineer",
            "Acme",
            ["ashby"],
            "https://jobs.ashbyhq.com/acme/low",
            fit="0.11",
        ),
        _observation(
            "lever:beta:noreq",
            "Software Engineer",
            "Beta",
            ["lever"],
            "https://jobs.lever.co/beta/noreq",
        ),
        _observation(
            "ashby:gamma:plain",
            "Research Engineer",
            "Gamma",
            ["ashby"],
            "https://jobs.ashbyhq.com/gamma/plain",
        ),
        # non-live and non-authority live observations must be excluded.
        _observation(
            "ashby:acme:dead",
            "Dead Role",
            "Acme",
            ["ashby"],
            "https://jobs.ashbyhq.com/acme/dead",
            live=False,
        ),
        _observation(
            "workable:delta:live",
            "Other Role",
            "Delta",
            ["workable"],
            "https://apply.workable.com/delta/live",
        ),
    ]
    postings = {
        "ashby:acme:high": {
            "title": "Senior AI Engineer",
            "content_text": "About Acme. We deploy Python agents.",
            "descriptionHtml": ASHBY_HTML.replace(
                "distributed backend systems in Python",
                "deploying LLM agent systems in Python on AWS",
            ),
        },
        "ashby:acme:low": {
            "title": "Backend Engineer",
            "content_text": "About Acme backend.",
            "descriptionHtml": ASHBY_HTML,
        },
        "lever:beta:noreq": {
            "title": "Software Engineer",
            "content_text": "About Beta.",
            "description": LEVER_HTML,
        },
        "ashby:gamma:plain": {
            "title": "Research Engineer",
            "content_text": "About Gamma plain text only, no markup.",
            "description": "Plain text description with no HTML markup at all.",
        },
    }
    discovery_path = _write_discovery(tmp_path, _discovery(observations))
    jobs_db = _write_jobs_db(tmp_path, postings)
    return discovery_path, jobs_db


def test_partition_and_ordering(tmp_path):
    discovery_path, jobs_db = _standard_case(tmp_path)
    document = _build(discovery_path, jobs_db)
    assert document["schema_version"] == PROJECTION_SCHEMA_VERSION
    assert document["counts"] == {
        "selected": 4,
        "fit_recomputed": 2,
        "prior_attempts": 0,
        "provider_native_aliases": 0,
        "quarantined": 2,
        # The one live non-official-authority source (``workable:delta:live``) is
        # enumerated, not silently dropped.
        "unresolved_live_sources": 1,
    }

    ranking = document["ranking"]
    assert {row["job_key"] for row in ranking} == {"ashby:acme:low", "ashby:acme:high"}
    assert [row["ascending_fit_rank"] for row in ranking] == [1, 2]
    # Ranking is strictly weakest-fit-first (ties broken by job_key).
    fits = [(Decimal(row["fit"]), row["job_key"]) for row in ranking]
    assert fits == sorted(fits)
    assert all(row["status"] == STATUS_FIT for row in ranking)
    # Every ranked record binds its canonical provider authority URL and native id.
    for row in ranking:
        assert row["authority_url"].startswith("https://jobs.ashbyhq.com/")
        assert row["provider_native_id"]

    quarantine_reasons = {
        row["job_key"]: row["status"] for row in document["quarantined"]
    }
    assert quarantine_reasons == {
        "lever:beta:noreq": QUARANTINE_NO_REQUIREMENTS,
        "ashby:gamma:plain": QUARANTINE_NO_HTML,
    }


def test_non_release_and_no_eligibility(tmp_path):
    discovery_path, jobs_db = _standard_case(tmp_path)
    document = _build(discovery_path, jobs_db)
    assert document["release_capable"] is False
    assert document["authorizes_action"] is False
    assert document["eligibility_determined"] is False
    # Advisory build over synthetic sources is never authoritative.
    assert document["authoritative"] is False
    # No opportunity record may carry an eligibility decision or release token.
    for row in document["ranking"] + document["quarantined"]:
        assert "decision" not in row
        assert "eligible" not in row
    # An unresolved live source is a worklist entry only: no fit, eligibility, or
    # decision may be attached to it.
    for row in document["unresolved_live_sources"]:
        assert row["requires"] == UNRESOLVED_LIVE_REQUIRES_CAPTURE
        assert "fit" not in row
        assert "decision" not in row
        assert "eligible" not in row


def test_fit_matches_audited_primitive(tmp_path):
    discovery_path, jobs_db = _standard_case(tmp_path)
    document = _build(discovery_path, jobs_db)
    _, evidence = _load_evidence()
    for row in document["ranking"]:
        markup = _posting_html(jobs_db, row["job_key"], row["description_html_field"])
        matrix = ca._evidence_matrix(markup, evidence)
        assert row["fit"] == ca.fit_from_evidence_matrix(matrix)
        # The invalid empty-profile fit must be recorded as discarded, not used.
        assert "empty_profile_fit_discarded" in row


def test_deterministic_bytes(tmp_path):
    discovery_path, jobs_db = _standard_case(tmp_path)
    first = _build(discovery_path, jobs_db)
    second = _build(discovery_path, jobs_db)
    assert ca._json_bytes(first) == ca._json_bytes(second)


def test_identity_mismatch_quarantined(tmp_path):
    observations = [
        _observation(
            "ashby:acme:x",
            "Senior AI Engineer",
            "Acme",
            ["ashby"],
            "https://jobs.ashbyhq.com/acme/x",
        )
    ]
    postings = {
        "ashby:acme:x": {
            "title": "A Completely Different Title",
            "content_text": "About Acme.",
            "descriptionHtml": ASHBY_HTML,
        }
    }
    discovery_path = _write_discovery(tmp_path, _discovery(observations))
    jobs_db = _write_jobs_db(tmp_path, postings)
    document = _build(discovery_path, jobs_db)
    assert document["counts"]["fit_recomputed"] == 0
    # Authority + native id both bind; only the title differs materially.
    assert document["quarantined"][0]["status"] == QUARANTINE_IDENTITY
    assert document["quarantined"][0]["title_match"] is False


def test_nonzero_interaction_rejected(tmp_path):
    observations = [
        _observation(
            "ashby:acme:x", "Role", "Acme", ["ashby"], "https://jobs.ashbyhq.com/acme/x"
        )
    ]
    discovery = _discovery(
        observations,
        interaction={"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 1},
    )
    discovery_path = _write_discovery(tmp_path, discovery)
    jobs_db = _write_jobs_db(tmp_path, {})
    with pytest.raises(ValueError, match="pure read-only observation"):
        _build(discovery_path, jobs_db)


def test_wrong_schema_rejected(tmp_path):
    discovery = _discovery([])
    discovery["schema_version"] = "something.else.v1"
    discovery_path = _write_discovery(tmp_path, discovery)
    jobs_db = _write_jobs_db(tmp_path, {})
    with pytest.raises(ValueError, match="multi-provider live discovery"):
        _build(discovery_path, jobs_db)


def test_no_official_authority_rejected(tmp_path):
    observations = [
        _observation(
            "workable:x:1", "Role", "X", ["workable"], "https://apply.workable.com/x"
        )
    ]
    discovery_path = _write_discovery(tmp_path, _discovery(observations))
    jobs_db = _write_jobs_db(tmp_path, {})
    with pytest.raises(ValueError, match="official-authority live"):
        _build(discovery_path, jobs_db)


def test_materialize_create_only_idempotent(tmp_path):
    discovery_path, jobs_db = _standard_case(tmp_path)
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    first = materialize_nongreenhouse_fit_projection(
        discovery_path=discovery_path,
        jobs_database=jobs_db,
        archive_root=archive_root,
        require_approved_sources=False,
    )
    assert first.projection_path.exists()
    assert first.object_path.read_bytes() == first.value
    # Re-materializing identical inputs verifies the create-only object matches.
    second = materialize_nongreenhouse_fit_projection(
        discovery_path=discovery_path,
        jobs_database=jobs_db,
        archive_root=archive_root,
        require_approved_sources=False,
    )
    assert second.sha256 == first.sha256

    # A mutated object of the same name must be rejected as not create-only.
    first.object_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="create-only"):
        materialize_nongreenhouse_fit_projection(
            discovery_path=discovery_path,
            jobs_database=jobs_db,
            archive_root=archive_root,
            require_approved_sources=False,
        )


def test_lever_native_body_scored_by_audited_primitive(tmp_path):
    # Lever discovery observations carry no role title and the durable posting has
    # no title column, exactly as in the real jobs database; identity matches on the
    # empty title and the split body is reassembled from native fields.
    observation = _observation(
        "lever:beta:structured",
        "",
        "Beta",
        ["lever"],
        "https://jobs.lever.co/beta/structured",
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(tmp_path, {"lever:beta:structured": _lever_posting("")})
    document = _build(discovery_path, jobs_db)
    assert document["counts"] == {
        "selected": 1,
        "fit_recomputed": 1,
        "prior_attempts": 0,
        "provider_native_aliases": 0,
        "quarantined": 0,
        "unresolved_live_sources": 0,
    }
    row = document["ranking"][0]
    assert row["status"] == STATUS_FIT
    assert row["description_html_field"] == LEVER_NATIVE_BODY_FIELD

    # Fit and requirement count come entirely from the audited primitive applied to
    # the reassembled provider-native body — no fit logic is added here.
    _, evidence = _load_evidence()
    field, markup, components = _lever_native_body(_lever_posting(""))
    assert field == LEVER_NATIVE_BODY_FIELD
    matrix = ca._evidence_matrix(markup, evidence)
    assert row["fit"] == ca.fit_from_evidence_matrix(matrix)
    assert row["requirement_count"] == len(matrix)

    # The reconstruction is fully reproducible: every contributing native field is
    # recorded with its exact SHA-256 in native order.
    assert row["description_reconstruction"] == list(components)
    assert [c["field"] for c in row["description_reconstruction"]] == [
        "description",
        "lists[0].text",
        "lists[0].content",
        "lists[1].text",
        "lists[1].content",
        "additional",
    ]
    assert row["description_html_sha256"] == ca.hashlib.sha256(markup.encode()).hexdigest()


def test_lever_reconstruction_is_deterministic(tmp_path):
    observation = _observation(
        "lever:beta:s", "", "Beta", ["lever"], "https://jobs.lever.co/beta/s"
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(tmp_path, {"lever:beta:s": _lever_posting("")})
    first = _build(discovery_path, jobs_db)
    second = _build(discovery_path, jobs_db)
    assert ca._json_bytes(first) == ca._json_bytes(second)


def test_lever_benefits_only_lists_yield_no_requirements(tmp_path):
    # A Lever posting whose only section is a benefits list must not mint any
    # requirement: the audited benefit filters, not this projection, decide.
    posting = {
        "content_text": "About Beta and our perks.",
        "description": "<div>We are a friendly, growing team.</div>",
        "lists": [
            {
                "text": "What We Offer",
                "content": (
                    "<ul><li>Competitive compensation and equity</li>"
                    "<li>Unlimited holiday</li></ul>"
                ),
            }
        ],
    }
    observation = _observation(
        "lever:beta:perks", "", "Beta", ["lever"], "https://jobs.lever.co/beta/perks"
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(tmp_path, {"lever:beta:perks": posting})
    document = _build(discovery_path, jobs_db)
    assert document["counts"]["fit_recomputed"] == 0
    assert document["quarantined"][0]["status"] == QUARANTINE_NO_REQUIREMENTS


def test_native_reconstruction_is_lever_scoped(tmp_path):
    # A non-Lever board carrying a stray ``lists`` field must be scored from its
    # own HTML description field, never the Lever reassembly path.
    posting = {
        "title": "Backend Engineer",
        "content_text": "About Acme backend.",
        "descriptionHtml": ASHBY_HTML,
        "lists": [{"text": "Ignored", "content": "<ul><li>should not be read</li></ul>"}],
    }
    observation = _observation(
        "ashby:acme:withlists",
        "Backend Engineer",
        "Acme",
        ["ashby"],
        "https://jobs.ashbyhq.com/acme/withlists",
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(tmp_path, {"ashby:acme:withlists": posting})
    document = _build(discovery_path, jobs_db)
    row = document["ranking"][0]
    assert row["description_html_field"] == "descriptionHtml"
    assert "description_reconstruction" not in row


def test_lever_without_lists_still_quarantines(tmp_path):
    # No native requirement sections at all: falls back to the description field,
    # which holds only a benefits blurb, so the audited extractor finds nothing.
    posting = {"content_text": "About Beta.", "description": LEVER_HTML}
    observation = _observation(
        "lever:beta:noreq", "", "Beta", ["lever"], "https://jobs.lever.co/beta/noreq"
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(tmp_path, {"lever:beta:noreq": posting})
    document = _build(discovery_path, jobs_db)
    assert document["quarantined"][0]["status"] == QUARANTINE_NO_REQUIREMENTS


# --------------------------------------------------------------------------- #
# Strict typed Lever section adapter (closes the 8a5c89d heading-sanitization
# audit). A ``lists[i].text`` heading is provider-native PLAIN TEXT; it is
# validated against a canonical grammar, classified as DATA, and replaced by a
# fixed trusted canonical heading before any markup reaches the audited HTML
# parser. A hostile heading is therefore never parsed as markup at all — it fails
# closed and quarantines the opportunity. The audited extractor still makes every
# requirement decision, now only over trusted headings.
# --------------------------------------------------------------------------- #


def _typed_posting(crafted_heading, section_content):
    """A Lever posting whose first section is a real requirement and whose second
    section carries a crafted heading + benefit content."""

    return {
        "content_text": "About Beta.",
        "description": "<h2>About Beta</h2><div>We build behavioural simulations.</div>",
        "lists": [
            {
                "text": "Requirements",
                "content": (
                    "<ul><li>Seven years of professional Python experience</li></ul>"
                ),
            },
            {"text": crafted_heading, "content": section_content},
        ],
    }


# Every heading shape the 8a5c89d audit named as a residual of the old
# decode-once / strip-angle-bracket transform. The strict grammar must fail closed
# on each — the raw heading never reaches the HTML parser.
_HOSTILE_HEADINGS = {
    "literal_markup": "What We Offer</h2><h2>Requirements",
    "entity_encoded": "What We Offer&lt;/h2&gt;&lt;h2&gt;Requirements",
    "double_encoded": "What We Offer&amp;lt;/h2&amp;gt;&amp;lt;h2&amp;gt;Requirements",
    "numeric_entity": "What We Offer&#60;/h2&#62;&#60;h2&#62;Requirements",
    "hex_entity": "What We Offer&#x3c;/h2&#x3e;Requirements",
    "comment_shaped": "Requirements<!-- hide -->",
    "cdata_shaped": "Requirements<![CDATA[x]]>",
    "pi_shaped": "Requirements<?php echo 1;?>",
    "embedded_nul": "Require\x00ments",
    "control_char": "Require\x07ments",
    "bidi_control": "Requ‮irements",
    "zero_width": "Bene​fits",
    "oversized": "Requirements " + "x" * 300,
}


@pytest.mark.parametrize("name", sorted(_HOSTILE_HEADINGS))
def test_lever_hostile_heading_fails_closed(name):
    # A hostile heading must quarantine the whole native body, never be neutralised
    # into a usable section — the raw heading is never parsed as markup.
    with pytest.raises(_LeverAdapterError):
        _validated_lever_heading(_HOSTILE_HEADINGS[name])


@pytest.mark.parametrize("name", sorted(_HOSTILE_HEADINGS))
def test_lever_hostile_heading_quarantines_opportunity(name, tmp_path):
    # End-to-end: a hostile second-section heading routes the opportunity to the
    # dedicated malformed-native-body quarantine, not into the fresh queue.
    posting = _typed_posting(
        _HOSTILE_HEADINGS[name], "<ul><li>Unlimited holiday allowance</li></ul>"
    )
    document = _single(
        "lever:beta:hostile",
        "https://jobs.lever.co/beta/hostile",
        posting,
        tmp_path,
        role_title="",
        providers=("lever",),
    )
    assert [r["status"] for r in document["quarantined"]] == [QUARANTINE_LEVER_MALFORMED]
    record = document["quarantined"][0]
    assert record.get("fit") is None
    assert "quarantine_detail" in record


def test_lever_zero_width_cannot_smuggle_benefit_as_requirement():
    # The specific classification-evasion risk: a zero-width space inside a benefit
    # heading would defeat the substring benefit marker and promote benefit bullets
    # to essential requirements. The grammar rejects the format character outright.
    with pytest.raises(_LeverAdapterError):
        _validated_lever_heading("What We​Offer")


def test_lever_legitimate_heading_survives_and_binds_exact_raw_bytes():
    # A legitimate padded heading is accepted, its exact raw bytes (padding
    # included) are hashed, and the real requirement is preserved. The emitted
    # heading is the trusted canonical literal, never the raw provider bytes.
    padded = "  What You'll Do  "
    posting = {
        "content_text": "About Beta.",
        "description": "<h2>About Beta</h2><div>We build things.</div>",
        "lists": [
            {
                "text": padded,
                "content": (
                    "<ul><li>Seven years of professional Python experience</li></ul>"
                ),
            }
        ],
    }
    _, markup, components = _lever_native_body(posting)
    heading_component = next(c for c in components if c["field"] == "lists[0].text")
    assert heading_component["sha256"] == ca.hashlib.sha256(padded.encode()).hexdigest()
    # Classification is essential; only the trusted canonical heading is emitted.
    assert heading_component["classification"] == "essential"
    assert heading_component["canonical_heading"] == "Requirements"
    assert "What You'll Do" not in markup
    assert "<h2>Requirements</h2>" in markup
    requirements = [r["requirement_text"].casefold() for r in ca._requirements(markup)]
    assert any("python" in r for r in requirements)


def test_lever_benefit_heading_classified_as_data_and_bullets_dropped():
    # A benefit-section heading is classified as ``benefit`` from data and emitted
    # as the trusted benefit heading, so the audited extractor drops its bullets.
    posting = _typed_posting(
        "What We Offer", "<ul><li>Unlimited holiday allowance</li></ul>"
    )
    _, markup, components = _lever_native_body(posting)
    heading = next(c for c in components if c["field"] == "lists[1].text")
    assert heading["classification"] == "benefit"
    assert heading["canonical_heading"] == "What we offer"
    requirements = [r["requirement_text"].casefold() for r in ca._requirements(markup)]
    assert any("python" in r for r in requirements)  # real requirement preserved
    assert not any("holiday" in r for r in requirements)  # benefit never minted


def test_lever_desirable_heading_classified_as_data():
    # A "nice to have" heading is classified desirable as data; its bullet is a
    # desirable requirement, not essential.
    posting = _typed_posting(
        "Nice to have", "<ul><li>Familiarity with Rust tooling</li></ul>"
    )
    _, markup, components = _lever_native_body(posting)
    heading = next(c for c in components if c["field"] == "lists[1].text")
    assert heading["classification"] == "desirable"
    assert heading["canonical_heading"] == "Nice to have"
    reqs = {r["requirement_text"].casefold(): r["classification"] for r in ca._requirements(markup)}
    rust = next((c for t, c in reqs.items() if "rust" in t), None)
    assert rust == "desirable"


def test_lever_classification_markers_mirror_audited_extractor():
    # The desirable markers used for data classification must stay in sync with the
    # audited extractor's own inline markers so classification cannot drift.
    import inspect

    source = inspect.getsource(ca._requirements)
    for marker in _LEVER_DESIRABLE_MARKERS:
        assert marker in source
    # Benefit markers are consumed directly from the audited constant.
    assert _classify_lever_section("What We Offer") == "benefit"
    assert _classify_lever_section("Requirements") == "essential"


def test_lever_mapping_shaped_lists_fails_closed():
    # A native ``lists`` is an ordered array; a mapping-shaped value is malformed
    # and must fail closed, never be silently treated as absent.
    posting = {
        "content_text": "About Beta.",
        "description": "<h2>About Beta</h2>",
        "lists": {"text": "Requirements", "content": "<ul><li>Python</li></ul>"},
    }
    with pytest.raises(_LeverAdapterError):
        _lever_native_body(posting)


def test_lever_non_mapping_entry_fails_closed():
    # A non-mapping list entry must fail closed rather than be silently skipped.
    posting = {
        "content_text": "About Beta.",
        "description": "<h2>About Beta</h2>",
        "lists": [
            {"text": "Requirements", "content": "<ul><li>Python experience</li></ul>"},
            "unexpected string entry",
        ],
    }
    with pytest.raises(_LeverAdapterError):
        _lever_native_body(posting)


def test_lever_non_string_content_fails_closed():
    # Non-string ``content`` (structured object) must fail closed, never be omitted.
    posting = {
        "content_text": "About Beta.",
        "description": "<h2>About Beta</h2>",
        "lists": [{"text": "Requirements", "content": {"nested": "object"}}],
    }
    with pytest.raises(_LeverAdapterError):
        _lever_native_body(posting)


def test_lever_missing_heading_fails_closed():
    # A list entry with no heading fails closed (missing heading), never silently
    # promoting its bullets under the previous section.
    posting = {
        "content_text": "About Beta.",
        "description": "<h2>About Beta</h2>",
        "lists": [{"content": "<ul><li>Python experience</li></ul>"}],
    }
    with pytest.raises(_LeverAdapterError):
        _lever_native_body(posting)


# --------------------------------------------------------------------------- #
# Adversarial closures for the 3dcf741 authoritative-queue audit.
# --------------------------------------------------------------------------- #


def _single(job_key, url, posting, tmp_path, *, role_title="Role", providers=("ashby",),
            bind_identity=True, **build_kwargs):
    observation = _observation(job_key, role_title, "Acme", list(providers), url)
    if posting is not None and "title" in posting and posting["title"] is None:
        posting = {k: v for k, v in posting.items() if k != "title"}
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(
        tmp_path, {job_key: posting} if posting is not None else {}, bind_identity=bind_identity
    )
    return _build(discovery_path, jobs_db, **build_kwargs)


def _scored_posting(title="Role"):
    return {"title": title, "content_text": "About Acme.", "descriptionHtml": ASHBY_HTML}


def test_authority_url_absent_quarantined(tmp_path):
    # H1: a provider claim with NO authority URL cannot be bound.
    document = _single(
        "ashby:acme:noeurl", "", _scored_posting(), tmp_path
    )
    assert document["counts"]["fit_recomputed"] == 0
    assert document["quarantined"][0]["status"] == QUARANTINE_AUTHORITY_URL


def test_authority_url_unrelated_quarantined(tmp_path):
    # H1: an unrelated host / different job path does not authorize the record.
    document = _single(
        "ashby:acme:real",
        "https://evil.example.com/acme/real",
        _scored_posting(),
        tmp_path,
    )
    assert document["quarantined"][0]["status"] == QUARANTINE_AUTHORITY_URL


def test_authority_url_wrong_path_quarantined(tmp_path):
    # H1/H2: allowlisted host but the path resolves to a DIFFERENT job identity.
    document = _single(
        "ashby:acme:real",
        "https://jobs.ashbyhq.com/acme/someone-else",
        _scored_posting(),
        tmp_path,
    )
    assert document["quarantined"][0]["status"] == QUARANTINE_AUTHORITY_URL


def test_aggregator_key_binds_capture_pending_alias(tmp_path):
    # An aggregator job_key with an official-provider Ashby authority URL (exactly
    # the real swissaijob/developerjobsch shape) binds a durable PROVIDER-NATIVE
    # ALIAS to the native identity parsed from that URL. It is NEVER scored or
    # ranked from the aggregator's own durable body (altered-body guard); the role
    # stays capture-pending until a later gated network capture.
    observation = _observation(
        "swissaijob:12293",
        "Research Engineer",
        "Mistral AI",
        ["ashby"],
        "https://jobs.ashbyhq.com/mistral.ai/8c71b069-0eda-40d1-8cb1-4094fd9c81de",
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(
        tmp_path,
        {"swissaijob:12293": {"content_text": "About Mistral.", "description": "plain"}},
        bind_identity=False,
    )
    document = _build(discovery_path, jobs_db)
    # Never scored, never ranked, never a generic quarantine.
    assert document["counts"]["fit_recomputed"] == 0
    assert document["ranking"] == []
    assert document["quarantined"] == []
    assert document["counts"]["provider_native_aliases"] == 1
    row = document["provider_native_aliases"][0]
    assert row["status"] == STATUS_ALIAS_CAPTURE_PENDING
    assert row["fit"] is None
    assert "evidence_matrix" not in row  # aggregator body was not scored
    alias = row["provider_native_alias"]
    assert alias["discovery_job_key"] == "swissaijob:12293"
    assert alias["native_job_key"] == "ashby:mistral.ai:8c71b069-0eda-40d1-8cb1-4094fd9c81de"
    assert alias["provider"] == "ashby"
    assert alias["native_company_slug"] == "mistral.ai"
    assert alias["native_job_id"] == "8c71b069-0eda-40d1-8cb1-4094fd9c81de"
    assert (
        alias["canonical_authority_url"]
        == "https://jobs.ashbyhq.com/mistral.ai/8c71b069-0eda-40d1-8cb1-4094fd9c81de"
    )
    assert alias["body_identity_verified"] is False
    assert alias["requires"] == "requires_network_capture"


def test_native_identity_swapped_body_quarantined(tmp_path):
    # H2: authority URL binds, but the durable posting is a DIFFERENT vacancy's
    # body (foreign native id + native URL). It must not masquerade as this role.
    posting = _scored_posting()
    posting["id"] = "a-different-job-id"
    posting["jobUrl"] = "https://jobs.ashbyhq.com/acme/a-different-job-id"
    document = _single(
        "ashby:acme:real",
        "https://jobs.ashbyhq.com/acme/real",
        posting,
        tmp_path,
        bind_identity=False,
    )
    assert document["counts"]["fit_recomputed"] == 0
    assert document["quarantined"][0]["status"] == QUARANTINE_NATIVE_IDENTITY


def test_native_identity_missing_id_quarantined(tmp_path):
    # H2: a posting with no provider-native id cannot prove it is this vacancy.
    posting = _scored_posting()  # no id / jobUrl, bind_identity disabled below
    document = _single(
        "ashby:acme:real",
        "https://jobs.ashbyhq.com/acme/real",
        posting,
        tmp_path,
        bind_identity=False,
    )
    assert document["quarantined"][0]["status"] == QUARANTINE_NATIVE_IDENTITY


def test_case_only_title_variation_accepted(tmp_path):
    # L1: after the strong URL + native-id bindings, a benign case/whitespace-only
    # title variation is accepted rather than falsely quarantined.
    posting = _scored_posting(title="Senior  AI ENGINEER")
    document = _single(
        "ashby:acme:real",
        "https://jobs.ashbyhq.com/acme/real",
        posting,
        tmp_path,
        role_title="Senior AI Engineer",
    )
    assert document["counts"]["fit_recomputed"] == 1
    row = document["ranking"][0]
    assert row["status"] == STATUS_FIT
    # The exact posting title is still recorded and title_match reflects exactness.
    assert row["title_match"] is False


def test_duplicate_job_identity_fails_closed(tmp_path):
    # M2: an exact duplicate official-authority observation must not rank twice.
    observation = _observation(
        "ashby:acme:real", "Role", "Acme", ["ashby"], "https://jobs.ashbyhq.com/acme/real"
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation, dict(observation)]))
    jobs_db = _write_jobs_db(tmp_path, {"ashby:acme:real": _scored_posting()})
    with pytest.raises(ValueError, match="duplicate official-authority"):
        _build(discovery_path, jobs_db)


def test_unapproved_jobs_database_rejected_when_authoritative(tmp_path, monkeypatch):
    # H3: an unapproved jobs database cannot produce an authoritative queue. The
    # discovery is treated as approved so the jobs-database gate is under test.
    from career_automation import nongreenhouse_fit_projection as proj

    discovery_path, jobs_db = _standard_case(tmp_path)
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    monkeypatch.setattr(proj, "APPROVED_DISCOVERY_SHA256", ca._file_sha256(discovery_path))
    monkeypatch.setattr(
        proj,
        "APPROVED_DISCOVERY_COVERAGE",
        proj._discovery_coverage(json.loads(discovery_path.read_text())),
    )
    with pytest.raises(ValueError, match="jobs database hash is not the approved"):
        build_nongreenhouse_fit_projection(
            discovery_path=discovery_path,
            jobs_database=jobs_db,
            archive_root=archive_root,
            require_approved_sources=True,
        )


def test_unapproved_discovery_rejected_when_authoritative(tmp_path, monkeypatch):
    # M1: an arbitrary discovery file with an invented snapshot hash is rejected as
    # authoritative even if the jobs database happens to match the approved hash.
    from career_automation import nongreenhouse_fit_projection as proj

    discovery_path, jobs_db = _standard_case(tmp_path)
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    # Pretend the (synthetic) jobs database is approved so the discovery gate is
    # the one under test; the discovery bytes remain unapproved.
    real_hash = ca._file_sha256(jobs_db)
    monkeypatch.setitem(proj.APPROVED_CANDIDATE_SOURCE_HASHES, "jobs_database", real_hash)
    with pytest.raises(ValueError, match="discovery artifact hash is not the approved"):
        build_nongreenhouse_fit_projection(
            discovery_path=discovery_path,
            jobs_database=jobs_db,
            archive_root=archive_root,
            require_approved_sources=True,
        )


def test_authoritative_requires_archive_binding(tmp_path, monkeypatch):
    # M3: authoritative use must bind a durable archive so prior attempts route.
    from career_automation import nongreenhouse_fit_projection as proj

    discovery_path, jobs_db = _standard_case(tmp_path)
    monkeypatch.setattr(proj, "APPROVED_DISCOVERY_SHA256", ca._file_sha256(discovery_path))
    monkeypatch.setitem(
        proj.APPROVED_CANDIDATE_SOURCE_HASHES, "jobs_database", ca._file_sha256(jobs_db)
    )
    monkeypatch.setattr(
        proj, "APPROVED_DISCOVERY_COVERAGE", proj._discovery_coverage(json.loads(discovery_path.read_text()))
    )
    with pytest.raises(ValueError, match="requires a bound archive"):
        build_nongreenhouse_fit_projection(
            discovery_path=discovery_path,
            jobs_database=jobs_db,
            archive_root=None,
            require_approved_sources=True,
        )


@pytest.mark.parametrize(
    "outcome, expected_retry",
    [
        ("blocked", RETRY_BLOCKED_REQUIRES_OPERATOR),
        ("historical_submitted_success", RETRY_PERMANENT_NO_RESUBMIT),
        ("crashed", RETRY_INDETERMINATE_QUARANTINE),
    ],
)
def test_prior_attempt_routed_out_of_fresh_queue(tmp_path, outcome, expected_retry):
    # M3: a fit-recomputed role whose identity already has a terminal attempt is
    # routed to prior_attempts under the right retry authority, never ranked fresh.
    observation = _observation(
        "ashby:acme:real", "Role", "Acme", ["ashby"], "https://jobs.ashbyhq.com/acme/real"
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(tmp_path, {"ashby:acme:real": _scored_posting()})
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    _write_terminal_attempt(archive_root, "ashby:acme:real", outcome)
    document = _build(discovery_path, jobs_db, archive_root=archive_root)
    assert document["counts"]["fit_recomputed"] == 0
    assert document["counts"]["prior_attempts"] == 1
    routed = document["prior_attempts"][0]
    assert routed["route"] == ROUTE_PRIOR_ATTEMPT
    assert routed["retry_authority"] == expected_retry
    assert routed["job_key"] == "ashby:acme:real"
    # The blocked/success/crashed record never appears in the fresh ascending queue.
    assert document["ranking"] == []


def test_release_manifest_forces_permanent_no_resubmit(tmp_path):
    # M3: a prior click-intent / release manifest is permanent-no-resubmit even if
    # the recorded terminal label looks benign.
    observation = _observation(
        "ashby:acme:real", "Role", "Acme", ["ashby"], "https://jobs.ashbyhq.com/acme/real"
    )
    discovery_path = _write_discovery(tmp_path, _discovery([observation]))
    jobs_db = _write_jobs_db(tmp_path, {"ashby:acme:real": _scored_posting()})
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    _write_terminal_attempt(archive_root, "ashby:acme:real", "abandoned", release="d" * 64)
    document = _build(discovery_path, jobs_db, archive_root=archive_root)
    assert document["prior_attempts"][0]["retry_authority"] == RETRY_PERMANENT_NO_RESUBMIT


# --------------------------------------------------------------------------- #
# Unresolved live-source enumeration — complete, secret-safe live accounting.
# --------------------------------------------------------------------------- #


def _mixed_live_discovery(tmp_path, *, extra_unresolved=()):
    """One official-authority live source plus unresolved live source(s).

    ``_select_opportunities`` requires at least one official-authority live
    source, so a scored Ashby role anchors the cohort; the unresolved rows (live
    sources with no supported official ATS authority) exercise the new partition.
    A non-live Ashby row confirms non-live sources are never enumerated.
    """

    official = _observation(
        "ashby:acme:real", "Role", "Acme", ["ashby"], "https://jobs.ashbyhq.com/acme/real"
    )
    unresolved = {
        "job_key": "jobicy:remote:9001",
        "role_title": "Remote Backend Engineer",
        "company_name": "Jobicy Co",
        "board": "jobicy",
        "location": "Remote (UK)",
        "final_url": "https://jobicy.com/jobs/remote-backend-engineer",
        "status": 200,
        "body_sha256": "b" * 64,
        "fit": "0.05",
        "verdict": {
            "live": True,
            "authority_providers": [],
            "authority_urls": [],
            "reason": "live_discovery_source_without_resolved_ats_authority",
        },
    }
    dead = _observation(
        "ashby:acme:dead",
        "Dead",
        "Acme",
        ["ashby"],
        "https://jobs.ashbyhq.com/acme/dead",
        live=False,
    )
    observations = [official, unresolved, dead, *extra_unresolved]
    discovery_path = _write_discovery(tmp_path, _discovery(observations))
    jobs_db = _write_jobs_db(tmp_path, {"ashby:acme:real": _scored_posting()})
    return discovery_path, jobs_db


def test_unresolved_live_source_enumerated(tmp_path):
    discovery_path, jobs_db = _mixed_live_discovery(tmp_path)
    document = _build(discovery_path, jobs_db)
    assert document["counts"]["unresolved_live_sources"] == 1
    entry = document["unresolved_live_sources"][0]
    assert entry["job_key"] == "jobicy:remote:9001"
    assert entry["board"] == "jobicy"
    assert entry["final_url_host"] == "jobicy.com"
    assert entry["requires"] == UNRESOLVED_LIVE_REQUIRES_CAPTURE
    assert (
        entry["discovery_reason"]
        == "live_discovery_source_without_resolved_ats_authority"
    )
    # Exactly the closed allowlist of fields — nothing more.
    assert set(entry) == set(_UNRESOLVED_SOURCE_FIELDS)


def test_live_source_reconciliation_reconstitutes_live_count(tmp_path):
    discovery_path, jobs_db = _mixed_live_discovery(tmp_path)
    document = _build(discovery_path, jobs_db)
    recon = document["live_source_reconciliation"]
    # One official-authority live source + one unresolved live source == two live.
    assert recon["live"] == 2
    assert recon["official_authority_live_selected"] == 1
    assert recon["unresolved_live_sources"] == 1
    assert recon["reconciled"] is True
    assert (
        recon["official_authority_live_selected"] + recon["unresolved_live_sources"]
        == recon["live"]
    )


def test_unresolved_excludes_official_and_non_live(tmp_path):
    discovery_path, jobs_db = _mixed_live_discovery(tmp_path)
    document = _build(discovery_path, jobs_db)
    keys = {e["job_key"] for e in document["unresolved_live_sources"]}
    # The official-authority live role and the dead role are never unresolved.
    assert keys == {"jobicy:remote:9001"}


def test_unresolved_live_source_is_secret_safe(tmp_path):
    # An unresolved observation carrying secret-bearing fields must never leak them
    # into the projection: only the closed allowlist of public identity fields is
    # copied through, and the final URL is reduced to its host (dropping any token).
    secret = "s3cr3t-session-token"  # noqa: S105 - test fixture, not a real secret
    poison = {
        "job_key": "weworkremotely:foo:42",
        "role_title": "Engineer",
        "company_name": "Foo",
        "board": "weworkremotely",
        "location": "Remote",
        "final_url": f"https://weworkremotely.com/apply?token={secret}",
        "status": 200,
        "body_sha256": "c" * 64,
        "verdict": {
            "live": True,
            "authority_providers": [],
            "authority_urls": [],
            "reason": "live_discovery_source_without_resolved_ats_authority",
        },
        # Secret-bearing / response fields that must be dropped entirely.
        "raw_response": f"Set-Cookie: session={secret}",
        "cookies": {"session": secret},
        "archived_response_sha256": "d" * 64,
        "network_evidence_sha256": "e" * 64,
        "access_token": secret,
    }
    discovery_path, jobs_db = _mixed_live_discovery(tmp_path, extra_unresolved=(poison,))
    document = _build(discovery_path, jobs_db)
    blob = json.dumps(document["unresolved_live_sources"])
    assert secret not in blob
    for leaked in (
        "raw_response",
        "cookies",
        "access_token",
        "archived_response_sha256",
        "network_evidence_sha256",
    ):
        assert leaked not in blob
    entry = next(
        e
        for e in document["unresolved_live_sources"]
        if e["job_key"] == "weworkremotely:foo:42"
    )
    assert entry["final_url_host"] == "weworkremotely.com"
    assert set(entry) == set(_UNRESOLVED_SOURCE_FIELDS)


def test_duplicate_unresolved_live_fails_closed(tmp_path):
    # Two live non-official observations for the same job identity must fail closed
    # exactly as duplicate official-authority observations do.
    dup = {
        "job_key": "jobicy:remote:9001",
        "role_title": "Remote Backend Engineer",
        "company_name": "Jobicy Co",
        "board": "jobicy",
        "final_url": "https://jobicy.com/jobs/x",
        "verdict": {
            "live": True,
            "authority_providers": [],
            "authority_urls": [],
            "reason": "r",
        },
    }
    discovery_path, jobs_db = _mixed_live_discovery(tmp_path, extra_unresolved=(dup,))
    with pytest.raises(ValueError, match="duplicate unresolved live"):
        _build(discovery_path, jobs_db)


def test_authoritative_projection_surfaces_reconciled_unresolved(tmp_path, monkeypatch):
    # The authoritative gate passes with the reconciliation invariant satisfied and
    # still surfaces the unresolved partition; release/action stay false.
    from career_automation import nongreenhouse_fit_projection as proj

    discovery_path, jobs_db = _mixed_live_discovery(tmp_path)
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    monkeypatch.setattr(proj, "APPROVED_DISCOVERY_SHA256", ca._file_sha256(discovery_path))
    monkeypatch.setitem(
        proj.APPROVED_CANDIDATE_SOURCE_HASHES, "jobs_database", ca._file_sha256(jobs_db)
    )
    monkeypatch.setattr(
        proj,
        "APPROVED_DISCOVERY_COVERAGE",
        proj._discovery_coverage(json.loads(discovery_path.read_text())),
    )
    document = build_nongreenhouse_fit_projection(
        discovery_path=discovery_path,
        jobs_database=jobs_db,
        archive_root=archive_root,
        require_approved_sources=True,
    )
    assert document["authoritative"] is True
    assert document["release_capable"] is False
    assert document["authorizes_action"] is False
    assert document["live_source_reconciliation"]["reconciled"] is True
    assert document["counts"]["unresolved_live_sources"] == 1


def _load_evidence():
    from career_automation.nongreenhouse_fit_projection import (
        _approved_candidate_projection,
    )

    return _approved_candidate_projection(ca.CandidateAuthoritySources())


def _posting_html(jobs_db: Path, job_key: str, field: str) -> str:
    connection = sqlite3.connect(f"file:{jobs_db}?mode=ro", uri=True)
    try:
        raw = connection.execute(
            "SELECT raw_json FROM postings WHERE key = ?", (job_key,)
        ).fetchone()[0]
    finally:
        connection.close()
    return json.loads(raw)[field]


# ---------------------------------------------------------------------------
# 60ddb18 unresolved-live accounting hardening — adversarial coverage.
#
# The independent audit of commit 60ddb18 required: a canonical https host (never
# raw netloc); a fail-closed allowlist that survives ``python -O``; strict typed,
# bounded public fields; and an exact set-partition proof over stable identities
# rather than a coincidental count equality. Each requirement is exercised below.
# ---------------------------------------------------------------------------


# --- Canonical https host, never netloc (audit item 1) ---------------------

@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://jobicy.com/apply", "jobicy.com"),
        ("https://JobIcy.COM/x", "jobicy.com"),
        ("https://jobicy.com/x?token=secret", "jobicy.com"),
        ("https://jöbicy.com/x", "xn--jbicy-jua.com"),  # IDNA canonicalization
    ],
)
def test_canonical_host_accepts_and_normalizes(url, expected):
    assert _canonical_host(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@jobicy.com/x",   # embedded credentials
        "https://tok3n@jobicy.com/x",       # userinfo token
        "https://jobicy.com:8443/x",        # explicit port
        "https://jobicy.com:notaport/x",    # malformed port
        "https://[::1]/x",                  # IPv6 literal
        "//jobicy.com/x",                   # scheme-relative
        "http://jobicy.com/x",              # non-HTTPS
        "ftp://jobicy.com/x",               # non-HTTPS scheme
        "https://jobicy..com/x",            # empty IDNA label
        "https://job\x00icy.com/x",         # embedded NUL/control
        "https://jobicy.com​/x",       # zero-width format char
        "https://-jobicy.com/x",            # leading-hyphen label
        "not a url",
        "",
    ],
)
def test_canonical_host_rejects_unsafe(url):
    assert _canonical_host(url) is None


def test_canonical_host_never_leaks_userinfo_token():
    # The whole URL is rejected; the token can never survive into the projection.
    secret = "s3cr3t"  # noqa: S105 - test literal
    assert _canonical_host(f"https://{secret}@jobicy.com/x") is None


def test_final_url_host_uses_canonical_not_netloc():
    # A netloc with mixed case + userinfo + port must not be returned verbatim.
    assert _final_url_host({"final_url": "https://u:p@JobIcy.com:8443/x"}) is None
    assert _final_url_host({"final_url": "https://JobIcy.COM/x"}) == "jobicy.com"


def test_final_url_host_falls_back_to_requested_url():
    assert _final_url_host({"requested_url": "https://jobicy.com/x"}) == "jobicy.com"


# --- Strict typed, bounded public fields (audit item 3) --------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (200, 200),
        (404, 404),
        (True, None),   # bool masquerading as int
        (False, None),
        (99, None),     # below range
        (600, None),    # above range
        ("200", None),  # numeric string
        ({"code": 200}, None),  # structured
        (None, None),
    ],
)
def test_bounded_status(value, expected):
    assert _bounded_status(value) == expected


@pytest.mark.parametrize(
    "value,ok",
    [
        ("a" * 64, True),
        ("A" * 64, False),   # uppercase not canonical
        ("z" * 63, False),   # too short
        ("g" * 64, False),   # non-hex
        (123, False),
        (None, False),
        ({"x": 1}, False),
    ],
)
def test_bounded_sha256(value, ok):
    assert (_bounded_sha256(value) is not None) == ok


@pytest.mark.parametrize(
    "value,expected",
    [
        ("  Remote (UK) ", "Remote (UK)"),
        ("z" * 600, None),          # oversized
        ("bad\x00null", None),      # embedded control
        ("bidi‮flip", None),   # bidi format char
        ({"nested": 1}, None),      # structured
        (123, None),                # non-string
        ("", None),
        ("   ", None),
    ],
)
def test_clean_text(value, expected):
    assert _clean_text(value) == expected


def _unresolved_obs(**over):
    obs = {
        "job_key": "jobicy:remote:9001",
        "role_title": "Engineer",
        "company_name": "Foo",
        "board": "jobicy",
        "location": "Remote",
        "final_url": "https://jobicy.com/x",
        "status": 200,
        "body_sha256": "b" * 64,
        "verdict": {
            "live": True,
            "authority_providers": [],
            "authority_urls": [],
            "reason": "r",
        },
    }
    obs.update(over)
    return obs


def test_unresolved_record_drops_structured_and_control_values():
    rec = _unresolved_live_record(
        _unresolved_obs(
            status={"code": 200},
            location={"city": "London"},
            company_name="X" * 600,
            board="brd\x00",
            body_sha256="not-hex",
            role_title="Re‮versed",
        )
    )
    assert rec["http_status"] is None
    assert rec["location"] is None
    assert rec["company_name"] is None
    assert rec["board"] is None
    assert rec["discovery_body_sha256"] is None
    assert rec["role_title"] is None
    # The closed allowlist is preserved even when every value is dropped.
    assert set(rec) == set(_UNRESOLVED_SOURCE_FIELDS)


@pytest.mark.parametrize("bad", [123, "", "x" * 201, "job\x00key", None, {"k": 1}])
def test_unresolved_job_key_fails_closed(bad):
    with pytest.raises(ValueError, match="job_key"):
        _unresolved_live_record(_unresolved_obs(job_key=bad))


def test_bounded_job_key_accepts_valid():
    assert _bounded_job_key("jobicy:remote:9001") == "jobicy:remote:9001"


# --- Allowlist guard survives python -O (audit item 2) ---------------------

def test_unresolved_allowlist_guard_raises_on_extra_key():
    over_wide = {field: None for field in _UNRESOLVED_SOURCE_FIELDS}
    over_wide["leaked_body"] = "secret"
    with pytest.raises(ValueError, match="allowlist"):
        _enforce_unresolved_allowlist(over_wide)


def test_unresolved_allowlist_guard_raises_on_missing_key():
    partial = {f: None for f in _UNRESOLVED_SOURCE_FIELDS if f != "board"}
    with pytest.raises(ValueError, match="allowlist"):
        _enforce_unresolved_allowlist(partial)


def test_allowlist_guard_enforced_under_optimized_mode():
    # An ``assert`` would be stripped by -O and the over-wide record would pass.
    # The explicit ``if/raise`` must still fire. If it does not, the child exits
    # nonzero via the ``else`` SystemExit and this test fails.
    script = textwrap.dedent(
        """
        from career_automation.nongreenhouse_fit_projection import (
            _enforce_unresolved_allowlist, _UNRESOLVED_SOURCE_FIELDS)
        record = {field: None for field in _UNRESOLVED_SOURCE_FIELDS}
        record["leaked_body"] = "secret"
        try:
            _enforce_unresolved_allowlist(record)
        except ValueError:
            print("RAISED")
        else:
            raise SystemExit("allowlist guard did not fire under -O")
        """
    )
    result = subprocess.run(
        [sys.executable, "-O", "-c", script],
        cwd=str(Path(__file__).resolve().parent),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "RAISED" in result.stdout


# --- Exact set-partition proof (audit item 4) ------------------------------

def test_partition_proof_exact_and_order_independent():
    proof = _live_partition_proof(["a", "b", "c", "d"], ["a", "b"], ["c", "d"])
    assert proof["partitioned"] is True
    assert proof["live_count"] == 4
    assert proof["official_count"] == 2
    assert proof["unresolved_count"] == 2
    for key in (
        "live_identities_sha256",
        "official_identities_sha256",
        "unresolved_identities_sha256",
    ):
        assert len(proof[key]) == 64
    # Sorted identity hashes make the proof order-independent and deterministic.
    assert _live_partition_proof(["d", "c", "b", "a"], ["b", "a"], ["d", "c"]) == proof


@pytest.mark.parametrize(
    "live,official,unresolved",
    [
        (["a", "b", "c"], ["a"], ["b"]),        # c dropped: union != live
        (["a", "b"], ["a"], ["a"]),             # overlap + b missing
        (["a", "b", "a"], ["a"], ["b"]),        # duplicate live identity
        (["a", "b"], ["a", "a"], ["b"]),        # duplicate official identity
        (["a", "b", "c"], ["a", "b"], ["c", "d"]),  # extra unresolved identity
    ],
)
def test_partition_proof_rejects_bad_partitions(live, official, unresolved):
    assert _live_partition_proof(live, official, unresolved)["partitioned"] is False


def test_build_surfaces_partition_proof(tmp_path):
    discovery_path, jobs_db = _mixed_live_discovery(tmp_path)
    document = _build(discovery_path, jobs_db)
    proof = document["live_source_reconciliation"]["partition_proof"]
    assert proof["partitioned"] is True
    assert proof["live_count"] == 2
    assert proof["official_count"] == 1
    assert proof["unresolved_count"] == 1
    assert document["live_source_reconciliation"]["reconciled"] is True


def test_live_observation_without_identity_fails_closed(tmp_path):
    # A live observation with no stable job_key was previously dropped silently by
    # the unresolved selector; it must now fail closed so no live identity is lost.
    official = _observation(
        "ashby:acme:real", "Role", "Acme", ["ashby"], "https://jobs.ashbyhq.com/acme/real"
    )
    ghost = {
        "role_title": "Ghost",
        "company_name": "Nowhere",
        "board": "ghostboard",
        "verdict": {"live": True, "authority_providers": [], "authority_urls": []},
    }
    discovery_path = _write_discovery(tmp_path, _discovery([official, ghost]))
    jobs_db = _write_jobs_db(tmp_path, {"ashby:acme:real": _scored_posting()})
    with pytest.raises(ValueError, match="cannot be partitioned"):
        _build(discovery_path, jobs_db)
