"""Adversarial matrix for the provider-native alias binding of aggregator keys.

Some live official-authority observations are discovered under an aggregator
board's own key (``swissaijob:12293``, ``developerjobsch:<uuid>``) while their
apply authority is an official provider (Ashby/Lever). The projection binds a
durable, read-only PROVIDER-NATIVE ALIAS to the exact ``(provider, company, job
id)`` parsed from the allowlisted authority URL, keeping provider-native vacancy
identity separate from the discovery-source key. The alias never scores the role
(body identity is deferred to a later, independently gated network capture) and
never mints or merges a duplicate vacancy.

These fixtures reproduce every failure the mandatory projection/archive-integrity
addendum enumerates: altered aggregator body, forged/malformed/missing-outcome
terminal manifests, duplicate aliases, and conflicting prior attempts, plus
ambiguous and non-allowlisted authority URLs. All read-only; no network, browser,
form, upload, click, email, or release action is exercised.
"""

import json
import sqlite3
from pathlib import Path

from career_automation.nongreenhouse_fit_projection import (
    QUARANTINE_ALIAS_AMBIGUOUS,
    QUARANTINE_ALIAS_DUPLICATE,
    QUARANTINE_AUTHORITY_URL,
    RETRY_BLOCKED_REQUIRES_OPERATOR,
    RETRY_PERMANENT_NO_RESUBMIT,
    RETRY_TERMINAL_REQUIRES_REVIEW,
    STATUS_ALIAS_CAPTURE_PENDING,
    STATUS_FIT,
    build_nongreenhouse_fit_projection,
)

ASHBY_HTML = (
    "<h2>Requirements</h2><ul>"
    "<li>Experience building distributed backend systems in Python</li>"
    "<li>Comfortable owning container orchestration and deployment</li>"
    "<li>Strong written communication across an engineering team</li>"
    "</ul>"
)


def _obs(job_key, providers, urls, *, live=True, role="Research Engineer", company="C"):
    return {
        "job_key": job_key,
        "role_title": role,
        "company_name": company,
        "body_sha256": "0" * 64,
        "fit": "0.10",
        "verdict": {
            "live": live,
            "authority_providers": list(providers),
            "authority_urls": list(urls),
        },
    }


def _write_discovery(tmp_path: Path, observations) -> Path:
    document = {
        "schema_version": "jaa.multi-provider-live-discovery.v1",
        "snapshot_sha256": "a" * 64,
        "observed_at": "2026-08-05T23:21:08.736558Z",
        "interaction": {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0},
        "observations": observations,
    }
    path = tmp_path / "discovery.json"
    path.write_text(json.dumps(document, indent=1), encoding="utf-8")
    return path


def _write_jobs_db(tmp_path: Path, postings) -> Path:
    path = tmp_path / "jobs.sqlite3"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE postings (key TEXT PRIMARY KEY, raw_json TEXT)"
        )
        connection.executemany(
            "INSERT INTO postings (key, raw_json) VALUES (?, ?)",
            [(key, json.dumps(value)) for key, value in postings.items()],
        )
        connection.commit()
    finally:
        connection.close()
    return path


def _native_posting(job_key: str, *, html: str = ASHBY_HTML) -> dict:
    _, slug, job_id = job_key.split(":")
    return {
        "id": job_id,
        "jobUrl": f"https://jobs.ashbyhq.com/{slug}/{job_id}",
        "title": "Research Engineer",
        "content_text": "About the company.",
        "descriptionHtml": html,
    }


def _write_terminal(
    archive_root: Path,
    vacancy_key: str,
    outcome,
    *,
    release=None,
    malformed=False,
    drop_outcome=False,
    tag="a",
):
    attempt_dir = archive_root / "attempts" / f"jaa-{tag}-{vacancy_key.replace(':', '_')}"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = attempt_dir / "terminal-manifest.json"
    if malformed:
        manifest_path.write_text("{ this is : not json", encoding="utf-8")
        return
    manifest = {
        "attempt_id": attempt_dir.name,
        "phase": "terminal",
        "vacancy": {"job_key": vacancy_key},
        "release_manifest_sha256": release,
    }
    if not drop_outcome:
        manifest["outcome"] = outcome
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _build(tmp_path, observations, postings, *, archive=None):
    discovery_path = _write_discovery(tmp_path, observations)
    jobs_db = _write_jobs_db(tmp_path, postings)
    return build_nongreenhouse_fit_projection(
        discovery_path=discovery_path,
        jobs_database=jobs_db,
        archive_root=archive,
        require_approved_sources=False,
    )


def _only_alias(document):
    aliases = document["provider_native_aliases"]
    assert len(aliases) == 1
    return aliases[0]


# --- altered aggregator body ------------------------------------------------


def test_alias_never_scores_a_rich_aggregator_body(tmp_path):
    # The aggregator's durable posting carries a fully scoreable Ashby-style body,
    # but it is NOT the provider-native description. It must never be scored or
    # ranked; the role stays capture-pending on its native identity.
    obs = _obs(
        "swissaijob:12293",
        ["ashby"],
        ["https://jobs.ashbyhq.com/mistral.ai/8c71b069-0eda-40d1-8cb1-4094fd9c81de"],
    )
    postings = {
        "swissaijob:12293": {
            "content_text": "About Mistral.",
            "descriptionHtml": ASHBY_HTML,  # a body that WOULD score, if trusted
        }
    }
    document = _build(tmp_path, [obs], postings)
    assert document["ranking"] == []
    assert document["quarantined"] == []
    row = _only_alias(document)
    assert row["status"] == STATUS_ALIAS_CAPTURE_PENDING
    assert row["fit"] is None
    assert "evidence_matrix" not in row
    assert "requirement_count" not in row
    assert row["provider_native_alias"]["body_identity_verified"] is False


# --- duplicate alias --------------------------------------------------------


def test_two_aggregator_keys_to_same_native_identity_fail_closed(tmp_path):
    # duplicate-alias: two discovery keys resolve to one native identity. Neither
    # may mint a vacancy; both quarantine and none is capture-pending.
    url = "https://jobs.ashbyhq.com/the-flex/samejob"
    observations = [
        _obs("swissaijob:1", ["ashby"], [url]),
        _obs("developerjobsch:2", ["ashby"], [url]),
    ]
    document = _build(tmp_path, observations, {})
    assert document["provider_native_aliases"] == []
    assert document["ranking"] == []
    statuses = {row["job_key"]: row["status"] for row in document["quarantined"]}
    assert statuses == {
        "swissaijob:1": QUARANTINE_ALIAS_DUPLICATE,
        "developerjobsch:2": QUARANTINE_ALIAS_DUPLICATE,
    }


def test_alias_colliding_with_native_opportunity_fails_closed(tmp_path):
    # conflicting vacancy: an alias resolves to a native identity that is ALSO a
    # natively-keyed ranked opportunity. The alias must not create/merge a
    # duplicate; the native opportunity is untouched.
    native_key = "ashby:acme:job123"
    observations = [
        _obs(
            native_key,
            ["ashby"],
            ["https://jobs.ashbyhq.com/acme/job123"],
            role="Research Engineer",
        ),
        _obs(
            "swissaijob:9",
            ["ashby"],
            ["https://jobs.ashbyhq.com/acme/job123"],
        ),
    ]
    postings = {native_key: _native_posting(native_key)}
    document = _build(tmp_path, observations, postings)
    # Native opportunity binds and is scored; aggregator alias is quarantined.
    assert {r["job_key"] for r in document["ranking"]} == {native_key}
    assert document["ranking"][0]["status"] == STATUS_FIT
    assert document["provider_native_aliases"] == []
    quarantined = {r["job_key"]: r["status"] for r in document["quarantined"]}
    assert quarantined == {"swissaijob:9": QUARANTINE_ALIAS_DUPLICATE}


# --- ambiguous alias --------------------------------------------------------


def test_ambiguous_authority_urls_fail_closed(tmp_path):
    # Two distinct native identities in the authority URLs → no single vacancy can
    # be bound. Fail closed rather than guess.
    obs = _obs(
        "swissaijob:1",
        ["ashby"],
        [
            "https://jobs.ashbyhq.com/acme/jobA",
            "https://jobs.ashbyhq.com/acme/jobB",
        ],
    )
    document = _build(tmp_path, [obs], {})
    assert document["provider_native_aliases"] == []
    assert document["quarantined"][0]["status"] == QUARANTINE_ALIAS_AMBIGUOUS


# --- unsafe authority URLs never mint an alias ------------------------------


def test_non_https_url_not_aliased(tmp_path):
    obs = _obs("swissaijob:1", ["ashby"], ["http://jobs.ashbyhq.com/acme/jobA"])
    document = _build(tmp_path, [obs], {})
    assert document["provider_native_aliases"] == []
    assert document["quarantined"][0]["status"] == QUARANTINE_AUTHORITY_URL


def test_non_allowlisted_host_not_aliased(tmp_path):
    obs = _obs("swissaijob:1", ["ashby"], ["https://evil.example/acme/jobA"])
    document = _build(tmp_path, [obs], {})
    assert document["provider_native_aliases"] == []
    assert document["quarantined"][0]["status"] == QUARANTINE_AUTHORITY_URL


def test_userinfo_in_authority_url_not_aliased(tmp_path):
    obs = _obs(
        "swissaijob:1",
        ["ashby"],
        ["https://user:pw@jobs.ashbyhq.com/acme/jobA"],
    )
    document = _build(tmp_path, [obs], {})
    assert document["provider_native_aliases"] == []
    assert document["quarantined"][0]["status"] == QUARANTINE_AUTHORITY_URL


def test_short_path_not_aliased(tmp_path):
    # A host-only or single-segment path cannot yield (slug, id).
    obs = _obs("swissaijob:1", ["ashby"], ["https://jobs.ashbyhq.com/acme"])
    document = _build(tmp_path, [obs], {})
    assert document["provider_native_aliases"] == []
    assert document["quarantined"][0]["status"] == QUARANTINE_AUTHORITY_URL


def test_apply_suffix_tolerated(tmp_path):
    # The real The-Flex URLs end in ``/application``; it must be tolerated.
    obs = _obs(
        "developerjobsch:x",
        ["ashby"],
        ["https://jobs.ashbyhq.com/the-flex/82eafc9b/application"],
    )
    document = _build(tmp_path, [obs], {})
    alias = _only_alias(document)["provider_native_alias"]
    assert alias["native_job_key"] == "ashby:the-flex:82eafc9b"
    assert alias["canonical_authority_url"] == "https://jobs.ashbyhq.com/the-flex/82eafc9b"


# --- prior attempts bar re-capture ------------------------------------------


def test_prior_blocked_under_native_key_blocks_capture(tmp_path):
    obs = _obs("swissaijob:1", ["ashby"], ["https://jobs.ashbyhq.com/the-flex/jid1"])
    archive = tmp_path / "archive"
    archive.mkdir()
    _write_terminal(archive, "ashby:the-flex:jid1", "blocked")
    document = _build(tmp_path, [obs], {}, archive=archive)
    row = _only_alias(document)
    assert row["capture_blocked_by_prior_attempt"] is True
    assert row["retry_authority"] == RETRY_BLOCKED_REQUIRES_OPERATOR
    assert len(row["prior_attempts"]) == 1


def test_prior_attempt_under_discovery_key_blocks_capture(tmp_path):
    # A terminal attempt recorded under the aggregator discovery key itself must
    # also bar re-capture.
    obs = _obs("swissaijob:1", ["ashby"], ["https://jobs.ashbyhq.com/the-flex/jid1"])
    archive = tmp_path / "archive"
    archive.mkdir()
    _write_terminal(archive, "swissaijob:1", "blocked")
    document = _build(tmp_path, [obs], {}, archive=archive)
    row = _only_alias(document)
    assert row["capture_blocked_by_prior_attempt"] is True
    assert len(row["prior_attempts"]) == 1


def test_prior_success_under_native_key_is_permanent(tmp_path):
    # conflicting-attempt: a release-bearing success plus a blocked attempt on the
    # native identity → permanent no-resubmit, the strongest bar.
    obs = _obs("swissaijob:1", ["ashby"], ["https://jobs.ashbyhq.com/the-flex/jid1"])
    archive = tmp_path / "archive"
    archive.mkdir()
    _write_terminal(
        archive, "ashby:the-flex:jid1", "submitted_success", release="f" * 64, tag="s"
    )
    _write_terminal(archive, "ashby:the-flex:jid1", "blocked", tag="b")
    document = _build(tmp_path, [obs], {}, archive=archive)
    row = _only_alias(document)
    assert row["capture_blocked_by_prior_attempt"] is True
    assert row["retry_authority"] == RETRY_PERMANENT_NO_RESUBMIT
    assert len(row["prior_attempts"]) == 2


def test_missing_outcome_manifest_still_blocks_capture(tmp_path):
    # missing-outcome: a finalized terminal manifest with no outcome is still a
    # prior terminal attempt; it must block, under review — never be ignored.
    obs = _obs("swissaijob:1", ["ashby"], ["https://jobs.ashbyhq.com/the-flex/jid1"])
    archive = tmp_path / "archive"
    archive.mkdir()
    _write_terminal(archive, "ashby:the-flex:jid1", None, drop_outcome=True)
    document = _build(tmp_path, [obs], {}, archive=archive)
    row = _only_alias(document)
    assert row["capture_blocked_by_prior_attempt"] is True
    assert row["retry_authority"] == RETRY_TERMINAL_REQUIRES_REVIEW


def test_malformed_manifest_neither_blocks_nor_clears(tmp_path):
    # forged/malformed-manifest: an unreadable terminal manifest is not a trusted
    # attempt record. It cannot fabricate a block, and — because it registers no
    # attempt — cannot silently clear one either. The alias stays plain
    # capture-pending, exactly as when no attempt exists.
    obs = _obs("swissaijob:1", ["ashby"], ["https://jobs.ashbyhq.com/the-flex/jid1"])
    archive = tmp_path / "archive"
    archive.mkdir()
    _write_terminal(archive, "ashby:the-flex:jid1", "blocked", malformed=True)
    document = _build(tmp_path, [obs], {}, archive=archive)
    row = _only_alias(document)
    assert "capture_blocked_by_prior_attempt" not in row
    assert "prior_attempts" not in row
    assert row["status"] == STATUS_ALIAS_CAPTURE_PENDING


# --- partition accounting stays exact ---------------------------------------


def test_alias_keeps_live_partition_exact(tmp_path):
    # An aliased aggregator key is still an official-authority live observation, so
    # official + unresolved must still reconstitute the exact live set.
    observations = [
        _obs("swissaijob:1", ["ashby"], ["https://jobs.ashbyhq.com/the-flex/jid1"]),
        _obs("workable:delta:live", ["workable"], ["https://apply.workable.com/delta/live"]),
    ]
    document = _build(tmp_path, observations, {})
    recon = document["live_source_reconciliation"]
    assert recon["reconciled"] is True
    assert document["counts"]["provider_native_aliases"] == 1
    assert document["counts"]["unresolved_live_sources"] == 1
