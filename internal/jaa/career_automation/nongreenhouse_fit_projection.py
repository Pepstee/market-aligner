"""Read-only ascending-fit projection for official-authority non-Greenhouse vacancies.

The Greenhouse candidate-authority path (``candidate_authority.py``) is release
capable and locked to a hand-curated, operator-approved Greenhouse cohort. The
global objective additionally holds official-authority live Ashby and Lever
opportunities whose discovery ``fit`` was produced with an empty ranking profile
and is therefore invalid for ordering.

This module recomputes fit for those opportunities from their exact atomic
requirements using ONLY the audited, provider-agnostic requirement/evidence/fit
primitives from ``candidate_authority`` — it never invents requirement extraction
or fit logic. Where the audited extractor cannot deterministically derive atomic
requirements (for example a board whose durable posting holds only plain text),
the opportunity is quarantined with an explicit reason rather than scored from an
unaudited extractor.

Lever postings do not carry a single HTML description field. Lever's own posting
structure splits the body across ``description`` (the opening), a native ``lists``
array where each entry pairs a section ``text`` heading with a ``content`` HTML
fragment of ``<li>`` requirement bullets, and ``additional`` (typically benefits).
For these the projection deterministically reassembles the provider-native body
into one HTML document — each list heading rendered as an ``<h2>`` before its own
``content`` markup — and feeds THAT to the same audited extractor. This is pure
provider-native field selection and assembly; the audited ``_requirements`` /
``_evidence_matrix`` / ``fit_from_evidence_matrix`` primitives remain the sole
requirement, classification, and fit authority, and the exact SHA-256 of the
reassembled body plus each contributing native field is recorded so the input is
independently reconstructable.

The output is explicitly NON-release and authorizes NO action:

* ``release_capable`` is ``false`` and ``authorizes_action`` is ``false``.
* Deterministic eligibility is NOT decided here; it requires operator-approved
  eligibility policy (the ``HARD_*`` classifications) that does not yet exist for
  these vacancies, plus real operator contact enrollment. Until both exist, no
  form fill, upload, click, or email is permitted for any of these opportunities.

The projection reads the same approved immutable jobs database as the release
path (``mode=ro&immutable=1``) and binds its SHA-256, the durable discovery
content address, and the audited candidate projection identity so the recomputed
ordering is fully reconstructable.

Every live source that is NOT one of the supported official providers is also
enumerated, in a secret-safe ``unresolved_live_sources`` partition, as an explicit
worklist for a future read-only network capture slice. This keeps the live-source
accounting complete — the official-authority records and the unresolved records
together reconstitute the discovery ``live`` count exactly — so no live source is
silently dropped and none is treated as ranked, eligible, or release capable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import unicodedata
from html import unescape as _html_unescape
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import urlsplit

# The audited, release-gated candidate-authority module is reused unchanged for
# all requirement extraction, evidence matching, fit computation, canonical JSON,
# and create-only archive writes. This projection adds only selection, per-board
# HTML field choice, identity binding, ordering, and non-release framing.
from career_automation import candidate_authority as _ca
from career_automation.candidate_authority import (
    APPROVED_CANDIDATE_SOURCE_HASHES,
    CandidateAuthoritySources,
)

DISCOVERY_SCHEMA_VERSION = "jaa.multi-provider-live-discovery.v1"
PROJECTION_SCHEMA_VERSION = "jaa.nongreenhouse-fit-projection.v2"

# Providers whose apply authority this projection covers.
OFFICIAL_AUTHORITY_PROVIDERS = frozenset({"ashby", "lever"})

# The only hosts whose posting URL is treated as an official provider apply
# authority. An observation whose ``authority_urls`` do not contain an allowlisted
# host AND path that resolve to the record's own stable job identity is NOT bound
# to that provider — it is quarantined, never ranked. This defeats a label-only
# ``authority_providers`` claim and an unrelated / aggregator-scraped URL.
PROVIDER_AUTHORITY_HOSTS: Mapping[str, str] = {
    "ashby": "jobs.ashbyhq.com",
    "lever": "jobs.lever.co",
}

# Approved, immutable production inputs. The projection is only AUTHORITATIVE when
# both the discovery artifact bytes and the jobs database bytes match these exact
# hashes and the discovery coverage contract holds. Anything else is advisory and
# must set ``authoritative`` false; a caller-declared ``snapshot_sha256`` inside a
# discovery file is never trusted in place of the artifact's own byte hash.
APPROVED_DISCOVERY_SHA256 = (
    "ebe3b9992fafd94bc938b20dd98a43c08adaa48b15a7d2ae1160f5642720ff9a"
)
APPROVED_DISCOVERY_COVERAGE: Mapping[str, int] = {
    "observations": 307,
    "unique_job_keys": 307,
    "live": 75,
    "official_authority_live": 15,
}

# Ordered candidate HTML description fields to feed to the audited requirement
# extractor. The first field that is a string containing markup is used. This is
# only field selection — never new extraction logic.
HTML_DESCRIPTION_FIELDS: tuple[str, ...] = (
    "descriptionHtml",
    "description",
    "descriptionBody",
    "descriptionPlain",
)

# Provider whose posting body is split across native fields rather than a single
# HTML description field.
LEVER_PROVIDER = "lever"
# Synthetic field label recorded for a reassembled Lever provider-native body. It
# is not a real posting column; ``description_reconstruction`` records the exact
# contributing native fields so the input is independently reproducible.
LEVER_NATIVE_BODY_FIELD = "lever:native-body"

STATUS_FIT = "fit_recomputed"
QUARANTINE_NO_POSTING = "posting_absent_from_jobs_database"
QUARANTINE_IDENTITY = "vacancy_identity_mismatch"
QUARANTINE_NO_HTML = "no_durable_html_description"
QUARANTINE_NO_REQUIREMENTS = "no_deterministic_atomic_requirements"
QUARANTINE_NO_CONTENT_TEXT = "no_durable_content_text"
# The record's ``authority_providers`` claim is not backed by an allowlisted
# provider-host authority URL that resolves to the record's own job identity.
QUARANTINE_AUTHORITY_URL = "provider_authority_url_unverified"
# The durable posting's own provider-native immutable identity (id + native apply
# URL) does not resolve to the same company/job as the bound authority URL, so a
# swapped-body row cannot masquerade as this vacancy.
QUARANTINE_NATIVE_IDENTITY = "provider_native_identity_mismatch"
# A Lever posting whose native ``lists`` shape or section heading is malformed,
# hostile, or ambiguous. The strict typed adapter fails closed on such input
# rather than silently omitting provider-native content, so a crafted heading can
# never quietly reclassify or hide a requirement section.
QUARANTINE_LEVER_MALFORMED = "lever_native_body_malformed"

# ---- Provider-native alias for aggregator discovery keys ---------------------
# Some live official-authority observations are discovered under an aggregator
# board's own key (``swissaijob:12293``, ``developerjobsch:<uuid>``) yet their
# apply authority is an official provider (Ashby/Lever). The aggregator's durable
# jobs-database posting holds only the aggregator's own scraped body, never the
# provider-native description, so the opportunity CANNOT be scored from it. Rather
# than discard the durable, allowlisted provider apply URL these observations
# carry, the projection binds a durable, read-only PROVIDER-NATIVE ALIAS: the
# exact ``(provider, company_slug, native_job_id)`` parsed from that authority URL.
# The alias keeps provider-native vacancy identity separate from the discovery
# source key, never mints a fresh duplicate vacancy, and never scores the role —
# body identity stays deferred to a later, independently gated network-capture
# slice. This status marks such a bound, capture-pending alias.
STATUS_ALIAS_CAPTURE_PENDING = "provider_native_alias_requires_capture"
# The authority URLs resolve to more than one distinct provider-native identity,
# so no single native vacancy can be bound. Fail closed rather than guess.
QUARANTINE_ALIAS_AMBIGUOUS = "provider_native_alias_ambiguous"
# Two discovery keys alias to the same provider-native identity, or an alias would
# collide with a natively-keyed opportunity. Either would create/merge a duplicate
# vacancy, so every colliding record fails closed instead of ranking.
QUARANTINE_ALIAS_DUPLICATE = "provider_native_alias_duplicate"
# The public reason surfaced on a bound alias: the provider-native body must still
# be captured (network, independently gated) before the role can be scored.
ALIAS_REQUIRES_CAPTURE = "requires_network_capture"

# A provider-native company slug and job id parsed from an authority-URL path.
# Bounded, control-free, no path separators/spaces; permissive enough for real
# Ashby slugs (``mistral.ai``, ``the-flex``) and UUID/numeric ids.
_ALIAS_SLUG_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,99}\Z")
_ALIAS_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
# Optional trailing apply-page path segments an Ashby/Lever native URL may carry
# after ``/{slug}/{id}``.
_ALIAS_APPLY_SEGMENTS = frozenset({"apply", "application"})

# ---- Strict typed Lever section adapter --------------------------------------
# A Lever ``lists[i].text`` heading is provider-native PLAIN TEXT, never markup.
# The audited requirement extractor decides essential/desirable/benefit from the
# heading it parses, so the heading's classification must be established as DATA
# here and only a fixed, trusted canonical heading literal may ever reach the HTML
# parser. A raw provider heading is therefore validated against a small plain-text
# grammar, classified as data, hashed exactly, and NEVER injected into markup.
#
# Generous plain-text section-heading length bound. Real Lever section headings are
# short ("What You'll Do", "What We Require"); anything larger is malformed/hostile.
_LEVER_HEADING_MAX = 200
# The ONLY heading strings ever emitted into the audited-extractor HTML. Each is a
# fixed literal chosen by the data classification below, so the extractor's own
# essential/desirable/benefit decision is driven by our validated data decision —
# not by any provider bytes. They are chosen to classify unambiguously under the
# audited extractor's own ``_BENEFIT_HEADINGS`` / desirable markers.
_LEVER_CANONICAL_HEADINGS: Mapping[str, str] = {
    "essential": "Requirements",
    "desirable": "Nice to have",
    "benefit": "What we offer",
}
# Desirable-section markers. This mirrors the audited extractor's inline desirable
# markers in ``candidate_authority._requirements``; a consistency test binds the
# two so they cannot silently drift.
_LEVER_DESIRABLE_MARKERS: tuple[str, ...] = (
    "ideally",
    "nice to have",
    "preferred",
    "bonus",
)


class _LeverAdapterError(ValueError):
    """A Lever native-body shape or heading that must quarantine, never be omitted."""

# A fit-recomputed record whose stable job identity already has a terminal attempt
# in the durable archive is routed here instead of the fresh ascending queue; it is
# never silently re-offered as a fresh candidate.
ROUTE_PRIOR_ATTEMPT = "prior_terminal_attempt"

# Retry-authority classes for a job identity that already has terminal attempts.
RETRY_PERMANENT_NO_RESUBMIT = "permanent_no_resubmit"
RETRY_INDETERMINATE_QUARANTINE = "indeterminate_quarantine"
RETRY_BLOCKED_REQUIRES_OPERATOR = "blocked_requires_operator_retry_authority"
RETRY_ABANDONED_REQUIRES_REVIEW = "abandoned_requires_review"
RETRY_TERMINAL_REQUIRES_REVIEW = "prior_terminal_requires_review"

# A live discovery source whose ATS apply authority is NOT one of the supported
# official providers (Ashby/Lever) and is not resolvable from the durable
# read-only observation alone: its archived body is omitted for secret safety and
# it carries no allowlisted authority URL. Such a source is neither ranked nor
# quarantined for fit (there is no audited body to score); it is enumerated as an
# explicit, evidence-bound worklist entry for a future read-only network capture
# slice. It is never silently dropped and never treated as ranked, eligible, or
# release capable.
UNRESOLVED_LIVE_REQUIRES_CAPTURE = "requires_network_capture"

# The only observation fields surfaced for an unresolved live source. This is a
# closed allowlist of public posting identity plus a capture pointer; archived
# response / network-evidence / raw-response fields are never copied through, so
# no secret-bearing value can leak into the projection.
_UNRESOLVED_SOURCE_FIELDS: tuple[str, ...] = (
    "job_key",
    "board",
    "company_name",
    "role_title",
    "location",
    "final_url_host",
    "http_status",
    "discovery_body_sha256",
    "discovery_reason",
    "requires",
)


@dataclass(frozen=True)
class MaterializedNonGreenhouseFitProjection:
    document: Mapping[str, object]
    value: bytes
    sha256: str
    object_path: Path
    projection_path: Path


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _approved_candidate_projection(
    sources: CandidateAuthoritySources,
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    """Reuse the audited candidate projection and approved evidence set.

    ``approved_evidence`` and ``negative_claim_suppressors`` define the candidate
    identity that fit is measured against; both are pinned to their approved
    hashes exactly as the release path pins them.
    """

    evidence_bytes = _pinned_source(sources.approved_evidence, "approved_evidence")
    suppressor_bytes = _pinned_source(
        sources.negative_claim_suppressors, "negative_claim_suppressors"
    )
    schema = _ca._regular_file(sources.schema, "candidate authority schema")
    policy = _ca._regular_file(sources.policy, "candidate authority policy")
    evidence = _ca._approved_evidence(evidence_bytes)
    suppressors = _ca._claim_suppressors(suppressor_bytes)
    projection = _ca._projection(
        evidence,
        suppressors,
        schema_sha256=_file_sha256(schema),
        policy_sha256=_file_sha256(policy),
    )
    return projection, evidence


def _pinned_source(path: Path, name: str) -> bytes:
    resolved = _ca._regular_file(path, f"candidate source {name}")
    value = resolved.read_bytes()
    if _sha256_hex(value) != APPROVED_CANDIDATE_SOURCE_HASHES[name]:
        raise ValueError(f"approved candidate source hash differs: {name}")
    return value


def _normalize_title(value: str) -> str:
    """Canonicalize only benign case/whitespace differences for title identity.

    Applied ONLY after the stronger authority-URL and provider-native identity
    bindings are mandatory, so a case-only variation of the same posting is not
    rejected while any material title change still is.
    """

    return re.sub(r"\s+", " ", value).strip().casefold()


def _strip_apply(path: str) -> str:
    path = path.rstrip("/")
    if path.endswith("/apply"):
        path = path[: -len("/apply")]
    return path


def _job_identity(provider: str, job_key: str) -> tuple[str, str] | None:
    """Return ``(company_slug, job_id)`` when ``job_key`` is this provider's own
    stable identity ``provider:company_slug:job_id``; otherwise ``None``.

    An aggregator key such as ``swissaijob:12293`` does not begin with the claimed
    provider and cannot be bound to that provider's authority, so it returns
    ``None`` and the record is quarantined rather than ranked.
    """

    parts = job_key.split(":")
    if len(parts) != 3 or parts[0] != provider:
        return None
    slug, job_id = parts[1], parts[2]
    if not slug or not job_id:
        return None
    return slug, job_id


def _canonical_authority_url(
    provider: str, job_key: str, authority_urls: Sequence[object]
) -> str | None:
    """Bind the canonical provider authority URL for this exact job identity.

    Requires an ``https`` URL whose host is the provider's allowlisted host and
    whose path resolves to ``/company_slug/job_id`` (an optional ``/apply`` suffix
    is tolerated). Returns the canonical ``https://host/slug/job_id`` on success.
    """

    host = PROVIDER_AUTHORITY_HOSTS.get(provider)
    identity = _job_identity(provider, job_key)
    if host is None or identity is None:
        return None
    slug, job_id = identity
    expected_path = f"/{slug}/{job_id}"
    for url in authority_urls:
        if not isinstance(url, str):
            continue
        split = urlsplit(url)
        if split.scheme != "https" or split.netloc != host:
            continue
        if _strip_apply(split.path) == expected_path:
            return f"https://{host}{expected_path}"
    return None


def _bind_provider(
    observation: Mapping[str, object], job_key: str
) -> tuple[str | None, str | None]:
    verdict = observation.get("verdict")
    providers = (
        verdict.get("authority_providers") or [] if isinstance(verdict, Mapping) else []
    )
    urls = verdict.get("authority_urls") or [] if isinstance(verdict, Mapping) else []
    official = sorted(p for p in providers if p in OFFICIAL_AUTHORITY_PROVIDERS)
    for provider in official:
        canonical = _canonical_authority_url(provider, job_key, urls)
        if canonical is not None:
            return provider, canonical
    return None, None


def _parse_provider_native_path(path: str) -> tuple[str, str] | None:
    """Parse ``/{slug}/{id}`` (optionally ``/apply`` or ``/application``) from an
    authority-URL path, returning validated ``(slug, id)`` or ``None``.

    The first two non-empty path segments are the provider-native company slug and
    job id. At most one extra trailing segment is tolerated and only when it is a
    known apply-page segment; any other shape (too few/many segments, control
    characters, out-of-grammar slug/id) fails closed so a crafted URL cannot mint a
    bogus native identity.
    """

    segments = [segment for segment in path.split("/") if segment]
    if len(segments) < 2:
        return None
    slug, job_id = segments[0], segments[1]
    extra = segments[2:]
    if extra and (len(extra) > 1 or extra[0].lower() not in _ALIAS_APPLY_SEGMENTS):
        return None
    if _has_control_or_format(slug) or _has_control_or_format(job_id):
        return None
    if not _ALIAS_SLUG_RE.match(slug) or not _ALIAS_ID_RE.match(job_id):
        return None
    return slug, job_id


def _resolve_provider_native_alias(
    observation: Mapping[str, object], job_key: str
) -> tuple[dict[str, object] | None, bool]:
    """Bind a provider-native alias for an aggregator-keyed observation.

    Returns ``(alias, ambiguous)``. ``alias`` is a durable, read-only binding of
    the exact ``(provider, company_slug, native_job_id)`` parsed from an
    allowlisted-host ``https`` authority URL; it is emitted ONLY when the
    observation's own ``job_key`` is not already a native provider identity (i.e.
    it is a discovery-source/aggregator key). ``ambiguous`` is true when the
    authority URLs resolve to more than one distinct native identity, in which case
    no alias is bound and the record fails closed.

    This never reads or trusts any posting body; it establishes provider-native
    *identity* only. Body identity remains deferred to a later gated capture.
    """

    verdict = observation.get("verdict")
    if not isinstance(verdict, Mapping):
        return None, False
    providers = verdict.get("authority_providers") or []
    urls = verdict.get("authority_urls") or []
    official = sorted(p for p in providers if p in OFFICIAL_AUTHORITY_PROVIDERS)
    resolved: set[tuple[str, str, str]] = set()
    canonical_by_identity: dict[tuple[str, str, str], str] = {}
    for provider in official:
        # If the discovery key is already this provider's own native identity, this
        # is not an aggregator alias case; leave it to the native binding path.
        if _job_identity(provider, job_key) is not None:
            return None, False
        host = PROVIDER_AUTHORITY_HOSTS.get(provider)
        if host is None:
            continue
        for url in urls:
            if not isinstance(url, str):
                continue
            split = urlsplit(url)
            if split.scheme != "https" or split.netloc != host:
                continue
            parsed = _parse_provider_native_path(split.path)
            if parsed is None:
                continue
            slug, native_id = parsed
            identity = (provider, slug, native_id)
            resolved.add(identity)
            canonical_by_identity.setdefault(
                identity, f"https://{host}/{slug}/{native_id}"
            )
    if not resolved:
        return None, False
    if len(resolved) > 1:
        return None, True
    provider, slug, native_id = next(iter(resolved))
    alias = {
        "discovery_job_key": job_key,
        "provider": provider,
        "native_company_slug": slug,
        "native_job_id": native_id,
        "native_job_key": f"{provider}:{slug}:{native_id}",
        "canonical_authority_url": canonical_by_identity[(provider, slug, native_id)],
        "body_identity_verified": False,
        "requires": ALIAS_REQUIRES_CAPTURE,
    }
    return alias, False


def _native_identity_ok(provider: str, job_key: str, posting: Mapping[str, object]) -> bool:
    """Prove the durable posting's own provider-native identity is this vacancy.

    The provider-native ``id`` must equal the bound ``job_id`` and the posting's
    native apply URL must resolve to the same host and ``/slug/job_id`` path. A
    body swapped in from a different vacancy carries a different native ``id`` and
    is rejected.
    """

    identity = _job_identity(provider, job_key)
    if identity is None:
        return False
    slug, job_id = identity
    native_id = posting.get("id")
    if not isinstance(native_id, str) or native_id != job_id:
        return False
    host = PROVIDER_AUTHORITY_HOSTS[provider]
    native_url = (
        posting.get("jobUrl") or posting.get("applyUrl") or posting.get("hostedUrl")
    )
    if not isinstance(native_url, str):
        return False
    split = urlsplit(native_url)
    if split.netloc != host:
        return False
    return _strip_apply(split.path) == f"/{slug}/{job_id}"


def _discovery_coverage(discovery: Mapping[str, object]) -> dict[str, int]:
    observations = discovery.get("observations")
    rows = observations if isinstance(observations, list) else []
    job_keys: set[str] = set()
    live = 0
    official = 0
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        key = row.get("job_key")
        if isinstance(key, str):
            job_keys.add(key)
        verdict = row.get("verdict")
        if isinstance(verdict, Mapping) and verdict.get("live"):
            live += 1
            providers = frozenset(verdict.get("authority_providers") or [])
            if providers & OFFICIAL_AUTHORITY_PROVIDERS:
                official += 1
    return {
        "observations": len(rows),
        "unique_job_keys": len(job_keys),
        "live": live,
        "official_authority_live": official,
    }


def _prior_attempt_index(archive_root: Path) -> dict[str, list[dict[str, object]]]:
    """Index terminal archive attempts by their bound vacancy ``job_key``.

    Read-only. Reads only finalized ``terminal-manifest.json`` files so an
    in-flight staging directory cannot masquerade as a terminal outcome.
    """

    index: dict[str, list[dict[str, object]]] = {}
    attempts_dir = archive_root / "attempts"
    if not attempts_dir.is_dir():
        return index
    for attempt_dir in sorted(attempts_dir.iterdir()):
        manifest = attempt_dir / "terminal-manifest.json"
        if not manifest.is_file():
            continue
        try:
            document = json.loads(manifest.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if not isinstance(document, Mapping):
            continue
        vacancy = document.get("vacancy")
        job_key = vacancy.get("job_key") if isinstance(vacancy, Mapping) else None
        if not isinstance(job_key, str):
            continue
        index.setdefault(job_key, []).append(
            {
                "attempt_id": document.get("attempt_id"),
                "outcome": document.get("outcome"),
                "phase": document.get("phase"),
                "has_release_manifest": bool(
                    document.get("release_manifest_sha256")
                ),
            }
        )
    for entries in index.values():
        entries.sort(key=lambda entry: str(entry.get("attempt_id")))
    return index


def _retry_authority(entries: Sequence[Mapping[str, object]]) -> str:
    outcomes = {entry.get("outcome") for entry in entries}
    if any(entry.get("has_release_manifest") for entry in entries) or (
        "historical_submitted_success" in outcomes
    ):
        return RETRY_PERMANENT_NO_RESUBMIT
    if "crashed" in outcomes:
        return RETRY_INDETERMINATE_QUARANTINE
    if "blocked" in outcomes:
        return RETRY_BLOCKED_REQUIRES_OPERATOR
    if "abandoned" in outcomes:
        return RETRY_ABANDONED_REQUIRES_REVIEW
    return RETRY_TERMINAL_REQUIRES_REVIEW


def _select_opportunities(
    discovery: Mapping[str, object],
) -> list[Mapping[str, object]]:
    observations = discovery.get("observations")
    interaction = discovery.get("interaction")
    if discovery.get("schema_version") != DISCOVERY_SCHEMA_VERSION:
        raise ValueError("discovery is not the multi-provider live discovery cohort")
    if not isinstance(observations, list) or not observations:
        raise ValueError("discovery has no observations")
    if not isinstance(interaction, Mapping) or any(
        int(interaction.get(field, -1)) != 0
        for field in ("fields_filled", "files_uploaded", "submit_clicks")
    ):
        raise ValueError("discovery evidence is not a pure read-only observation")
    selected: list[Mapping[str, object]] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        verdict = observation.get("verdict")
        if not isinstance(verdict, Mapping) or not verdict.get("live"):
            continue
        providers = frozenset(verdict.get("authority_providers") or [])
        if providers & OFFICIAL_AUTHORITY_PROVIDERS:
            selected.append(observation)
    if not selected:
        raise ValueError("discovery holds no official-authority live opportunities")
    # One authoritative record per stable job identity. Fail closed on any
    # duplicate/conflicting observation rather than letting it rank twice.
    seen: set[str] = set()
    for observation in selected:
        job_key = str(observation["job_key"])
        if job_key in seen:
            raise ValueError(
                f"duplicate official-authority observation for job identity: {job_key}"
            )
        seen.add(job_key)
    return sorted(selected, key=lambda row: str(row["job_key"]))


# Maximum length for any public free-text field surfaced in the unresolved
# worklist. Real posting identity strings are short; anything longer is treated
# as malformed and dropped rather than copied through.
_MAX_TEXT_LEN = 512
# A canonical lowercase hex SHA-256 and nothing else.
_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
# A canonical ASCII hostname: 1..253 chars, dot-separated LDH labels (1..63),
# no leading hyphen, no empty label, no port, no userinfo, no IP-literal colons.
_ASCII_HOST_RE = re.compile(
    r"\A(?=.{1,253}\Z)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})*\Z"
)


def _has_control_or_format(value: str) -> bool:
    """True if ``value`` holds any Unicode control/format character (category C*).

    This rejects NUL, other C0/C1 controls, bidi/zero-width format characters,
    line/paragraph separators, and surrogate/private-use noise that could hide or
    reshape a public field. Ordinary printable text passes.
    """

    return any(unicodedata.category(ch)[0] == "C" for ch in value)


def _clean_text(value: object, *, max_len: int = _MAX_TEXT_LEN) -> str | None:
    """Return a bounded, control-free trimmed string, or ``None`` if malformed.

    A non-string (structured object, number, boolean, nested mapping/list), an
    oversized string, or a string bearing any control/format character is dropped
    to ``None`` so it can never appear in the projection.
    """

    if not isinstance(value, str):
        return None
    if len(value) > max_len:
        return None
    if _has_control_or_format(value):
        return None
    stripped = value.strip()
    return stripped or None


def _bounded_status(value: object) -> int | None:
    """Return a plausible HTTP status integer, or ``None``.

    ``bool`` is a subclass of ``int`` in Python, so a boolean masquerading as a
    status is rejected explicitly. A structured status object, a numeric string,
    or an out-of-range value is dropped to ``None``.
    """

    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 100 <= value <= 599:
        return value
    return None


def _bounded_sha256(value: object) -> str | None:
    """Return ``value`` only when it is a canonical lowercase hex SHA-256."""

    if isinstance(value, str) and _HEX64_RE.match(value):
        return value
    return None


def _bounded_job_key(value: object) -> str:
    """Validate the unresolved source's stable identity, failing closed if bad.

    ``job_key`` is the partition identity; a malformed identity cannot be
    reconciled or safely surfaced, so it raises rather than being silently
    dropped or coerced.
    """

    if not isinstance(value, str) or not (1 <= len(value) <= 200):
        raise ValueError("unresolved live source job_key is malformed")
    if _has_control_or_format(value):
        raise ValueError("unresolved live source job_key holds control characters")
    return value


def _canonical_host(value: object) -> str | None:
    """Return the canonical lowercase ASCII (IDNA) hostname of an https URL.

    A non-secret provider host is the only URL fragment surfaced. This does NOT
    return ``netloc``: ``netloc`` can carry userinfo (credentials/tokens), a port,
    mixed case, an IP literal, IDNA/Unicode ambiguity, or embedded control
    characters. Instead it parses and validates an absolute ``https`` URL,
    rejects any credentials/port/IP-literal/malformed input, IDNA-encodes the
    host, and emits only a canonical lowercase hostname. Anything that is not an
    unambiguous https hostname returns ``None`` so nothing unsafe leaks.
    """

    if not isinstance(value, str) or not value or _has_control_or_format(value):
        return None
    split = urlsplit(value)
    if split.scheme != "https":
        return None
    # Reject embedded credentials outright — never surface userinfo.
    if split.username is not None or split.password is not None:
        return None
    # An explicit or malformed port is ambiguous provider identity; reject both.
    try:
        if split.port is not None:
            return None
    except ValueError:
        return None
    host = split.hostname
    if not host:
        return None
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if not _ASCII_HOST_RE.match(ascii_host):
        return None
    return ascii_host


def _final_url_host(observation: Mapping[str, object]) -> str | None:
    """Return only the canonical host of the observation's final/requested URL."""

    for field in ("final_url", "requested_url"):
        host = _canonical_host(observation.get(field))
        if host is not None:
            return host
    return None


def _unresolved_live_record(observation: Mapping[str, object]) -> dict[str, object]:
    """Project one live-but-unresolved source into a secret-safe worklist entry.

    Built from a closed allowlist of public posting identity fields plus a capture
    pointer. No archived-response, network-evidence, cookie, or raw-response value
    is ever read here, so a secret cannot pass through regardless of what the
    observation carries.
    """

    verdict = observation.get("verdict")
    verdict = verdict if isinstance(verdict, Mapping) else {}
    # Every public field is strictly typed and bounded. A structured, oversized,
    # control-character-bearing, boolean-as-integer, non-hex, or nested value is
    # dropped to ``None`` (or, for the identity field, fails closed) so no
    # source-body or secret-shaped value can appear in the projection.
    record: dict[str, object] = {
        "job_key": _bounded_job_key(observation.get("job_key")),
        "board": _clean_text(observation.get("board")),
        "company_name": _clean_text(observation.get("company_name")),
        "role_title": _clean_text(observation.get("role_title")),
        "location": _clean_text(observation.get("location")),
        "final_url_host": _final_url_host(observation),
        "http_status": _bounded_status(observation.get("status")),
        "discovery_body_sha256": _bounded_sha256(observation.get("body_sha256")),
        "discovery_reason": _clean_text(verdict.get("reason")),
        "requires": UNRESOLVED_LIVE_REQUIRES_CAPTURE,
    }
    # Enforce the closed allowlist with an explicit fail-closed check that still
    # executes under ``python -O`` (an ``assert`` would be stripped and silently
    # allow an over-wide record).
    _enforce_unresolved_allowlist(record)
    return record


def _enforce_unresolved_allowlist(record: Mapping[str, object]) -> None:
    """Fail closed if the projected unresolved record's keys drift from the
    closed public allowlist. Runs unconditionally (never an ``assert``)."""

    if set(record) != set(_UNRESOLVED_SOURCE_FIELDS):
        raise ValueError(
            "unresolved live source escaped the closed field allowlist"
        )


def _select_unresolved_live(
    discovery: Mapping[str, object],
) -> list[Mapping[str, object]]:
    """Return every live observation whose ATS authority is not a supported
    official provider, one authoritative record per stable job identity.

    These are the live sources the ranked projection cannot yet score because the
    durable read-only evidence holds no official-provider apply authority for
    them. Enumerating them keeps the authoritative queue's live-source accounting
    complete instead of silently dropping the difference between ``live`` and
    ``official_authority_live``.
    """

    observations = discovery.get("observations")
    rows = observations if isinstance(observations, list) else []
    selected: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for observation in rows:
        if not isinstance(observation, Mapping):
            continue
        verdict = observation.get("verdict")
        if not isinstance(verdict, Mapping) or not verdict.get("live"):
            continue
        providers = frozenset(verdict.get("authority_providers") or [])
        if providers & OFFICIAL_AUTHORITY_PROVIDERS:
            # A resolved official-authority live source is handled by the ranked
            # path; it must not also appear as unresolved.
            continue
        job_key = observation.get("job_key")
        if not isinstance(job_key, str):
            continue
        if job_key in seen:
            raise ValueError(
                f"duplicate unresolved live observation for job identity: {job_key}"
            )
        seen.add(job_key)
        selected.append(observation)
    return sorted(selected, key=lambda row: str(row["job_key"]))


def _live_identities(discovery: Mapping[str, object]) -> list[str]:
    """Return the stable identity of every live observation.

    A live observation without a usable ``job_key`` cannot be assigned to either
    partition, so it fails closed here rather than being silently dropped — that
    is exactly the "no live identity is dropped" guarantee the partition proof
    depends on.
    """

    observations = discovery.get("observations")
    rows = observations if isinstance(observations, list) else []
    identities: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        verdict = row.get("verdict")
        if not isinstance(verdict, Mapping) or not verdict.get("live"):
            continue
        key = row.get("job_key")
        if not isinstance(key, str) or not key:
            raise ValueError(
                "live observation without a stable job identity cannot be partitioned"
            )
        identities.append(key)
    return identities


def _identity_hash(identities: Sequence[str]) -> str:
    """Deterministic hash bound to a stable sorted identity set."""

    return _sha256_hex(_ca._json_bytes(sorted(identities)))


def _live_partition_proof(
    live_identities: Sequence[str],
    official_identities: Sequence[str],
    unresolved_identities: Sequence[str],
) -> dict[str, object]:
    """Prove exact set-partition of the live cohort, not a coincidental count.

    ``official`` and ``unresolved`` must be disjoint, individually duplicate-free,
    and together reconstitute the exact live identity set. Sorted identity hashes
    are bound for the live set and both partitions so the partition is
    independently reconstructable.
    """

    live = sorted(live_identities)
    official = sorted(official_identities)
    unresolved = sorted(unresolved_identities)
    live_set = set(live)
    official_set = set(official)
    unresolved_set = set(unresolved)
    partitioned = (
        len(live) == len(live_set)
        and len(official) == len(official_set)
        and len(unresolved) == len(unresolved_set)
        and official_set.isdisjoint(unresolved_set)
        and official_set | unresolved_set == live_set
    )
    return {
        "live_count": len(live_set),
        "official_count": len(official_set),
        "unresolved_count": len(unresolved_set),
        "live_identities_sha256": _identity_hash(live),
        "official_identities_sha256": _identity_hash(official),
        "unresolved_identities_sha256": _identity_hash(unresolved),
        "partitioned": partitioned,
    }


def _html_field(posting: Mapping[str, object]) -> tuple[str, str] | None:
    for field in HTML_DESCRIPTION_FIELDS:
        value = posting.get(field)
        if isinstance(value, str) and "<" in value:
            return field, value
    return None


def _validated_lever_heading(raw: object) -> str:
    """Validate one raw Lever ``lists[i].text`` heading as canonical plain text.

    A section heading is provider-native plain text, never markup. This enforces a
    small canonical grammar and FAILS CLOSED (``_LeverAdapterError``) on anything
    outside it, so a hostile heading quarantines the whole opportunity instead of
    being silently trusted for classification:

    - not a string, or whitespace-only → reject;
    - longer than ``_LEVER_HEADING_MAX`` → reject (oversized/malformed markup);
    - any Unicode control/format character (category ``C*``) → reject. This
      removes NUL and control characters, bidi controls, and zero-width/format
      characters that could obscure or flip the benefit/desirable classification
      (e.g. a zero-width space hidden inside ``benefits``);
    - any literal angle bracket ``<``/``>`` → reject (comment/CDATA/PI/tag shapes);
    - any HTML character reference → reject. ``html.unescape`` decodes named,
      numeric, and hex references (including legacy semicolon-less forms); if
      decoding changes the string, or it contains a numeric-reference ``&#``
      sentinel, a character reference is present and the heading is rejected. This
      closes recursively/double-encoded and numeric-entity injection at the
      grammar, not with an ad-hoc blacklist.

    The returned value is the whitespace-collapsed canonical heading used ONLY for
    the data classification below; it is never emitted into markup.
    """

    if not isinstance(raw, str):
        raise _LeverAdapterError("lever list heading must be a string")
    if len(raw) > _LEVER_HEADING_MAX:
        raise _LeverAdapterError("lever list heading exceeds length bound")
    for char in raw:
        if unicodedata.category(char)[0] == "C":
            raise _LeverAdapterError("lever list heading has a control/format character")
    if "<" in raw or ">" in raw:
        raise _LeverAdapterError("lever list heading contains an angle bracket")
    if "&#" in raw or _html_unescape(raw) != raw:
        raise _LeverAdapterError("lever list heading contains a character reference")
    collapsed = " ".join(raw.split())
    if not collapsed:
        raise _LeverAdapterError("lever list heading is empty")
    return collapsed


def _classify_lever_section(canonical_heading: str) -> str:
    """Classify a validated Lever section heading as data.

    Returns ``benefit``, ``desirable`` or ``essential`` using the same markers the
    audited extractor applies to a parsed heading — but here as a pure data
    decision over already-validated plain text, so no provider bytes ever reach
    the HTML parser to establish classification.
    """

    folded = canonical_heading.casefold()
    if any(marker in folded for marker in _ca._BENEFIT_HEADINGS):
        return "benefit"
    if any(marker in folded for marker in _LEVER_DESIRABLE_MARKERS):
        return "desirable"
    return "essential"


def _lever_native_body(
    posting: Mapping[str, object],
) -> tuple[str, str, tuple[dict[str, object], ...]] | None:
    """Reassemble Lever's native split body into one audited-extractor HTML input.

    Lever stores the opening in ``description``, each requirement section in a
    ``lists`` entry (a plain-text ``text`` heading plus a ``content`` HTML fragment
    of ``<li>`` bullets), and benefits in ``additional``. Each section heading is
    validated against a strict plain-text grammar, classified as DATA, and replaced
    by a fixed trusted canonical heading (``Requirements`` / ``Nice to have`` /
    ``What we offer``) before the body reaches the audited HTML parser. The raw
    provider heading is therefore never parsed as markup, so it cannot open a tag,
    mint a second heading, or reclassify bullets; the audited extractor still makes
    every requirement decision, now over trusted headings.

    Fails closed (``_LeverAdapterError``) on a mapping-shaped ``lists``, a
    non-mapping entry, a missing/hostile heading, or non-string ``content`` — such
    provider-native content is quarantined, never silently omitted. Each raw native
    field is hashed exactly (padding included) so the reassembly is reproducible,
    and the heading component additionally records the derived classification and
    the trusted canonical heading actually emitted. Returns ``None`` only when the
    posting carries no native ``lists`` section at all (so the caller falls back to
    single-field HTML selection).
    """

    lists = posting.get("lists")
    if isinstance(lists, Mapping):
        # A native Lever ``lists`` is an ordered array; a mapping-shaped value is
        # malformed and must never be silently treated as absent.
        raise _LeverAdapterError("lever lists must be an array, not a mapping")
    if not isinstance(lists, list) or not lists:
        return None

    parts: list[str] = []
    components: list[dict[str, object]] = []

    def _add_markup(field: str, value: object) -> None:
        if isinstance(value, str) and value.strip():
            parts.append(value)
            components.append({"field": field, "sha256": _sha256_hex(value.encode())})

    _add_markup("description", posting.get("description"))
    for index, entry in enumerate(lists):
        if not isinstance(entry, Mapping):
            raise _LeverAdapterError(f"lever lists[{index}] is not a mapping")
        canonical = _validated_lever_heading(entry.get("text"))
        classification = _classify_lever_section(canonical)
        trusted_heading = _LEVER_CANONICAL_HEADINGS[classification]
        parts.append(f"<h2>{trusted_heading}</h2>")
        # Bind the component hash to the EXACT raw provider ``text`` bytes (padding
        # included), never the collapsed/canonical heading, and record the derived
        # classification plus the trusted heading actually emitted so the entire
        # reassembly — including the data decision — is independently reproducible.
        raw_text = entry.get("text")
        components.append(
            {
                "field": f"lists[{index}].text",
                "sha256": _sha256_hex(str(raw_text).encode())
                if isinstance(raw_text, str)
                else None,
                "classification": classification,
                "canonical_heading": trusted_heading,
            }
        )
        content = entry.get("content")
        if content is not None and not isinstance(content, str):
            raise _LeverAdapterError(f"lever lists[{index}].content must be a string")
        _add_markup(f"lists[{index}].content", content)
    _add_markup("additional", posting.get("additional"))

    markup = "\n".join(parts)
    if "<" not in markup:
        return None
    return LEVER_NATIVE_BODY_FIELD, markup, tuple(components)


def _description_markup(
    observation: Mapping[str, object],
    posting: Mapping[str, object],
) -> tuple[str, str, tuple[dict[str, object], ...] | None] | None:
    """Select the exact markup fed to the audited extractor for one posting.

    Lever's split body is reassembled from native fields; every other board uses
    its single HTML description field unchanged.
    """

    verdict = observation.get("verdict")
    providers = frozenset(
        verdict.get("authority_providers") or []
        if isinstance(verdict, Mapping)
        else []
    )
    if LEVER_PROVIDER in providers:
        native = _lever_native_body(posting)
        if native is not None:
            return native
    selection = _html_field(posting)
    if selection is None:
        return None
    field_name, markup = selection
    return field_name, markup, None


def _opportunity_record(
    observation: Mapping[str, object],
    posting: Mapping[str, object] | None,
    evidence: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    verdict = observation["verdict"]
    job_key = str(observation["job_key"])
    role_title = str(observation.get("role_title", "")).strip()
    company_name = str(observation.get("company_name", "")).strip()
    record: dict[str, object] = {
        "job_key": job_key,
        "authority_providers": sorted(verdict.get("authority_providers") or []),
        "authority_urls": sorted(verdict.get("authority_urls") or []),
        "role_title": role_title,
        "company_name": company_name,
        "discovery_body_sha256": observation.get("body_sha256"),
        "empty_profile_fit_discarded": str(observation.get("fit")),
    }
    # Identity gate 1: the provider claim must be backed by an allowlisted-host
    # authority URL that resolves to this record's own stable job identity.
    provider, authority_url = _bind_provider(observation, job_key)
    if provider is None:
        # The provider claim is not backed by a native-keyed authority URL. Before
        # quarantining as unverified, try to bind a provider-native ALIAS from an
        # allowlisted-host apply URL carried under an aggregator discovery key. A
        # bound alias is capture-pending (never scored here); it never reads the
        # aggregator's durable body, so a swapped/altered aggregator body cannot
        # promote or score the role.
        alias, ambiguous = _resolve_provider_native_alias(observation, job_key)
        if ambiguous:
            record["status"] = QUARANTINE_ALIAS_AMBIGUOUS
            record["fit"] = None
            return record
        if alias is not None:
            record["status"] = STATUS_ALIAS_CAPTURE_PENDING
            record["provider_native_alias"] = alias
            record["fit"] = None
            return record
        record["status"] = QUARANTINE_AUTHORITY_URL
        record["fit"] = None
        return record
    record["authority_provider"] = provider
    record["authority_url"] = authority_url
    if posting is None:
        record["status"] = QUARANTINE_NO_POSTING
        record["fit"] = None
        return record
    # Identity gate 2: the durable posting's provider-native immutable identity
    # (native id + native apply URL) must resolve to the same vacancy.
    if not _native_identity_ok(provider, job_key, posting):
        record["status"] = QUARANTINE_NATIVE_IDENTITY
        record["fit"] = None
        return record
    record["provider_native_id"] = posting.get("id")
    posting_title = str(posting.get("title", "")).strip()
    record["posting_title"] = posting_title
    record["title_match"] = posting_title == role_title
    content_text = posting.get("content_text")
    if not isinstance(content_text, str) or not content_text.strip():
        record["status"] = QUARANTINE_NO_CONTENT_TEXT
        record["fit"] = None
        return record
    record["content_text_sha256"] = _sha256_hex(content_text.encode())
    # Identity gate 3: benign case/whitespace title variation is tolerated only
    # now that the stronger URL and native-id bindings above are mandatory.
    if _normalize_title(posting_title) != _normalize_title(role_title):
        record["status"] = QUARANTINE_IDENTITY
        record["fit"] = None
        return record
    try:
        markup_selection = _description_markup(observation, posting)
    except _LeverAdapterError as exc:
        # A malformed or hostile Lever native body quarantines the opportunity
        # (fail closed) rather than being silently omitted or partially assembled.
        # ``str(exc)`` is one of our own controlled messages, never provider bytes.
        record["status"] = QUARANTINE_LEVER_MALFORMED
        record["quarantine_detail"] = str(exc)
        record["fit"] = None
        return record
    if markup_selection is None:
        record["status"] = QUARANTINE_NO_HTML
        record["fit"] = None
        return record
    field_name, markup, reconstruction = markup_selection
    record["description_html_field"] = field_name
    record["description_html_sha256"] = _sha256_hex(markup.encode())
    if reconstruction is not None:
        record["description_reconstruction"] = list(reconstruction)
    try:
        matrix = _ca._evidence_matrix(markup, evidence)
    except ValueError:
        record["status"] = QUARANTINE_NO_REQUIREMENTS
        record["fit"] = None
        return record
    record["status"] = STATUS_FIT
    record["requirement_count"] = len(matrix)
    record["fit"] = _ca.fit_from_evidence_matrix(matrix)
    record["evidence_matrix"] = list(matrix)
    return record


def _reconcile_provider_native_aliases(
    records: Sequence[dict[str, object]],
    prior_index: Mapping[str, Sequence[Mapping[str, object]]],
) -> None:
    """Fail closed on aliases that would duplicate a vacancy, then bind prior
    attempts to every surviving capture-pending alias.

    A provider-native alias must never mint a fresh duplicate vacancy: if two
    discovery keys resolve to the same native identity, or an alias collides with a
    natively-keyed opportunity, every colliding record is quarantined
    (``QUARANTINE_ALIAS_DUPLICATE``) instead of being offered for capture. Each
    surviving alias then inherits any terminal attempt recorded under EITHER its
    discovery key or its native identity, so a prior success/blocked/indeterminate
    outcome bars re-capture rather than silently re-offering the vacancy.
    """

    # Native identities already claimed by a natively-keyed opportunity.
    native_opportunity_keys: set[str] = set()
    for row in records:
        job_key = str(row["job_key"])
        provider = job_key.split(":", 1)[0]
        if provider in OFFICIAL_AUTHORITY_PROVIDERS and _job_identity(provider, job_key):
            native_opportunity_keys.add(job_key)

    # How many aliases resolve to each native identity (duplicate-alias guard).
    alias_native_counts: dict[str, int] = {}
    for row in records:
        if row.get("status") != STATUS_ALIAS_CAPTURE_PENDING:
            continue
        alias = row.get("provider_native_alias")
        if isinstance(alias, Mapping):
            native_key = str(alias["native_job_key"])
            alias_native_counts[native_key] = alias_native_counts.get(native_key, 0) + 1

    for row in records:
        if row.get("status") != STATUS_ALIAS_CAPTURE_PENDING:
            continue
        alias = row.get("provider_native_alias")
        if not isinstance(alias, Mapping):
            continue
        native_key = str(alias["native_job_key"])
        if (
            alias_native_counts.get(native_key, 0) > 1
            or native_key in native_opportunity_keys
        ):
            row["status"] = QUARANTINE_ALIAS_DUPLICATE
            row["fit"] = None
            continue
        entries: list[Mapping[str, object]] = []
        seen_ids: set[object] = set()
        for lookup_key in (str(row["job_key"]), native_key):
            for entry in prior_index.get(lookup_key, ()):
                attempt_id = entry.get("attempt_id")
                if attempt_id in seen_ids:
                    continue
                seen_ids.add(attempt_id)
                entries.append(entry)
        if entries:
            entries.sort(key=lambda entry: str(entry.get("attempt_id")))
            row["prior_attempts"] = list(entries)
            row["retry_authority"] = _retry_authority(entries)
            row["capture_blocked_by_prior_attempt"] = True


def build_nongreenhouse_fit_projection(
    *,
    discovery_path: Path,
    jobs_database: Path | None = None,
    sources: CandidateAuthoritySources = CandidateAuthoritySources(),
    archive_root: Path | None = None,
    require_approved_sources: bool = True,
) -> dict[str, object]:
    discovery_path = _ca._regular_file(discovery_path, "multi-provider discovery")
    discovery_bytes = discovery_path.read_bytes()
    discovery = json.loads(discovery_bytes)
    opportunities = _select_opportunities(discovery)
    unresolved = [
        _unresolved_live_record(observation)
        for observation in _select_unresolved_live(discovery)
    ]

    database = _ca._regular_file(
        jobs_database or sources.jobs_database, "jobs database"
    )
    jobs_database_sha256 = _file_sha256(database)
    projection, evidence = _approved_candidate_projection(sources)

    discovery_file_sha256 = _sha256_hex(discovery_bytes)
    coverage = _discovery_coverage(discovery)
    discovery_approved = discovery_file_sha256 == APPROVED_DISCOVERY_SHA256
    jobs_database_approved = (
        jobs_database_sha256 == APPROVED_CANDIDATE_SOURCE_HASHES["jobs_database"]
    )
    coverage_approved = coverage == dict(APPROVED_DISCOVERY_COVERAGE)
    # Self-consistency: every live source is either an official-authority record
    # (ranked/quarantined/prior-routed below) or an enumerated unresolved source.
    # Prove an exact set partition over stable identities — disjoint, duplicate
    # free, and together reconstituting the exact live identity set — rather than
    # trusting a coincidental count equality.
    partition_proof = _live_partition_proof(
        _live_identities(discovery),
        [str(row["job_key"]) for row in opportunities],
        [str(row["job_key"]) for row in unresolved],
    )
    live_reconciled = bool(partition_proof["partitioned"])

    resolved_archive = archive_root.resolve(strict=True) if archive_root else None
    if require_approved_sources:
        # Authoritative use requires the exact approved artifact bytes, the exact
        # coverage contract, and a bound durable archive so prior attempts are
        # never silently re-offered. A caller-declared provenance is insufficient.
        if not discovery_approved:
            raise ValueError("discovery artifact hash is not the approved discovery")
        if not jobs_database_approved:
            raise ValueError("jobs database hash is not the approved database")
        if not coverage_approved:
            raise ValueError("discovery coverage contract differs from approved")
        if resolved_archive is None:
            raise ValueError("authoritative projection requires a bound archive root")
        if not live_reconciled:
            raise ValueError(
                "live-source reconciliation failed: official + unresolved != live"
            )
    prior_index = (
        _prior_attempt_index(resolved_archive) if resolved_archive is not None else {}
    )

    job_keys = [str(row["job_key"]) for row in opportunities]
    connection = sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
    try:
        placeholders = ",".join("?" for _ in job_keys)
        rows = connection.execute(
            f"SELECT key, raw_json FROM postings WHERE key IN ({placeholders})",
            tuple(sorted(job_keys)),
        ).fetchall()
    finally:
        connection.close()
    postings = {str(key): json.loads(raw) for key, raw in rows}

    records = [
        _opportunity_record(observation, postings.get(str(observation["job_key"])), evidence)
        for observation in opportunities
    ]
    _reconcile_provider_native_aliases(records, prior_index)
    # Route fit-recomputed records with a prior terminal attempt out of the fresh
    # queue under the applicable retry authority; never re-offer them as fresh.
    fresh: list[dict[str, object]] = []
    prior_attempts: list[dict[str, object]] = []
    for row in records:
        entries = prior_index.get(str(row["job_key"]))
        if row["status"] == STATUS_FIT and entries:
            row["route"] = ROUTE_PRIOR_ATTEMPT
            row["prior_attempts"] = entries
            row["retry_authority"] = _retry_authority(entries)
            prior_attempts.append(row)
        elif row["status"] == STATUS_FIT:
            fresh.append(row)
    ranking = sorted(
        fresh,
        key=lambda row: (Decimal(str(row["fit"])), str(row["job_key"])),
    )
    for rank, row in enumerate(ranking, start=1):
        row["ascending_fit_rank"] = rank
    prior_attempts.sort(key=lambda row: str(row["job_key"]))
    # Capture-pending provider-native aliases are surfaced in their own section so
    # the exact ``(provider, native id)`` worklist for a later gated capture stays
    # separate from both ranked opportunities and generic quarantines. Aliases that
    # failed closed (ambiguous/duplicate) are ordinary quarantines.
    provider_native_aliases = sorted(
        (row for row in records if row["status"] == STATUS_ALIAS_CAPTURE_PENDING),
        key=lambda row: str(row["job_key"]),
    )
    quarantined = sorted(
        (
            row
            for row in records
            if row["status"] not in (STATUS_FIT, STATUS_ALIAS_CAPTURE_PENDING)
        ),
        key=lambda row: str(row["job_key"]),
    )

    authoritative = bool(
        require_approved_sources
        and discovery_approved
        and jobs_database_approved
        and coverage_approved
        and resolved_archive is not None
    )
    document: dict[str, object] = {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "release_capable": False,
        "authorizes_action": False,
        "eligibility_determined": False,
        "authoritative": authoritative,
        "eligibility_note": (
            "Deterministic eligibility is not decided here. It requires "
            "operator-approved eligibility policy for these vacancies and real "
            "operator contact enrollment. No form fill, upload, click, or email "
            "is permitted for any opportunity below until both exist."
        ),
        "fit_authority": "career_automation.candidate_authority.fit_from_evidence_matrix",
        "evidence_projection_schema": _ca.TYPED_EVIDENCE_SCHEMA,
        "evidence_projection_sha256": _ca.typed_evidence_projection_hash(evidence),
        "discovery_file_sha256": discovery_file_sha256,
        "discovery_snapshot_sha256": discovery.get("snapshot_sha256"),
        "discovery_schema_version": discovery.get("schema_version"),
        "discovery_observed_at": discovery.get("observed_at"),
        "jobs_database_sha256": jobs_database_sha256,
        "jobs_database_approved": jobs_database_approved,
        "authoritative_source_binding": {
            "discovery_sha256_approved": discovery_approved,
            "jobs_database_sha256_approved": jobs_database_approved,
            "coverage": coverage,
            "coverage_approved": coverage_approved,
            "archive_bound": resolved_archive is not None,
        },
        "candidate_projection": projection,
        "counts": {
            "selected": len(records),
            "fit_recomputed": len(ranking),
            "prior_attempts": len(prior_attempts),
            "provider_native_aliases": len(provider_native_aliases),
            "quarantined": len(quarantined),
            "unresolved_live_sources": len(unresolved),
        },
        "live_source_reconciliation": {
            "live": coverage["live"],
            "official_authority_live_selected": len(opportunities),
            "unresolved_live_sources": len(unresolved),
            "reconciled": live_reconciled,
            "partition_proof": partition_proof,
        },
        "ranking": ranking,
        "prior_attempts": prior_attempts,
        "provider_native_aliases": provider_native_aliases,
        "quarantined": quarantined,
        "unresolved_live_sources": unresolved,
    }
    return document


def materialize_nongreenhouse_fit_projection(
    *,
    discovery_path: Path,
    archive_root: Path,
    jobs_database: Path | None = None,
    sources: CandidateAuthoritySources = CandidateAuthoritySources(),
    require_approved_sources: bool = True,
) -> MaterializedNonGreenhouseFitProjection:
    archive_root = archive_root.resolve(strict=True)
    document = build_nongreenhouse_fit_projection(
        discovery_path=discovery_path,
        jobs_database=jobs_database,
        sources=sources,
        archive_root=archive_root,
        require_approved_sources=require_approved_sources,
    )
    output = _ca._json_bytes(document)
    digest = _sha256_hex(output)
    object_path = archive_root / "objects" / digest[:2] / digest
    projection_path = (
        archive_root / "nongreenhouse-fit-projections" / f"{digest}.json"
    )
    _ca._atomic_create_or_verify(archive_root, object_path, output)
    _ca._atomic_create_or_verify(archive_root, projection_path, output)
    return MaterializedNonGreenhouseFitProjection(
        document=document,
        value=output,
        sha256=digest,
        object_path=object_path,
        projection_path=projection_path,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--jobs-database", type=Path, default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = materialize_nongreenhouse_fit_projection(
        discovery_path=arguments.discovery,
        archive_root=arguments.archive_root,
        jobs_database=arguments.jobs_database,
    )
    print(
        json.dumps(
            {
                "projection_path": str(result.projection_path),
                "sha256": result.sha256,
                "counts": result.document["counts"],
                "release_capable": result.document["release_capable"],
                "authoritative": result.document["authoritative"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MaterializedNonGreenhouseFitProjection",
    "STATUS_ALIAS_CAPTURE_PENDING",
    "QUARANTINE_ALIAS_AMBIGUOUS",
    "QUARANTINE_ALIAS_DUPLICATE",
    "UNRESOLVED_LIVE_REQUIRES_CAPTURE",
    "build_nongreenhouse_fit_projection",
    "materialize_nongreenhouse_fit_projection",
]
