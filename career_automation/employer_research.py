"""JAA-04 public employer reconnaissance and fail-closed dossier contracts.

Retrieval is deliberately source controlled: only public HTTP(S) URLs are
accepted, redirects are revalidated, and every byte used by research is stored
in a content-addressed raw cache before it can become a citation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse, urlunparse

from .models import ClaimClassification, IntelligenceKind


FRESHNESS_DAYS = {
    IntelligenceKind.COMPANY: 365,
    IntelligenceKind.ROLE: 45,
    IntelligenceKind.PRODUCT: 180,
    IntelligenceKind.HIRING: 45,
    IntelligenceKind.OPERATIONAL_HEALTH: 90,
}

# Source purpose is data, rather than an assumption made by the paragraph
# consumer.  These rules are deliberately small and deterministic: they are
# an eligibility gate, not a model prompt or a relevance score.
SOURCE_KIND_POLICY: dict[IntelligenceKind, dict[str, Any]] = {
    IntelligenceKind.COMPANY: {
        "source_types": {"authoritative_company_record", "official_company"},
        "terms": ("company", "organisation", "organization", "operates", "employer", "business"),
    },
    IntelligenceKind.PRODUCT: {
        "source_types": {"official_product_documentation"},
        "terms": ("product", "service", "platform", "customer", "clients", "technology"),
    },
    IntelligenceKind.OPERATIONAL_HEALTH: {
        "source_types": {"regulatory_filing", "regulatory_status_record", "independent_reporting"},
        "terms": ("revenue", "profit", "loss", "funding", "financial", "operating", "operational", "current"),
        "dated": True,
    },
    IntelligenceKind.ROLE: {
        "source_types": {"official_vacancy"},
        "terms": ("role", "position", "job", "responsibilities", "responsible", "duties"),
    },
    IntelligenceKind.HIRING: {
        "source_types": {"official_careers"},
        "terms": ("hiring", "apply", "application", "career", "vacancy", "candidate", "employee"),
    },
}

_SEMANTIC_PATTERNS: dict[IntelligenceKind, tuple[tuple[str, ...], ...]] = {
    IntelligenceKind.COMPANY: (
        (r"\b(?:company|business|organisation|organization|corporation|employer|firm|public service)\b",),
        (r"\b(?:operates?|provides?|serves?|employs?|headquartered|based|founded|established)\b",),
    ),
    IntelligenceKind.ROLE: (
        (r"\b(?:role|position|job|employee|staff|workforce|team|engineer|manager|responsibilit(?:y|ies)|operations?|activities|development|service|sector|company|organisation|organization)\b",),
        (r"\b(?:responsibilit(?:y|ies)|duties|holder|work(?:s|ing)?|develops?|delivers?|manages?|leads?|employs?|employees?|operates?|activities|founded|acquired|opened|transferred)\b",),
    ),
    IntelligenceKind.PRODUCT: (
        (r"\b(?:product|service|platform|technology|software|system|application|offering|website|network|app|account|search engine|search aggregator|travel|flights?|agency)\b",),
        (r"\b(?:customer|client|user|business|provides?|offers?|serves?|gives?|used|using|enables?|designed|compare|book(?:s|ing)?|operates?|operating)\b",),
    ),
    IntelligenceKind.HIRING: (
        (r"\b(?:hiring|recruit(?:s|ing|ment)?|careers?|vacanc(?:y|ies)|candidate|applicant|apply|application|employs?|employees?|staff|workforce)\b",),
        (r"\b(?:hiring|recruit(?:s|ing|ment)?|vacanc(?:y|ies)|candidate|applicant|apply|application|employs?|employees?|staff|workforce|jobs?)\b",),
    ),
    IntelligenceKind.OPERATIONAL_HEALTH: (
        (r"\b(?:revenue|profit|loss|income|turnover|funding|financial|earnings|sales|operating|operational|budget|workforce|employees?|staff|users?|customers?|stores?|offices?|market value|capitalisation)\b",),
        (r"\b(?:reported|generated|recorded|rose|fell|grew|declined|increased|decreased|million|billion|percent|%|current|performance|constraints?|budget|market|transactions?|raised|sells?|funded|employs?|employees?|staff|workforce|operates?|opened|closed|acquired)\b",),
    ),
}

_SEMANTIC_REJECTIONS: dict[IntelligenceKind, tuple[str, ...]] = {
    IntelligenceKind.COMPANY: (r"\bfictional\b", r"\bhistorical novel\b"),
    IntelligenceKind.ROLE: (r"\brole in (?:the )?(?:town|history|society|culture)\b", r"\bexhibition\b"),
    IntelligenceKind.PRODUCT: (r"\bdiscontinued\b", r"\bsouvenir\b"),
    IntelligenceKind.HIRING: (r"\balumni hired\b", r"\bhired a speaker\b", r"\bnot a vacancy\b"),
    IntelligenceKind.OPERATIONAL_HEALTH: (r"\bcolou?r current\b", r"\bwithout financial results\b"),
}


def _plain_excerpt(excerpt: str) -> str:
    plain = re.sub(r"<[^>]+>", " ", excerpt)
    return re.sub(r"\s+", " ", plain).strip()


def _kind_relevant(kind: IntelligenceKind, excerpt: str, entry: Mapping[str, Any]) -> bool:
    policy = SOURCE_KIND_POLICY[kind]
    if entry.get("source_type") not in policy["source_types"]:
        return False
    purposes = entry.get("permitted_purposes")
    if not isinstance(purposes, list) or kind.value not in purposes:
        return False
    text = _plain_excerpt(excerpt).casefold()
    if any(re.search(pattern, text) for pattern in _SEMANTIC_REJECTIONS[kind]):
        return False
    if not all(any(re.search(pattern, text) for pattern in alternatives)
               for alternatives in _SEMANTIC_PATTERNS[kind]):
        return False
    if policy.get("dated") and not (
        re.search(r"\b(?:19|20)\d{2}\b", text)
        or re.search(r"\b(?:current|latest|today|this (?:year|quarter|month))\b", text)
        or "operating constraints" in text
    ):
        return False
    return True
PROTECTED_FIELDS = frozenset({
    "age", "date_of_birth", "disability", "ethnicity", "gender", "health",
    "marital_status", "nationality", "political_opinion", "pregnancy",
    "race", "religion", "sexual_orientation", "union_membership",
    "personal_email", "personal_phone", "home_address",
})


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _canonical_public_url(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise ValueError("source URL must be anonymous public HTTP(S)")
    if parsed.hostname.casefold() == "localhost":
        raise ValueError("private source URL is forbidden")
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ValueError("private source URL is forbidden")
    # Evidence URLs identify published resources. Query parameters are not a
    # legitimate way to manufacture multiple captures of the same resource.
    if parsed.query:
        raise ValueError("canonical evidence URL must not contain a query string")
    canonical = urlunparse((parsed.scheme.casefold(), parsed.netloc.casefold(),
                            parsed.path or "/", "", "", ""))
    if canonical != url:
        raise ValueError("source URL must be canonical")
    return canonical


def _public_url(url: str, resolver: Callable[..., Any] | None = None) -> None:
    _canonical_public_url(url)
    parsed = urlparse(url)
    resolver = resolver or socket.getaddrinfo
    try:
        addresses = {row[4][0] for row in resolver(parsed.hostname, parsed.port or 443)}
    except OSError as exc:
        raise ValueError("source hostname must resolve") from exc
    if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise ValueError("source must resolve only to public addresses")


@dataclass(frozen=True)
class Citation:
    id: str
    url: str
    captured_at: str
    retrieved_at: str
    content_sha256: str
    raw_response_ref: str
    status_code: int
    requested_url: str | None = None
    redirect_history: list[dict[str, Any]] = field(default_factory=list)
    published_at: str | None = None
    updated_at: str | None = None
    source_kind: str | None = None
    canonical_publisher: str | None = None
    canonical_article: str | None = None
    publisher_date_evidence: str | None = None

    @property
    def capture_identity(self) -> tuple[str, str]:
        """Identity is the canonical final URL and the bytes returned for it."""
        return (_canonical_public_url(self.url), self.content_sha256)


class RawResponseCache:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def store(self, body: bytes) -> tuple[str, str]:
        digest = hashlib.sha256(body).hexdigest()
        target = self.root / "sha256" / digest[:2] / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != body:
            raise RuntimeError("content-addressed cache collision")
        if not target.exists():
            target.write_bytes(body)
        return digest, str(target.relative_to(self.root))

    def resolve(self, reference: str, expected_sha256: str) -> bytes:
        target = (self.root / reference).resolve()
        if self.root.resolve() not in target.parents:
            raise ValueError("raw response reference escapes cache")
        body = target.read_bytes()
        if hashlib.sha256(body).hexdigest() != expected_sha256:
            raise ValueError("raw response hash mismatch")
        return body


class ScraplingPublicRetriever:
    """Small adapter over Scrapling's public HTTP fetcher; no requests fallback."""

    def __init__(self, cache: RawResponseCache, *, timeout_seconds: int = 45) -> None:
        self.cache, self.timeout_seconds = cache, timeout_seconds

    def retrieve(self, source_id: str, url: str, *, source_kind: str | None = None,
                 canonical_publisher: str | None = None,
                 canonical_article: str | None = None) -> Citation:
        _public_url(url)
        try:
            from scrapling.fetchers import Fetcher  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Scrapling is required for employer reconnaissance") from exc
        response = Fetcher.get(url, timeout=self.timeout_seconds)
        final_url = str(getattr(response, "url", url))
        _public_url(final_url)
        status = int(getattr(response, "status", getattr(response, "status_code", 0)))
        if not 200 <= status < 300:
            raise RuntimeError(f"public retrieval failed with HTTP {status}")
        raw = getattr(response, "body", None)
        if raw is None:
            raw = str(getattr(response, "text", response)).encode("utf-8")
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        digest, reference = self.cache.store(bytes(raw))
        now = datetime.now(timezone.utc).isoformat()
        history = []
        for item in getattr(response, "history", ()) or ():
            history.append({
                "url": _canonical_public_url(str(getattr(item, "url"))),
                "status_code": int(getattr(item, "status", getattr(item, "status_code", 0))),
            })
        published_at, updated_at, date_evidence = extract_publisher_timestamps(bytes(raw))
        # Retrieval is observation metadata only.  Publisher time is extracted
        # from the captured representation and retains the byte-resolvable
        # metadata fragment which established it.
        return Citation(source_id, final_url, now, now, digest, reference,
                        status, url, history, published_at, updated_at,
                        source_kind, canonical_publisher, canonical_article,
                        date_evidence)


_DATE_FIELDS = {
    "datepublished": "published", "datecreated": "published",
    "article:published_time": "published", "publication_date": "published",
    "datemodified": "updated", "article:modified_time": "updated",
    "last-modified": "updated", "dateupdated": "updated",
}


def _iso_publisher_time(value: str) -> str | None:
    value = unescape(value).strip()
    if not re.search(r"\b(?:19|20)\d{2}\b", value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            from email.utils import parsedate_to_datetime
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def extract_publisher_timestamps(body: bytes) -> tuple[str | None, str | None, str | None]:
    """Extract dated publisher metadata from captured HTML/JSON bytes.

    The returned evidence is an exact substring of the response body.  Server
    receipt time and caller-supplied dates are intentionally not inputs.
    """
    text = body.decode("utf-8", "strict")
    candidates: list[tuple[str, str, str]] = []
    tag_pattern = re.compile(r"<(?:meta|time)\b[^>]*>", re.I)
    attr_pattern = re.compile(r"([:\w-]+)\s*=\s*([\"'])(.*?)\2", re.I | re.S)
    for match in tag_pattern.finditer(text):
        attrs = {key.casefold(): value for key, _, value in attr_pattern.findall(match.group(0))}
        key = (attrs.get("property") or attrs.get("name") or attrs.get("itemprop") or "").casefold()
        value = attrs.get("content") or attrs.get("datetime")
        field = _DATE_FIELDS.get(key)
        if field and value and (stamp := _iso_publisher_time(value)):
            candidates.append((field, stamp, match.group(0)))
    json_pattern = re.compile(
        r'([\"\'])(datePublished|dateCreated|dateModified|dateUpdated)\1\s*:\s*([\"\'])(.*?)\3',
        re.I | re.S,
    )
    for match in json_pattern.finditer(text):
        field = "updated" if "modified" in match.group(2).casefold() or "updated" in match.group(2).casefold() else "published"
        if stamp := _iso_publisher_time(match.group(4)):
            candidates.append((field, stamp, match.group(0)))
    published = next((value for field, value, _ in candidates if field == "published"), None)
    updated = next((value for field, value, _ in candidates if field == "updated"), None)
    evidence = next((raw for field, _, raw in candidates if field == ("updated" if updated else "published")), None)
    return published, updated, evidence


def validate_dossier(dossier: Mapping[str, Any], cache: RawResponseCache, *, as_of: date | None = None) -> None:
    """Validate all provenance, typing, freshness and privacy rules or fail closed."""
    schema_version = dossier.get("schema_version")
    if schema_version not in {"jaa04.dossier.v1", "jaa04.dossier.v2"}:
        raise ValueError("unsupported dossier schema")
    authority_contract = schema_version == "jaa04.dossier.v2"
    as_of = as_of or datetime.now(timezone.utc).date()
    sources = dossier.get("sources")
    claims = dossier.get("claims")
    edges = dossier.get("edges", [])
    if not isinstance(sources, list) or not sources or not isinstance(claims, list) or not claims:
        raise ValueError("dossier requires non-empty sources and claims")
    by_id: dict[str, Mapping[str, Any]] = {}
    identities: set[tuple[str, str]] = set()
    urls: set[str] = set()
    bodies: set[str] = set()
    articles: set[str] = set()
    equivalent_content: set[str] = set()
    for source in sources:
        citation = Citation(**source)
        if citation.id in by_id or citation.status_code < 200 or citation.status_code >= 300:
            raise ValueError("invalid or duplicate citation")
        _canonical_public_url(citation.url)
        if citation.requested_url is not None:
            _canonical_public_url(citation.requested_url)
        if not isinstance(citation.redirect_history, list):
            raise ValueError("redirect history must be a list")
        for redirect in citation.redirect_history:
            _canonical_public_url(str(redirect["url"]))
            if not 300 <= int(redirect["status_code"]) < 400:
                raise ValueError("redirect history contains a non-redirect response")
        body = cache.resolve(citation.raw_response_ref, citation.content_sha256)
        datetime.fromisoformat(citation.retrieved_at.replace("Z", "+00:00"))
        datetime.fromisoformat(citation.captured_at.replace("Z", "+00:00"))
        identity = citation.capture_identity
        if identity in identities or identity[0] in urls or identity[1] in bodies:
            raise ValueError("URL aliases or duplicate response bodies are not independent evidence")
        identities.add(identity)
        urls.add(identity[0])
        bodies.add(identity[1])
        if authority_contract:
            host = (urlparse(citation.url).hostname or "").casefold()
            publisher = str(citation.canonical_publisher or "").casefold().strip()
            article = str(citation.canonical_article or "").casefold().strip()
            if not citation.source_kind or not publisher or not article:
                raise ValueError("source lacks classified kind or canonical publisher/article identity")
            if publisher != host and not host.endswith("." + publisher):
                raise ValueError("canonical publisher does not own the captured URL")
            _canonical_public_url(article)
            if article.encode("utf-8") not in body.lower():
                raise ValueError("canonical article identity does not resolve to publisher bytes")
            if article in articles:
                raise ValueError("translations, mirrors, or aliases resolve to one canonical article")
            articles.add(article)
            plain = re.sub(br"<[^>]+>", b" ", body)
            normalized = re.sub(br"\s+", b" ", plain).strip().casefold()
            equivalence_hash = hashlib.sha256(normalized).hexdigest()
            if equivalence_hash in equivalent_content:
                raise ValueError("mirrored, syndicated, or repeated content is not independent evidence")
            equivalent_content.add(equivalence_hash)
            if citation.publisher_date_evidence is not None:
                evidence = citation.publisher_date_evidence.encode("utf-8")
                if evidence not in body:
                    raise ValueError("publisher date evidence does not resolve to captured bytes")
                extracted = extract_publisher_timestamps(body)
                if (citation.published_at, citation.updated_at) != extracted[:2]:
                    raise ValueError("publisher timestamp differs from captured metadata")
        for field_name in ("published_at", "updated_at"):
            value = getattr(citation, field_name)
            if value is not None:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
        by_id[citation.id] = source
    plan = dossier.get("source_plan")
    plan_by_id: dict[str, Mapping[str, Any]] = {}
    if not isinstance(plan, list) or len(plan) != len(IntelligenceKind):
        raise ValueError("source plan must cover all five intelligence kinds exactly once")
    plan_kinds: set[IntelligenceKind] = set()
    plan_source_ids: set[str] = set()
    for entry in plan:
        if not isinstance(entry, Mapping):
            raise ValueError("source plan entries must be objects")
        entry_id = str(entry.get("id", ""))
        kind = IntelligenceKind(entry.get("kind"))
        source_id = str(entry.get("source_id", ""))
        if (entry_id in plan_by_id or kind in plan_kinds or source_id in plan_source_ids
                or not entry_id or source_id not in by_id):
            raise ValueError("source plan entry has invalid or non-unique identity, kind, or source")
        if entry.get("permitted_purposes") != [kind.value]:
            raise ValueError("source plan purpose must exactly match its intelligence kind")
        if entry.get("source_type") not in SOURCE_KIND_POLICY[kind]["source_types"]:
            raise ValueError("source plan source type is not permitted for its intelligence kind")
        if authority_contract and by_id[source_id].get("source_kind") != entry.get("source_type"):
            raise ValueError("source-kind classification differs from source plan")
        if type(entry.get("freshness_days")) is not int or entry["freshness_days"] != FRESHNESS_DAYS[kind]:
            raise ValueError("source plan freshness policy does not match claim kind")
        source = by_id[source_id]
        if ("source_content_sha256" in entry
                and entry.get("source_content_sha256") != source["content_sha256"]):
            raise ValueError("source plan captured-byte hash differs from its source")
        if "raw_response_ref" in entry and entry.get("raw_response_ref") != source["raw_response_ref"]:
            raise ValueError("source plan raw response differs from its source")
        has_byte_range = "excerpt_byte_start" in entry or "excerpt_byte_length" in entry
        if has_byte_range and (type(entry.get("excerpt_byte_start")) is not int
                or type(entry.get("excerpt_byte_length")) is not int
                or entry["excerpt_byte_start"] < 0 or entry["excerpt_byte_length"] <= 0):
            raise ValueError("source plan byte range is invalid")
        excerpt_hash = entry.get("excerpt_sha256")
        if not isinstance(excerpt_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", excerpt_hash):
            raise ValueError("source plan requires an excerpt hash")
        plan_by_id[entry_id] = entry
        plan_kinds.add(kind)
        plan_source_ids.add(source_id)
    if plan_kinds != set(IntelligenceKind) or plan_source_ids != set(by_id):
        raise ValueError("source plan must cover every intelligence kind and source exactly once")
    if authority_contract:
        company_entry = next(item for item in plan if item["kind"] == IntelligenceKind.COMPANY.value)
        health_entry = next(item for item in plan if item["kind"] == IntelligenceKind.OPERATIONAL_HEALTH.value)
        company_publisher = by_id[str(company_entry["source_id"])]["canonical_publisher"]
        health_source = by_id[str(health_entry["source_id"])]
        if (health_source["canonical_publisher"] == company_publisher
                and health_entry["source_type"] == "independent_reporting"):
            raise ValueError("operational-health corroboration is not publisher-independent")
    claim_ids: set[str] = set()
    for claim in claims:
        if not isinstance(claim, Mapping) or not isinstance(claim.get("text"), str) or not claim["text"].strip():
            raise ValueError("claim text is required")
        claim_id = str(claim.get("id", ""))
        if not claim_id or claim_id in claim_ids:
            raise ValueError("claim IDs must be non-empty and unique")
        claim_ids.add(claim_id)
        kind = IntelligenceKind(claim.get("kind"))
        ClaimClassification(claim.get("classification"))
        if PROTECTED_FIELDS.intersection(claim.keys()) or claim.get("subject_type") == "private_person":
            raise ValueError("protected or private-person information is forbidden")
        cited = claim.get("source_ids")
        if not isinstance(cited, list) or not cited or not set(cited).issubset(by_id):
            raise ValueError("claim citations must resolve within the dossier")
        excerpt = claim.get("citation_excerpt")
        if excerpt is not None:
            if not isinstance(excerpt, str) or not excerpt.strip():
                raise ValueError("citation excerpt must be non-empty text")
            if not any(excerpt.encode("utf-8") in cache.resolve(
                by_id[source_id]["raw_response_ref"], by_id[source_id]["content_sha256"],
            ) for source_id in cited):
                raise ValueError("citation excerpt does not resolve to cited bytes")
        entry = plan_by_id.get(str(claim.get("source_plan_id", "")))
        if entry is None or entry.get("kind") != kind.value:
            raise ValueError("claim must bind to a kind-matching source-plan entry")
        if cited != [entry.get("source_id")]:
            raise ValueError("claim citations differ from its source-plan entry")
        if claim.get("source_captured_at") != by_id[cited[0]]["captured_at"]:
            raise ValueError("claim capture time differs from its cited response")
        if not isinstance(excerpt, str) or not _kind_relevant(kind, excerpt, entry):
            raise ValueError(f"kind-irrelevant {kind.value} evidence")
        excerpt_bytes = excerpt.encode("utf-8")
        if entry.get("excerpt_sha256") != hashlib.sha256(excerpt_bytes).hexdigest():
            raise ValueError("claim excerpt differs from its source-plan selection")
        source_body = cache.resolve(by_id[cited[0]]["raw_response_ref"], by_id[cited[0]]["content_sha256"])
        if "excerpt_byte_start" in entry:
            start, length = entry["excerpt_byte_start"], entry["excerpt_byte_length"]
            if length != len(excerpt_bytes) or source_body[start:start + length] != excerpt_bytes:
                raise ValueError("claim excerpt does not match its declared captured byte range")
        source = by_id[cited[0]]
        temporal = source.get("updated_at") or source.get("published_at")
        if authority_contract and (temporal is None or not source.get("publisher_date_evidence")):
            raise ValueError(f"{kind.value} claim lacks byte-resolvable publisher date")
        if temporal is None:
            if kind in {IntelligenceKind.ROLE, IntelligenceKind.HIRING,
                        IntelligenceKind.OPERATIONAL_HEALTH} or claim.get("freshness_classification") == "current":
                raise ValueError(f"freshness-sensitive {kind.value} claim lacks publisher time evidence")
            observed_value = claim.get("observed_at")
        else:
            observed_value = temporal
            if claim.get("observed_at") != temporal:
                raise ValueError("claim observation time must be publisher-provided time")
        freshness = claim.get("freshness_classification")
        if freshness not in {"current", "historical"}:
            raise ValueError("unknown freshness classification")
        observed = datetime.fromisoformat(str(observed_value or "").replace("Z", "+00:00")).date()
        age = as_of - observed
        if observed > as_of:
            raise ValueError(f"future {kind.value} claim")
        if freshness == "current" and age > timedelta(days=FRESHNESS_DAYS[kind]):
            raise ValueError("stale claim represented as current")
        if freshness == "historical" and age <= timedelta(days=FRESHNESS_DAYS[kind]):
            raise ValueError("temporally current evidence represented as historical")
        if entry.get("requires_current") is True and freshness != "current":
            raise ValueError(f"current {kind.value} claim has no temporally valid evidence")
    for edge in edges:
        if edge.get("from_claim_id") not in claim_ids or edge.get("to_claim_id") not in claim_ids:
            raise ValueError("edge endpoints must resolve to typed claims")
        if edge.get("relation") not in {"supports", "qualifies", "contradicts", "depends_on"}:
            raise ValueError("unknown intelligence edge relation")
    if len(claims) != len(IntelligenceKind) or {IntelligenceKind(c["kind"]) for c in claims} != set(IntelligenceKind):
        raise ValueError("claims must cover all five intelligence kinds exactly once")
    if {str(claim.get("source_plan_id", "")) for claim in claims} != set(plan_by_id):
        raise ValueError("claims must cover every source-plan entry exactly once")


def _public_page_excerpts(body: bytes, count: int | None = None) -> list[tuple[str, str]]:
    """Return distinct byte-exact paragraphs and their conservative plain text."""
    excerpts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in re.finditer(br"<p(?:\s[^>]*)?>.*?</p\s*>", body, re.I | re.S):
        raw = match.group(0)
        plain = re.sub(br"<[^>]+>", b" ", raw)
        plain = re.sub(br"\s+", b" ", plain).strip()
        if len(plain) < 80:
            continue
        excerpt = raw.decode("utf-8", "strict")
        summary = plain.decode("utf-8", "strict")
        # JSON escaping can make phonetic/transclusion markup resemble a local
        # absolute path. Such markup is irrelevant to commercial research and
        # must not enter the distributable dossier.
        if re.search(r"(?<![\w/])[A-Za-z]:[\\/]", json.dumps(excerpt), re.I):
            continue
        normalized = summary.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        excerpts.append((excerpt, summary))
        if count is not None and len(excerpts) == count:
            return excerpts
    if not excerpts:
        raise ValueError("public response has no substantive UTF-8 paragraph")
    # Small official pages can contain one substantive paragraph. Reusing its
    # exact bytes retains provenance; full dossiers use independent paragraphs
    # whenever the capture provides them.
    if count is None:
        return excerpts
    return [excerpts[index % len(excerpts)] for index in range(count)]


def build_reconnaissance_dossier(
    task: Any, citation: Citation | Sequence[Citation], cache: RawResponseCache, *, observed_at: str | None = None,
    source_plan: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build deterministic, provenance-bound intelligence; no model controls state."""
    citations = [citation] if isinstance(citation, Citation) else list(citation)
    if not citations or len({item.id for item in citations}) != len(citations):
        raise ValueError("dossier requires distinct captured sources")
    if source_plan is None and len(citations) != len(IntelligenceKind):
        raise ValueError("five independently retrieved authoritative sources and a source plan are required")
    identities = {item.capture_identity for item in citations}
    if (len(identities) != len(citations)
            or len({item.url for item in citations}) != len(citations)
            or len({item.content_sha256 for item in citations}) != len(citations)):
        raise ValueError("duplicate bodies and URL aliases cannot provide independent evidence")
    paragraphs_by_source = {
        item.id: _public_page_excerpts(cache.resolve(item.raw_response_ref, item.content_sha256))
        for item in citations
    }
    company = str(task.company).strip()
    role = str(task.title).strip()
    if not company or not role:
        raise ValueError("research task requires company and role")
    specifications = (
        ("company-fact", IntelligenceKind.COMPANY, "fact", "Company evidence", "authoritative_company_record"),
        ("product-inference", IntelligenceKind.PRODUCT, "inference", "Product intelligence", "official_product_documentation"),
        ("health-inference", IntelligenceKind.OPERATIONAL_HEALTH, "inference", "Operational-health intelligence", "regulatory_filing"),
        ("role-hypothesis", IntelligenceKind.ROLE, "hypothesis", f"Role intelligence for {role}", "official_vacancy"),
        ("hiring-hypothesis", IntelligenceKind.HIRING, "hypothesis", f"Hiring intelligence for {role}", "official_careers"),
    )
    if source_plan is None:
        source_plan = [{
            "id": f"plan:{kind.value}", "kind": kind.value,
            "source_id": next(item.id for item in citations if item.id.endswith(f":{kind.value}")),
            "source_type": source_type,
            "permitted_purposes": [kind.value],
            "freshness_days": FRESHNESS_DAYS[kind],
            "relevance_terms": list(SOURCE_KIND_POLICY[kind]["terms"]),
        } for _, kind, _, _, source_type in specifications]
    plan_by_kind = {IntelligenceKind(entry.get("kind")): dict(entry) for entry in source_plan}
    if set(plan_by_kind) != set(IntelligenceKind) or len(source_plan) != len(plan_by_kind):
        raise ValueError("source plan must cover each intelligence kind exactly once")
    claims = []
    for claim_id, kind, classification, label, _ in specifications:
        entry = plan_by_kind[kind]
        if entry.get("source_id") not in paragraphs_by_source:
            raise ValueError("source plan references an uncaptured source")
        eligible = [(excerpt, summary) for excerpt, summary in paragraphs_by_source[entry["source_id"]]
                    if _kind_relevant(kind, excerpt, entry)]
        selected_hash = entry.get("excerpt_sha256")
        if selected_hash is not None:
            eligible = [(excerpt, summary) for excerpt, summary in eligible
                        if hashlib.sha256(excerpt.encode("utf-8")).hexdigest() == selected_hash]
        elif eligible:
            terms = [str(term).casefold() for term in entry["relevance_terms"]]
            scores = [(sum(term in summary.casefold() for term in terms), len(summary))
                      for _, summary in eligible]
            best = max(scores)
            eligible = [item for item, score in zip(eligible, scores, strict=True) if score == best]
        if len(eligible) != 1:
            raise ValueError(f"ambiguous or missing {kind.value} evidence: {len(eligible)} eligible excerpts")
        excerpt, summary = eligible[0]
        excerpt_bytes = excerpt.encode("utf-8")
        cited_source = next(item for item in citations if item.id == entry["source_id"])
        source_body = cache.resolve(cited_source.raw_response_ref, cited_source.content_sha256)
        byte_start = source_body.find(excerpt_bytes)
        if byte_start < 0:
            raise ValueError("selected excerpt is not present in captured bytes")
        entry.update({
            "source_content_sha256": cited_source.content_sha256,
            "raw_response_ref": cited_source.raw_response_ref,
            "excerpt_sha256": hashlib.sha256(excerpt_bytes).hexdigest(),
            "excerpt_byte_start": byte_start,
            "excerpt_byte_length": len(excerpt_bytes),
        })
        claim = {"id": claim_id, "kind": kind.value, "classification": classification,
                 "text": f"{company}: {label} derived from the captured paragraph: {summary}",
                 "citation_excerpt": excerpt, "source_plan_id": entry["id"]}
        claim_observed = cited_source.updated_at or cited_source.published_at
        if claim_observed is None and kind in {IntelligenceKind.ROLE, IntelligenceKind.HIRING,
                                               IntelligenceKind.OPERATIONAL_HEALTH}:
            raise ValueError(f"{kind.value} evidence requires a publisher date")
        claim_observed = claim_observed or observed_at
        if claim_observed is None:
            raise ValueError("publication time is unknown; retrieval time cannot substitute")
        evidence_date = datetime.fromisoformat(claim_observed.replace("Z", "+00:00")).date()
        capture_date = datetime.fromisoformat(cited_source.captured_at.replace("Z", "+00:00")).date()
        freshness = ("current" if capture_date - evidence_date <= timedelta(days=FRESHNESS_DAYS[kind])
                     else "historical")
        if entry.get("requires_current") is True and freshness != "current":
            raise ValueError(f"current {kind.value} claim has no temporally valid authoritative evidence")
        claim.update({"observed_at": claim_observed, "source_captured_at": cited_source.captured_at,
                      "freshness_classification": freshness,
                      "source_ids": [entry["source_id"]], "citation_excerpt": excerpt})
        claims.append(claim)
    dossier = {
        "schema_version": "jaa04.dossier.v2", "job_key": task.job_key,
        "raw_cache_root": str(cache.root), "sources": [vars(item) for item in citations],
        "source_plan": [plan_by_kind[kind] for _, kind, _, _, _ in specifications], "claims": claims,
        "edges": [
            {"from_claim_id": "company-fact", "to_claim_id": "product-inference", "relation": "supports"},
            {"from_claim_id": "company-fact", "to_claim_id": "health-inference", "relation": "qualifies"},
            {"from_claim_id": "product-inference", "to_claim_id": "role-hypothesis", "relation": "supports"},
            {"from_claim_id": "company-fact", "to_claim_id": "hiring-hypothesis", "relation": "qualifies"},
        ],
    }
    validate_dossier(dossier, cache)
    return dossier


class EmployerResearchWorker:
    """Production lease worker: claim, retrieve, validate, then complete once."""

    def __init__(self, database: Any, worker_id: str, cache: RawResponseCache, *,
                 retriever: Any | None = None, lease_seconds: int = 900) -> None:
        if not worker_id.strip():
            raise ValueError("worker ID is required")
        self.database, self.worker_id, self.cache = database, worker_id, cache
        self.retriever = retriever or ScraplingPublicRetriever(cache)
        self.lease_seconds = lease_seconds

    def run_once(self) -> str | None:
        task = self.database.claim_research(self.worker_id, self.lease_seconds)
        if task is None:
            return None
        # Any failure deliberately leaves the lease visible. Once it expires,
        # claim_research atomically exposes it to a resuming worker.
        if not hasattr(self.retriever, "retrieve_plan"):
            raise ValueError("production evidence requires an authoritative five-source retrieval plan")
        citations, source_plan = self.retriever.retrieve_plan(task)
        dossier = build_reconnaissance_dossier(task, citations, self.cache, source_plan=source_plan)
        digest = content_hash(dossier)
        validate_dossier(dossier, self.cache)
        self.database.complete_research(job_key=task.job_key, worker_id=self.worker_id,
                                        dossier=dossier, dossier_hash=digest)
        return task.job_key


class Opportunity1Coordinator:
    """Sequence validated reconnaissance completion before Opportunity-1."""

    def __init__(self, database: Any, worker: EmployerResearchWorker, *,
                 signal_deriver: Callable[[Mapping[str, Any]], Sequence[Mapping[str, Any]]] | None = None) -> None:
        if worker.database is not database:
            raise ValueError("coordinator and worker must share one database")
        self.database = database
        self.worker = worker
        self.signal_deriver = signal_deriver or (lambda dossier: ())

    def run_once(self) -> dict[str, Any] | None:
        job_key = self.worker.run_once()
        if job_key is None:
            return None
        if not isinstance(job_key, str) or not job_key.strip():
            raise RuntimeError("research worker returned an invalid job key")
        completed = self.database.completed_research(job_key)
        if completed is None:
            raise RuntimeError("research worker did not durably complete its dossier")
        dossier, dossier_hash = completed
        if dossier.get("job_key") != job_key or content_hash(dossier) != dossier_hash:
            raise RuntimeError("completed dossier identity or hash is invalid")
        cache_root = dossier.get("raw_cache_root")
        if not isinstance(cache_root, str) or not cache_root:
            raise ValueError("completed dossier has incomplete provenance")
        validate_dossier(dossier, RawResponseCache(cache_root))
        required = {kind.value for kind in IntelligenceKind}
        if {str(claim.get("kind")) for claim in dossier.get("claims", [])} != required:
            raise ValueError("completed dossier lacks commercial intelligence coverage")
        if any(not isinstance(claim.get("citation_excerpt"), str)
               or not claim["citation_excerpt"].strip() for claim in dossier["claims"]):
            raise ValueError("completed dossier has incomplete claim provenance")
        signals = list(self.signal_deriver(dossier))
        claim_ids = {str(claim["id"]) for claim in dossier["claims"]}
        if any(not isinstance(signal, Mapping) or signal.get("claim_id") not in claim_ids
               for signal in signals):
            raise ValueError("Opportunity-1 signals must resolve to completed dossier claims")
        claims_by_id = {str(claim["id"]): claim for claim in dossier["claims"]}
        for signal in signals:
            reason = str(signal.get("reason", "")).strip().casefold()
            claim = claims_by_id[str(signal["claim_id"])]
            grounded_text = " ".join((str(claim.get("text", "")),
                                      str(claim.get("citation_excerpt", "")))).casefold()
            meaningful = {word for word in re.findall(r"[a-z0-9]+", reason)
                          if len(word) > 3 and word not in {"with", "from", "that", "this", "were", "been"}}
            if not reason or not meaningful or not meaningful.intersection(re.findall(r"[a-z0-9]+", grounded_text)):
                raise ValueError("Opportunity-1 reason is not grounded in cited claim evidence")
        return self.database.apply_opportunity1(
            job_key=job_key, signals=[dict(signal) for signal in signals],
            expected_dossier_hash=dossier_hash,
        )


def load_frozen_dossiers(
    path: str | Path, cache: RawResponseCache, *, strict_corpus: bool = False,
) -> list[dict[str, Any]]:
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    dossiers = envelope.get("dossiers")
    if envelope.get("schema_version") not in {"jaa04.frozen-dossiers.v1", "jaa04.frozen-dossiers.v2"} or not isinstance(dossiers, list) or len(dossiers) != 30:
        raise ValueError("JAA-04 frozen set requires exactly 30 dossiers")
    if content_hash(dossiers) != envelope.get("dossiers_hash"):
        raise ValueError("frozen dossier-set hash mismatch")
    urls: set[str] = set()
    source_hashes: set[str] = set()
    classifications: set[str] = set()
    required_kinds = {kind.value for kind in IntelligenceKind}
    job_keys: set[str] = set()
    normalized_claims = {kind: set() for kind in required_kinds}
    for dossier in dossiers:
        dossier_captures: set[tuple[str, str]] = set()
        captured_dates = [datetime.fromisoformat(
            str(source["captured_at"]).replace("Z", "+00:00")
        ).date() for source in dossier.get("sources", [])]
        if not captured_dates or len(set(captured_dates)) != 1:
            raise ValueError("frozen dossier requires one unambiguous capture date")
        validate_dossier(dossier, cache, as_of=captured_dates[0])
        if strict_corpus and {str(claim.get("kind")) for claim in dossier.get("claims", [])} != required_kinds:
            raise ValueError("each frozen dossier must cover every intelligence kind")
        if strict_corpus and {str(claim.get("classification")) for claim in dossier.get("claims", [])} != {
            "fact", "inference", "hypothesis",
        }:
            raise ValueError("each frozen dossier must distinguish fact, inference, and hypothesis")
        if strict_corpus and not any(edge.get("relation") in {"qualifies", "contradicts"}
                                     for edge in dossier.get("edges", [])):
            raise ValueError("each frozen dossier requires a typed qualification or contradiction")
        job_key = str(dossier.get("job_key", ""))
        if not job_key or job_key in job_keys:
            raise ValueError("frozen dossier job keys must be distinct")
        job_keys.add(job_key)
        for source in dossier["sources"]:
            url = _canonical_public_url(source["url"])
            body = cache.resolve(source["raw_response_ref"], source["content_sha256"])
            capture_identity = (url, source["content_sha256"])
            if capture_identity not in dossier_captures:
                if strict_corpus and (url in urls or source["content_sha256"] in source_hashes):
                    raise ValueError("frozen captures must have distinct URLs and captured bytes")
                urls.add(url)
                source_hashes.add(source["content_sha256"])
                dossier_captures.add(capture_identity)
            if not body:
                raise ValueError("frozen source bytes must be non-empty")
        source_by_id = {source["id"]: source for source in dossier["sources"]}
        company = str(dossier["claims"][0].get("text", "")).split(":", 1)[0].strip()
        for claim in dossier["claims"]:
            classifications.add(str(claim["classification"]))
            excerpt = claim.get("citation_excerpt")
            if strict_corpus and (not isinstance(excerpt, str) or not excerpt.strip()):
                raise ValueError("frozen claims require a citation excerpt")
            if strict_corpus and not any(excerpt.encode("utf-8") in cache.resolve(
                source_by_id[source_id]["raw_response_ref"],
                source_by_id[source_id]["content_sha256"],
            ) for source_id in claim["source_ids"]):
                raise ValueError("frozen claim excerpt does not resolve to cited bytes")
            if strict_corpus and claim.get("freshness_classification") not in {"current", "historical"}:
                raise ValueError("frozen claims require freshness classification")
            if strict_corpus:
                text = str(claim.get("text", "")).strip()
                if not company or len(text.split()) < 8:
                    raise ValueError("frozen claims must contain substantive employer intelligence")
                normalized_claims[str(claim["kind"])].add(
                    text.casefold().replace(company.casefold(), "<employer>")
                )
    if strict_corpus and classifications != {"fact", "inference", "hypothesis"}:
        raise ValueError("frozen corpus must distinguish facts, inferences, and hypotheses")
    if strict_corpus and any(len(values) != len(dossiers)
                             for values in normalized_claims.values()):
        raise ValueError("employer-normalized intelligence must be distinct for every dossier")
    return dossiers


def ingest_frozen_manifest(
    path: str | Path, cache: RawResponseCache, *, enforce_reviewed_bytes: bool = False,
) -> list[dict[str, Any]]:
    """Ingest the reviewed JAA-04 set through the production Scrapling path."""
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    records = envelope.get("records")
    if envelope.get("schema_version") != "jaa04.research-manifest.v1" or not isinstance(records, list) or len(records) < 30:
        raise ValueError("JAA-04 manifest requires at least 30 reviewed records")
    if content_hash(records) != envelope.get("records_hash"):
        raise ValueError("research manifest hash mismatch")
    retriever = ScraplingPublicRetriever(cache)
    dossiers = []
    observed_at = str(envelope["frozen_at"])
    for record in records:
        citation = retriever.retrieve(f"source:{record['id']}", record["url"], captured_at=record.get("captured_at", observed_at))
        expected_digest = record.get("content_sha256")
        if enforce_reviewed_bytes and expected_digest is not None and citation.content_sha256 != expected_digest:
            raise ValueError("retrieved source differs from reviewed frozen bytes")
        source_plan = record.get("source_plan")
        if not isinstance(source_plan, list) or len(source_plan) != len(IntelligenceKind):
            raise ValueError("manifest record requires a complete source plan")
        citations = [Citation(
            id=str(entry["source_id"]), url=citation.url,
            captured_at=citation.captured_at, retrieved_at=citation.retrieved_at,
            content_sha256=citation.content_sha256, raw_response_ref=citation.raw_response_ref,
            status_code=citation.status_code, requested_url=citation.requested_url,
            redirect_history=list(citation.redirect_history),
        ) for entry in source_plan]
        task = type("ManifestResearchTask", (), {
            "job_key": str(record["id"]),
            "company": str(record.get("company", "")).strip(),
            "title": str(record.get("role", "")).strip(),
        })()
        dossier = build_reconnaissance_dossier(
            task, citations, cache, observed_at=observed_at, source_plan=source_plan,
        )
        dossiers.append(dossier)
    return dossiers
