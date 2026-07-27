"""JAA-04 public employer reconnaissance and fail-closed dossier contracts.

Retrieval is deliberately source controlled: only public HTTP(S) URLs are
accepted, redirects are revalidated, and every byte used by research is stored
in a content-addressed raw cache before it can become a citation.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import asdict, dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urljoin, urlparse, urlunparse

from .models import ClaimClassification, IntelligenceKind
from .public_access import PublicAccessPolicy, replay_access_receipt


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
        "source_types": {"authoritative_company_record", "official_company", "official_vacancy"},
        "terms": ("company", "organisation", "organization", "operates", "employer", "business"),
    },
    IntelligenceKind.PRODUCT: {
        "source_types": {"official_product_documentation", "official_product", "official_company", "official_vacancy"},
        "terms": ("product", "service", "platform", "customer", "clients", "technology"),
    },
    IntelligenceKind.OPERATIONAL_HEALTH: {
        "source_types": {"regulatory_filing", "regulatory_status_record", "independent_reporting", "official_financial"},
        "terms": ("revenue", "profit", "loss", "funding", "financial", "operating", "operational", "current"),
        "dated": True,
    },
    IntelligenceKind.ROLE: {
        "source_types": {"official_vacancy"},
        "terms": ("role", "position", "job", "responsibilities", "responsible", "duties"),
    },
    IntelligenceKind.HIRING: {
        "source_types": {"official_careers", "official_vacancy"},
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

_OPERATIONAL_SUBSTANCE = (
    r"\b(?:revenue|turnover|profit|loss|income|earnings|cash flow|funding|capital|"
    r"insolvenc(?:y|ies)|administration|liquidation|bankrupt(?:cy)?|going concern|"
    r"operating (?:margin|profit|loss|costs?|expenses?)|financial (?:results?|statements?|performance))\b",
    r"(?:[$£€]\s?\d|\b\d+(?:[.,]\d+)?\s*(?:million|billion|m|bn|percent|%)\b)",
)


def _plain_excerpt(excerpt: str) -> str:
    decoded = excerpt
    if re.search(r"\\(?:u[0-9a-fA-F]{4}|[\"\\/bfnrt])", excerpt):
        try:
            decoded = json.loads(f'"{excerpt}"')
        except json.JSONDecodeError:
            decoded = excerpt
    plain = re.sub(r"<[^>]+>", " ", unescape(decoded))
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
    if kind is IntelligenceKind.OPERATIONAL_HEALTH:
        # Generic scale, staffing, "operational" or company-status language is
        # not evidence of health. Admit only substantive operational/financial
        # results, distress events, or a quantified performance measure.
        if not any(re.search(pattern, text) for pattern in _OPERATIONAL_SUBSTANCE):
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


def _public_url(
    url: str,
    resolver: Callable[..., Any] | None = None,
) -> tuple[str, ...]:
    _canonical_public_url(url)
    parsed = urlparse(url)
    resolver = resolver or socket.getaddrinfo
    try:
        addresses = {row[4][0] for row in resolver(parsed.hostname, parsed.port or 443)}
    except OSError as exc:
        raise ValueError("source hostname must resolve") from exc
    if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise ValueError("source must resolve only to public addresses")
    return tuple(sorted(addresses))


def _public_transport_url(
    url: str,
    resolver: Callable[..., Any] | None = None,
) -> tuple[str, ...]:
    """Validate an anonymous public request URL without making it evidence identity.

    Official ATS APIs legitimately use query parameters for representation and
    pagination.  Those parameters remain part of the exact requested transport
    URL, but they must never become a canonical evidence identity.
    """
    parsed = urlparse(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment):
        raise ValueError("transport URL must be anonymous public HTTP(S)")
    if parsed.hostname.casefold() == "localhost":
        raise ValueError("private transport URL is forbidden")
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ValueError("private transport URL is forbidden")
    canonical = urlunparse((
        parsed.scheme.casefold(),
        parsed.netloc.casefold(),
        parsed.path or "/",
        "",
        parsed.query,
        "",
    ))
    if canonical != url:
        raise ValueError("transport URL must be canonical")
    resolver = resolver or socket.getaddrinfo
    try:
        addresses = {
            row[4][0]
            for row in resolver(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )
        }
    except OSError as exc:
        raise ValueError("transport hostname must resolve") from exc
    if not addresses or any(
        not ipaddress.ip_address(value).is_global
        for value in addresses
    ):
        raise ValueError("transport must resolve only to public addresses")
    return tuple(sorted(addresses))


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
    retrieval_engine: str | None = None
    access_receipt: dict[str, Any] | None = None

    @property
    def capture_identity(self) -> tuple[str, str]:
        """Identity is the canonical final URL and the bytes returned for it."""
        return (_canonical_public_url(self.url), self.content_sha256)


@dataclass(frozen=True)
class ATSAuthorityCanary:
    job_key: str
    company: str
    title: str
    admitted_url: str
    authority_url: str
    authority_hosts: tuple[str, ...]
    final_paths: tuple[str, ...]


# Increment-A fixtures remain bound to their exact admitted capture routes.
# Production acquisition uses the separate live route set below so a provider
# host migration does not rewrite or fabricate accepted provenance.
ATS_AUTHORITY_CANARIES = (
    ATSAuthorityCanary("greenhouse:anthropic:5030244008", "Anthropic",
        "Anthropic Fellows Program, AI Security",
        "https://job-boards.greenhouse.io/anthropic/jobs/5030244008",
        "https://api.greenhouse.io/v1/boards/anthropic/jobs/5030244008",
        ("job-boards.greenhouse.io", "api.greenhouse.io"),
        ("/anthropic/jobs/5030244008", "/v1/boards/anthropic/jobs/5030244008")),
    ATSAuthorityCanary("ashby:lendable:043d9c49-43e6-4a27-ad55-12344a941974", "Lendable",
        "Senior Frontend Engineer (React Native)",
        "https://jobs.ashbyhq.com/lendable/043d9c49-43e6-4a27-ad55-12344a941974",
        "https://jobs.ashbyhq.com/lendable/043d9c49-43e6-4a27-ad55-12344a941974",
        ("jobs.ashbyhq.com",),
        ("/lendable/043d9c49-43e6-4a27-ad55-12344a941974",)),
    ATSAuthorityCanary("workable:cogna:847CFBC5F4", "Cogna", "Software Engineer",
        "https://apply.workable.com/j/847CFBC5F4",
        "https://apply.workable.com/cogna/jobs/view/847CFBC5F4.md",
        ("apply.workable.com",),
        ("/j/847CFBC5F4", "/cogna/j/847CFBC5F4", "/cogna/j/847CFBC5F4/",
         "/cogna/jobs/view/847CFBC5F4.md")),
)
LIVE_ATS_AUTHORITY_CANARIES = (
    ATSAuthorityCanary("greenhouse:anthropic:5030244008", "Anthropic",
        "Anthropic Fellows Program, AI Security",
        "https://job-boards.greenhouse.io/anthropic/jobs/5030244008",
        "https://boards-api.greenhouse.io/v1/boards/anthropic/jobs/5030244008",
        ("job-boards.greenhouse.io", "boards-api.greenhouse.io"),
        ("/anthropic/jobs/5030244008", "/v1/boards/anthropic/jobs/5030244008")),
    ATS_AUTHORITY_CANARIES[1],
    ATS_AUTHORITY_CANARIES[2],
)
_ATS_CANARY_BY_KEY = {record.job_key: record for record in LIVE_ATS_AUTHORITY_CANARIES}
_TYPED_ATS_HOSTS = frozenset(
    host for record in LIVE_ATS_AUTHORITY_CANARIES for host in record.authority_hosts
)
_OFFICIAL_ATS_HOSTS = frozenset({
    "job-boards.greenhouse.io", "boards-api.greenhouse.io", "apply.workable.com",
    "jobs.ashbyhq.com", "jobs.lever.co", "jobs.smartrecruiters.com",
    "api.smartrecruiters.com",
})


AGGREGATOR_HOSTS = frozenset({
    "himalayas.app", "www.himalayas.app", "jobicy.com", "www.jobicy.com",
    "remotefirstjobs.com", "www.remotefirstjobs.com", "remoteok.com",
    "www.remoteok.com", "weworkremotely.com", "www.weworkremotely.com",
    "remotive.com", "www.remotive.com", "themuse.com", "www.themuse.com",
    "arbeitnow.com", "www.arbeitnow.com", "adzuna.co.uk", "www.adzuna.co.uk",
    "reed.co.uk", "www.reed.co.uk", "jooble.org", "uk.jooble.org",
})


@dataclass(frozen=True)
class ATSRouteAdapter:
    """Deterministic authority transform bound to an admitted ATS identity."""

    family: str
    admitted_hosts: tuple[str, ...]
    authority_hosts: tuple[str, ...]

    def _identity(self, task: Any) -> tuple[str, str]:
        parts = str(task.job_key).split(":")
        if len(parts) != 3 or parts[0].casefold() != self.family:
            raise ValueError("ATS job key is not a canonical family:tenant:vacancy identity")
        tenant, vacancy = parts[1], parts[2]
        if not tenant or not vacancy or any(value in {".", ".."} for value in (tenant, vacancy)):
            raise ValueError("ATS tenant and vacancy identities must be non-empty path segments")
        return tenant, vacancy

    def _validate_route(self, task: Any, url: str, *, final: bool = False) -> None:
        """Bind one request/redirect URL to the typed tenant and vacancy.

        Host allow-lists alone are insufficient: ATS hosts commonly serve many
        tenants and a successful response may describe a different vacancy.
        """
        tenant, vacancy = self._identity(task)
        canonical = _canonical_public_url(url)
        parsed = urlparse(canonical)
        host, path = (parsed.hostname or "").casefold(), parsed.path
        admitted = host in self.admitted_hosts
        authority = host in self.authority_hosts
        valid = False
        if self.family == "greenhouse":
            valid = ((admitted and path == f"/{tenant}/jobs/{vacancy}") or
                     (authority and path == f"/v1/boards/{tenant}/jobs/{vacancy}"))
        elif self.family == "ashby":
            valid = admitted and path == f"/{tenant}/{vacancy}"
        elif self.family == "lever":
            valid = admitted and path == f"/{tenant}/{vacancy}"
        elif self.family == "smartrecruiters":
            if admitted:
                segments = path.split("/")
                valid = (len(segments) == 3 and segments[1] == tenant and
                         (segments[2] == vacancy or segments[2].startswith(vacancy + "-")))
            if authority:
                valid = valid or path == f"/v1/companies/{tenant}/postings/{vacancy}"
        elif self.family == "workable":
            folded = path.casefold()
            tenant_folded, vacancy_folded = tenant.casefold(), vacancy.casefold()
            # The tenant-less /j route is only a seed. A final representation
            # must carry the tenant as well as the vacancy identity.
            seed = folded == f"/j/{vacancy_folded}"
            tenant_routes = {
                f"/{tenant_folded}/j/{vacancy_folded}",
                f"/{tenant_folded}/j/{vacancy_folded}/",
                f"/{tenant_folded}/jobs/view/{vacancy_folded}.md",
            }
            valid = admitted and ((seed and not final) or folded in tenant_routes)
        if not valid:
            raise ValueError(f"{self.family} route does not match the admitted tenant and vacancy identity")

    def authority_url(self, task: Any) -> str:
        tenant, vacancy = self._identity(task)
        parsed = urlparse(str(task.url))
        host, path = (parsed.hostname or "").casefold(), parsed.path.rstrip("/")
        if host not in self.admitted_hosts:
            raise ValueError("admitted ATS URL host does not match its typed identity")
        if self.family == "greenhouse":
            expected = f"/{tenant}/jobs/{vacancy}"
            if path != expected:
                raise ValueError("Greenhouse admitted path does not match its typed identity")
            return f"https://boards-api.greenhouse.io/v1/boards/{tenant}/jobs/{vacancy}"
        if self.family == "ashby":
            if path != f"/{tenant}/{vacancy}":
                raise ValueError("Ashby admitted path does not match its typed identity")
            return str(task.url)
        if self.family == "lever":
            if path != f"/{tenant}/{vacancy}":
                raise ValueError("Lever admitted path does not match its typed identity")
            return str(task.url)
        if self.family == "smartrecruiters":
            segments = [part for part in path.split("/") if part]
            if (len(segments) != 2 or segments[0] != tenant or
                    not (segments[1] == vacancy or segments[1].startswith(vacancy + "-"))):
                raise ValueError("SmartRecruiters admitted path does not match its typed identity")
            # The public job representation carries byte-resolvable structured
            # vacancy metadata. The API robots policy disallows this product's
            # user agent, so acquisition must remain on the admitted official
            # page instead of treating an API terms grant as a robots bypass.
            return str(task.url)
        if self.family == "workable":
            if path.casefold() != f"/j/{vacancy}".casefold():
                raise ValueError("Workable admitted path does not match its typed identity")
            # Workable's admitted rendering route publishes this exact
            # tenant-bound Markdown representation. Use the official vacancy
            # representation so semantic evidence and publisher time remain
            # byte-resolvable, as they are for the declared Workable canary.
            return f"https://apply.workable.com/{tenant}/jobs/view/{vacancy}.md"
        raise ValueError("unsupported ATS family")

    def validate_capture(self, task: Any, citation: Citation, cache: "RawResponseCache") -> None:
        body = cache.resolve(citation.raw_response_ref, citation.content_sha256)
        if citation.status_code < 200 or citation.status_code >= 300 or not body:
            raise ValueError("ATS authority response is not a live non-empty success")
        requested = citation.requested_url
        if not requested:
            raise ValueError("ATS capture lacks its requested route")
        self._validate_route(task, requested)
        for row in citation.redirect_history:
            self._validate_route(task, str(row.get("url", "")))
        self._validate_route(task, citation.url, final=True)
        text = _plain_excerpt(body.decode("utf-8", "strict")).casefold()
        company_tokens = [token for token in re.findall(r"[a-z0-9]+", str(task.company).casefold()) if len(token) > 2]
        title_tokens = [token for token in re.findall(r"[a-z0-9]+", str(task.title).casefold()) if len(token) > 3]
        if not company_tokens or not any(token in text for token in company_tokens):
            raise ValueError("ATS response does not identify the admitted employer")
        if not title_tokens or sum(token in text for token in title_tokens) < min(2, len(title_tokens)):
            raise ValueError("ATS response does not identify the admitted vacancy title")


DEFAULT_ATS_ROUTE_ADAPTERS = {
    row.family: row for row in (
        ATSRouteAdapter(
            "greenhouse",
            ("job-boards.greenhouse.io", "job-boards.eu.greenhouse.io"),
            ("boards-api.greenhouse.io",),
        ),
        ATSRouteAdapter("workable", ("apply.workable.com",), ("apply.workable.com",)),
        ATSRouteAdapter("ashby", ("jobs.ashbyhq.com",), ("jobs.ashbyhq.com",)),
        ATSRouteAdapter("lever", ("jobs.lever.co",), ("jobs.lever.co",)),
        ATSRouteAdapter("smartrecruiters", ("jobs.smartrecruiters.com",), ("api.smartrecruiters.com",)),
    )
}


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
            try:
                with target.open("xb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                target.chmod(0o444)
            except FileExistsError:
                if target.read_bytes() != body:
                    raise RuntimeError("content-addressed cache collision")
        return digest, str(target.relative_to(self.root))

    def resolve(self, reference: str, expected_sha256: str) -> bytes:
        target = (self.root / reference).resolve()
        if self.root.resolve() not in target.parents:
            raise ValueError("raw response reference escapes cache")
        body = target.read_bytes()
        if hashlib.sha256(body).hexdigest() != expected_sha256:
            raise ValueError("raw response hash mismatch")
        return body


@dataclass(frozen=True)
class PublicRetrievalAttempt:
    """Immutable, byte-resolvable evidence for one policy-gated fetch stage."""

    engine: str
    requested_url: str
    final_url: str | None
    status_code: int | None
    body_bytes: int | None
    content_sha256: str | None
    raw_response_ref: str | None
    access_receipt_json: str
    renderer_shell: bool | None
    retrieved_at: str
    redirect_history: tuple[dict[str, Any], ...] = ()
    error_type: str | None = None
    error_message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "body_bytes": self.body_bytes,
            "content_sha256": self.content_sha256,
            "raw_response_ref": self.raw_response_ref,
            "access_receipt": json.loads(self.access_receipt_json),
            "renderer_shell": self.renderer_shell,
            "retrieved_at": self.retrieved_at,
            "redirect_history": [dict(row) for row in self.redirect_history],
            "error_type": self.error_type,
            "error_message": self.error_message,
        }


class PublicRetrievalExhausted(RuntimeError):
    """All ordinary public transports failed, with immutable attempt evidence."""

    def __init__(
        self,
        message: str,
        attempts: Sequence[PublicRetrievalAttempt],
    ) -> None:
        super().__init__(message)
        self.attempts = tuple(attempts)


class ScraplingPublicRetriever:
    """Policy-gated adapter over static and ordinary browser rendering."""

    def __init__(self, cache: RawResponseCache, *, timeout_seconds: int = 45,
                 root: str | Path | None = None, access_policy: Any | None = None,
                 access_controller: Any | None = None) -> None:
        from career_automation.public_access import (
            DenyAllPublicAccess,
            PublicAccessController,
        )
        from scraper.scrapling_client import ScraplingClient

        self.cache, self.timeout_seconds = cache, timeout_seconds
        project_root = Path(root).resolve() if root else Path(__file__).resolve().parents[1]
        self.client = ScraplingClient(project_root, {
            "command_timeout_seconds": timeout_seconds,
        })
        if access_controller is not None and access_policy is not None:
            raise ValueError("supply access_policy or access_controller, not both")
        if access_controller is not None:
            self.access = access_controller
        elif access_policy is not None:
            self.access = PublicAccessController(access_policy, self.client, cache)
        else:
            self.access = DenyAllPublicAccess()
        self._retrieval_attempts: list[PublicRetrievalAttempt] = []

    @property
    def retrieval_attempts(self) -> tuple[PublicRetrievalAttempt, ...]:
        """Return immutable typed evidence for every transport stage attempted."""
        return tuple(self._retrieval_attempts)

    def _remember_attempt(
        self,
        attempt: PublicRetrievalAttempt,
        current: list[PublicRetrievalAttempt],
    ) -> None:
        current.append(attempt)
        self._retrieval_attempts.append(attempt)

    @staticmethod
    def _terminal_challenge(response: Mapping[str, Any]) -> str | None:
        status = int(response.get("status", 0))
        if status in {401, 403, 429}:
            return f"HTTP {status}"
        text = str(response.get("text", "")).casefold()[:100_000]
        markers = (
            r"\bcomplete (?:the )?captcha\b", r"\bcaptcha challenge\b",
            r"\bg-recaptcha\b", r"\bhcaptcha\b", r"\bverify you are human\b",
            r"<title[^>]*>\s*access denied\b", r"\bcloudflare challenge\b",
            r"\bcf-chl-",
        )
        return next((marker for marker in markers if re.search(marker, text)), None)

    @staticmethod
    def _renderer_shell(response: Mapping[str, Any]) -> bool:
        """Recognise an ordinary HTML renderer shell with no useful content."""
        text = str(response.get("text", ""))
        if not re.search(
            r"(?i)<(?:!doctype\s+html|html|body|noscript|div|main)\b",
            text,
        ):
            return False
        renderer_required = bool(
            re.search(
                r"(?is)<noscript\b[^>]*>.*?"
                r"(?:enable|require|support).*?javascript.*?</noscript>",
                text,
            )
            or re.search(
                r"(?i)\b(?:(?:you\s+need\s+to\s+enable|please\s+enable)\s+"
                r"javascript|javascript\s+(?:is\s+)?required)\b",
                text,
            )
            or (
                re.search(
                    r"(?is)<(?:div|main)\b[^>]*\bid=[\"']"
                    r"(?:root|app|application)[\"'][^>]*>\s*</(?:div|main)>",
                    text,
                )
                and re.search(r"(?i)<script\b", text)
            )
        )
        if not renderer_required:
            return False
        without_programs = re.sub(
            r"(?is)<(?:script|style|template)\b[^>]*>.*?</(?:script|style|template)>",
            " ",
            text,
        )
        visible = _plain_excerpt(without_programs).casefold()
        visible = re.sub(
            r"(?i)\b(?:you\s+need\s+to\s+enable|please\s+enable)\s+"
            r"javascript(?:\s+to\s+(?:run|use)\s+(?:this\s+)?(?:app|site|website))?\b"
            r"|\bjavascript\s+(?:is\s+)?required\b",
            " ",
            visible,
        )
        generic = {
            "app", "application", "applications", "browser", "career", "careers",
            "job", "jobs", "loading", "please", "run", "site", "this", "use",
            "website",
        }
        meaningful = [
            token
            for token in re.findall(r"[a-z0-9][a-z0-9+#.-]*", visible)
            if token not in generic
        ]
        return len(meaningful) <= 1

    def _fetch(self, url: str) -> Any:
        from career_automation.public_access import PublicAccessDenied, USER_AGENT
        from scraper.scrapling_client import ScraplingResult

        attempts: list[dict[str, Any]] = []
        evidence_attempts: list[PublicRetrievalAttempt] = []
        requested_host = (urlparse(url).hostname or "").casefold()
        stages = (
            ("static", {"timeout": self.timeout_seconds,
                        "retries": 1,
                        "stealthy_headers": False,
                        "headers": {"User-Agent": USER_AGENT}}),
            ("dynamic", {"network_idle": True,
                         "timeout": max(self.timeout_seconds, 60) * 1000,
                         "retries": 1,
                         "google_search": False,
                         "useragent": USER_AGENT}),
        )
        for engine, kwargs in stages:
            receipt = self.access.before_request(url)
            try:
                response = self.client.fetch(engine, url, **kwargs)
            except Exception as exc:
                attempts.append({"engine": engine, "ok": False,
                                 "error": type(exc).__name__, "message": str(exc),
                                 "access_receipt": asdict(receipt)})
                self._remember_attempt(PublicRetrievalAttempt(
                    engine=engine,
                    requested_url=url,
                    final_url=None,
                    status_code=None,
                    body_bytes=None,
                    content_sha256=None,
                    raw_response_ref=None,
                    access_receipt_json=canonical_json(asdict(receipt)),
                    renderer_shell=None,
                    retrieved_at=datetime.now(timezone.utc).isoformat(),
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                ), evidence_attempts)
                continue
            final_url = str(response.get("url", url))
            status: int | None = None
            raw: bytes | None = None
            digest: str | None = None
            reference: str | None = None
            try:
                raw = base64.b64decode(
                    str(response["body_base64"]),
                    validate=True,
                )
                digest, reference = self.cache.store(raw)
                status = int(response.get("status", 0))
                declared_size = int(response.get("body_bytes", -1))
                if len(raw) != declared_size:
                    raise ValueError("Scrapling response byte count mismatch")
                renderer_shell = self._renderer_shell(response)
            except Exception as exc:
                self._remember_attempt(PublicRetrievalAttempt(
                    engine=engine,
                    requested_url=url,
                    final_url=final_url,
                    status_code=status,
                    body_bytes=len(raw) if raw is not None else None,
                    content_sha256=digest,
                    raw_response_ref=reference,
                    access_receipt_json=canonical_json(asdict(receipt)),
                    renderer_shell=None,
                    retrieved_at=datetime.now(timezone.utc).isoformat(),
                    redirect_history=tuple(
                        {
                            "url": str(item.get("url", "")),
                            "status_code": int(item.get("status", 0)),
                        }
                        for item in response.get("history", ()) or ()
                    ),
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                ), evidence_attempts)
                raise PublicRetrievalExhausted(
                    "public retrieval response evidence is malformed",
                    evidence_attempts,
                ) from exc
            attempts.append({
                "engine": engine,
                "ok": True,
                "response": response,
                "access_receipt": asdict(receipt),
            })
            self._remember_attempt(PublicRetrievalAttempt(
                engine=engine,
                requested_url=url,
                final_url=final_url,
                status_code=status,
                body_bytes=len(raw),
                content_sha256=digest,
                raw_response_ref=reference,
                access_receipt_json=canonical_json(asdict(receipt)),
                renderer_shell=renderer_shell,
                retrieved_at=datetime.now(timezone.utc).isoformat(),
                redirect_history=tuple(
                    {
                        "url": str(item.get("url", "")),
                        "status_code": int(item.get("status", 0)),
                    }
                    for item in response.get("history", ()) or ()
                ),
            ), evidence_attempts)
            assert status is not None
            final_host = (urlparse(final_url).hostname or "").casefold()
            redirect_hosts = {
                (urlparse(str(item.get("url", ""))).hostname or "").casefold()
                for item in response.get("history", ()) or ()
            }
            if final_host != requested_host or redirect_hosts - {requested_host}:
                raise PublicAccessDenied("cross-host redirects are forbidden in JAA public retrieval")
            if challenge := self._terminal_challenge(response):
                raise PublicAccessDenied(f"ACCESS_DENIED: {challenge}")
            if (
                200 <= status < 300
                and len(raw) >= 128
                and not renderer_shell
            ):
                return ScraplingResult(engine, dict(response), tuple(attempts)), receipt
            if status in {404, 410}:
                raise RuntimeError(f"public vacancy is unavailable with HTTP {status}")
        raise PublicRetrievalExhausted(
            "static and dynamic public retrieval were exhausted",
            evidence_attempts,
        )

    def retrieve(self, source_id: str, url: str, *, source_kind: str | None = None,
        canonical_publisher: str | None = None,
                 canonical_article: str | None = None) -> Citation:
        _public_url(url)
        result, access_receipt = self._fetch(url)
        response = result.response
        final_url = str(response.get("url", url))
        _public_url(final_url)
        status = int(response.get("status", 0))
        if not 200 <= status < 300:
            raise RuntimeError(f"public retrieval failed with HTTP {status}")
        raw = base64.b64decode(str(response["body_base64"]), validate=True)
        if len(raw) != int(response.get("body_bytes", -1)):
            raise RuntimeError("Scrapling response byte count mismatch")
        digest, reference = self.cache.store(raw)
        now = datetime.now(timezone.utc).isoformat()
        history = []
        for item in response.get("history", ()) or ():
            history.append({
                "url": _canonical_public_url(str(item["url"])),
                "status_code": int(item.get("status", 0)),
            })
        published_at, updated_at, date_evidence = extract_publisher_timestamps(raw)
        # Retrieval is observation metadata only.  Publisher time is extracted
        # from the captured representation and retains the byte-resolvable
        # metadata fragment which established it.
        final_publisher = (urlparse(final_url).hostname or "").casefold()
        return Citation(source_id, final_url, now, now, digest, reference,
                        status, url, history, published_at, updated_at,
                        source_kind, final_publisher, final_url,
                        date_evidence, f"scrapling-{result.engine}",
                        asdict(access_receipt))


class PortableAuthorityRetriever:
    """Discover authority from the admitted vacancy instead of an URL inventory.

    The vacancy is the only seed.  Candidate routes must be links actually
    published in retrieved bytes (canonical, hiring-organisation, sameAs, or
    ordinary anchors).  This keeps discovery portable across ATS and employer
    hosts and prevents guessed host-specific paths from becoming evidence.
    """

    _LINK = re.compile(
        r"<(?:a|link)\b[^>]*?href\s*=\s*([\"'])(.*?)\1|"
        r"[\"'](?:url|sameAs|applicationUrl)[\"']\s*:\s*([\"'])(.*?)\3",
        re.I | re.S,
    )

    def __init__(self, cache: RawResponseCache, *, retriever: ScraplingPublicRetriever | None = None,
                 maximum_routes: int = 12, exact_canaries: bool = True,
                 ats_adapters: Mapping[str, ATSRouteAdapter] | None = None) -> None:
        self.cache = cache
        self.retriever = retriever or ScraplingPublicRetriever(cache)
        self.maximum_routes = maximum_routes
        self.exact_canaries = exact_canaries
        self.ats_adapters = dict(ats_adapters or DEFAULT_ATS_ROUTE_ADAPTERS)

    def _retrieve(self, source_id: str, url: str, source_kind: str) -> Citation:
        publisher = (urlparse(url).hostname or "").casefold()
        try:
            item = self.retriever.retrieve(source_id, url, source_kind=source_kind,
                                           canonical_publisher=publisher,
                                           canonical_article=url)
        except TypeError as exc:
            if "unexpected keyword" not in str(exc):
                raise
            item = self.retriever.retrieve(source_id, url)
            item = replace(item, source_kind=source_kind,
                           canonical_publisher=(urlparse(item.url).hostname or "").casefold(),
                           canonical_article=item.url,
                           retrieval_engine=item.retrieval_engine or "deterministic-retriever")
        return item

    @staticmethod
    def _canary_for(task: Any) -> ATSAuthorityCanary | None:
        record = _ATS_CANARY_BY_KEY.get(str(task.job_key))
        seed_host = (urlparse(str(task.url)).hostname or "").casefold()
        if record is None:
            if seed_host in _TYPED_ATS_HOSTS:
                raise ValueError("ATS vacancy is outside the exact admitted authority canaries")
            return None
        if (str(task.company) != record.company or str(task.title) != record.title
                or str(task.url) != record.admitted_url):
            raise ValueError("ATS vacancy identity differs from its exact admitted record")
        return record

    @staticmethod
    def _validate_canary_capture(record: ATSAuthorityCanary, citation: Citation,
                                 artifact: bytes | RawResponseCache,
                                 *, require_temporal: bool = True) -> None:
        body = (artifact.resolve(citation.raw_response_ref, citation.content_sha256)
                if isinstance(artifact, RawResponseCache) else artifact)
        if hashlib.sha256(body).hexdigest() != citation.content_sha256:
            raise ValueError("ATS authority bytes differ from the cited SHA-256 artifact")
        requested = citation.requested_url
        if not requested:
            raise ValueError("ATS authority capture lacks its requested route")
        allowed_paths = set(record.final_paths)
        route_urls = [requested, *(str(row.get("url", ""))
                                   for row in citation.redirect_history), citation.url]
        for route_url in route_urls:
            _canonical_public_url(route_url)
            route = urlparse(route_url)
            if ((route.hostname or "").casefold() not in record.authority_hosts
                    or route.path not in allowed_paths):
                raise ValueError("ATS route differs from the admitted tenant or vacancy")
        parsed = urlparse(citation.url)
        if ((parsed.hostname or "").casefold() not in record.authority_hosts
                or parsed.path not in record.final_paths):
            raise ValueError("redirect escaped the admitted ATS authority chain")
        path = parsed.path.casefold()
        if (path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"))
                or "/apply" in path or "/application" in path):
            raise ValueError("assets and application forms are not ATS vacancy authority")
        text = _plain_excerpt(body.decode("utf-8", "strict")).casefold()
        if record.company.casefold() not in text or record.title.casefold() not in text:
            raise ValueError("ATS authority bytes do not identify the admitted employer and vacancy")
        if require_temporal:
            published, updated, evidence = extract_publisher_timestamps(body)
            if (published is None and updated is None) or evidence is None:
                raise ValueError("ATS authority bytes lack an unambiguous publisher date")
            cited_published = (_iso_publisher_time(citation.published_at)
                               if citation.published_at else None)
            cited_updated = (_iso_publisher_time(citation.updated_at)
                             if citation.updated_at else None)
            if ((citation.published_at is not None and cited_published is None)
                    or (citation.updated_at is not None and cited_updated is None)):
                raise ValueError("ATS publisher date is not verifiable")
            cited_evidence = citation.publisher_date_evidence
            if (cited_published != published or cited_updated != updated
                    or cited_evidence != evidence):
                raise ValueError("ATS publisher dates differ from the cited response bytes")

    @staticmethod
    def _published_routes(base: str, body: bytes) -> list[str]:
        text = body.decode("utf-8", "strict")
        routes: list[str] = []
        for match in PortableAuthorityRetriever._LINK.finditer(text):
            value = unescape(match.group(2) or match.group(4) or "").strip()
            try:
                route = urljoin(base, value)
                _canonical_public_url(route)
            except ValueError:
                continue
            if route not in routes:
                routes.append(route)
        return routes

    @staticmethod
    def _classify(url: str, vacancy_url: str, body: bytes) -> set[IntelligenceKind]:
        plain = _plain_excerpt(body.decode("utf-8", "strict"))
        kinds = {kind for kind in IntelligenceKind
                 if any(re.search(pattern, plain.casefold()) for group in _SEMANTIC_PATTERNS[kind]
                        for pattern in group)}
        if url == vacancy_url:
            kinds.update({IntelligenceKind.ROLE, IntelligenceKind.HIRING})
        return kinds

    @staticmethod
    def _employer_bound(company: str, body: bytes) -> bool:
        text = _plain_excerpt(body.decode("utf-8", "strict")).casefold()
        tokens = [token for token in re.findall(r"[a-z0-9]+", company.casefold())
                  if len(token) > 2 and token not in {"limited", "ltd", "plc", "group", "company"}]
        return bool(tokens) and any(token in text for token in tokens)

    @staticmethod
    def _vacancy_bound(task: Any, citation: Citation, body: bytes) -> bool:
        if citation.status_code < 200 or citation.status_code >= 300 or not body:
            return False
        text = _plain_excerpt(body.decode("utf-8", "strict")).casefold()
        if re.search(r"\b(?:job|vacancy|position) (?:is )?(?:closed|expired|removed|no longer available)\b", text):
            return False
        title = str(getattr(task, "title", "")).strip()
        title_tokens = [token for token in re.findall(r"[a-z0-9]+", title.casefold())
                        if len(token) > 3 and token not in {"with", "from", "the", "and"}]
        return (PortableAuthorityRetriever._employer_bound(str(task.company), body)
                and (not title or (bool(title_tokens)
                     and sum(token in text for token in title_tokens) >= min(2, len(title_tokens)))))

    @staticmethod
    def _aggregator_vacancy_bound(task: Any, citation: Citation, body: bytes) -> bool:
        """Validate one official candidate against its captured representation."""
        if not PortableAuthorityRetriever._vacancy_bound(task, citation, body):
            return False
        try:
            final = urlparse(_canonical_public_url(citation.url))
            requested = urlparse(_canonical_public_url(citation.requested_url or citation.url))
        except ValueError:
            return False
        if ((final.hostname or "").casefold() in AGGREGATOR_HOSTS
                or (requested.hostname or "").casefold() in AGGREGATOR_HOSTS
                or not final.path or final.path == "/"):
            return False
        published, updated, evidence = extract_publisher_timestamps(body)
        return bool(
            evidence
            and (published is not None or updated is not None)
            and citation.publisher_date_evidence == evidence
            and citation.published_at == published
            and citation.updated_at == updated
        )

    @staticmethod
    def _source_types(item: Citation, vacancy: Citation, body: bytes) -> tuple[str, ...]:
        if item.id == vacancy.id:
            return ("official_vacancy",)
        path = (urlparse(item.url).path or "/").casefold()
        text = _plain_excerpt(body.decode("utf-8", "strict")).casefold()
        types = ["official_company"]
        if re.search(r"/(?:career|careers|job|jobs|vacanc)", path) or re.search(r"\b(?:careers?|vacanc(?:y|ies)|apply)\b", text):
            types.append("official_careers")
        if re.search(r"/(?:product|products|service|services|platform|docs?)", path) or re.search(r"\b(?:product|service|platform|documentation)\b", text):
            types.extend(("official_product", "official_product_documentation"))
        if re.search(r"/(?:investor|financial|results?|reports?|filings?)", path) or any(
                re.search(pattern, text) for pattern in _OPERATIONAL_SUBSTANCE):
            types.append("official_financial")
        return tuple(dict.fromkeys(types))

    def retrieve_plan(self, task: Any) -> tuple[list[Citation], list[dict[str, Any]]]:
        canary = self._canary_for(task) if self.exact_canaries else _ATS_CANARY_BY_KEY.get(str(task.job_key))
        if canary is not None:
            seed = self._retrieve(f"source:{task.job_key}:admitted", task.url, "official_vacancy")
            self._validate_canary_capture(canary, seed, self.cache,
                                          require_temporal=canary.authority_url == task.url)
            if canary.authority_url == task.url:
                citations = [seed]
            else:
                authority = self._retrieve(f"source:{task.job_key}:typed-authority",
                                           canary.authority_url, "official_vacancy")
                self._validate_canary_capture(canary, authority, self.cache)
                citations = [authority]
            return self._plan_from_citations(task, citations, citations[0])

        family = str(task.job_key).split(":", 1)[0].casefold()
        adapter = self.ats_adapters.get(family)
        if adapter is not None:
            authority_url = adapter.authority_url(task)
            authority = self._retrieve(f"source:{task.job_key}:typed-authority",
                                       authority_url, "official_vacancy")
            adapter.validate_capture(task, authority, self.cache)
            return self._plan_from_citations(task, [authority], authority)

        admitted_host = (urlparse(str(task.url)).hostname or "").casefold()
        discovery_only = admitted_host in AGGREGATOR_HOSTS
        vacancy = self._retrieve(f"source:{task.job_key}:vacancy", task.url,
                                 "discovery_input" if discovery_only else "official_vacancy")
        citations = [] if discovery_only else [vacancy]
        vacancy_body = self.cache.resolve(vacancy.raw_response_ref, vacancy.content_sha256)
        if not discovery_only and not self._vacancy_bound(task, vacancy, vacancy_body):
            raise ValueError("direct vacancy response is stale, mismatched, empty, or ambiguous")
        routes = self._published_routes(vacancy.url, vacancy_body)
        seen = {vacancy.capture_identity, vacancy.content_sha256}
        official_candidates: list[Citation] = []
        official_route_identities: set[tuple[str, str]] = set()
        unresolved_official_routes: set[tuple[str, str]] = set()
        for index, route in enumerate(routes[:self.maximum_routes]):
            if route == vacancy.url:
                continue
            route_host = (urlparse(route).hostname or "").casefold()
            if route_host in AGGREGATOR_HOSTS:
                continue
            route_path = (urlparse(route).path or "/").casefold()
            route_kind = ("official_vacancy" if (route_host in _OFFICIAL_ATS_HOSTS or
                          re.search(r"/(?:job|jobs|vacanc|position|posting)", route_path))
                          else "official_company")
            route_identity = (route_host, route_path)
            try:
                item = self._retrieve(f"source:{task.job_key}:discovered:{index}", route, route_kind)
            except (RuntimeError, ValueError, UnicodeError):
                if discovery_only and route_kind == "official_vacancy":
                    unresolved_official_routes.add(route_identity)
                continue
            body = self.cache.resolve(item.raw_response_ref, item.content_sha256)
            if discovery_only and route_kind == "official_vacancy":
                # Candidate accounting precedes evidence de-duplication. Two
                # published official routes are ambiguous even when redirects
                # or response bytes alias, and the whole bounded route set must
                # be evaluated before a decision is made.
                if self._aggregator_vacancy_bound(task, item, body):
                    official_candidates.append(item)
                    official_route_identities.add(route_identity)
                elif self._vacancy_bound(task, item, body):
                    # Employer/title/response bytes make this a competing
                    # vacancy, but its route or publisher time cannot be
                    # conclusively validated. It cannot be silently discarded.
                    unresolved_official_routes.add(route_identity)
            if item.capture_identity in seen or item.content_sha256 in seen:
                continue
            seen.update((item.capture_identity, item.content_sha256))
            if not self._employer_bound(str(task.company), body):
                continue
            if item.source_kind == "official_vacancy" and not self._vacancy_bound(task, item, body):
                continue
            citations.append(item)
        if discovery_only:
            if (unresolved_official_routes or len(official_candidates) != 1
                    or len(official_route_identities) != 1):
                raise ValueError(
                    "aggregator discovery requires exactly one validated official vacancy route"
                )
            vacancy = official_candidates[0]
            # Only the uniquely admitted official response may enter evidence.
            citations = [item for item in citations if item.source_kind != "official_vacancy"]
            citations.insert(0, vacancy)
        return self._plan_from_citations(task, citations, vacancy)

    def _plan_from_citations(self, task: Any, citations: list[Citation],
                             vacancy: Citation) -> tuple[list[Citation], list[dict[str, Any]]]:
        supported: dict[IntelligenceKind, tuple[Citation, str, str, int]] = {}
        admitted_ranges: dict[str, set[tuple[int, int]]] = {}
        for item in citations:
            body = self.cache.resolve(item.raw_response_ref, item.content_sha256)
            if item.id != vacancy.id and not self._employer_bound(str(task.company), body):
                # A published link is only a discovery route. Its bytes must
                # still bind it to the admitted employer before admission.
                continue
            try:
                excerpts = _public_page_excerpts(body)
            except (ValueError, UnicodeError):
                excerpts = []
            for excerpt, _ in excerpts:
                start = body.find(excerpt.encode("utf-8"))
                for kind in self._classify(item.url, vacancy.url, excerpt.encode("utf-8")):
                    for source_type in self._source_types(item, vacancy, body):
                        byte_range = (start, start + len(excerpt.encode()))
                        if (kind not in supported and byte_range not in admitted_ranges.setdefault(item.id, set())
                                and _kind_relevant(kind, excerpt, {
                            "source_type": source_type, "permitted_purposes": [kind.value],
                        }) and not (kind in {IntelligenceKind.ROLE, IntelligenceKind.HIRING,
                                            IntelligenceKind.OPERATIONAL_HEALTH}
                                   and not (item.updated_at or item.published_at))):
                            supported[kind] = (item, excerpt, source_type, start)
                            admitted_ranges[item.id].add(byte_range)
                            break
        plan = []
        for kind in IntelligenceKind:
            base = {"id": f"plan:{kind.value}", "kind": kind.value,
                    "permitted_purposes": [kind.value], "freshness_days": FRESHNESS_DAYS[kind]}
            if kind not in supported:
                plan.append({**base, "outcome": "unknown", "reason": "no purpose-specific official authority excerpt discovered"})
                continue
            item, excerpt, source_type, start = supported[kind]
            plan.append({**base, "outcome": "supported", "source_id": item.id,
                         "source_type": source_type,
                         "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
                         "excerpt_byte_start": start, "excerpt_byte_length": len(excerpt.encode())})
        return citations, plan


def _default_source_type(kind: IntelligenceKind) -> str:
    return {
        IntelligenceKind.COMPANY: "official_company",
        IntelligenceKind.PRODUCT: "official_product_documentation",
        IntelligenceKind.OPERATIONAL_HEALTH: "official_financial",
        IntelligenceKind.ROLE: "official_vacancy",
        IntelligenceKind.HIRING: "official_careers",
    }[kind]


class SidecarAuthorityRetriever:
    """Reviewed authority plans executed through the production Scrapling sidecar.

    Plan fields may classify and locate evidence, but response-derived metadata
    and claim excerpts always come from immutable bytes returned by the worker.
    """

    def __init__(self, records: Sequence[Mapping[str, Any]], cache: RawResponseCache,
                 *, root: str | Path, access_policy: Any | None = None) -> None:
        self.cache = cache
        self.records = {str(record["job_key"]): dict(record) for record in records}
        self.transport = ScraplingPublicRetriever(
            cache,
            root=root,
            access_policy=access_policy,
        )
        if not self.transport.client.available:
            raise RuntimeError("configured production Scrapling runtime is unavailable")

    def retrieve_plan(self, task: Any) -> tuple[list[Citation], list[dict[str, Any]]]:
        import base64
        record = self.records.get(str(task.job_key))
        if record is None:
            raise ValueError("claimed vacancy is outside the reviewed authority cohort")
        if (record.get("vacancy_url") != task.url or record.get("company") != task.company
                or record.get("role") != task.title):
            raise ValueError("claimed vacancy identity differs from the frozen authority record")
        citations: list[Citation] = []
        plan: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        seen_hashes: set[str] = set()
        seen_articles: set[str] = set()
        for specification in record["sources"]:
            kind = IntelligenceKind(str(specification.get("kind")))
            source_type = str(specification.get("source_type", ""))
            production_types = {
                IntelligenceKind.COMPANY: {"authoritative_company_record", "official_company"},
                IntelligenceKind.PRODUCT: {"official_product_documentation"},
                IntelligenceKind.OPERATIONAL_HEALTH: {
                    "regulatory_filing", "regulatory_status_record", "independent_reporting",
                },
                IntelligenceKind.ROLE: {"official_vacancy"},
                IntelligenceKind.HIRING: {"official_careers"},
            }
            if source_type not in production_types[kind]:
                raise ValueError("authority source type cannot support its assigned purpose")
            requested_url = str(specification.get("url", ""))
            _public_url(requested_url)
            if kind is IntelligenceKind.ROLE and requested_url != task.url:
                raise ValueError("role authority is not the admitted vacancy URL")
            publisher = str(specification.get("canonical_publisher", "")).casefold().strip()
            article = str(specification.get("canonical_article", "")).strip()
            requested_host = (urlparse(requested_url).hostname or "").casefold()
            if (not publisher or (publisher != requested_host and not requested_host.endswith("." + publisher))
                    or not article or article.casefold() in seen_articles):
                raise ValueError("source is not an independent publisher-owned authority")
            result, access_receipt = self.transport._fetch(requested_url)
            response = result.response
            status = int(response.get("status", 0))
            if not 200 <= status < 300:
                raise RuntimeError(f"authority retrieval failed with HTTP {status}")
            body = base64.b64decode(response["body_base64"], validate=True)
            if len(body) != int(response.get("body_bytes", -1)):
                raise RuntimeError("authority response byte count is inconsistent")
            digest, reference = self.cache.store(body)
            final_url = str(response.get("url", ""))
            _public_url(final_url)
            final_host = (urlparse(final_url).hostname or "").casefold()
            if publisher != final_host and not final_host.endswith("." + publisher):
                raise ValueError("redirect escaped the reviewed authoritative publisher")
            if article != final_url:
                raise ValueError("reviewed canonical article differs from the retrieved final URL")
            if final_url in seen_urls or digest in seen_hashes:
                raise ValueError("duplicate authority capture cannot support another purpose")
            seen_urls.add(final_url)
            seen_hashes.add(digest)
            seen_articles.add(article.casefold())
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body.decode("utf-8", "strict"))).casefold()
            company_terms = [part for part in re.findall(r"[a-z0-9]+", str(task.company).casefold()) if len(part) > 2]
            if company_terms and not any(term in text for term in company_terms):
                raise ValueError("captured authority does not identify the admitted employer")
            published_at, updated_at, date_evidence = extract_publisher_timestamps(body)
            history = [{"url": str(item["url"]), "status_code": int(item["status"])}
                       for item in response.get("history", [])]
            now = datetime.now(timezone.utc).isoformat()
            source_id = f"source:{task.job_key}:{kind.value}"
            citation = Citation(
                source_id, final_url, now, now, digest, reference, status,
                requested_url, history, published_at, updated_at, source_type,
                publisher, article, date_evidence, result.engine,
                asdict(access_receipt),
            )
            if specification.get("requires_current") is True and not (published_at or updated_at):
                raise ValueError("freshness-sensitive authority has no verified publisher date")
            citations.append(citation)
            terms = specification.get("relevance_terms")
            if not isinstance(terms, list) or not terms:
                raise ValueError("authority purpose requires reviewed semantic terms")
            plan.append({
                "id": f"plan:{kind.value}", "kind": kind.value, "source_id": source_id,
                "source_type": source_type, "permitted_purposes": [kind.value],
                "freshness_days": FRESHNESS_DAYS[kind], "relevance_terms": terms,
                "requires_current": specification.get("requires_current") is True,
                **({"excerpt_sha256": specification["excerpt_sha256"]}
                   if specification.get("excerpt_sha256") else {}),
            })
        return citations, plan


_DATE_FIELDS = {
    "datepublished": "published", "datecreated": "published",
    "dateposted": "published",
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
            parsed = None
        if parsed is None:
            for pattern in ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(value, pattern)
                    break
                except ValueError:
                    continue
        if parsed is None:
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
        r'([\"\'])(datePublished|dateCreated|datePosted|publishedAt|updated_at|dateModified|dateUpdated)\1\s*:\s*([\"\'])(.*?)\3',
        re.I | re.S,
    )
    for match in json_pattern.finditer(text):
        key = match.group(2).casefold()
        field = "updated" if "modified" in key or "updated" in key else "published"
        if stamp := _iso_publisher_time(match.group(4)):
            candidates.append((field, stamp, match.group(0)))
    for match in re.finditer(
            r"(?im)^(?:\*\*)?Posted(?:\*\*)?\s*:?\s*(?:\*\*)?([^\r\n*]+)(?:\*\*)?\s*$", text):
        if stamp := _iso_publisher_time(match.group(1)):
            candidates.append(("published", stamp, match.group(0)))
    for match in re.finditer(r"(?i)\bPosted\s+((?:19|20)\d{2}-\d{2}-\d{2})\b", text):
        if stamp := _iso_publisher_time(match.group(1)):
            candidates.append(("published", stamp, match.group(0)))
    # Multiple equivalent metadata declarations are acceptable. Conflicting
    # publisher values are ambiguous and therefore deliberately remain unknown.
    published_values = {value for field, value, _ in candidates if field == "published"}
    updated_values = {value for field, value, _ in candidates if field == "updated"}
    if len(published_values) > 1 or len(updated_values) > 1:
        return None, None, None
    published = next(iter(published_values)) if len(published_values) == 1 else None
    updated = next(iter(updated_values)) if len(updated_values) == 1 else None
    chosen_field = "updated" if updated else ("published" if published else None)
    evidence = next((raw for field, value, raw in candidates
                     if field == chosen_field and value == (updated or published)), None)
    return published, updated, evidence


def validate_dossier(
    dossier: Mapping[str, Any],
    cache: RawResponseCache,
    *,
    as_of: date | None = None,
    access_policies: Mapping[str, PublicAccessPolicy] | None = None,
) -> None:
    """Validate all provenance, typing, freshness and privacy rules or fail closed."""
    schema_version = dossier.get("schema_version")
    if schema_version in {"jaa04.dossier.v3", "jaa04.dossier.v4"}:
        _validate_portable_dossier(
            dossier,
            cache,
            as_of=as_of,
            access_policies=access_policies,
            require_access=schema_version == "jaa04.dossier.v4",
        )
        return
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
            article = str(citation.canonical_article or "").strip()
            if not citation.source_kind or not publisher or not article:
                raise ValueError("source lacks classified kind or canonical publisher/article identity")
            if publisher != host and not host.endswith("." + publisher):
                raise ValueError("canonical publisher does not own the captured URL")
            _canonical_public_url(article)
            if article != _canonical_public_url(citation.url):
                raise ValueError("canonical article identity differs from the captured final URL")
            if article.casefold() in articles:
                raise ValueError("translations, mirrors, or aliases resolve to one canonical article")
            articles.add(article.casefold())
            plain = re.sub(br"<[^>]+>", b" ", body)
            normalized = re.sub(br"\s+", b" ", plain).strip().decode("utf-8", "strict").casefold().encode()
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
            if not citation.retrieval_engine:
                raise ValueError("authority capture lacks its production retrieval engine")
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
        if authority_contract:
            prefix, separator, assertion = str(claim["text"]).partition(":")
            if (not prefix.strip() or not separator
                    or assertion.strip() != _plain_excerpt(excerpt)):
                raise ValueError("authority claim must exactly reflect its cited excerpt")
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
        if authority_contract and temporal is not None and not source.get("publisher_date_evidence"):
            raise ValueError(f"{kind.value} claim lacks byte-resolvable publisher date")
        if temporal is None:
            if (entry.get("requires_current") is True
                    or kind in {IntelligenceKind.ROLE, IntelligenceKind.HIRING,
                                IntelligenceKind.OPERATIONAL_HEALTH}):
                raise ValueError(f"freshness-sensitive {kind.value} claim lacks publisher time evidence")
            observed_value = claim.get("observed_at")
        else:
            observed_value = temporal
            if claim.get("observed_at") != temporal:
                raise ValueError("claim observation time must be publisher-provided time")
        freshness = claim.get("freshness_classification")
        if freshness not in {"current", "historical", "unknown"}:
            raise ValueError("unknown freshness classification")
        if freshness == "unknown":
            if temporal is not None or observed_value is not None:
                raise ValueError("unknown freshness may only represent absent publisher time")
            continue
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


def _validate_portable_dossier(
    dossier: Mapping[str, Any],
    cache: RawResponseCache,
    *,
    as_of: date | None = None,
    access_policies: Mapping[str, PublicAccessPolicy] | None = None,
    require_access: bool = False,
) -> None:
    """Validate the portable contract: five outcomes may share real captures."""
    sources = dossier.get("sources")
    claims = dossier.get("claims")
    plan = dossier.get("source_plan")
    if not isinstance(sources, list) or not sources or not isinstance(claims, list) or not isinstance(plan, list):
        raise ValueError("portable dossier requires sources, claims and outcomes")
    by_id: dict[str, tuple[Mapping[str, Any], bytes]] = {}
    identities: set[tuple[str, str]] = set()
    hashes: set[str] = set()
    source_ids: set[str] = set()
    access_by_host: dict[str, tuple[str, str, str]] = {}
    for row in sources:
        citation = Citation(**row)
        if not citation.id or citation.id in source_ids or not 200 <= citation.status_code < 300:
            raise ValueError("invalid or duplicate capture identity")
        source_ids.add(citation.id)
        _canonical_public_url(citation.url)
        if citation.requested_url is not None:
            _canonical_public_url(citation.requested_url)
        if not isinstance(citation.redirect_history, list):
            raise ValueError("capture redirect provenance is invalid")
        for redirect in citation.redirect_history:
            _canonical_public_url(str(redirect["url"]))
            if not 300 <= int(redirect["status_code"]) < 400:
                raise ValueError("capture redirect provenance is invalid")
        body = cache.resolve(citation.raw_response_ref, citation.content_sha256)
        identity = citation.capture_identity
        if identity in identities or citation.content_sha256 in hashes:
            raise ValueError("duplicate content must be represented by its original capture")
        identities.add(identity)
        hashes.add(citation.content_sha256)
        datetime.fromisoformat(citation.captured_at.replace("Z", "+00:00"))
        datetime.fromisoformat(citation.retrieved_at.replace("Z", "+00:00"))
        if not citation.source_kind or not citation.retrieval_engine:
            raise ValueError("capture lacks authority classification or retrieval metadata")
        if require_access:
            if citation.retrieval_engine not in {"scrapling-static", "scrapling-dynamic"}:
                raise ValueError("certified capture used a forbidden retrieval engine")
            content_urls = tuple(dict.fromkeys((
                citation.requested_url or citation.url,
                *(str(item["url"]) for item in citation.redirect_history),
                citation.url,
            )))
            receipt = replay_access_receipt(
                citation.access_receipt,
                cache,
                content_urls=content_urls,
                content_retrieved_at=citation.retrieved_at,
                policies=access_policies,
            )
            access_identity = (
                receipt.content_sha256,
                receipt.raw_response_ref,
                receipt.retrieved_at,
            )
            prior = access_by_host.setdefault(receipt.host, access_identity)
            if prior != access_identity:
                raise ValueError("one host has inconsistent robots capture identities")
        host = (urlparse(citation.url).hostname or "").casefold()
        publisher = str(citation.canonical_publisher or "").casefold().strip()
        article = str(citation.canonical_article or "").strip()
        if (not publisher or (publisher != host and not host.endswith("." + publisher))
                or not article or _canonical_public_url(article) != citation.url):
            raise ValueError("capture lacks publisher-owned canonical provenance")
        extracted = extract_publisher_timestamps(body)
        if citation.publisher_date_evidence is not None:
            if citation.publisher_date_evidence.encode() not in body or (
                    citation.published_at, citation.updated_at) != extracted[:2]:
                raise ValueError("publisher time is not byte-resolvable")
        elif citation.published_at is not None or citation.updated_at is not None:
            raise ValueError("publisher time lacks byte-resolvable provenance")
        by_id[citation.id] = (row, body)
    outcomes = {str(row.get("kind")): row for row in plan if isinstance(row, Mapping)}
    required = {kind.value for kind in IntelligenceKind}
    if set(outcomes) != required or len(plan) != len(required):
        raise ValueError("exactly five purpose-specific outcomes are required")
    claims_by_kind = {str(row.get("kind")): row for row in claims if isinstance(row, Mapping)}
    if set(claims_by_kind) != required or len(claims) != len(required):
        raise ValueError("claims must record every intelligence outcome")
    used_ranges: dict[str, set[tuple[int, int]]] = {}
    as_of = as_of or datetime.now(timezone.utc).date()
    for kind_value in required:
        kind = IntelligenceKind(kind_value)
        outcome, claim = outcomes[kind_value], claims_by_kind[kind_value]
        state = outcome.get("outcome")
        if state not in {"supported", "unknown", "abstained"} or claim.get("outcome") != state:
            raise ValueError("invalid or inconsistent intelligence outcome")
        if (outcome.get("permitted_purposes") != [kind.value]
                or outcome.get("freshness_days") != FRESHNESS_DAYS[kind]):
            raise ValueError("outcome purpose or temporal policy is invalid")
        if PROTECTED_FIELDS.intersection(claim.keys()) or claim.get("subject_type") == "private_person":
            raise ValueError("protected or private-person information is forbidden")
        if state != "supported":
            if (claim.get("classification") is not None or claim.get("source_ids") not in ([], None)
                    or claim.get("citation_excerpt") is not None or claim.get("score_delta_bp", 0) != 0):
                raise ValueError("unsupported intelligence cannot become a claim or score contribution")
            reason = str(outcome.get("reason", "")).strip()
            if len(reason) < 20 or len(re.findall(r"[A-Za-z0-9]+", reason)) < 4:
                raise ValueError("unknown or abstained outcome requires a reason")
            if claim.get("text") != outcome.get("reason"):
                raise ValueError("unsupported outcome reason must be recorded exactly")
            continue
        ClaimClassification(claim.get("classification"))
        source_id = str(outcome.get("source_id", ""))
        if source_id not in by_id or claim.get("source_ids") != [source_id]:
            raise ValueError("supported claim has unresolved source identity")
        excerpt = claim.get("citation_excerpt")
        if not isinstance(excerpt, str) or not excerpt:
            raise ValueError("supported claim requires an exact excerpt")
        text = str(claim.get("text", ""))
        prefix, separator, assertion = text.partition(":")
        if not prefix.strip() or not separator or assertion.strip() != _plain_excerpt(excerpt):
            raise ValueError("supported assertion must exactly reflect its cited excerpt")
        excerpt_bytes = excerpt.encode("utf-8")
        start, length = outcome.get("excerpt_byte_start"), outcome.get("excerpt_byte_length")
        if (type(start) is not int or type(length) is not int or start < 0
                or length <= 0 or length != len(excerpt_bytes)):
            raise ValueError("supported claim requires exact excerpt boundaries")
        source, body = by_id[source_id]
        if body[start:start + length] != excerpt_bytes:
            raise ValueError("excerpt boundaries do not resolve to captured content")
        if outcome.get("excerpt_sha256") != hashlib.sha256(excerpt_bytes).hexdigest():
            raise ValueError("excerpt hash mismatch")
        if outcome.get("source_content_sha256", source["content_sha256"]) != source["content_sha256"]:
            raise ValueError("outcome is not bound to captured content")
        purpose = outcome.get("permitted_purposes")
        if purpose != [kind.value] or outcome.get("source_type") not in SOURCE_KIND_POLICY[kind]["source_types"]:
            raise ValueError("outcome authority is not permitted for its purpose")
        byte_range = (start, start + length)
        ranges = used_ranges.setdefault(source_id, set())
        if any(start < previous_end and previous_start < start + length
               for previous_start, previous_end in ranges):
            raise ValueError("one capture may support multiple kinds only through disjoint excerpts")
        ranges.add(byte_range)
        if not _kind_relevant(kind, excerpt, {"source_type": outcome.get("source_type"),
                                              "permitted_purposes": purpose}):
            raise ValueError(f"kind-irrelevant {kind.value} evidence")
        temporal = source.get("updated_at") or source.get("published_at")
        semantics = claim.get("temporal_semantics")
        if temporal is not None:
            if semantics != "publisher_time" or claim.get("observed_at") != temporal:
                raise ValueError("supported outcome has invalid publisher-time semantics")
            observed = datetime.fromisoformat(str(temporal).replace("Z", "+00:00")).date()
            if observed > as_of or as_of - observed > timedelta(days=FRESHNESS_DAYS[kind]):
                raise ValueError("supported outcome is not temporally applicable")
        elif kind in {IntelligenceKind.ROLE, IntelligenceKind.HIRING,
                      IntelligenceKind.OPERATIONAL_HEALTH} or semantics != "retrieval_snapshot":
            raise ValueError("freshness-sensitive outcome lacks publisher time")


def _public_page_excerpts(body: bytes, count: int | None = None) -> list[tuple[str, str]]:
    """Return distinct byte-exact paragraphs and their conservative plain text."""
    excerpts: list[tuple[str, str]] = []
    seen: set[str] = set()

    def admit(raw: bytes) -> bool:
        excerpt = raw.decode("utf-8", "strict")
        summary = _plain_excerpt(excerpt)
        if len(summary.encode("utf-8")) < 80:
            return False
        # JSON escaping can make phonetic/transclusion markup resemble a local
        # absolute path. Such markup is irrelevant to commercial research and
        # must not enter the distributable dossier.
        if re.search(r"(?<![\w/])[A-Za-z]:[\\/]", json.dumps(excerpt), re.I):
            return False
        normalized = summary.casefold()
        if normalized in seen:
            return False
        seen.add(normalized)
        excerpts.append((excerpt, summary))
        if count is not None and len(excerpts) == count:
            return True
        return False

    paragraph_patterns = (
        br"<p(?:\s[^>]*)?>.*?</p\s*>",
        br"&lt;p(?:\s[^&]*?)?&gt;.*?&lt;/p\s*&gt;",
        br"\\u0026lt;p.*?\\u0026gt;.*?\\u0026lt;/p\\u0026gt;",
    )
    for pattern in paragraph_patterns:
        for match in re.finditer(pattern, body, re.I | re.S):
            if admit(match.group(0)):
                return excerpts

    # Official ATS representations such as Workable publish Markdown rather
    # than HTML. Preserve each exact UTF-8 block as the cited byte range. Do
    # not treat arbitrary JSON as Markdown; structured JSON must contribute an
    # actual HTML or entity-encoded paragraph above.
    stripped = body.lstrip()
    if not excerpts and not stripped.startswith((b"{", b"[")):
        for block in re.split(br"(?:\r?\n)[ \t]*(?:\r?\n)+", body):
            raw = block.strip()
            if raw and admit(raw):
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
    if source_plan is not None and any("outcome" in entry for entry in source_plan):
        return _build_portable_dossier(task, citations, cache, source_plan)
    if source_plan is None and len(citations) != len(IntelligenceKind):
        plan: list[dict[str, Any]] = []
        for kind in IntelligenceKind:
            selected = None
            for item in citations:
                body = cache.resolve(item.raw_response_ref, item.content_sha256)
                try:
                    excerpts = _public_page_excerpts(body)
                except (ValueError, UnicodeError):
                    excerpts = []
                source_type = item.source_kind or _default_source_type(kind)
                for excerpt, _ in excerpts:
                    if _kind_relevant(kind, excerpt, {"source_type": source_type,
                                                       "permitted_purposes": [kind.value]}):
                        raw = excerpt.encode()
                        selected = {"id": f"plan:{kind.value}", "kind": kind.value,
                                    "outcome": "supported", "source_id": item.id,
                                    "source_type": source_type,
                                    "permitted_purposes": [kind.value],
                                    "freshness_days": FRESHNESS_DAYS[kind],
                                    "excerpt_sha256": hashlib.sha256(raw).hexdigest(),
                                    "excerpt_byte_start": body.find(raw),
                                    "excerpt_byte_length": len(raw)}
                        break
                if selected:
                    break
            plan.append(selected or {"id": f"plan:{kind.value}", "kind": kind.value,
                                      "outcome": "unknown", "permitted_purposes": [kind.value],
                                      "freshness_days": FRESHNESS_DAYS[kind],
                                      "reason": "no purpose-specific official authority excerpt discovered"})
        return _build_portable_dossier(task, citations, cache, plan)
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
    for claim_id, kind, classification, _label, _ in specifications:
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
                 "text": f"{company}: {summary}",
                 "citation_excerpt": excerpt, "source_plan_id": entry["id"]}
        claim_observed = cited_source.updated_at or cited_source.published_at
        if claim_observed is None and kind in {IntelligenceKind.ROLE, IntelligenceKind.HIRING,
                                               IntelligenceKind.OPERATIONAL_HEALTH}:
            raise ValueError(f"{kind.value} evidence requires a publisher date")
        if claim_observed is None:
            freshness = "unknown"
        else:
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


def _build_portable_dossier(task: Any, citations: Sequence[Citation], cache: RawResponseCache,
                            source_plan: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    plan = [dict(row) for row in source_plan]
    claims: list[dict[str, Any]] = []
    for entry in plan:
        kind = IntelligenceKind(entry["kind"])
        state = str(entry.get("outcome"))
        claim: dict[str, Any] = {"id": f"outcome:{kind.value}", "kind": kind.value,
                                 "outcome": state, "score_delta_bp": 0}
        if state in {"unknown", "abstained"}:
            claim.update({"classification": None, "text": str(entry["reason"]),
                          "source_ids": [], "citation_excerpt": None})
            claims.append(claim)
            continue
        source = next((item for item in citations if item.id == entry.get("source_id")), None)
        if source is None:
            raise ValueError("supported outcome refers to an uncaptured source")
        body = cache.resolve(source.raw_response_ref, source.content_sha256)
        start, length = int(entry["excerpt_byte_start"]), int(entry["excerpt_byte_length"])
        excerpt = body[start:start + length].decode("utf-8", "strict")
        entry.update({"source_content_sha256": source.content_sha256,
                      "raw_response_ref": source.raw_response_ref})
        plain = _plain_excerpt(excerpt)
        claim.update({"classification": "fact", "text": f"{task.company}: {plain}",
                      "source_ids": [source.id], "citation_excerpt": excerpt,
                      "source_captured_at": source.captured_at,
                      "observed_at": source.updated_at or source.published_at,
                      "temporal_semantics": ("publisher_time" if source.updated_at or source.published_at
                                             else "retrieval_snapshot")})
        claims.append(claim)
    schema_version = (
        "jaa04.dossier.v4"
        if citations and all(item.access_receipt is not None for item in citations)
        else "jaa04.dossier.v3"
    )
    dossier = {"schema_version": schema_version, "job_key": task.job_key,
               "raw_cache_root": str(cache.root), "sources": [vars(item) for item in citations],
               "source_plan": plan, "claims": claims, "edges": []}
    validate_dossier(dossier, cache)
    return dossier


class EmployerResearchWorker:
    """Production lease worker: claim, retrieve, validate, then complete once."""

    def __init__(self, database: Any, worker_id: str, cache: RawResponseCache, *,
                 retriever: Any | None = None, lease_seconds: int = 900) -> None:
        if not worker_id.strip():
            raise ValueError("worker ID is required")
        self.database, self.worker_id, self.cache = database, worker_id, cache
        self.retriever = retriever or PortableAuthorityRetriever(cache)
        self.lease_seconds = lease_seconds

    def run_once(self) -> str | None:
        task = self.database.claim_research(self.worker_id, self.lease_seconds)
        if task is None:
            return None
        # Any failure deliberately leaves the lease visible. Once it expires,
        # claim_research atomically exposes it to a resuming worker.
        try:
            if not hasattr(self.retriever, "retrieve_plan"):
                # Compatibility for deterministic test retrievers: their single
                # admitted-vacancy response is still discovered from the task URL.
                self.retriever = PortableAuthorityRetriever(self.cache, retriever=self.retriever)
            citations, source_plan = self.retriever.retrieve_plan(task)
            dossier = build_reconnaissance_dossier(task, citations, self.cache, source_plan=source_plan)
            digest = content_hash(dossier)
            validate_dossier(dossier, self.cache)
            self.database.complete_research(job_key=task.job_key, worker_id=self.worker_id,
                                            dossier=dossier, dossier_hash=digest)
        except Exception as exc:
            self.database.record_research_failure(job_key=task.job_key, worker_id=self.worker_id,
                                                  error=f"{type(exc).__name__}: {exc}")
            raise
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
        supported_claims = [claim for claim in dossier["claims"]
                            if claim.get("outcome", "supported") == "supported"]
        if any(not isinstance(claim.get("citation_excerpt"), str)
               or not claim["citation_excerpt"].strip() for claim in supported_claims):
            raise ValueError("completed dossier has incomplete claim provenance")
        signals = list(self.signal_deriver(dossier))
        claim_ids = {str(claim["id"]) for claim in supported_claims}
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
        decision = self.database.apply_opportunity1(
            job_key=job_key, signals=[dict(signal) for signal in signals],
            expected_dossier_hash=dossier_hash,
        )
        return {"job_key": job_key, **decision}


def load_frozen_dossiers(
    path: str | Path,
    cache: RawResponseCache,
    *,
    strict_corpus: bool = False,
    access_policies: Mapping[str, PublicAccessPolicy] | None = None,
) -> list[dict[str, Any]]:
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    dossiers = envelope.get("dossiers")
    if envelope.get("schema_version") not in {
        "jaa04.frozen-dossiers.v1",
        "jaa04.frozen-dossiers.v2",
        "jaa04.frozen-dossiers.v3",
        "jaa04.frozen-dossiers.v4",
        "jaa04.frozen-dossiers.v5",
    } or not isinstance(dossiers, list) or len(dossiers) < 30:
        raise ValueError("JAA-04 frozen set requires at least 30 dossiers")
    if strict_corpus and len(dossiers) != 30:
        raise ValueError("certified JAA-04 corpus requires exactly 30 dossiers")
    if strict_corpus and (
        envelope.get("schema_version") != "jaa04.frozen-dossiers.v5"
        or access_policies is None
        or not access_policies
    ):
        raise ValueError("certified JAA-04 corpus requires v5 access-policy-bound evidence")
    if content_hash(dossiers) != envelope.get("dossiers_hash"):
        raise ValueError("frozen dossier-set hash mismatch")
    classifications: set[str] = set()
    required_kinds = {kind.value for kind in IntelligenceKind}
    job_keys: set[str] = set()
    normalized_claims = {kind: set() for kind in required_kinds}
    normalized_claim_counts = {kind: 0 for kind in required_kinds}
    corpus_access_by_host: dict[str, tuple[str, str]] = {}
    for dossier in dossiers:
        dossier_captures: set[tuple[str, str]] = set()
        captured_dates = [datetime.fromisoformat(
            str(source["captured_at"]).replace("Z", "+00:00")
        ).date() for source in dossier.get("sources", [])]
        if not captured_dates or len(set(captured_dates)) != 1:
            raise ValueError("frozen dossier requires one unambiguous capture date")
        if strict_corpus and dossier.get("schema_version") != "jaa04.dossier.v4":
            raise ValueError("certified JAA-04 dossiers require v4 access receipts")
        validate_dossier(
            dossier,
            cache,
            as_of=captured_dates[0],
            access_policies=access_policies,
        )
        if strict_corpus:
            for source in dossier["sources"]:
                access = source["access_receipt"]
                host = str(access["host"])
                identity = (
                    str(access["content_sha256"]),
                    str(access["raw_response_ref"]),
                )
                prior = corpus_access_by_host.setdefault(host, identity)
                if prior != identity:
                    raise ValueError("certified corpus has inconsistent robots bytes for one host")
        if strict_corpus and {str(claim.get("kind")) for claim in dossier.get("claims", [])} != required_kinds:
            raise ValueError("each frozen dossier must cover every intelligence kind")
        portable = dossier.get("schema_version") in {"jaa04.dossier.v3", "jaa04.dossier.v4"}
        positive = [claim for claim in dossier.get("claims", [])
                    if claim.get("outcome", "supported") == "supported"]
        if strict_corpus and not portable and {str(claim.get("classification")) for claim in dossier.get("claims", [])} != {
            "fact", "inference", "hypothesis",
        }:
            raise ValueError("each frozen dossier must distinguish fact, inference, and hypothesis")
        if strict_corpus and not portable and not any(
                edge.get("relation") in {"qualifies", "contradicts"}
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
                dossier_captures.add(capture_identity)
            if not body:
                raise ValueError("frozen source bytes must be non-empty")
        source_by_id = {source["id"]: source for source in dossier["sources"]}
        company = str(dossier["claims"][0].get("text", "")).split(":", 1)[0].strip()
        for claim in dossier["claims"]:
            if claim.get("classification") is not None:
                classifications.add(str(claim["classification"]))
            excerpt = claim.get("citation_excerpt")
            supported = claim.get("outcome", "supported") == "supported"
            if strict_corpus and supported and (not isinstance(excerpt, str) or not excerpt.strip()):
                raise ValueError("frozen claims require a citation excerpt")
            if strict_corpus and supported and not any(excerpt.encode("utf-8") in cache.resolve(
                source_by_id[source_id]["raw_response_ref"],
                source_by_id[source_id]["content_sha256"],
            ) for source_id in claim["source_ids"]):
                raise ValueError("frozen claim excerpt does not resolve to cited bytes")
            if strict_corpus and not portable and claim.get("freshness_classification") not in {"current", "historical"}:
                raise ValueError("frozen claims require freshness classification")
            if strict_corpus and supported:
                text = str(claim.get("text", "")).strip()
                if not company or len(text.split()) < 8:
                    raise ValueError("frozen claims must contain substantive employer intelligence")
                normalized_claims[str(claim["kind"])].add(
                    text.casefold().replace(company.casefold(), "<employer>")
                )
                normalized_claim_counts[str(claim["kind"])] += 1
    if strict_corpus and not all(
        row.get("schema_version") in {"jaa04.dossier.v3", "jaa04.dossier.v4"}
        for row in dossiers
    ) and classifications != {"fact", "inference", "hypothesis"}:
        raise ValueError("frozen corpus must distinguish facts, inferences, and hypotheses")
    # Certification deliberately treats any employer-normalized collision as
    # a blocker. Genuine source-specific prose must remain distinct; a corpus
    # that cannot demonstrate that distinction requires operator correction.
    if strict_corpus and any(
        len(normalized_claims[kind]) != normalized_claim_counts[kind]
        for kind in required_kinds
    ):
        raise ValueError("employer-normalized boilerplate cannot become certified intelligence")
    # Unknown/abstained outcomes are deliberately repetitive and do not count
    # as employer intelligence. Supported prose remains provenance-bound.
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
