"""Source-bound employer and role research contracts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urlsplit

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BYTE_SELECTOR = re.compile(r"^bytes:(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$")
RESEARCH_ARCHIVE_ROOT_POLICY_SHA256 = (
    "209f1714c8b020971286b0e3fb33263d5a0c029524055bc74dbb8c1cc1282572"
)

RESEARCH_REFRESH_BRIDGE_FIELDS = (
    "collection_context_sha256",
    "collection_operation_id",
    "collection_receipt_file_sha256",
    "collection_receipt_sha256",
    "collection_refresh_id",
    "collection_transition_sha256",
    "new_fetched_at",
    "new_raw_object_sha256",
    "old_canonical_content_sha256",
    "old_collector_content_sha256",
    "prior_dossier_hash",
    "promotion_receipt_sha256",
    "source_content_sha256",
)


def research_refresh_bridge_sha256(
    *, event_type: str, actor_kind: str, idempotency_key: str, payload: dict[str, object]
) -> str:
    """Hash every semantic field carried across one refresh-worker lease."""

    fields = {key: payload.get(key) for key in RESEARCH_REFRESH_BRIDGE_FIELDS}
    allowed = set(RESEARCH_REFRESH_BRIDGE_FIELDS)
    if set(payload) not in (
        allowed,
        allowed | {"refresh_bridge_sha256"},
    ) or any(value is None for value in fields.values()):
        raise ValueError("research refresh bridge payload is incomplete")
    document = {
        "actor_kind": actor_kind,
        "event_type": event_type,
        "fields": fields,
        "idempotency_key": idempotency_key,
        "schema_version": "market-aligner.research-refresh-bridge.v1",
    }
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def research_refresh_preserves_source_authority(
    *,
    source_content_sha256: object,
    old_collector_content_sha256: object,
    old_canonical_content_sha256: object,
) -> bool:
    """Accept a direct refresh or an admitted canonical continuation.

    The promotion remains the source authority.  A later unchanged refresh may
    advance from the preceding canonical identity without relabelling it.
    """

    values = (
        source_content_sha256,
        old_collector_content_sha256,
        old_canonical_content_sha256,
    )
    return all(
        isinstance(value, str) and _SHA256.fullmatch(value) for value in values
    ) and (
        old_collector_content_sha256 == source_content_sha256
        or old_collector_content_sha256 == old_canonical_content_sha256
    )


@dataclass(frozen=True)
class SourceCitation:
    citation_id: str
    url: str
    title: str
    accessed_at: str
    content_sha256: str
    source_kind: str = "public_web"

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme != "https" or not parts.netloc:
            raise ValueError("research citations require a public HTTPS URL")
        if not _SHA256.fullmatch(self.content_sha256):
            raise ValueError("citation content_sha256 must be a SHA-256 digest")
        if self.source_kind not in {"canonical_vacancy", "public_web"}:
            raise ValueError("citation source_kind is unsupported")


@dataclass(frozen=True)
class ClaimSupport:
    citation_id: str
    selector: str
    excerpt: str
    excerpt_sha256: str

    def __post_init__(self) -> None:
        if not self.citation_id.strip() or not self.excerpt:
            raise ValueError("claim support requires a citation and exact excerpt")
        match = _BYTE_SELECTOR.fullmatch(self.selector)
        if match is None or int(match.group(1)) >= int(match.group(2)):
            raise ValueError("claim support selector must be a non-empty byte range")
        if not _SHA256.fullmatch(self.excerpt_sha256):
            raise ValueError("claim support excerpt_sha256 must be a SHA-256 digest")


@dataclass(frozen=True)
class ResearchClaim:
    claim: str
    citation_ids: tuple[str, ...]
    confidence: float
    supports: tuple[ClaimSupport, ...] = ()

    def __post_init__(self) -> None:
        if not self.claim.strip() or not self.citation_ids:
            raise ValueError("every research claim requires at least one citation")
        if not 0 <= float(self.confidence) <= 1:
            raise ValueError("research claim confidence must be in [0,1]")
        for support in self.supports:
            support.__post_init__()
        if self.supports and set(self.citation_ids) != {row.citation_id for row in self.supports}:
            raise ValueError("claim support identities differ from claim citations")


@dataclass(frozen=True)
class ResearchDossier:
    profile_id: str
    job_key: str
    company: str
    role: str
    claims: tuple[ResearchClaim, ...]
    citations: tuple[SourceCitation, ...]
    unknowns: tuple[str, ...] = ()
    source_content_sha256: str | None = None
    vacancy_snapshot_sha256: str | None = None
    promotion_receipt_sha256: str | None = None
    canonical_vacancy_object_sha256: str | None = None
    schema_version: str = "market-aligner.employer-dossier.v1"

    def validate(self) -> None:
        known = {citation.citation_id for citation in self.citations}
        if len(known) != len(self.citations):
            raise ValueError("duplicate research citation_id")
        missing = sorted(
            citation_id
            for claim in self.claims
            for citation_id in claim.citation_ids
            if citation_id not in known
        )
        if missing:
            raise ValueError(f"research claims cite unknown sources: {missing}")
        if self.schema_version == "market-aligner.employer-dossier.v2":
            for value in (
                self.source_content_sha256,
                self.vacancy_snapshot_sha256,
                self.promotion_receipt_sha256,
                self.canonical_vacancy_object_sha256,
            ):
                if not isinstance(value, str) or not _SHA256.fullmatch(value):
                    raise ValueError("v2 dossier lacks a protected vacancy/promotion binding")
            if not self.claims or any(not claim.supports for claim in self.claims):
                raise ValueError("v2 dossier claims require exact archived support")
            official = [row for row in self.citations if row.source_kind == "canonical_vacancy"]
            if (
                len(official) != 1
                or official[0].content_sha256
                != self.canonical_vacancy_object_sha256
            ):
                raise ValueError("v2 dossier canonical vacancy citation differs")
        elif self.schema_version != "market-aligner.employer-dossier.v1":
            raise ValueError("research dossier schema is unsupported")


@dataclass(frozen=True)
class ResearchEvidenceBinding:
    dossier_sha256: str
    source_content_sha256: str
    vacancy_snapshot_sha256: str
    promotion_receipt_sha256: str
    canonical_vacancy_object_sha256: str
    semantic_receipt_sha256: str
    receipt_file_sha256: str
    archive_root_identity: str
    archive_root_policy_sha256: str
    receipt_relative_path: str
    schema_version: str = "market-aligner.research-store-binding.v2"

    def validate(self) -> None:
        if self.schema_version != "market-aligner.research-store-binding.v2":
            raise ValueError("research evidence binding schema is unsupported")
        for value in (
            self.dossier_sha256,
            self.source_content_sha256,
            self.vacancy_snapshot_sha256,
            self.promotion_receipt_sha256,
            self.canonical_vacancy_object_sha256,
            self.semantic_receipt_sha256,
            self.receipt_file_sha256,
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError("research evidence binding contains an invalid digest")
        if (
            self.archive_root_policy_sha256 != RESEARCH_ARCHIVE_ROOT_POLICY_SHA256
            or not self.archive_root_identity
            or self.archive_root_identity.startswith(("/", "../"))
            or "/../" in self.archive_root_identity
            or self.receipt_relative_path
            != (
            f"receipts/{self.semantic_receipt_sha256}.json"
            )
        ):
            raise ValueError("research evidence binding receipt path is invalid")


@dataclass(frozen=True)
class ResearchTask:
    profile_id: str
    job_key: str
    title: str
    company: str
    url: str
    opportunity: float
    priority: int
    attempts: int
    source_content_sha256: str | None = None
    vacancy_snapshot_sha256: str | None = None
    promotion_receipt_sha256: str | None = None
    refresh_event_id: int | None = None
    refresh_bridge_sha256: str | None = None
    refresh_event_idempotency_key: str | None = None
    refresh_receipt_sha256: str | None = None
    refresh_receipt_file_sha256: str | None = None
    refresh_transition_sha256: str | None = None
    refresh_id: str | None = None
    refresh_context_sha256: str | None = None
    refresh_operation_id: str | None = None
    refresh_legacy_content_sha256: str | None = None
    refresh_canonical_content_sha256: str | None = None
    refresh_raw_object_sha256: str | None = None
    refresh_fetched_at: str | None = None
    refresh_promotion_receipt_sha256: str | None = None
    refresh_prior_dossier_sha256: str | None = None
