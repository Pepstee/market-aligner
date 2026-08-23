"""Source-bound employer and role research contracts."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class SourceCitation:
    citation_id: str
    url: str
    title: str
    accessed_at: str
    content_sha256: str

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError("research citations require a public HTTP(S) URL")
        if len(self.content_sha256) != 64:
            raise ValueError("citation content_sha256 must be a SHA-256 digest")


@dataclass(frozen=True)
class ResearchClaim:
    claim: str
    citation_ids: tuple[str, ...]
    confidence: float

    def __post_init__(self) -> None:
        if not self.claim.strip() or not self.citation_ids:
            raise ValueError("every research claim requires at least one citation")
        if not 0 <= float(self.confidence) <= 1:
            raise ValueError("research claim confidence must be in [0,1]")


@dataclass(frozen=True)
class ResearchDossier:
    profile_id: str
    job_key: str
    company: str
    role: str
    claims: tuple[ResearchClaim, ...]
    citations: tuple[SourceCitation, ...]
    unknowns: tuple[str, ...] = ()

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
