"""Source-bound public employer research for the existing research worker.

The generic worker and AssessmentStore deliberately do not fetch the web.  This
module owns the distinct lifecycle of retrieving public source bytes, archiving
them outside the repository, and materialising a cited ResearchDossier.  It does
not rank jobs, generate candidate claims, or grant application authority.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .models import ResearchClaim, ResearchDossier, ResearchTask, SourceCitation


_MAX_SOURCE_BYTES = 5 * 1024 * 1024


class PublicResearchError(ValueError):
    """Public research could not be bound to the exact queued task."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_public_url(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise PublicResearchError("research source must be a credential-free HTTPS URL")
    host = parts.hostname.casefold()
    if host == "localhost" or host.endswith(".localhost"):
        raise PublicResearchError("research source cannot target localhost")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise PublicResearchError("research source cannot target a non-public address")
    return value


def _private_external_root(path: Path, repository_root: Path) -> Path:
    root = path.resolve()
    repository = repository_root.resolve(strict=True)
    if root == repository or repository in root.parents:
        raise PublicResearchError("research archive must live outside the repository")
    if root.exists() and root.is_symlink():
        raise PublicResearchError("research archive cannot be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def _write_exact(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != value:
            raise PublicResearchError("content-addressed research replay differs")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


@dataclass(frozen=True)
class PlannedCitation:
    citation_id: str
    url: str
    title: str


@dataclass(frozen=True)
class PlannedClaim:
    claim: str
    citation_ids: tuple[str, ...]
    confidence: float


@dataclass(frozen=True)
class PublicResearchPlan:
    profile_id: str
    job_key: str
    company: str
    role: str
    citations: tuple[PlannedCitation, ...]
    claims: tuple[PlannedClaim, ...]
    unknowns: tuple[str, ...] = ()


@dataclass(frozen=True)
class FetchedPublicSource:
    requested_url: str
    final_url: str
    status: int
    body: bytes
    content_type: str
    accessed_at: str


@dataclass(frozen=True)
class MaterializedPublicResearch:
    dossier: ResearchDossier
    dossier_sha256: str
    receipt_path: Path
    receipt_sha256: str


class ScraplingPublicSourceFetcher:
    """Fetch one public page with Scrapling's safe redirect handling."""

    def __init__(self, *, timeout_seconds: int = 30) -> None:
        self.timeout_seconds = max(1, min(int(timeout_seconds), 60))

    def __call__(self, url: str) -> FetchedPublicSource:
        from scrapling.fetchers import Fetcher

        requested = _safe_public_url(url)
        page = Fetcher.get(
            requested,
            timeout=self.timeout_seconds,
            follow_redirects=True,
            stealthy_headers=True,
        )
        final_url = _safe_public_url(str(page.url))
        headers = dict(page.headers or {})
        content_type = str(headers.get("content-type", headers.get("Content-Type", "")))
        return FetchedPublicSource(
            requested_url=requested,
            final_url=final_url,
            status=int(page.status),
            body=bytes(page.body),
            content_type=content_type,
            accessed_at=datetime.now(timezone.utc).isoformat(),
        )


class SourceBoundResearchProvider:
    """Materialise reviewed claims only after archiving every cited source."""

    def __init__(
        self,
        *,
        plan: PublicResearchPlan,
        repository_root: Path,
        archive_root: Path,
        fetcher: Callable[[str], FetchedPublicSource] | None = None,
    ) -> None:
        self.plan = plan
        self.root = _private_external_root(archive_root, repository_root)
        self.fetcher = fetcher or ScraplingPublicSourceFetcher()
        self.last_materialization: MaterializedPublicResearch | None = None

    def _validate_plan(self, task: ResearchTask) -> None:
        if (
            self.plan.profile_id != task.profile_id
            or self.plan.job_key != task.job_key
            or self.plan.company != task.company
            or self.plan.role != task.title
        ):
            raise PublicResearchError("research plan differs from the leased task")
        ids = [row.citation_id for row in self.plan.citations]
        if not ids or len(ids) != len(set(ids)) or any(not value.strip() for value in ids):
            raise PublicResearchError("research citation identities are empty or duplicated")
        known = set(ids)
        for row in self.plan.citations:
            _safe_public_url(row.url)
            if not row.title.strip():
                raise PublicResearchError("research citation title is empty")
        for claim in self.plan.claims:
            if not claim.claim.strip() or not claim.citation_ids:
                raise PublicResearchError("research claim is empty or uncited")
            if not set(claim.citation_ids) <= known:
                raise PublicResearchError("research claim cites an unknown source")
            if not 0 <= float(claim.confidence) <= 1:
                raise PublicResearchError("research confidence is outside [0,1]")

    def materialize(self, task: ResearchTask) -> MaterializedPublicResearch:
        self._validate_plan(task)
        entries: list[dict[str, object]] = []
        citations: list[SourceCitation] = []
        for planned in sorted(self.plan.citations, key=lambda row: row.citation_id):
            fetched = self.fetcher(planned.url)
            if fetched.requested_url != planned.url:
                raise PublicResearchError("fetcher substituted the requested source")
            if fetched.status != 200 or not fetched.body:
                raise PublicResearchError("research source did not return a non-empty HTTP 200")
            if len(fetched.body) > _MAX_SOURCE_BYTES:
                raise PublicResearchError("research source exceeds the archive size limit")
            _safe_public_url(fetched.final_url)
            if not fetched.accessed_at.endswith(("+00:00", "Z")):
                raise PublicResearchError("research source time is not explicit UTC")
            object_sha = _sha256(fetched.body)
            metadata = {
                "accessed_at": fetched.accessed_at,
                "citation_id": planned.citation_id,
                "content_sha256": object_sha,
                "content_type": fetched.content_type,
                "final_url": fetched.final_url,
                "requested_url": fetched.requested_url,
                "schema_version": "market-aligner.public-research-source.v1",
                "status": fetched.status,
                "title": planned.title,
            }
            metadata_bytes = _canonical_bytes(metadata)
            metadata_sha = _sha256(metadata_bytes)
            _write_exact(self.root / "objects" / object_sha, fetched.body)
            _write_exact(self.root / "metadata" / f"{metadata_sha}.json", metadata_bytes)
            entries.append(
                {
                    "citation_id": planned.citation_id,
                    "metadata_sha256": metadata_sha,
                    "object_sha256": object_sha,
                }
            )
            citations.append(
                SourceCitation(
                    planned.citation_id,
                    fetched.final_url,
                    planned.title,
                    fetched.accessed_at,
                    object_sha,
                )
            )
        dossier = ResearchDossier(
            task.profile_id,
            task.job_key,
            task.company,
            task.title,
            tuple(
                ResearchClaim(row.claim, row.citation_ids, row.confidence)
                for row in self.plan.claims
            ),
            tuple(citations),
            self.plan.unknowns,
        )
        dossier.validate()
        dossier_payload = json.dumps(asdict(dossier), ensure_ascii=False, sort_keys=True)
        dossier_sha = _sha256(dossier_payload.encode("utf-8"))
        receipt_body = {
            "application_authority": False,
            "claim_semantic_authority": "reviewed_plan_only",
            "dossier_sha256": dossier_sha,
            "entries": entries,
            "job_key": task.job_key,
            "profile_id": task.profile_id,
            "release_authority": False,
            "schema_version": "market-aligner.public-research-materialization.v1",
        }
        receipt_sha = _sha256(_canonical_bytes(receipt_body))
        receipt = {**receipt_body, "receipt_sha256": receipt_sha}
        receipt_path = self.root / "receipts" / f"{receipt_sha}.json"
        _write_exact(receipt_path, _canonical_bytes(receipt))
        result = MaterializedPublicResearch(
            dossier, dossier_sha, receipt_path, receipt_sha
        )
        self.last_materialization = result
        return result

    def research(self, task: ResearchTask) -> ResearchDossier:
        """ResearchProvider interface used by the canonical ResearchWorker."""

        return self.materialize(task).dossier


__all__ = [
    "FetchedPublicSource",
    "MaterializedPublicResearch",
    "PlannedCitation",
    "PlannedClaim",
    "PublicResearchError",
    "PublicResearchPlan",
    "ScraplingPublicSourceFetcher",
    "SourceBoundResearchProvider",
]
