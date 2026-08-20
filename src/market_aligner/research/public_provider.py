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
import re
import secrets
import socket
import sqlite3
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit

from market_aligner.state.vacancies import JobDatabase, VacancyRefreshConflict

from .models import ClaimSupport, ResearchClaim, ResearchDossier, ResearchTask, SourceCitation


_MAX_SOURCE_BYTES = 5 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BYTE_SELECTOR = re.compile(r"^bytes:(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$")


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


def _safe_public_url(
    value: str, *, resolver: Callable[..., Iterable[tuple[object, ...]]] | None = None
) -> str:
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise PublicResearchError("research source port is malformed") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or port not in {None, 443}
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
    if resolver is not None:
        try:
            rows = tuple(resolver(host, 443, type=socket.SOCK_STREAM))
        except OSError as exc:
            raise PublicResearchError("research source DNS resolution failed") from exc
        if not rows:
            raise PublicResearchError("research source DNS resolution is empty")
        for row in rows:
            try:
                resolved = ipaddress.ip_address(str(row[4][0]))
            except (IndexError, TypeError, ValueError) as exc:
                raise PublicResearchError("research source DNS result is malformed") from exc
            if not resolved.is_global:
                raise PublicResearchError("research source DNS targets a non-public address")
    return value


def _private_external_root(path: Path, repository_root: Path) -> Path:
    absolute = path.absolute()
    if not absolute.is_absolute() or ".." in absolute.parts:
        raise PublicResearchError("research archive path is unsafe")
    repository = repository_root.resolve(strict=True)
    root = absolute
    if root == repository or repository in root.parents:
        raise PublicResearchError("research archive must live outside the repository")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in root.parts[1:]:
            try:
                os.mkdir(component, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise PublicResearchError(
                    "research archive path contains an unsafe component"
                ) from exc
            os.close(descriptor)
            descriptor = child
        details = os.fstat(descriptor)
        if details.st_uid != os.geteuid():
            raise PublicResearchError("research archive owner differs from runtime user")
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)
    return root


def _secure_directory(root: Path, category: str) -> int:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.mkdir(category, 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        try:
            directory_fd = os.open(
                category, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
            )
        except OSError as exc:
            raise PublicResearchError("research archive component is unsafe") from exc
    finally:
        os.close(root_fd)
    details = os.fstat(directory_fd)
    if details.st_uid != os.geteuid():
        os.close(directory_fd)
        raise PublicResearchError("research archive component owner differs")
    os.fchmod(directory_fd, 0o700)
    return directory_fd


def _read_existing_exact(directory_fd: int, name: str, value: bytes) -> bool:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise PublicResearchError("research archive object is unsafe") from exc
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or details.st_mode & 0o077
        ):
            raise PublicResearchError("research archive object permissions are unsafe")
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            if handle.read() != value:
                raise PublicResearchError("content-addressed research replay differs")
    finally:
        os.close(descriptor)
    return True


def _write_exact(root: Path, category: str, name: str, value: bytes) -> Path:
    if "/" in name or name in {"", ".", ".."}:
        raise PublicResearchError("research archive object name is unsafe")
    directory_fd = _secure_directory(root, category)
    temporary = f".{name}.{secrets.token_hex(16)}"
    try:
        if _read_existing_exact(directory_fd, name, value):
            return root / category / name
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if not _read_existing_exact(directory_fd, name, value):
                raise PublicResearchError("research archive replay raced unsafely")
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return root / category / name
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory_fd)


@dataclass(frozen=True)
class PlannedCitation:
    citation_id: str
    url: str
    title: str
    expected_content_sha256: str
    expected_final_url: str
    source_kind: str = "public_web"


@dataclass(frozen=True)
class PlannedSupport:
    citation_id: str
    selector: str
    excerpt: str


@dataclass(frozen=True)
class PlannedClaim:
    claim: str
    citation_ids: tuple[str, ...]
    confidence: float
    supports: tuple[PlannedSupport, ...]


@dataclass(frozen=True)
class PublicResearchPlan:
    profile_id: str
    job_key: str
    company: str
    role: str
    citations: tuple[PlannedCitation, ...]
    claims: tuple[PlannedClaim, ...]
    source_content_sha256: str
    vacancy_snapshot_sha256: str
    promotion_receipt_sha256: str
    unknowns: tuple[str, ...] = ()
    schema_version: str = "market-aligner.public-research-plan.v2"
    production_authority: bool = True


@dataclass(frozen=True)
class FetchedPublicSource:
    requested_url: str
    final_url: str
    status: int
    body: bytes
    content_type: str
    accessed_at: str
    redirect_chain: tuple[str, ...] = ()
    source_kind: str = "public_web"
    authority_source_content_sha256: str | None = None


class CanonicalCollectorVacancyLoader:
    """Read the exact fetched vacancy row from the canonical collector database.

    The collector's legacy ``content_hash`` remains the promotion authority.  The
    archived object is a separate, unambiguous canonical envelope, so its SHA is
    intentionally a different hash domain.
    """

    def __init__(
        self,
        database: Path | None = None,
        *,
        data_home: Path | None = None,
        collection_config_path: Path | None = None,
    ) -> None:
        self.database = None if database is None else database.absolute()
        self.data_home = None if data_home is None else data_home.absolute()
        self.collection_config_path = (
            None
            if collection_config_path is None
            else collection_config_path.absolute()
        )

    @staticmethod
    def _safe_database(path: Path, *, label: str) -> None:
        try:
            details = path.lstat()
        except OSError as exc:
            raise PublicResearchError(f"{label} is unavailable") from exc
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o022
            or path.resolve(strict=True) != path
        ):
            raise PublicResearchError(f"{label} is unsafe")

    @staticmethod
    def _posting_row(connection: sqlite3.Connection, job_key: str) -> sqlite3.Row | None:
        return connection.execute(
            """SELECT key,url,fetched_at,raw_text,raw_json,content_hash,fetch_status
               FROM postings WHERE key=?""",
            (job_key,),
        ).fetchone()

    @staticmethod
    def _parsed_posting(row: sqlite3.Row, task: ResearchTask) -> tuple[str, object]:
        if row is None or row["fetch_status"] != "fetched":
            raise PublicResearchError("canonical collector vacancy is not fetched")
        if row["url"] != task.url:
            raise PublicResearchError("canonical collector vacancy URL differs from task")
        fetched_at = str(row["fetched_at"] or "")
        try:
            parsed_time = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PublicResearchError("canonical collector fetched time is invalid") from exc
        if (
            parsed_time.tzinfo is None
            or parsed_time.utcoffset() is None
            or parsed_time.utcoffset().total_seconds() != 0
        ):
            raise PublicResearchError("canonical collector fetched time is not explicit UTC")
        raw_json = None
        if row["raw_json"] is not None:
            try:
                raw_json = json.loads(str(row["raw_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise PublicResearchError("canonical collector raw JSON is invalid") from exc
        if row["raw_text"] is None and raw_json is None:
            raise PublicResearchError("canonical collector vacancy has no source content")
        return fetched_at, raw_json

    def _bridge_event_payload(self, task: ResearchTask) -> dict[str, object]:
        if self.data_home is None or self.collection_config_path is None:
            raise PublicResearchError(
                "refresh bridge requires deployment-bound data home and collection config"
            )
        required = {
            "collection_context_sha256": task.refresh_context_sha256,
            "collection_operation_id": task.refresh_operation_id,
            "collection_receipt_file_sha256": task.refresh_receipt_file_sha256,
            "collection_receipt_sha256": task.refresh_receipt_sha256,
            "collection_refresh_id": task.refresh_id,
            "collection_transition_sha256": task.refresh_transition_sha256,
            "new_fetched_at": task.refresh_fetched_at,
            "new_raw_object_sha256": task.refresh_raw_object_sha256,
            "old_canonical_content_sha256": task.refresh_canonical_content_sha256,
            "old_collector_content_sha256": task.refresh_legacy_content_sha256,
            "promotion_receipt_sha256": task.refresh_promotion_receipt_sha256,
            "source_content_sha256": task.source_content_sha256,
            "prior_dossier_hash": task.refresh_prior_dossier_sha256,
        }
        if (
            type(task.refresh_event_id) is not int
            or task.refresh_event_id <= 0
            or any(value is None or value == "" for value in required.values())
            or task.refresh_legacy_content_sha256 != task.source_content_sha256
            or task.refresh_promotion_receipt_sha256
            != task.promotion_receipt_sha256
        ):
            raise PublicResearchError("research refresh task binding is incomplete")
        assessment_path = self.data_home / "state" / "assessments.sqlite3"
        self._safe_database(assessment_path, label="canonical assessment database")
        connection = sqlite3.connect(
            f"file:{assessment_path.as_posix()}?mode=ro", uri=True, timeout=30
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            row = connection.execute(
                """SELECT q.refresh_event_id,q.status,e.event_type,e.actor_kind,
                          e.payload_json,e.idempotency_key,d.dossier_hash,
                          d.dossier_json,
                          p.source_content_sha256,
                          p.receipt_sha256 AS promotion_receipt_sha256
                   FROM employer_research_queue q
                   JOIN assessment_events e
                     ON e.id=q.refresh_event_id
                    AND e.profile_id=q.profile_id AND e.job_key=q.job_key
                   JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (task.profile_id, task.job_key),
            ).fetchone()
            if row is None:
                raise PublicResearchError("research refresh event is not canonical")
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise PublicResearchError("research refresh event payload is invalid") from exc
            expected = dict(required)
            if (
                row["refresh_event_id"] != task.refresh_event_id
                or row["status"] not in {"queued", "leased"}
                or row["event_type"]
                != "employer_research_collection_refresh_queued"
                or row["actor_kind"] != "deterministic"
                or row["idempotency_key"]
                != task.refresh_event_idempotency_key
                or task.refresh_event_idempotency_key
                != (
                    f"research-collection-refresh:{task.profile_id}:"
                    f"{task.job_key}:{task.refresh_transition_sha256}"
                )
                or payload != expected
                or row["dossier_hash"] != task.refresh_prior_dossier_sha256
                or hashlib.sha256(
                    str(row["dossier_json"] or "").encode("utf-8")
                ).hexdigest()
                != row["dossier_hash"]
                or row["source_content_sha256"] != task.source_content_sha256
                or row["promotion_receipt_sha256"]
                != task.promotion_receipt_sha256
            ):
                raise PublicResearchError("research refresh event differs from task")
            connection.commit()
        finally:
            connection.close()
        return expected

    def _load_bridge(self, task: ResearchTask) -> FetchedPublicSource:
        self._bridge_event_payload(task)
        assert self.data_home is not None
        assert self.collection_config_path is not None
        receipt_path = (
            self.data_home
            / "state"
            / "collection-refresh-receipts"
            / f"{task.refresh_receipt_sha256}.json"
        )
        try:
            resolved_collector = JobDatabase.resolve_vacancy_refresh_collector(
                self.data_home, receipt_path, self.collection_config_path
            )
            collector = resolved_collector.database
            connection = collector.connect()
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
                resolved_collector.verify_open_connection(connection)
                verified = collector.verify_vacancy_refresh_receipt(
                    receipt_path, job_key=task.job_key, connection=connection
                )
                row = self._posting_row(connection, task.job_key)
                fetched_at, raw_json = self._parsed_posting(row, task)
                if (
                    verified.changed
                    or verified.old_content_sha256
                    != task.refresh_legacy_content_sha256
                    or verified.old_content_sha256 != task.source_content_sha256
                    or verified.old_canonical_content_sha256
                    != verified.new_content_sha256
                    or verified.new_content_sha256
                    != task.refresh_canonical_content_sha256
                    or str(row["content_hash"] or "")
                    != task.refresh_canonical_content_sha256
                    or verified.receipt_sha256 != task.refresh_receipt_sha256
                    or verified.receipt_file_sha256
                    != task.refresh_receipt_file_sha256
                    or verified.transition_sha256 != task.refresh_transition_sha256
                    or verified.refresh_id != task.refresh_id
                    or verified.context_sha256 != task.refresh_context_sha256
                    or verified.operation_id != task.refresh_operation_id
                    or verified.new_raw_object_sha256
                    != task.refresh_raw_object_sha256
                    or verified.new_fetched_at != task.refresh_fetched_at
                    or fetched_at != task.refresh_fetched_at
                ):
                    raise PublicResearchError(
                        "canonical refresh receipt or current vacancy differs from task"
                    )
                resolved_collector.verify_open_connection(connection)
                connection.commit()
            finally:
                connection.close()
        except (OSError, sqlite3.Error, VacancyRefreshConflict, ValueError) as exc:
            if isinstance(exc, PublicResearchError):
                raise
            raise PublicResearchError("canonical refresh bridge verification failed") from exc
        envelope = {
            "authority_source_content_sha256": task.source_content_sha256,
            "canonical_current_content_sha256": task.refresh_canonical_content_sha256,
            "collection_refresh_event_id": task.refresh_event_id,
            "collection_refresh_context_sha256": task.refresh_context_sha256,
            "collection_refresh_id": task.refresh_id,
            "collection_refresh_operation_id": task.refresh_operation_id,
            "collection_refresh_raw_object_sha256": task.refresh_raw_object_sha256,
            "collection_refresh_receipt_file_sha256": (
                task.refresh_receipt_file_sha256
            ),
            "collection_refresh_receipt_sha256": task.refresh_receipt_sha256,
            "collection_refresh_transition_sha256": task.refresh_transition_sha256,
            "fetched_at": fetched_at,
            "job_key": row["key"],
            "promotion_receipt_sha256": task.promotion_receipt_sha256,
            "raw_json": raw_json,
            "raw_text": row["raw_text"],
            "schema_version": "market-aligner.canonical-collector-vacancy.v2",
            "url": row["url"],
        }
        return FetchedPublicSource(
            requested_url=row["url"],
            final_url=row["url"],
            status=200,
            body=_canonical_bytes(envelope),
            content_type="application/vnd.market-aligner.canonical-vacancy+json",
            accessed_at=fetched_at,
            redirect_chain=(row["url"],),
            source_kind="canonical_vacancy",
            authority_source_content_sha256=task.source_content_sha256,
        )

    def __call__(self, task: ResearchTask) -> FetchedPublicSource:
        refresh_values = (
            task.refresh_event_id,
            task.refresh_event_idempotency_key,
            task.refresh_receipt_sha256,
            task.refresh_receipt_file_sha256,
            task.refresh_transition_sha256,
            task.refresh_id,
            task.refresh_context_sha256,
            task.refresh_operation_id,
            task.refresh_legacy_content_sha256,
            task.refresh_canonical_content_sha256,
            task.refresh_raw_object_sha256,
            task.refresh_fetched_at,
            task.refresh_promotion_receipt_sha256,
            task.refresh_prior_dossier_sha256,
        )
        if any(value is not None for value in refresh_values):
            if any(value is None for value in refresh_values):
                raise PublicResearchError("research refresh task binding is incomplete")
            return self._load_bridge(task)
        if self.database is None:
            raise PublicResearchError("canonical collector database is unavailable")
        self._safe_database(self.database, label="canonical collector database")
        connection = sqlite3.connect(
            f"file:{self.database.as_posix()}?mode=ro", uri=True, timeout=30
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            row = self._posting_row(connection, task.job_key)
        except sqlite3.Error as exc:
            raise PublicResearchError("canonical collector database cannot be read") from exc
        finally:
            connection.close()
        fetched_at, raw_json = self._parsed_posting(row, task)
        if (
            not _SHA256.fullmatch(str(row["content_hash"] or ""))
            or row["content_hash"] != task.source_content_sha256
        ):
            raise PublicResearchError("canonical collector source authority differs from task")
        envelope = {
            "authority_source_content_sha256": row["content_hash"],
            "fetched_at": fetched_at,
            "job_key": row["key"],
            "raw_json": raw_json,
            "raw_text": row["raw_text"],
            "schema_version": "market-aligner.canonical-collector-vacancy.v1",
            "url": row["url"],
        }
        return FetchedPublicSource(
            requested_url=row["url"],
            final_url=row["url"],
            status=200,
            body=_canonical_bytes(envelope),
            content_type="application/vnd.market-aligner.canonical-vacancy+json",
            accessed_at=fetched_at,
            redirect_chain=(row["url"],),
            source_kind="canonical_vacancy",
            authority_source_content_sha256=row["content_hash"],
        )


@dataclass(frozen=True)
class MaterializedPublicResearch:
    dossier: ResearchDossier
    dossier_sha256: str
    receipt_path: Path
    semantic_receipt_sha256: str
    receipt_file_sha256: str
    archive_root: Path

    @property
    def receipt_sha256(self) -> str:
        """Compatibility alias; the v2 name makes the hash domain explicit."""
        return self.semantic_receipt_sha256


class ScraplingPublicSourceFetcher:
    """Fetch one public page with Scrapling's safe redirect handling."""

    def __init__(
        self,
        *,
        timeout_seconds: int = 30,
        resolver: Callable[..., Iterable[tuple[object, ...]]] = socket.getaddrinfo,
    ) -> None:
        self.timeout_seconds = max(1, min(int(timeout_seconds), 60))
        self.resolver = resolver

    def __call__(self, url: str) -> FetchedPublicSource:
        from scrapling.fetchers import Fetcher

        requested = _safe_public_url(url, resolver=self.resolver)
        page = Fetcher.get(
            requested,
            timeout=self.timeout_seconds,
            follow_redirects="safe",
            stealthy_headers=True,
        )
        chain = tuple(str(row.url) for row in (page.history or ())) + (str(page.url),)
        if len(chain) > 6:
            raise PublicResearchError("research source exceeded the redirect limit")
        for hop in chain:
            _safe_public_url(hop, resolver=self.resolver)
        final_url = chain[-1]
        headers = dict(page.headers or {})
        content_type = str(headers.get("content-type", headers.get("Content-Type", "")))
        return FetchedPublicSource(
            requested_url=requested,
            final_url=final_url,
            status=int(page.status),
            body=bytes(page.body),
            content_type=content_type,
            accessed_at=datetime.now(timezone.utc).isoformat(),
            redirect_chain=chain,
            source_kind="public_web",
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
        canonical_vacancy_loader: CanonicalCollectorVacancyLoader | None = None,
    ) -> None:
        self.plan = plan
        self.root = _private_external_root(archive_root, repository_root)
        self.fetcher = fetcher or ScraplingPublicSourceFetcher()
        self.canonical_vacancy_loader = canonical_vacancy_loader
        self.last_materialization: MaterializedPublicResearch | None = None

    def _validate_plan(self, task: ResearchTask) -> None:
        if (
            self.plan.profile_id != task.profile_id
            or self.plan.job_key != task.job_key
            or self.plan.company != task.company
            or self.plan.role != task.title
        ):
            raise PublicResearchError("research plan differs from the leased task")
        if self.plan.schema_version != "market-aligner.public-research-plan.v2":
            raise PublicResearchError("research plan schema is unsupported")
        bindings = (
            (self.plan.source_content_sha256, task.source_content_sha256),
            (self.plan.vacancy_snapshot_sha256, task.vacancy_snapshot_sha256),
            (self.plan.promotion_receipt_sha256, task.promotion_receipt_sha256),
        )
        if any(
            not _SHA256.fullmatch(planned) or planned != leased
            for planned, leased in bindings
        ):
            raise PublicResearchError("research plan vacancy/promotion binding differs")
        ids = [row.citation_id for row in self.plan.citations]
        if not ids or len(ids) != len(set(ids)) or any(not value.strip() for value in ids):
            raise PublicResearchError("research citation identities are empty or duplicated")
        known = set(ids)
        for row in self.plan.citations:
            _safe_public_url(row.url)
            _safe_public_url(row.expected_final_url)
            if not row.title.strip():
                raise PublicResearchError("research citation title is empty")
            if not _SHA256.fullmatch(row.expected_content_sha256):
                raise PublicResearchError("research citation expected hash is invalid")
            if row.source_kind not in {"canonical_vacancy", "public_web"}:
                raise PublicResearchError("research citation source kind is unsupported")
        for claim in self.plan.claims:
            if not claim.claim.strip() or not claim.citation_ids or not claim.supports:
                raise PublicResearchError("research claim is empty or uncited")
            if not set(claim.citation_ids) <= known:
                raise PublicResearchError("research claim cites an unknown source")
            if set(claim.citation_ids) != {row.citation_id for row in claim.supports}:
                raise PublicResearchError("research claim support identities differ")
            for support in claim.supports:
                match = _BYTE_SELECTOR.fullmatch(support.selector)
                if (
                    support.citation_id not in known
                    or match is None
                    or int(match.group(1)) >= int(match.group(2))
                    or not support.excerpt
                ):
                    raise PublicResearchError("research claim support selector is invalid")
            if not 0 <= float(claim.confidence) <= 1:
                raise PublicResearchError("research confidence is outside [0,1]")
        canonical = [
            row for row in self.plan.citations if row.source_kind == "canonical_vacancy"
        ]
        if len(canonical) != 1:
            raise PublicResearchError("research plan lacks the exact canonical vacancy source")
        if self.plan.production_authority is not True or len(self.plan.citations) != 1:
            raise PublicResearchError(
                "v2 production research permits only canonical collector vacancy bytes"
            )
        if not isinstance(self.canonical_vacancy_loader, CanonicalCollectorVacancyLoader):
            raise PublicResearchError(
                "v2 production research requires the canonical collector loader"
            )

    def materialize(self, task: ResearchTask) -> MaterializedPublicResearch:
        self._validate_plan(task)
        entries: list[dict[str, object]] = []
        citations: list[SourceCitation] = []
        fetched_by_id: dict[str, FetchedPublicSource] = {}
        for planned in sorted(self.plan.citations, key=lambda row: row.citation_id):
            fetched = (
                self.canonical_vacancy_loader(task)
                if planned.source_kind == "canonical_vacancy"
                else self.fetcher(planned.url)
            )
            if fetched is None:
                raise PublicResearchError("canonical vacancy source was not supplied")
            if fetched.requested_url != planned.url:
                raise PublicResearchError("fetcher substituted the requested source")
            if fetched.final_url != planned.expected_final_url:
                raise PublicResearchError("fetcher substituted the final source")
            if fetched.source_kind != planned.source_kind:
                raise PublicResearchError("fetcher substituted the source authority kind")
            if (
                fetched.source_kind == "canonical_vacancy"
                and fetched.authority_source_content_sha256
                != self.plan.source_content_sha256
            ):
                raise PublicResearchError(
                    "canonical vacancy bytes differ from collector source authority"
                )
            if fetched.status != 200 or not fetched.body:
                raise PublicResearchError("research source did not return a non-empty HTTP 200")
            if len(fetched.body) > _MAX_SOURCE_BYTES:
                raise PublicResearchError("research source exceeds the archive size limit")
            _safe_public_url(fetched.final_url)
            if not fetched.accessed_at.endswith(("+00:00", "Z")):
                raise PublicResearchError("research source time is not explicit UTC")
            object_sha = _sha256(fetched.body)
            if object_sha != planned.expected_content_sha256:
                raise PublicResearchError("research source differs from its reviewed content hash")
            metadata = {
                "accessed_at": fetched.accessed_at,
                "citation_id": planned.citation_id,
                "content_sha256": object_sha,
                "content_type": fetched.content_type,
                "final_url": fetched.final_url,
                "requested_url": fetched.requested_url,
                "redirect_chain": list(fetched.redirect_chain or (fetched.final_url,)),
                "schema_version": "market-aligner.public-research-source.v2",
                "source_kind": fetched.source_kind,
                "status": fetched.status,
                "title": planned.title,
            }
            metadata_bytes = _canonical_bytes(metadata)
            metadata_sha = _sha256(metadata_bytes)
            _write_exact(self.root, "objects", object_sha, fetched.body)
            _write_exact(self.root, "metadata", f"{metadata_sha}.json", metadata_bytes)
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
                    fetched.source_kind,
                )
            )
            fetched_by_id[planned.citation_id] = fetched
        claims: list[ResearchClaim] = []
        for row in self.plan.claims:
            supports: list[ClaimSupport] = []
            for planned_support in row.supports:
                body = fetched_by_id[planned_support.citation_id].body
                match = _BYTE_SELECTOR.fullmatch(planned_support.selector)
                assert match is not None
                start, end = int(match.group(1)), int(match.group(2))
                if end > len(body):
                    raise PublicResearchError(
                        "research support selector exceeds archived source"
                    )
                selected = body[start:end]
                try:
                    excerpt = selected.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PublicResearchError(
                        "research support is not exact UTF-8 text"
                    ) from exc
                if excerpt != planned_support.excerpt:
                    raise PublicResearchError(
                        "research claim is unsupported by archived bytes"
                    )
                if " ".join(row.claim.split()) != " ".join(excerpt.split()):
                    raise PublicResearchError(
                        "production research claims must be verbatim source excerpts"
                    )
                supports.append(
                    ClaimSupport(
                        planned_support.citation_id,
                        planned_support.selector,
                        excerpt,
                        _sha256(selected),
                    )
                )
            claims.append(
                ResearchClaim(row.claim, row.citation_ids, row.confidence, tuple(supports))
            )
        dossier = ResearchDossier(
            task.profile_id,
            task.job_key,
            task.company,
            task.title,
            tuple(claims),
            tuple(citations),
            self.plan.unknowns,
            self.plan.source_content_sha256,
            self.plan.vacancy_snapshot_sha256,
            self.plan.promotion_receipt_sha256,
            next(
                row.content_sha256
                for row in citations
                if row.source_kind == "canonical_vacancy"
            ),
            "market-aligner.employer-dossier.v2",
        )
        dossier.validate()
        dossier_payload = json.dumps(asdict(dossier), ensure_ascii=False, sort_keys=True)
        dossier_sha = _sha256(dossier_payload.encode("utf-8"))
        receipt_body = {
            "application_authority": False,
            "claim_semantic_authority": "verbatim_source_text_v2",
            "canonical_vacancy_object_sha256": (
                dossier.canonical_vacancy_object_sha256
            ),
            "dossier_sha256": dossier_sha,
            "entries": entries,
            "job_key": task.job_key,
            "promotion_receipt_sha256": self.plan.promotion_receipt_sha256,
            "profile_id": task.profile_id,
            "production_authority": True,
            "release_authority": False,
            "schema_version": "market-aligner.public-research-materialization.v2",
            "source_content_sha256": self.plan.source_content_sha256,
            "vacancy_snapshot_sha256": self.plan.vacancy_snapshot_sha256,
        }
        semantic_receipt_sha = _sha256(_canonical_bytes(receipt_body))
        receipt = {
            **receipt_body,
            "semantic_receipt_sha256": semantic_receipt_sha,
        }
        receipt_bytes = _canonical_bytes(receipt)
        receipt_file_sha = _sha256(receipt_bytes)
        receipt_path = _write_exact(
            self.root,
            "receipts",
            f"{semantic_receipt_sha}.json",
            receipt_bytes,
        )
        result = MaterializedPublicResearch(
            dossier,
            dossier_sha,
            receipt_path,
            semantic_receipt_sha,
            receipt_file_sha,
            self.root,
        )
        self.last_materialization = result
        return result

    def research(self, task: ResearchTask) -> ResearchDossier:
        """ResearchProvider interface used by the canonical ResearchWorker."""

        return self.materialize(task).dossier


__all__ = [
    "FetchedPublicSource",
    "CanonicalCollectorVacancyLoader",
    "MaterializedPublicResearch",
    "PlannedCitation",
    "PlannedClaim",
    "PlannedSupport",
    "PublicResearchError",
    "PublicResearchPlan",
    "ScraplingPublicSourceFetcher",
    "SourceBoundResearchProvider",
]
