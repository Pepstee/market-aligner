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
import subprocess
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlsplit

from market_aligner.state.vacancies import JobDatabase, VacancyRefreshConflict

from .models import (
    ClaimSupport,
    ResearchClaim,
    ResearchDossier,
    ResearchTask,
    SourceCitation,
    research_refresh_bridge_sha256,
    research_refresh_preserves_source_authority,
)
from .store import AssessmentStore


_MAX_SOURCE_BYTES = 5 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
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


def _directory_identity(descriptor: int) -> tuple[int, int, int, int]:
    details = os.fstat(descriptor)
    if not stat.S_ISDIR(details.st_mode):
        raise PublicResearchError("research archive ancestry is not a directory")
    mode = stat.S_IMODE(details.st_mode)
    if mode & 0o022 and not (details.st_uid == 0 and mode & stat.S_ISVTX):
        raise PublicResearchError("research archive ancestry is writable by another user")
    return details.st_dev, details.st_ino, details.st_uid, mode


def _open_directory_chain(path: Path) -> tuple[list[int], list[tuple[int, int, int, int]]]:
    absolute = path.absolute()
    if not absolute.is_absolute() or ".." in absolute.parts:
        raise PublicResearchError("research archive ancestry is unsafe")
    descriptors = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    identities = [_directory_identity(descriptors[0])]
    try:
        for component in absolute.parts[1:]:
            descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptors[-1],
            )
            descriptors.append(descriptor)
            identities.append(_directory_identity(descriptor))
    except (OSError, PublicResearchError) as exc:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if isinstance(exc, PublicResearchError):
            raise
        raise PublicResearchError("research archive ancestry is unavailable") from exc
    return descriptors, identities


def _verify_directory_chain(
    path: Path,
    descriptors: list[int],
    identities: list[tuple[int, int, int, int]],
) -> None:
    if [_directory_identity(fd) for fd in descriptors] != identities:
        raise PublicResearchError("open research archive ancestry changed")
    check_descriptors, check_identities = _open_directory_chain(path)
    try:
        if check_identities != identities:
            raise PublicResearchError("research archive path ancestry was replaced")
    finally:
        for descriptor in reversed(check_descriptors):
            os.close(descriptor)


def _directory_chain_snapshot(
    path: Path,
) -> tuple[tuple[int, int, int, int], ...]:
    descriptors, identities = _open_directory_chain(path)
    try:
        return tuple(identities)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def _pinned_directory(
    path: Path,
    expected_identities: tuple[tuple[int, int, int, int], ...] | None = None,
):
    descriptors, identities = _open_directory_chain(path)
    if expected_identities is not None and tuple(identities) != expected_identities:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise PublicResearchError("research archive pinned ancestry was replaced")
    try:
        yield descriptors[-1]
    finally:
        try:
            _verify_directory_chain(path, descriptors, identities)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


@contextmanager
def _pinned_category(
    root: Path,
    category: str,
    *,
    create: bool,
    expected_ancestry: tuple[tuple[int, int, int, int], ...] | None = None,
):
    if "/" in category or category in {"", ".", ".."}:
        raise PublicResearchError("research archive category is unsafe")
    with _pinned_directory(root, expected_ancestry) as root_fd:
        if create:
            try:
                os.mkdir(category, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
        try:
            directory_fd = os.open(
                category,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise PublicResearchError("research archive component is unsafe") from exc
        identity: tuple[int, int, int, int] | None = None
        try:
            identity = _directory_identity(directory_fd)
            if identity[2] != os.geteuid() or identity[3] != 0o700:
                raise PublicResearchError("research archive category is not private 0700")
            yield directory_fd
        finally:
            try:
                if identity is not None and _directory_identity(directory_fd) != identity:
                    raise PublicResearchError("open research archive category changed")
                if identity is not None:
                    try:
                        check_fd = os.open(
                            category,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=root_fd,
                        )
                    except OSError as exc:
                        raise PublicResearchError(
                            "research archive category path changed"
                        ) from exc
                    try:
                        if _directory_identity(check_fd) != identity:
                            raise PublicResearchError("research archive category was replaced")
                    finally:
                        os.close(check_fd)
            finally:
                os.close(directory_fd)


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


def _write_exact(
    root: Path,
    category: str,
    name: str,
    value: bytes,
    *,
    expected_ancestry: tuple[tuple[int, int, int, int], ...] | None = None,
) -> Path:
    if "/" in name or name in {"", ".", ".."}:
        raise PublicResearchError("research archive object name is unsafe")
    temporary = f".{name}.{secrets.token_hex(16)}"
    with _pinned_category(
        root, category, create=True, expected_ancestry=expected_ancestry
    ) as directory_fd:
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
            "refresh_bridge_sha256": task.refresh_bridge_sha256,
        }
        if (
            type(task.refresh_event_id) is not int
            or task.refresh_event_id <= 0
            or any(value is None or value == "" for value in required.values())
            or not research_refresh_preserves_source_authority(
                source_content_sha256=task.source_content_sha256,
                old_collector_content_sha256=task.refresh_legacy_content_sha256,
                old_canonical_content_sha256=task.refresh_canonical_content_sha256,
            )
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
                """SELECT q.refresh_event_id,q.refresh_bridge_sha256,q.status,
                          e.event_type,e.actor_kind,
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
                or row["refresh_bridge_sha256"] != task.refresh_bridge_sha256
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
                or research_refresh_bridge_sha256(
                    event_type=str(row["event_type"]),
                    actor_kind=str(row["actor_kind"]),
                    idempotency_key=str(row["idempotency_key"]),
                    payload=payload,
                )
                != task.refresh_bridge_sha256
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
            task.refresh_bridge_sha256,
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


@dataclass(frozen=True)
class RefreshPlanDerivation:
    plan_sha256: str
    plan_path: Path
    semantic_receipt_sha256: str
    receipt_file_sha256: str
    receipt_path: Path
    prior_dossier_sha256: str
    current_canonical_object_sha256: str


@dataclass(frozen=True)
class SelectorOccurrenceReview:
    map_sha256: str
    map_path: Path
    semantic_receipt_sha256: str
    receipt_file_sha256: str
    receipt_path: Path
    prior_dossier_sha256: str
    current_canonical_object_sha256: str


def _private_exact_file(
    path: Path,
    root: Path,
    category: str,
    *,
    label: str,
    expected_ancestry: tuple[tuple[int, int, int, int], ...],
) -> bytes:
    absolute = path.absolute()
    parent = root / category
    if absolute.parent != parent.absolute() or absolute.name in {"", ".", ".."}:
        raise PublicResearchError(f"{label} is outside its fixed archive directory")
    with _pinned_category(
        root,
        category,
        create=False,
        expected_ancestry=expected_ancestry,
    ) as directory_fd:
        try:
            descriptor = os.open(
                absolute.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd
            )
        except OSError as exc:
            raise PublicResearchError(f"{label} is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise PublicResearchError(
                    f"{label} is not a private regular 0600 file"
                )
            with os.fdopen(os.dup(descriptor), "rb") as handle:
                value = handle.read()
            check = os.fstat(descriptor)
            if (check.st_dev, check.st_ino) != identity:
                raise PublicResearchError(f"open {label} changed")
            check_fd = os.open(
                absolute.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd
            )
            try:
                check_metadata = os.fstat(check_fd)
                if (check_metadata.st_dev, check_metadata.st_ino) != identity:
                    raise PublicResearchError(f"{label} was replaced")
            finally:
                os.close(check_fd)
        finally:
            os.close(descriptor)
    if len(value) > _MAX_SOURCE_BYTES:
        raise PublicResearchError(f"{label} exceeds the size limit")
    return value


def _repository_source_identity(repository_root: Path) -> dict[str, str]:
    source = Path(__file__).resolve(strict=True)
    try:
        commit = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicResearchError("repository identity is unavailable") from exc
    if not _GIT_OID.fullmatch(commit):
        raise PublicResearchError("repository commit identity is invalid")
    return {
        "repository_commit_oid": commit,
        "repository_root": str(repository_root),
        "source_file": str(source.relative_to(repository_root)),
        "source_file_sha256": _sha256(source.read_bytes()),
    }


def _research_dossier_from_document(document: object) -> ResearchDossier:
    if not isinstance(document, dict):
        raise PublicResearchError("prior research dossier is not an object")
    try:
        claims = tuple(
            ResearchClaim(
                str(row["claim"]),
                tuple(str(value) for value in row["citation_ids"]),
                float(row["confidence"]),
                tuple(
                    ClaimSupport(
                        str(support["citation_id"]),
                        str(support["selector"]),
                        str(support["excerpt"]),
                        str(support["excerpt_sha256"]),
                    )
                    for support in row.get("supports", ())
                ),
            )
            for row in document["claims"]
        )
        citations = tuple(
            SourceCitation(
                str(row["citation_id"]),
                str(row["url"]),
                str(row["title"]),
                str(row["accessed_at"]),
                str(row["content_sha256"]),
                str(row.get("source_kind", "public_web")),
            )
            for row in document["citations"]
        )
        dossier = ResearchDossier(
            profile_id=str(document["profile_id"]),
            job_key=str(document["job_key"]),
            company=str(document["company"]),
            role=str(document["role"]),
            claims=claims,
            citations=citations,
            unknowns=tuple(str(value) for value in document.get("unknowns", ())),
            source_content_sha256=document.get("source_content_sha256"),
            vacancy_snapshot_sha256=document.get("vacancy_snapshot_sha256"),
            promotion_receipt_sha256=document.get("promotion_receipt_sha256"),
            canonical_vacancy_object_sha256=document.get(
                "canonical_vacancy_object_sha256"
            ),
            schema_version=str(document.get("schema_version", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PublicResearchError("prior research dossier shape is invalid") from exc
    dossier.validate()
    return dossier


class RefreshDerivedResearchProvider:
    """Derive an unchanged-claims v2 plan for one verified refresh lease."""

    def __init__(
        self,
        *,
        store: AssessmentStore,
        canonical_vacancy_loader: CanonicalCollectorVacancyLoader,
        repository_root: Path,
        archive_root: Path,
        selector_review_receipt_path: Path | None = None,
    ) -> None:
        self.store = store
        self.loader = canonical_vacancy_loader
        self.root = _private_external_root(archive_root, repository_root)
        self._archive_ancestry = _directory_chain_snapshot(self.root)
        self.repository_root = repository_root.resolve(strict=True)
        self.last_materialization: MaterializedPublicResearch | None = None
        self.last_derivation: RefreshPlanDerivation | None = None
        self.selector_review_receipt_path = selector_review_receipt_path
        self.last_selector_review: SelectorOccurrenceReview | None = None
        self._selector_map: dict[str, str] | None = None

    def _load_prior(self, task: ResearchTask) -> tuple[ResearchDossier, bytes, str]:
        if task.refresh_event_id is None or task.refresh_bridge_sha256 is None:
            raise PublicResearchError("research-run-one requires a refresh-linked task")
        with self.store.connection() as connection:
            row = connection.execute(
                """SELECT q.refresh_event_id,q.refresh_bridge_sha256,
                          d.dossier_json,d.dossier_hash,e.payload_json
                   FROM employer_research_queue q
                   JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   JOIN assessment_events e
                     ON e.id=q.refresh_event_id
                    AND e.profile_id=q.profile_id AND e.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (task.profile_id, task.job_key),
            ).fetchone()
        if row is None:
            raise PublicResearchError("refresh-linked prior dossier is unavailable")
        exact_bytes = str(row["dossier_json"]).encode("utf-8")
        digest = _sha256(exact_bytes)
        try:
            event_payload = json.loads(str(row["payload_json"]))
            document = json.loads(exact_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicResearchError("prior dossier or refresh event is invalid JSON") from exc
        if (
            row["refresh_event_id"] != task.refresh_event_id
            or row["refresh_bridge_sha256"] != task.refresh_bridge_sha256
            or digest != row["dossier_hash"]
            or digest != task.refresh_prior_dossier_sha256
            or not isinstance(event_payload, dict)
            or event_payload.get("prior_dossier_hash") != digest
            or event_payload.get("refresh_bridge_sha256")
            != task.refresh_bridge_sha256
        ):
            raise PublicResearchError("prior dossier differs from refresh authority")
        dossier = _research_dossier_from_document(document)
        if (
            json.dumps(asdict(dossier), ensure_ascii=False, sort_keys=True).encode("utf-8")
            != exact_bytes
            or dossier.profile_id != task.profile_id
            or dossier.job_key != task.job_key
            or dossier.company != task.company
            or dossier.role != task.title
            or dossier.source_content_sha256 != task.source_content_sha256
            or dossier.vacancy_snapshot_sha256 != task.vacancy_snapshot_sha256
            or dossier.promotion_receipt_sha256 != task.promotion_receipt_sha256
        ):
            raise PublicResearchError("prior dossier semantic authority differs from task")
        return dossier, exact_bytes, digest

    def _read_prior_object(self, dossier: ResearchDossier) -> bytes:
        digest = dossier.canonical_vacancy_object_sha256
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise PublicResearchError("prior dossier lacks canonical object authority")
        path = self.root / "objects" / digest
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise PublicResearchError("prior canonical object is unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
        ):
            raise PublicResearchError("prior canonical object is unsafe")
        value = path.read_bytes()
        if _sha256(value) != digest:
            raise PublicResearchError("prior canonical object hash differs")
        return value

    def _selector_map_rows(
        self,
        prior: ResearchDossier,
        prior_bytes: bytes,
        current: FetchedPublicSource,
        rows: object,
    ) -> dict[str, str]:
        if not isinstance(rows, list):
            raise PublicResearchError("selector review rows are not a list")
        mapping: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "prior_selector", "reviewed_current_selector"
            }:
                raise PublicResearchError("selector review row shape is invalid")
            prior_selector = row["prior_selector"]
            current_selector = row["reviewed_current_selector"]
            if (
                not isinstance(prior_selector, str)
                or not isinstance(current_selector, str)
                or prior_selector in mapping
            ):
                raise PublicResearchError("selector review rows are not one-to-one")
            mapping[prior_selector] = current_selector

        supports = [support for claim in prior.claims for support in claim.supports]
        prior_selectors = [support.selector for support in supports]
        if len(set(prior_selectors)) != len(prior_selectors):
            raise PublicResearchError("prior dossier has duplicate support selectors")
        if set(mapping) != set(prior_selectors) or len(mapping) != len(supports):
            raise PublicResearchError("selector review does not cover every support exactly once")

        for claim in prior.claims:
            for support in claim.supports:
                prior_match = _BYTE_SELECTOR.fullmatch(support.selector)
                current_match = _BYTE_SELECTOR.fullmatch(mapping[support.selector])
                if prior_match is None or current_match is None:
                    raise PublicResearchError("selector review contains an invalid selector")
                old_start, old_end = int(prior_match.group(1)), int(prior_match.group(2))
                new_start, new_end = int(current_match.group(1)), int(current_match.group(2))
                old_selected = prior_bytes[old_start:old_end]
                new_selected = current.body[new_start:new_end]
                try:
                    old_excerpt = old_selected.decode("utf-8")
                    new_excerpt = new_selected.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PublicResearchError("selector review support is not UTF-8") from exc
                normalized_claim = " ".join(claim.claim.split())
                if (
                    old_end > len(prior_bytes)
                    or new_end > len(current.body)
                    or old_excerpt != support.excerpt
                    or new_excerpt != support.excerpt
                    or _sha256(old_selected) != support.excerpt_sha256
                    or _sha256(new_selected) != support.excerpt_sha256
                    or normalized_claim != " ".join(old_excerpt.split())
                    or normalized_claim != " ".join(new_excerpt.split())
                ):
                    raise PublicResearchError("selector review occurrence differs from claim authority")
        return mapping

    def _config_identity(self) -> dict[str, str]:
        path = self.loader.collection_config_path
        if path is None:
            raise PublicResearchError("selector review requires exact collection config")
        try:
            resolved = path.resolve(strict=True)
            value = resolved.read_bytes()
        except OSError as exc:
            raise PublicResearchError("collection config identity is unavailable") from exc
        return {
            "collection_config_path": str(resolved),
            "collection_config_sha256": _sha256(value),
        }

    def admit_selector_review(
        self, task: ResearchTask, input_path: Path
    ) -> SelectorOccurrenceReview:
        current = self.loader(task)
        prior, _prior_dossier_bytes, prior_digest = self._load_prior(task)
        prior_object = self._read_prior_object(prior)
        with _pinned_category(
            self.root,
            "review-inputs",
            create=True,
            expected_ancestry=self._archive_ancestry,
        ):
            pass
        input_bytes = _private_exact_file(
            input_path,
            self.root,
            "review-inputs",
            label="selector review input",
            expected_ancestry=self._archive_ancestry,
        )
        try:
            document = json.loads(input_bytes)
        except json.JSONDecodeError as exc:
            raise PublicResearchError("selector review input is invalid JSON") from exc
        if input_bytes != _canonical_bytes(document) or not isinstance(document, dict):
            raise PublicResearchError("selector review input is not canonical JSON")
        if set(document) != {"job_key", "profile_id", "rows", "schema_version"} or (
            document.get("schema_version")
            != "market-aligner.selector-occurrence-review-input.v1"
            or document.get("profile_id") != task.profile_id
            or document.get("job_key") != task.job_key
        ):
            raise PublicResearchError("selector review input scope is invalid")
        self._selector_map_rows(prior, prior_object, current, document["rows"])
        map_bytes = input_bytes
        map_sha = _sha256(map_bytes)
        map_path = _write_exact(
            self.root,
            "selector-review-maps",
            f"{map_sha}.json",
            map_bytes,
            expected_ancestry=self._archive_ancestry,
        )
        identities = {
            **_repository_source_identity(self.repository_root),
            **self._config_identity(),
        }
        receipt_body = {
            "application_authority": False,
            "authority_mode": "selector_occurrence_only",
            "current_canonical_object_sha256": _sha256(current.body),
            "job_key": task.job_key,
            "map_file_sha256": map_sha,
            "map_sha256": map_sha,
            "prior_canonical_object_sha256": prior.canonical_vacancy_object_sha256,
            "prior_dossier_sha256": prior_digest,
            "profile_id": task.profile_id,
            "refresh_bridge_sha256": task.refresh_bridge_sha256,
            "refresh_event_id": task.refresh_event_id,
            "refresh_event_idempotency_key": task.refresh_event_idempotency_key,
            "release_authority": False,
            "schema_version": "market-aligner.selector-occurrence-review-admission.v1",
            **identities,
        }
        semantic_sha = _sha256(_canonical_bytes(receipt_body))
        receipt_bytes = _canonical_bytes(
            {**receipt_body, "semantic_receipt_sha256": semantic_sha}
        )
        receipt_path = _write_exact(
            self.root,
            "selector-review-receipts",
            f"{semantic_sha}.json",
            receipt_bytes,
            expected_ancestry=self._archive_ancestry,
        )
        result = SelectorOccurrenceReview(
            map_sha, map_path, semantic_sha, _sha256(receipt_bytes), receipt_path,
            prior_digest, _sha256(current.body),
        )
        self.last_selector_review = result
        return result

    def _load_admitted_selector_review(
        self, task: ResearchTask
    ) -> dict[str, str] | None:
        if self.selector_review_receipt_path is None:
            return None
        receipt_bytes = _private_exact_file(
            self.selector_review_receipt_path,
            self.root,
            "selector-review-receipts",
            label="selector review admission receipt",
            expected_ancestry=self._archive_ancestry,
        )
        try:
            receipt = json.loads(receipt_bytes)
        except json.JSONDecodeError as exc:
            raise PublicResearchError("selector review receipt is invalid JSON") from exc
        semantic = receipt.get("semantic_receipt_sha256") if isinstance(receipt, dict) else None
        body = dict(receipt) if isinstance(receipt, dict) else {}
        body.pop("semantic_receipt_sha256", None)
        identities = {
            **_repository_source_identity(self.repository_root),
            **self._config_identity(),
        }
        if (
            receipt_bytes != _canonical_bytes(receipt)
            or not isinstance(semantic, str)
            or _sha256(_canonical_bytes(body)) != semantic
            or self.selector_review_receipt_path.name != f"{semantic}.json"
            or body.get("schema_version")
            != "market-aligner.selector-occurrence-review-admission.v1"
            or body.get("authority_mode") != "selector_occurrence_only"
            or body.get("application_authority") is not False
            or body.get("release_authority") is not False
            or body.get("profile_id") != task.profile_id
            or body.get("job_key") != task.job_key
            or body.get("refresh_event_id") != task.refresh_event_id
            or body.get("refresh_event_idempotency_key")
            != task.refresh_event_idempotency_key
            or body.get("refresh_bridge_sha256") != task.refresh_bridge_sha256
            or any(body.get(key) != value for key, value in identities.items())
        ):
            raise PublicResearchError("selector review receipt differs from current authority")
        current = self.loader(task)
        prior, _prior_dossier_bytes, prior_digest = self._load_prior(task)
        prior_object = self._read_prior_object(prior)
        if (
            body.get("prior_dossier_sha256") != prior_digest
            or body.get("prior_canonical_object_sha256")
            != prior.canonical_vacancy_object_sha256
            or body.get("current_canonical_object_sha256") != _sha256(current.body)
        ):
            raise PublicResearchError("selector review source authority changed")
        map_sha = body.get("map_sha256")
        if not isinstance(map_sha, str) or not _SHA256.fullmatch(map_sha):
            raise PublicResearchError("selector review map identity is invalid")
        map_path = self.root / "selector-review-maps" / f"{map_sha}.json"
        map_bytes = _private_exact_file(
            map_path,
            self.root,
            "selector-review-maps",
            label="admitted selector review map",
            expected_ancestry=self._archive_ancestry,
        )
        try:
            map_document = json.loads(map_bytes)
        except json.JSONDecodeError as exc:
            raise PublicResearchError("admitted selector review map is invalid JSON") from exc
        if (
            map_bytes != _canonical_bytes(map_document)
            or _sha256(map_bytes) != map_sha
            or body.get("map_file_sha256") != map_sha
        ):
            raise PublicResearchError("admitted selector review map differs")
        mapping = self._selector_map_rows(
            prior, prior_object, current, map_document.get("rows")
        )
        self.last_selector_review = SelectorOccurrenceReview(
            map_sha, map_path, semantic, _sha256(receipt_bytes),
            self.selector_review_receipt_path, prior_digest, _sha256(current.body),
        )
        return mapping

    def preflight(self, task: ResearchTask) -> None:
        self._selector_map = self._load_admitted_selector_review(task)

    def validate_completion(self, task: ResearchTask) -> None:
        expected = dict(self._selector_map) if self._selector_map is not None else None
        actual = self._load_admitted_selector_review(task)
        if actual != expected:
            raise PublicResearchError("selector review changed before completion")

    def _derive_plan(
        self,
        task: ResearchTask,
        prior: ResearchDossier,
        prior_bytes: bytes,
        prior_digest: str,
        current: FetchedPublicSource,
    ) -> PublicResearchPlan:
        if (
            len(prior.citations) != 1
            or prior.citations[0].source_kind != "canonical_vacancy"
            or prior.citations[0].content_sha256
            != prior.canonical_vacancy_object_sha256
        ):
            raise PublicResearchError(
                "refresh derivation permits no prior public-web authority"
            )
        citation = prior.citations[0]
        planned_claims: list[PlannedClaim] = []
        for claim in prior.claims:
            if (
                tuple(claim.citation_ids) != (citation.citation_id,)
                or not claim.supports
                or {support.citation_id for support in claim.supports}
                != {citation.citation_id}
            ):
                raise PublicResearchError("prior claim authority is not canonical-only")
            planned_supports: list[PlannedSupport] = []
            for support in claim.supports:
                match = _BYTE_SELECTOR.fullmatch(support.selector)
                if match is None:
                    raise PublicResearchError("prior support selector is invalid")
                start, end = int(match.group(1)), int(match.group(2))
                selected = prior_bytes[start:end]
                try:
                    excerpt = selected.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PublicResearchError("prior support is not UTF-8") from exc
                if (
                    end > len(prior_bytes)
                    or excerpt != support.excerpt
                    or _sha256(selected) != support.excerpt_sha256
                    or " ".join(claim.claim.split())
                    != " ".join(excerpt.split())
                ):
                    raise PublicResearchError("prior claim support differs from dossier")
                reviewed_selector = (
                    self._selector_map.get(support.selector, support.selector)
                    if self._selector_map is not None
                    else support.selector
                )
                reviewed_match = _BYTE_SELECTOR.fullmatch(reviewed_selector)
                if reviewed_match is None:
                    raise PublicResearchError("reviewed current selector is invalid")
                current_start, current_end = (
                    int(reviewed_match.group(1)), int(reviewed_match.group(2))
                )
                current_selected = current.body[current_start:current_end]
                try:
                    current_excerpt = current_selected.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PublicResearchError(
                        "current support at prior selector is not UTF-8"
                    ) from exc
                if (
                    current_end > len(current.body)
                    or current_excerpt != support.excerpt
                    or _sha256(current_selected) != support.excerpt_sha256
                    or " ".join(claim.claim.split())
                    != " ".join(current_excerpt.split())
                ):
                    raise PublicResearchError(
                        "current claim differs at the exact prior selector"
                    )
                planned_supports.append(
                    PlannedSupport(
                        citation.citation_id,
                        reviewed_selector,
                        support.excerpt,
                    )
                )
            planned_claims.append(
                PlannedClaim(
                    claim.claim,
                    tuple(claim.citation_ids),
                    claim.confidence,
                    tuple(planned_supports),
                )
            )
        plan = PublicResearchPlan(
            profile_id=task.profile_id,
            job_key=task.job_key,
            company=task.company,
            role=task.title,
            citations=(
                PlannedCitation(
                    citation.citation_id,
                    citation.url,
                    citation.title,
                    _sha256(current.body),
                    current.final_url,
                    "canonical_vacancy",
                ),
            ),
            claims=tuple(planned_claims),
            source_content_sha256=task.source_content_sha256 or "",
            vacancy_snapshot_sha256=task.vacancy_snapshot_sha256 or "",
            promotion_receipt_sha256=task.promotion_receipt_sha256 or "",
            unknowns=tuple(prior.unknowns),
        )
        plan_bytes = _canonical_bytes(asdict(plan))
        plan_sha = _sha256(plan_bytes)
        plan_path = _write_exact(self.root, "plans", f"{plan_sha}.json", plan_bytes)
        receipt_body = {
            "application_authority": False,
            "current_canonical_object_sha256": _sha256(current.body),
            "job_key": task.job_key,
            "plan_file_sha256": plan_sha,
            "plan_sha256": plan_sha,
            "prior_dossier_sha256": prior_digest,
            "profile_id": task.profile_id,
            "promotion_receipt_sha256": task.promotion_receipt_sha256,
            "refresh_bridge_sha256": task.refresh_bridge_sha256,
            "refresh_event_id": task.refresh_event_id,
            "refresh_event_idempotency_key": task.refresh_event_idempotency_key,
            "release_authority": False,
            "schema_version": "market-aligner.refresh-plan-derivation.v1",
            "source_content_sha256": task.source_content_sha256,
            "vacancy_snapshot_sha256": task.vacancy_snapshot_sha256,
        }
        semantic_sha = _sha256(_canonical_bytes(receipt_body))
        receipt_bytes = _canonical_bytes(
            {**receipt_body, "semantic_receipt_sha256": semantic_sha}
        )
        receipt_file_sha = _sha256(receipt_bytes)
        receipt_path = _write_exact(
            self.root, "derivations", f"{semantic_sha}.json", receipt_bytes
        )
        self.last_derivation = RefreshPlanDerivation(
            plan_sha,
            plan_path,
            semantic_sha,
            receipt_file_sha,
            receipt_path,
            prior_digest,
            _sha256(current.body),
        )
        return plan

    def research(self, task: ResearchTask) -> ResearchDossier:
        self.preflight(task)
        current = self.loader(task)
        prior, _exact_dossier_bytes, prior_digest = self._load_prior(task)
        prior_object = self._read_prior_object(prior)
        plan = self._derive_plan(
            task, prior, prior_object, prior_digest, current
        )

        def no_public_web(_url: str) -> FetchedPublicSource:
            raise PublicResearchError("refresh derivation forbids public-web fetching")

        delegate = SourceBoundResearchProvider(
            plan=plan,
            repository_root=self.repository_root,
            archive_root=self.root,
            fetcher=no_public_web,
            canonical_vacancy_loader=self.loader,
        )
        dossier = delegate.research(task)
        self.last_materialization = delegate.last_materialization
        return dossier


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
    "RefreshDerivedResearchProvider",
    "RefreshPlanDerivation",
    "SelectorOccurrenceReview",
]
