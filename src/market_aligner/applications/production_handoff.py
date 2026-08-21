"""Fresh production Market Aligner handoff construction from durable state.

This module replaces operator-authored handoff manifests.  It reads the exact
profile, processing promotion, vacancy source and employer-research records
that already own those facts, revalidates their current bindings, and emits a
non-release protected outbox bundle.  It never calls a model or a provider.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.producer import (
    HandoffReference,
    WrittenHandoffBundle,
    write_protected_handoff_bundle,
)
from market_aligner.assessment.scoring import ScoringParams
from market_aligner.research.models import (
    RESEARCH_ARCHIVE_ROOT_POLICY_SHA256,
    ClaimSupport,
    ResearchClaim,
    ResearchDossier,
    ResearchEvidenceBinding,
    SourceCitation,
)
from market_aligner.research.store import (
    research_refresh_bridge_sha256,
    research_refresh_preserves_source_authority,
)
from market_aligner.service.api import MarketAlignerService
from market_aligner.state.vacancies import JobDatabase, VacancyRefreshConflict

PRODUCTION_HANDOFF_TRUST_ROOT_ID = "gigabyte-market-aligner-protected-outbox-v1"
PRODUCTION_VACANCY_MAXIMUM_AGE_SECONDS = 21_600
PRODUCTION_DOSSIER_MAXIMUM_AGE_SECONDS = 86_400
PRODUCTION_CANDIDATE_AUTHORITY_PATH = Path(
    "/home/gutua/software-factory/protected/majaa-20260810/candidate/candidate_authority.json"
)
PRODUCTION_CANDIDATE_AUTHORITY_SHA256 = (
    "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProductionHandoffError(ValueError):
    """Fail-closed production handoff error with a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class _ProductionHandoffDeployment:
    """Pins supplied only by JAA's root-owned deployment configuration."""

    data_home: Path
    repository_root: Path
    output_root: Path
    collection_config_path: Path
    collection_config_sha256: str
    collection_config_file_sha256: str
    deployment_configuration_sha256: str
    research_archive_root_identity: str


@dataclass(frozen=True)
class ProductionHandoffReceipt:
    source_job_key: str
    handoff_job_key: str
    application_id: str
    handoff_root_sha256: str
    source_record_sha256: str
    manifest_sha256: str
    bundle_path: Path
    canonical_vacancy_metadata_sha256: str
    canonical_vacancy_object_sha256: str
    research_semantic_receipt_sha256: str
    research_receipt_file_sha256: str
    research_archive_root_identity: str
    research_vacancy_snapshot_sha256: str
    source_content_sha256: str
    processing_promotion_sha256: str
    employer_dossier_sha256: str
    execution_receipt_path: Path
    execution_receipt_sha256: str
    environment: str = "production"
    release_authority: bool = False

    def document(self) -> dict[str, object]:
        return {
            "application_id": self.application_id,
            "bundle_path": str(self.bundle_path),
            "employer_dossier_sha256": self.employer_dossier_sha256,
            "environment": self.environment,
            "execution_receipt_path": str(self.execution_receipt_path),
            "execution_receipt_sha256": self.execution_receipt_sha256,
            "handoff_job_key": self.handoff_job_key,
            "handoff_root_sha256": self.handoff_root_sha256,
            "manifest_sha256": self.manifest_sha256,
            "canonical_vacancy_metadata_sha256": self.canonical_vacancy_metadata_sha256,
            "canonical_vacancy_object_sha256": self.canonical_vacancy_object_sha256,
            "research_archive_root_identity": self.research_archive_root_identity,
            "research_receipt_file_sha256": self.research_receipt_file_sha256,
            "research_semantic_receipt_sha256": self.research_semantic_receipt_sha256,
            "research_vacancy_snapshot_sha256": self.research_vacancy_snapshot_sha256,
            "source_content_sha256": self.source_content_sha256,
            "processing_promotion_sha256": self.processing_promotion_sha256,
            "release_token_issued": False,
            "schema_version": "market-aligner.production-handoff-receipt.v2",
            "source_job_key": self.source_job_key,
            "source_record_sha256": self.source_record_sha256,
            "submission_authority": False,
            "trust_root_id": PRODUCTION_HANDOFF_TRUST_ROOT_ID,
        }


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return canonical_json_bytes(value)


def _instant(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith(("+00:00", "Z")):
        raise ProductionHandoffError(
            "invalid_timestamp", f"{label} must be explicit UTC"
        )
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise ProductionHandoffError(
            "invalid_timestamp", f"{label} is invalid"
        ) from exc
    if parsed.utcoffset() != timedelta(0):
        raise ProductionHandoffError("invalid_timestamp", f"{label} must be UTC")
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _open_directory_chain(path: Path, *, require_private_leaf: bool) -> int:
    """Open an absolute directory descriptor-relative without following links."""

    if not path.is_absolute() or ".." in path.parts:
        raise ProductionHandoffError("unsafe_path", "protected path must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if require_private_leaf and (
            metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ProductionHandoffError(
                "unsafe_permissions", "protected directory is not private to its owner"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular(path: Path, label: str, *, private: bool = False) -> bytes:
    parent_fd = _open_directory_chain(
        path.parent.absolute(), require_private_leaf=private
    )
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        os.close(parent_fd)
        raise ProductionHandoffError("unsafe_input", f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
        ):
            raise ProductionHandoffError(
                "unsafe_input", f"{label} is not a protected regular file"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)
        os.close(parent_fd)


class _SecureArchive:
    """Descriptor-safe reader rooted at one protected data-home identity."""

    def __init__(self, data_home: Path, identity: str) -> None:
        relative = Path(identity)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ProductionHandoffError(
                "research_archive", "store archive identity is unsafe"
            )
        descriptor = _open_directory_chain(
            data_home.absolute(), require_private_leaf=True
        )
        try:
            for component in relative.parts:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                metadata = os.fstat(next_descriptor)
                if (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    os.close(next_descriptor)
                    raise ProductionHandoffError(
                        "research_archive", "archive directory is not private"
                    )
                os.close(descriptor)
                descriptor = next_descriptor
            self._descriptor = descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        os.close(self._descriptor)

    def read(self, category: str, name: str) -> bytes:
        if (
            category not in {"metadata", "objects", "receipts"}
            or "/" in name
            or name in {"", ".", ".."}
        ):
            raise ProductionHandoffError(
                "research_archive", "archive component is invalid"
            )
        directory = os.open(
            category,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=self._descriptor,
        )
        try:
            directory_metadata = os.fstat(directory)
            if (
                directory_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(directory_metadata.st_mode) & 0o077
            ):
                raise ProductionHandoffError(
                    "research_archive", "archive category is not private"
                )
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise ProductionHandoffError(
                        "research_archive", "archive object is not private"
                    )
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 1_048_576)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)


def _write_execution_receipt_bytes(descriptor: int, exact: bytes) -> None:
    view = memoryview(exact)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("execution receipt write did not progress")
        view = view[written:]


def _publish_execution_receipt_noreplace(
    directory_descriptor: int, temporary_name: str, final_name: str
) -> bool:
    """Publish one receipt without replacing an independently published replay."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            directory_descriptor,
            os.fsencode(temporary_name),
            directory_descriptor,
            os.fsencode(final_name),
            1,  # RENAME_NOREPLACE
        )
        == 0
    ):
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        return False
    raise OSError(error, os.strerror(error))


def _persist_execution_receipt(root: Path, semantic_sha256: str, exact: bytes) -> Path:
    """Persist deterministic receipt bytes as receipts/<semantic>.json, create-or-exact."""

    if not _SHA256.fullmatch(semantic_sha256):
        raise ProductionHandoffError("execution_receipt", "receipt identity is invalid")
    root_fd = _open_directory_chain(root.absolute(), require_private_leaf=True)
    try:
        try:
            os.mkdir("receipts", 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        receipts_fd = os.open(
            "receipts",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        try:
            receipts_metadata = os.fstat(receipts_fd)
            if (
                receipts_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(receipts_metadata.st_mode) & 0o077
            ):
                raise ProductionHandoffError(
                    "execution_receipt", "receipt directory is not private"
                )
            name = f"{semantic_sha256}.json"

            def existing_exact() -> bool:
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=receipts_fd,
                    )
                except FileNotFoundError:
                    return False
                try:
                    metadata = os.fstat(descriptor)
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(descriptor, 1_048_576)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or b"".join(chunks) != exact
                    ):
                        raise ProductionHandoffError(
                            "execution_receipt_replay", "stored receipt differs"
                        )
                    return True
                finally:
                    os.close(descriptor)

            if existing_exact():
                return root / "receipts" / name
            temporary_name = f".{name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            try:
                descriptor = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=receipts_fd,
                )
                try:
                    _write_execution_receipt_bytes(descriptor, exact)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                if (
                    not _publish_execution_receipt_noreplace(
                        receipts_fd, temporary_name, name
                    )
                    and not existing_exact()
                ):
                    raise ProductionHandoffError(
                        "execution_receipt", "receipt publication raced"
                    )
                os.fsync(receipts_fd)
            finally:
                try:
                    os.unlink(temporary_name, dir_fd=receipts_fd)
                except FileNotFoundError:
                    pass
            return root / "receipts" / name
        finally:
            os.close(receipts_fd)
    finally:
        os.close(root_fd)


def _document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionHandoffError(
            "invalid_input", f"{label} is invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ProductionHandoffError("invalid_input", f"{label} must be an object")
    return value


def _git_commit(
    repository_root: Path, *, repository_descriptor: int | None = None
) -> str:
    repository = repository_root.resolve(strict=True)
    executing_root = Path(__file__).resolve().parents[3]
    if repository != executing_root:
        raise ProductionHandoffError(
            "producer_repository", "repository root differs from executing source tree"
        )
    working_directory: Path | str = repository
    pinned_identity: tuple[int, int] | None = None
    if repository_descriptor is not None:
        metadata = os.fstat(repository_descriptor)
        current = repository.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != current.st_dev
            or metadata.st_ino != current.st_ino
        ):
            raise ProductionHandoffError(
                "producer_repository", "pinned repository identity differs"
            )
        pinned_identity = (int(metadata.st_dev), int(metadata.st_ino))
        working_directory = f"/proc/self/fd/{repository_descriptor}"
    discovered_root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=working_directory,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if Path(discovered_root).resolve(strict=True) != repository:
        raise ProductionHandoffError(
            "producer_repository", "executing source tree is not the Git root"
        )
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=working_directory,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise ProductionHandoffError(
            "producer_dirty",
            "production handoff requires a completely clean repository",
        )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=working_directory,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ProductionHandoffError("producer_commit", "repository HEAD is invalid")
    if pinned_identity is not None:
        final = os.fstat(repository_descriptor)
        if (int(final.st_dev), int(final.st_ino)) != pinned_identity:
            raise ProductionHandoffError(
                "producer_repository", "pinned repository changed during identity check"
            )
    return commit


def _workable_identity(url: str) -> tuple[str | None, str]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "apply.workable.com":
        raise ProductionHandoffError(
            "official_route", "official observation is not Workable"
        )
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) == 2 and segments[0] == "j":
        tenant, vacancy_id = None, segments[1]
    elif len(segments) == 3 and segments[1] == "j":
        tenant, vacancy_id = segments[0], segments[2]
    else:
        raise ProductionHandoffError(
            "official_route", "Workable vacancy route is not canonical"
        )
    if not re.fullmatch(r"[A-Z0-9]{10}", vacancy_id):
        raise ProductionHandoffError(
            "official_route", "Workable vacancy identity is malformed"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProductionHandoffError(
            "official_route", "Workable URL port is malformed"
        ) from exc
    if (
        parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or port not in {None, 443}
    ):
        raise ProductionHandoffError(
            "official_route", "Workable vacancy URL has unsupported authority"
        )
    return tenant, vacancy_id


def _protected_candidate_authority(
    path: Path, projection: Mapping[str, Any], expected_sha256: str
) -> bytes:
    exact = _read_regular(path, "protected candidate authority", private=True)
    if not _SHA256.fullmatch(expected_sha256) or _sha(exact) != expected_sha256:
        raise ProductionHandoffError(
            "candidate_authority_identity",
            "protected candidate authority differs from deployment-owned pin",
        )
    document = _document(exact, "protected candidate authority")
    candidate_projection = document.get("candidate_projection")
    if (
        document.get("schema_version") != "jaa.production-candidate-authority.v2"
        or not isinstance(candidate_projection, dict)
        or candidate_projection.get("projection_sha256")
        != projection.get("authority_projection_sha256")
    ):
        raise ProductionHandoffError(
            "candidate_authority_binding",
            "protected candidate authority differs from the canonical profile projection",
        )
    return exact


def _validated_dossier(document: Mapping[str, Any]) -> ResearchDossier:
    try:
        citations = tuple(
            SourceCitation(**row) for row in document.get("citations", [])
        )
        claims = tuple(
            ResearchClaim(
                claim=row["claim"],
                citation_ids=tuple(row["citation_ids"]),
                confidence=float(row["confidence"]),
                supports=tuple(
                    ClaimSupport(**support) for support in row.get("supports", [])
                ),
            )
            for row in document.get("claims", [])
        )
        dossier = ResearchDossier(
            profile_id=document["profile_id"],
            job_key=document["job_key"],
            company=document["company"],
            role=document["role"],
            claims=claims,
            citations=citations,
            unknowns=tuple(document.get("unknowns", [])),
            source_content_sha256=document.get("source_content_sha256"),
            vacancy_snapshot_sha256=document.get("vacancy_snapshot_sha256"),
            promotion_receipt_sha256=document.get("promotion_receipt_sha256"),
            canonical_vacancy_object_sha256=document.get(
                "canonical_vacancy_object_sha256"
            ),
            schema_version=document.get("schema_version", ""),
        )
        dossier.validate()
        return dossier
    except (KeyError, TypeError, ValueError) as exc:
        raise ProductionHandoffError(
            "research_dossier", "v2 dossier contract is invalid"
        ) from exc


def _verify_refresh_ancestry(
    data_home: Path,
    envelope: Mapping[str, Any],
    evidence_row: Mapping[str, Any],
    *,
    profile_id: str,
    source_job_key: str,
    dossier_sha256: str,
    promotion_receipt_sha256: str,
    source_content_sha256: str,
    collection_config_path: Path,
    collection_config_sha256: str,
    collection_config_file_sha256: str,
) -> None:
    receipt_sha = str(envelope["collection_refresh_receipt_sha256"])
    receipt_path = (
        data_home / "state" / "collection-refresh-receipts" / f"{receipt_sha}.json"
    )
    config_path = collection_config_path
    if not config_path.is_absolute():
        raise ProductionHandoffError(
            "research_refresh_ancestry", "collection configuration is not absolute"
        )
    if _sha(_read_regular(config_path, "collection configuration")) != (
        collection_config_file_sha256
    ):
        raise ProductionHandoffError(
            "research_refresh_ancestry",
            "collection configuration file identity differs",
        )
    try:
        resolved = JobDatabase.resolve_vacancy_refresh_collector(
            data_home, receipt_path, config_path
        )
        assessment_path = data_home / "state" / "assessments.sqlite3"
        connection = sqlite3.connect(assessment_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("ATTACH DATABASE ? AS collector", (str(resolved.path),))
            connection.execute("BEGIN IMMEDIATE")
            resolved.verify_open_connection(connection, schema="collector")
            verified = resolved.database.verify_vacancy_refresh_receipt(
                receipt_path,
                job_key=source_job_key,
                connection=connection,
                schema="collector",
            )
            refresh_row = connection.execute(
                "SELECT context_json FROM collector.vacancy_refreshes WHERE refresh_id=?",
                (verified.refresh_id,),
            ).fetchone()
            refresh_context = (
                None
                if refresh_row is None
                else json.loads(str(refresh_row["context_json"]))
            )
            row = connection.execute(
                """SELECT q.status,q.refresh_event_id,q.refresh_bridge_sha256,
                          ev.event_type,ev.actor_kind,ev.payload_json,ev.idempotency_key,
                          p.source_content_sha256,p.receipt_sha256 AS promotion_receipt_sha256,
                          d.dossier_hash,
                          re.dossier_hash AS evidence_dossier_hash,
                          re.source_content_sha256 AS evidence_source_content_sha256,
                          re.vacancy_snapshot_sha256,
                          re.promotion_receipt_sha256 AS evidence_promotion_receipt_sha256,
                          re.canonical_vacancy_object_sha256,
                          re.semantic_receipt_sha256,re.receipt_file_sha256,
                          re.archive_root_identity,re.archive_root_policy_sha256,
                          re.receipt_relative_path,re.schema_version
                   FROM employer_research_queue q
                   JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   JOIN employer_research_evidence re
                     ON re.profile_id=q.profile_id AND re.job_key=q.job_key
                   JOIN assessment_events ev
                     ON ev.id=q.refresh_event_id
                    AND ev.profile_id=q.profile_id AND ev.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (profile_id, source_job_key),
            ).fetchone()
            if row is None:
                raise ValueError("refresh ancestry has no current assessment graph")
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                raise ValueError("refresh event payload is not an object")
            expected_event_key = (
                f"research-collection-refresh:{profile_id}:{source_job_key}:"
                f"{verified.transition_sha256}"
            )
            expected_event = {
                "collection_context_sha256": verified.context_sha256,
                "collection_operation_id": verified.operation_id,
                "collection_receipt_file_sha256": verified.receipt_file_sha256,
                "collection_receipt_sha256": verified.receipt_sha256,
                "collection_refresh_id": verified.refresh_id,
                "collection_transition_sha256": verified.transition_sha256,
                "new_fetched_at": verified.new_fetched_at,
                "new_raw_object_sha256": verified.new_raw_object_sha256,
                "old_canonical_content_sha256": verified.old_canonical_content_sha256,
                "old_collector_content_sha256": verified.old_content_sha256,
                "prior_dossier_hash": payload.get("prior_dossier_hash"),
                "promotion_receipt_sha256": promotion_receipt_sha256,
                "source_content_sha256": source_content_sha256,
            }
            expected_bridge = research_refresh_bridge_sha256(
                event_type="employer_research_collection_refresh_queued",
                actor_kind="deterministic",
                idempotency_key=expected_event_key,
                payload=expected_event,
            )
            evidence_fields = {
                "dossier_hash": "evidence_dossier_hash",
                "source_content_sha256": "evidence_source_content_sha256",
                "vacancy_snapshot_sha256": "vacancy_snapshot_sha256",
                "promotion_receipt_sha256": "evidence_promotion_receipt_sha256",
                "canonical_vacancy_object_sha256": "canonical_vacancy_object_sha256",
                "semantic_receipt_sha256": "semantic_receipt_sha256",
                "receipt_file_sha256": "receipt_file_sha256",
                "archive_root_identity": "archive_root_identity",
                "archive_root_policy_sha256": "archive_root_policy_sha256",
                "receipt_relative_path": "receipt_relative_path",
                "schema_version": "schema_version",
            }
            if (
                verified.changed
                or not isinstance(refresh_context, dict)
                or refresh_context.get("config_sha256") != collection_config_sha256
                or verified.old_canonical_content_sha256 != verified.new_content_sha256
                or not research_refresh_preserves_source_authority(
                    source_content_sha256=source_content_sha256,
                    old_collector_content_sha256=verified.old_content_sha256,
                    old_canonical_content_sha256=verified.old_canonical_content_sha256,
                )
                or verified.new_content_sha256
                != envelope["canonical_current_content_sha256"]
                or verified.new_raw_object_sha256
                != envelope["collection_refresh_raw_object_sha256"]
                or verified.receipt_sha256
                != envelope["collection_refresh_receipt_sha256"]
                or verified.receipt_file_sha256
                != envelope["collection_refresh_receipt_file_sha256"]
                or verified.transition_sha256
                != envelope["collection_refresh_transition_sha256"]
                or verified.context_sha256
                != envelope["collection_refresh_context_sha256"]
                or verified.refresh_id != envelope["collection_refresh_id"]
                or verified.operation_id != envelope["collection_refresh_operation_id"]
                or verified.new_fetched_at != envelope["fetched_at"]
                or row["status"] != "completed"
                or row["refresh_event_id"] != envelope["collection_refresh_event_id"]
                or row["event_type"] != "employer_research_collection_refresh_queued"
                or row["actor_kind"] != "deterministic"
                or row["idempotency_key"] != expected_event_key
                or payload
                != {**expected_event, "refresh_bridge_sha256": expected_bridge}
                or row["refresh_bridge_sha256"] != expected_bridge
                or row["source_content_sha256"] != source_content_sha256
                or row["promotion_receipt_sha256"] != promotion_receipt_sha256
                or row["dossier_hash"] != dossier_sha256
                or any(
                    row[row_key] != evidence_row.get(evidence_key)
                    for evidence_key, row_key in evidence_fields.items()
                )
            ):
                raise ValueError("refresh ancestry differs from current authorities")
            reverified = resolved.database.verify_vacancy_refresh_receipt(
                receipt_path,
                job_key=source_job_key,
                connection=connection,
                schema="collector",
            )
            resolved.verify_open_connection(connection, schema="collector")
            if reverified != verified:
                raise ValueError("refresh ancestry changed during locked verification")
            connection.rollback()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError, VacancyRefreshConflict) as exc:
        raise ProductionHandoffError(
            "research_refresh_ancestry",
            "canonical refresh ancestry is not current and exact",
        ) from exc


def _research_evidence(
    data_home: Path,
    evidence_row: Mapping[str, Any],
    *,
    profile_id: str,
    source_job_key: str,
    canonical_url: str,
    dossier_bytes: bytes,
    dossier_document: Mapping[str, Any],
    promotion_receipt_sha256: str,
    source_content_sha256: str,
    now: datetime,
    maximum_age_seconds: int,
    expected_archive_root_identity: str,
    collection_config_path: Path,
    collection_config_sha256: str,
    collection_config_file_sha256: str,
) -> tuple[bytes, bytes, bytes, datetime]:
    """Reverify the store-owned v2 archive binding; no path comes from the operator."""

    try:
        binding = ResearchEvidenceBinding(
            dossier_sha256=str(evidence_row.get("dossier_hash") or ""),
            source_content_sha256=str(evidence_row.get("source_content_sha256") or ""),
            vacancy_snapshot_sha256=str(
                evidence_row.get("vacancy_snapshot_sha256") or ""
            ),
            promotion_receipt_sha256=str(
                evidence_row.get("promotion_receipt_sha256") or ""
            ),
            canonical_vacancy_object_sha256=str(
                evidence_row.get("canonical_vacancy_object_sha256") or ""
            ),
            semantic_receipt_sha256=str(
                evidence_row.get("semantic_receipt_sha256") or ""
            ),
            receipt_file_sha256=str(evidence_row.get("receipt_file_sha256") or ""),
            archive_root_identity=str(evidence_row.get("archive_root_identity") or ""),
            archive_root_policy_sha256=str(
                evidence_row.get("archive_root_policy_sha256") or ""
            ),
            receipt_relative_path=str(evidence_row.get("receipt_relative_path") or ""),
            schema_version=str(evidence_row.get("schema_version") or ""),
        )
        binding.validate()
    except ValueError as exc:
        raise ProductionHandoffError(
            "research_contract_v2_required",
            "legacy research cannot authorize production",
        ) from exc
    if binding.archive_root_identity != expected_archive_root_identity:
        raise ProductionHandoffError(
            "research_archive_authority",
            "research archive differs from the installed deployment authority",
        )
    dossier = _validated_dossier(dossier_document)
    expected_snapshot = _sha(
        _canonical(
            {
                "company": dossier_document.get("company"),
                "job_key": source_job_key,
                "promotion_receipt_sha256": promotion_receipt_sha256,
                "schema_version": "market-aligner.research-vacancy-snapshot.v1",
                "source_content_sha256": source_content_sha256,
                "title": dossier_document.get("role"),
                "url": canonical_url,
            }
        )
    )
    exact_bindings = {
        "source_content_sha256": source_content_sha256,
        "vacancy_snapshot_sha256": expected_snapshot,
        "promotion_receipt_sha256": promotion_receipt_sha256,
    }
    if (
        dossier.canonical_vacancy_object_sha256
        != binding.canonical_vacancy_object_sha256
        or binding.dossier_sha256 != _sha(dossier_bytes)
        or any(
            evidence_row.get(key) != value or dossier_document.get(key) != value
            for key, value in exact_bindings.items()
        )
    ):
        raise ProductionHandoffError(
            "research_binding", "v2 research differs from current vacancy"
        )

    archive = _SecureArchive(data_home, binding.archive_root_identity)
    receipt_raw = archive.read("receipts", f"{binding.semantic_receipt_sha256}.json")
    receipt = _document(receipt_raw, "research materialization receipt")
    receipt_body = dict(receipt)
    stated_semantic_sha = receipt_body.pop("semantic_receipt_sha256", None)
    semantic_sha = _sha(_canonical(receipt_body))
    if (
        receipt.get("schema_version")
        != "market-aligner.public-research-materialization.v2"
        or _canonical(receipt) != receipt_raw
        or _sha(receipt_raw) != evidence_row.get("receipt_file_sha256")
        or stated_semantic_sha != evidence_row.get("semantic_receipt_sha256")
        or semantic_sha != stated_semantic_sha
        or receipt.get("profile_id") != profile_id
        or receipt.get("job_key") != source_job_key
        or receipt.get("dossier_sha256") != evidence_row.get("dossier_hash")
        or receipt.get("canonical_vacancy_object_sha256")
        != evidence_row.get("canonical_vacancy_object_sha256")
        or any(receipt.get(key) != value for key, value in exact_bindings.items())
        or receipt.get("production_authority") is not True
        or receipt.get("application_authority") is not False
        or receipt.get("release_authority") is not False
    ):
        raise ProductionHandoffError("research_receipt", "v2 research receipt differs")

    citations = [
        row
        for row in dossier_document.get("citations", [])
        if row.get("source_kind") == "canonical_vacancy"
    ]
    if len(citations) != 1:
        raise ProductionHandoffError(
            "research_dossier", "canonical vacancy citation is absent"
        )
    citation = citations[0]
    object_sha = evidence_row.get("canonical_vacancy_object_sha256")
    if (
        citation.get("content_sha256") != object_sha
        or citation.get("url") != canonical_url
    ):
        raise ProductionHandoffError(
            "research_dossier", "canonical vacancy citation differs"
        )
    matching = [
        row
        for row in receipt.get("entries", [])
        if isinstance(row, dict)
        and row.get("citation_id") == citation.get("citation_id")
        and row.get("object_sha256") == object_sha
    ]
    if len(matching) != 1:
        raise ProductionHandoffError(
            "research_receipt", "canonical vacancy entry is absent"
        )
    metadata_sha = matching[0].get("metadata_sha256")
    if not isinstance(metadata_sha, str) or not _SHA256.fullmatch(metadata_sha):
        raise ProductionHandoffError(
            "research_metadata", "metadata identity is invalid"
        )
    metadata_raw = archive.read("metadata", f"{metadata_sha}.json")
    metadata = _document(metadata_raw, "canonical vacancy metadata")
    if (
        _sha(metadata_raw) != metadata_sha
        or _canonical(metadata) != metadata_raw
        or metadata.get("schema_version") != "market-aligner.public-research-source.v2"
        or metadata.get("source_kind") != "canonical_vacancy"
        or metadata.get("citation_id") != citation.get("citation_id")
        or metadata.get("content_sha256") != object_sha
        or metadata.get("requested_url") != canonical_url
        or metadata.get("final_url") != canonical_url
        or metadata.get("status") != 200
    ):
        raise ProductionHandoffError(
            "research_metadata", "canonical vacancy metadata differs"
        )
    job_parts = source_job_key.split(":")
    route_tenant, route_id = _workable_identity(canonical_url)
    if (
        len(job_parts) != 3
        or job_parts[0] != "workable"
        or (route_tenant is not None and job_parts[1] != route_tenant)
        or job_parts[2] != route_id
    ):
        raise ProductionHandoffError(
            "official_source_route", "source job identity differs"
        )
    object_raw = archive.read("objects", str(object_sha))
    envelope = _document(object_raw, "canonical vacancy object")
    schema = envelope.get("schema_version")
    v1_keys = {
        "authority_source_content_sha256",
        "fetched_at",
        "job_key",
        "raw_json",
        "raw_text",
        "schema_version",
        "url",
    }
    v2_sha_fields = {
        "canonical_current_content_sha256",
        "collection_refresh_context_sha256",
        "collection_refresh_raw_object_sha256",
        "collection_refresh_receipt_file_sha256",
        "collection_refresh_receipt_sha256",
        "collection_refresh_transition_sha256",
        "promotion_receipt_sha256",
    }
    v2_keys = (
        v1_keys
        | v2_sha_fields
        | {
            "collection_refresh_event_id",
            "collection_refresh_id",
            "collection_refresh_operation_id",
        }
    )
    schema_valid = (
        schema == "market-aligner.canonical-collector-vacancy.v1"
        and set(envelope) == v1_keys
    ) or (
        schema == "market-aligner.canonical-collector-vacancy.v2"
        and set(envelope) == v2_keys
        and all(
            type(envelope.get(field)) is str and _SHA256.fullmatch(str(envelope[field]))
            for field in v2_sha_fields
        )
        and type(envelope.get("collection_refresh_event_id")) is int
        and envelope["collection_refresh_event_id"] > 0
        and type(envelope.get("collection_refresh_id")) is str
        and bool(_SHA256.fullmatch(str(envelope["collection_refresh_id"])))
        and envelope["collection_refresh_id"]
        == _sha(
            _canonical(
                {
                    "context_sha256": envelope["collection_refresh_context_sha256"],
                    "schema_version": "market-aligner.vacancy-refresh-id.v1",
                }
            )
        )
        and type(envelope.get("collection_refresh_operation_id")) is str
        and bool(
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
                str(envelope["collection_refresh_operation_id"]),
            )
        )
        and envelope["promotion_receipt_sha256"]
        == evidence_row.get("promotion_receipt_sha256")
    )
    if schema == "market-aligner.canonical-collector-vacancy.v2" and schema_valid:
        _verify_refresh_ancestry(
            data_home,
            envelope,
            evidence_row,
            profile_id=profile_id,
            source_job_key=source_job_key,
            dossier_sha256=_sha(dossier_bytes),
            promotion_receipt_sha256=promotion_receipt_sha256,
            source_content_sha256=source_content_sha256,
            collection_config_path=collection_config_path,
            collection_config_sha256=collection_config_sha256,
            collection_config_file_sha256=collection_config_file_sha256,
        )
    if (
        _sha(object_raw) != object_sha
        or _canonical(envelope) != object_raw
        or not schema_valid
        or envelope.get("job_key") != source_job_key
        or envelope.get("url") != canonical_url
        or envelope.get("authority_source_content_sha256") != source_content_sha256
        or envelope.get("fetched_at") != metadata.get("accessed_at")
        or citation.get("accessed_at") != metadata.get("accessed_at")
    ):
        raise ProductionHandoffError(
            "research_object", "canonical vacancy object differs"
        )
    entry_by_citation = {
        row["citation_id"]: row
        for row in receipt.get("entries", [])
        if isinstance(row, dict)
    }
    citation_by_id = {row["citation_id"]: row for row in dossier_document["citations"]}
    object_cache = {citation["citation_id"]: object_raw}
    for claim in dossier_document["claims"]:
        for support in claim["supports"]:
            citation_id = support["citation_id"]
            source = citation_by_id.get(citation_id)
            entry = entry_by_citation.get(citation_id)
            if (
                source is None
                or entry is None
                or entry.get("object_sha256") != source.get("content_sha256")
            ):
                archive.close()
                raise ProductionHandoffError(
                    "research_support", "claim source binding differs"
                )
            supported_object = object_cache.get(citation_id)
            if supported_object is None:
                supported_object = archive.read("objects", str(entry["object_sha256"]))
                object_cache[citation_id] = supported_object
            match = re.fullmatch(
                r"bytes:(0|[1-9][0-9]*)-(0|[1-9][0-9]*)", support["selector"]
            )
            if match is None:
                archive.close()
                raise ProductionHandoffError(
                    "research_support", "claim selector is invalid"
                )
            start, end = int(match.group(1)), int(match.group(2))
            excerpt_bytes = supported_object[start:end]
            try:
                excerpt = excerpt_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                archive.close()
                raise ProductionHandoffError(
                    "research_support", "claim excerpt is not UTF-8"
                ) from exc
            if (
                end > len(supported_object)
                or excerpt != support["excerpt"]
                or _sha(excerpt_bytes) != support["excerpt_sha256"]
                or " ".join(claim["claim"].split()) != " ".join(excerpt.split())
            ):
                archive.close()
                raise ProductionHandoffError(
                    "research_support", "claim is not exact archived text"
                )
    observed = _instant(metadata.get("accessed_at"), "official source accessed_at")
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    age = (current - observed).total_seconds()
    if age < -300 or age > maximum_age_seconds:
        archive.close()
        raise ProductionHandoffError(
            "official_source_stale", "official source is not current"
        )
    archive.close()
    return metadata_raw, object_raw, receipt_raw, observed


def _logical_job_key(adapter: str, canonical_url: str, source_job_id: str) -> str:
    return "job_" + _sha(
        _canonical(
            {
                "adapter": adapter,
                "canonical_url": canonical_url,
                "source_job_id": source_job_id,
            }
        )
    )


def _reference(
    exact: bytes,
    *,
    type_id: str,
    schema_version: str,
    subject: Mapping[str, str],
    issued_at: datetime,
    valid_until: datetime | None,
) -> HandoffReference:
    return HandoffReference(
        exact_bytes=exact,
        type_id=type_id,
        schema_version=schema_version,
        subject=dict(subject),
        issued_at=_utc(issued_at),
        valid_until=None if valid_until is None else _utc(valid_until),
    )


def _deterministic_handoff_issuance(
    *,
    source_observed_at: datetime,
    dossier_issued_at: datetime,
    evaluated_at: datetime,
    vacancy_maximum_age_seconds: int,
    dossier_maximum_age_seconds: int,
) -> tuple[datetime, datetime, datetime]:
    """Derive identity time only from durable inputs and prove their validity."""

    values = (source_observed_at, dossier_issued_at, evaluated_at)
    if (
        vacancy_maximum_age_seconds <= 0
        or dossier_maximum_age_seconds <= 0
        or any(
            value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond
            for value in values
        )
    ):
        raise ProductionHandoffError(
            "input_time_order", "handoff input times or validity intervals are invalid"
        )
    if source_observed_at > evaluated_at:
        raise ProductionHandoffError(
            "official_source_future", "official source was observed after evaluation"
        )
    if dossier_issued_at > evaluated_at:
        raise ProductionHandoffError(
            "employer_research_future", "employer dossier was issued after evaluation"
        )
    handoff_issued_at = max(source_observed_at, dossier_issued_at)
    vacancy_valid_until = source_observed_at + timedelta(
        seconds=vacancy_maximum_age_seconds
    )
    dossier_valid_until = dossier_issued_at + timedelta(
        seconds=dossier_maximum_age_seconds
    )
    if not (
        source_observed_at <= handoff_issued_at <= evaluated_at < vacancy_valid_until
    ):
        raise ProductionHandoffError(
            "official_source_stale",
            "official source is not current at handoff and evaluation",
        )
    if not (
        dossier_issued_at <= handoff_issued_at <= evaluated_at < dossier_valid_until
    ):
        raise ProductionHandoffError(
            "employer_research_stale",
            "employer dossier is not current at handoff and evaluation",
        )
    return handoff_issued_at, vacancy_valid_until, dossier_valid_until


def _build_production_handoff_from_authenticated_time(
    *,
    deployment: _ProductionHandoffDeployment,
    profile_id: str,
    track: str,
    source_job_key: str,
    freshness_time: datetime,
    vacancy_maximum_age_seconds: int = PRODUCTION_VACANCY_MAXIMUM_AGE_SECONDS,
    dossier_maximum_age_seconds: int = PRODUCTION_DOSSIER_MAXIMUM_AGE_SECONDS,
) -> ProductionHandoffReceipt:
    """Build one immutable production bundle, or fail before creating it."""

    current = freshness_time.astimezone(timezone.utc).replace(microsecond=0)
    if vacancy_maximum_age_seconds <= 0 or dossier_maximum_age_seconds <= 0:
        raise ProductionHandoffError(
            "freshness_policy", "freshness intervals must be positive"
        )
    service = MarketAlignerService(deployment.data_home)
    profile, _ = service.profiles.load(profile_id)
    if track not in profile.tracks:
        raise ProductionHandoffError(
            "candidate_track", "profile does not authorize this track"
        )

    profile_directory = service.profiles.directory(profile_id).resolve(strict=True)
    profile_path = profile_directory / "profile.yaml"
    evidence_path = profile_directory / "evidence.jsonl"
    projection_path = profile_directory / "projection-receipt.json"
    profile_bytes = _read_regular(profile_path, "canonical profile")
    evidence_bytes = _read_regular(evidence_path, "canonical evidence ledger")
    projection = _document(
        _read_regular(projection_path, "canonical projection receipt"),
        "canonical projection receipt",
    )
    if (
        projection.get("schema") != "market-aligner.canonical-profile-projection.v1"
        or projection.get("profile_id") != profile_id
        or projection.get("release_authority") is not False
    ):
        raise ProductionHandoffError(
            "candidate_projection", "canonical profile projection receipt differs"
        )
    authority_path = PRODUCTION_CANDIDATE_AUTHORITY_PATH
    repository = deployment.repository_root.absolute()
    if authority_path == repository or repository in authority_path.parents:
        raise ProductionHandoffError(
            "candidate_authority_location",
            "protected candidate authority must be outside the repository",
        )
    candidate_authority_bytes = _protected_candidate_authority(
        authority_path, projection, PRODUCTION_CANDIDATE_AUTHORITY_SHA256
    )

    try:
        promotion_row = service.assessments.processing_promotion(
            profile_id, source_job_key
        )
    except KeyError as exc:
        raise ProductionHandoffError(
            "processing_promotion", "canonical assessment promotion is absent"
        ) from exc
    if promotion_row["track"] != track:
        raise ProductionHandoffError(
            "processing_promotion",
            "canonical assessment promotion targets another track",
        )
    promotion_bytes = bytes(promotion_row["receipt_bytes"])
    promotion_document = _document(promotion_bytes, "processing promotion")
    promotion_body = dict(promotion_document)
    stated_promotion_sha = promotion_body.pop("receipt_sha256", None)
    if (
        not isinstance(promotion_row["receipt_sha256"], str)
        or stated_promotion_sha != str(promotion_row["receipt_sha256"])
        or _sha(_canonical(promotion_body)) != str(promotion_row["receipt_sha256"])
        or promotion_document.get("policy_sha256") != str(promotion_row["policy_hash"])
    ):
        raise ProductionHandoffError(
            "processing_promotion", "canonical assessment promotion differs"
        )

    with service.jobs.connect() as connection:
        connection.row_factory = sqlite3.Row
        posting = connection.execute(
            "SELECT * FROM postings WHERE key=?", (source_job_key,)
        ).fetchone()
        processing = connection.execute(
            """SELECT * FROM processing_jobs
               WHERE profile_id=? AND track=? AND job_key=?
                 AND authority_sha256=? AND processing_config_sha256=?
                 AND source_content_sha256=? AND status='completed'
                 AND result_json IS NOT NULL""",
            (
                profile_id,
                track,
                source_job_key,
                promotion_row["authority_sha256"],
                promotion_row["processing_config_sha256"],
                promotion_row["source_content_sha256"],
            ),
        ).fetchall()
    if posting is None or len(processing) != 1 or posting["fetch_status"] != "fetched":
        raise ProductionHandoffError(
            "vacancy_state", "current fetched processing row is absent"
        )
    # This is the collector's persisted content identity from
    # VacancyStore.store_raw.  Keep the two components explicit here so a
    # reviewer can verify both their order and their individual boundaries.
    raw_text_bytes = str(posting["raw_text"] or "").encode("utf-8")
    raw_json_bytes = str(posting["raw_json"] or "").encode("utf-8")
    raw_material = raw_text_bytes + raw_json_bytes
    if (
        not raw_material
        or _sha(raw_material) != posting["content_hash"]
        or posting["content_hash"] != promotion_row["source_content_sha256"]
    ):
        raise ProductionHandoffError(
            "vacancy_hash", "current vacancy source bytes differ"
        )
    result = _document(str(processing[0]["result_json"]).encode(), "processing result")
    vacancy = result.get("vacancy")
    if (
        not isinstance(vacancy, dict)
        or vacancy.get("source_content_sha256") != posting["content_hash"]
    ):
        raise ProductionHandoffError("vacancy_projection", "processing vacancy differs")

    try:
        dossier_row = service.assessments.research_evidence(profile_id, source_job_key)
    except KeyError as exc:
        raise ProductionHandoffError(
            "employer_research_missing",
            "no canonical v2 AssessmentStore research evidence exists for the current vacancy",
        ) from exc
    dossier_bytes = bytes(dossier_row["dossier_json"], "utf-8")
    if _sha(dossier_bytes) != dossier_row["dossier_hash"]:
        raise ProductionHandoffError(
            "employer_research_hash", "canonical dossier differs"
        )
    dossier_document = _document(dossier_bytes, "canonical employer dossier")
    if (
        dossier_document.get("profile_id") != profile_id
        or dossier_document.get("job_key") != source_job_key
        or dossier_document.get("company") != vacancy.get("company")
        or dossier_document.get("role") != vacancy.get("title")
    ):
        raise ProductionHandoffError(
            "employer_research_binding", "canonical dossier differs"
        )
    try:
        dossier_issued = (
            datetime.fromisoformat(
                str(dossier_row["created_at"]).replace(" ", "T") + "+00:00"
            )
            .astimezone(timezone.utc)
            .replace(microsecond=0)
        )
    except ValueError as exc:
        raise ProductionHandoffError(
            "employer_research_timestamp", "canonical dossier timestamp is invalid"
        ) from exc
    metadata_bytes, source_object_bytes, source_receipt_bytes, observed_at = (
        _research_evidence(
            deployment.data_home,
            dict(dossier_row),
            profile_id=profile_id,
            source_job_key=source_job_key,
            canonical_url=str(posting["url"]),
            dossier_bytes=dossier_bytes,
            dossier_document=dossier_document,
            promotion_receipt_sha256=str(promotion_row["receipt_sha256"]),
            source_content_sha256=str(promotion_row["source_content_sha256"]),
            now=current,
            maximum_age_seconds=vacancy_maximum_age_seconds,
            expected_archive_root_identity=deployment.research_archive_root_identity,
            collection_config_path=deployment.collection_config_path,
            collection_config_sha256=deployment.collection_config_sha256,
            collection_config_file_sha256=deployment.collection_config_file_sha256,
        )
    )
    handoff_issued_at, vacancy_until, dossier_until = _deterministic_handoff_issuance(
        source_observed_at=observed_at,
        dossier_issued_at=dossier_issued,
        evaluated_at=current,
        vacancy_maximum_age_seconds=vacancy_maximum_age_seconds,
        dossier_maximum_age_seconds=dossier_maximum_age_seconds,
    )
    source_envelope = _document(source_object_bytes, "canonical vacancy object")
    expected_raw_json = (
        None if posting["raw_json"] is None else json.loads(str(posting["raw_json"]))
    )
    if (
        source_envelope.get("raw_text") != posting["raw_text"]
        or source_envelope.get("raw_json") != expected_raw_json
    ):
        raise ProductionHandoffError(
            "vacancy_archive_substitution",
            "archived canonical vacancy components differ from collector state",
        )

    location_category = str((result.get("geographic_preference") or {}).get("category"))
    location_map = {
        "uk_remote": ("UK_REMOTE", 1, "GB", "remote"),
        "uk_hybrid": ("UK_HYBRID", 2, "GB", "hybrid"),
        "uk_onsite": ("UK_ONSITE", 3, "GB", "onsite"),
        "romania_remote": ("RO_REMOTE", 4, "RO", "remote"),
        "eu_remote": ("EU_REMOTE", 5, "RO", "remote"),
    }
    try:
        geography_bucket, geography_rank, country_code, work_mode = location_map[
            location_category
        ]
    except KeyError as exc:
        raise ProductionHandoffError(
            "geography_binding", "processing geography cannot enter the handoff"
        ) from exc
    raw_location = str(vacancy.get("location") or "")
    location = {
        "country_code": country_code,
        "locality": raw_location.split(",", 1)[0].strip(),
        "raw_text": raw_location,
        "region": "",
        "work_mode": work_mode,
    }
    location_bytes = _canonical(location)

    adapter = str(vacancy.get("board") or posting["board"])
    source_job_id = str(vacancy.get("job_id") or posting["job_id"])
    canonical_url = str(vacancy.get("url") or posting["url"])
    if (
        adapter != posting["board"]
        or source_job_id != posting["job_id"]
        or canonical_url != posting["url"]
    ):
        raise ProductionHandoffError("vacancy_identity", "vacancy identity differs")
    handoff_job_key = _logical_job_key(adapter, canonical_url, source_job_id)

    requirements = {
        key: vacancy.get(key) or []
        for key in (
            "preferred_qualifications",
            "preferred_skills",
            "required_qualifications",
            "required_skills",
            "responsibilities",
        )
    }
    requirements_bytes = _canonical(requirements)
    provenance = {
        "adapter": adapter,
        "canonical_url": canonical_url,
        "discovered_at": _utc(observed_at),
        "fetched_at": _utc(observed_at),
        "source_job_id": source_job_id,
    }
    vacancy_snapshot_document = {
        "company_name": str(vacancy.get("company")),
        "job_key": handoff_job_key,
        "location_facts_sha256": _sha(location_bytes),
        "raw_listing_sha256": _sha(raw_material),
        "requirements_sha256": _sha(requirements_bytes),
        "role_title": str(vacancy.get("title")),
        "schema_version": "market-aligner.vacancy-snapshot.v1",
    }
    vacancy_snapshot_bytes = _canonical(vacancy_snapshot_document)
    vacancy_snapshot_sha = _sha(vacancy_snapshot_bytes)
    subject = {
        "profile_id": profile_id,
        "profile_version": profile.version,
        "job_key": handoff_job_key,
        "vacancy_snapshot_sha256": vacancy_snapshot_sha,
    }
    vacancy_subject = {
        "job_key": handoff_job_key,
        "vacancy_snapshot_sha256": vacancy_snapshot_sha,
    }

    eligibility_sources = {
        "first_job_scope": result.get("first_job_scope"),
        "vacancy_viability": result.get("viability"),
    }
    if any(
        not isinstance(value, dict) or value.get("decision") != "include"
        for value in eligibility_sources.values()
    ):
        raise ProductionHandoffError(
            "eligibility_state", "processing hard gate did not pass"
        )
    check_objects: dict[str, bytes] = {}
    checks: list[dict[str, str]] = []
    for code, source in sorted(eligibility_sources.items()):
        exact = _canonical(
            {
                "code": code,
                "outcome": "pass",
                "processing_config_sha256": promotion_row["processing_config_sha256"],
                "promotion_receipt_sha256": str(promotion_row["receipt_sha256"]),
                "source": source,
                "source_job_key": source_job_key,
            }
        )
        check_objects[code] = exact
        checks.append({"code": code, "evidence_sha256": _sha(exact), "outcome": "pass"})
    eligibility_document = {
        "checks": checks,
        "decision": "eligible",
        "hard_gate_passed": True,
        "promotion_receipt_sha256": str(promotion_row["receipt_sha256"]),
        "source_job_key": source_job_key,
    }
    eligibility_bytes = _canonical(eligibility_document)

    promotion_policy = promotion_document.get("policy")
    if not isinstance(promotion_policy, dict):
        raise ProductionHandoffError("selection_policy", "promotion policy is absent")
    selection_policy_bytes = _canonical(promotion_policy)
    if _sha(selection_policy_bytes) != str(promotion_row["policy_hash"]):
        raise ProductionHandoffError(
            "selection_policy", "promotion policy hash differs"
        )
    rationale_codes = sorted(
        {
            f"geography_priority_{location_category}",
            "hard_gates_passed",
            "selection_policy_passed",
        }
    )
    selection_receipt_document = {
        "decision": "selected_for_application",
        "geography_bucket": geography_bucket,
        "geography_priority_rank": geography_rank,
        "hard_gate_passed": True,
        "promotion_receipt_sha256": str(promotion_row["receipt_sha256"]),
        "rationale_codes": rationale_codes,
        "source_job_key": source_job_key,
    }
    selection_receipt_bytes = _canonical(selection_receipt_document)

    candidate_intent_document = {
        "authority_revision": 1,
        "authority_source_sha256": _sha(candidate_authority_bytes),
        "created_at": _utc(handoff_issued_at),
        "geography_priority": [
            {"rank": 1, "region_code": "UK", "work_mode": "remote"},
            {"rank": 2, "region_code": "UK", "work_mode": "hybrid"},
            {"rank": 3, "region_code": "UK", "work_mode": "onsite"},
            {"rank": 4, "region_code": "RO", "work_mode": "remote"},
            {"rank": 5, "region_code": "EU", "work_mode": "remote"},
        ],
        "profile_id": profile_id,
        "profile_version": profile.version,
        "role_track_ids": sorted(profile.tracks),
        "schema_version": "market-aligner.candidate-intent.v1",
    }
    candidate_intent_bytes = _canonical(candidate_intent_document)

    scoring_parameters_bytes = json.dumps(
        {
            "blend": ScoringParams().blend,
            "epsilon": ScoringParams().epsilon,
            "fit_weights": [list(row) for row in ScoringParams().fit_weights],
            "mean_p": ScoringParams().mean_p,
            "opportunity_weights": [
                list(row) for row in ScoringParams().opportunity_weights
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    score = result.get("score")
    if not isinstance(score, dict) or _sha(scoring_parameters_bytes) != score.get(
        "parameters_hash"
    ):
        raise ProductionHandoffError(
            "scoring_parameters", "exact scoring parameters are unavailable"
        )

    assessment_receipt_bytes = promotion_bytes
    selection = {
        **selection_receipt_document,
        "selection_policy_sha256": _sha(selection_policy_bytes),
        "selection_receipt_sha256": _sha(selection_receipt_bytes),
    }
    selection.pop("promotion_receipt_sha256")
    selection.pop("source_job_key")
    eligibility = {
        "checks": checks,
        "decision": "eligible",
        "eligibility_receipt_sha256": _sha(eligibility_bytes),
        "hard_gate_passed": True,
    }
    producer_commit = _git_commit(deployment.repository_root)
    manifest = {
        "assessment_receipt_sha256": _sha(assessment_receipt_bytes),
        "candidate_intent_sha256": _sha(candidate_intent_bytes),
        "created_at": _utc(handoff_issued_at),
        "eligibility": eligibility,
        "employer_dossier_sha256": _sha(dossier_bytes),
        "evidence_ledger_sha256": _sha(evidence_bytes),
        "producer_commit_sha": producer_commit,
        "selection": selection,
        "vacancy": {
            "company_name": vacancy_snapshot_document["company_name"],
            "location": {**location, "facts_sha256": _sha(location_bytes)},
            "provenance": provenance,
            "raw_listing_sha256": _sha(raw_material),
            "requirements_sha256": _sha(requirements_bytes),
            "role_title": vacancy_snapshot_document["role_title"],
            "vacancy_snapshot_sha256": vacancy_snapshot_sha,
        },
    }
    handoff = service.handoff(
        profile_id,
        source_job_key,
        manifest,
        handoff_job_key=handoff_job_key,
    )

    profile_subject = {"profile_id": profile_id, "profile_version": profile.version}
    active_until = handoff_issued_at + timedelta(days=30)
    references: dict[str, HandoffReference] = {
        "assessment.receipt": _reference(
            assessment_receipt_bytes,
            type_id="assessment_receipt",
            schema_version="market-aligner.assessment-receipt.v1",
            subject=subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        ),
        "assessment.scoring_parameters": _reference(
            scoring_parameters_bytes,
            type_id="scoring_parameters",
            schema_version="market-aligner.scoring-parameters.v1",
            subject={},
            issued_at=handoff_issued_at,
            valid_until=None,
        ),
        "candidate_intent": _reference(
            candidate_intent_bytes,
            type_id="candidate_intent",
            schema_version="market-aligner.candidate-intent.v1",
            subject=profile_subject,
            issued_at=handoff_issued_at,
            valid_until=active_until,
        ),
        "candidate_intent.authority_source": _reference(
            candidate_authority_bytes,
            type_id="candidate_authority_source",
            schema_version="market-aligner.candidate-authority-source.v1",
            subject=profile_subject,
            issued_at=handoff_issued_at,
            valid_until=active_until,
        ),
        "eligibility.receipt": _reference(
            eligibility_bytes,
            type_id="eligibility_receipt",
            schema_version="market-aligner.eligibility-receipt.v1",
            subject=subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        ),
        "employer_dossier": _reference(
            dossier_bytes,
            type_id="employer_dossier",
            schema_version="market-aligner.employer-dossier.v2",
            subject=vacancy_subject,
            issued_at=dossier_issued,
            valid_until=dossier_until,
        ),
        "evidence_ledger": _reference(
            evidence_bytes,
            type_id="evidence_ledger",
            schema_version="market-aligner.evidence-ledger.v1",
            subject=profile_subject,
            issued_at=handoff_issued_at,
            valid_until=active_until,
        ),
        "selection.policy": _reference(
            selection_policy_bytes,
            type_id="selection_policy",
            schema_version="market-aligner.selection-policy.v1",
            subject={},
            issued_at=handoff_issued_at,
            valid_until=active_until,
        ),
        "selection.receipt": _reference(
            selection_receipt_bytes,
            type_id="selection_receipt",
            schema_version="market-aligner.selection-receipt.v1",
            subject=subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        ),
        "vacancy.location.facts": _reference(
            location_bytes,
            type_id="location_facts",
            schema_version="market-aligner.location-facts.v1",
            subject=vacancy_subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        ),
        "vacancy.raw_listing": _reference(
            raw_material,
            type_id="raw_listing",
            schema_version="market-aligner.raw-listing-evidence.v1",
            subject=vacancy_subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        ),
        "vacancy.requirements": _reference(
            requirements_bytes,
            type_id="requirement_projection",
            schema_version="market-aligner.requirement-projection.v1",
            subject=vacancy_subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        ),
        "vacancy.snapshot": _reference(
            vacancy_snapshot_bytes,
            type_id="vacancy_snapshot",
            schema_version="market-aligner.vacancy-snapshot.v1",
            subject=vacancy_subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        ),
    }
    for code, exact in check_objects.items():
        references[f"eligibility.checks/{code}/evidence"] = _reference(
            exact,
            type_id="eligibility_evidence",
            schema_version="market-aligner.eligibility-evidence.v1",
            subject=subject,
            issued_at=handoff_issued_at,
            valid_until=vacancy_until,
        )

    output = deployment.output_root.absolute()
    repository = deployment.repository_root.absolute()
    if output == repository or repository in output.parents:
        raise ProductionHandoffError(
            "outbox_location", "production outbox must be outside the repository"
        )
    written: WrittenHandoffBundle = write_protected_handoff_bundle(
        output,
        handoff,
        references=references,
        environment="production",
        trust_root_id=PRODUCTION_HANDOFF_TRUST_ROOT_ID,
        issued_at=_utc(handoff_issued_at),
        source_job_key=source_job_key,
    )
    receipt_basis = {
        "application_id": handoff.application_id,
        "bundle_identity": f"bundles/{written.source_record_sha256}",
        "employer_dossier_sha256": _sha(dossier_bytes),
        "environment": "production",
        "handoff_job_key": handoff_job_key,
        "handoff_root_sha256": written.handoff_root_sha256,
        "manifest_sha256": written.manifest_sha256,
        "processing_promotion_sha256": str(promotion_row["receipt_sha256"]),
        "producer_commit_sha": producer_commit,
        "release_token_issued": False,
        "schema_version": "market-aligner.production-handoff-execution.v2",
        "source_job_key": source_job_key,
        "source_record_sha256": written.source_record_sha256,
        "submission_authority": False,
        "trust_root_id": PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }
    receipt_semantic_sha = _sha(_canonical(receipt_basis))
    receipt_bytes = _canonical(
        {**receipt_basis, "semantic_receipt_sha256": receipt_semantic_sha}
    )
    receipt_path = _persist_execution_receipt(
        deployment.output_root, receipt_semantic_sha, receipt_bytes
    )
    return ProductionHandoffReceipt(
        source_job_key=source_job_key,
        handoff_job_key=handoff_job_key,
        application_id=handoff.application_id,
        handoff_root_sha256=written.handoff_root_sha256,
        source_record_sha256=written.source_record_sha256,
        manifest_sha256=written.manifest_sha256,
        bundle_path=written.path,
        canonical_vacancy_metadata_sha256=_sha(metadata_bytes),
        canonical_vacancy_object_sha256=_sha(source_object_bytes),
        research_semantic_receipt_sha256=str(dossier_row["semantic_receipt_sha256"]),
        research_receipt_file_sha256=_sha(source_receipt_bytes),
        research_archive_root_identity=str(dossier_row["archive_root_identity"]),
        research_vacancy_snapshot_sha256=str(dossier_row["vacancy_snapshot_sha256"]),
        source_content_sha256=str(dossier_row["source_content_sha256"]),
        processing_promotion_sha256=str(promotion_row["receipt_sha256"]),
        employer_dossier_sha256=_sha(dossier_bytes),
        execution_receipt_path=receipt_path,
        execution_receipt_sha256=_sha(receipt_bytes),
    )


__all__ = [
    "PRODUCTION_CANDIDATE_AUTHORITY_PATH",
    "PRODUCTION_CANDIDATE_AUTHORITY_SHA256",
    "PRODUCTION_HANDOFF_TRUST_ROOT_ID",
    "ProductionHandoffError",
    "ProductionHandoffReceipt",
]
