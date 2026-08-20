"""Fixed production admission boundary for a Market execution receipt.

The generic admission store remains reusable. This owner exists because this
operator lifecycle has deployment-owned paths, trust, time and durable receipts
that a caller must never supply.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.production_handoff import (
    PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    _git_commit,
)

from .current_time import (
    AuthenticatedCurrentTimeWitness,
    installed_production_current_time_witness,
)
from .handoff_admission import HandoffAdmissionStore, ProtectedLocalOutbox
from .production_handoff_runner import (
    PRODUCTION_MARKET_DATA_HOME,
    PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT,
    PRODUCTION_MARKET_OUTBOX_ROOT,
    PRODUCTION_MARKET_REPOSITORY_ROOT,
    _validate_deployment_roots,
    installed_production_handoff_deployment,
)

PRODUCTION_ADMISSION_ROOT = (
    PRODUCTION_MARKET_DATA_HOME / "state/jaa-production-admissions"
)
PRODUCTION_ADMISSION_DATABASE = PRODUCTION_ADMISSION_ROOT / "admissions.sqlite3"
PRODUCTION_ADMISSION_RECEIPT_ROOT = PRODUCTION_ADMISSION_ROOT / "receipts"
EXECUTION_SCHEMA = "market-aligner.production-handoff-execution.v1"
OPERATION_SCHEMA = "jaa.production-handoff-admission-operation.v1"
_MAX_RECEIPT_BYTES = 65536
_SHA_FIELDS = {
    "canonical_vacancy_metadata_sha256",
    "canonical_vacancy_object_sha256",
    "employer_dossier_sha256",
    "handoff_root_sha256",
    "manifest_sha256",
    "processing_promotion_sha256",
    "research_receipt_file_sha256",
    "research_semantic_receipt_sha256",
    "research_vacancy_snapshot_sha256",
    "semantic_receipt_sha256",
    "source_content_sha256",
    "source_record_sha256",
}
_EXECUTION_KEYS = {
    "application_id",
    "bundle_identity",
    "canonical_vacancy_metadata_sha256",
    "canonical_vacancy_object_sha256",
    "employer_dossier_sha256",
    "environment",
    "handoff_job_key",
    "handoff_root_sha256",
    "manifest_sha256",
    "processing_promotion_sha256",
    "producer_commit_sha",
    "release_token_issued",
    "research_archive_root_identity",
    "research_receipt_file_sha256",
    "research_semantic_receipt_sha256",
    "research_vacancy_snapshot_sha256",
    "schema_version",
    "semantic_receipt_sha256",
    "source_content_sha256",
    "source_job_key",
    "source_record_sha256",
    "submission_authority",
    "trust_root_id",
}


class ProductionHandoffAdmissionError(ValueError):
    """The supplied receipt or installed production authority differs."""


@dataclass(frozen=True)
class _ProductionAdmissionDeployment:
    data_home: Path
    repository_root: Path
    outbox_root: Path
    execution_receipt_root: Path
    admission_root: Path


@dataclass(frozen=True)
class ProductionHandoffAdmissionReceipt:
    operation: str
    application_id: str
    verification_receipt_sha256: str
    operation_receipt_path: Path
    operation_receipt_sha256: str
    execution_receipt_semantic_sha256: str
    execution_receipt_file_sha256: str
    handoff_root_sha256: str
    source_record_sha256: str
    producer_commit_sha: str
    environment: str = "production"

    def document(self) -> dict[str, object]:
        return {
            "application_id": self.application_id,
            "environment": self.environment,
            "execution_receipt_file_sha256": self.execution_receipt_file_sha256,
            "execution_receipt_semantic_sha256": self.execution_receipt_semantic_sha256,
            "handoff_root_sha256": self.handoff_root_sha256,
            "operation": self.operation,
            "operation_receipt_path": str(self.operation_receipt_path),
            "operation_receipt_sha256": self.operation_receipt_sha256,
            "producer_commit_sha": self.producer_commit_sha,
            "release_token_issued": False,
            "schema_version": "jaa.production-handoff-admission-receipt.v1",
            "source_record_sha256": self.source_record_sha256,
            "submission_authority": False,
            "verification_receipt_sha256": self.verification_receipt_sha256,
        }


def _open_private_directory(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ProductionHandoffAdmissionError(
            "production path is not absolute and normalized"
        )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ProductionHandoffAdmissionError(
            "protected directory is unavailable"
        ) from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise ProductionHandoffAdmissionError(
            "protected directory identity or mode differs"
        )
    return descriptor


def _reject_symlink_ancestry(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ProductionHandoffAdmissionError(
                    "production path ancestry contains a link"
                )
        except FileNotFoundError:
            break


def _open_private_child(parent_descriptor: int, name: str) -> int:
    if not name or "/" in name or name in {".", ".."}:
        raise ProductionHandoffAdmissionError("protected child name is invalid")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise ProductionHandoffAdmissionError("protected child is unavailable") from exc
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise ProductionHandoffAdmissionError(
            "protected child identity or mode differs"
        )
    return descriptor


def _read_execution_receipt(path: Path, root: Path) -> tuple[dict[str, object], bytes]:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ProductionHandoffAdmissionError(
            "execution receipt escapes the compiled root"
        ) from exc
    if not path.is_absolute() or len(relative.parts) != 1:
        raise ProductionHandoffAdmissionError(
            "execution receipt must be a direct compiled-root file"
        )
    root_descriptor = _open_private_directory(root)
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
        except OSError as exc:
            raise ProductionHandoffAdmissionError(
                "execution receipt cannot be opened safely"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ProductionHandoffAdmissionError(
                    "execution receipt identity or mode differs"
                )
            raw = os.read(descriptor, _MAX_RECEIPT_BYTES + 1)
        finally:
            os.close(descriptor)
    finally:
        os.close(root_descriptor)
    if not raw or len(raw) > _MAX_RECEIPT_BYTES:
        raise ProductionHandoffAdmissionError("execution receipt size is invalid")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionHandoffAdmissionError(
            "execution receipt is invalid JSON"
        ) from exc
    if type(document) is not dict or set(document) != _EXECUTION_KEYS:
        raise ProductionHandoffAdmissionError("execution receipt schema differs")
    if canonical_json_bytes(document) != raw:
        raise ProductionHandoffAdmissionError("execution receipt is not canonical JSON")
    return document, raw


def _validate_execution_receipt(document: dict[str, object], path: Path) -> None:
    if (
        document["schema_version"] != EXECUTION_SCHEMA
        or document["environment"] != "production"
        or document["trust_root_id"] != PRODUCTION_HANDOFF_TRUST_ROOT_ID
        or document["release_token_issued"] is not False
        or document["submission_authority"] is not False
    ):
        raise ProductionHandoffAdmissionError("execution receipt authority differs")
    for field in _SHA_FIELDS:
        value = document[field]
        if (
            type(value) is not str
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ProductionHandoffAdmissionError(
                f"execution receipt {field} is invalid"
            )
    commit = document["producer_commit_sha"]
    if (
        type(commit) is not str
        or len(commit) != 40
        or any(c not in "0123456789abcdef" for c in commit)
    ):
        raise ProductionHandoffAdmissionError(
            "execution receipt producer commit is invalid"
        )
    semantic = str(document["semantic_receipt_sha256"])
    basis = dict(document)
    del basis["semantic_receipt_sha256"]
    if hashlib.sha256(canonical_json_bytes(basis)).hexdigest() != semantic:
        raise ProductionHandoffAdmissionError("execution receipt semantic hash differs")
    if path.name != f"{semantic}.json":
        raise ProductionHandoffAdmissionError("execution receipt filename differs")
    source = str(document["source_record_sha256"])
    if document["bundle_identity"] != f"bundles/{source}":
        raise ProductionHandoffAdmissionError(
            "execution receipt bundle identity differs"
        )


def _create_or_exact(parent_descriptor: int, name: str, value: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
    except FileExistsError:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            existing = os.read(descriptor, len(value) + 1)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or existing != value
            ):
                raise ProductionHandoffAdmissionError(
                    "operation receipt replay differs"
                )
        finally:
            os.close(descriptor)
        return
    try:
        remaining = memoryview(value)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short operation receipt write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(descriptor)


def _prepare_database(parent_descriptor: int) -> None:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            "admissions.sqlite3", flags, 0o600, dir_fd=parent_descriptor
        )
    except OSError as exc:
        raise ProductionHandoffAdmissionError(
            "production admission database cannot be opened safely"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ProductionHandoffAdmissionError(
                "production admission database identity or mode differs"
            )
        os.fsync(parent_descriptor)
    finally:
        os.close(descriptor)


def _run_production_handoff_admission(
    *,
    execution_receipt_path: str | Path,
    deployment: _ProductionAdmissionDeployment,
    witness: AuthenticatedCurrentTimeWitness,
    commit_resolver: Callable[[Path], str] = _git_commit,
) -> ProductionHandoffAdmissionReceipt:
    if (
        deployment.execution_receipt_root != deployment.outbox_root / "receipts"
        or deployment.admission_root
        != deployment.data_home / "state" / "jaa-production-admissions"
    ):
        raise ProductionHandoffAdmissionError("production deployment roots differ")
    if (
        type(witness) is not AuthenticatedCurrentTimeWitness
        or getattr(witness, "environment", None) != "production"
    ):
        raise ProductionHandoffAdmissionError("production current-time witness differs")
    for protected_path in (
        deployment.data_home,
        deployment.outbox_root,
        deployment.execution_receipt_root,
    ):
        _reject_symlink_ancestry(protected_path)
    receipt_path = Path(execution_receipt_path)
    document, receipt_bytes = _read_execution_receipt(
        receipt_path, deployment.execution_receipt_root
    )
    _validate_execution_receipt(document, receipt_path)
    current_commit = commit_resolver(deployment.repository_root)
    if document["producer_commit_sha"] != current_commit:
        raise ProductionHandoffAdmissionError(
            "producer commit differs from current clean HEAD"
        )
    source_record = str(document["source_record_sha256"])
    bundle_path = deployment.outbox_root / "bundles" / source_record
    _reject_symlink_ancestry(bundle_path)
    adapter = ProtectedLocalOutbox(
        bundle_path,
        repository_root=deployment.repository_root,
        expected_source_record_sha256=source_record,
        allowed_producer_commits=frozenset({current_commit}),
    )
    if (
        hashlib.sha256(adapter._manifest_bytes).hexdigest()
        != document["manifest_sha256"]
        or adapter._manifest.get("handoff_root_sha256")
        != document["handoff_root_sha256"]
        or adapter._source_record.get("source_job_key") != document["source_job_key"]
        or adapter._source_record.get("trust_root_id") != document["trust_root_id"]
    ):
        raise ProductionHandoffAdmissionError(
            "execution receipt and authenticated bundle differ"
        )
    data_descriptor = _open_private_directory(deployment.data_home)
    try:
        state_descriptor = _open_private_child(data_descriptor, "state")
        try:
            admission_descriptor = _open_private_child(
                state_descriptor, "jaa-production-admissions"
            )
            try:
                receipts_descriptor = _open_private_child(
                    admission_descriptor, "receipts"
                )
                try:
                    database = deployment.admission_root / "admissions.sqlite3"
                    _prepare_database(admission_descriptor)
                    store = HandoffAdmissionStore(
                        database,
                        context_authenticator=adapter,
                        resolver=adapter,
                        current_time_witness=witness,
                    )
                    _prepare_database(admission_descriptor)
                    admission = store.admit_authenticated(
                        adapter.handoff_bytes, adapter.context_bytes
                    )
                    _prepare_database(admission_descriptor)
                    if (
                        admission.environment != "production"
                        or admission.authority_scope != "production"
                        or admission.application_id != document["application_id"]
                        or admission.job_key != document["handoff_job_key"]
                        or admission.handoff_root_sha256
                        != document["handoff_root_sha256"]
                    ):
                        raise ProductionHandoffAdmissionError(
                            "admission result differs from execution receipt"
                        )
                    operation = "created" if admission.created else "replay"
                    basis = {
                        "application_id": admission.application_id,
                        "environment": "production",
                        "execution_receipt_file_sha256": hashlib.sha256(
                            receipt_bytes
                        ).hexdigest(),
                        "execution_receipt_semantic_sha256": document[
                            "semantic_receipt_sha256"
                        ],
                        "handoff_root_sha256": admission.handoff_root_sha256,
                        "operation": operation,
                        "producer_commit_sha": current_commit,
                        "release_token_issued": False,
                        "schema_version": OPERATION_SCHEMA,
                        "source_record_sha256": source_record,
                        "submission_authority": False,
                        "verification_receipt_sha256": admission.verification_receipt_sha256,
                    }
                    semantic = hashlib.sha256(canonical_json_bytes(basis)).hexdigest()
                    operation_bytes = canonical_json_bytes(
                        {**basis, "semantic_receipt_sha256": semantic}
                    )
                    operation_path = (
                        deployment.admission_root / "receipts" / f"{semantic}.json"
                    )
                    _create_or_exact(
                        receipts_descriptor, operation_path.name, operation_bytes
                    )
                    return ProductionHandoffAdmissionReceipt(
                        operation=operation,
                        application_id=admission.application_id,
                        verification_receipt_sha256=admission.verification_receipt_sha256,
                        operation_receipt_path=operation_path,
                        operation_receipt_sha256=hashlib.sha256(
                            operation_bytes
                        ).hexdigest(),
                        execution_receipt_semantic_sha256=str(
                            document["semantic_receipt_sha256"]
                        ),
                        execution_receipt_file_sha256=hashlib.sha256(
                            receipt_bytes
                        ).hexdigest(),
                        handoff_root_sha256=str(admission.handoff_root_sha256),
                        source_record_sha256=source_record,
                        producer_commit_sha=current_commit,
                    )
                finally:
                    os.close(receipts_descriptor)
            finally:
                os.close(admission_descriptor)
        finally:
            os.close(state_descriptor)
    finally:
        os.close(data_descriptor)


def run_production_handoff_admission(
    *, execution_receipt_path: str | Path
) -> ProductionHandoffAdmissionReceipt:
    """Admit one fixed-root production Market receipt; never release or submit."""
    handoff = installed_production_handoff_deployment()
    _validate_deployment_roots(handoff)
    deployment = _ProductionAdmissionDeployment(
        data_home=PRODUCTION_MARKET_DATA_HOME,
        repository_root=PRODUCTION_MARKET_REPOSITORY_ROOT,
        outbox_root=PRODUCTION_MARKET_OUTBOX_ROOT,
        execution_receipt_root=PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT,
        admission_root=PRODUCTION_ADMISSION_ROOT,
    )
    return _run_production_handoff_admission(
        execution_receipt_path=execution_receipt_path,
        deployment=deployment,
        witness=installed_production_current_time_witness(),
    )


__all__ = [
    "PRODUCTION_ADMISSION_DATABASE",
    "PRODUCTION_ADMISSION_RECEIPT_ROOT",
    "PRODUCTION_ADMISSION_ROOT",
    "ProductionHandoffAdmissionError",
    "ProductionHandoffAdmissionReceipt",
    "run_production_handoff_admission",
]
