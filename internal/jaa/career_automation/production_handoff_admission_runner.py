"""Fixed production admission boundary for a Market execution receipt.

The generic admission store remains reusable. This owner exists because this
operator lifecycle has deployment-owned paths, trust, time and durable receipts
that a caller must never supply.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import secrets
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
from .market_aligner_handoff import parse_handoff
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
EXECUTION_SCHEMA = "market-aligner.production-handoff-execution.v2"
OPERATION_SCHEMA = "jaa.production-handoff-admission-operation.v1"
_MAX_RECEIPT_BYTES = 65536
_SHA_FIELDS = {
    "employer_dossier_sha256",
    "handoff_root_sha256",
    "manifest_sha256",
    "processing_promotion_sha256",
    "semantic_receipt_sha256",
    "source_record_sha256",
}
_EXECUTION_KEYS = {
    "application_id",
    "bundle_identity",
    "employer_dossier_sha256",
    "environment",
    "handoff_job_key",
    "handoff_root_sha256",
    "manifest_sha256",
    "processing_promotion_sha256",
    "producer_commit_sha",
    "release_token_issued",
    "schema_version",
    "semantic_receipt_sha256",
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


def _open_absolute_directory_chain(
    path: Path, *, private_leaf: bool
) -> tuple[int, ...]:
    if not path.is_absolute() or ".." in path.parts:
        raise ProductionHandoffAdmissionError(
            "production path is not absolute and normalized"
        )
    descriptors = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    try:
        for component in path.parts[1:]:
            descriptors.append(
                os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptors[-1],
                )
            )
        metadata = os.fstat(descriptors[-1])
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & (0o077 if private_leaf else 0o022)
        ):
            raise ProductionHandoffAdmissionError(
                "compiled directory identity or permissions differ"
            )
        return tuple(descriptors)
    except OSError as exc:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise ProductionHandoffAdmissionError(
            "compiled directory ancestry contains a link or is unavailable"
        ) from exc
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _open_existing_private_child(parent_descriptor: int, name: str) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise ProductionHandoffAdmissionError(
            "compiled protected child is unavailable"
        ) from exc
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise ProductionHandoffAdmissionError(
            "compiled protected child identity or mode differs"
        )
    return descriptor


class _PinnedProductionPaths:
    def __init__(self, deployment: _ProductionAdmissionDeployment) -> None:
        self._descriptors: list[int] = []
        self._adapters: list[ProtectedLocalOutbox] = []
        self._pins: list[tuple[Path, int]] = []
        self._outbox_path = deployment.outbox_root
        try:
            data = _open_absolute_directory_chain(
                deployment.data_home, private_leaf=True
            )
            outbox = _open_absolute_directory_chain(
                deployment.outbox_root, private_leaf=True
            )
            repository = _open_absolute_directory_chain(
                deployment.repository_root, private_leaf=False
            )
            self._descriptors.extend((*data, *outbox, *repository))
            self.data_descriptor = data[-1]
            self.outbox_descriptor = outbox[-1]
            self.repository_descriptor = repository[-1]
            for path, chain in (
                (deployment.data_home, data),
                (deployment.outbox_root, outbox),
                (deployment.repository_root, repository),
            ):
                current = Path(path.anchor)
                for component, descriptor in zip(
                    path.parts[1:], chain[1:], strict=True
                ):
                    current /= component
                    self._pins.append((current, descriptor))
            self.receipts_descriptor = _open_existing_private_child(
                self.outbox_descriptor, "receipts"
            )
            self._descriptors.append(self.receipts_descriptor)
            self._pins.append(
                (deployment.execution_receipt_root, self.receipts_descriptor)
            )
        except BaseException:
            self.close()
            raise

    def open_bundle(self, source_record_sha256: str) -> int:
        bundles = _open_existing_private_child(self.outbox_descriptor, "bundles")
        try:
            bundle = _open_existing_private_child(bundles, source_record_sha256)
        finally:
            os.close(bundles)
        self._descriptors.append(bundle)
        self._pins.append(
            (
                self._outbox_path / "bundles" / source_record_sha256,
                bundle,
            )
        )
        return bundle

    def register_adapter(self, adapter: ProtectedLocalOutbox) -> None:
        self._adapters.append(adapter)

    def verify_references(self) -> None:
        for path, descriptor in self._pins:
            pinned = os.fstat(descriptor)
            try:
                current = path.lstat()
            except OSError as exc:
                raise ProductionHandoffAdmissionError(
                    "compiled path reference is unavailable"
                ) from exc
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISDIR(current.st_mode)
                or pinned.st_dev != current.st_dev
                or pinned.st_ino != current.st_ino
            ):
                raise ProductionHandoffAdmissionError(
                    "compiled path reference changed during operation"
                )

    def close(self) -> None:
        while self._adapters:
            self._adapters.pop().close()
        while self._descriptors:
            os.close(self._descriptors.pop())


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


def _read_execution_receipt(
    path: Path, root: Path, *, root_descriptor: int | None = None
) -> tuple[dict[str, object], bytes]:
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
    owned_root_descriptor = root_descriptor is None
    if root_descriptor is None:
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
        if owned_root_descriptor:
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
    def existing_exact() -> bool:
        try:
            existing_descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            return False
        try:
            metadata = os.fstat(existing_descriptor)
            chunks: list[bytes] = []
            remaining = len(value) + 1
            while remaining:
                chunk = os.read(existing_descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or b"".join(chunks) != value
            ):
                raise ProductionHandoffAdmissionError(
                    "operation receipt replay differs"
                )
            return True
        finally:
            os.close(existing_descriptor)

    if existing_exact():
        return
    temporary_name = f".{name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
        try:
            remaining = memoryview(value)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short operation receipt write")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
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
        result = renameat2(
            parent_descriptor,
            os.fsencode(temporary_name),
            parent_descriptor,
            os.fsencode(name),
            1,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error != errno.EEXIST:
                raise OSError(error, os.strerror(error))
            if not existing_exact():
                raise ProductionHandoffAdmissionError(
                    "operation receipt publication raced"
                )
        os.fsync(parent_descriptor)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass


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


def _run_production_handoff_admission_pinned(
    *,
    execution_receipt_path: str | Path,
    deployment: _ProductionAdmissionDeployment,
    witness: AuthenticatedCurrentTimeWitness,
    paths: _PinnedProductionPaths,
    commit_resolver: Callable[[Path, int], str],
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
        receipt_path,
        deployment.execution_receipt_root,
        root_descriptor=paths.receipts_descriptor,
    )
    _validate_execution_receipt(document, receipt_path)
    current_commit = commit_resolver(
        deployment.repository_root, paths.repository_descriptor
    )
    paths.verify_references()
    if document["producer_commit_sha"] != current_commit:
        raise ProductionHandoffAdmissionError(
            "producer commit differs from current clean HEAD"
        )
    source_record = str(document["source_record_sha256"])
    bundle_path = deployment.outbox_root / "bundles" / source_record
    bundle_descriptor = paths.open_bundle(source_record)
    adapter = ProtectedLocalOutbox(
        bundle_path,
        repository_root=deployment.repository_root,
        expected_source_record_sha256=source_record,
        allowed_producer_commits=frozenset({current_commit}),
        bundle_descriptor=bundle_descriptor,
    )
    paths.register_adapter(adapter)
    handoff = parse_handoff(adapter.handoff_bytes)
    try:
        context = json.loads(adapter.context_bytes)
        dossier_entry = adapter._entries["employer_dossier"]
        promotion_entry = adapter._entries["assessment.receipt"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProductionHandoffAdmissionError(
            "authenticated bundle graph is incomplete"
        ) from exc
    if (
        hashlib.sha256(adapter._manifest_bytes).hexdigest()
        != document["manifest_sha256"]
        or adapter._manifest.get("handoff_root_sha256")
        != document["handoff_root_sha256"]
        or adapter._source_record.get("source_job_key") != document["source_job_key"]
        or adapter._source_record.get("trust_root_id") != document["trust_root_id"]
        or dossier_entry.get("object_sha256") != document["employer_dossier_sha256"]
        or promotion_entry.get("object_sha256")
        != document["processing_promotion_sha256"]
        or handoff.root_sha256 != document["handoff_root_sha256"]
        or handoff.application_id != document["application_id"]
        or handoff.payload.get("job_key") != document["handoff_job_key"]
        or context.get("environment") != document["environment"]
        or context.get("source_record_sha256") != source_record
        or context.get("producer_commit_sha") != current_commit
        or context.get("trust_root_id") != document["trust_root_id"]
        or context.get("handoff_root_sha256") != document["handoff_root_sha256"]
    ):
        raise ProductionHandoffAdmissionError(
            "execution receipt and authenticated bundle differ"
        )
    data_descriptor = os.dup(paths.data_descriptor)
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
                    database = Path(
                        f"/proc/self/fd/{admission_descriptor}/admissions.sqlite3"
                    )
                    _prepare_database(admission_descriptor)
                    store = HandoffAdmissionStore(
                        database,
                        context_authenticator=adapter,
                        resolver=adapter,
                        current_time_witness=witness,
                    )
                    _prepare_database(admission_descriptor)
                    paths.verify_references()
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
                    paths.verify_references()
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


def _run_production_handoff_admission(
    *,
    execution_receipt_path: str | Path,
    deployment: _ProductionAdmissionDeployment,
    witness: AuthenticatedCurrentTimeWitness,
    commit_resolver: Callable[[Path, int], str] = (
        lambda repository, descriptor: _git_commit(
            repository, repository_descriptor=descriptor
        )
    ),
) -> ProductionHandoffAdmissionReceipt:
    paths = _PinnedProductionPaths(deployment)
    try:
        return _run_production_handoff_admission_pinned(
            execution_receipt_path=execution_receipt_path,
            deployment=deployment,
            witness=witness,
            paths=paths,
            commit_resolver=commit_resolver,
        )
    finally:
        paths.close()


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
