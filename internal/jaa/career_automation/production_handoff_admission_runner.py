"""Fixed production admission boundary for a Market execution receipt.

The generic admission store remains reusable. This owner exists because this
operator lifecycle has deployment-owned paths, trust, time and durable receipts
that a caller must never supply.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.production_handoff import (
    PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    _git_commit,
)
from market_aligner.state.atomic_publish import publish_noreplace

from .current_time import (
    AuthenticatedCurrentTimeWitness,
    installed_production_current_time_witness,
)
from .handoff_admission import (
    ADMISSION_KIND_CURRENT_RUNTIME,
    CURRENT_RUNTIME_AUTHORITY_SCOPE,
    CURRENT_RUNTIME_ENVIRONMENT,
    CURRENT_RUNTIME_FRESHNESS_PROVENANCE,
    CURRENT_RUNTIME_TRUST_ROOT_ID,
    CURRENT_RUNTIME_TRUST_MODE,
    HandoffAdmissionError,
    HandoffAdmissionStore,
    ProtectedLocalOutbox,
    _parse_current_runtime_handoff,
)
from .migrations import verify_current_runtime_admission_schema
from .market_aligner_handoff import parse_handoff
from .production_handoff_runner import (
    PRODUCTION_MARKET_DATA_HOME,
    PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT,
    PRODUCTION_MARKET_OUTBOX_ROOT,
    PRODUCTION_MARKET_REPOSITORY_ROOT,
    _validate_deployment_roots,
    installed_current_runtime_handoff_deployment,
    installed_production_handoff_deployment,
    select_runtime_deployment,
)

PRODUCTION_ADMISSION_ROOT = (
    PRODUCTION_MARKET_DATA_HOME / "state/jaa-production-admissions"
)
PRODUCTION_ADMISSION_DATABASE = PRODUCTION_ADMISSION_ROOT / "admissions.sqlite3"
PRODUCTION_ADMISSION_RECEIPT_ROOT = PRODUCTION_ADMISSION_ROOT / "receipts"
EXECUTION_SCHEMA = "market-aligner.production-handoff-execution.v2"
CURRENT_RUNTIME_EXECUTION_SCHEMA = "market-aligner.current-runtime-handoff-execution.v1"
OPERATION_SCHEMA = "jaa.production-handoff-admission-operation.v1"
CURRENT_RUNTIME_OPERATION_SCHEMA = "jaa.current-runtime-handoff-admission-operation.v1"
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
_CURRENT_RUNTIME_EXECUTION_KEYS = _EXECUTION_KEYS | {
    "freshness_provenance",
    "release_authority",
}


class ProductionHandoffAdmissionError(ValueError):
    """The supplied receipt or installed production authority differs."""


def _admission_deployment_for_handoff(handoff) -> _ProductionAdmissionDeployment:
    return _ProductionAdmissionDeployment(
        data_home=handoff.data_home,
        repository_root=handoff.repository_root,
        outbox_root=handoff.output_root,
        execution_receipt_root=handoff.output_root / "receipts",
        admission_root=handoff.data_home / "state" / "jaa-production-admissions",
        environment=getattr(handoff, "environment", "production"),
        trust_root_id=getattr(
            handoff, "trust_root_id", PRODUCTION_HANDOFF_TRUST_ROOT_ID
        ),
        freshness_provenance=getattr(handoff, "freshness_provenance", None),
    )


@dataclass(frozen=True)
class _ProductionAdmissionDeployment:
    data_home: Path
    repository_root: Path
    outbox_root: Path
    execution_receipt_root: Path
    admission_root: Path
    environment: str = "production"
    trust_root_id: str = PRODUCTION_HANDOFF_TRUST_ROOT_ID
    freshness_provenance: str | None = None


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
    freshness_provenance: str | None = None
    trust_root_id: str = PRODUCTION_HANDOFF_TRUST_ROOT_ID

    def document(self) -> dict[str, object]:
        document = {
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
            "schema_version": (
                CURRENT_RUNTIME_OPERATION_SCHEMA
                if self.environment == "current_runtime"
                else OPERATION_SCHEMA
            ),
            "source_record_sha256": self.source_record_sha256,
            "submission_authority": False,
            "verification_receipt_sha256": self.verification_receipt_sha256,
        }
        if self.environment == "current_runtime":
            document.update(
                {
                    "authority_scope": "current_runtime_non_release",
                    "freshness_provenance": self.freshness_provenance,
                    "release_authority": False,
                    "trust_root_id": self.trust_root_id,
                }
            )
        return document


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
    path: Path,
    root: Path,
    *,
    root_descriptor: int | None = None,
    current_runtime: bool = False,
) -> tuple[dict[str, object], bytes]:
    document, raw = _read_execution_receipt_document(
        path, root, root_descriptor=root_descriptor
    )
    expected_keys = (
        _CURRENT_RUNTIME_EXECUTION_KEYS if current_runtime else _EXECUTION_KEYS
    )
    if set(document) != expected_keys:
        raise ProductionHandoffAdmissionError("execution receipt schema differs")
    return document, raw


def _read_execution_receipt_document(
    path: Path,
    root: Path,
    *,
    root_descriptor: int | None = None,
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
    if type(document) is not dict or canonical_json_bytes(document) != raw:
        raise ProductionHandoffAdmissionError("execution receipt is not canonical JSON")
    return document, raw


def _validate_execution_receipt(
    document: dict[str, object], path: Path, *, current_runtime: bool = False
) -> None:
    if current_runtime:
        authority_invalid = (
            document["schema_version"] != CURRENT_RUNTIME_EXECUTION_SCHEMA
            or document["environment"] != "current_runtime"
            or document["trust_root_id"]
            != "market-aligner-current-runtime-non-release-v1"
            or document["release_authority"] is not False
            or document["freshness_provenance"] != "local_system_utc"
        )
    else:
        authority_invalid = (
            document["schema_version"] != EXECUTION_SCHEMA
            or document["environment"] != "production"
            or document["trust_root_id"] != PRODUCTION_HANDOFF_TRUST_ROOT_ID
        )
    if (
        authority_invalid
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


def _read_current_runtime_admission_index(
    deployment: _ProductionAdmissionDeployment,
    *,
    profile_id: str,
    profile_version: str,
) -> tuple[sqlite3.Connection, dict[str, sqlite3.Row]]:
    expected_root = deployment.data_home / "state" / "jaa-production-admissions"
    database = expected_root / "admissions.sqlite3"
    if deployment.admission_root != expected_root:
        raise ProductionHandoffAdmissionError("current runtime admission root differs")
    _reject_symlink_ancestry(database)
    try:
        before = database.lstat()
    except OSError as exc:
        raise ProductionHandoffAdmissionError(
            "current runtime admission store is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise ProductionHandoffAdmissionError(
            "current runtime admission store identity differs"
        )
    try:
        connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        verify_current_runtime_admission_schema(connection)
        rows = connection.execute(
            "SELECT * FROM current_runtime_admissions "
            "WHERE profile_id=? AND profile_version=? ORDER BY application_id",
            (profile_id, profile_version),
        ).fetchall()
        after = database.lstat()
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        try:
            connection.close()
        except UnboundLocalError:
            pass
        raise ProductionHandoffAdmissionError(
            "current runtime admission index is invalid"
        ) from exc
    if (
        (before.st_dev, before.st_ino, before.st_uid, before.st_mode, before.st_nlink)
        != (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_nlink)
    ):
        connection.close()
        raise ProductionHandoffAdmissionError(
            "current runtime admission store changed while reading"
        )
    by_application: dict[str, sqlite3.Row] = {}
    identity_roots: dict[tuple[str, str, str], str] = {}
    for row in rows:
        application_id = row["application_id"]
        root_sha256 = row["handoff_root_sha256"]
        producer_commit = row["producer_commit_sha"]
        original_bytes = row["original_bytes"]
        if (
            row["admission_kind"] != ADMISSION_KIND_CURRENT_RUNTIME
            or row["environment"] != CURRENT_RUNTIME_ENVIRONMENT
            or row["authority_scope"] != CURRENT_RUNTIME_AUTHORITY_SCOPE
            or row["emission_profile"] != "current_runtime_non_release_v1"
            or row["trust_mode"] != CURRENT_RUNTIME_TRUST_MODE
            or row["trust_root_id"] != CURRENT_RUNTIME_TRUST_ROOT_ID
            or row["producer_product"] != "market-aligner"
            or row["freshness_provenance"] != CURRENT_RUNTIME_FRESHNESS_PROVENANCE
            or type(row["sealed"]) is not int
            or row["sealed"] != 1
            or type(application_id) is not str
            or len(application_id) != 68
            or not application_id.startswith("app_")
            or type(root_sha256) is not str
            or len(root_sha256) != 64
            or any(character not in "0123456789abcdef" for character in root_sha256)
            or type(producer_commit) is not str
            or len(producer_commit) != 40
            or any(character not in "0123456789abcdef" for character in producer_commit)
            or type(original_bytes) is not bytes
            or hashlib.sha256(original_bytes).hexdigest() != root_sha256
        ):
            connection.close()
            raise ProductionHandoffAdmissionError(
                "current runtime admission index binding differs"
            )
        try:
            handoff = _parse_current_runtime_handoff(original_bytes)
        except ValueError as exc:
            connection.close()
            raise ProductionHandoffAdmissionError(
                "current runtime admission index handoff differs"
            ) from exc
        payload = handoff.payload
        identity = (
            str(payload["profile_id"]),
            str(payload["profile_version"]),
            str(payload["job_key"]),
        )
        if (
            handoff.application_id != application_id
            or handoff.root_sha256 != root_sha256
            or payload["profile_id"] != profile_id
            or payload["profile_version"] != profile_version
            or payload["producer"]["commit_sha"] != producer_commit
            or row["profile_id"] != profile_id
            or row["profile_version"] != profile_version
            or row["job_key"] != payload["job_key"]
            or application_id in by_application
            or (identity in identity_roots and identity_roots[identity] != root_sha256)
        ):
            connection.close()
            raise ProductionHandoffAdmissionError(
                "current runtime admission roots are ambiguous"
            )
        identity_roots[identity] = root_sha256
        by_application[application_id] = row
    return connection, by_application


def _producer_commit_is_ancestor(
    repository_descriptor: int, producer_commit: str, current_commit: str
) -> bool:
    for value in (producer_commit, current_commit):
        if (
            type(value) is not str
            or len(value) != 40
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ProductionHandoffAdmissionError("producer commit identity is invalid")
    if producer_commit == current_commit:
        return True
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", producer_commit, current_commit],
            cwd=f"/proc/self/fd/{repository_descriptor}",
            check=False,
            capture_output=True,
            pass_fds=(repository_descriptor,),
        )
    except OSError as exc:
        raise ProductionHandoffAdmissionError(
            "producer ancestry could not be verified"
        ) from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise ProductionHandoffAdmissionError(
        "producer ancestry could not be verified"
    )


def _verify_current_runtime_admission_row(
    row: sqlite3.Row, *, adapter: ProtectedLocalOutbox
) -> None:
    store = HandoffAdmissionStore.__new__(HandoffAdmissionStore)
    store.context_authenticator = adapter
    try:
        store._verify_stored_current_runtime(row)
    except HandoffAdmissionError as exc:
        raise ProductionHandoffAdmissionError(
            "stored current runtime admission differs"
        ) from exc


def _admitted_current_runtime_receipt_row(
    document: dict[str, object],
    admitted_rows: dict[str, sqlite3.Row],
) -> sqlite3.Row | None:
    if document.get("schema_version") != CURRENT_RUNTIME_EXECUTION_SCHEMA:
        return None
    application_id = document.get("application_id")
    root_sha256 = document.get("handoff_root_sha256")
    if type(application_id) is not str or type(root_sha256) is not str:
        return None
    admitted = admitted_rows.get(application_id)
    if admitted is None or admitted["handoff_root_sha256"] != root_sha256:
        return None
    if document.get("producer_commit_sha") != admitted["producer_commit_sha"]:
        raise ProductionHandoffAdmissionError(
            "published producer differs from stored admission"
        )
    return admitted


def _promotion_receipt_semantic_identity(
    adapter: ProtectedLocalOutbox,
    handoff: object,
    promotion_entry: dict[str, object],
    *,
    source_job_key: object,
) -> str:
    """Bind the promotion's semantic identity to its exact bundle object."""

    exact_sha256 = promotion_entry.get("object_sha256")
    if (
        type(exact_sha256) is not str
        or len(exact_sha256) != 64
        or any(character not in "0123456789abcdef" for character in exact_sha256)
    ):
        raise ProductionHandoffAdmissionError(
            "assessment promotion object identity is invalid"
        )
    try:
        exact = adapter._read(f"objects/{exact_sha256}")
        promotion = json.loads(exact)
        assessment = handoff.payload.get("assessment")
        promotion_canonical = canonical_json_bytes(promotion)
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProductionHandoffAdmissionError(
            "assessment promotion object is invalid"
        ) from exc
    if (
        type(promotion) is not dict
        or promotion_canonical != exact
        or hashlib.sha256(exact).hexdigest() != exact_sha256
        or type(assessment) is not dict
        or assessment.get("assessment_receipt_sha256") != exact_sha256
        or promotion.get("schema_version")
        != "market-aligner.assessment-promotion-receipt.v1"
        or promotion.get("job_key") != source_job_key
    ):
        raise ProductionHandoffAdmissionError(
            "assessment promotion object differs from authenticated bundle"
        )
    basis = dict(promotion)
    semantic_sha256 = basis.pop("receipt_sha256", None)
    if (
        type(semantic_sha256) is not str
        or hashlib.sha256(canonical_json_bytes(basis)).hexdigest() != semantic_sha256
    ):
        raise ProductionHandoffAdmissionError(
            "assessment promotion semantic identity differs"
        )
    return semantic_sha256


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
        if not publish_noreplace(parent_descriptor, temporary_name, name) and not existing_exact():
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


def _read_published_handoff_pinned(
    *,
    execution_receipt_path: str | Path,
    deployment: _ProductionAdmissionDeployment,
    paths: _PinnedProductionPaths,
    commit_resolver: Callable[[Path, int], str],
    allow_admitted_current_ancestor: bool = False,
) -> tuple[dict[str, object], bytes, str, str, ProtectedLocalOutbox, object]:
    """Validate published bytes under live path pins without creating admission state.

    The caller owns the pins and adapter lifetime. This result is publication
    evidence only, never release or submission authority.
    """
    for protected_path in (
        deployment.data_home,
        deployment.outbox_root,
        deployment.execution_receipt_root,
    ):
        _reject_symlink_ancestry(protected_path)
    receipt_path = Path(execution_receipt_path)
    current_runtime = deployment.environment == CURRENT_RUNTIME_ENVIRONMENT
    if deployment.environment not in {"production", CURRENT_RUNTIME_ENVIRONMENT}:
        raise ProductionHandoffAdmissionError("runtime environment is unsupported")
    document, receipt_bytes = _read_execution_receipt(
        receipt_path,
        deployment.execution_receipt_root,
        root_descriptor=paths.receipts_descriptor,
        current_runtime=current_runtime,
    )
    _validate_execution_receipt(
        document, receipt_path, current_runtime=current_runtime
    )
    current_commit = commit_resolver(
        deployment.repository_root, paths.repository_descriptor
    )
    paths.verify_references()
    producer_commit = str(document["producer_commit_sha"])
    producer_matches = producer_commit == current_commit
    if (
        not producer_matches
        and current_runtime
        and allow_admitted_current_ancestor
    ):
        producer_matches = _producer_commit_is_ancestor(
            paths.repository_descriptor, producer_commit, current_commit
        )
    if not producer_matches:
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
        allowed_producer_commits=frozenset({producer_commit}),
        bundle_descriptor=bundle_descriptor,
    )
    paths.register_adapter(adapter)
    handoff = (
        _parse_current_runtime_handoff(adapter.handoff_bytes)
        if current_runtime
        else parse_handoff(adapter.handoff_bytes)
    )
    try:
        context = json.loads(adapter.context_bytes)
        dossier_entry = adapter._entries["employer_dossier"]
        promotion_entry = adapter._entries["assessment.receipt"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProductionHandoffAdmissionError(
            "authenticated bundle graph is incomplete"
        ) from exc
    promotion_semantic_sha256 = _promotion_receipt_semantic_identity(
        adapter,
        handoff,
        promotion_entry,
        source_job_key=document["source_job_key"],
    )
    if (
        hashlib.sha256(adapter._manifest_bytes).hexdigest()
        != document["manifest_sha256"]
        or adapter._manifest.get("handoff_root_sha256")
        != document["handoff_root_sha256"]
        or adapter._source_record.get("source_job_key") != document["source_job_key"]
        or adapter._source_record.get("trust_root_id") != document["trust_root_id"]
        or dossier_entry.get("object_sha256") != document["employer_dossier_sha256"]
        or promotion_semantic_sha256 != document["processing_promotion_sha256"]
        or handoff.root_sha256 != document["handoff_root_sha256"]
        or handoff.application_id != document["application_id"]
        or handoff.payload.get("job_key") != document["handoff_job_key"]
        or context.get("environment") != document["environment"]
        or context.get("source_record_sha256") != source_record
        or context.get("producer_commit_sha") != producer_commit
        or context.get("trust_root_id") != document["trust_root_id"]
        or context.get("handoff_root_sha256") != document["handoff_root_sha256"]
    ):
        raise ProductionHandoffAdmissionError(
            "execution receipt and authenticated bundle differ"
        )
    paths.verify_references()
    return document, receipt_bytes, current_commit, source_record, adapter, handoff


def _run_production_handoff_admission_pinned(
    *,
    execution_receipt_path: str | Path,
    deployment: _ProductionAdmissionDeployment,
    witness: AuthenticatedCurrentTimeWitness | None,
    paths: _PinnedProductionPaths,
    commit_resolver: Callable[[Path, int], str],
) -> ProductionHandoffAdmissionReceipt:
    if (
        deployment.execution_receipt_root != deployment.outbox_root / "receipts"
        or deployment.admission_root
        != deployment.data_home / "state" / "jaa-production-admissions"
    ):
        raise ProductionHandoffAdmissionError("production deployment roots differ")
    current_runtime = deployment.environment == CURRENT_RUNTIME_ENVIRONMENT
    if current_runtime:
        if (
            witness is not None
            or deployment.trust_root_id != CURRENT_RUNTIME_TRUST_ROOT_ID
            or deployment.freshness_provenance != CURRENT_RUNTIME_FRESHNESS_PROVENANCE
        ):
            raise ProductionHandoffAdmissionError("current runtime provenance differs")
    elif (
        deployment.environment != "production"
        or type(witness) is not AuthenticatedCurrentTimeWitness
        or getattr(witness, "environment", None) != "production"
    ):
        raise ProductionHandoffAdmissionError("production current-time witness differs")
    document, receipt_bytes, current_commit, source_record, adapter, _handoff = (
        _read_published_handoff_pinned(
            execution_receipt_path=execution_receipt_path,
            deployment=deployment,
            paths=paths,
            commit_resolver=commit_resolver,
        )
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
                    admission = (
                        store.admit_current_runtime_nonrelease(
                            adapter.handoff_bytes, adapter.context_bytes
                        )
                        if current_runtime
                        else store.admit_authenticated(
                            adapter.handoff_bytes, adapter.context_bytes
                        )
                    )
                    _prepare_database(admission_descriptor)
                    if (
                        admission.environment
                        != (CURRENT_RUNTIME_ENVIRONMENT if current_runtime else "production")
                        or admission.authority_scope
                        != (
                            CURRENT_RUNTIME_AUTHORITY_SCOPE
                            if current_runtime
                            else "production"
                        )
                        or admission.admission_kind
                        != (
                            ADMISSION_KIND_CURRENT_RUNTIME
                            if current_runtime
                            else "market_aligner_handoff_v1"
                        )
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
                        "environment": (
                            CURRENT_RUNTIME_ENVIRONMENT
                            if current_runtime
                            else "production"
                        ),
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
                        "schema_version": (
                            CURRENT_RUNTIME_OPERATION_SCHEMA
                            if current_runtime
                            else OPERATION_SCHEMA
                        ),
                        "source_record_sha256": source_record,
                        "submission_authority": False,
                        "verification_receipt_sha256": admission.verification_receipt_sha256,
                    }
                    if current_runtime:
                        basis.update(
                            {
                                "authority_scope": CURRENT_RUNTIME_AUTHORITY_SCOPE,
                                "freshness_provenance": CURRENT_RUNTIME_FRESHNESS_PROVENANCE,
                                "release_authority": False,
                                "trust_root_id": CURRENT_RUNTIME_TRUST_ROOT_ID,
                            }
                        )
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
                        environment=(
                            CURRENT_RUNTIME_ENVIRONMENT
                            if current_runtime
                            else "production"
                        ),
                        freshness_provenance=(
                            CURRENT_RUNTIME_FRESHNESS_PROVENANCE
                            if current_runtime
                            else None
                        ),
                        trust_root_id=deployment.trust_root_id,
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
    witness: AuthenticatedCurrentTimeWitness | None,
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


def _selected_published_handoffs(
    *,
    profile_id: str,
    profile_version: str,
    candidate_intent_sha256: str,
    deployment: _ProductionAdmissionDeployment,
    commit_resolver: Callable[[Path, int], str],
) -> list[dict[str, object]]:
    """Inspect one captured receipt listing; never create admissions or release authority."""
    from market_aligner.assessment.geography import selection_sort_key
    from market_aligner.profiler.schema import validate_profile_id

    validate_profile_id(profile_id)
    if type(profile_version) is not str or not profile_version.strip():
        raise ProductionHandoffAdmissionError("profile version is required")
    if (
        type(candidate_intent_sha256) is not str
        or len(candidate_intent_sha256) != 64
        or any(c not in "0123456789abcdef" for c in candidate_intent_sha256)
    ):
        raise ProductionHandoffAdmissionError("candidate intent identity is invalid")
    if deployment.execution_receipt_root != deployment.outbox_root / "receipts":
        raise ProductionHandoffAdmissionError("production receipt root differs")
    paths = _PinnedProductionPaths(deployment)
    current_runtime = deployment.environment == CURRENT_RUNTIME_ENVIRONMENT
    try:
        admission_connection = None
        admitted_rows: dict[str, sqlite3.Row] = {}
        if current_runtime:
            admission_connection, admitted_rows = _read_current_runtime_admission_index(
                deployment,
                profile_id=profile_id,
                profile_version=profile_version,
            )
        rows = []
        selected_roots: set[tuple[str, str]] = set()
        for name in sorted(os.listdir(paths.receipts_descriptor)):
            # Interrupted private publications never become published selections.
            if name.startswith("."):
                continue
            if current_runtime:
                receipt_path = deployment.execution_receipt_root / name
                document, _receipt_bytes = _read_execution_receipt_document(
                    receipt_path,
                    deployment.execution_receipt_root,
                    root_descriptor=paths.receipts_descriptor,
                )
                application_id = document.get("application_id")
                root_sha256 = document.get("handoff_root_sha256")
                admitted = _admitted_current_runtime_receipt_row(
                    document, admitted_rows
                )
                if admitted is None:
                    continue
                _validate_execution_receipt(
                    document, receipt_path, current_runtime=True
                )
                if document["producer_commit_sha"] != admitted["producer_commit_sha"]:
                    raise ProductionHandoffAdmissionError(
                        "published producer differs from stored admission"
                    )
                published = _read_published_handoff_pinned(
                    execution_receipt_path=receipt_path,
                    deployment=deployment,
                    paths=paths,
                    commit_resolver=commit_resolver,
                    allow_admitted_current_ancestor=True,
                )
                document, _, _, _, adapter, handoff = published
                if (
                    handoff.application_id != application_id
                    or handoff.root_sha256 != root_sha256
                ):
                    raise ProductionHandoffAdmissionError(
                        "published handoff differs from stored admission"
                    )
                identity = (application_id, root_sha256)
                if identity in selected_roots:
                    raise ProductionHandoffAdmissionError(
                        "current runtime selection contains ambiguous roots"
                    )
                selected_roots.add(identity)
                _verify_current_runtime_admission_row(
                    admitted, adapter=adapter
                )
                if handoff.emission_profile != "current_runtime_non_release_v1":
                    raise ProductionHandoffAdmissionError(
                        "current runtime selection contains a different profile"
                    )
            else:
                document, _, _, _, _, handoff = _read_published_handoff_pinned(
                    execution_receipt_path=deployment.execution_receipt_root / name,
                    deployment=deployment,
                    paths=paths,
                    commit_resolver=commit_resolver,
                )
                if not handoff.strict_profile:
                    raise ProductionHandoffAdmissionError(
                        "published handoff is not strict"
                    )
            payload = handoff.payload
            if (
                payload["profile_id"] != profile_id
                or payload["profile_version"] != profile_version
                or payload["candidate_intent_sha256"] != candidate_intent_sha256
            ):
                continue
            selection = payload["selection"]
            if (
                selection["decision"] != "selected_for_application"
                or selection["hard_gate_passed"] is not True
                or payload["eligibility"]["hard_gate_passed"] is not True
            ):
                raise ProductionHandoffAdmissionError("published selection is blocked")
            assessment = payload["assessment"]
            row = {
                "application_id": handoff.application_id,
                "handoff_root_sha256": handoff.root_sha256,
                "execution_receipt_sha256": document["semantic_receipt_sha256"],
                "profile_id": profile_id,
                "profile_version": profile_version,
                "candidate_intent_sha256": candidate_intent_sha256,
                "geography_bucket": selection["geography_bucket"],
                "geography_rank": selection["geography_priority_rank"],
                "final_score": assessment["final"] * 100,
                "opportunity": assessment["opportunity"],
                "job_key": payload["job_key"],
                "source_job_key": document["source_job_key"],
                "vacancy_snapshot_sha256": payload["vacancy"]["vacancy_snapshot_sha256"],
                "handoff_created_at": payload["created_at"],
                "release_authority": False,
                "submission_authority": False,
            }
            if row["geography_rank"] is None and current_runtime:
                if row["geography_bucket"] is not None:
                    raise ProductionHandoffAdmissionError(
                        "unknown current geography has a bucket"
                    )
            elif row["geography_rank"] is not None:
                selection_sort_key(
                    row["geography_rank"],
                    row["final_score"],
                    row["opportunity"],
                    row["job_key"],
                )
            rows.append(row)
        if current_runtime:
            rows.sort(
                key=lambda row: (
                    row["geography_rank"] is None,
                    0 if row["geography_rank"] is None else row["geography_rank"],
                    -row["final_score"],
                    -row["opportunity"],
                    row["job_key"],
                    row["application_id"],
                )
            )
        else:
            rows.sort(
                key=lambda row: (
                    *selection_sort_key(
                        row["geography_rank"],
                        row["final_score"],
                        row["opportunity"],
                        row["job_key"],
                    ),
                    row["application_id"],
                )
            )
        paths.verify_references()
        return rows
    finally:
        if "admission_connection" in locals() and admission_connection is not None:
            admission_connection.close()
        paths.close()


def selected_published_handoffs(
    profile_id: str,
    *,
    profile_version: str,
    candidate_intent_sha256: str,
    current_runtime_config_path: str | Path | None = None,
    current_runtime_config_sha256: str | None = None,
    current_runtime_private_root: str | Path | None = None,
) -> list[dict[str, object]]:
    """List verified installed-deployment selections, without release authority."""
    config_path = (
        str(current_runtime_config_path)
        if isinstance(current_runtime_config_path, Path)
        else current_runtime_config_path
    )
    private_root = (
        str(current_runtime_private_root)
        if isinstance(current_runtime_private_root, Path)
        else current_runtime_private_root
    )
    _, deployment = select_runtime_deployment(
        config_path=config_path,
        config_sha256=current_runtime_config_sha256,
        private_root=private_root,
        legacy_loader=installed_production_handoff_deployment,
        current_loader=lambda **options: installed_current_runtime_handoff_deployment(
            configuration_path=Path(options["configuration_path"]),
            configuration_sha256=options["configuration_sha256"],
            private_root=Path(options["private_root"]),
        ),
    )
    _validate_deployment_roots(deployment)
    return _selected_published_handoffs(
        profile_id=profile_id,
        profile_version=profile_version,
        candidate_intent_sha256=candidate_intent_sha256,
        deployment=_admission_deployment_for_handoff(deployment),
        commit_resolver=lambda repository, descriptor: _git_commit(
            repository, repository_descriptor=descriptor
        ),
    )


def run_production_handoff_admission(
    *,
    execution_receipt_path: str | Path,
    current_runtime_config_path: str | Path | None = None,
    current_runtime_config_sha256: str | None = None,
    current_runtime_private_root: str | Path | None = None,
) -> ProductionHandoffAdmissionReceipt:
    """Admit one explicitly selected Market receipt; never release or submit."""
    config_path = (
        str(current_runtime_config_path)
        if isinstance(current_runtime_config_path, Path)
        else current_runtime_config_path
    )
    private_root = (
        str(current_runtime_private_root)
        if isinstance(current_runtime_private_root, Path)
        else current_runtime_private_root
    )
    current_runtime, handoff = select_runtime_deployment(
        config_path=config_path,
        config_sha256=current_runtime_config_sha256,
        private_root=private_root,
        legacy_loader=installed_production_handoff_deployment,
        current_loader=lambda **options: installed_current_runtime_handoff_deployment(
            configuration_path=Path(options["configuration_path"]),
            configuration_sha256=options["configuration_sha256"],
            private_root=Path(options["private_root"]),
        ),
    )
    _validate_deployment_roots(handoff)
    deployment = _admission_deployment_for_handoff(handoff)
    return _run_production_handoff_admission(
        execution_receipt_path=execution_receipt_path,
        deployment=deployment,
        witness=(
            None
            if current_runtime
            else installed_production_current_time_witness()
        ),
    )


__all__ = [
    "PRODUCTION_ADMISSION_DATABASE",
    "PRODUCTION_ADMISSION_RECEIPT_ROOT",
    "PRODUCTION_ADMISSION_ROOT",
    "ProductionHandoffAdmissionError",
    "ProductionHandoffAdmissionReceipt",
    "run_production_handoff_admission",
    "selected_published_handoffs",
]
