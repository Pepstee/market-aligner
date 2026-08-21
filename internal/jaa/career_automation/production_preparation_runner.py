"""Fixed-root production preparation lifecycle for one admitted application.

This owner is distinct from the reusable preparation coordinator: callers may
choose only the already admitted application ID.  Deployment paths, authorities,
models and transports are compiled and root-configured.  The result is always
non-release and grants no browser or submission authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.production_handoff import (
    PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    _git_commit,
)

from cv_generation.editorial_composition import (
    DetachedCodexEditorialAdapter,
    EditorialCompositionRuntime,
)

from .candidate_contact_authority import PUBLIC_KEY_ENV, REGISTRY_ENV
from .current_time import installed_production_current_time_witness
from .handoff_admission import HandoffAdmissionStore, ProtectedLocalOutbox
from .market_aligner_preparation import (
    CanonicalPreparationInputMaterializer,
    MarketApplicationPreparation,
    prepare_admitted_market_application_from_authorities,
)
from .production_handoff_admission_runner import PRODUCTION_ADMISSION_DATABASE
from .production_handoff_admission_runner import (
    PRODUCTION_ADMISSION_ROOT,
    _PinnedProductionPaths,
    _ProductionAdmissionDeployment,
    _open_absolute_directory_chain,
)
from .production_handoff_runner import (
    PRODUCTION_MARKET_DATA_HOME,
    PRODUCTION_MARKET_OUTBOX_ROOT,
    PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT,
    PRODUCTION_MARKET_REPOSITORY_ROOT,
    _read_root_owned_configuration,
)
from .production_recruiter_assessor import ProductionDetachedRecruiterAssessor


PRODUCTION_PREPARATION_CONFIG_PATH = Path(
    "/etc/gigabyte/majaa-public/application-preparation-v1.json"
)
PRODUCTION_CANDIDATE_AUTHORITY_PATH = Path(
    "/home/gutua/software-factory/protected/majaa-20260810/candidate/candidate_authority.json"
)
PRODUCTION_CANDIDATE_AUTHORITY_SHA256 = (
    "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9"
)
PRODUCTION_CONTACT_AUTHORITY_PATH = Path(
    "/home/gutua/.local/share/jaa/operator-contact-20260810/authorities/"
    "6a96a7aaed38312a4af36b350e3befb27f582c64729e4f0315a851bceb392b31.json"
)
PRODUCTION_CONTACT_ENVELOPE_SHA256 = "cbe93fa186faa187cb6b0d7ab0996209380da493b3ad20527bedc3fc592e244c"
PRODUCTION_CONTACT_PUBLIC_KEY_PATH = Path(
    "/home/gutua/.local/share/jaa/operator-contact-20260810/keys/"
    "operator-contact-public-key.pem"
)
PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256 = "554f3b0e3228bef7426b465bb2de5065f885453acf83ddc602b28dee5be7b004"
PRODUCTION_CONTACT_REGISTRY_PATH = Path(
    "/home/gutua/.local/share/jaa/operator-contact-20260810/registry/"
    "17000df77f9c8c26b31b41e5ffc1d395d25e71eb24b177c0910a39acd2fde326.json"
)
PRODUCTION_CONTACT_REGISTRY_FILE_SHA256 = "f32a54329910e385fc585d2afa400b944d5db19de542d5985b51b3e175e432fb"
PRODUCTION_PREPARATION_OUTPUT_ROOT = (
    PRODUCTION_MARKET_DATA_HOME / "state/jaa-production-preparations"
)
PRODUCTION_RECRUITER_ARCHIVE_ROOT = (
    PRODUCTION_MARKET_DATA_HOME / "state/jaa-production-recruiter-diagnostics"
)
PRODUCTION_CODEX_BINARY = Path(
    "/usr/lib/node_modules/@openai/codex/bin/codex.js"
)
PRODUCTION_CODEX_BINARY_SHA256 = (
    "134063e133f0b4244fa3b251acf973d4fe4b4aeeacbdc135211bf480f59f1477"
)
PRODUCTION_CODEX_MODEL = "gpt-5.6-sol"
PRODUCTION_CODEX_TIMEOUT_SECONDS = 300.0
PRODUCTION_POPPLER_BIN = Path("/home/gutua/.local/poppler/usr/bin")
PRODUCTION_POPPLER_SHA256 = {
    "pdffonts": "5956c57d42bf8a116aa6c44f961720366664c60471e948d215a698bdb6608fba",
    "pdfinfo": "bc643b05d93f5edf86ac536313c38d759130c8192ea83e0251b9d8d4cb336763",
    "pdftoppm": "ad3659e9229f0609640db64611023130222f892a00706ea318af04a07326014a",
    "pdftotext": "5bc8817737f5a4c94240e3f642943ec085669e22b85af33bae22786a45c8d49e",
}
_CONFIG_SCHEMA = "jaa.production-application-preparation-deployment.v1"


class ProductionPreparationDeploymentError(ValueError):
    pass


@dataclass(frozen=True)
class _ProductionPreparationDeployment:
    repository_root: Path
    admission_database: Path
    outbox_root: Path
    candidate_authority_path: Path
    contact_authority_path: Path
    contact_public_key_path: Path
    contact_registry_path: Path
    output_root: Path
    recruiter_archive_root: Path
    codex_binary: Path
    model: str
    timeout_seconds: float


@dataclass(frozen=True)
class _PinnedFile:
    path: Path
    descriptor: int
    device: int
    inode: int
    uid: int
    mode: int
    sha256: str | None


class _PinnedPreparationResources:
    """Hold exact deployment files and writable roots across preparation."""

    def __init__(self) -> None:
        self._descriptors: list[int] = []
        self._directory_pins: list[tuple[Path, int, int, int, int]] = []
        self._file_pins: list[_PinnedFile] = []

    def _record_chain(self, path: Path, chain: tuple[int, ...]) -> None:
        current = Path(path.anchor)
        for component, descriptor in zip(path.parts[1:], chain[1:], strict=True):
            current /= component
            metadata = os.fstat(descriptor)
            self._directory_pins.append(
                (
                    current,
                    descriptor,
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_uid,
                )
            )

    @staticmethod
    def _open_resource_chain(path: Path) -> tuple[int, ...]:
        if not path.is_absolute() or ".." in path.parts:
            raise ProductionPreparationDeploymentError(
                "compiled preparation path is not absolute and normalized"
            )
        descriptors = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
        try:
            for component in path.parts[1:]:
                descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptors[-1],
                )
                metadata = os.fstat(descriptor)
                mode = stat.S_IMODE(metadata.st_mode)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid not in {0, os.geteuid()}
                    or (
                        mode & 0o022
                        and not (
                            metadata.st_uid == 0
                            and metadata.st_mode & stat.S_ISVTX
                        )
                    )
                ):
                    os.close(descriptor)
                    raise ProductionPreparationDeploymentError(
                        "compiled preparation ancestry differs"
                    )
                descriptors.append(descriptor)
            return tuple(descriptors)
        except BaseException:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    def pin_file(
        self,
        path: Path,
        *,
        expected_sha256: str | None,
        expected_mode: int,
        expected_uid: int,
        executable: bool = False,
        label: str = "preparation",
    ) -> Path:
        try:
            chain = self._open_resource_chain(path.parent)
        except OSError as exc:
            raise ProductionPreparationDeploymentError(
                f"compiled {label} ancestry contains a link or is unavailable"
            ) from exc
        self._descriptors.extend(chain)
        self._record_chain(path.parent, chain)
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=chain[-1],
            )
        except OSError as exc:
            raise ProductionPreparationDeploymentError(
                f"compiled {label} file is unavailable"
            ) from exc
        metadata = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or (
                expected_sha256 is not None
                and digest.hexdigest() != expected_sha256
            )
            or (executable and not metadata.st_mode & stat.S_IXUSR)
        ):
            os.close(descriptor)
            raise ProductionPreparationDeploymentError(
                f"compiled {label} file identity differs"
            )
        self._descriptors.append(descriptor)
        self._file_pins.append(
            _PinnedFile(
                path=path,
                descriptor=descriptor,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                uid=metadata.st_uid,
                mode=stat.S_IMODE(metadata.st_mode),
                sha256=expected_sha256,
            )
        )
        return path

    def pin_private_directory(self, path: Path) -> Path:
        parent_chain = _open_absolute_directory_chain(path.parent, private_leaf=True)
        self._descriptors.extend(parent_chain)
        self._record_chain(path.parent, parent_chain)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_chain[-1])
        except FileExistsError:
            pass
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_chain[-1],
            )
        except OSError as exc:
            raise ProductionPreparationDeploymentError(
                "compiled preparation directory is unavailable"
            ) from exc
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise ProductionPreparationDeploymentError(
                "compiled preparation directory identity differs"
            )
        self._descriptors.append(descriptor)
        self._directory_pins.append(
            (path, descriptor, metadata.st_dev, metadata.st_ino, metadata.st_uid)
        )
        return path

    def verify(self) -> None:
        for path, descriptor, device, inode, uid in self._directory_pins:
            pinned = os.fstat(descriptor)
            try:
                current = path.lstat()
            except OSError as exc:
                raise ProductionPreparationDeploymentError(
                    "compiled preparation directory reference is unavailable"
                ) from exc
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISDIR(current.st_mode)
                or current.st_dev != device
                or current.st_ino != inode
                or current.st_uid != uid
                or pinned.st_dev != device
                or pinned.st_ino != inode
            ):
                raise ProductionPreparationDeploymentError(
                    "compiled preparation directory changed during operation"
                )
        for pin in self._file_pins:
            pinned = os.fstat(pin.descriptor)
            try:
                current = pin.path.lstat()
            except OSError as exc:
                raise ProductionPreparationDeploymentError(
                    "compiled preparation file reference is unavailable"
                ) from exc
            os.lseek(pin.descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            while chunk := os.read(pin.descriptor, 1024 * 1024):
                digest.update(chunk)
            os.lseek(pin.descriptor, 0, os.SEEK_SET)
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or current.st_dev != pin.device
                or current.st_ino != pin.inode
                or current.st_uid != pin.uid
                or current.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != pin.mode
                or pinned.st_dev != pin.device
                or pinned.st_ino != pin.inode
                or pinned.st_nlink != 1
                or stat.S_IMODE(pinned.st_mode) != pin.mode
                or (
                    pin.sha256 is not None
                    and digest.hexdigest() != pin.sha256
                )
            ):
                raise ProductionPreparationDeploymentError(
                    "compiled preparation file changed during operation"
                )

    def close(self) -> None:
        while self._descriptors:
            os.close(self._descriptors.pop())


def _expected_configuration() -> dict[str, object]:
    return {
        "admission_database": str(PRODUCTION_ADMISSION_DATABASE),
        "candidate_authority_path": str(PRODUCTION_CANDIDATE_AUTHORITY_PATH),
        "candidate_authority_sha256": PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        "codex_binary": str(PRODUCTION_CODEX_BINARY),
        "codex_binary_sha256": PRODUCTION_CODEX_BINARY_SHA256,
        "contact_authority_path": str(PRODUCTION_CONTACT_AUTHORITY_PATH),
        "contact_envelope_sha256": PRODUCTION_CONTACT_ENVELOPE_SHA256,
        "contact_public_key_path": str(PRODUCTION_CONTACT_PUBLIC_KEY_PATH),
        "contact_public_key_file_sha256": PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256,
        "contact_registry_path": str(PRODUCTION_CONTACT_REGISTRY_PATH),
        "contact_registry_file_sha256": PRODUCTION_CONTACT_REGISTRY_FILE_SHA256,
        "model": PRODUCTION_CODEX_MODEL,
        "outbox_root": str(PRODUCTION_MARKET_OUTBOX_ROOT),
        "poppler_bin": str(PRODUCTION_POPPLER_BIN),
        "poppler_sha256": dict(PRODUCTION_POPPLER_SHA256),
        "output_root": str(PRODUCTION_PREPARATION_OUTPUT_ROOT),
        "recruiter_archive_root": str(PRODUCTION_RECRUITER_ARCHIVE_ROOT),
        "repository_root": str(PRODUCTION_MARKET_REPOSITORY_ROOT),
        "schema_version": _CONFIG_SCHEMA,
        "timeout_seconds": PRODUCTION_CODEX_TIMEOUT_SECONDS,
        "trust_root_id": PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }


def production_preparation_configuration_bytes() -> bytes:
    return canonical_json_bytes(_expected_configuration())


def installed_production_preparation_deployment() -> _ProductionPreparationDeployment:
    raw = _read_root_owned_configuration(PRODUCTION_PREPARATION_CONFIG_PATH)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionPreparationDeploymentError("preparation deployment is invalid JSON") from exc
    if document != _expected_configuration() or raw != production_preparation_configuration_bytes():
        raise ProductionPreparationDeploymentError("preparation deployment differs from compiled authority")
    if Path(__file__).resolve().parents[3] != PRODUCTION_MARKET_REPOSITORY_ROOT:
        raise ProductionPreparationDeploymentError("preparation executes from another repository")
    return _ProductionPreparationDeployment(
        repository_root=PRODUCTION_MARKET_REPOSITORY_ROOT,
        admission_database=PRODUCTION_ADMISSION_DATABASE,
        outbox_root=PRODUCTION_MARKET_OUTBOX_ROOT,
        candidate_authority_path=PRODUCTION_CANDIDATE_AUTHORITY_PATH,
        contact_authority_path=PRODUCTION_CONTACT_AUTHORITY_PATH,
        contact_public_key_path=PRODUCTION_CONTACT_PUBLIC_KEY_PATH,
        contact_registry_path=PRODUCTION_CONTACT_REGISTRY_PATH,
        output_root=PRODUCTION_PREPARATION_OUTPUT_ROOT,
        recruiter_archive_root=PRODUCTION_RECRUITER_ARCHIVE_ROOT,
        codex_binary=PRODUCTION_CODEX_BINARY,
        model=PRODUCTION_CODEX_MODEL,
        timeout_seconds=PRODUCTION_CODEX_TIMEOUT_SECONDS,
    )


def _source_record_for_application(database: Path, application_id: str) -> str:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT admission_context_bytes FROM application_admissions WHERE application_id=? AND sealed=1",
            (application_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ProductionPreparationDeploymentError("sealed production admission is missing")
    try:
        context = json.loads(bytes(row[0]))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionPreparationDeploymentError("sealed admission context is invalid") from exc
    source_record = context.get("source_record_sha256") if isinstance(context, dict) else None
    if (
        not isinstance(source_record, str)
        or len(source_record) != 64
        or any(c not in "0123456789abcdef" for c in source_record)
        or context.get("environment") != "production"
        or context.get("trust_root_id") != PRODUCTION_HANDOFF_TRUST_ROOT_ID
    ):
        raise ProductionPreparationDeploymentError("sealed admission context differs")
    return source_record


def _open_admission_database(data_descriptor: int) -> tuple[int, int]:
    state_descriptor: int | None = None
    admission_descriptor: int | None = None
    try:
        parent = data_descriptor
        for name in ("state", "jaa-production-admissions"):
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent,
            )
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ProductionPreparationDeploymentError("admission directory is not private")
            if state_descriptor is None:
                state_descriptor = descriptor
            else:
                admission_descriptor = descriptor
            parent = descriptor
        database = os.open(
            "admissions.sqlite3",
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        metadata = os.fstat(database)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            os.close(database)
            raise ProductionPreparationDeploymentError("admission database is not private")
        assert admission_descriptor is not None
        os.close(state_descriptor)
        state_descriptor = None
        return admission_descriptor, database
    except BaseException:
        if admission_descriptor is not None:
            os.close(admission_descriptor)
        raise
    finally:
        if state_descriptor is not None:
            os.close(state_descriptor)


def _verify_preparation_output(
    result: MarketApplicationPreparation,
    output_root: Path,
) -> None:
    expected = output_root / "preparations" / result.preparation_id
    if (
        len(result.preparation_id) != 64
        or any(c not in "0123456789abcdef" for c in result.preparation_id)
        or result.path != expected
    ):
        raise ProductionPreparationDeploymentError(
            "production preparation output path differs"
        )
    chain = _open_absolute_directory_chain(expected, private_leaf=True)
    try:
        for descriptor in chain[-2:]:
            metadata = os.fstat(descriptor)
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ProductionPreparationDeploymentError(
                    "production preparation output directory differs"
                )
        expected_files = {"cover-letter.pdf", "cv.pdf", "receipt.json"}
        actual_files: set[str] = set()
        with os.scandir(f"/proc/self/fd/{chain[-1]}") as entries:
            for entry in entries:
                if entry.name == "objects":
                    continue
                actual_files.add(entry.name)
        if actual_files != expected_files:
            raise ProductionPreparationDeploymentError(
                "production preparation output inventory differs"
            )
        objects_descriptor = os.open(
            "objects",
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=chain[-1],
        )
        try:
            objects_metadata = os.fstat(objects_descriptor)
            if (
                objects_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(objects_metadata.st_mode) != 0o700
            ):
                raise ProductionPreparationDeploymentError(
                    "production preparation object directory differs"
                )
            with os.scandir(f"/proc/self/fd/{objects_descriptor}") as entries:
                object_names = tuple(entry.name for entry in entries)
            if not object_names:
                raise ProductionPreparationDeploymentError(
                    "production preparation objects are absent"
                )
            for name in object_names:
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=objects_descriptor,
                )
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                    ):
                        raise ProductionPreparationDeploymentError(
                            "production preparation object differs"
                        )
                finally:
                    os.close(descriptor)
        finally:
            os.close(objects_descriptor)
        for name in sorted(expected_files):
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=chain[-1],
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise ProductionPreparationDeploymentError(
                        "production preparation output file differs"
                    )
                if name == "receipt.json":
                    digest = hashlib.sha256()
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                    if digest.hexdigest() != result.receipt_sha256:
                        raise ProductionPreparationDeploymentError(
                            "production preparation receipt differs"
                        )
            finally:
                os.close(descriptor)
    finally:
        for descriptor in reversed(chain):
            os.close(descriptor)


def _run_production_preparation(
    application_id: str,
    deployment: _ProductionPreparationDeployment,
) -> MarketApplicationPreparation:
    if (
        not application_id.startswith("app_")
        or len(application_id) != 68
        or any(c not in "0123456789abcdef" for c in application_id[4:])
    ):
        raise ProductionPreparationDeploymentError("application ID is malformed")
    resources = _PinnedPreparationResources()
    pinned: _PinnedProductionPaths | None = None
    admission_descriptor: int | None = None
    database_descriptor: int | None = None
    saved_environment = {
        name: os.environ.get(name)
        for name in (PUBLIC_KEY_ENV, REGISTRY_ENV, "JAA_POPPLER_BIN")
    }
    try:
        for name, expected in PRODUCTION_POPPLER_SHA256.items():
            resources.pin_file(
                PRODUCTION_POPPLER_BIN / name,
                expected_sha256=expected,
                expected_mode=0o755,
                expected_uid=os.geteuid(),
                executable=True,
                label="Poppler",
            )
        resources.pin_file(
            deployment.codex_binary,
            expected_sha256=PRODUCTION_CODEX_BINARY_SHA256,
            expected_mode=0o755,
            expected_uid=0,
            executable=True,
            label="Codex",
        )
        for path, expected in (
            (
                deployment.candidate_authority_path,
                PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
            ),
            (deployment.contact_authority_path, PRODUCTION_CONTACT_ENVELOPE_SHA256),
            (
                deployment.contact_public_key_path,
                PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256,
            ),
            (
                deployment.contact_registry_path,
                PRODUCTION_CONTACT_REGISTRY_FILE_SHA256,
            ),
        ):
            resources.pin_file(
                path,
                expected_sha256=expected,
                expected_mode=0o600,
                expected_uid=os.geteuid(),
                label="authority",
            )
        resources.pin_private_directory(deployment.output_root)
        resources.pin_private_directory(deployment.recruiter_archive_root)
        resources.pin_file(
            deployment.admission_database,
            expected_sha256=None,
            expected_mode=0o600,
            expected_uid=os.geteuid(),
            label="admission database",
        )
        resources.verify()
        pinned = _PinnedProductionPaths(
            _ProductionAdmissionDeployment(
                data_home=PRODUCTION_MARKET_DATA_HOME,
                repository_root=deployment.repository_root,
                outbox_root=deployment.outbox_root,
                execution_receipt_root=PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT,
                admission_root=PRODUCTION_ADMISSION_ROOT,
            )
        )
        current_commit = _git_commit(
            deployment.repository_root,
            repository_descriptor=pinned.repository_descriptor,
        )
        admission_descriptor, database_descriptor = _open_admission_database(
            pinned.data_descriptor
        )
        pinned_database = Path(
            f"/proc/self/fd/{admission_descriptor}/admissions.sqlite3"
        )
        source_record = _source_record_for_application(pinned_database, application_id)
        bundle_descriptor = pinned.open_bundle(source_record)
        adapter = ProtectedLocalOutbox(
            deployment.outbox_root / "bundles" / source_record,
            repository_root=deployment.repository_root,
            expected_source_record_sha256=source_record,
            allowed_producer_commits=frozenset({current_commit}),
            bundle_descriptor=bundle_descriptor,
        )
        pinned.register_adapter(adapter)
        store = HandoffAdmissionStore(
            pinned_database,
            context_authenticator=adapter,
            resolver=adapter,
            current_time_witness=installed_production_current_time_witness(),
        )
        pinned.verify_references()
        resources.verify()
        os.environ[PUBLIC_KEY_ENV] = str(deployment.contact_public_key_path)
        os.environ[REGISTRY_ENV] = str(deployment.contact_registry_path)
        os.environ["JAA_POPPLER_BIN"] = str(PRODUCTION_POPPLER_BIN)

        def runtime(kind: str) -> EditorialCompositionRuntime:
            prefix = "cover_letter_" if kind == "cover_letter" else ""
            return EditorialCompositionRuntime(
                environment="production",
                writer=DetachedCodexEditorialAdapter(
                    stage=f"{prefix}writer" if prefix else "resume_writer",
                    model=deployment.model,
                    codex_binary=str(deployment.codex_binary),
                    environment="production",
                    timeout_seconds=deployment.timeout_seconds,
                ),
                humanizer=DetachedCodexEditorialAdapter(
                    stage=f"{prefix}humanizer" if prefix else "humanizer",
                    model=deployment.model,
                    codex_binary=str(deployment.codex_binary),
                    environment="production",
                    timeout_seconds=deployment.timeout_seconds,
                ),
                document_kind=kind,
            )

        assessor = ProductionDetachedRecruiterAssessor(
            model=deployment.model,
            archive_root=deployment.recruiter_archive_root,
            repository_root=deployment.repository_root,
            cli_timeout_seconds=deployment.timeout_seconds,
            codex_binary=str(deployment.codex_binary),
        )
        result = prepare_admitted_market_application_from_authorities(
            admission_store=store,
            application_id=application_id,
            repository_root=deployment.repository_root,
            data_home=deployment.output_root,
            candidate_authority_path=deployment.candidate_authority_path,
            contact_authority_path=deployment.contact_authority_path,
            input_materializer=CanonicalPreparationInputMaterializer(
                candidate_authority_path=deployment.candidate_authority_path
            ),
            environment="production",
            editorial_runtime=runtime("cv"),
            cover_letter_editorial_runtime=runtime("cover_letter"),
            orchestration_extras={
                "bindings": (),
                "form_fields": (),
                "production_recruiter_assessor": assessor,
            },
        )
        _verify_preparation_output(result, deployment.output_root)
        pinned.verify_references()
        resources.verify()
    finally:
        for name, value in saved_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        if pinned is not None:
            pinned.close()
        if database_descriptor is not None:
            os.close(database_descriptor)
        if admission_descriptor is not None:
            os.close(admission_descriptor)
        resources.close()
    if result.release_authority:
        raise RuntimeError("production preparation unexpectedly acquired release authority")
    return result


def run_production_preparation(*, application_id: str) -> MarketApplicationPreparation:
    return _run_production_preparation(
        application_id, installed_production_preparation_deployment()
    )


__all__ = [
    "PRODUCTION_PREPARATION_CONFIG_PATH",
    "ProductionPreparationDeploymentError",
    "installed_production_preparation_deployment",
    "production_preparation_configuration_bytes",
    "run_production_preparation",
]
