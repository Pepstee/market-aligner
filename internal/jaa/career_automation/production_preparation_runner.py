"""Fixed-root production preparation lifecycle for one admitted application.

This owner is distinct from the reusable preparation coordinator: callers may
choose only the already admitted application ID.  Deployment paths, authorities,
models and transports are compiled and root-configured.  The result is always
non-release and grants no browser or submission authority.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
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

from cv_generation.editorial_composition import (
    DetachedCodexEditorialAdapter,
    EditorialCompositionRuntime,
)
from cv_generation.document_quality import pinned_poppler_runtime

from .candidate_contact_authority import (
    PUBLIC_KEY_ENV,
    REGISTRY_ENV,
    CandidateContactResourceLease,
    CurrentContactProvenance,
    load_current_contact_provenance,
)
from .current_time import installed_production_current_time_witness
from .handoff_admission import (
    ADMISSION_KIND_CURRENT_RUNTIME,
    CURRENT_RUNTIME_AUTHORITY_SCOPE,
    CURRENT_RUNTIME_EMISSION_PROFILE,
    CURRENT_RUNTIME_ENVIRONMENT,
    CURRENT_RUNTIME_FRESHNESS_PROVENANCE,
    CURRENT_RUNTIME_TRUST_MODE,
    CURRENT_RUNTIME_TRUST_ROOT_ID,
    HandoffAdmissionStore,
    ProtectedLocalOutbox,
    VerifiedApplicationInput,
    _parse_current_runtime_handoff,
)
from .market_aligner_preparation import (
    CanonicalPreparationInputMaterializer,
    MarketApplicationMaterializationContext,
    MarketApplicationPreparation,
    prepare_admitted_market_application_from_authorities,
)
from .market_aligner_handoff import HandoffContractError, decode_canonical_json
from .production_handoff_admission_runner import (
    _PinnedProductionPaths,
    _ProductionAdmissionDeployment,
    _open_absolute_directory_chain,
)
from .production_handoff_runner import (
    PRODUCTION_MARKET_DATA_HOME,
    PRODUCTION_MARKET_OUTBOX_ROOT,
    PRODUCTION_MARKET_REPOSITORY_ROOT,
    _read_root_owned_configuration,
    _validate_deployment_roots,
    installed_current_runtime_handoff_deployment,
    installed_production_handoff_deployment,
    select_runtime_deployment,
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
PRODUCTION_CODEX_OWNER_UID = 0
PRODUCTION_CODEX_MODEL = "gpt-5.6-sol"
CURRENT_RUNTIME_CODEX_MODEL = "gpt-6-luna"
PRODUCTION_CODEX_TIMEOUT_SECONDS = 300.0
PRODUCTION_POPPLER_BIN = Path("/home/gutua/.local/poppler/usr/bin")
PRODUCTION_POPPLER_LIBRARY_DIRECTORY = Path(
    "/home/gutua/.local/poppler/usr/lib/x86_64-linux-gnu"
)
PRODUCTION_POPPLER_SHA256 = {
    "pdffonts": "5956c57d42bf8a116aa6c44f961720366664c60471e948d215a698bdb6608fba",
    "pdfinfo": "bc643b05d93f5edf86ac536313c38d759130c8192ea83e0251b9d8d4cb336763",
    "pdftoppm": "ad3659e9229f0609640db64611023130222f892a00706ea318af04a07326014a",
    "pdftotext": "5bc8817737f5a4c94240e3f642943ec085669e22b85af33bae22786a45c8d49e",
}
PRODUCTION_POPPLER_LIBRARY_SHA256 = {
    "libLerc.so.4": "b7c1fe626e31e8c3ecb80d428ffb3a8824fd241ec55c6edc8b12437412206060",
    "libdeflate.so.0": "0e33bbae9bd7f62fd4172ac04d9088736defa499491aacae723732ce4e905f94",
    "libgpgme.so.45.0.1": "caece624998149737441172de399b6927b93b303e55fdd0123ae20904df1234b",
    "libgpgmepp.so.7.0.0": "79d799f07547309334a48360a4344cd6e570068d0f2eec6f88c1209facc9448b",
    "libjbig.so.0": "19ae16694b0f2c442b367fd9dfecf8da68c9b8ded0bc9029c1d53a9ba91a4151",
    "libjpeg.so.8.2.2": "90a1eebead4d7c1abc46cf9c66c5392c60fc2c16f038af20fc7efbd0d8dd427f",
    "libpoppler.so.156.0.0": "6a315c699daad7f4727f8177cbe8f6241735bd5066fcf3836682ac0e533c6db7",
    "libtiff.so.6.1.0": "d65b506791e2469e886c716a7993b5e65ce40015aef1d15a678804a9fc3c4844",
    "libwebp.so.7.1.10": "0b477702bb43d90a1205813a9c211faa8dfef025a258b9d60663b37311b87c08",
}
_CONFIG_SCHEMA = "jaa.production-application-preparation-deployment.v1"
_HANDOFF_AUTHORITY_PATHS = (
    "src/market_aligner/applications/producer.py",
    "src/market_aligner/applications/handoff.py",
    "src/market_aligner/applications/production_handoff.py",
    "src/market_aligner/service/api.py",
    "internal/jaa/career_automation/handoff_admission.py",
    "internal/jaa/career_automation/production_handoff_runner.py",
    "internal/jaa/career_automation/production_handoff_admission_runner.py",
    "internal/jaa/career_automation/current_time.py",
    "internal/jaa/career_automation/authenticated_time_witness.py",
)
_CURRENT_RUNTIME_READER_PATHS = frozenset(
    {
        "internal/jaa/career_automation/handoff_admission.py",
        "internal/jaa/career_automation/production_handoff_admission_runner.py",
    }
)


class ProductionPreparationDeploymentError(ValueError):
    pass


@dataclass(frozen=True)
class _ProductionPreparationDeployment:
    repository_root: Path
    data_home: Path
    admission_database: Path
    outbox_root: Path
    candidate_authority_path: Path
    contact_authority_path: Path | None
    contact_public_key_path: Path | None
    contact_registry_path: Path | None
    output_root: Path
    recruiter_archive_root: Path
    codex_binary: Path | None
    poppler_bin: Path | None
    model: str
    timeout_seconds: float
    current_runtime: bool = False
    candidate_authority_sha256: str | None = None
    recovery_manifest_relative_path: str | None = None

    @property
    def poppler_library_directory(self) -> Path:
        if self.poppler_bin is None:
            raise ProductionPreparationDeploymentError(
                "current materialization does not configure Poppler"
            )
        return self.poppler_bin.parent / "lib/x86_64-linux-gnu"


def _decode_current_artifact_document(raw: object) -> dict[str, object]:
    from market_aligner.profiler.current_activation import (
        _canonical_document_bytes,
        _strict_json_loads,
    )

    try:
        if type(raw) is not bytes:
            raise ValueError
        document = _strict_json_loads(raw)
        if (
            type(document) is not dict
            or _canonical_document_bytes(document) != raw
        ):
            raise ValueError
    except (TypeError, ValueError, UnicodeDecodeError, RecursionError):
        raise ValueError("current artifact document is invalid") from None
    return document


def _resolve_current_selected_track(
    selection: object,
    promotion: object,
    *,
    expected_profile_id: str,
    expected_source_job_key: str,
) -> str:
    invalid = "selected track binding invalid"
    if (
        type(selection) is not dict
        or type(promotion) is not dict
        or type(expected_profile_id) is not str
        or not expected_profile_id.strip()
        or expected_profile_id != expected_profile_id.strip()
        or type(expected_source_job_key) is not str
        or not expected_source_job_key.strip()
        or expected_source_job_key != expected_source_job_key.strip()
    ):
        raise ValueError(invalid)
    if (
        type(selection.get("decision")) is not str
        or selection["decision"] != "selected_for_application"
        or selection.get("hard_gate_passed") is not True
        or type(selection.get("source_job_key")) is not str
        or selection["source_job_key"] != expected_source_job_key
    ):
        raise ValueError(invalid)
    selection_promotion_sha256 = selection.get("promotion_receipt_sha256")
    promotion_sha256 = promotion.get("receipt_sha256")
    if (
        type(selection_promotion_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", selection_promotion_sha256) is None
        or type(promotion_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", promotion_sha256) is None
        or selection_promotion_sha256 != promotion_sha256
        or type(promotion.get("schema_version")) is not str
        or promotion["schema_version"]
        != "market-aligner.assessment-promotion-receipt.v1"
        or type(promotion.get("decision")) is not str
        or promotion["decision"] != "pass"
        or type(promotion.get("profile_id")) is not str
        or promotion["profile_id"] != expected_profile_id
        or type(promotion.get("job_key")) is not str
        or promotion["job_key"] != expected_source_job_key
    ):
        raise ValueError(invalid)
    binding = promotion.get("binding")
    if (
        type(binding) is not dict
        or type(binding.get("schema_version")) is not str
        or binding["schema_version"]
        != "market-aligner.assessment-promotion-binding.v1"
        or type(binding.get("profile_id")) is not str
        or binding["profile_id"] != expected_profile_id
        or type(binding.get("job_key")) is not str
        or binding["job_key"] != expected_source_job_key
    ):
        raise ValueError(invalid)
    track = binding.get("track")
    if (
        type(track) is not str
        or not track.strip()
        or track != track.strip()
    ):
        raise ValueError(invalid)
    return track


def _projection_from_current_bundle(
    documents: object,
    receipt: object,
    *,
    expected_activation_sha256: str,
) -> dict[str, object]:
    if type(documents) is not dict or type(receipt) is not dict:
        raise ValueError("current projection bundle is invalid")
    projection = _decode_current_artifact_document(
        documents.get("candidate_projection_bytes")
    )
    if receipt.get("activation_sha256") != expected_activation_sha256:
        raise ValueError("current projection bundle is invalid")
    return projection


def _load_pinned_current_contact_provenance(
    *,
    deployment: _ProductionPreparationDeployment,
    verified,
    candidate_authority_bytes: bytes,
) -> tuple[CurrentContactProvenance, dict[str, str], bytes]:
    from market_aligner.profiler.current_activation import (
        PinnedCurrentActivationArtifact,
        PinnedRecoveryInputs,
        compile_current_profile_projection,
        read_current_candidate_policy_canary_for_activation,
        read_current_profile_projection_bundle,
        _strict_json_loads,
    )
    from market_aligner.service.api import MarketAlignerService

    invalid = "current contact inputs differ from the admitted profile"
    try:
        authority = _decode_current_artifact_document(candidate_authority_bytes)
        selection = decode_canonical_json(
            verified.selection_receipt_bytes,
            label="current contact selection receipt",
        )
        promotion = decode_canonical_json(
            verified.assessment_receipt_bytes,
            label="current assessment promotion receipt",
        )
        if (
            type(authority) is not dict
            or type(selection) is not dict
            or hashlib.sha256(candidate_authority_bytes).hexdigest()
            != verified.candidate_authority_sha256
            or candidate_authority_bytes != verified.candidate_authority_bytes
            or hashlib.sha256(verified.selection_receipt_bytes).hexdigest()
            != verified.selection_receipt_sha256
            or hashlib.sha256(verified.assessment_receipt_bytes).hexdigest()
            != verified.assessment_receipt_sha256
        ):
            raise ValueError(invalid)
        track = _resolve_current_selected_track(
            selection,
            promotion,
            expected_profile_id=verified.profile_id,
            expected_source_job_key=verified.source_job_key,
        )
        projection = authority.get("candidate_projection")
        profile_binding = authority.get("profile_binding")
        activation_sha256 = authority.get("activation_sha256")
        if (
            type(projection) is not dict
            or type(profile_binding) is not dict
            or set(profile_binding)
            != {"profile_id", "profile_sha256", "evidence_ledger_sha256"}
            or profile_binding.get("profile_id") != verified.profile_id
            or type(activation_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", activation_sha256) is None
            or type(projection.get("source_hashes")) is not dict
            or projection["source_hashes"].get("current_profile_activation")
            != activation_sha256
            or type(projection["source_hashes"].get("recovery_manifest"))
            is not str
            or re.fullmatch(
                r"[0-9a-f]{64}",
                projection["source_hashes"]["recovery_manifest"],
            )
            is None
        ):
            raise ValueError(invalid)
        service = MarketAlignerService(deployment.data_home)
        snapshot = service.profiles.coherent_snapshot(
            verified.profile_id, require_committed_generation=True
        )
        try:
            if (
                snapshot.profile.version != verified.profile_version
                or profile_binding.get("profile_sha256")
                != snapshot.hashes.get("profile_sha256")
                or profile_binding.get("evidence_ledger_sha256")
                != snapshot.hashes.get("evidence_ledger_sha256")
            ):
                raise ValueError(invalid)
            current_documents, current_projection_receipt = read_current_profile_projection_bundle(
                data_home=deployment.data_home,
                profile_id=verified.profile_id,
                candidate_authority_path=deployment.candidate_authority_path,
                expected_candidate_authority_sha256=(
                    deployment.candidate_authority_sha256
                ),
                profile_sha256=snapshot.hashes["profile_sha256"],
                evidence_ledger_sha256=snapshot.hashes[
                    "evidence_ledger_sha256"
                ],
            )
            current_projection = _projection_from_current_bundle(
                current_documents,
                current_projection_receipt,
                expected_activation_sha256=activation_sha256,
            )
            approved_evidence_bytes = current_documents.get(
                "evidence_packet_bytes"
            )
            projection_source_hashes = current_projection.get("source_hashes")
            if (
                current_documents.get("candidate_authority_bytes")
                != candidate_authority_bytes
                or current_projection != projection
                or type(approved_evidence_bytes) is not bytes
                or type(projection_source_hashes) is not dict
                or type(projection_source_hashes.get("approved_evidence"))
                is not str
                or hashlib.sha256(approved_evidence_bytes).hexdigest()
                != projection_source_hashes["approved_evidence"]
            ):
                raise ValueError(invalid)
            recovery_manifest_sha256 = projection["source_hashes"][
                "recovery_manifest"
            ]
            canary_bytes, canary_sha256 = (
                read_current_candidate_policy_canary_for_activation(
                    data_home=deployment.data_home,
                    profile_id=verified.profile_id,
                    track=track,
                    source_job_key=verified.source_job_key,
                    activation_sha256=activation_sha256,
                )
            )
            if hashlib.sha256(canary_bytes).hexdigest() != canary_sha256:
                raise ValueError(invalid)
            canary = _strict_json_loads(canary_bytes)
            if (
                type(canary) is not dict
                or canary.get("recovery_manifest_sha256")
                != recovery_manifest_sha256
            ):
                raise ValueError(invalid)
            activation_name = canary.get("activation_name")
            activation_file_sha256 = canary.get("activation_file_sha256")
            with PinnedCurrentActivationArtifact(
                data_home=deployment.data_home,
                profile_id=verified.profile_id,
                artifact_name=activation_name,
                expected_sha256=activation_file_sha256,
            ) as activation:
                activation_document = activation.document
                approval_id = activation_document.get("approval_id")
                source_hashes = activation_document.get("source_hashes")
                if (
                    activation_document.get("profile_id") != verified.profile_id
                    or activation_document.get("activation_sha256")
                    != activation_sha256
                    or type(approval_id) is not str
                    or not approval_id
                    or type(source_hashes) is not dict
                    or source_hashes.get("recovery_manifest")
                    != recovery_manifest_sha256
                ):
                    raise ValueError(invalid)
                with PinnedRecoveryInputs(
                    data_home=deployment.data_home,
                    manifest_relative_path=(
                        deployment.recovery_manifest_relative_path
                    ),
                    expected_manifest_sha256=recovery_manifest_sha256,
                    approval_id=approval_id,
                    include_saved_cvs=True,
                ) as recovered:
                    compiled_documents = compile_current_profile_projection(
                        profile_id=verified.profile_id,
                        activation_bytes=activation.raw_bytes,
                        expected_activation_sha256=activation.sha256,
                        manifest_bytes=recovered.manifest_bytes,
                        expected_manifest_sha256=recovery_manifest_sha256,
                        approval_id=approval_id,
                        recovered_profile_bytes=recovered.files[
                            "candidate_profile_and_job_preferences"
                        ],
                        recovered_evidence_bytes=recovered.files[
                            "existing_profile_claims_and_provenance"
                        ],
                        snapshot=snapshot,
                    )
                    if compiled_documents != current_documents:
                        raise ValueError(invalid)
                    bindings = {
                        "manifest_sha256": recovery_manifest_sha256,
                        "activation_sha256": activation_sha256,
                        "profile_sha256": snapshot.hashes["profile_sha256"],
                        "approval_id": approval_id,
                    }
                    contact_provenance = load_current_contact_provenance(
                        saved_cv_bytes=recovered.saved_cv_bytes,
                        saved_cv_descriptors=recovered.saved_cv_descriptors,
                        bindings=bindings,
                    )
                    activation.revalidate()
                    recovered.revalidate()
                    snapshot.revalidate()
                    return contact_provenance, bindings, approved_evidence_bytes
        finally:
            snapshot.close()
    except (OSError, TypeError, ValueError, KeyError, HandoffContractError):
        raise ProductionPreparationDeploymentError(invalid) from None


@dataclass(frozen=True)
class _AdmittedSourceRecord:
    source_record_sha256: str
    producer_commit_sha: str


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

    def file_descriptor(self, path: Path) -> int:
        matches = [pin.descriptor for pin in self._file_pins if pin.path == path]
        if len(matches) != 1:
            raise ProductionPreparationDeploymentError(
                "compiled preparation file lease is absent"
            )
        return matches[0]

    def file_bytes(self, path: Path) -> bytes:
        descriptor = self.file_descriptor(path)
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return b"".join(chunks)

    def pin_contact_registry_chain(
        self, head_path: Path
    ) -> tuple[tuple[Path, bytes], ...]:
        """Pin every signed registry predecessor while retaining the exact head."""

        chain: list[tuple[Path, bytes]] = []
        cursor = head_path
        seen: set[Path] = set()
        while True:
            if cursor in seen or len(seen) >= 64:
                raise ProductionPreparationDeploymentError(
                    "compiled contact registry chain is cyclic or unbounded"
                )
            seen.add(cursor)
            if cursor != head_path:
                self.pin_file(
                    cursor,
                    expected_sha256=None,
                    expected_mode=0o600,
                    expected_uid=os.geteuid(),
                    label="contact registry predecessor",
                )
            value = self.file_bytes(cursor)
            try:
                document = json.loads(value)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProductionPreparationDeploymentError(
                    "compiled contact registry chain is invalid JSON"
                ) from exc
            prior = document.get("prior_registry_sha256")
            chain.append((cursor, value))
            if prior is None:
                return tuple(chain)
            if (
                not isinstance(prior, str)
                or len(prior) != 64
                or any(character not in "0123456789abcdef" for character in prior)
            ):
                raise ProductionPreparationDeploymentError(
                    "compiled contact registry predecessor is malformed"
                )
            cursor = head_path.parent / f"{prior}.json"

    def directory_descriptor(self, path: Path) -> int:
        matches = [row[1] for row in self._directory_pins if row[0] == path]
        if len(matches) != 1:
            raise ProductionPreparationDeploymentError(
                "compiled preparation directory lease is absent"
            )
        return matches[0]

    def close(self) -> None:
        while self._descriptors:
            os.close(self._descriptors.pop())


_PREPARATION_HOST_ARGUMENTS = (
    "data_home",
    "repository_root",
    "outbox_root",
    "candidate_authority_path",
    "contact_authority_path",
    "contact_public_key_path",
    "contact_registry_path",
    "codex_binary",
    "poppler_bin",
)
_PREPARATION_PATH_KEYS = frozenset(
    {
        "admission_database",
        "candidate_authority_path",
        "codex_binary",
        "contact_authority_path",
        "contact_public_key_path",
        "contact_registry_path",
        "outbox_root",
        "poppler_bin",
        "output_root",
        "recruiter_archive_root",
        "repository_root",
    }
)


def _normalized_preparation_path(value: object, label: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise ProductionPreparationDeploymentError(
            f"preparation configuration {label} is invalid"
        )
    path = Path(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or str(path) != str(value)
        or path == Path("/")
    ):
        raise ProductionPreparationDeploymentError(
            f"preparation configuration {label} is not a normalized absolute path"
        )
    return path


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _expected_configuration(
    *,
    data_home: str | Path = PRODUCTION_MARKET_DATA_HOME,
    repository_root: str | Path = PRODUCTION_MARKET_REPOSITORY_ROOT,
    outbox_root: str | Path = PRODUCTION_MARKET_OUTBOX_ROOT,
    candidate_authority_path: str | Path = PRODUCTION_CANDIDATE_AUTHORITY_PATH,
    contact_authority_path: str | Path = PRODUCTION_CONTACT_AUTHORITY_PATH,
    contact_public_key_path: str | Path = PRODUCTION_CONTACT_PUBLIC_KEY_PATH,
    contact_registry_path: str | Path = PRODUCTION_CONTACT_REGISTRY_PATH,
    codex_binary: str | Path = PRODUCTION_CODEX_BINARY,
    poppler_bin: str | Path = PRODUCTION_POPPLER_BIN,
) -> dict[str, object]:
    data_home_path = _normalized_preparation_path(data_home, "data_home")
    repository_path = _normalized_preparation_path(repository_root, "repository_root")
    outbox_path = _normalized_preparation_path(outbox_root, "outbox_root")
    authority_path = _normalized_preparation_path(
        candidate_authority_path, "candidate_authority_path"
    )
    contact_path = _normalized_preparation_path(
        contact_authority_path, "contact_authority_path"
    )
    public_key_path = _normalized_preparation_path(
        contact_public_key_path, "contact_public_key_path"
    )
    registry_path = _normalized_preparation_path(
        contact_registry_path, "contact_registry_path"
    )
    codex_path = _normalized_preparation_path(codex_binary, "codex_binary")
    poppler_path = _normalized_preparation_path(poppler_bin, "poppler_bin")
    document = {
        "admission_database": str(
            data_home_path / "state/jaa-production-admissions/admissions.sqlite3"
        ),
        "candidate_authority_path": str(authority_path),
        "candidate_authority_sha256": PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        "codex_binary": str(codex_path),
        "codex_binary_sha256": PRODUCTION_CODEX_BINARY_SHA256,
        "contact_authority_path": str(contact_path),
        "contact_envelope_sha256": PRODUCTION_CONTACT_ENVELOPE_SHA256,
        "contact_public_key_path": str(public_key_path),
        "contact_public_key_file_sha256": PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256,
        "contact_registry_path": str(registry_path),
        "contact_registry_file_sha256": PRODUCTION_CONTACT_REGISTRY_FILE_SHA256,
        "model": PRODUCTION_CODEX_MODEL,
        "outbox_root": str(outbox_path),
        "poppler_bin": str(poppler_path),
        "poppler_sha256": dict(PRODUCTION_POPPLER_SHA256),
        "output_root": str(
            data_home_path / "state/jaa-production-preparations"
        ),
        "recruiter_archive_root": str(
            data_home_path / "state/jaa-production-recruiter-diagnostics"
        ),
        "repository_root": str(repository_path),
        "schema_version": _CONFIG_SCHEMA,
        "timeout_seconds": PRODUCTION_CODEX_TIMEOUT_SECONDS,
        "trust_root_id": PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }
    _validate_preparation_configuration(document)
    return document


def _validate_preparation_configuration(document: object) -> dict[str, object]:
    if type(document) is not dict:
        raise ProductionPreparationDeploymentError(
            "preparation deployment keys differ from the supported schema"
        )
    expected = {
        "admission_database",
        "candidate_authority_path",
        "candidate_authority_sha256",
        "codex_binary",
        "codex_binary_sha256",
        "contact_authority_path",
        "contact_envelope_sha256",
        "contact_public_key_path",
        "contact_public_key_file_sha256",
        "contact_registry_path",
        "contact_registry_file_sha256",
        "model",
        "outbox_root",
        "poppler_bin",
        "poppler_sha256",
        "output_root",
        "recruiter_archive_root",
        "repository_root",
        "schema_version",
        "timeout_seconds",
        "trust_root_id",
    }
    if set(document) != expected:
        raise ProductionPreparationDeploymentError(
            "preparation deployment keys differ from the supported schema"
        )
    fixed_values = {
        "candidate_authority_sha256": PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        "codex_binary_sha256": PRODUCTION_CODEX_BINARY_SHA256,
        "contact_envelope_sha256": PRODUCTION_CONTACT_ENVELOPE_SHA256,
        "contact_public_key_file_sha256": PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256,
        "contact_registry_file_sha256": PRODUCTION_CONTACT_REGISTRY_FILE_SHA256,
        "model": PRODUCTION_CODEX_MODEL,
        "poppler_sha256": dict(PRODUCTION_POPPLER_SHA256),
        "schema_version": _CONFIG_SCHEMA,
        "timeout_seconds": PRODUCTION_CODEX_TIMEOUT_SECONDS,
        "trust_root_id": PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }
    if any(document.get(key) != value for key, value in fixed_values.items()):
        raise ProductionPreparationDeploymentError(
            "preparation deployment authority or dependency identity differs"
        )
    paths = {
        key: _normalized_preparation_path(document.get(key), key)
        for key in _PREPARATION_PATH_KEYS
    }
    database = paths["admission_database"]
    if database.parts[-3:] != (
        "state",
        "jaa-production-admissions",
        "admissions.sqlite3",
    ):
        raise ProductionPreparationDeploymentError(
            "preparation admission database is outside the deployed data home"
        )
    data_home = database.parents[2]
    if (
        paths["output_root"]
        != data_home / "state/jaa-production-preparations"
        or paths["recruiter_archive_root"]
        != data_home / "state/jaa-production-recruiter-diagnostics"
    ):
        raise ProductionPreparationDeploymentError(
            "preparation output roots differ from the deployed data home"
        )
    core_roots = (
        paths["repository_root"],
        data_home,
        paths["outbox_root"],
    )
    if any(
        _paths_overlap(core_roots[left], core_roots[right])
        for left in range(len(core_roots))
        for right in range(left + 1, len(core_roots))
    ):
        raise ProductionPreparationDeploymentError(
            "preparation repository, data and outbox roots overlap"
        )
    external_files = (
        paths["candidate_authority_path"],
        paths["contact_authority_path"],
        paths["contact_public_key_path"],
        paths["contact_registry_path"],
        paths["codex_binary"],
        paths["poppler_bin"],
    )
    if any(
        _paths_overlap(path, root)
        for path in external_files
        for root in core_roots
    ):
        raise ProductionPreparationDeploymentError(
            "preparation authority or dependency path overlaps a deployment root"
        )
    if paths["poppler_bin"].name != "bin":
        raise ProductionPreparationDeploymentError(
            "Poppler binary directory must be named bin"
        )
    return document


def production_preparation_configuration_bytes(
    **host_paths: str | Path,
) -> bytes:
    if host_paths and set(host_paths) != set(_PREPARATION_HOST_ARGUMENTS):
        raise ProductionPreparationDeploymentError(
            "host preparation requires all nine deployment paths"
        )
    document = (
        _expected_configuration(**host_paths)
        if host_paths
        else _expected_configuration()
    )
    return canonical_json_bytes(document)


def installed_production_preparation_deployment() -> _ProductionPreparationDeployment:
    raw = _read_root_owned_configuration(PRODUCTION_PREPARATION_CONFIG_PATH)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionPreparationDeploymentError("preparation deployment is invalid JSON") from exc
    validated = _validate_preparation_configuration(document)
    if raw != canonical_json_bytes(validated):
        raise ProductionPreparationDeploymentError(
            "preparation deployment is not canonical JSON"
        )
    values = {
        key: Path(validated[key])
        for key in _PREPARATION_PATH_KEYS
    }
    data_home = values["admission_database"].parents[2]
    handoff = installed_production_handoff_deployment()
    if (
        data_home != handoff.data_home
        or values["repository_root"] != handoff.repository_root
        or values["outbox_root"] != handoff.output_root
        or values["candidate_authority_path"] != handoff.candidate_authority_path
        or validated["candidate_authority_sha256"]
        != handoff.candidate_authority_sha256
    ):
        raise ProductionPreparationDeploymentError(
            "preparation deployment differs from the installed handoff authority"
        )
    if Path(__file__).resolve().parents[3] != values["repository_root"]:
        raise ProductionPreparationDeploymentError("preparation executes from another repository")
    return _ProductionPreparationDeployment(
        repository_root=values["repository_root"],
        data_home=data_home,
        admission_database=values["admission_database"],
        outbox_root=values["outbox_root"],
        candidate_authority_path=values["candidate_authority_path"],
        contact_authority_path=values["contact_authority_path"],
        contact_public_key_path=values["contact_public_key_path"],
        contact_registry_path=values["contact_registry_path"],
        output_root=values["output_root"],
        recruiter_archive_root=values["recruiter_archive_root"],
        codex_binary=values["codex_binary"],
        poppler_bin=values["poppler_bin"],
        model=PRODUCTION_CODEX_MODEL,
        timeout_seconds=PRODUCTION_CODEX_TIMEOUT_SECONDS,
    )


def _current_preparation_deployment(
    handoff, recovery_manifest_relative_path: str
) -> _ProductionPreparationDeployment:
    if (
        type(recovery_manifest_relative_path) is not str
        or not recovery_manifest_relative_path.startswith("recovered-inputs/")
        or "\\" in recovery_manifest_relative_path
        or "//" in recovery_manifest_relative_path
        or any(
            part in {"", ".", ".."}
            for part in recovery_manifest_relative_path.split("/")
        )
        or not recovery_manifest_relative_path.endswith("/recovery-manifest.json")
    ):
        raise ProductionPreparationDeploymentError(
            "current recovery manifest locator is invalid"
        )
    data_home = handoff.data_home
    return _ProductionPreparationDeployment(
        repository_root=handoff.repository_root,
        data_home=data_home,
        admission_database=(
            data_home / "state/jaa-production-admissions/admissions.sqlite3"
        ),
        outbox_root=handoff.output_root,
        candidate_authority_path=handoff.candidate_authority_path,
        contact_authority_path=None,
        contact_public_key_path=None,
        contact_registry_path=None,
        output_root=data_home / "state/jaa-production-preparations",
        recruiter_archive_root=(
            data_home / "state/jaa-production-recruiter-diagnostics"
        ),
        codex_binary=None,
        poppler_bin=None,
        model=CURRENT_RUNTIME_CODEX_MODEL,
        timeout_seconds=PRODUCTION_CODEX_TIMEOUT_SECONDS,
        current_runtime=True,
        candidate_authority_sha256=handoff.candidate_authority_sha256,
        recovery_manifest_relative_path=recovery_manifest_relative_path,
    )


def _current_runtime_tool_paths() -> tuple[Path, Path]:
    codex_found = shutil.which("codex")
    poppler_found = {
        name: shutil.which(name) for name in PRODUCTION_POPPLER_SHA256
    }
    if codex_found is None or any(value is None for value in poppler_found.values()):
        raise ProductionPreparationDeploymentError(
            "current preparation tools are unavailable"
        )
    codex_path = Path(codex_found).resolve(strict=True)
    poppler_paths = {
        name: Path(value).resolve(strict=True)
        for name, value in poppler_found.items()
        if value is not None
    }
    if len({path.parent for path in poppler_paths.values()}) != 1:
        raise ProductionPreparationDeploymentError(
            "current Poppler tools do not share a pinned directory"
        )
    for path in (codex_path, *poppler_paths.values()):
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & stat.S_IXUSR
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ProductionPreparationDeploymentError(
                "current preparation tool identity is invalid"
            )
    return codex_path, next(iter(poppler_paths.values())).parent


def _source_record_for_application(
    database: Path, application_id: str
) -> _AdmittedSourceRecord:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        current_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='current_runtime_admissions'"
        ).fetchone()
        current_row = (
            connection.execute(
                "SELECT * FROM current_runtime_admissions WHERE application_id=?",
                (application_id,),
            ).fetchone()
            if current_table is not None
            else None
        )
        if current_row is not None:
            legacy_conflict = connection.execute(
                "SELECT 1 FROM application_admissions WHERE application_id=?",
                (application_id,),
            ).fetchone()
            if legacy_conflict is not None:
                raise ProductionPreparationDeploymentError(
                    "admission mode conflicts"
                )
            return _current_runtime_source_record(current_row, application_id)
        row = connection.execute(
            "SELECT admission_context_bytes, admission_context_sha256, "
            "producer_commit_sha, producer_product, environment, trust_root_id, "
            "handoff_root_sha256 FROM application_admissions "
            "WHERE application_id=? AND sealed=1",
            (application_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ProductionPreparationDeploymentError("sealed production admission is missing")
    try:
        context_bytes = bytes(row[0])
        context = json.loads(context_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionPreparationDeploymentError("sealed admission context is invalid") from exc
    source_record = context.get("source_record_sha256") if isinstance(context, dict) else None
    producer_commit = context.get("producer_commit_sha") if isinstance(context, dict) else None
    if (
        not isinstance(source_record, str)
        or len(source_record) != 64
        or any(c not in "0123456789abcdef" for c in source_record)
        or not isinstance(producer_commit, str)
        or len(producer_commit) != 40
        or any(c not in "0123456789abcdef" for c in producer_commit)
        or canonical_json_bytes(context) != context_bytes
        or hashlib.sha256(context_bytes).hexdigest() != row[1]
        or producer_commit != row[2]
        or context.get("producer_product") != row[3]
        or context.get("environment") != row[4]
        or context.get("trust_root_id") != row[5]
        or context.get("handoff_root_sha256") != row[6]
        or row[3] != "market-aligner"
        or context.get("environment") != "production"
        or context.get("trust_root_id") != PRODUCTION_HANDOFF_TRUST_ROOT_ID
    ):
        raise ProductionPreparationDeploymentError("sealed admission context differs")
    return _AdmittedSourceRecord(
        source_record_sha256=source_record,
        producer_commit_sha=producer_commit,
    )


def _current_runtime_source_record(
    row: sqlite3.Row, application_id: str
) -> _AdmittedSourceRecord:
    error = ProductionPreparationDeploymentError(
        "current runtime admission differs"
    )
    if (
        row["application_id"] != application_id
        or row["admission_kind"] != ADMISSION_KIND_CURRENT_RUNTIME
        or row["environment"] != CURRENT_RUNTIME_ENVIRONMENT
        or row["authority_scope"] != CURRENT_RUNTIME_AUTHORITY_SCOPE
        or row["emission_profile"] != CURRENT_RUNTIME_EMISSION_PROFILE
        or row["trust_mode"] != CURRENT_RUNTIME_TRUST_MODE
        or row["trust_root_id"] != CURRENT_RUNTIME_TRUST_ROOT_ID
        or row["producer_product"] != "market-aligner"
        or row["freshness_provenance"] != CURRENT_RUNTIME_FRESHNESS_PROVENANCE
        or type(row["sealed"]) is not int
        or row["sealed"] != 1
        or type(row["reference_count"]) is not int
        or row["reference_count"] < 1
    ):
        raise error

    context_bytes = row["admission_context_bytes"]
    if type(context_bytes) is not bytes:
        raise error
    try:
        context = decode_canonical_json(
            context_bytes, label="current runtime admission context"
        )
    except HandoffContractError:
        raise error from None
    context_keys = {
        "environment",
        "handoff_root_sha256",
        "issued_at",
        "producer_commit_sha",
        "producer_product",
        "source_record_sha256",
        "trust_mode",
        "trust_proof_sha256",
        "trust_root_id",
    }
    if (
        type(context) is not dict
        or set(context) != context_keys
        or canonical_json_bytes(context) != context_bytes
    ):
        raise error

    source_record = context["source_record_sha256"]
    producer_commit = context["producer_commit_sha"]
    digest_fields = (
        source_record,
        row["handoff_root_sha256"],
        row["payload_sha256"],
        row["vacancy_snapshot_sha256"],
        row["logical_identity_sha256"],
        row["admission_context_sha256"],
        row["context_authenticator_sha256"],
        row["verification_receipt_sha256"],
    )
    if (
        type(source_record) is not str
        or any(
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in digest_fields
        )
        or type(producer_commit) is not str
        or len(producer_commit) != 40
        or any(character not in "0123456789abcdef" for character in producer_commit)
        or context["environment"] != CURRENT_RUNTIME_ENVIRONMENT
        or context["trust_mode"] != CURRENT_RUNTIME_TRUST_MODE
        or context["trust_root_id"] != CURRENT_RUNTIME_TRUST_ROOT_ID
        or context["producer_product"] != "market-aligner"
        or context["producer_commit_sha"] != row["producer_commit_sha"]
        or context["handoff_root_sha256"] != row["handoff_root_sha256"]
        or hashlib.sha256(context_bytes).hexdigest()
        != row["admission_context_sha256"]
    ):
        raise error
    context_basis = dict(context)
    proof = context_basis.pop("trust_proof_sha256")
    if (
        type(proof) is not str
        or len(proof) != 64
        or any(character not in "0123456789abcdef" for character in proof)
        or hashlib.sha256(canonical_json_bytes(context_basis)).hexdigest() != proof
    ):
        raise error

    original_bytes = row["original_bytes"]
    receipt_bytes = row["verification_receipt_bytes"]
    if type(original_bytes) is not bytes or type(receipt_bytes) is not bytes:
        raise error
    try:
        handoff = _parse_current_runtime_handoff(original_bytes)
        receipt = decode_canonical_json(
            receipt_bytes, label="current runtime admission receipt"
        )
    except (ValueError, HandoffContractError):
        raise error from None
    if (
        hashlib.sha256(original_bytes).hexdigest() != row["handoff_root_sha256"]
        or row["original_bytes_sha256"] != row["handoff_root_sha256"]
        or handoff.application_id != application_id
        or handoff.emission_profile != CURRENT_RUNTIME_EMISSION_PROFILE
        or handoff.strict_profile
        or handoff.root_sha256 != row["handoff_root_sha256"]
        or handoff.payload_sha256 != row["payload_sha256"]
        or handoff.payload["profile_id"] != row["profile_id"]
        or handoff.payload["profile_version"] != row["profile_version"]
        or handoff.payload["job_key"] != row["job_key"]
        or handoff.payload["producer"]["product"] != row["producer_product"]
        or handoff.payload["producer"]["commit_sha"] != producer_commit
        or handoff.payload["vacancy"]["vacancy_snapshot_sha256"]
        != row["vacancy_snapshot_sha256"]
        or row["vacancy_source_identity"] != handoff.vacancy_source_identity
        or row["logical_identity_json"]
        != canonical_json_bytes(handoff.logical_identity_document).decode("utf-8")
        or row["logical_identity_sha256"] != handoff.logical_identity_sha256
    ):
        raise error

    outbox_identity = {
        "allowed_producer_commits": [producer_commit],
        "source_record_sha256": source_record,
        "trust_root_id": CURRENT_RUNTIME_TRUST_ROOT_ID,
    }
    authenticator_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {"kind": "protected-local-outbox-context", **outbox_identity}
        )
    ).hexdigest()
    expected_receipt = {
        "admission_context_sha256": row["admission_context_sha256"],
        "admission_kind": ADMISSION_KIND_CURRENT_RUNTIME,
        "admitted_at": row["admitted_at"],
        "authority_scope": CURRENT_RUNTIME_AUTHORITY_SCOPE,
        "context_authenticator_sha256": authenticator_sha256,
        "emission_profile": CURRENT_RUNTIME_EMISSION_PROFILE,
        "environment": CURRENT_RUNTIME_ENVIRONMENT,
        "freshness_provenance": CURRENT_RUNTIME_FRESHNESS_PROVENANCE,
        "handoff_root_sha256": row["handoff_root_sha256"],
        "payload_sha256": row["payload_sha256"],
        "release_authority": False,
        "release_token_issued": False,
        "schema_version": "market-aligner.current-runtime-handoff-verification.v1",
        "submission_authority": False,
        "trust_mode": CURRENT_RUNTIME_TRUST_MODE,
        "trust_root_id": CURRENT_RUNTIME_TRUST_ROOT_ID,
    }
    if (
        hashlib.sha256(receipt_bytes).hexdigest()
        != row["verification_receipt_sha256"]
        or type(receipt) is not dict
        or any(receipt.get(key) != value for key, value in expected_receipt.items())
        or any(
            type(receipt.get(key)) is not bool
            for key in (
                "release_authority",
                "release_token_issued",
                "submission_authority",
            )
        )
        or receipt.get("current_time_receipt_sha256") is not None
        or type(receipt.get("references")) is not list
        or len(receipt["references"]) != row["reference_count"]
        or context["source_record_sha256"] != source_record
        or row["producer_commit_sha"] != producer_commit
    ):
        raise error
    return _AdmittedSourceRecord(
        source_record_sha256=source_record,
        producer_commit_sha=producer_commit,
    )


def require_consumer_compatibility(
    *,
    admitted_commit: str,
    current_commit: str,
    ancestor_status: int,
    diff_status: int,
    changed_paths: tuple[str, ...],
    protected_paths: frozenset[str],
    reader_paths: frozenset[str],
    current_runtime: bool = False,
    current_bundle_revalidated: bool = False,
) -> str:
    commit_hex = frozenset("0123456789abcdef")

    def check_path(path: str) -> None:
        if type(path) is not str or not path or "\x00" in path:
            raise ValueError("invalid path entry")

    def check_commit(value: str) -> None:
        if (
            type(value) is not str
            or len(value) != 40
            or any(character not in commit_hex for character in value)
        ):
            raise ValueError("invalid commit identifier")

    if type(current_runtime) is not bool or type(current_bundle_revalidated) is not bool:
        raise ValueError("invalid mode flags")
    check_commit(admitted_commit)
    check_commit(current_commit)
    if type(ancestor_status) is not int or ancestor_status not in (0, 1):
        raise ValueError("invalid ancestor status")
    if type(diff_status) is not int or diff_status != 0:
        raise ValueError("invalid diff status")
    if type(changed_paths) is not tuple:
        raise ValueError("invalid changed paths")
    seen: set[str] = set()
    for path in changed_paths:
        check_path(path)
        if path in seen:
            raise ValueError("invalid changed paths")
        seen.add(path)
    if type(protected_paths) is not frozenset or type(reader_paths) is not frozenset:
        raise ValueError("invalid path configuration")
    for path in protected_paths:
        check_path(path)
    for path in reader_paths:
        check_path(path)
    if not reader_paths or not reader_paths < protected_paths:
        raise ValueError("invalid reader scope")
    if not seen <= protected_paths:
        raise ValueError("changed paths outside protected scope")
    if admitted_commit == current_commit:
        if ancestor_status != 0 or diff_status != 0 or seen:
            raise ValueError("inconsistent same-commit report")
        return "same_commit"
    if ancestor_status != 0:
        raise ValueError("admitted producer is not an ancestor of current commit")
    if not seen:
        return "unchanged_authority"
    if not current_runtime:
        raise ValueError("protected change requires current reader mode")
    if seen <= reader_paths and current_bundle_revalidated:
        return "current_reader_revalidated"
    raise ValueError("current reader compatibility not established")


def _require_admitted_producer_ancestor(
    *,
    repository_descriptor: int,
    admitted_producer_commit: str,
    current_commit: str,
) -> None:
    commit_hex = frozenset("0123456789abcdef")
    if (
        type(admitted_producer_commit) is not str
        or len(admitted_producer_commit) != 40
        or any(character not in commit_hex for character in admitted_producer_commit)
        or type(current_commit) is not str
        or len(current_commit) != 40
        or any(character not in commit_hex for character in current_commit)
    ):
        raise ProductionPreparationDeploymentError("producer commit identity is malformed")
    try:
        repository = _descriptor_directory_path(repository_descriptor)
    except OSError as exc:
        raise ProductionPreparationDeploymentError(
            "admitted producer repository lease is unavailable on this host"
        ) from exc
    try:
        ancestor = subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                admitted_producer_commit,
                current_commit,
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            pass_fds=(repository_descriptor,),
        )
    except (OSError, ValueError) as exc:
        raise ProductionPreparationDeploymentError(
            "admitted producer compatibility cannot be verified"
        ) from exc
    if ancestor.returncode == 1:
        raise ProductionPreparationDeploymentError(
            "admitted producer is not an ancestor of current commit"
        )
    if ancestor.returncode != 0:
        raise ProductionPreparationDeploymentError(
            "admitted producer compatibility cannot be verified"
        )
    try:
        _require_descriptor_path_identity(repository_descriptor, repository)
    except OSError as exc:
        raise ProductionPreparationDeploymentError(
            "admitted producer repository lease changed during verification"
        ) from exc


def _require_compatible_admitted_producer(
    *,
    repository_descriptor: int,
    admitted_producer_commit: str,
    current_commit: str,
    current_runtime: bool = False,
    verified_current_input: VerifiedApplicationInput | None = None,
    expected_application_id: str | None = None,
    expected_handoff_root_sha256: str | None = None,
) -> None:
    if (
        type(admitted_producer_commit) is not str
        or len(admitted_producer_commit) != 40
        or any(c not in "0123456789abcdef" for c in admitted_producer_commit)
        or type(current_commit) is not str
        or len(current_commit) != 40
        or any(c not in "0123456789abcdef" for c in current_commit)
    ):
        raise ProductionPreparationDeploymentError("producer commit identity is malformed")
    if admitted_producer_commit == current_commit:
        return
    try:
        repository = _descriptor_directory_path(repository_descriptor)
    except OSError as exc:
        raise ProductionPreparationDeploymentError(
            "admitted producer repository lease is unavailable on this host"
        ) from exc
    try:
        ancestor = subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                admitted_producer_commit,
                current_commit,
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            pass_fds=(repository_descriptor,),
        )
        protected_diff = subprocess.run(
            [
                "git",
                "diff",
                "--name-only",
                "-z",
                "--no-renames",
                admitted_producer_commit,
                current_commit,
                "--",
                *_HANDOFF_AUTHORITY_PATHS,
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            pass_fds=(repository_descriptor,),
        )
    except (OSError, ValueError) as exc:
        raise ProductionPreparationDeploymentError(
            "admitted producer compatibility cannot be verified"
        ) from exc
    if ancestor.returncode == 1:
        raise ProductionPreparationDeploymentError(
            "admitted producer is not an ancestor of current commit"
        )
    if ancestor.returncode != 0:
        raise ProductionPreparationDeploymentError(
            "admitted producer compatibility cannot be verified"
        )
    if protected_diff.returncode != 0:
        raise ProductionPreparationDeploymentError(
            "admitted producer compatibility cannot be verified"
        )
    raw_paths = protected_diff.stdout
    if raw_paths and not raw_paths.endswith(b"\x00"):
        raise ProductionPreparationDeploymentError(
            "admitted producer compatibility cannot be verified"
        )
    try:
        changed_paths = tuple(
            value.decode("utf-8", "strict")
            for value in raw_paths.split(b"\x00")
            if value
        )
    except UnicodeDecodeError as exc:
        raise ProductionPreparationDeploymentError(
            "admitted producer compatibility cannot be verified"
        ) from exc
    current_bundle_revalidated = (
        type(verified_current_input) is VerifiedApplicationInput
        and verified_current_input.application_id == expected_application_id
        and verified_current_input.application_id != ""
        and verified_current_input.admission_kind == ADMISSION_KIND_CURRENT_RUNTIME
        and verified_current_input.environment == CURRENT_RUNTIME_ENVIRONMENT
        and verified_current_input.authority_scope == CURRENT_RUNTIME_AUTHORITY_SCOPE
        and verified_current_input.current_boundary == "strategy"
        and verified_current_input.handoff_root_sha256 == expected_handoff_root_sha256
        and type(expected_handoff_root_sha256) is str
        and len(expected_handoff_root_sha256) == 64
        and all(
            character in "0123456789abcdef"
            for character in expected_handoff_root_sha256
        )
    )
    try:
        require_consumer_compatibility(
            admitted_commit=admitted_producer_commit,
            current_commit=current_commit,
            ancestor_status=ancestor.returncode,
            diff_status=protected_diff.returncode,
            changed_paths=changed_paths,
            protected_paths=frozenset(_HANDOFF_AUTHORITY_PATHS),
            reader_paths=_CURRENT_RUNTIME_READER_PATHS,
            current_runtime=current_runtime,
            current_bundle_revalidated=current_bundle_revalidated,
        )
    except ValueError as exc:
        if changed_paths and not current_runtime:
            raise ProductionPreparationDeploymentError(
                "handoff authority changed after the admitted producer commit"
            ) from exc
        raise ProductionPreparationDeploymentError(str(exc)) from exc
    try:
        _require_descriptor_path_identity(repository_descriptor, repository)
    except OSError as exc:
        raise ProductionPreparationDeploymentError(
            "admitted producer repository lease changed during verification"
        ) from exc


def _current_runtime_strategy_input(
    *,
    store: HandoffAdmissionStore,
    application_id: str,
    adapter: ProtectedLocalOutbox,
    repository_root: Path,
    repository_descriptor: int,
    admitted_producer_commit: str,
    current_commit: str,
) -> VerifiedApplicationInput:
    verified = store.for_boundary(application_id, "strategy")
    if type(verified) is not VerifiedApplicationInput:
        raise ProductionPreparationDeploymentError(
            "current runtime strategy input is not verified"
        )
    handoff = _parse_current_runtime_handoff(adapter.handoff_bytes)
    verified_current_commit = _git_commit(
        repository_root, repository_descriptor=repository_descriptor
    )
    if verified_current_commit != current_commit:
        raise ProductionPreparationDeploymentError(
            "repository commit changed during admitted bundle revalidation"
        )
    _require_compatible_admitted_producer(
        repository_descriptor=repository_descriptor,
        admitted_producer_commit=admitted_producer_commit,
        current_commit=verified_current_commit,
        current_runtime=True,
        verified_current_input=verified,
        expected_application_id=application_id,
        expected_handoff_root_sha256=handoff.root_sha256,
    )
    return verified


def _normalized_device(value: int) -> int:
    return value & ((1 << 64) - 1)


def _require_descriptor_path_identity(descriptor: int, path: str) -> None:
    descriptor_metadata = os.fstat(descriptor)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    # Linux exposes this exact already-owned descriptor through a kernel link.
    # Ordinary caller paths must still reject symlinks; both routes verify inode
    # and device against the original descriptor after opening.
    if path != f"/proc/self/fd/{descriptor}":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    path_descriptor = os.open(path, flags)
    try:
        path_metadata = os.fstat(path_descriptor)
    finally:
        os.close(path_descriptor)
    if (
        not stat.S_ISDIR(descriptor_metadata.st_mode)
        or not stat.S_ISDIR(path_metadata.st_mode)
        or descriptor_metadata.st_ino != path_metadata.st_ino
        or _normalized_device(descriptor_metadata.st_dev)
        != _normalized_device(path_metadata.st_dev)
    ):
        raise OSError("descriptor directory identity differs")


def _descriptor_directory_path(descriptor: int) -> str:
    proc_path = f"/proc/self/fd/{descriptor}"
    if os.path.isdir(proc_path):
        _require_descriptor_path_identity(descriptor, proc_path)
        return proc_path
    if not hasattr(fcntl, "F_GETPATH"):
        raise OSError("host cannot resolve a directory descriptor")
    raw = fcntl.fcntl(descriptor, fcntl.F_GETPATH, b"\0" * 1024)
    path = os.fsdecode(raw.split(b"\0", 1)[0])
    if not path:
        raise OSError("directory descriptor has no host path")
    _require_descriptor_path_identity(descriptor, path)
    return path


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
    *,
    output_root_descriptor: int | None = None,
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
    if output_root_descriptor is None:
        chain = _open_absolute_directory_chain(expected, private_leaf=True)
    else:
        root_metadata = os.fstat(output_root_descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise ProductionPreparationDeploymentError(
                "production preparation output lease differs"
            )
        chain_members: list[int] = []
        parent = output_root_descriptor
        try:
            for name in ("preparations", result.preparation_id):
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent,
                )
                chain_members.append(descriptor)
                parent = descriptor
            chain = tuple(chain_members)
        except BaseException:
            for descriptor in reversed(chain_members):
                os.close(descriptor)
            raise
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
        with os.scandir(chain[-1]) as entries:
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
            with os.scandir(objects_descriptor) as entries:
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


def _preparation_environment_and_contact_bytes(
    deployment: _ProductionPreparationDeployment,
    contact_lease: CandidateContactResourceLease | None,
) -> tuple[str, bytes | None]:
    if type(deployment.current_runtime) is not bool:
        raise ProductionPreparationDeploymentError(
            "preparation deployment mode is invalid"
        )
    if deployment.current_runtime:
        if contact_lease is not None:
            raise ProductionPreparationDeploymentError(
                "current preparation rejects legacy contact authority"
            )
        return CURRENT_RUNTIME_ENVIRONMENT, None
    if type(contact_lease) is not CandidateContactResourceLease:
        raise ProductionPreparationDeploymentError(
            "legacy preparation requires pinned contact authority"
        )
    return "production", contact_lease.authority_bytes


def _run_production_preparation(
    application_id: str,
    deployment: _ProductionPreparationDeployment,
    *,
    after_preflight_hook: Callable[[str], None] | None = None,
    materialization_only: bool = False,
    current_runtime_pre_review: bool = False,
) -> MarketApplicationPreparation | MarketApplicationMaterializationContext:
    if (
        not application_id.startswith("app_")
        or len(application_id) != 68
        or any(c not in "0123456789abcdef" for c in application_id[4:])
    ):
        raise ProductionPreparationDeploymentError("application ID is malformed")
    if deployment.current_runtime and (
        (not materialization_only and not current_runtime_pre_review)
        or (materialization_only and current_runtime_pre_review)
        or not deployment.recovery_manifest_relative_path
        or deployment.candidate_authority_sha256 is None
        or deployment.contact_authority_path is not None
        or deployment.contact_public_key_path is not None
        or deployment.contact_registry_path is not None
    ):
        raise ProductionPreparationDeploymentError(
            "current runtime requires explicit materialization or pre-review mode"
        )
    resources = _PinnedPreparationResources()
    codex_binary = deployment.codex_binary
    poppler_bin = deployment.poppler_bin
    current_poppler_hashes: dict[str, str] = {}
    if current_runtime_pre_review:
        if not deployment.current_runtime:
            raise ProductionPreparationDeploymentError(
                "current pre-review requires current runtime deployment"
            )
        codex_binary, poppler_bin = _current_runtime_tool_paths()
    pinned: _PinnedProductionPaths | None = None
    admission_descriptor: int | None = None
    database_descriptor: int | None = None
    saved_environment = {
        name: os.environ.get(name)
        for name in (PUBLIC_KEY_ENV, REGISTRY_ENV, "JAA_POPPLER_BIN")
    }
    try:
        if not materialization_only:
            expected_poppler_hashes = (
                {
                    name: hashlib.sha256((poppler_bin / name).read_bytes()).hexdigest()
                    for name in PRODUCTION_POPPLER_SHA256
                }
                if current_runtime_pre_review and poppler_bin is not None
                else PRODUCTION_POPPLER_SHA256
            )
            for name, expected in expected_poppler_hashes.items():
                assert poppler_bin is not None
                tool_path = poppler_bin / name
                metadata = tool_path.stat()
                resources.pin_file(
                    tool_path,
                    expected_sha256=expected,
                    expected_mode=(
                        stat.S_IMODE(metadata.st_mode)
                        if current_runtime_pre_review
                        else 0o755
                    ),
                    expected_uid=(
                        metadata.st_uid
                        if current_runtime_pre_review
                        else os.geteuid()
                    ),
                    executable=True,
                    label="Poppler",
                )
                current_poppler_hashes[name] = expected
            if not current_runtime_pre_review:
                for name, expected in PRODUCTION_POPPLER_LIBRARY_SHA256.items():
                    resources.pin_file(
                        deployment.poppler_library_directory / name,
                        expected_sha256=expected,
                        expected_mode=0o644,
                        expected_uid=os.geteuid(),
                        label="Poppler library",
                    )
            assert codex_binary is not None
            codex_metadata = codex_binary.stat()
            resources.pin_file(
                codex_binary,
                expected_sha256=(
                    hashlib.sha256(codex_binary.read_bytes()).hexdigest()
                    if current_runtime_pre_review
                    else PRODUCTION_CODEX_BINARY_SHA256
                ),
                expected_mode=(
                    stat.S_IMODE(codex_metadata.st_mode)
                    if current_runtime_pre_review
                    else 0o755
                ),
                expected_uid=(
                    codex_metadata.st_uid
                    if current_runtime_pre_review
                    else PRODUCTION_CODEX_OWNER_UID
                ),
                executable=True,
                label="Codex",
            )
        authority_files = [
            (
                deployment.candidate_authority_path,
                deployment.candidate_authority_sha256
                if deployment.current_runtime
                else PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
            )
        ]
        if not deployment.current_runtime:
            assert deployment.contact_authority_path is not None
            assert deployment.contact_public_key_path is not None
            assert deployment.contact_registry_path is not None
            authority_files.extend(
                (
                    (deployment.contact_authority_path, PRODUCTION_CONTACT_ENVELOPE_SHA256),
                    (
                        deployment.contact_public_key_path,
                        PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256,
                    ),
                    (
                        deployment.contact_registry_path,
                        PRODUCTION_CONTACT_REGISTRY_FILE_SHA256,
                    ),
                )
            )
        for path, expected in authority_files:
            resources.pin_file(
                path,
                expected_sha256=expected,
                expected_mode=0o600,
                expected_uid=os.geteuid(),
                label="authority",
            )
        registry_chain = (
            None
            if deployment.current_runtime
            else resources.pin_contact_registry_chain(
                deployment.contact_registry_path
            )
        )
        resources.pin_private_directory(deployment.output_root)
        if not deployment.current_runtime:
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
                data_home=deployment.data_home,
                repository_root=deployment.repository_root,
                outbox_root=deployment.outbox_root,
                execution_receipt_root=deployment.outbox_root / "receipts",
                admission_root=(
                    deployment.data_home / "state/jaa-production-admissions"
                ),
            )
        )
        current_commit = _git_commit(
            deployment.repository_root,
            repository_descriptor=pinned.repository_descriptor,
        )
        admission_descriptor, database_descriptor = _open_admission_database(
            pinned.data_descriptor
        )
        leased_database = resources.file_descriptor(deployment.admission_database)
        if (
            os.fstat(leased_database).st_dev
            != os.fstat(database_descriptor).st_dev
            or os.fstat(leased_database).st_ino
            != os.fstat(database_descriptor).st_ino
        ):
            raise ProductionPreparationDeploymentError(
                "admission database descriptor differs from compiled lease"
            )
        if after_preflight_hook is not None:
            after_preflight_hook("database")
        resources.verify()
        pinned_database = Path(f"/proc/self/fd/{database_descriptor}")
        admitted_source = _source_record_for_application(
            pinned_database, application_id
        )
        if deployment.current_runtime:
            _require_admitted_producer_ancestor(
                repository_descriptor=pinned.repository_descriptor,
                admitted_producer_commit=admitted_source.producer_commit_sha,
                current_commit=current_commit,
            )
        else:
            _require_compatible_admitted_producer(
                repository_descriptor=pinned.repository_descriptor,
                admitted_producer_commit=admitted_source.producer_commit_sha,
                current_commit=current_commit,
            )
        source_record = admitted_source.source_record_sha256
        bundle_descriptor = pinned.open_bundle(source_record)
        if after_preflight_hook is not None:
            after_preflight_hook("bundle")
        pinned.verify_references()
        adapter = ProtectedLocalOutbox(
            deployment.outbox_root / "bundles" / source_record,
            repository_root=deployment.repository_root,
            expected_source_record_sha256=source_record,
            allowed_producer_commits=frozenset(
                {admitted_source.producer_commit_sha}
            ),
            bundle_descriptor=bundle_descriptor,
        )
        pinned.register_adapter(adapter)
        store = HandoffAdmissionStore(
            pinned_database,
            context_authenticator=adapter,
            resolver=adapter,
            current_time_witness=(
                None
                if deployment.current_runtime
                else installed_production_current_time_witness()
            ),
        )
        pinned.verify_references()
        if after_preflight_hook is not None:
            after_preflight_hook("resources")
        resources.verify()
        if not deployment.current_runtime:
            assert deployment.contact_public_key_path is not None
            assert deployment.contact_registry_path is not None
            os.environ[PUBLIC_KEY_ENV] = str(deployment.contact_public_key_path)
            os.environ[REGISTRY_ENV] = str(deployment.contact_registry_path)
        if not materialization_only:
            assert poppler_bin is not None
            os.environ["JAA_POPPLER_BIN"] = str(poppler_bin)
        candidate_bytes = resources.file_bytes(deployment.candidate_authority_path)
        contact_lease = None
        contact_provenance = None
        current_contact_bindings = None
        current_approved_evidence_bytes = None
        if deployment.current_runtime:
            verified_current_input = _current_runtime_strategy_input(
                store=store,
                application_id=application_id,
                adapter=adapter,
                repository_root=deployment.repository_root,
                repository_descriptor=pinned.repository_descriptor,
                admitted_producer_commit=admitted_source.producer_commit_sha,
                current_commit=current_commit,
            )
            (
                contact_provenance,
                current_contact_bindings,
                current_approved_evidence_bytes,
            ) = (
                _load_pinned_current_contact_provenance(
                    deployment=deployment,
                    verified=verified_current_input,
                    candidate_authority_bytes=candidate_bytes,
                )
            )
        else:
            assert deployment.contact_authority_path is not None
            assert deployment.contact_public_key_path is not None
            assert deployment.contact_registry_path is not None
            assert registry_chain is not None
            contact_lease = CandidateContactResourceLease(
                authority_path=deployment.contact_authority_path,
                authority_bytes=resources.file_bytes(deployment.contact_authority_path),
                public_key_path=deployment.contact_public_key_path,
                public_key_bytes=resources.file_bytes(deployment.contact_public_key_path),
                registry_path=deployment.contact_registry_path,
                registry_bytes=resources.file_bytes(deployment.contact_registry_path),
                registry_chain=registry_chain,
            )
        codex_descriptor = None
        poppler_runtime = None
        if not materialization_only:
            assert codex_binary is not None
            codex_descriptor = resources.file_descriptor(codex_binary)
            assert poppler_bin is not None
            poppler_runtime = pinned_poppler_runtime(
                {
                    name: resources.file_descriptor(poppler_bin / name)
                    for name in current_poppler_hashes
                },
                current_poppler_hashes,
                library_descriptors=(
                    None
                    if current_runtime_pre_review
                    else {
                        name: resources.file_descriptor(
                            deployment.poppler_library_directory / name
                        )
                        for name in PRODUCTION_POPPLER_LIBRARY_SHA256
                    }
                ),
                expected_library_sha256=(
                    None
                    if current_runtime_pre_review
                    else PRODUCTION_POPPLER_LIBRARY_SHA256
                ),
            )

        editorial_runtime = None
        cover_letter_editorial_runtime = None
        orchestration_extras = None
        if not materialization_only:
            def runtime(kind: str) -> EditorialCompositionRuntime:
                prefix = "cover_letter_" if kind == "cover_letter" else ""
                return EditorialCompositionRuntime(
                    environment="production",
                    writer=DetachedCodexEditorialAdapter(
                        stage=f"{prefix}writer" if prefix else "resume_writer",
                        model=deployment.model,
                        codex_binary=str(codex_binary),
                        environment="production",
                        timeout_seconds=deployment.timeout_seconds,
                        codex_binary_fd=codex_descriptor,
                        allow_missing_city=(
                            current_runtime_pre_review
                            and contact_provenance is not None
                            and contact_provenance.contact.city is None
                        ),
                    ),
                    humanizer=DetachedCodexEditorialAdapter(
                        stage=f"{prefix}humanizer" if prefix else "humanizer",
                        model=deployment.model,
                        codex_binary=str(codex_binary),
                        environment="production",
                        timeout_seconds=deployment.timeout_seconds,
                        codex_binary_fd=codex_descriptor,
                        allow_missing_city=(
                            current_runtime_pre_review
                            and contact_provenance is not None
                            and contact_provenance.contact.city is None
                        ),
                    ),
                    document_kind=kind,
                )

            editorial_runtime = runtime("cv")
            cover_letter_editorial_runtime = runtime("cover_letter")
            orchestration_extras = {
                "bindings": (),
                "form_fields": (),
                "poppler_runtime": poppler_runtime,
            }
            if not current_runtime_pre_review:
                assessor = ProductionDetachedRecruiterAssessor(
                    model=deployment.model,
                    archive_root=deployment.recruiter_archive_root,
                    repository_root=deployment.repository_root,
                    cli_timeout_seconds=deployment.timeout_seconds,
                    codex_binary=str(codex_binary),
                    codex_binary_fd=codex_descriptor,
                    archive_descriptor=resources.directory_descriptor(
                        deployment.recruiter_archive_root
                    ),
                )
                orchestration_extras["production_recruiter_assessor"] = assessor
        preparation_environment, contact_authority_bytes = (
            _preparation_environment_and_contact_bytes(
                deployment, contact_lease
            )
        )
        result = prepare_admitted_market_application_from_authorities(
            admission_store=store,
            application_id=application_id,
            repository_root=deployment.repository_root,
            data_home=deployment.output_root,
            candidate_authority_path=deployment.candidate_authority_path,
            contact_authority_path=deployment.contact_authority_path,
            input_materializer=CanonicalPreparationInputMaterializer(
                candidate_authority_path=deployment.candidate_authority_path,
                candidate_authority_bytes=candidate_bytes,
                approved_evidence_bytes=current_approved_evidence_bytes,
                contact_authority_bytes=contact_authority_bytes,
                materialization_only=materialization_only,
            ),
            environment=preparation_environment,
            editorial_runtime=editorial_runtime,
            cover_letter_editorial_runtime=cover_letter_editorial_runtime,
            orchestration_extras=orchestration_extras,
            candidate_authority_bytes=candidate_bytes,
            contact_resource_lease=contact_lease,
            contact_provenance=contact_provenance,
            current_contact_bindings=current_contact_bindings,
            output_root_descriptor=resources.directory_descriptor(
                deployment.output_root
            ),
            materialization_only=materialization_only,
            current_runtime_pre_review=current_runtime_pre_review,
        )
        if not materialization_only and not current_runtime_pre_review:
            _verify_preparation_output(
                result,
                deployment.output_root,
                output_root_descriptor=resources.directory_descriptor(
                    deployment.output_root
                ),
            )
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


def run_production_market_materialization(
    *,
    application_id: str,
    current_runtime_config_path: str | Path | None = None,
    current_runtime_config_sha256: str | None = None,
    current_runtime_private_root: str | Path | None = None,
    current_recovery_manifest_relative_path: str | None = None,
) -> MarketApplicationMaterializationContext:
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
    if current_recovery_manifest_relative_path is not None and not all(
        value is not None
        for value in (
            config_path,
            current_runtime_config_sha256,
            private_root,
        )
    ):
        raise ProductionPreparationDeploymentError(
            "current recovery manifest locator requires current runtime opt-in"
        )
    current_runtime, selected_deployment = select_runtime_deployment(
        config_path=config_path,
        config_sha256=current_runtime_config_sha256,
        private_root=private_root,
        legacy_loader=installed_production_preparation_deployment,
        current_loader=lambda **options: installed_current_runtime_handoff_deployment(
            configuration_path=Path(options["configuration_path"]),
            configuration_sha256=options["configuration_sha256"],
            private_root=Path(options["private_root"]),
        ),
    )
    if current_runtime:
        if current_recovery_manifest_relative_path is None:
            raise ProductionPreparationDeploymentError(
                "current materialization requires the approved recovery manifest"
            )
        _validate_deployment_roots(selected_deployment)
        deployment = _current_preparation_deployment(
            selected_deployment, current_recovery_manifest_relative_path
        )
    else:
        if current_recovery_manifest_relative_path is not None:
            raise ProductionPreparationDeploymentError(
                "legacy materialization rejects a current recovery manifest"
            )
        deployment = selected_deployment
    result = _run_production_preparation(
        application_id,
        deployment,
        materialization_only=True,
    )
    if type(result) is not MarketApplicationMaterializationContext:
        raise ProductionPreparationDeploymentError(
            "production materialization returned a non-canonical context"
        )
    return result


def run_production_market_pre_review(
    *,
    application_id: str,
    current_runtime_config_path: str | Path,
    current_runtime_config_sha256: str,
    current_runtime_private_root: str | Path,
    current_recovery_manifest_relative_path: str,
) -> MarketApplicationPreparation:
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
    if not all(
        type(value) is str and value
        for value in (
            config_path,
            current_runtime_config_sha256,
            private_root,
            current_recovery_manifest_relative_path,
        )
    ):
        raise ProductionPreparationDeploymentError(
            "current pre-review requires complete runtime configuration bindings"
        )
    current_runtime, selected_deployment = select_runtime_deployment(
        config_path=config_path,
        config_sha256=current_runtime_config_sha256,
        private_root=private_root,
        legacy_loader=installed_production_preparation_deployment,
        current_loader=lambda **options: installed_current_runtime_handoff_deployment(
            configuration_path=Path(options["configuration_path"]),
            configuration_sha256=options["configuration_sha256"],
            private_root=Path(options["private_root"]),
        ),
    )
    if not current_runtime:
        raise ProductionPreparationDeploymentError(
            "current pre-review refuses the legacy deployment mode"
        )
    _validate_deployment_roots(selected_deployment)
    deployment = _current_preparation_deployment(
        selected_deployment, current_recovery_manifest_relative_path
    )
    result = _run_production_preparation(
        application_id,
        deployment,
        materialization_only=False,
        current_runtime_pre_review=True,
    )
    if (
        getattr(result, "review_status", None) != "not_performed"
        or getattr(result, "release_authority", None) is not False
    ):
        raise ProductionPreparationDeploymentError(
            "current pre-review returned an invalid preparation result"
        )
    return result


__all__ = [
    "PRODUCTION_PREPARATION_CONFIG_PATH",
    "ProductionPreparationDeploymentError",
    "installed_production_preparation_deployment",
    "production_preparation_configuration_bytes",
    "run_production_preparation",
    "run_production_market_pre_review",
    "run_production_market_materialization",
]
